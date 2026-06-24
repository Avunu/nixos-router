# ── Threat Protection module ──────────────────────────────────────────────────
# Optional Suricata inline IPS via NFQUEUE: the service (NFQ-mode ExecStart
# override + journald namespace), the policy/rule renderers feeding
# suricata-update, the daily rule-update timer, and log rotation. HOME_NET is
# derived from the shared topology (config.router._internal.homeNets).
{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  cfg = config.router;
  inherit (config.router._internal) homeNets;

  # ── Suricata local rules ────────────────────────────────
  # Custom IDS/IPS signatures for policy enforcement. These run
  # alongside the Emerging Threats (ET Open) ruleset.
  #
  # Rule categories:
  #   SID 1000001:      Alert on DNS-over-TLS (port 853) bypass attempts.
  #   SID 1000002-1007: Alert on DoH bypass via TLS SNI matching for
  #                     known DoH provider hostnames (Cloudflare, Google,
  #                     Quad9, NextDNS, Mullvad, AdGuard).
  #   SID 1000010-1011: Alert on SafeSearch bypass attempts detected
  #                     via HTTP URI parameters (safe=off, safeSearch=off).
  #
  # Additional rules can be appended via `router.suricata.extraRules`.
  localSuricataRules = ''
    alert tls $HOME_NET any -> $EXTERNAL_NET 853 (msg:"POLICY DoT bypass attempt"; flow:to_server,established; sid:1000001; rev:1;)
    alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"POLICY DoH bypass - Cloudflare"; tls.sni; content:"cloudflare-dns.com"; sid:1000002; rev:1;)
    alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"POLICY DoH bypass - Google DNS"; tls.sni; content:"dns.google"; sid:1000003; rev:1;)
    alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"POLICY DoH bypass - Quad9"; tls.sni; content:"dns.quad9.net"; sid:1000004; rev:1;)
    alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"POLICY DoH bypass - NextDNS"; tls.sni; content:"dns.nextdns.io"; sid:1000005; rev:1;)
    alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"POLICY DoH bypass - Mullvad"; tls.sni; content:"doh.mullvad.net"; sid:1000006; rev:1;)
    alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"POLICY DoH bypass - AdGuard"; tls.sni; content:"dns.adguard.com"; sid:1000007; rev:1;)
    alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"POLICY SafeSearch bypass - safe=off"; http.uri; content:"safe=off"; sid:1000010; rev:1;)
    alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"POLICY SafeSearch bypass - safeSearch=off"; http.uri; content:"safeSearch=off"; sid:1000011; rev:1;)
  ''
  + cfg.suricata.extraRules;

  # ── Suricata policy files (suricata-update + threshold) ──
  # The Cockpit "Policies" tab edits router.suricata.{categories,
  # policies,suppressions}; here we render them into the files
  # suricata-update and Suricata consume. Categories key on the
  # suricata-update rule *group* (source rule-file name); policies and
  # suppressions key on the signature id (gid 1).
  suricataCats =
    action: filter (n: cfg.suricata.categories.${n} == action) (attrNames cfg.suricata.categories);
  suricataPolicySids =
    action: map (p: toString p.sid) (filter (p: p.action == action) cfg.suricata.policies);

  # disable.conf — rules removed before load. Carries over the upstream
  # module's services.suricata.disabledRules (its default disables the
  # dnp3 signatures, whose app-layer parser is off), then layers the
  # category + per-signature disables from the router config.
  suricataDisableConf = pkgs.writeText "suricata-disable.conf" (
    concatStringsSep "\n" (
      [ "# from services.suricata.disabledRules (module default: dnp3 rules)" ]
      ++ config.services.suricata.disabledRules
      ++ [ "# category disables (router.suricata.categories = \"disabled\")" ]
      ++ map (n: "group:${n}") (suricataCats "disabled")
      ++ [ "# per-signature disables (router.suricata.policies)" ]
      ++ suricataPolicySids "disable"
    )
    + "\n"
  );

  # drop.conf — matching rules have their action rewritten to `drop`.
  # Empty in IDS mode, so enabling/disabling drop is a single mode flip.
  suricataDropConf = pkgs.writeText "suricata-drop.conf" (
    concatStringsSep "\n" (
      optionals (cfg.suricata.mode == "ips") (
        map (n: "group:${n}") (suricataCats "drop") ++ suricataPolicySids "drop"
      )
    )
    + "\n"
  );

  # threshold.config — per-host suppressions ("do nothing for this host").
  suricataThreshold = pkgs.writeText "suricata-threshold.config" (
    concatStringsSep "\n" (
      map (
        s: "suppress gen_id 1, sig_id ${toString s.sid}, track ${s.track}, ip ${s.ip}"
      ) cfg.suricata.suppressions
    )
    + "\n"
  );

  # suricata-update invocation, overriding the upstream module's script so
  # we can also pass --drop-conf (the module only wires --disable-conf).
  # Reproduces the module's enable-source / update-sources preamble.
  suricataUpdateScript =
    let
      python = pkgs.python3.withPackages (ps: with ps; [ pyyaml ]);
      pkg = config.services.suricata.package;
      enableSources = concatMapStringsSep "\n" (
        src: "${python.interpreter} ${pkg}/bin/suricata-update enable-source ${src}"
      ) config.services.suricata.enabledSources;
    in
    ''
      ${enableSources}
      ${python.interpreter} ${pkg}/bin/suricata-update update-sources
      ${python.interpreter} ${pkg}/bin/suricata-update update \
        --suricata-conf ${config.services.suricata.configFile} --no-test \
        --disable-conf ${suricataDisableConf} \
        --drop-conf ${suricataDropConf}
    '';
in
{
  options.router = {
    # ── Suricata IPS ───────────────────────────────────────
    # Optional inline IPS using NFQUEUE. When enabled:
    #   • The nftables forward chain sends packets to NFQUEUE 0
    #     with fail-open (traffic passes if Suricata is down).
    #   • Suricata runs in NFQ accept mode, inspecting forwarded
    #     traffic with ET Open rules + custom local rules.
    #   • A daily timer updates ET Open rules via suricata-update.
    #   • Logs are rotated daily, kept for 14 days.
    suricata = {
      enable = mkEnableOption "Suricata IPS inline inspection";

      mode = mkOption {
        type = types.enum [
          "ids"
          "ips"
        ];
        default = "ids";
        description = ''
          Detection mode. `ids` = alert only, never drop (Synology
          "detect"). `ips` = honor the drop actions configured per
          category/signature below (Synology "drop high-risk packets
          automatically"). NFQUEUE already enforces `drop` verdicts; this
          gates whether any `drop` conversions are emitted to
          suricata-update at all.
        '';
      };

      categories = mkOption {
        type = types.attrsOf (
          types.enum [
            "enabled"
            "disabled"
            "drop"
          ]
        );
        default = { };
        example = {
          "emerging-malware.rules" = "drop";
          "emerging-pop3.rules" = "disabled";
        };
        description = ''
          Per-category action overrides, keyed by suricata-update rule
          group (the source rule-file name, e.g. `emerging-malware.rules`).
          `disabled` adds a `group:` line to the suricata-update disable
          list; `drop` adds one to the drop list (only effective in
          `ips` mode); `enabled` keeps the ruleset default. Categories
          absent here are unchanged. Edited from the Cockpit IPS
          "Policies" tab.
        '';
      };

      policies = mkOption {
        type = types.listOf (
          types.submodule {
            options = {
              sid = mkOption {
                type = types.int;
                description = "Signature ID (gid 1).";
              };
              action = mkOption {
                type = types.enum [
                  "alert"
                  "drop"
                  "disable"
                ];
                default = "alert";
                description = ''
                  `alert` (default, no change), `drop` (convert to drop —
                  `ips` mode only), or `disable` (remove the rule).
                '';
              };
              comment = mkOption {
                type = types.str;
                default = "";
                description = "Free-text note shown in the UI.";
              };
            };
          }
        );
        default = [ ];
        description = ''
          Per-signature action overrides ("self-defined policy"). Built
          from the Cockpit IPS "Policies" tab, typically by editing the
          action of a signature seen in the Events list.
        '';
      };

      suppressions = mkOption {
        type = types.listOf (
          types.submodule {
            options = {
              sid = mkOption {
                type = types.int;
                description = "Signature ID (gid 1) to suppress.";
              };
              track = mkOption {
                type = types.enum [
                  "by_src"
                  "by_dst"
                  "by_either"
                ];
                default = "by_src";
                description = "Which side of the flow the IP matches.";
              };
              ip = mkOption {
                type = types.str;
                description = "Host or subnet exempted from this signature.";
              };
              comment = mkOption {
                type = types.str;
                default = "";
                description = "Free-text note shown in the UI.";
              };
            };
          }
        );
        default = [ ];
        description = ''
          Per-host signature suppressions, rendered into Suricata's
          threshold.config as `suppress` lines ("do nothing for this host
          on this signature").
        '';
      };

      extraRules = mkOption {
        type = types.lines;
        default = "";
        description = "Additional Suricata local rules";
      };
    };
  };

  config = {
    # ── 6. IPS — Suricata ────────────────────────────────
    # When enabled, Suricata runs as an inline IPS via NFQUEUE
    # using the NixOS services.suricata module. The module manages
    # config file generation, service hardening, user/group
    # creation, and rule fetching via suricata-update.
    #
    # Since the module only supports interface-capture modes
    # natively (af-packet, pcap, etc.), ExecStart is overridden
    # to run in NFQ mode (-q 0) with fail-open. A dummy pcap
    # entry satisfies the module's capture-interface assertion.
    #
    # A daily timer refreshes ET Open rules via suricata-update
    # with a randomized delay to avoid thundering herd.
    environment.etc."suricata/rules/local.rules" = mkIf cfg.suricata.enable {
      text = localSuricataRules;
    };

    services.suricata = mkIf cfg.suricata.enable {
      enable = true;
      settings = {
        # Dummy pcap to satisfy the module's capture-interface
        # assertion; overridden by NFQ mode via ExecStart below.
        pcap = [ { interface = "lo"; } ];

        vars = {
          address-groups = {
            HOME_NET = homeNets;
            EXTERNAL_NET = "!$HOME_NET";
            DNS_SERVERS = "$HOME_NET";
          };
          port-groups = {
            HTTP_PORTS = "80";
            SHELLCODE_PORTS = "!80";
            ORACLE_PORTS = "1521";
            SSH_PORTS = "22";
            DNP3_PORTS = "20000";
            MODBUS_PORTS = "502";
            FILE_DATA_PORTS = "[$HTTP_PORTS,110,143]";
            FTP_PORTS = "21";
            GENEVE_PORTS = "6081";
            VXLAN_PORTS = "4789";
            TEREDO_PORTS = "3544";
            DNS_PORTS = "53";
          };
        };

        host-mode = "router";
        default-log-dir = "/var/log/suricata";

        stats = {
          enable = true;
          interval = "30";
        };

        logging = {
          default-log-level = "notice";
          outputs = {
            console.enable = false;
            file = {
              enable = true;
              filename = "suricata.log";
              level = "info";
            };
          };
        };

        outputs = [
          {
            eve-log = {
              enabled = true;
              filetype = "regular";
              filename = "eve.json";
              community-id = true;
              types = [
                { alert.tagged-packets = true; }
                {
                  drop = {
                    alerts = true;
                    flows = "start";
                  };
                }
                "dns"
                "tls"
                { http.extended = true; }
                { flow.logged = true; }
                { stats.deltas = true; }
              ];
            };
          }
          {
            # Second EVE stream → syslog → journald, limited to the alert
            # events the Cockpit IPS page surfaces. journald captures these
            # under SYSLOG_IDENTIFIER=suricata, which the Cockpit views read
            # via journalctl. The service runs with PrivateDevices=true,
            # whose private /dev omits the /dev/log socket; the service
            # override below bind-mounts journald's socket back to /dev/log
            # so syslog() reaches the journal (otherwise libc's LOG_CONS
            # fallback would send these to the console, unstored). Keeping
            # dns/tls/http/flow out of this stream means the journal isn't
            # flooded — those stay in the regular eve.json file above for
            # forensics. Only `alert` (not `drop`): Suricata permits a
            # single `drop` logger and the file output above owns it;
            # blocked packets still appear here as alert events with
            # alert.action = "blocked".
            eve-log = {
              enabled = true;
              filetype = "syslog";
              identity = "suricata";
              facility = "local5";
              level = "Info";
              community-id = true;
              types = [
                "alert"
              ];
            };
          }
          {
            fast = {
              enabled = true;
              filename = "fast.log";
              append = true;
            };
          }
        ];

        nfq = [
          {
            mode = "accept";
            id = 0;
            fail-open = true;
          }
        ];

        app-layer.protocols = {
          http = {
            enabled = "yes";
            libhtp.default-config = {
              personality = "IDS";
              request-body-limit = 131072;
              response-body-limit = 131072;
            };
          };
          tls = {
            enabled = "yes";
            detection-ports.dp = 443;
            ja3-fingerprints = true;
          };
          dns = {
            enabled = "yes";
            tcp.enabled = "yes";
            udp.enabled = "yes";
          };
          ssh.enabled = "yes";
          smtp.enabled = "yes";
          ftp.enabled = "yes";
          smb.enabled = "yes";
          dcerpc.enabled = "yes";
        };

        rule-files = [
          "suricata.rules"
          "/etc/suricata/rules/local.rules"
        ];

        # Per-host suppressions from router.suricata.suppressions
        # (Cockpit "Policies" tab). A store path is fine — read-only and
        # world-readable under the service's ProtectSystem=strict sandbox.
        threshold-file = toString suricataThreshold;

        detect = {
          profile = "medium";
          sgh-mpm-context = "auto";
          inspection-recursion-limit = 3000;
        };

        stream = {
          memcap = "64mb";
          checksum-validation = true;
          midstream = false;
          async-oneside = false;
          reassembly = {
            memcap = "256mb";
            depth = "1mb";
            toserver-chunk-size = 2560;
            toclient-chunk-size = 2560;
          };
        };

        threading = {
          set-cpu-affinity = false;
          detect-thread-ratio = 1.0;
        };
      };
    };

    systemd.services = mkIf cfg.suricata.enable {
      # Override the module's ExecStart to use NFQ mode instead
      # of interface capture (-i). The module generates the
      # config file; we just change how suricata reads packets.
      suricata.serviceConfig = {
        ExecStart = mkForce "!${config.services.suricata.package}/bin/suricata -c ${config.services.suricata.configFile} -q 0";
        ExecReload = "${pkgs.coreutils}/bin/kill -USR2 $MAINPID";
        LimitNOFILE = 65536;
        # The -T config test in ExecStartPre loads all rules (~56MB)
        # which takes ~2 min on low-power hardware; default 90s is insufficient.
        TimeoutStartSec = 300;
        # Route this service's logs (stdout/stderr + the EVE syslog
        # output) into a dedicated journald namespace. This is what makes
        # the EVE syslog stream reach the journal at all: the upstream
        # module's PrivateDevices=true gives the service a private /dev
        # with no /dev/log, and LogNamespace re-provides a working
        # /dev/log wired to the namespace's journald (plain syslog would
        # otherwise fall back to the console, unstored). It also isolates
        # the IPS event volume from the main system journal — the Cockpit
        # views read it with `journalctl --namespace suricata`.
        LogNamespace = "suricata";
      };

      # Reload Suricata after rule updates (uses + prefix for
      # root privileges since suricata-update runs as limited user).
      # --no-block is essential: this runs while suricata is ordered
      # after suricata-update, so during a rebuild suricata is often
      # still activating (its ~2 min `-T` rule check) or failing. A
      # *blocking* reload would enqueue a job that waits indefinitely
      # for suricata to become active, wedging `switch-to-configuration`
      # (the reload job never times out). Fire-and-forget instead;
      # try-reload-or-restart is already a no-op when suricata is inactive.
      suricata-update.serviceConfig.ExecStartPost = "+${pkgs.systemd}/bin/systemctl --no-block try-reload-or-restart suricata.service";

      # Override the module's update script so it also passes
      # --drop-conf (the module only wires --disable-conf). Renders the
      # category/signature/suppression policies from the router config.
      suricata-update.script = mkForce suricataUpdateScript;
    };

    systemd.timers = mkIf cfg.suricata.enable {
      suricata-update = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = "daily";
          Persistent = true;
          RandomizedDelaySec = "1h";
        };
      };
    };

    services.logrotate.settings = mkIf cfg.suricata.enable {
      suricata = {
        files = "/var/log/suricata/*.log /var/log/suricata/*.json";
        frequency = "daily";
        rotate = 14;
        compress = true;
        delaycompress = true;
        missingok = true;
        notifempty = true;
        postrotate = "systemctl reload suricata.service 2>/dev/null || true";
      };
    };
  };
}
