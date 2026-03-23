# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  NixOS Router — Declarative Home/Office Router Configuration               ║
# ║                                                                            ║
# ║  A single-flake NixOS module that turns a multi-NIC machine into a fully   ║
# ║  featured router with:                                                     ║
# ║    • systemd-networkd managed WAN (DHCP) + LAN/Guest bridges w/ DHCPServer ║
# ║    • nftables stateful firewall with NAT, DNS hijacking, DoT blocking      ║
# ║    • AdGuard Home DNS filtering + SafeSearch on :53 (direct to clients)    ║
# ║    • WireGuard VPN tunnels with full LAN ↔ WAN ↔ WG routing                ║
# ║    • Optional Suricata IPS inline via NFQUEUE                              ║
# ║    • Optional Cockpit web UI for administration                            ║
# ║    • Disko-based declarative disk partitioning (UEFI or legacy)            ║
# ║                                                                            ║
# ║  Usage:                                                                    ║
# ║    Import `nixosModules.router` and set the `router.*` options in your     ║
# ║    host configuration. See the MODULE OPTIONS section for all settings.    ║
# ║                                                                            ║
# ║  Architecture:                                                             ║
# ║    DNS flow: clients → AdGuard Home (:53) → DoH upstream                  ║
# ║    Traffic:  LAN/Guest/WG → nftables (→ Suricata NFQUEUE) → NAT → WAN     ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
{
  description = "NixOS Router";

  # ── Flake Inputs ────────────────────────────────────────────────────────────
  # nixpkgs:  NixOS unstable channel — provides all packages and the NixOS
  #           module system. Unstable is used for the latest kernel, networkd,
  #           and security patches.
  # devenv:   Developer shell with git hooks (nixfmt formatting, flake check).
  # disko:    Declarative disk partitioning — generates partition layouts from
  #           Nix expressions, supporting both UEFI (GPT+ESP) and legacy
  #           (GPT+BIOS boot) modes.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    devenv = {
      url = "github:cachix/devenv";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      ...
    }:
    let
      lib = nixpkgs.lib;
      forAllSystems = lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
    in
    {
      # ── Developer Shell ──────────────────────────────────────────────────────
      # Provides a devenv-managed shell with:
      #   • nixfmt for consistent Nix code formatting
      #   • Pre-commit hooks:
      #     - nixfmt:        auto-formats .nix files on commit
      #     - flake-checker: runs `nix flake check` to catch evaluation errors
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = inputs.devenv.lib.mkShell {
            inherit inputs pkgs;
            modules = [
              {
                packages = [ pkgs.nixfmt ];

                git-hooks.hooks = {
                  nixfmt = {
                    enable = true;
                    package = pkgs.nixfmt;
                  };
                  flake-checker = {
                    enable = true;
                    name = "nix flake check";
                    entry = "nix flake check --no-pure-eval";
                    pass_filenames = false;
                    stages = [ "pre-commit" ];
                  };
                };
              }
            ];
          };
        }
      );

      # ════════════════════════════════════════════════════════════════════════
      #  ROUTER MODULE
      #
      #  This NixOS module is the core of the flake. It declares all
      #  `router.*` options and maps them to NixOS config (systemd-networkd,
      #  nftables, dnsmasq, AdGuard Home, WireGuard, Suricata, Cockpit, etc.).
      #
      #  The module is structured as:
      #    1. `let` block:  Derived values, helpers, sub-module types, and
      #                     generated config fragments (nftables ruleset,
      #                     Suricata YAML, filter lists).
      #    2. `options`:    All user-facing `router.*` option declarations.
      #    3. `config`:     The implementation that wires options into NixOS.
      # ════════════════════════════════════════════════════════════════════════
      nixosModules.router =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        with lib;
        let
          cfg = config.router;

          # ── Derived values ──────────────────────────────────────
          # These are computed from the user-facing `router.*` options and
          # referenced throughout the config implementation. Centralizing
          # them here avoids repetition and ensures consistency.
          #
          # brLAN / lanGW / lanPrefix / lanCIDR:
          #   Bridge name, gateway IP, prefix length, and CIDR notation for
          #   the primary LAN network. Used in networkd, nftables, and
          #   Suricata HOME_NET.
          brLAN = cfg.lan.bridge;
          lanGW = cfg.lan.address;
          lanPrefix = toString cfg.lan.prefixLength;
          lanCIDR = "${cfg.lan.networkAddress}/${lanPrefix}";

          # wgNames / wgInterfaces:
          #   List of WireGuard interface names (e.g. ["wg0"]) and their
          #   config attrsets. Used to generate networkd units, nftables
          #   rules, and Suricata HOME_NET entries.
          wgNames = attrNames cfg.wireguard;
          wgInterfaces = attrValues cfg.wireguard;
          wgIFNames = wgNames;

          # homeNets:
          #   Aggregated list of all "internal" subnets (LAN + WireGuard +
          #   Guest) formatted as a Suricata YAML list for $HOME_NET.
          #   $EXTERNAL_NET is automatically set to "!$HOME_NET".
          lanNets = [ lanCIDR ];
          wgNets = concatMap (wg: [ wg.address ] ++ concatMap (p: p.allowedIPs) wg.peers) wgInterfaces;
          guestNets = optional cfg.guest.enable guestCIDR;
          allHomeNets = lanNets ++ wgNets ++ guestNets;
          homeNets = "[${concatStringsSep ", " allHomeNets}]";

          # nftSet:
          #   Helper to format a list of interface names as a quoted,
          #   comma-separated nftables set literal, e.g. { "br-lan", "wg0" }.
          # trustedIFs:
          #   Interfaces allowed full access to the router (LAN bridge + all
          #   WireGuard tunnels). Used in the nftables input chain.
          nftSet = items: concatStringsSep ", " (map (i: ''"${i}"'') items);
          trustedIFs = [ brLAN ] ++ wgIFNames;

          # ── Guest network derived values ────────────────────────
          # Mirror of the LAN derived values, for the isolated guest network.
          # Guest traffic is only allowed to reach the WAN — never LAN or WG.
          brGuest = cfg.guest.bridge;
          guestGW = cfg.guest.address;
          guestPrefix = toString cfg.guest.prefixLength;
          guestCIDR = "${cfg.guest.networkAddress}/${guestPrefix}";

          # ── Standard filter list catalogue ──────────────────────
          # Registry of well-known ad/malware/phishing blocklists for AdGuard
          # Home. Each entry has a stable numeric `id` (used by AdGuard
          # internally to track filter state), a human-readable `name`, and
          # the upstream URL. Users toggle individual lists on/off via
          # `router.dns.adguard.standardFilters.<key> = true|false`.
          #
          # The `standardFilters` derivation below takes the user's boolean
          # toggles, looks up matching entries here, marks them `enabled`,
          # and passes the result to AdGuard Home's `filters` config.
          standardFilterCatalogue = {
            adguard_ads = {
              name = "AdGuard Base";
              url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt";
              id = 1;
            };
            adguard_malware = {
              name = "AdGuard Malware URL Blocklist";
              url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt";
              id = 2;
            };
            adaway = {
              name = "AdAway";
              url = "https://adaway.org/hosts.txt";
              id = 3;
            };
            yoyo_adservers = {
              name = "Peter Lowe's Ad and tracker server list";
              url = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=1&mimetype=plaintext";
              id = 4;
            };
            adguard_hacked_sites = {
              name = "Hacked Malware Web Sites";
              url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt";
              id = 5;
            };
            steven_black = {
              name = "Steven Black's Hosts";
              url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt";
              id = 6;
            };
            adguard_phishing = {
              name = "AdGuard Phishing URL Blocklist";
              url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt";
              id = 7;
            };
            adguard_anti_malware = {
              name = "Dandelion Sprout's Anti-Malware List";
              url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt";
              id = 8;
            };
            phishtank_openphish = {
              name = "Phishing Army (PhishTank + OpenPhish)";
              url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt";
              id = 9;
            };
          };

          # Build the list of enabled standard filters by filtering the
          # catalogue keys against the user's boolean toggles, then merging
          # in `enabled = true` so AdGuard Home activates them.
          standardFilters = map (key: standardFilterCatalogue.${key} // { enabled = true; }) (
            filter (key: cfg.dns.adguard.standardFilters.${key}) (attrNames cfg.dns.adguard.standardFilters)
          );

          # ── UT Capitole blacklist filters ───────────────────────
          # The Université Toulouse Capitole maintains a curated collection
          # of domain blacklists organized by category (adult, malware,
          # phishing, gambling, etc.). Each category string from
          # `router.dns.adguard.utCapitoleCategories` is turned into an
          # AdGuard filter entry. IDs start at 10000 to avoid collisions
          # with the standard filter catalogue (IDs 1-9).
          utCapitoleFilters = imap1 (i: cat: {
            enabled = true;
            name = "UT Capitole - ${cat}";
            url = "https://dsi.ut-capitole.fr/blacklists/download/${cat}/domains";
            id = 9999 + i;
          }) cfg.dns.adguard.utCapitoleCategories;

          # ── Suricata config (native Nix → YAML) ────────────────
          # The entire suricata.yaml is built as a Nix attrset and serialized
          # to YAML via pkgs.formats.yaml. This is done by folding multiple
          # config fragments with `recursiveUpdate` to keep each concern
          # (vars, outputs, nfq, app-layer, rules, detect/stream) separate
          # and readable.
          #
          # Key design decisions:
          #   • NFQ mode with fail-open: if Suricata crashes, traffic passes
          #     rather than blocking the entire network.
          #   • EVE JSON logging with community-id: enables correlation with
          #     other network tools (Zeek, Elastic, etc.).
          #   • HOME_NET is dynamically computed from all internal subnets
          #     (LAN + WG + Guest) so Suricata rules automatically cover
          #     the correct address space.
          #   • JA3 fingerprinting enabled for TLS traffic analysis.
          yamlFormat = pkgs.formats.yaml { };

          suricataConfig = lib.foldl lib.recursiveUpdate { } [
            {
              vars = {
                address-groups = {
                  HOME_NET = homeNets;
                  EXTERNAL_NET = "!$HOME_NET";
                  DNS_SERVERS = "$HOME_NET";
                };
                port-groups = {
                  HTTP_PORTS = "80";
                  SHELLCODE_PORTS = "!80";
                  SSH_PORTS = "22";
                  DNS_PORTS = "53";
                };
              };
              default-log-dir = "/var/log/suricata/";
              stats = {
                enabled = true;
                interval = 30;
              };
              logging = {
                default-log-level = "notice";
                outputs = [
                  { console.enabled = false; }
                  {
                    file = {
                      enabled = true;
                      filename = "suricata.log";
                      level = "info";
                    };
                  }
                ];
              };
              threading = {
                set-cpu-affinity = false;
                detect-thread-ratio = 1.0;
              };
            }
            {
              outputs = [
                {
                  eve-log = {
                    enabled = true;
                    filetype = "regular";
                    filename = "eve.json";
                    community-id = true;
                    types = [
                      {
                        alert = {
                          tagged-packets = true;
                        };
                      }
                      {
                        drop = {
                          alerts = true;
                          flows = "start";
                        };
                      }
                      "dns"
                      "tls"
                      {
                        http = {
                          extended = true;
                        };
                      }
                      {
                        flow = {
                          logged = true;
                        };
                      }
                      {
                        stats = {
                          deltas = true;
                        };
                      }
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
            }
            {
              nfq = [
                {
                  mode = "accept";
                  id = 0;
                  fail-open = true;
                }
              ];
            }
            {
              app-layer.protocols = {
                http = {
                  enabled = true;
                  libhtp.default-config = {
                    personality = "IDS";
                    request-body-limit = 131072;
                    response-body-limit = 131072;
                  };
                };
                tls = {
                  enabled = true;
                  detection-ports = {
                    dp = 443;
                  };
                  ja3-fingerprints = true;
                };
                dns = {
                  enabled = true;
                  tcp.enabled = true;
                  udp.enabled = true;
                };
                ssh.enabled = true;
                smtp.enabled = true;
                ftp.enabled = true;
                smb.enabled = true;
                dcerpc.enabled = true;
              };
            }
            {
              default-rule-path = "/var/lib/suricata/rules";
              rule-files = [
                "suricata.rules"
                "local.rules"
              ];
            }
            {
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
            }
          ];

          # ── DoH block rules for AdGuard ─────────────────────────
          # AdGuard user rules that block DNS-over-HTTPS provider domains
          # at the DNS level. This prevents devices from bypassing the
          # local DNS filtering by using their own DoH resolvers.
          # The "||domain^" syntax is AdGuard's domain-matching filter:
          #   || = match domain and all subdomains
          #   ^  = separator character (end of domain)
          # These rules complement the nftables DoT port-853 block and
          # Suricata TLS SNI alerts for defense-in-depth DNS enforcement.
          dohBlockRules = [
            "||dns.google^"
            "||cloudflare-dns.com^"
            "||mozilla.cloudflare-dns.com^"
            "||dns.quad9.net^"
            "||doh.opendns.com^"
            "||dns.nextdns.io^"
            "||doh.cleanbrowsing.org^"
            "||dns.adguard.com^"
            "||doh.mullvad.net^"
            "||dns.controld.com^"
          ];

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

          # ── nftables ruleset generation ─────────────────────────
          # The firewall ruleset is generated as a Nix multi-line string
          # and passed to `networking.nftables.ruleset`. It's built from
          # the user's interface/network config so rules adapt automatically.
          #
          # wgInputRules:
          #   Dynamically generates `accept` rules for each WireGuard
          #   tunnel's UDP listen port on the WAN interface, allowing
          #   inbound VPN connections.
          wgInputRules = concatMapStringsSep "\n          " (
            name:
            let
              wg = cfg.wireguard.${name};
            in
            ''iifname "${cfg.wan.interface}" udp dport ${toString wg.listenPort} accept comment "Allow WireGuard ${name}"''
          ) wgNames;

          # wgForwardRules:
          #   For each WireGuard tunnel, generates bidirectional forwarding
          #   rules (LAN ↔ WG) and outbound WAN access with stateful return
          #   traffic. This allows VPN clients to reach LAN resources and
          #   route to the internet through the router.
          wgForwardRules =
            concatMapStringsSep "\n          "
              (name: ''
                # LAN ↔ ${name} (bidirectional)
                iifname "${brLAN}" oifname "${name}" accept
                iifname "${name}"  oifname "${brLAN}" accept

                # ${name} → WAN
                iifname "${name}" oifname "${cfg.wan.interface}" accept
                iifname "${cfg.wan.interface}" oifname "${name}" ct state { established, related } accept'')
              wgNames;

          # nftRuleset:
          #   The complete nftables configuration, organized into three tables:
          #
          #   1. `inet filter` — Stateful firewall (input + forward chains)
          #      • Input: loopback accepted; trusted IFs (LAN+WG) fully open;
          #        guest limited to DHCP/DNS only; WAN allows established +
          #        ICMP + WireGuard ports; everything else dropped.
          #      • Forward: optional Suricata NFQUEUE inspection; WG
          #        bidirectional; LAN→WAN; WAN→LAN established; guest→WAN
          #        only (fully isolated from LAN and WG).
          #
          #   2. `ip nat` — NAT and DNS hijacking
          #      • Prerouting: intercepts all DNS (port 53) from LAN/guest
          #        and redirects to the local resolver, preventing clients
          #        from bypassing AdGuard filtering by hardcoding external
          #        DNS servers.
          #      • Postrouting: masquerades outbound WAN traffic.
          #
          #   3. `inet dot_block` — DNS-over-TLS blocking
          #      • Runs at priority filter-1 (before the main filter) to
          #        drop TCP port 853 from LAN/guest, preventing DoT bypass
          #        of the local DNS resolver.
          nftRuleset = ''
            table inet filter {
              chain input {
                type filter hook input priority 0; policy drop;

                # Loopback
                iifname "lo" accept

                # Trusted internal networks
                iifname { ${nftSet trustedIFs} } accept comment "Allow LAN and WG to router"

                ${optionalString cfg.guest.enable ''
                  # Guest: DHCP and DNS to router only (all other guest→router dropped)
                  iifname "${brGuest}" udp dport { 53, 67 } accept
                  iifname "${brGuest}" tcp dport 53 accept
                ''}

                # WAN: only established/related + select ICMP
                iifname "${cfg.wan.interface}" ct state { established, related } accept
                iifname "${cfg.wan.interface}" icmp type { echo-request, destination-unreachable, time-exceeded } counter accept
                ${wgInputRules}

                # Drop everything else from WAN
                iifname "${cfg.wan.interface}" counter drop
              }

              chain forward {
                type filter hook forward priority filter; policy drop;

                # Suricata IPS inline inspection (NFQUEUE with bypass)
                ${optionalString cfg.suricata.enable "queue num 0 bypass"}

                ${wgForwardRules}

                # LAN → WAN
                iifname "${brLAN}" oifname "${cfg.wan.interface}" accept

                # WAN → LAN (established only)
                iifname "${cfg.wan.interface}" oifname "${brLAN}" ct state { established, related } accept

                ${optionalString cfg.guest.enable ''
                  # Guest → WAN only (fully isolated from LAN and WireGuard)
                  iifname "${brGuest}" oifname "${cfg.wan.interface}" accept
                  iifname "${cfg.wan.interface}" oifname "${brGuest}" ct state { established, related } accept
                ''}
              }
            }

            table ip nat {
              chain prerouting {
                type nat hook prerouting priority dstnat; policy accept;

                # Force all LAN DNS through local resolver (prevents bypass)
                iifname "${brLAN}" udp dport 53 ip daddr != ${lanGW} dnat to ${lanGW}:53
                iifname "${brLAN}" tcp dport 53 ip daddr != ${lanGW} dnat to ${lanGW}:53

                ${optionalString cfg.guest.enable ''
                  # Force guest DNS through local resolver
                  iifname "${brGuest}" udp dport 53 ip daddr != ${guestGW} dnat to ${guestGW}:53
                  iifname "${brGuest}" tcp dport 53 ip daddr != ${guestGW} dnat to ${guestGW}:53
                ''}
              }

              chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;
                oifname "${cfg.wan.interface}" masquerade
              }
            }

            # Block DoT bypass (port 853) in forward chain
            table inet dot_block {
              chain forward {
                type filter hook forward priority filter - 1; policy accept;
                iifname "${brLAN}" tcp dport 853 counter drop comment "Block DoT bypass"
                ${optionalString cfg.guest.enable ''iifname "${brGuest}" tcp dport 853 counter drop comment "Block guest DoT bypass"''}
              }
            }
          '';

          # ── WireGuard peer submodule type ───────────────────────
          # Defines the schema for a single WireGuard peer. Each peer has:
          #   • publicKey:           The peer's WireGuard public key.
          #   • endpoint:            Optional remote address:port (null for
          #                          peers that connect inbound only).
          #   • allowedIPs:          Subnets routed through the WG tunnel to
          #                          this peer (also used in Suricata HOME_NET).
          #   • persistentKeepalive: Seconds between keepalive packets
          #                          (default 25, useful for NAT traversal).
          wgPeerType = types.submodule {
            options = {
              publicKey = mkOption {
                type = types.str;
                description = "Public key of the WireGuard peer";
              };
              endpoint = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "Endpoint address:port of the peer";
              };
              allowedIPs = mkOption {
                type = types.listOf types.str;
                description = "Allowed IP ranges for this peer";
              };
              persistentKeepalive = mkOption {
                type = types.int;
                default = 25;
                description = "Persistent keepalive interval in seconds";
              };
            };
          };

          # ── WireGuard interface submodule type ──────────────────
          # Defines the schema for a WireGuard tunnel interface. The
          # attribute name in `router.wireguard` becomes the interface name
          # (e.g. `wg0`). Each interface gets:
          #   • address:        Local tunnel IP with CIDR (e.g. 10.100.0.1/24).
          #   • listenPort:     UDP port (default 51820; auto-opened in nftables).
          #   • privateKeyFile: Path to the private key file (never in the Nix
          #                    store — should be in /etc/wireguard/ or similar).
          #   • peers:          List of wgPeerType entries.
          #   • routes:         Extra destination CIDRs to add as systemd-networkd
          #                    routes on this tunnel.
          wgInterfaceType = types.submodule {
            options = {
              address = mkOption {
                type = types.str;
                description = "Local WireGuard address with CIDR (e.g. 10.100.0.1/24)";
              };
              listenPort = mkOption {
                type = types.port;
                default = 51820;
                description = "UDP listen port for WireGuard";
              };
              privateKeyFile = mkOption {
                type = types.path;
                description = "Path to the WireGuard private key file";
              };
              peers = mkOption {
                type = types.listOf wgPeerType;
                default = [ ];
                description = "List of WireGuard peers";
              };
              routes = mkOption {
                type = types.listOf types.str;
                default = [ ];
                description = "Additional route destinations to add for this tunnel";
              };
            };
          };

        in
        {
          imports = [
            inputs.disko.nixosModules.disko
          ];

          # ══════════════════════════════════════════════════════════
          #  MODULE OPTIONS
          #
          #  All user-facing configuration lives under `router.*`.
          #  These options are the public API of this module — consumers
          #  set them in their host configuration to customize the router.
          #
          #  Option groups:
          #    router.hostName / timeZone / stateVersion / diskDevice / bootMode
          #      → Basic system identity and boot configuration.
          #    router.wan.*        → WAN (upstream) interface.
          #    router.lan.*        → LAN bridge, addressing, and DHCP pool.
          #    router.guest.*      → Optional isolated guest network.
          #    router.wireguard.*  → WireGuard VPN tunnel definitions.
          #    router.dns.*        → Upstream DNS, AdGuard Home filtering.
          #    router.suricata.*   → Optional Suricata IPS.
          #    router.cockpit.*    → Optional Cockpit web admin UI.
          #    router.adminUser.*  → SSH admin account.
          #    router.extraPackages → Additional system packages.
          # ══════════════════════════════════════════════════════════
          options.router = {
            hostName = mkOption {
              type = types.str;
              description = "Hostname for the router";
            };

            timeZone = mkOption {
              type = types.str;
              default = "America/New_York";
              description = "System timezone";
            };

            stateVersion = mkOption {
              type = types.str;
              default = "25.11";
              description = "NixOS state version";
            };

            diskDevice = mkOption {
              type = types.str;
              default = "/dev/sda";
              description = "Disk device for disko partitioning";
            };

            bootMode = mkOption {
              type = types.enum [
                "uefi"
                "legacy"
              ];
              default = "uefi";
              description = "Boot mode: uefi (systemd-boot) or legacy (GRUB)";
            };

            # ── WAN ────────────────────────────────────────────────
            # The upstream (internet-facing) interface. This interface is
            # configured as a DHCPv4 client and is the masquerade source
            # for all outbound NAT. It receives the strictest firewall
            # treatment: only established/related traffic, select ICMP
            # types, and WireGuard UDP ports are allowed inbound.
            wan = {
              interface = mkOption {
                type = types.str;
                description = "WAN network interface name (e.g. enp1s0)";
              };
            };

            # ── LAN ────────────────────────────────────────────────
            # The trusted internal network. Physical ports listed in
            # `interfaces` are bridged together under the bridge device.
            # The bridge gets a static IP (the gateway) and serves as
            # the DHCP server and DNS forwarder for all LAN clients.
            #
            # Addressing example:
            #   address        = "192.168.10.1"   (gateway IP)
            #   networkAddress = "192.168.10.0"   (network base)
            #   prefixLength   = 24               (/24 = 254 hosts)
            #   dhcp.poolOffset/poolSize  = 100/151    (DHCP pool)
            lan = {
              interfaces = mkOption {
                type = types.listOf types.str;
                description = "Physical LAN port interface names";
              };

              bridge = mkOption {
                type = types.str;
                default = "br-lan";
                description = "Name of the LAN bridge device";
              };

              address = mkOption {
                type = types.str;
                description = "LAN gateway IP address (e.g. 192.168.10.1)";
              };

              networkAddress = mkOption {
                type = types.str;
                description = "LAN network address (e.g. 192.168.10.0)";
              };

              prefixLength = mkOption {
                type = types.int;
                default = 24;
                description = "LAN subnet prefix length";
              };

              domain = mkOption {
                type = types.str;
                default = "lan";
                description = "Local DNS domain";
              };

              dhcp = {
                poolOffset = mkOption {
                  type = types.int;
                  description = "Offset from network base to first DHCP address (e.g. 100 for .100)";
                };

                poolSize = mkOption {
                  type = types.int;
                  description = "Number of addresses in the DHCP pool (e.g. 151 for .100-.250)";
                };

                leaseTime = mkOption {
                  type = types.str;
                  default = "24h";
                  description = "DHCP lease duration";
                };
              };
            };

            # ── Guest Network ──────────────────────────────────────
            # Optional isolated network for untrusted devices. When enabled:
            #   • A separate bridge (br-guest) is created for guest ports.
            #   • nftables restricts guest traffic to WAN-only (no LAN/WG access).
            #   • Guest clients can reach DHCP (port 67) and DNS (port 53)
            #     on the router, but nothing else on the router itself.
            #   • DNS is hijacked to the local resolver (same as LAN).
            #   • DoT (port 853) is blocked to prevent DNS bypass.
            #   • Shorter default DHCP lease (1h) encourages address rotation.
            guest = {
              enable = mkEnableOption "guest network with client isolation";

              interfaces = mkOption {
                type = types.listOf types.str;
                default = [ ];
                description = "Physical interface names to assign to the guest bridge";
              };

              bridge = mkOption {
                type = types.str;
                default = "br-guest";
                description = "Bridge device name for the guest network";
              };

              address = mkOption {
                type = types.str;
                default = "192.168.20.1";
                description = "Guest gateway IP address";
              };

              networkAddress = mkOption {
                type = types.str;
                default = "192.168.20.0";
                description = "Guest network address (e.g. 192.168.20.0)";
              };

              prefixLength = mkOption {
                type = types.int;
                default = 24;
                description = "Guest subnet prefix length";
              };

              dhcp = {
                poolOffset = mkOption {
                  type = types.int;
                  default = 100;
                  description = "Offset from network base to first guest DHCP address";
                };

                poolSize = mkOption {
                  type = types.int;
                  default = 151;
                  description = "Number of addresses in the guest DHCP pool";
                };

                leaseTime = mkOption {
                  type = types.str;
                  default = "1h";
                  description = "Guest DHCP lease duration (shorter default encourages rotation)";
                };
              };
            };

            # ── WireGuard ──────────────────────────────────────────
            # Attribute set of WireGuard tunnel interfaces. The attribute
            # name becomes the Linux interface name (e.g. wg0, wg-site).
            # For each tunnel, the module automatically:
            #   • Creates the WG interface via networking.wireguard.interfaces.
            #   • Adds a systemd-networkd .network unit with IPv4Forwarding
            #     and relaxed reverse-path filtering.
            #   • Opens the UDP listen port in the nftables WAN input chain.
            #   • Generates bidirectional LAN↔WG and WG→WAN forward rules.
            #   • Includes WG subnets in Suricata's HOME_NET.
            wireguard = mkOption {
              type = types.attrsOf wgInterfaceType;
              default = { };
              description = "WireGuard tunnel interfaces (keys are interface names, e.g. wg0)";
            };

            # ── DNS ────────────────────────────────────────────────
            # DNS resolution pipeline:
            #   1. Clients send queries to the router's LAN/guest IP (:53).
            #   2. AdGuard Home receives on :53 (bound to LAN GW, guest GW,
            #      and 127.0.0.1), applies filter lists, SafeSearch, and
            #      DoH blocking rules.
            #   3. Unblocked queries are forwarded to upstream DoH servers
            #      (Cloudflare, Google by default).
            #   4. Bootstrap servers (plain DNS) are used only to resolve
            #      the DoH server hostnames themselves.
            #
            # DNS bypass prevention (defense-in-depth):
            #   • nftables DNAT: hijacks all port-53 traffic to local resolver.
            #   • nftables DoT block: drops TCP port 853 in forward chain.
            #   • AdGuard user rules: blocks known DoH provider domains.
            #   • Suricata alerts: TLS SNI matching for DoH/DoT providers.
            dns = {
              upstreamServers = mkOption {
                type = types.listOf types.str;
                default = [
                  "https://dns.cloudflare.com/dns-query"
                  "https://dns.google/dns-query"
                ];
                description = "Upstream DNS-over-HTTPS servers for AdGuard";
              };

              bootstrapServers = mkOption {
                type = types.listOf types.str;
                default = [
                  "1.1.1.1"
                  "8.8.8.8"
                ];
                description = "Bootstrap DNS servers for resolving DoH hostnames";
              };

              adguard = {
                enable = mkEnableOption "AdGuard Home DNS filtering";

                listenPort = mkOption {
                  type = types.port;
                  default = 53;
                  description = "DNS listen port for AdGuard Home (default 53, served directly to clients)";
                };

                webPort = mkOption {
                  type = types.port;
                  default = 3000;
                  description = "Web UI port for AdGuard Home";
                };

                safeSearch = mkEnableOption "SafeSearch enforcement";

                standardFilters = {
                  adaway = mkOption {
                    type = types.bool;
                    default = true;
                    description = "AdAway hosts list";
                  };
                  adguard_ads = mkOption {
                    type = types.bool;
                    default = true;
                    description = "AdGuard Base list (ads & trackers)";
                  };
                  adguard_anti_malware = mkOption {
                    type = types.bool;
                    default = true;
                    description = "Dandelion Sprout's Anti-Malware List (filter_12)";
                  };
                  adguard_malware = mkOption {
                    type = types.bool;
                    default = true;
                    description = "AdGuard Malware filter";
                  };
                  adguard_hacked_sites = mkOption {
                    type = types.bool;
                    default = true;
                    description = "The Big List of Hacked Malware Web Sites (filter_9)";
                  };
                  adguard_phishing = mkOption {
                    type = types.bool;
                    default = true;
                    description = "AdGuard Phishing URL Blocklist (filter_18)";
                  };
                  phishtank_openphish = mkOption {
                    type = types.bool;
                    default = true;
                    description = "Phishing Army list based on PhishTank + OpenPhish (filter_30)";
                  };
                  steven_black = mkOption {
                    type = types.bool;
                    default = true;
                    description = "Steven Black's unified hosts file (ads + malware)";
                  };
                  yoyo_adservers = mkOption {
                    type = types.bool;
                    default = true;
                    description = "Peter Lowe's ad/tracker server list (yoyo.org)";
                  };
                };

                extraFilters = mkOption {
                  type = types.listOf (types.attrsOf types.unspecified);
                  default = [ ];
                  description = "Additional custom AdGuard filter list objects (with enabled, name, url, id)";
                };

                utCapitoleCategories = mkOption {
                  type = types.listOf types.str;
                  default = [ ];
                  description = ''
                    UT Capitole blacklist categories to enable as AdGuard filters.
                    Each category name maps to a domain list fetched from
                    https://dsi.ut-capitole.fr/blacklists/download/<category>/domains.
                    See https://dsi.ut-capitole.fr/blacklists/index_en.php for the
                    full list of available categories (e.g. "adult", "malware",
                    "phishing", "gambling", "cryptojacking", "vpn", "dating", etc.).
                  '';
                };

                extraUserRules = mkOption {
                  type = types.listOf types.str;
                  default = [ ];
                  description = "Additional AdGuard user rules (e.g. whitelists)";
                };
              };
            };

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

              extraRules = mkOption {
                type = types.lines;
                default = "";
                description = "Additional Suricata local rules";
              };
            };

            # ── Cockpit web UI ────────────────────────────────────
            # Optional browser-based system administration interface.
            # Accessible from trusted interfaces (LAN + WG) on the
            # configured port (default 9090). The NixOS firewall is not
            # used (openFirewall = false) because nftables already allows
            # all traffic from trusted IFs in the input chain.
            cockpit = {
              enable = mkEnableOption "Cockpit web-based system administration UI";

              port = mkOption {
                type = types.port;
                default = 9090;
                description = "Port for the Cockpit web interface";
              };

              package = mkOption {
                type = types.package;
                default = pkgs.cockpit;
                defaultText = literalExpression "pkgs.cockpit";
                description = "Cockpit package to use";
              };

              plugins = mkOption {
                type = types.listOf types.package;
                default = [ ];
                description = "Additional Cockpit plugin packages";
              };

              allowedOrigins = mkOption {
                type = types.listOf types.str;
                default = [ ];
                description = "Allowed origins for the Cockpit web interface (e.g. [ \"https://router.lan:9090\" ])";
              };

              showBanner = mkOption {
                type = types.bool;
                default = true;
                description = "Show system banner on the Cockpit login page";
              };

              settings = mkOption {
                type =
                  with types;
                  attrsOf (
                    attrsOf (oneOf [
                      bool
                      int
                      str
                    ])
                  );
                default = { };
                description = "Additional cockpit.conf settings as nested attribute set (section → key → value)";
              };
            };

            # ── Admin user ─────────────────────────────────────────
            # The primary admin account. Created as a normal user in the
            # `wheel` group (sudo access). SSH key-only authentication
            # is enforced (password auth disabled in sshd config).
            adminUser = {
              name = mkOption {
                type = types.str;
                default = "admin";
                description = "Admin user account name";
              };

              sshKeys = mkOption {
                type = types.listOf types.str;
                default = [ ];
                description = "SSH public keys for the admin user";
              };

              initialPassword = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "Initial password for the admin user (required for sudo access on first login; should be changed immediately)";
              };
            };

            extraPackages = mkOption {
              type = types.listOf types.package;
              default = [ ];
              description = "Additional packages to install";
            };
          };

          # ══════════════════════════════════════════════════════════
          #  CONFIG IMPLEMENTATION
          #
          #  This section maps the `router.*` options into concrete NixOS
          #  configuration. It is organized into numbered subsections that
          #  correspond to the router's functional layers:
          #
          #   1. Boot & basics     — Bootloader, hostname, timezone, disko.
          #   2. Kernel            — Sysctl tuning, conntrack, kernel modules.
          #   3. systemd-networkd  — WAN/LAN/Guest/WG interface + DHCPServer.
          #   4. nftables          — Stateful firewall, NAT, DNS hijacking.
          #   5. AdGuard Home      — DNS server, filtering, SafeSearch.
          #   6. Suricata          — Inline IPS (optional).
          #   7. Cockpit           — Web admin UI (optional).
          #   8. Packages          — System packages (diagnostic tools, etc.).
          #   9. Logging           — journald size/retention limits.
          #  10. Hardening         — SSH lockdown, sudo policy.
          #  11. Maintenance       — Nix GC, auto-upgrade.
          # ══════════════════════════════════════════════════════════
          config = {

            # ── 1. Boot & basics ─────────────────────────────────
            # Selects between systemd-boot (UEFI) and GRUB (legacy BIOS)
            # based on `router.bootMode`. UEFI mode uses a 1G ESP partition
            # formatted as vfat; legacy mode uses a 1M BIOS boot partition.
            # Both use f2fs for the root filesystem with zstd compression,
            # ATGC garbage collection, and noatime for SSD-friendly operation.
            # mkDefault allows host configs to override without conflicts.
            boot.loader =
              if cfg.bootMode == "uefi" then
                {
                  efi.canTouchEfiVariables = mkDefault true;
                  systemd-boot = {
                    configurationLimit = mkDefault 10;
                    enable = mkDefault true;
                  };
                }
              else
                {
                  grub = {
                    devices = mkForce [ cfg.diskDevice ];
                    efiSupport = false;
                    enable = mkDefault true;
                  };
                };

            networking.hostName = cfg.hostName;
            time.timeZone = cfg.timeZone;

            disko.devices = {
              disk = {
                main = {
                  device = cfg.diskDevice;
                  type = "disk";
                  content =
                    if cfg.bootMode == "uefi" then
                      {
                        type = "gpt";
                        partitions = {
                          ESP = {
                            size = "1G";
                            type = "EF00";
                            content = {
                              type = "filesystem";
                              format = "vfat";
                              mountpoint = "/boot";
                              mountOptions = [
                                "noatime"
                                "umask=0077"
                              ];
                              extraArgs = [
                                "-n"
                                "ESP"
                              ];
                            };
                          };
                          root = {
                            size = "100%";
                            content = {
                              type = "filesystem";
                              format = "f2fs";
                              mountpoint = "/";
                              mountOptions = [
                                "atgc"
                                "compress_algorithm=zstd:1"
                                "compress_cache"
                                "compress_chksum"
                                "compress_extension=*"
                                "gc_merge"
                                "noatime"
                                "nodiscard"
                              ];
                              extraArgs = [
                                "-O"
                                "extra_attr,compression"
                                "-l"
                                "root"
                              ];
                            };
                          };
                        };
                      }
                    else
                      {
                        type = "gpt";
                        partitions = {
                          biosboot = {
                            size = "1M";
                            type = "EF02";
                          };
                          boot = {
                            size = "512M";
                            content = {
                              type = "filesystem";
                              format = "ext4";
                              mountpoint = "/boot";
                              mountOptions = [ "noatime" ];
                              extraArgs = [
                                "-L"
                                "boot"
                              ];
                            };
                          };
                          root = {
                            size = "100%";
                            content = {
                              type = "filesystem";
                              format = "f2fs";
                              mountpoint = "/";
                              mountOptions = [
                                "atgc"
                                "compress_algorithm=zstd:1"
                                "compress_cache"
                                "compress_chksum"
                                "compress_extension=*"
                                "gc_merge"
                                "noatime"
                                "nodiscard"
                              ];
                              extraArgs = [
                                "-O"
                                "extra_attr,compression"
                                "-l"
                                "root"
                              ];
                            };
                          };
                        };
                      };
                };
              };
            };

            # ── 2. Kernel — perf + conntrack ──────────────────
            # Per-interface forwarding and rp_filter are managed by
            # systemd-networkd (IPv4Forwarding, IPv4ReversePathFilter in
            # each .network unit). The sysctl defaults here apply to
            # interfaces not yet configured by networkd (e.g. during early
            # boot or for dynamically created interfaces).
            #
            # Tuning rationale:
            #   rp_filter=1:          Strict reverse-path filtering by default
            #                         (networkd overrides per-interface as needed).
            #   rmem/wmem_max=25MB:   Allows large socket buffers for high-throughput
            #                         forwarding and Suricata packet capture.
            #   netdev_max_backlog:   Increases the per-CPU input queue to handle
            #                         burst traffic without drops.
            #   nf_conntrack_max:     131K entries supports ~65K concurrent NAT
            #                         sessions (each needs 2 conntrack entries).
            boot.kernel.sysctl = {
              "net.ipv4.conf.default.rp_filter" = 1;
              "net.core.rmem_max" = 26214400;
              "net.core.wmem_max" = 26214400;
              "net.core.netdev_max_backlog" = 5000;
              "net.netfilter.nf_conntrack_max" = 131072;
            };

            # nf_conntrack:      Required for stateful NAT and ct state matching
            #                    in nftables rules.
            # nfnetlink_queue:   Required for Suricata's NFQUEUE inline mode.
            #                    Loaded unconditionally so the module is available
            #                    even if Suricata is enabled later without rebuild.
            boot.kernelModules = [
              "nf_conntrack"
              "nfnetlink_queue"
            ];

            # ── 3. systemd-networkd — interfaces + bridge ────────
            # All network configuration is handled by systemd-networkd.
            # NixOS's built-in DHCP, NAT, and firewall are disabled to
            # avoid conflicts with our explicit networkd + nftables setup.
            #
            # Interface topology:
            #   WAN (enp1s0, etc.) ─── DHCPv4 client, strict rp_filter
            #   LAN ports (enp2s0, etc.) ──┐
            #                              ├── br-lan (bridge) ─── static IP (gateway)
            #   LAN ports (enp3s0, etc.) ──┘
            #   Guest ports ──── br-guest (bridge) ─── static IP (gateway)
            #   WireGuard (wg0, etc.) ─── tunnel IP, forwarding enabled
            networking = {
              useNetworkd = true;
              useDHCP = false;
              nat.enable = false;
              firewall.enable = false;
            };

            systemd.network = {
              enable = true;
              # Don't block boot waiting for all interfaces — any one is enough.
              wait-online.anyInterface = true;

              # ── Virtual devices (bridges) ──────────────────────
              # The LAN bridge aggregates physical LAN ports into a single
              # L2 domain. Guest bridge is created only when guest.enable = true.
              netdevs = {
                "20-br-lan" = {
                  netdevConfig = {
                    Kind = "bridge";
                    Name = brLAN;
                  };
                };
              }
              // optionalAttrs cfg.guest.enable {
                "21-br-guest" = {
                  netdevConfig = {
                    Kind = "bridge";
                    Name = brGuest;
                  };
                };
              };

              # ── Network units ────────────────────────────────────
              networks = {
                # WAN interface: DHCP client for upstream connectivity.
                # • IPv4Forwarding: enables kernel forwarding sysctl for this IF.
                # • IPv4ReversePathFilter=strict: drops packets with spoofed
                #   source addresses (BCP38/RFC3704 compliance).
                # • IPv6AcceptRA=false: no IPv6 on WAN (IPv4-only deployment).
                # • IgnoreCarrierLoss=3s: tolerates brief cable/modem blips
                #   without tearing down DHCP lease and routes.
                # • KeepConfiguration=dynamic-on-stop: preserves DHCP addresses
                #   and routes during networkd restarts (avoids brief outages).
                # • dhcpV4Config: prevents ISP DHCP from overriding local DNS
                #   (UseDNS/UseHostname/UseDomains=false), while still sending
                #   our hostname to the ISP for lease identification.
                #   RouteMetric=100 gives WAN routes explicit priority.
                "10-wan" = {
                  matchConfig.Name = cfg.wan.interface;
                  networkConfig = {
                    DHCP = "ipv4";
                    IPv4Forwarding = true;
                    IPv4ReversePathFilter = "strict";
                    IPv6AcceptRA = false;
                    IgnoreCarrierLoss = "3s";
                    KeepConfiguration = "dynamic-on-stop";
                  };
                  dhcpV4Config = {
                    UseDNS = false;
                    UseHostname = false;
                    UseDomains = false;
                    SendHostname = true;
                    RouteMetric = 100;
                  };
                  linkConfig.RequiredForOnline = "routable";
                };

                # LAN bridge member ports: enslaved to br-lan.
                # • ConfigureWithoutCarrier: allow networkd to configure the
                #   port even when no cable is plugged in.
                # • LinkLocalAddressing=no: bridge members don't need their own
                #   IP addresses — the bridge device itself handles addressing.
                # • IPv6AcceptRA=false: prevents rogue RA attacks on LAN ports.
                # • RequiredForOnline=enslaved: port is "online" when joined
                #   to the bridge, even without an IP address.
                "30-lan-ports" = {
                  matchConfig.Name = concatStringsSep " " cfg.lan.interfaces;
                  networkConfig = {
                    Bridge = brLAN;
                    ConfigureWithoutCarrier = true;
                    LinkLocalAddressing = "no";
                    IPv6AcceptRA = false;
                  };
                  linkConfig.RequiredForOnline = "enslaved";
                };

                # LAN bridge: the router's internal gateway interface.
                # • Static IP address (lanGW/lanPrefix) — this is the default
                #   gateway and DNS server for all LAN clients.
                # • DHCPServer=true: networkd serves DHCP directly on the bridge,
                #   eliminating startup-ordering issues with external DHCP daemons.
                # • dhcpServerConfig: pool range computed from rangeStart/rangeEnd,
                #   DNS points clients to the gateway (dnsmasq on :53), EmitRouter
                #   auto-advertises the bridge IP as the default gateway.
                # • ConfigureWithoutCarrier: keeps config stable even if all
                #   physical ports are unplugged momentarily.
                # • IPv4Forwarding: enables IP forwarding on this interface.
                # • IPv4ReversePathFilter=no: relaxed because traffic arrives
                #   from bridged ports with various source subnets.
                # • IPv6AcceptRA=false: blocks rogue IPv6 RAs on the bridge.
                # • LLDP=routers-only: receives LLDP from connected switches
                #   (query via `networkctl lldp` for topology discovery).
                # • EmitLLDP=nearest-bridge: announces this router to directly
                #   connected switches for identification.
                # • RequiredForOnline=no: boot doesn't wait for this interface.
                "40-br-lan" = {
                  matchConfig.Name = brLAN;
                  address = [ "${lanGW}/${lanPrefix}" ];
                  networkConfig = {
                    ConfigureWithoutCarrier = true;
                    DHCPServer = true;
                    IPv4Forwarding = true;
                    IPv4ReversePathFilter = "no";
                    IPv6AcceptRA = false;
                    LLDP = "routers-only";
                    EmitLLDP = "nearest-bridge";
                  };
                  dhcpServerConfig = {
                    PoolOffset = cfg.lan.dhcp.poolOffset;
                    PoolSize = cfg.lan.dhcp.poolSize;
                    DefaultLeaseTimeSec = cfg.lan.dhcp.leaseTime;
                    DNS = [ lanGW ];
                    EmitDNS = true;
                    EmitRouter = true;
                  };
                  linkConfig.RequiredForOnline = "no";
                };
              }
              # WireGuard tunnel network units: generated dynamically from
              # `router.wireguard` entries. Each tunnel gets forwarding
              # enabled and relaxed rp_filter (WG traffic arrives from the
              # tunnel, not the physical interface the route points to).
              // listToAttrs (
                imap0 (
                  i: name:
                  let
                    wg = cfg.wireguard.${name};
                  in
                  nameValuePair "50-${name}" {
                    matchConfig.Name = name;
                    address = [ wg.address ];
                    routes = map (dest: { Destination = dest; }) wg.routes;
                    networkConfig = {
                      IPv4Forwarding = true;
                      IPv4ReversePathFilter = "no";
                    };
                    linkConfig.RequiredForOnline = "no";
                  }
                ) wgNames
              )
              # Guest network units (only when guest.enable = true):
              # Same pattern as LAN — member ports enslaved to bridge,
              # bridge gets static IP. LLDP enabled for topology visibility.
              // optionalAttrs cfg.guest.enable {
                # Guest bridge member ports — same rationale as LAN ports.
                "31-guest-ports" = {
                  matchConfig.Name = concatStringsSep " " cfg.guest.interfaces;
                  networkConfig = {
                    Bridge = brGuest;
                    ConfigureWithoutCarrier = true;
                    LinkLocalAddressing = "no";
                    IPv6AcceptRA = false;
                  };
                  linkConfig.RequiredForOnline = "enslaved";
                };
                # Guest bridge — same config pattern as br-lan, but on
                # a separate subnet. nftables isolates guest from LAN/WG.
                # DHCPServer config mirrors LAN but with guest-specific pool
                # and shorter lease time for address rotation.
                "41-br-guest" = {
                  matchConfig.Name = brGuest;
                  address = [ "${guestGW}/${guestPrefix}" ];
                  networkConfig = {
                    ConfigureWithoutCarrier = true;
                    DHCPServer = true;
                    IPv4Forwarding = true;
                    IPv4ReversePathFilter = "no";
                    IPv6AcceptRA = false;
                    LLDP = "routers-only";
                    EmitLLDP = "nearest-bridge";
                  };
                  dhcpServerConfig = {
                    PoolOffset = cfg.guest.dhcp.poolOffset;
                    PoolSize = cfg.guest.dhcp.poolSize;
                    DefaultLeaseTimeSec = cfg.guest.dhcp.leaseTime;
                    DNS = [ guestGW ];
                    EmitDNS = true;
                    EmitRouter = true;
                  };
                  linkConfig.RequiredForOnline = "no";
                };
              };
            };

            # ── WireGuard interfaces ─────────────────────────────
            # Creates WireGuard tunnel interfaces using NixOS's built-in
            # wireguard module. Each `router.wireguard.<name>` entry becomes
            # a kernel WG interface. The `optionalAttrs` block only includes
            # the `endpoint` field when it's non-null, supporting both
            # client-initiated (endpoint set) and server-only (endpoint null)
            # peer configurations.
            networking.wireguard.interfaces = mapAttrs (name: wg: {
              ips = [ wg.address ];
              listenPort = wg.listenPort;
              privateKeyFile = wg.privateKeyFile;
              peers = map (
                p:
                {
                  publicKey = p.publicKey;
                  allowedIPs = p.allowedIPs;
                  persistentKeepalive = p.persistentKeepalive;
                }
                // optionalAttrs (p.endpoint != null) {
                  endpoint = p.endpoint;
                }
              ) wg.peers;
            }) cfg.wireguard;

            # ── 4. nftables ──────────────────────────────────────
            # The complete firewall ruleset generated from `nftRuleset` above.
            # See the nftRuleset generation section in the `let` block for
            # detailed documentation of each table and chain.
            networking.nftables = {
              enable = true;
              ruleset = nftRuleset;
            };

            # ── 5. DNS server — AdGuard Home ─────────────────────
            # AdGuard Home is the primary DNS server for all networks.
            # It listens directly on :53 on the LAN gateway, guest gateway
            # (if enabled), and 127.0.0.1 (for the router itself).
            # Clients reach it directly — no intermediary forwarder needed.
            #
            # Configuration includes:
            #   • dns.bind_hosts: LAN GW + guest GW + loopback for full coverage.
            #   • dns.protection/filtering_enabled: master switches for blocking.
            #   • dns.rate_limit=0: no per-client rate limiting.
            #   • dns.cache: 4MB cache with 5min-24h TTL bounds for performance.
            #   • dns.rewrites: maps router hostname to LAN gateway IP.
            #   • safe_search: forces SafeSearch on major search engines/YouTube
            #     by rewriting DNS responses to safe variants.
            #   • filters: combination of standard lists, UT Capitole categories,
            #     and user-supplied extra filters.
            #   • user_rules: DoH provider blocking rules + user extras.
            #   • mutableSettings=true: allows runtime changes via the AGH web UI
            #     (persisted to /var/lib/AdGuardHome/AdGuardHome.yaml).
            #
            # The router's own DNS is set to 127.0.0.1 so it also uses AGH.
            networking.nameservers = [ "127.0.0.1" ];

            services.adguardhome = mkIf cfg.dns.adguard.enable {
              enable = true;
              mutableSettings = true;
              host = lanGW;
              port = cfg.dns.adguard.webPort;
              settings = {

                dns = {
                  bind_hosts = [
                    "127.0.0.1"
                    lanGW
                  ]
                  ++ optional cfg.guest.enable guestGW;
                  port = cfg.dns.adguard.listenPort;
                  upstream_dns = cfg.dns.upstreamServers;
                  bootstrap_dns = cfg.dns.bootstrapServers;
                  protection_enabled = true;
                  filtering_enabled = true;
                  rate_limit = 0;
                  cache_size = 4194304;
                  cache_ttl_min = 300;
                  cache_ttl_max = 86400;
                  rewrites = [
                    {
                      domain = "${cfg.hostName}.${cfg.lan.domain}";
                      answer = lanGW;
                    }
                  ];
                };

                safe_search = mkIf cfg.dns.adguard.safeSearch {
                  enabled = true;
                  bing = true;
                  duckduckgo = true;
                  google = true;
                  pixabay = true;
                  yandex = true;
                  youtube = true;
                };

                filters = standardFilters ++ utCapitoleFilters ++ cfg.dns.adguard.extraFilters;

                user_rules = dohBlockRules ++ cfg.dns.adguard.extraUserRules;
              };
            };

            # ── 6. IPS — Suricata ────────────────────────────────
            # When enabled, Suricata runs as an inline IPS via NFQUEUE.
            # The config is placed in /etc/suricata/ via environment.etc,
            # and a systemd service handles startup, rule updates, and
            # log rotation.
            #
            # Startup sequence (ExecStartPre):
            #   1. Create rule/log directories.
            #   2. Copy local.rules from /etc (Nix-managed) to /var/lib
            #      (writable location Suricata expects).
            #   3. Run suricata-update to fetch/merge ET Open rules.
            #
            # The service is hardened with:
            #   • ProtectSystem=strict + explicit ReadWritePaths for logs/state.
            #   • CAP_NET_ADMIN + CAP_NET_RAW for packet capture.
            #   • NoNewPrivileges + PrivateTmp for isolation.
            #
            # A daily timer (suricata-update.timer) refreshes ET Open rules
            # with a randomized delay to avoid thundering herd on update servers.
            environment.etc = mkIf cfg.suricata.enable {
              "suricata/suricata.yaml".source = yamlFormat.generate "suricata.yaml" suricataConfig;
              "suricata/rules/local.rules".text = localSuricataRules;
            };

            # Bypass cockpit-tls: have the socket hand connections directly
            # to cockpit-ws (plain HTTP) instead of cockpit-tls.
            # Suricata services are also defined here (conditional on enable).
            systemd.services = mkMerge [
              (mkIf cfg.cockpit.enable {
                cockpit-ws = {
                  overrideStrategy = "asDropin";
                  serviceConfig.ExecStart = [
                    "" # clear the default ExecStart
                    "${cfg.cockpit.package}/libexec/cockpit-ws --no-tls --port ${toString cfg.cockpit.port}"
                  ];
                };
              })
              (mkIf cfg.suricata.enable {
                suricata = {
                  description = "Suricata IPS";
                  after = [ "network-online.target" ];
                  wants = [ "network-online.target" ];
                  wantedBy = [ "multi-user.target" ];
                  serviceConfig = {
                    ExecStartPre = [
                      "${pkgs.coreutils}/bin/mkdir -p /var/lib/suricata/rules /var/log/suricata"
                      "${pkgs.coreutils}/bin/cp /etc/suricata/rules/local.rules /var/lib/suricata/rules/local.rules"
                      "${pkgs.suricata}/bin/suricata-update --no-test --no-reload"
                    ];
                    ExecStart = "${pkgs.suricata}/bin/suricata -c /etc/suricata/suricata.yaml -q 0 --pidfile /run/suricata.pid";
                    ExecReload = "${pkgs.coreutils}/bin/kill -USR2 $MAINPID";
                    Type = "simple";
                    Restart = "on-failure";
                    RestartSec = "10s";
                    LimitNOFILE = 65536;
                    ProtectHome = true;
                    ProtectSystem = "strict";
                    ReadWritePaths = [
                      "/var/log/suricata"
                      "/var/lib/suricata"
                      "/run"
                    ];
                    CapabilityBoundingSet = [
                      "CAP_NET_ADMIN"
                      "CAP_NET_RAW"
                      "CAP_SYS_NICE"
                    ];
                    AmbientCapabilities = [
                      "CAP_NET_ADMIN"
                      "CAP_NET_RAW"
                    ];
                    NoNewPrivileges = true;
                    PrivateTmp = true;
                  };
                };

                suricata-update = {
                  description = "Update Suricata ET Open rules";
                  serviceConfig = {
                    Type = "oneshot";
                    ExecStart = "${pkgs.suricata}/bin/suricata-update --no-test";
                    ExecStartPost = "${pkgs.systemd}/bin/systemctl reload suricata.service";
                  };
                };
              })
            ];

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

            # ── 7. Web UI — Cockpit ─────────────────────────────
            # Cockpit provides a browser-based admin interface for system
            # monitoring, service management, and terminal access. It's
            # only accessible from trusted networks (LAN + WG) via the
            # nftables input chain — openFirewall is disabled since we
            # manage access through nftables, not the NixOS firewall.
            services.cockpit = mkIf cfg.cockpit.enable {
              enable = true;
              port = cfg.cockpit.port;
              package = cfg.cockpit.package;
              plugins = cfg.cockpit.plugins;
              openFirewall = false; # managed by nftables (LAN/WG already accepted)
              showBanner = cfg.cockpit.showBanner;
              "allowed-origins" = cfg.cockpit.allowedOrigins;
              settings = mkMerge [
                cfg.cockpit.settings
                {
                  WebService = {
                    AllowUnencrypted = true;
                  };
                }
              ];
            };

            # ── 8. Packages ──────────────────────────────────────
            # Baseline diagnostic tools for router troubleshooting:
            #   tcpdump:        Packet capture and analysis.
            #   htop:           Interactive process/resource monitor.
            #   ethtool:        NIC diagnostics (link speed, offloading, etc.).
            #   iftop:          Real-time per-connection bandwidth monitor.
            #   conntrack-tools: Inspect/manage the nf_conntrack table.
            #   jq:             JSON processing (useful for Suricata eve.json).
            #   iperf3:         Network throughput testing.
            # Suricata and wireguard-tools are added conditionally.
            environment.systemPackages =
              with pkgs;
              [
                tcpdump
                htop
                ethtool
                iftop
                conntrack-tools
                jq
                iperf3
              ]
              ++ optional cfg.suricata.enable suricata
              ++ optional (cfg.wireguard != { }) wireguard-tools
              ++ cfg.extraPackages;

            # ── 9. Logging ──────────────────────────────────────
            # Cap journald storage to 500MB and 30 days to prevent the
            # system journal from consuming all disk space on routers
            # with limited storage (common with eMMC/SSD appliances).
            services.journald.extraConfig = ''
              SystemMaxUse=500M
              MaxRetentionSec=30day
            '';

            # ── 10. Hardening ────────────────────────────────────
            # SSH is the primary remote management interface. Security:
            #   • PermitRootLogin=prohibit-password: root can only auth via
            #     key (prevents brute-force; useful for emergency recovery).
            #   • PasswordAuthentication=false: keys only for all users.
            #   • KbdInteractiveAuthentication=false: disables challenge-response.
            #   • openFirewall=false: access controlled by nftables (trusted IFs).
            #   • wheelNeedsPassword=true: sudo requires the user's password
            #     even for wheel group members (defense against stolen SSH keys).
            services.openssh = {
              enable = true;
              settings = {
                PermitRootLogin = "prohibit-password";
                PasswordAuthentication = false;
                KbdInteractiveAuthentication = false;
              };
              openFirewall = false;
            };

            security.sudo.wheelNeedsPassword = true;

            users.users.${cfg.adminUser.name} = {
              isNormalUser = true;
              extraGroups = [ "wheel" ];
              initialPassword = cfg.adminUser.initialPassword;
              openssh.authorizedKeys.keys = cfg.adminUser.sshKeys;
            };

            # ── 11. Maintenance ──────────────────────────────────
            # Automated housekeeping:
            #   • Nix GC: weekly cleanup of store paths older than 30 days.
            #     Keeps disk usage bounded on long-running routers.
            #   • Auto-upgrade: daily check for NixOS updates at 04:00.
            #     allowReboot=false by default — upgrades apply on next
            #     manual reboot (safe for headless routers).
            #   • Flakes + nix-command enabled for modern Nix CLI.
            nix = {
              gc = {
                automatic = true;
                dates = "weekly";
                options = "--delete-older-than 30d";
              };
              settings.experimental-features = [
                "nix-command"
                "flakes"
              ];
            };

            system = {
              autoUpgrade = {
                enable = mkDefault true;
                allowReboot = mkDefault false;
                dates = mkDefault "04:00";
              };
              stateVersion = cfg.stateVersion;
            };
          };
        };
    };

}
