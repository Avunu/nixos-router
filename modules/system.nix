# ── System module ─────────────────────────────────────────────────────────────
# The host platform layer: image slimming, boot/disko, kernel/sysctl tuning,
# system identity, the Cockpit web UI (which installs the in-repo router plugin),
# packages, journald limits, SSH/sudo hardening, the admin user, Nix GC /
# auto-upgrade, and the /etc/router/effective.json snapshot the Cockpit UI reads.
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
  # Network topology (interface names, CIDRs, the VLAN/port model, and
  # the networkd-unit helpers) is computed once in modules/topology.nix
  # and exposed via `config.router._internal`. Re-bind the names here so
  # the config implementation below keeps reading them unqualified.
  t = config.router._internal;
  inherit (t)
    brLAN
    lanGW
    lanPrefix
    lanCIDR
    wgNames
    wgInterfaces
    wgIFNames
    lanNets
    wgNets
    guestNets
    allHomeNets
    homeNets
    nftSet
    trustedIFs
    ;

  # cockpitRouterPlugin:
  #   The in-repo Cockpit plugin (pkg/cockpit-router) that adds
  #   router-specific views (connected hosts, Suricata + AdGuard
  #   events, network diagnostics) to Cockpit. Installed via the
  #   services.cockpit.plugins hook. The AdGuard web port is passed
  #   in so the plugin can reach the local AGH REST API.
  cockpitRouterPlugin = pkgs.callPackage ../pkg/cockpit-router/package.nix {
    adguardPort = cfg.dns.adguard.webPort;
    hostName = cfg.hostName;
    flakePath = cfg.cockpit.flakePath;
    settingsFile = cfg.cockpit.settingsFile;
  };

  # Keys of the cockpit-managed router config exposed to the web UI as
  # /etc/router/effective.json. Everything serializable; package-typed
  # options (extraPackages, cockpit.package/plugins) are intentionally
  # excluded — those stay in Nix.
  effectiveKeys = [
    "hostName"
    "timeZone"
    "stateVersion"
    "diskDevice"
    "bootMode"
    "trunkInterfaces"
    "wan"
    "lan"
    "guest"
    "wireguard"
    "dns"
    "suricata"
    "upnp"
    "portForwards"
    "adminUser"
  ];

  # ── Network topology (continued) ────────────────────────
  # Guest CIDRs, the VLAN/port assignment model, and the networkd-unit
  # helpers also come from modules/topology.nix (see config.router._internal).
  inherit (t)
    brGuest
    guestGW
    guestPrefix
    guestCIDR
    wanPhys
    lanPhys
    guestPhys
    ownedPorts
    netList
    vlanIds
    vlanChild
    childrenOf
    allChildren
    allPhys
    childrenOnPort
    wanIsBridged
    brWAN
    wanIf
    wanNetworkBase
    directWanPort
    parentPorts
    ownerOf
    ownerBridgeOf
    childBridgeOf
    mkPortUnit
    ;

in
{
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

      flakePath = mkOption {
        type = types.str;
        default = "/etc/nixos";
        description = ''
          Path to the host flake on the deployed router. The Cockpit
          router plugin runs `nixos-rebuild --flake <flakePath>#<hostName>`
          from the System page (and the changes tray's Apply).
        '';
      };

      settingsFile = mkOption {
        type = types.str;
        default = "/etc/nixos/router-settings.json";
        description = ''
          Path to the editable JSON config the Cockpit plugin reads and
          writes. The host flake feeds this same file into the router
          module with `router = builtins.fromJSON (builtins.readFile ...)`,
          so changes saved from the web UI take effect on the next rebuild.
          Only used to tell the plugin where the file lives — the module
          itself does not read it.
        '';
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

    # ── 0. Image slimming ────────────────────────────────
    # A router has no users, GUI, fonts, or need for RAID/exotic
    # filesystems.  Stripping these reduces the system closure
    # size and attack surface.

    # Disable filesystems the router never mounts.  Only f2fs
    # (root), vfat (ESP), and ext4 (legacy /boot) are needed.
    boot.supportedFilesystems = {
      btrfs = mkForce false;
      cifs = mkForce false;
      ntfs = mkForce false;
      xfs = mkForce false;
      zfs = mkForce false;
    };

    # No software RAID; the router is single-disk by design.
    boot.swraid.enable = mkForce false;

    # No Bluetooth hardware targeted by this module.
    hardware.bluetooth.enable = mkDefault false;

    # Documentation is never read on a headless router and adds
    # ~200MB to the closure; disable all of it.
    documentation = {
      doc.enable = false;
      info.enable = false;
      man.enable = false;
      nixos.enable = false;
    };

    # NixOS ships a small set of default packages (nano, perl, etc.)
    # that are unnecessary on a dedicated router appliance.
    environment.defaultPackages = mkForce [ ];

    # Fonts serve no purpose on a headless system.
    fonts.fontconfig.enable = false;

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
      "net.ipv6.conf.all.forwarding" = 1;
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

    # The cockpit-router plugin reads /etc/router/effective.json to show
    # the *applied* config (defaults + Nix overrides) and to detect which
    # fields are locked in Nix. Root-only because it includes secrets
    # (adminUser.initialPassword, ssh keys). The plugin also writes an
    # "applied" snapshot to /var/lib/cockpit-router for the changes tray.
    environment.etc."router/effective.json" = mkIf cfg.cockpit.enable {
      mode = "0600";
      text = builtins.toJSON (genAttrs effectiveKeys (k: cfg.${k}));
    };

    systemd.services.flake-update = {
      unitConfig = {
        Description = "Update flake inputs";
        StartLimitIntervalSec = 300;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        ExecStart = "${pkgs.nix}/bin/nix flake update --flake /etc/nixos/";
        Restart = "on-failure";
        RestartSec = "30";
        Type = "oneshot"; # Ensure that it finishes before starting nixos-upgrade
        User = "root";
      };
      after = [ "network-online.target" ];
      before = [ "nixos-upgrade.service" ];
      requiredBy = [ "nixos-upgrade.service" ];
      wants = [ "network-online.target" ];
      path = [
        pkgs.nix
        pkgs.git
        pkgs.host
      ];
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
      plugins = [ cockpitRouterPlugin ] ++ cfg.cockpit.plugins;
      openFirewall = false; # managed by nftables (LAN/WG already accepted)
      showBanner = cfg.cockpit.showBanner;
      settings = mkMerge [
        cfg.cockpit.settings
        {
          WebService = {
            AllowUnencrypted = true;
            Origins = mkForce (
              builtins.concatStringsSep " " (
                [
                  "https://${lanGW}"
                  "https://${lanGW}:${toString cfg.cockpit.port}"
                  "https://${cfg.hostName}.local"
                  "https://${cfg.hostName}.local:${toString cfg.cockpit.port}"
                  "https://${cfg.hostName}.${cfg.lan.domain}"
                  "https://${cfg.hostName}.${cfg.lan.domain}:${toString cfg.cockpit.port}"
                ]
                ++ cfg.cockpit.allowedOrigins
              )
            );
            ListenAddress = "0.0.0.0";
          };
        }
      ];
    };

    # State dir for the cockpit-router plugin's "applied config" snapshot
    # (written by the web UI after a successful rebuild; drives the
    # unapplied-changes tray). Root-only — may mirror secrets.
    systemd.tmpfiles.rules = mkIf cfg.cockpit.enable [
      "d /var/lib/cockpit-router 0700 root root -"
    ];

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
        conntrack-tools
        ethtool
        htop
        iftop
        iperf3
        jq
        service-wrapper
        tcpdump
      ]
      ++ [
        # Update flake inputs and rebuild. Clears any hung rebuild/upgrade
        # units first (a stuck switch-to-configuration leaves the next
        # rebuild blocked). Targets the router's configured flake path and
        # host by default; override as `system-upgrade [FLAKE] [HOST]`.
        # Also invoked by the Cockpit System page ("Update system").
        (writeShellScriptBin "system-upgrade" ''
          set -euo pipefail

          FLAKE="''${1:-${cfg.cockpit.flakePath}}"
          HOST="''${2:-${cfg.hostName}}"

          # Run privileged steps via sudo from an admin shell; when already
          # root (e.g. invoked from Cockpit) run them directly so there is
          # no password prompt.
          as_root() {
            if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
          }

          echo ":: Clearing any hung rebuild/upgrade units"
          for unit in nixos-rebuild-switch-to-configuration.service nixos-upgrade.service; do
            as_root systemctl stop "$unit" 2>/dev/null || true
            as_root systemctl reset-failed "$unit" 2>/dev/null || true
          done
          as_root systemctl daemon-reload

          echo ":: Updating flake inputs in $FLAKE"
          as_root nix flake update --flake "$FLAKE"

          echo ":: Rebuilding and switching to $FLAKE#$HOST"
          as_root nixos-rebuild switch --flake "$FLAKE#$HOST" --impure

          echo ":: system-upgrade complete"
        '')
        # migrate script to convert legacy router configs to the new flake-based format
        (writeShellScriptBin "migrate-router-config" ''
          set -euo pipefail
          nix eval --impure --json --expr '(removeAttrs (import /etc/nixos/router-settings.nix).router [ "extraPackages" "cockpit" ])' | jq . > /etc/nixos/router-settings.json
        '')
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
        # Same flake target as the `system-upgrade` script and the Cockpit
        # System page (router.cockpit.flakePath), so all three rebuild from
        # one configured location instead of a hardcoded path.
        flake = "${cfg.cockpit.flakePath}#${cfg.hostName}";
        allowReboot = mkDefault true;
        flags = mkDefault [
          "--refresh"
          "--update-input"
          "nixpkgs"
          "--update-input"
          "nixos-router"
        ];
        dates = mkDefault "03:00";
      };
      stateVersion = cfg.stateVersion;
    };
  };
}
