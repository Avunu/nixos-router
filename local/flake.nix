{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nixos-router = {
      url = "github:Avunu/nixos-router";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      nixos-router,
    }:
    let
      hostName = "948-router";
      system = "x86_64-linux";
    in
    {
      nixosConfigurations = {
        "${hostName}" = nixpkgs.lib.nixosSystem {
          system = system;
          modules = [
            { nix.nixPath = [ "nixpkgs=${self.inputs.nixpkgs}" ]; }
            nixos-router.nixosModules.router
            {
              router = {
                hostName = hostName;
                timeZone = "America/New_York";
                stateVersion = "26.11";
                diskDevice = "/dev/sda";
                bootMode = "legacy";

                # ── WAN ──────────────────────────────────────────
                wan.interface = "enp0s20f0";

                # ── LAN ──────────────────────────────────────────
                lan = {
                  interfaces = [
                    "enp0s20f1"
                    "enp0s20f2"
                    "enp0s20f3"
                    "ens2"
                    "enp4s0"
                    "enp7s0"
                    "enp8s0"
                  ];
                  address = "10.48.4.1";
                  networkAddress = "10.48.4.0";
                  prefixLength = 24;
                  domain = "lan";
                  dhcp = {
                    poolOffset = 100;
                    poolSize = 150;
                    leaseTime = "30d";
                  };
                };

                # ── Guest network ─────────────────────────────────
                # Each network (wan/lan/guest) is assigned physical `interfaces`
                # for UNTAGGED traffic (exclusive — one owner per port) and/or a
                # `vlan` id for TAGGED traffic. A VLAN tag is carried only on the
                # explicit ports: the global `trunkInterfaces` (implicit for all)
                # plus that network's own `taggedInterfaces`.
                #
                # Here guest has no `interfaces`; it rides as tagged VLAN 20 over
                # the LAN ports listed in `taggedInterfaces` (adjust to match the
                # ports your VLAN-aware switch trunks guest traffic on).
                #
                # Single-NIC variant (e.g. a Pi behind a smart switch that
                # delivers every network as a tagged VLAN on one cable):
                #   trunkInterfaces = [ "eth0" ];
                #   wan = { interface = null; vlan = 10; };
                #   lan = { vlan = 20; address = "10.48.4.1"; ... };
                #   guest = { enable = true; vlan = 30; ... };
                guest = {
                  enable = true;
                  vlan = 20;
                  taggedInterfaces = [
                    "enp0s20f1"
                    "enp0s20f2"
                    "enp0s20f3"
                    "ens2"
                    "enp4s0"
                    "enp7s0"
                    "enp8s0"
                  ];
                  address = "192.168.20.1";
                  networkAddress = "192.168.20.0";
                  prefixLength = 24;
                  dhcp = {
                    poolOffset = 100;
                    poolSize = 150;
                    leaseTime = "1h";
                  };
                };

                # ── WireGuard tunnels (multiple supported) ───────
                # wireguard = {
                #   wg0 = {
                #     address = "10.100.0.1/24";
                #     listenPort = 51820;
                #     privateKeyFile = "/etc/wireguard/wg0.key";
                #     routes = [ "10.20.0.0/24" ];
                #     peers = [
                #       {
                #         publicKey = "PEER_PUBLIC_KEY_HERE";
                #         endpoint = "remote-office.example.com:51820";
                #         allowedIPs = [
                #           "10.100.0.0/24"
                #           "10.20.0.0/24"
                #         ];
                #         persistentKeepalive = 25;
                #       }
                #     ];
                #   };

                #   Example: second WireGuard tunnel
                #   wg1 = {
                #     address       = "10.200.0.1/24";
                #     listenPort    = 51821;
                #     privateKeyFile = "/etc/wireguard/wg1.key";
                #     routes = [ "10.30.0.0/24" ];
                #     peers = [
                #       {
                #         publicKey   = "OTHER_PEER_PUBLIC_KEY";
                #         endpoint    = "branch-office.example.com:51821";
                #         allowedIPs  = [ "10.200.0.0/24" "10.30.0.0/24" ];
                #         persistentKeepalive = 25;
                #       }
                #     ];
                #   };
                # };

                # ── DNS & filtering ──────────────────────────────
                dns = {
                  upstreamServers = [
                    "https://dns.cloudflare.com/dns-query"
                    "https://dns.google/dns-query"
                  ];
                  bootstrapServers = [
                    "1.1.1.1"
                    "8.8.8.8"
                  ];

                  adguard = {
                    enable = true;
                    webPort = 3000;
                    safeSearch = true;
                    # UT Capitole blacklist categories to block in addition to ads.
                    # Full category list: https://dsi.ut-capitole.fr/blacklists/index_en.php
                    utCapitoleCategories = [
                      "malware"
                      "phishing"
                      "cryptojacking"
                      "ddos"
                      "porn"
                      # "gambling"
                      # "vpn"
                      # "dating"
                      # "social_networks"
                      # "warez"
                      # "hacking"
                    ];
                    standardFilters = {
                      adaway = true;
                      adguard_ads = true;
                      adguard_anti_malware = true;
                      adguard_hacked_sites = true;
                      adguard_malware = true;
                      adguard_phishing = true;
                      phishtank_openphish = true;
                      steven_black = true;
                      yoyo_adservers = true;
                    };
                    allowList = [
                      "supabase.com" # blocked by utcapitole
                    ];
                  };
                };

                # ── Suricata IPS ─────────────────────────────────
                suricata = {
                  enable = true;
                  extraRules = "";
                };

                # ── Cockpit web UI ───────────────────────────────
                cockpit = {
                  enable = true;
                  port = 9090;
                  # plugins = [ pkgs.cockpit-machines ];
                  allowedOrigins = [ "https://948-router.lan:9090" ];
                };

                # ── Admin user ───────────────────────────────────
                adminUser = {
                  name = "admin";
                  sshKeys = [
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILtMd4jTM9A36iVI2R6zw8cApkd7HQExr0ayfHcwaOp/"
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOv4SpIhHJqtRaYBRQOin4PTDUxRwo7ozoQHTUFjMGLW"
                  ];
                  initialPassword = "admin123"; # Change this immediately after first login
                };

                extraPackages = with nixpkgs.legacyPackages.${system}; [
                  # Add any additional packages here
                ];
              };
            }
          ];
        };
      };
    };
}
