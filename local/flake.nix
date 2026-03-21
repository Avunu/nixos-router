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
      hostName = "258-router";
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
                  ];
                  bridge = "br-lan";
                  address = "10.58.1.20";
                  networkAddress = "10.58.1.0";
                  prefixLength = 24;
                  domain = "lan";
                  dhcp = {
                    rangeStart = "10.58.1.100";
                    rangeEnd = "10.58.1.250";
                    leaseTime = "30d";
                  };
                };

                # ── Guest network ─────────────────────────────────
                guest = {
                  enable = true;
                  interfaces = [
                    "enp0s20f2"
                    "enp0s20f3"
                    "ens2"
                    "enp4s0"
                    "enp7s0"
                    "enp8s0"
                  ]; # physical ports for guest
                  bridge = "br-guest";
                  address = "192.168.20.1";
                  networkAddress = "192.168.20.0";
                  prefixLength = 24;
                  dhcp = {
                    rangeStart = "192.168.20.100";
                    rangeEnd = "192.168.20.250";
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
                    listenPort = 5353;
                    webPort = 3000;
                    safeSearch = true;
                    # UT Capitole blacklist categories to block in addition to ads.
                    # Full category list: https://dsi.ut-capitole.fr/blacklists/index_en.php
                    utCapitoleCategories = [
                      "malware"
                      "phishing"
                      "cryptojacking"
                      "ddos"
                      # "adult"
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
                    extraUserRules = [
                      # "@@||example.com^"   # office whitelists
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
                  # allowedOrigins = [ "https://office-router.lan:9090" ];
                };

                # ── Admin user ───────────────────────────────────
                adminUser = {
                  name = "admin";
                  sshKeys = [
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILtMd4jTM9A36iVI2R6zw8cApkd7HQExr0ayfHcwaOp/"
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOv4SpIhHJqtRaYBRQOin4PTDUxRwo7ozoQHTUFjMGLW"
                  ];
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
