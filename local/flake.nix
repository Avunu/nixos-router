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
      hostName = "office-router";
      system = "x86_64-linux";
    in
    {
      nixosConfigurations = {
        "${hostName}" = nixpkgs.lib.nixosSystem {
          system = system;
          modules = [
            ./hardware-configuration.nix
            { nix.nixPath = [ "nixpkgs=${self.inputs.nixpkgs}" ]; }
            nixos-router.nixosModules.router
            {
              router = {
                hostName = hostName;
                timeZone = "America/New_York";
                stateVersion = "26.11";
                diskDevice = "/dev/sda";

                # ── WAN ──────────────────────────────────────────
                wan.interface = "enp1s0";

                # ── LAN ──────────────────────────────────────────
                lan = {
                  interfaces = [
                    "enp2s0"
                    "enp3s0"
                  ];
                  bridge = "br-lan";
                  address = "192.168.10.1";
                  networkAddress = "192.168.10.0";
                  prefixLength = 24;
                  domain = "lan";
                  dhcp = {
                    rangeStart = "192.168.10.100";
                    rangeEnd = "192.168.10.250";
                    leaseTime = "24h";
                  };
                };

                # ── WireGuard tunnels (multiple supported) ───────
                wireguard = {
                  wg0 = {
                    address = "10.100.0.1/24";
                    listenPort = 51820;
                    privateKeyFile = "/etc/wireguard/wg0.key";
                    routes = [ "10.20.0.0/24" ];
                    peers = [
                      {
                        publicKey = "PEER_PUBLIC_KEY_HERE";
                        endpoint = "remote-office.example.com:51820";
                        allowedIPs = [
                          "10.100.0.0/24"
                          "10.20.0.0/24"
                        ];
                        persistentKeepalive = 25;
                      }
                    ];
                  };

                  # Example: second WireGuard tunnel
                  # wg1 = {
                  #   address       = "10.200.0.1/24";
                  #   listenPort    = 51821;
                  #   privateKeyFile = "/etc/wireguard/wg1.key";
                  #   routes = [ "10.30.0.0/24" ];
                  #   peers = [
                  #     {
                  #       publicKey   = "OTHER_PEER_PUBLIC_KEY";
                  #       endpoint    = "branch-office.example.com:51821";
                  #       allowedIPs  = [ "10.200.0.0/24" "10.30.0.0/24" ];
                  #       persistentKeepalive = 25;
                  #     }
                  #   ];
                  # };
                };

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
                    filters = [
                      {
                        enabled = true;
                        name = "AdGuard Base";
                        url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt";
                        id = 1;
                      }
                      {
                        enabled = true;
                        name = "AdAway";
                        url = "https://adaway.org/hosts.txt";
                        id = 2;
                      }
                      {
                        enabled = true;
                        name = "Malware filter";
                        url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt";
                        id = 3;
                      }
                      {
                        enabled = true;
                        name = "Peter Lowe's tracker list";
                        url = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=1&mimetype=plaintext";
                        id = 4;
                      }
                    ];
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
