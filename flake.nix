{
  description = "NixOS Router";

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
          brLAN = cfg.lan.bridge;
          lanGW = cfg.lan.address;
          lanPrefix = toString cfg.lan.prefixLength;
          lanCIDR = "${cfg.lan.networkAddress}/${lanPrefix}";
          lanDHCPRange = "${brLAN},${cfg.lan.dhcp.rangeStart},${cfg.lan.dhcp.rangeEnd},${cfg.lan.dhcp.leaseTime}";

          wgNames = attrNames cfg.wireguard;
          wgInterfaces = attrValues cfg.wireguard;

          # All WG interface names for nftables
          wgIFNames = wgNames;

          # Collect all internal subnets for Suricata HOME_NET
          lanNets = [ lanCIDR ];
          wgNets = concatMap (wg: [ wg.address ] ++ concatMap (p: p.allowedIPs) wg.peers) wgInterfaces;
          guestNets = optional cfg.guest.enable guestCIDR;
          allHomeNets = lanNets ++ wgNets ++ guestNets;
          homeNets = "[${concatStringsSep ", " allHomeNets}]";

          # nftables helper: quoted list for sets
          nftSet = items: concatStringsSep ", " (map (i: ''"${i}"'') items);
          trustedIFs = [ brLAN ] ++ wgIFNames;

          # ── Guest network derived values ────────────────────────
          brGuest = cfg.guest.bridge;
          guestGW = cfg.guest.address;
          guestPrefix = toString cfg.guest.prefixLength;
          guestCIDR = "${cfg.guest.networkAddress}/${guestPrefix}";
          guestDHCPRange = "${brGuest},${cfg.guest.dhcp.rangeStart},${cfg.guest.dhcp.rangeEnd},${cfg.guest.dhcp.leaseTime}";

          # ── Standard filter list catalogue ──────────────────────
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

          standardFilters = map (key: standardFilterCatalogue.${key} // { enabled = true; }) (
            filter (key: cfg.dns.adguard.standardFilters.${key}) (attrNames cfg.dns.adguard.standardFilters)
          );

          # ── UT Capitole blacklist filters ───────────────────────
          utCapitoleFilters = imap1 (i: cat: {
            enabled = true;
            name = "UT Capitole - ${cat}";
            url = "https://dsi.ut-capitole.fr/blacklists/download/${cat}/domains";
            id = 9999 + i;
          }) cfg.dns.adguard.utCapitoleCategories;

          # ── Suricata config (native Nix → YAML) ────────────────
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
          wgInputRules = concatMapStringsSep "\n          " (
            name:
            let
              wg = cfg.wireguard.${name};
            in
            ''iifname "${cfg.wan.interface}" udp dport ${toString wg.listenPort} accept comment "Allow WireGuard ${name}"''
          ) wgNames;

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
            wan = {
              interface = mkOption {
                type = types.str;
                description = "WAN network interface name (e.g. enp1s0)";
              };
            };

            # ── LAN ────────────────────────────────────────────────
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
                rangeStart = mkOption {
                  type = types.str;
                  description = "First IP in DHCP range (e.g. 192.168.10.100)";
                };

                rangeEnd = mkOption {
                  type = types.str;
                  description = "Last IP in DHCP range (e.g. 192.168.10.250)";
                };

                leaseTime = mkOption {
                  type = types.str;
                  default = "24h";
                  description = "DHCP lease duration";
                };
              };
            };

            # ── Guest Network ──────────────────────────────────────
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
                rangeStart = mkOption {
                  type = types.str;
                  default = "192.168.20.100";
                  description = "First IP in guest DHCP range";
                };

                rangeEnd = mkOption {
                  type = types.str;
                  default = "192.168.20.250";
                  description = "Last IP in guest DHCP range";
                };

                leaseTime = mkOption {
                  type = types.str;
                  default = "1h";
                  description = "Guest DHCP lease duration (shorter default encourages rotation)";
                };
              };
            };

            # ── WireGuard ──────────────────────────────────────────
            wireguard = mkOption {
              type = types.attrsOf wgInterfaceType;
              default = { };
              description = "WireGuard tunnel interfaces (keys are interface names, e.g. wg0)";
            };

            # ── DNS ────────────────────────────────────────────────
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
                  default = 5353;
                  description = "DNS listen port for AdGuard Home";
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
            suricata = {
              enable = mkEnableOption "Suricata IPS inline inspection";

              extraRules = mkOption {
                type = types.lines;
                default = "";
                description = "Additional Suricata local rules";
              };
            };

            # ── Cockpit web UI ────────────────────────────────────
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
            };

            extraPackages = mkOption {
              type = types.listOf types.package;
              default = [ ];
              description = "Additional packages to install";
            };
          };

          # ══════════════════════════════════════════════════════════
          #  CONFIG IMPLEMENTATION
          # ══════════════════════════════════════════════════════════
          config = {

            # ── 1. Boot & basics ─────────────────────────────────
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
                    enable = mkDefault true;
                    efiSupport = false;
                    devices = mkForce [ cfg.diskDevice ];
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
                          boot = {
                            size = "1M";
                            type = "EF02";
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

            # ── 2. Kernel — forwarding, martian filtering, perf ──
            boot.kernel.sysctl = {
              "net.ipv4.conf.all.forwarding" = true;
              "net.ipv6.conf.all.forwarding" = false;
              "net.ipv4.conf.default.rp_filter" = 1;
              "net.ipv4.conf.${cfg.wan.interface}.rp_filter" = 1;
              "net.ipv4.conf.${brLAN}.rp_filter" = 0;
              "net.core.rmem_max" = 26214400;
              "net.core.wmem_max" = 26214400;
              "net.core.netdev_max_backlog" = 5000;
              "net.netfilter.nf_conntrack_max" = 131072;
            }
            // listToAttrs (
              map (name: {
                name = "net.ipv4.conf.${name}.rp_filter";
                value = 0;
              }) wgNames
            )
            // optionalAttrs cfg.guest.enable {
              "net.ipv4.conf.${brGuest}.rp_filter" = 0;
            };

            boot.kernelModules = [
              "nf_conntrack"
              "nfnetlink_queue"
            ];

            # ── 3. systemd-networkd — interfaces + bridge ────────
            networking = {
              useNetworkd = true;
              useDHCP = false;
              nat.enable = false;
              firewall.enable = false;
            };

            systemd.network = {
              enable = true;
              wait-online.anyInterface = true;

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

              networks = {
                "10-wan" = {
                  matchConfig.Name = cfg.wan.interface;
                  networkConfig = {
                    DHCP = "ipv4";
                    DNSOverTLS = true;
                    DNSSEC = true;
                    IPForward = true;
                    IPv6PrivacyExtensions = false;
                  };
                  linkConfig.RequiredForOnline = "routable";
                };

                "30-lan-ports" = {
                  matchConfig.Name = concatStringsSep " " cfg.lan.interfaces;
                  networkConfig = {
                    Bridge = brLAN;
                    ConfigureWithoutCarrier = true;
                  };
                  linkConfig.RequiredForOnline = "enslaved";
                };

                "40-br-lan" = {
                  matchConfig.Name = brLAN;
                  address = [ "${lanGW}/${lanPrefix}" ];
                  networkConfig = {
                    ConfigureWithoutCarrier = true;
                  };
                  linkConfig.RequiredForOnline = "no";
                };
              }
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
                    linkConfig.RequiredForOnline = "no";
                  }
                ) wgNames
              )
              // optionalAttrs cfg.guest.enable {
                "31-guest-ports" = {
                  matchConfig.Name = concatStringsSep " " cfg.guest.interfaces;
                  networkConfig = {
                    Bridge = brGuest;
                    ConfigureWithoutCarrier = true;
                  };
                  linkConfig.RequiredForOnline = "enslaved";
                };
                "41-br-guest" = {
                  matchConfig.Name = brGuest;
                  address = [ "${guestGW}/${guestPrefix}" ];
                  networkConfig.ConfigureWithoutCarrier = true;
                  linkConfig.RequiredForOnline = "no";
                };
              };
            };

            # ── WireGuard interfaces ─────────────────────────────
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
            networking.nftables = {
              enable = true;
              ruleset = nftRuleset;
            };

            # ── 5. DHCP + DNS forwarding — dnsmasq ───────────────
            services.dnsmasq = {
              enable = true;
              settings = {
                interface =
                  if cfg.guest.enable then
                    [
                      brLAN
                      brGuest
                    ]
                  else
                    brLAN;
                bind-interfaces = true;
                dhcp-range = [ lanDHCPRange ] ++ optional cfg.guest.enable guestDHCPRange;
                dhcp-host = lanGW;
                dhcp-option =
                  if cfg.guest.enable then
                    [
                      "tag:${brLAN},option:router,${lanGW}"
                      "tag:${brLAN},option:dns-server,${lanGW}"
                      "tag:${brGuest},option:router,${guestGW}"
                      "tag:${brGuest},option:dns-server,${guestGW}"
                    ]
                  else
                    [
                      "option:router,${lanGW}"
                      "option:dns-server,${lanGW}"
                    ];
                dhcp-leasefile = "/var/lib/dnsmasq/dnsmasq.leases";
                server = [ "127.0.0.1#${toString cfg.dns.adguard.listenPort}" ];
                no-resolv = true;
                cache-size = 0;
                domain-needed = true;
                bogus-priv = true;
                stop-dns-rebind = true;
                rebind-localhost-ok = true;
                local = "/${cfg.lan.domain}/";
                domain = cfg.lan.domain;
                expand-hosts = true;
                no-hosts = true;
                address = "/${cfg.hostName}.${cfg.lan.domain}/${lanGW}";
              };
            };

            # ── 6. Ad-blocking + SafeSearch — AdGuard Home ────────
            services.adguardhome = mkIf cfg.dns.adguard.enable {
              enable = true;
              mutableSettings = true;
              host = lanGW;
              port = cfg.dns.adguard.webPort;
              settings = {

                dns = {
                  bind_hosts = [ "127.0.0.1" ];
                  port = cfg.dns.adguard.listenPort;
                  upstream_dns = cfg.dns.upstreamServers;
                  bootstrap_dns = cfg.dns.bootstrapServers;
                  protection_enabled = true;
                  filtering_enabled = true;
                  rate_limit = 0;
                  cache_size = 4194304;
                  cache_ttl_min = 300;
                  cache_ttl_max = 86400;
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

            # ── 7. IPS — Suricata ────────────────────────────────
            environment.etc = mkIf cfg.suricata.enable {
              "suricata/suricata.yaml".source = yamlFormat.generate "suricata.yaml" suricataConfig;
              "suricata/rules/local.rules".text = localSuricataRules;
            };

            systemd.services = mkIf cfg.suricata.enable {
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

            # ── 8. Web UI — Cockpit ─────────────────────────────
            services.cockpit = mkIf cfg.cockpit.enable {
              enable = true;
              port = cfg.cockpit.port;
              package = cfg.cockpit.package;
              plugins = cfg.cockpit.plugins;
              openFirewall = false; # managed by nftables (LAN/WG already accepted)
              showBanner = cfg.cockpit.showBanner;
              "allowed-origins" = cfg.cockpit.allowedOrigins;
              settings = cfg.cockpit.settings;
            };

            # ── 9. Packages ──────────────────────────────────────
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

            # ── 10. Logging ──────────────────────────────────────
            services.journald.extraConfig = ''
              SystemMaxUse=500M
              MaxRetentionSec=30day
            '';

            # ── 11. Hardening ────────────────────────────────────
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
              openssh.authorizedKeys.keys = cfg.adminUser.sshKeys;
            };

            # ── 12. Maintenance ──────────────────────────────────
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
