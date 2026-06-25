# ── Access Protection module ──────────────────────────────────────────────────
# DNS filtering with AdGuard Home OR Technitium DNS Server:
#   • AdGuard Home: standard blocklist catalogue, UT Capitole categories,
#     DoH-provider block rules, SafeSearch
#   • Technitium DNS Server: enterprise-grade filtering with RBAC, group policies,
#     advanced blocking, multi-user administration, and better scalability
#
# BACKEND SELECTION:
#   - Enable AdGuard:    router.dns.adguard.enable = true;
#   - Enable Technitium: router.dns.technitium.enable = true;
#   - If both enabled:   Technitium takes precedence
#
# MIGRATION FROM ADGUARD TO TECHNITIUM:
#   1. Set router.dns.adguard.enable = false;
#   2. Set router.dns.technitium.enable = true;
#   3. Configure router.dns.technitium.* options (similar to adguard.* options)
#   4. Most block lists and configurations are directly compatible
#
# KEY DIFFERENCES:
#   - Technitium supports RBAC, multi-user admin, and SSO
#   - Technitium has advanced group-based network policies
#   - Technitium provides better scalability and clustering
#   - Technitium uses existing nixpkgs package with minimal configuration
#
# Both options bind to LAN/guest gateways, with Avahi mDNS hostname publishing.
{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  cfg = config.router;
  inherit (config.router._internal) lanGW guestGW;

  # Detect which DNS backend is enabled
  useAdGuard = cfg.dns.adguard.enable && !cfg.dns.technitium.enable;
  useTechnitium = cfg.dns.technitium.enable;

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
  #
  # Source: olbat/ut1-blacklists GitHub mirror of the UT Capitole
  # archives. The upstream site (dsi.ut-capitole.fr) only serves
  # categories as .tar.gz archives; this mirror extracts them into
  # individual `domains` files suitable for AdGuard Home.
  #
  # NOTE: The "adult" category is too large (~50MB) for a plain
  # domains file on GitHub — use "mixed_adult" or "porn" instead,
  # or omit it and rely on a dedicated adult-content filter list.
  utCapitoleFilters = imap1 (i: cat: {
    enabled = true;
    name = "UT Capitole - ${cat}";
    url = "https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/${cat}/domains";
    id = 9999 + i;
  }) cfg.dns.adguard.utCapitoleCategories;

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
in
{
  options.router = {
    # ── DNS ────────────────────────────────────────────────
    # DNS resolution pipeline:
    #   Choose between AdGuard Home or Technitium DNS Server:
    #   1. Clients send queries to the router's LAN/guest IP (:53).
    #   2. Selected DNS server receives queries, applies filtering,
    #      SafeSearch, and group policies.
    #   3. Unblocked queries are forwarded to upstream DoH servers.
    #
    # DNS bypass prevention (defense-in-depth):
    #   • nftables DNAT: hijacks all port-53 traffic to local resolver.
    #   • nftables DoT block: drops TCP port 853 in forward chain.
    #   • DNS server rules: blocks known DoH provider domains.
    #   • Suricata alerts: TLS SNI matching for DoH/DoT providers.
    dns = {
      upstreamServers = mkOption {
        type = types.listOf types.str;
        default = [
          "https://dns.cloudflare.com/dns-query"
          "https://dns.google/dns-query"
        ];
        description = "Upstream DNS-over-HTTPS servers (shared by both AdGuard and Technitium)";
      };

      bootstrapServers = mkOption {
        type = types.listOf types.str;
        default = [
          "1.1.1.1"
          "8.8.8.8"
        ];
        description = "Bootstrap DNS servers for resolving DoH hostnames (AdGuard only)";
      };

      safeSearch = mkEnableOption "SafeSearch enforcement (both AdGuard and Technitium)";

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

        allowList = mkOption {
          type = types.listOf types.str;
          default = [ ];
          description = "List of domains or URL patterns to allow. Each entry will be converted to an AdGuard allow rule (e.g., 'example.com' becomes '@@||example.com^').";
        };

        blockList = mkOption {
          type = types.listOf types.str;
          default = [ ];
          description = "List of domains or URL patterns to block. Each entry will be converted to an AdGuard block rule (e.g., 'example.com' becomes '||example.com^').";
        };
      };

      technitium = {
        enable = mkEnableOption "Technitium DNS Server (enterprise alternative to AdGuard Home)";

        package = mkOption {
          type = types.package;
          default = pkgs.technitium-dns-server;
          defaultText = "pkgs.technitium-dns-server";
          description = "Technitium DNS Server package to use";
        };

        adminPasswordHash = mkOption {
          type = types.str;
          default = "";
          description = "Hashed admin password for Technitium (use 'technitium-dns-server hash' command)";
        };

        webPort = mkOption {
          type = types.port;
          default = 5380;
          description = "Technitium web UI port (default: 5380)";
        };

        blockDoHProviders = mkOption {
          type = types.bool;
          default = true;
          description = "Block common DoH provider domains to prevent DNS bypass";
        };

        # Block lists (equivalent to AdGuard's standardFilters)
        blockLists = mkOption {
          type = types.listOf types.str;
          default = [
            "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
            "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt"
            "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt"
            "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt"
            "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt"
            "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt"
          ];
          description = "Block list URLs (similar to AdGuard's standard filters)";
        };

        allowLists = mkOption {
          type = types.listOf types.str;
          default = [ ];
          description = "Allow list URLs";
        };

        guestBlockLists = mkOption {
          type = types.listOf types.str;
          default = [
            # Stricter filtering for guest network
            "https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/porn/domains"
            "https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/dating/domains"
            "https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/gambling/domains"
          ];
          description = "Additional block lists for guest network";
        };

        utCapitoleCategories = mkOption {
          type = types.listOf types.str;
          default = [
            "malware"
            "phishing"
            "gambling"
          ];
          description = "UT Capitole categories to include (if using UT lists)";
        };

        # Advanced features that Technitium enables
        enableRbac = mkEnableOption "Role-based access control with multiple users (Technitium feature)";
        enableGroupPolicies = mkEnableOption "Network-based group policies via Advanced Blocking App (Technitium feature)";
        enableSso = mkEnableOption "OpenID Connect SSO integration (Technitium feature)";

        # SSO configuration
        ssoAuthority = mkOption {
          type = types.str;
          default = "";
          description = "OIDC authority URL (e.g., https://auth.example.com)";
        };

        ssoClientId = mkOption {
          type = types.str;
          default = "";
          description = "OIDC client ID";
        };

        ssoClientSecret = mkOption {
          type = types.str;
          default = "";
          description = "OIDC client secret";
        };
      };
    };
  };

  config = mkMerge [
    # ── DNS backend selection warning ─────────────────────
    {
      warnings = mkIf (cfg.dns.adguard.enable && cfg.dns.technitium.enable) [
        "Both AdGuard Home and Technitium DNS Server are enabled. Only Technitium will be used."
      ];
    }

    # ── Common DNS configuration ─────────────────────────
    {
      networking.nameservers = [
        "127.0.0.1"
        "::1"
      ];
      services.resolved.enable = mkIf (useAdGuard || useTechnitium) false;
    }

    # ── AdGuard Home configuration ────────────────────────
    {
      services.adguardhome = mkIf useAdGuard {
        enable = true;
        mutableSettings = false; # disable runtime changes via AGH UI (managed by NixOS config)
        # When the Cockpit UI is enabled, AdGuard's own web UI is hidden
        # (bound to localhost) and surfaced through the router Cockpit
        # plugin instead — a single web experience. The plugin reaches
        # the AGH REST API over 127.0.0.1. Otherwise bind to lanGW.
        host = if cfg.cockpit.enable then "127.0.0.1" else lanGW;
        port = cfg.dns.adguard.webPort;
        settings =
          let
            allowRules = map (pattern: "@@||${pattern}^") cfg.dns.adguard.allowList;
            blockRules = map (pattern: "||${pattern}^") cfg.dns.adguard.blockList;
          in
          {

            dns = {
              bind_hosts = [
                "127.0.0.1"
                "::1"
                lanGW
                "::"
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
                {
                  domain = "${cfg.hostName}.local";
                  answer = lanGW;
                }
              ];
            };

            # Query log + statistics power the router Cockpit plugin's
            # AdGuard views (read via the REST API on localhost).
            querylog = {
              enabled = true;
              interval = "168h"; # 7-day retention
            };
            statistics = {
              enabled = true;
              interval = "168h";
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

            user_rules = dohBlockRules ++ allowRules ++ blockRules ++ cfg.dns.adguard.extraUserRules;
          };
      };
    }

    # ── Technitium DNS Server configuration ─────────────────
    # Enterprise-grade DNS filtering with RBAC, group policies,
    # advanced blocking, multi-user administration. Uses the
    # existing nixpkgs service with extended configuration.
    {
      services.technitium-dns-server = mkIf useTechnitium {
        enable = true;

        # Use existing package or override if needed
        package = cfg.dns.technitium.package;

        # Firewall configuration
        openFirewall = true;
        firewallTCPPorts = [ cfg.dns.technitium.webPort ];
        firewallUDPPorts = [ 53 ];

        # Start the service with our custom configuration
        # Note: The base service handles basic setup, we extend it here
      };

      # Technitium requires additional systemd configuration
      # since the base nixpkgs service is minimal
      systemd.services.technitium-dns-server = mkIf useTechnitium {
        # Extend the base service with our configuration
        serviceConfig = {
          # Additional configuration directories
          Environment = [
            "DOTNET_Environment=Production"
            "DOTNET_EnableDiagnostics=0"
          ];
        };
      };

      # Generate Technitium configuration from our router options
      # Technitium stores config in /etc/technitium-dns-server/dnsconfig.txt
      environment.etc."technitium-dns-server/dnsconfig.txt" = mkIf useTechnitium {
        text = ''
          # Auto-generated by nixos-router access-protection module
          # Do not edit manually - changes will be overwritten

          # Server Settings
          DnsServerDomain=${cfg.hostName}.${cfg.lan.domain}
          ServerId=${cfg.hostName}
          DefaultRecordTtl=3600
          DefaultSoaRecordTtl=900
          DefaultNsRecordTtl=14400
          DnssecValidation=true

          # DNS Server Configuration
          ListenIPs=127.0.0.1,${lanGW},::${optionalString cfg.guest.enable ",${guestGW}"}
          DnsPort=53
          WebServicePort=${toString cfg.dns.technitium.webPort}
          WebServiceLocalOnlyOnly=${if cfg.cockpit.enable then "true" else "false"}

          # DNS Resolution Settings
          PreferIPv6=false
          DisableIPv6=false
          CacheSize=4096
          CacheMinimumTtl=300
          CacheMaximumTtl=86400

          # Forwarder Configuration
          ${concatStringsSep "\n" (map (upstream: "DnsForwarders=${upstream}") cfg.dns.upstreamServers)}

          # Blocking Configuration
          BlockingEnabled=true
          BlockListUrlUpdateIntervalHours=24
          BlockListUrlUpdateIntervalMinutes=0
          AllowTxtBlockingReport=true
          BlockAsNxDomain=false
          BlockingAddresses=0.0.0.0,::

          # Query Logging & Statistics
          QueryLoggingEnabled=true
          QueryLogRetentionDays=7
          StatisticsEnabled=true
          StatisticsRetentionDays=30
          EnableCacheInspection=true

          # SafeSearch Configuration
          ${optionalString cfg.dns.safeSearch ''
            SafeSearchEnabled=true
            SafeSearchBing=true
            SafeSearchDuckDuckGo=true
            SafeSearchGoogle=true
            SafeSearchPixabay=true
            SafeSearchYandex=true
            SafeSearchYouTube=true
          ''}

          # DNS Rewrites (equivalent to AdGuard rewrites)
          # These map hostnames to IPs
          DnsRewritesEnabled=true
          DnsRewrites=${cfg.hostName}.${cfg.lan.domain}=${lanGW},${cfg.hostName}.local=${lanGW}

          # DoH Provider Blocking (equivalent to AdGuard dohBlockRules)
          ${optionalString cfg.dns.technitium.blockDoHProviders ''
            # Block common DoH providers to prevent DNS bypass
            BlockingRules=||dns.google^,||cloudflare-dns.com^,||mozilla.cloudflare-dns.com^,||dns.quad9.net^,||doh.opendns.com^,||dns.nextdns.io^,||doh.cleanbrowsing.org^,||dns.adguard.com^,||doh.mullvad.net^,||dns.controld.com^
          ''}
        '';
      };

      # Advanced Blocking App configuration for group policies
      environment.etc."technitium-dns-server/Apps/AdvancedBlockingApp/dnsApp.config" =
        mkIf (useTechnitium && cfg.dns.technitium.enableGroupPolicies)
          {
            text = builtins.toJSON {
              enableBlocking = true;
              blockingAnswerTtl = 30;
              blockListUrlUpdateIntervalHours = 24;
              localEndPointGroupMap = {
                "127.0.0.1" = "admin";
              };
              networkGroupMap = {
                "${removeSuffix "/24" cfg.lan.cidr}" = "lan";
              }
              // optionalAttrs cfg.guest.enable {
                "${removeSuffix "/24" cfg.guest.cidr}" = "guest";
              };
              groups = [
                {
                  name = "lan";
                  enableBlocking = true;
                  allowTxtBlockingReport = true;
                  blockAsNxDomain = false;
                  blockingAddresses = [
                    "0.0.0.0"
                    "::"
                  ];
                  allowed = [ ];
                  blocked = [ ];
                  allowListUrls = cfg.dns.technitium.allowLists;
                  blockListUrls = cfg.dns.technitium.blockLists;
                  allowedRegex = [ ];
                  blockedRegex = [ ];
                  regexAllowListUrls = [ ];
                  regexBlockListUrls = [ ];
                  adblockListUrls = [ ];
                }
              ]
              ++ optional cfg.guest.enable {
                name = "guest";
                enableBlocking = true;
                allowTxtBlockingReport = true;
                blockAsNxDomain = false;
                blockingAddresses = [
                  "0.0.0.0"
                  "::"
                ];
                allowed = [ ];
                blocked = [ ];
                allowListUrls = cfg.dns.technitium.allowLists;
                blockListUrls = cfg.dns.technitium.blockLists ++ cfg.dns.technitium.guestBlockLists;
                allowedRegex = [ ];
                blockedRegex = [ ];
                regexAllowListUrls = [ ];
                regexBlockListUrls = [ ];
                adblockListUrls = [ ];
              };
            };
          };

      # User configuration for Technitium RBAC
      environment.etc."technitium-dns-server/auth.config" =
        mkIf (useTechnitium && cfg.dns.technitium.enableRbac)
          {
            text = ''
              # Auto-generated user configuration
              # Users are managed via Technitium web UI or API

              # Default admin user - password should be set via UI first boot
              admin_password_hash=${cfg.dns.technitium.adminPasswordHash}

              # Group memberships
              admin_groups=Administrators,DNS-Administrators

              ${optionalString cfg.dns.technitium.enableSso ''
                # SSO Configuration
                sso_enabled=true
                sso_authority=${cfg.dns.technitium.ssoAuthority}
                sso_client_id=${cfg.dns.technitium.ssoClientId}
                sso_client_secret=${cfg.dns.technitium.ssoClientSecret}
                sso_auto_create_users=true
                sso_default_groups=Everyone
              ''}
            '';
          };
    }

    # ── Avahi mDNS ───────────────────────────────────────
    # Publish the router's hostname via mDNS so clients can resolve
    # it as hostname.local (e.g., 258-router.local).
    {
      services.avahi = {
        enable = true;
        publish = {
          enable = true;
          addresses = true;
          workstation = true;
        };
      };
    }
  ];
}
