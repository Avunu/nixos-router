# ── Access Protection module ──────────────────────────────────────────────────
# AdGuard Home DNS filtering: the standard blocklist catalogue, UT Capitole
# category lists, DoH-provider block rules, SafeSearch, and the AGH service bound
# to the LAN/guest gateways (plus Avahi mDNS hostname publishing and pointing the
# router's own resolver at AGH). Gateway IPs come from the shared topology.
{
  config,
  lib,
  ...
}:
with lib;
let
  cfg = config.router;
  inherit (config.router._internal) lanGW guestGW;

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
    };
  };

  config = {
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
    # systemd-resolved must be disabled to free port 53 for AGH.
    networking.nameservers = [
      "127.0.0.1"
      "::1"
    ];
    services.resolved.enable = false;

    services.adguardhome = mkIf cfg.dns.adguard.enable {
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

    # ── Avahi mDNS ───────────────────────────────────────
    # Publish the router's hostname via mDNS so clients can resolve
    # it as hostname.local (e.g., 258-router.local).
    services.avahi = {
      enable = true;
      publish = {
        enable = true;
        addresses = true;
        workstation = true;
      };
    };
  };
}
