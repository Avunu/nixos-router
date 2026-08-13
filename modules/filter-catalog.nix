# ── Filter catalog ─────────────────────────────────────────────────────────────
# Pure data consumed via `import ./filter-catalog.nix` (NOT a NixOS module).
# Shared by the access-policies module (policy → Advanced Blocking compilation)
# and the Cockpit settings schema.
#
# Every list entry carries a `format` tag because Technitium's Advanced
# Blocking app does not auto-detect list syntax the way AdGuard Home does:
#   • format = "adblock" → the URL belongs in a group's `adblockListUrls`
#     (AdGuard/ABP syntax: ||domain^, @@||domain^ …)
#   • format = "hosts"   → the URL belongs in `blockListUrls`
#     (hosts-file or one-domain-per-line format)
{
  # ── Standard filter list catalog ─────────────────────────
  # Well-known ad/malware/phishing blocklists, selectable per access
  # policy via `standardFilters = [ "adguard_ads" … ]`. The
  # HostlistsRegistry assets and the yoyo export (hostformat=adblockplus)
  # are AdBlock syntax; AdAway ships a classic hosts file.
  standardFilters = {
    adguard_ads = {
      name = "AdGuard Base";
      url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt";
      format = "adblock";
    };
    adguard_malware = {
      name = "AdGuard Malware URL Blocklist";
      url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt";
      format = "adblock";
    };
    adaway = {
      name = "AdAway";
      url = "https://adaway.org/hosts.txt";
      format = "hosts";
    };
    yoyo_adservers = {
      name = "Peter Lowe's Ad and tracker server list";
      url = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=1&mimetype=plaintext";
      format = "adblock";
    };
    adguard_hacked_sites = {
      name = "Hacked Malware Web Sites";
      url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt";
      format = "adblock";
    };
    steven_black = {
      name = "Steven Black's Hosts";
      url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt";
      format = "adblock";
    };
    adguard_phishing = {
      name = "AdGuard Phishing URL Blocklist";
      url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt";
      format = "adblock";
    };
    adguard_anti_malware = {
      name = "Dandelion Sprout's Anti-Malware List";
      url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt";
      format = "adblock";
    };
    phishtank_openphish = {
      name = "Phishing Army (PhishTank + OpenPhish)";
      url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt";
      format = "adblock";
    };
  };

  # ── UT Capitole category blacklists ──────────────────────
  # Université Toulouse Capitole curated domain blacklists by category,
  # served as plain `domains` files (hosts format) from the olbat mirror.
  # Selectable per access policy via `categories = [ "porn" … ]`.
  #
  # NOTE: the "adult" category is too large (~50MB) for the mirror —
  # use "mixed_adult" or "porn" instead.
  utCapitole = {
    urlFor =
      category:
      "https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/${category}/domains";
    format = "hosts";
    # Single source of truth for category ids: ut-capitole.json (shared with
    # the Cockpit category selector, which also carries the display labels).
    categories = map (c: c.id) (
      builtins.fromJSON (builtins.readFile ../pkgs/cockpit-router/src/ut-capitole.json)
    );
  };

  # ── DoH provider domains ─────────────────────────────────
  # Public DNS-over-HTTPS resolvers blocked in every compiled policy
  # group (when dns.technitium.blockDoHProviders is set) so devices
  # cannot bypass local filtering with their own DoH endpoint.
  # Complements the nftables DoT :853 drop and Suricata SNI alerts.
  dohProviderDomains = [
    "dns.google"
    "cloudflare-dns.com"
    "mozilla.cloudflare-dns.com"
    "dns.quad9.net"
    "doh.opendns.com"
    "dns.nextdns.io"
    "doh.cleanbrowsing.org"
    "dns.adguard.com"
    "doh.mullvad.net"
    "dns.controld.com"
  ];

  # ── SafeSearch record map ────────────────────────────────
  # Technitium has no built-in SafeSearch; the reconcile service
  # creates a tiny authoritative zone per host below with an apex
  # ANAME pointing at the provider's enforcement endpoint.
  safeSearchRecords = {
    "www.google.com" = "forcesafesearch.google.com";
    "www.bing.com" = "strict.bing.com";
    "duckduckgo.com" = "safe.duckduckgo.com";
    "www.duckduckgo.com" = "safe.duckduckgo.com";
    "www.youtube.com" = "restrict.youtube.com";
    "m.youtube.com" = "restrict.youtube.com";
    "youtubei.googleapis.com" = "restrict.youtube.com";
    "youtube.googleapis.com" = "restrict.youtube.com";
    "www.youtube-nocookie.com" = "restrict.youtube.com";
  };
}
