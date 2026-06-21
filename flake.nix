# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  NixOS Router — Declarative Home/Office Router Configuration               ║
# ║                                                                            ║
# ║  A single-flake NixOS module that turns a multi-NIC machine into a fully   ║
# ║  featured router with:                                                     ║
# ║    • systemd-networkd managed WAN (DHCP) + LAN/Guest bridges w/ DHCPServer ║
# ║    • nftables stateful firewall with NAT, DNS hijacking, DoT blocking      ║
# ║    • AdGuard Home DNS filtering + SafeSearch on :53 (direct to clients)    ║
# ║    • Avahi mDNS for hostname resolution (router.local)                     ║
# ║    • WireGuard VPN tunnels with full LAN ↔ WAN ↔ WG routing                ║
# ║    • Optional Suricata IPS inline via NFQUEUE                              ║
# ║    • Web admin UI: OliveTin + Netdata + Homepage                           ║
# ║    • Disko-based declarative disk partitioning (UEFI or legacy)            ║
# ║                                                                            ║
# ║  Usage:                                                                    ║
# ║    Import `nixosModules.router` and set the `router.*` options in your     ║
# ║    host configuration. See the MODULE OPTIONS section for all settings.    ║
# ║                                                                            ║
# ║  Architecture:                                                             ║
# ║    DNS flow: clients → AdGuard Home (:53) → DoH upstream                  ║
# ║    mDNS: clients → Avahi (multicast) for .local resolution                ║
# ║    Traffic:  LAN/Guest/WG → nftables (→ Suricata NFQUEUE) → NAT → WAN     ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
{
  description = "NixOS Router";

  # ── Flake Inputs ────────────────────────────────────────────────────────────
  # nixpkgs:   NixOS unstable channel — provides all packages and the NixOS
  #            module system. Unstable is used for the latest kernel, networkd,
  #            and security patches.
  # git-hooks: Pre-commit hook runner (nixfmt formatting, flake check).
  # disko:     Declarative disk partitioning — generates partition layouts from
  #            Nix expressions, supporting both UEFI (GPT+ESP) and legacy
  #            (GPT+BIOS boot) modes.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
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
      # ── Pre-commit checks ────────────────────────────────────────────────────
      # nixfmt:        auto-formats .nix files on commit
      # flake-checker: runs `nix flake check` to catch evaluation errors
      checks = forAllSystems (system: {
        pre-commit = inputs.git-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            nixfmt = {
              enable = true;
              package = nixpkgs.legacyPackages.${system}.nixfmt;
            };
            # flake-checker = {
            #   enable = true;
            #   name = "nix flake check";
            #   entry = "nix flake check --no-pure-eval --extra-experimental-features nix-command --extra-experimental-features flakes --impure";
            #   pass_filenames = false;
            #   stages = [ "pre-commit" ];
            #   extraPackages = with nixpkgs.legacyPackages.${system}; [
            #     nix
            #   ];
            # };
          };
        };
      });

      # ── Developer Shell ──────────────────────────────────────────────────────
      # Installs the pre-commit hooks and provides nixfmt on PATH.
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              nixd
              nixfmt
            ];
            inherit (self.checks.${system}.pre-commit) shellHook;
          };
        }
      );

      # ── Installer scripts ────────────────────────────────────────────────────
      # The ISO workflow is two repo-relative scripts run directly from a checkout
      # (they read/write local/flake.nix beside themselves, so they are not
      # packaged as `nix run` targets):
      #   ./local/generate-config.sh   — interactively writes local/flake.nix
      #   ./local/build-iso.sh         — builds the installer ISO from it

      # ════════════════════════════════════════════════════════════════════════
      #  ROUTER MODULE
      #
      #  This NixOS module is the core of the flake. It declares all
      #  `router.*` options and maps them to NixOS config (systemd-networkd,
      #  nftables, dnsmasq, AdGuard Home, WireGuard, Suricata, OliveTin, etc.).
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
          brLAN = "br-lan";
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
          brGuest = "br-guest";
          guestGW = cfg.guest.address;
          guestPrefix = toString cfg.guest.prefixLength;
          guestCIDR = "${cfg.guest.networkAddress}/${guestPrefix}";

          # ── VLAN / interface assignment model ───────────────────
          # Each network (wan/lan/guest) may be assigned physical interfaces
          # (claiming UNTAGGED traffic on them) and/or a VLAN id for TAGGED
          # traffic. VLAN availability is EXPLICIT: a network's tag is carried on
          # the global `trunkInterfaces` (implicit for every network) plus that
          # network's own `taggedInterfaces` (WAN: trunk only). A single physical
          # port can therefore carry untagged traffic for its owner network AND
          # tagged VLAN traffic for another: the kernel's 802.1q demux
          # (vlan_do_receive) runs before the bridge rx_handler, so the
          # `<port>.<vid>` sub-interface receives tagged frames before the owner's
          # plain bridge ever sees them. See the systemd-networkd section below.
          #
          # wanPhys/lanPhys/guestPhys:
          #   Untagged physical ports owned by each network.
          wanPhys = optional (cfg.wan.interface != null) cfg.wan.interface;
          lanPhys = cfg.lan.interfaces;
          guestPhys = optionals cfg.guest.enable cfg.guest.interfaces;
          # ownedPorts: physical ports that have an untagged owner network.
          # Untagged ownership is exclusive (a port has at most one owner).
          ownedPorts = wanPhys ++ lanPhys ++ guestPhys;

          # netList:
          #   Uniform description of each network: key, target bridge (null for a
          #   direct/untagged WAN), VLAN id, owned (untagged) ports, and the
          #   ports its VLAN tag rides on (`taggedPorts`). VLAN availability is
          #   EXPLICIT: the global `trunkInterfaces` (implicit for every network)
          #   plus each network's own `taggedInterfaces`. WAN's tag is restricted
          #   to `trunkInterfaces` only. The guest entry only appears when
          #   guest.enable = true.
          netList = [
            {
              key = "wan";
              bridge = null;
              vlan = cfg.wan.vlan;
              phys = wanPhys;
              taggedPorts = cfg.trunkInterfaces;
            }
            {
              key = "lan";
              bridge = brLAN;
              vlan = cfg.lan.vlan;
              phys = lanPhys;
              taggedPorts = unique (cfg.trunkInterfaces ++ cfg.lan.taggedInterfaces);
            }
          ]
          ++ optional cfg.guest.enable {
            key = "guest";
            bridge = brGuest;
            vlan = cfg.guest.vlan;
            phys = guestPhys;
            taggedPorts = unique (cfg.trunkInterfaces ++ cfg.guest.taggedInterfaces);
          };

          # vlanChild:
          #   Sub-interface name for a VLAN id on a parent port (kernel 8021q
          #   naming convention, e.g. enp1s0.20).
          vlanChild = parent: vid: "${parent}.${toString vid}";

          # allChildren:
          #   Flat list of every VLAN sub-interface to create — for each network
          #   with a VLAN id, one child per port in its `taggedPorts`.
          #
          #   Security note: because the kernel's VLAN demux precedes the bridge,
          #   a tag injected on a port lands directly in the matching network,
          #   bypassing that port's input chain. Availability is explicit, so a
          #   network's tag only appears where listed. The intended topology is a
          #   managed/smart switch acting as the trust boundary; WAN's tag is
          #   confined to `trunkInterfaces` so the internet side can never inject
          #   an internal VLAN onto a LAN/guest port.
          childrenOf =
            n:
            if n.vlan == null then
              [ ]
            else
              map (p: {
                inherit p;
                child = vlanChild p n.vlan;
                net = n;
              }) n.taggedPorts;
          allChildren = concatMap childrenOf netList;

          # allPhys: every physical port that needs a parent .network unit —
          # untagged owners, declared trunk ports, and any port a VLAN child
          # rides on. Trunk/tagged-only ports have no untagged network of their
          # own and act as pure carriers.
          allPhys = unique (ownedPorts ++ cfg.trunkInterfaces ++ map (c: c.p) allChildren);

          # childrenOnPort:
          #   VLAN sub-interface names that ride on a given parent port — attached
          #   to that port's .network via the `vlan` (VLAN=) list.
          childrenOnPort = parent: map (c: c.child) (filter (c: c.p == parent) allChildren);

          # wanIf:
          #   The WAN L3 interface name used by the firewall, NAT, and IPv6 prefix
          #   delegation. A VLAN-based (or interface-less) WAN runs its DHCP client
          #   on a bridge (br-wan) aggregating its VLAN sub-interfaces; otherwise
          #   it is the untagged uplink interface, exactly as before.
          wanIsBridged = cfg.wan.vlan != null || cfg.wan.interface == null;
          brWAN = "br-wan";
          wanIf = if wanIsBridged then brWAN else cfg.wan.interface;

          # wanNetworkBase:
          #   DHCP-client settings for the WAN L3 interface, applied to either
          #   the untagged uplink (10-wan) or the br-wan bridge (10-br-wan).
          wanNetworkBase = {
            networkConfig = {
              DHCP = "yes";
              IPv4Forwarding = true;
              IPv6Forwarding = true;
              IPv4ReversePathFilter = "strict";
              IPv6AcceptRA = true;
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
            dhcpV6Config = {
              UseDNS = false;
              UseHostname = false;
              WithoutRA = "solicit";
              PrefixDelegationHint = "::/60";
            };
            ipv6AcceptRAConfig = {
              UseDNS = false;
              DHCPv6Client = "always";
              # Ignore the MTU option in upstream Router Advertisements.
              # Some ISP uplinks advertise a jumbo MTU (e.g. 9192) on the
              # handoff segment; networkd then tries to set the WAN's IPv6
              # MTU above its 1500 link MTU, which the kernel rejects with
              # EINVAL on every RA — flooding the logs. The internet path
              # MTU is 1500 regardless, so the advertised value is useless
              # here.
              UseMTU = false;
            };
            linkConfig.RequiredForOnline = "routable";
          };

          # parentPorts / ownerBridgeOf / childBridgeOf:
          #   parentPorts: physical ports that need their own parent .network
          #   unit (the untagged WAN uplink is excluded when WAN is direct — it
          #   has its own 10-wan DHCP-client unit). An owned port enslaves to its
          #   owner's bridge; a trunk-only port is a pure carrier (no bridge/L3).
          #   childBridgeOf: the bridge a VLAN child enslaves to (WAN → br-wan).
          directWanPort = optionals (!wanIsBridged) wanPhys;
          parentPorts = subtractLists directWanPort allPhys;
          ownerOf = p: findFirst (n: elem p n.phys) (head netList) netList;
          ownerBridgeOf =
            p:
            let
              n = ownerOf p;
            in
            if n.key == "wan" then brWAN else n.bridge;
          childBridgeOf = net: if net.key == "wan" then brWAN else net.bridge;

          # mkPortUnit:
          #   The parent .network unit for a physical port: attaches the VLAN
          #   sub-interfaces riding on it (`vlan` list) and, if the port has an
          #   untagged owner, enslaves it to that owner's bridge. Trunk-only
          #   ports carry tagged VLANs only and terminate no L3 themselves.
          mkPortUnit =
            p:
            let
              owned = elem p ownedPorts;
            in
            {
              matchConfig.Name = p;
              networkConfig = {
                ConfigureWithoutCarrier = true;
                LinkLocalAddressing = "no";
                IPv6AcceptRA = false;
              }
              // optionalAttrs owned { Bridge = ownerBridgeOf p; };
              vlan = childrenOnPort p;
              linkConfig.RequiredForOnline = if owned then "enslaved" else "no";
            };

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
            ''iifname "${wanIf}" udp dport ${toString wg.listenPort} accept comment "Allow WireGuard ${name}"''
          ) wgNames;

          # wgForwardRules:
          #   For each WireGuard tunnel, generates bidirectional forwarding
          #   rules (LAN ↔ WG) and outbound WAN access with stateful return
          #   traffic. This allows VPN clients to reach LAN resources and
          #   route to the internet through the router.
          wgForwardRules = concatMapStringsSep "\n          " (name: ''
            # LAN ↔ ${name} (bidirectional)
            iifname "${brLAN}" oifname "${name}" accept
            iifname "${name}"  oifname "${brLAN}" accept

            # ${name} → WAN
            iifname "${name}" oifname "${wanIf}" accept
            iifname "${wanIf}" oifname "${name}" ct state { established, related } accept'') wgNames;

          # portForwardDnatRules / portForwardFilterRules:
          #   Static inbound port forwarding (DNAT) generated from
          #   cfg.portForwards. Each entry rewrites WAN-inbound traffic on
          #   the listed ports to an internal host (prerouting DNAT), and a
          #   matching accept rule lets that traffic cross the drop-policy
          #   forward chain (matched on destination IP + port, so it does
          #   not depend on which bridge the host is on). IPv4 only; ports
          #   are mapped 1:1 (router port == destination port). An optional
          #   `source` restricts the accepted WAN source prefix.
          pfDports =
            ports:
            if length ports == 1 then
              toString (head ports)
            else
              "{ ${concatMapStringsSep ", " toString ports} }";
          pfSaddr = source: optionalString (source != null) "ip saddr ${source} ";
          pfComment = name: optionalString (name != "") " comment \"${name}\"";
          portForwardDnatRules = concatMapStringsSep "\n                " (
            f:
            ''iifname "${wanIf}" ${pfSaddr f.source}${f.protocol} dport ${pfDports f.ports} dnat ip to ${f.destination}${pfComment f.name}''
          ) cfg.portForwards;
          portForwardFilterRules = concatMapStringsSep "\n                " (
            f:
            ''iifname "${wanIf}" ${pfSaddr f.source}ip daddr ${f.destination} ${f.protocol} dport ${pfDports f.ports} ct state { new, established, related } accept${pfComment f.name}''
          ) cfg.portForwards;

          # ════════════════════════════════════════════════════════
          #  Web admin UI — OliveTin control actions + wrappers
          # ════════════════════════════════════════════════════════
          # OliveTin runs as an unprivileged user. Each privileged
          # operation is a tiny wrapper script that sudo allowlists by
          # exact store path; the wrapper self-validates its input. The
          # generated `actions`/`dashboards` feed services.olivetin.settings
          # in the config section (§7).
          sudoBin = "${config.security.wrapperDir}/sudo";
          otHost = cfg.hostName;
          otFlake = cfg.webui.olivetin.flakePath;
          aghBase = "http://127.0.0.1:${toString cfg.dns.adguard.webPort}";

          # Units OliveTin may restart — drives both the UI dropdown and
          # the restart wrapper's allowlist.
          managedUnits = [
            "systemd-networkd"
            "sshd"
            "avahi-daemon"
            "olivetin"
          ]
          ++ optional cfg.dns.adguard.enable "adguardhome"
          ++ optional cfg.suricata.enable "suricata"
          ++ optional cfg.webui.netdata.enable "netdata"
          ++ optional cfg.webui.homepage.enable "homepage-dashboard";

          otWrappers = {
            restart = pkgs.writeShellApplication {
              name = "router-svc-restart";
              runtimeInputs = [ pkgs.systemd ];
              text = ''
                unit="''${1:-}"
                case "$unit" in
                  ${concatStringsSep "|" managedUnits})
                    exec systemctl restart "$unit.service"
                    ;;
                  *)
                    echo "refusing to restart unmanaged unit: $unit" >&2
                    exit 1
                    ;;
                esac
              '';
            };
            reboot = pkgs.writeShellApplication {
              name = "router-reboot";
              runtimeInputs = [ pkgs.systemd ];
              text = "exec systemctl reboot";
            };
            updateStage = pkgs.writeShellApplication {
              name = "router-update-stage";
              runtimeInputs = [
                pkgs.nix
                pkgs.nixos-rebuild
                pkgs.git
                pkgs.systemd
                pkgs.coreutils
              ];
              text = ''
                nix flake update --flake ${otFlake}
                exec nixos-rebuild boot --flake ${otFlake}#${otHost}
              '';
            };
            updateApply = pkgs.writeShellApplication {
              name = "router-update-apply";
              runtimeInputs = [
                pkgs.nix
                pkgs.nixos-rebuild
                pkgs.git
                pkgs.systemd
                pkgs.coreutils
              ];
              text = "exec nixos-rebuild switch --flake ${otFlake}#${otHost}";
            };
            rollback = pkgs.writeShellApplication {
              name = "router-update-rollback";
              runtimeInputs = [
                pkgs.nix
                pkgs.nixos-rebuild
                pkgs.systemd
              ];
              text = "exec nixos-rebuild switch --rollback";
            };
            suricataUpdate = pkgs.writeShellApplication {
              name = "router-suricata-update";
              runtimeInputs = [ pkgs.systemd ];
              text = ''
                systemctl start --wait suricata-update.service
                exec systemctl reload suricata.service
              '';
            };
            suricataRecent = pkgs.writeShellApplication {
              name = "router-suricata-recent";
              runtimeInputs = [
                pkgs.coreutils
                pkgs.jq
              ];
              text = ''
                n="''${1:-50}"
                case "$n" in
                  "" | *[!0-9]*) n=50 ;;
                esac
                tail -n "$n" /var/log/suricata/eve.json 2>/dev/null \
                  | jq -r 'select(.event_type=="alert" or .event_type=="drop")
                           | [.timestamp, .event_type, (.src_ip // "-"), (.dest_ip // "-"), (.proto // "-"), (.alert.signature // "-")]
                           | @tsv' \
                  || true
              '';
            };
            wgShow = pkgs.writeShellApplication {
              name = "router-wg-show";
              runtimeInputs = [ pkgs.wireguard-tools ];
              text = "exec wg show all dump";
            };
          };

          sudoCmd = w: "${sudoBin} ${getExe w}";
          unitChoices = map (u: {
            value = u;
            title = u;
          }) managedUnits;
          confirmArg = {
            name = "confirm";
            title = "Confirm";
            type = "confirmation";
          };

          # Generated OliveTin actions, grouped by area. Read-only actions
          # run directly; privileged ones call a sudo-wrapped script.
          otActions = [
            # ── System ──
            {
              title = "System · failed units";
              icon = "🩺";
              shell = "systemctl --failed --no-legend --no-pager || true";
            }
            {
              title = "System · resource snapshot";
              icon = "📊";
              shell = "uptime; echo; free -h; echo; df -h /";
            }
            {
              title = "System · service status";
              icon = "🔍";
              arguments = [
                {
                  name = "unit";
                  title = "Service";
                  choices = unitChoices;
                }
              ];
              shell = "systemctl status {{ unit }}.service --no-pager -n 25 || true";
            }
            {
              title = "System · restart service";
              icon = "🔄";
              arguments = [
                {
                  name = "service";
                  title = "Service";
                  choices = unitChoices;
                }
              ];
              shell = "${sudoCmd otWrappers.restart} {{ service }}";
            }
            {
              title = "System · reboot router";
              icon = "⚠️";
              timeout = 60;
              arguments = [ confirmArg ];
              shell = ''
                : "{{ confirm }}"
                ${sudoCmd otWrappers.reboot}
              '';
            }
            # ── Updates ──
            {
              title = "Update · stage for next boot";
              icon = "⬆️";
              timeout = 3600;
              shell = sudoCmd otWrappers.updateStage;
            }
            {
              title = "Update · apply now (switch)";
              icon = "🚀";
              timeout = 3600;
              arguments = [ confirmArg ];
              shell = ''
                : "{{ confirm }}"
                ${sudoCmd otWrappers.updateApply}
              '';
            }
            {
              title = "Update · rollback to previous";
              icon = "↩️";
              timeout = 1200;
              arguments = [ confirmArg ];
              shell = ''
                : "{{ confirm }}"
                ${sudoCmd otWrappers.rollback}
              '';
            }
            {
              title = "Update · list generations";
              icon = "🗂️";
              shell = "nix-env --list-generations --profile /nix/var/nix/profiles/system || true";
            }
            # ── Network ──
            {
              title = "Network · devices (neighbours)";
              icon = "🖥️";
              shell = "ip neigh show | sort";
            }
            {
              title = "Network · interfaces";
              icon = "🔌";
              shell = "networkctl list --no-pager; echo; ip -br addr";
            }
            {
              title = "Network · WireGuard peers";
              icon = "🔐";
              shell = ''${sudoCmd otWrappers.wgShow} || echo "no wireguard peers"'';
            }
            # ── DNS (AdGuard REST API on localhost) ──
            {
              title = "DNS · recent queries";
              icon = "🌐";
              arguments = [
                {
                  name = "limit";
                  title = "Rows";
                  type = "int";
                  default = "50";
                }
              ];
              shell = ''curl -s "${aghBase}/control/querylog?limit={{ limit }}" | jq -r '.data[] | [.time, .client, (.question.name // .question.host // "?"), (.reason // "")] | @tsv' '';
            }
            {
              title = "DNS · recent blocks";
              icon = "🛑";
              arguments = [
                {
                  name = "limit";
                  title = "Rows";
                  type = "int";
                  default = "50";
                }
              ];
              shell = ''curl -s "${aghBase}/control/querylog?response_status=blocked&limit={{ limit }}" | jq -r '.data[] | [.time, .client, (.question.name // .question.host // "?"), (.reason // "")] | @tsv' '';
            }
            {
              title = "DNS · search domain";
              icon = "🔎";
              arguments = [
                {
                  name = "domain";
                  title = "Domain contains";
                  type = "ascii_identifier";
                }
                {
                  name = "limit";
                  title = "Rows";
                  type = "int";
                  default = "50";
                }
              ];
              shell = ''curl -s "${aghBase}/control/querylog?search={{ domain }}&limit={{ limit }}" | jq -r '.data[] | [.time, .client, (.question.name // .question.host // "?"), (.reason // "")] | @tsv' '';
            }
            {
              title = "DNS · stats summary";
              icon = "📈";
              shell = ''curl -s "${aghBase}/control/stats" | jq '{queries: .num_dns_queries, blocked: .num_blocked_filtering, safebrowsing: .num_replaced_safebrowsing, safesearch: .num_replaced_safesearch, avg_ms: .avg_processing_time}' '';
            }
            {
              title = "DNS · pause filtering 5 min";
              icon = "⏸️";
              arguments = [ confirmArg ];
              shell = ''
                : "{{ confirm }}"
                curl -s -X POST "${aghBase}/control/protection" --json '{"enabled":false,"duration":300000}' && echo "filtering paused 5 min"
              '';
            }
            {
              title = "DNS · resume filtering";
              icon = "▶️";
              shell = ''curl -s -X POST "${aghBase}/control/protection" --json '{"enabled":true}' && echo "filtering resumed"'';
            }
            {
              title = "DNS · flush cache";
              icon = "🧹";
              shell = ''curl -s -X POST "${aghBase}/control/cache_clear" && echo "cache cleared"'';
            }
            {
              title = "DNS · reload filters";
              icon = "🔁";
              shell = ''curl -s -X POST "${aghBase}/control/filtering/refresh" --json '{"whitelist":false}' && echo "filters refreshed"'';
            }
            # ── Security (Suricata) ──
            {
              title = "Security · recent blocks/alerts";
              icon = "🛡️";
              arguments = [
                {
                  name = "count";
                  title = "Lines to scan";
                  type = "int";
                  default = "50";
                }
              ];
              shell = "${sudoCmd otWrappers.suricataRecent} {{ count }}";
            }
            {
              title = "Security · top signatures";
              icon = "🏷️";
              shell = "${sudoCmd otWrappers.suricataRecent} 5000 | awk -F'\\t' '{print $6}' | sort | uniq -c | sort -rn | head -20";
            }
            {
              title = "Security · update rules";
              icon = "📥";
              timeout = 900;
              shell = sudoCmd otWrappers.suricataUpdate;
            }
            {
              title = "Security · suricata status";
              icon = "🔍";
              shell = "systemctl status suricata.service --no-pager -n 20 || true";
            }
            # ── Logs ──
            {
              title = "Logs · tail unit";
              icon = "📜";
              arguments = [
                {
                  name = "unit";
                  title = "Service";
                  choices = unitChoices;
                }
                {
                  name = "lines";
                  title = "Lines";
                  type = "int";
                  default = "100";
                }
              ];
              shell = "journalctl -u {{ unit }}.service -n {{ lines }} --no-pager";
            }
            {
              title = "Logs · grep unit";
              icon = "🔦";
              arguments = [
                {
                  name = "unit";
                  title = "Service";
                  choices = unitChoices;
                }
                {
                  name = "pattern";
                  title = "Pattern";
                  type = "ascii_sentence";
                }
                {
                  name = "lines";
                  title = "Lines";
                  type = "int";
                  default = "200";
                }
              ];
              shell = "journalctl -u {{ unit }}.service -n {{ lines }} --no-pager -g {{ pattern }}";
            }
            {
              title = "Logs · recent errors";
              icon = "🚨";
              shell = "journalctl -p err -b -n 100 --no-pager";
            }
          ];

          otDashboards = [
            {
              title = "System";
              contents = [
                {
                  title = "Status";
                  type = "fieldset";
                  contents = [
                    { title = "System · failed units"; }
                    { title = "System · resource snapshot"; }
                    { title = "System · service status"; }
                  ];
                }
                {
                  title = "Control";
                  type = "fieldset";
                  contents = [
                    { title = "System · restart service"; }
                    { title = "System · reboot router"; }
                  ];
                }
              ];
            }
            {
              title = "Updates";
              contents = [
                { title = "Update · stage for next boot"; }
                { title = "Update · apply now (switch)"; }
                { title = "Update · rollback to previous"; }
                { title = "Update · list generations"; }
              ];
            }
            {
              title = "Network";
              contents = [
                { title = "Network · devices (neighbours)"; }
                { title = "Network · interfaces"; }
                { title = "Network · WireGuard peers"; }
              ];
            }
            {
              title = "DNS";
              contents = [
                {
                  title = "Lookups";
                  type = "fieldset";
                  contents = [
                    { title = "DNS · recent queries"; }
                    { title = "DNS · recent blocks"; }
                    { title = "DNS · search domain"; }
                    { title = "DNS · stats summary"; }
                  ];
                }
                {
                  title = "Controls";
                  type = "fieldset";
                  contents = [
                    { title = "DNS · pause filtering 5 min"; }
                    { title = "DNS · resume filtering"; }
                    { title = "DNS · flush cache"; }
                    { title = "DNS · reload filters"; }
                  ];
                }
              ];
            }
            {
              title = "Security";
              contents = [
                { title = "Security · recent blocks/alerts"; }
                { title = "Security · top signatures"; }
                { title = "Security · update rules"; }
                { title = "Security · suricata status"; }
              ];
            }
            {
              title = "Logs";
              contents = [
                { title = "Logs · tail unit"; }
                { title = "Logs · grep unit"; }
                { title = "Logs · recent errors"; }
              ];
            }
          ];

          # Non-secret OliveTin config. The `authLocalUsers` block (with the
          # Argon2id password hash) is merged in from auth.secretFile via
          # services.olivetin.extraConfigFiles, so it never enters the store.
          olivetinSettings = {
            logLevel = "INFO";
            ListenAddressSingleHTTPFrontend = "0.0.0.0:${toString cfg.webui.olivetin.port}";
            pageTitle = "${cfg.hostName} admin";
            authRequireGuestsToLogin = true;
            accessControlLists = [
              {
                name = "admins";
                matchUsergroups = [ "admins" ];
                addToEveryAction = true;
                permissions = {
                  view = true;
                  exec = true;
                  logs = true;
                };
              }
            ];
            actions = otActions ++ cfg.webui.olivetin.extraActions;
            dashboards = otDashboards;
          };

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
                  # Guest: DHCP/DNS and NDP to router only (all other guest→router dropped)
                  iifname "${brGuest}" udp dport { 53, 67 } accept
                  iifname "${brGuest}" tcp dport 53 accept
                  iifname "${brGuest}" icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept
                ''}

                # mDNS (multicast DNS) for hostname resolution
                udp dport 5353 accept comment "Allow mDNS queries"

                # WAN: only established/related + select ICMP
                iifname "${wanIf}" ct state { established, related } accept
                iifname "${wanIf}" icmp type { echo-request, destination-unreachable, time-exceeded } counter accept
                iifname "${wanIf}" icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } counter accept
                iifname "${wanIf}" udp dport 546 accept comment "DHCPv6 client"
                ${wgInputRules}

                # Drop everything else from WAN
                iifname "${wanIf}" counter drop
              }

              chain forward {
                type filter hook forward priority filter; policy drop;

                # Suricata IPS inline inspection (NFQUEUE with bypass)
                ${optionalString cfg.suricata.enable "queue num 0 bypass"}

                ${wgForwardRules}

                # LAN → WAN
                iifname "${brLAN}" oifname "${wanIf}" accept

                # WAN → LAN (established only)
                iifname "${wanIf}" oifname "${brLAN}" ct state { established, related } accept

                ${optionalString cfg.upnp.enable ''
                  # UPnP/NAT-PMP: accept inbound traffic matching an active
                  # miniupnpd port mapping. miniupnpd installs the DNAT in
                  # its own `inet miniupnpd` table; without this rule the
                  # redirected packets would hit this chain's `policy drop`.
                  iifname "${wanIf}" oifname "${brLAN}" ct status dnat accept
                ''}

                ${optionalString (cfg.portForwards != [ ]) ''
                  # Static inbound port forwards: allow WAN traffic destined
                  # for the configured internal hosts/ports (DNAT'd above).
                  ${portForwardFilterRules}
                ''}

                ${optionalString cfg.guest.enable ''
                  # Guest → WAN only (fully isolated from LAN and WireGuard)
                  iifname "${brGuest}" oifname "${wanIf}" accept
                  iifname "${wanIf}" oifname "${brGuest}" ct state { established, related } accept

                  # LAN → Guest (one-way access for administration)
                  iifname "${brLAN}" oifname "${brGuest}" accept
                ''}
              }
            }

            table inet nat {
              chain prerouting {
                type nat hook prerouting priority dstnat; policy accept;

                # Force all LAN DNS through local resolver (prevents bypass)
                # IPv4: DNAT to gateway IP; IPv6: redirect (PD address is dynamic)
                iifname "${brLAN}" udp dport 53 ip daddr != ${lanGW} dnat to ${lanGW}:53
                iifname "${brLAN}" tcp dport 53 ip daddr != ${lanGW} dnat to ${lanGW}:53
                iifname "${brLAN}" meta nfproto ipv6 udp dport 53 redirect to :53
                iifname "${brLAN}" meta nfproto ipv6 tcp dport 53 redirect to :53

                ${optionalString cfg.guest.enable ''
                  # Force guest DNS through local resolver
                  iifname "${brGuest}" udp dport 53 ip daddr != ${guestGW} dnat to ${guestGW}:53
                  iifname "${brGuest}" tcp dport 53 ip daddr != ${guestGW} dnat to ${guestGW}:53
                  iifname "${brGuest}" meta nfproto ipv6 udp dport 53 redirect to :53
                  iifname "${brGuest}" meta nfproto ipv6 tcp dport 53 redirect to :53
                ''}

                ${optionalString (cfg.portForwards != [ ]) ''
                  # Static inbound port forwards (WAN → internal hosts)
                  ${portForwardDnatRules}
                ''}
              }

              chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;
                # IPv4 masquerade only — IPv6 uses global PD addresses
                meta nfproto ipv4 oifname "${wanIf}" masquerade
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
          #    router.webui.*      → Unified web admin UI (OliveTin + Netdata + Homepage).
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

            # ── Trunk interfaces ───────────────────────────────────
            # Physical ports that carry VLAN-tagged traffic but have no untagged
            # network of their own. The canonical case is a single-NIC router
            # (e.g. a Raspberry Pi) cabled to a smart switch that delivers every
            # network as a tagged VLAN on that one port. List the port here and
            # give each network a `vlan` id; VLAN sub-interfaces are created on
            # every trunk port (in addition to other networks' interfaces).
            trunkInterfaces = mkOption {
              type = types.listOf types.str;
              default = [ ];
              description = "Physical ports carrying tagged VLANs with no untagged network of their own (e.g. a single switch-trunk uplink).";
            };

            # ── WAN ────────────────────────────────────────────────
            # The upstream (internet-facing) interface. This interface is
            # configured as a DHCPv4 client and is the masquerade source
            # for all outbound NAT. It receives the strictest firewall
            # treatment: only established/related traffic, select ICMP
            # types, and WireGuard UDP ports are allowed inbound.
            wan = {
              interface = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "WAN untagged uplink interface name (e.g. enp1s0). Set null for a VLAN-only WAN.";
              };

              vlan = mkOption {
                type = types.nullOr types.int;
                default = null;
                description = ''
                  WAN VLAN id (tagged); null = untagged uplink. The WAN tag is
                  carried only on `trunkInterfaces` (never on LAN/guest ports).
                  When set, the WAN DHCP client runs on a bridge (br-wan)
                  aggregating those VLAN sub-interfaces.
                '';
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
                default = [ ];
                description = "Physical LAN port interface names (untagged). May be empty for a VLAN-only LAN.";
              };

              vlan = mkOption {
                type = types.nullOr types.int;
                default = null;
                description = ''
                  VLAN id for this network's tagged traffic; null = untagged-only.
                  The tag is carried on `trunkInterfaces` plus this network's
                  `taggedInterfaces`.
                '';
              };

              taggedInterfaces = mkOption {
                type = types.listOf types.str;
                default = [ ];
                description = ''
                  Interfaces on which this network's VLAN tag is available, in
                  addition to the global `trunkInterfaces`. Non-exclusive: a port
                  may carry several networks' tags. Requires `vlan` to be set.
                '';
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
            #   • nftables restricts guest traffic to WAN-only (no LAN/WG access),
            #     but allows LAN to access Guest (one-way) for administration.
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
                description = "Physical interface names to assign to the guest bridge (untagged)";
              };

              vlan = mkOption {
                type = types.nullOr types.int;
                default = null;
                description = ''
                  VLAN id for this network's tagged traffic; null = untagged-only.
                  The tag is carried on `trunkInterfaces` plus this network's
                  `taggedInterfaces`.
                '';
              };

              taggedInterfaces = mkOption {
                type = types.listOf types.str;
                default = [ ];
                description = ''
                  Interfaces on which this network's VLAN tag is available, in
                  addition to the global `trunkInterfaces`. Non-exclusive: a port
                  may carry several networks' tags. Requires `vlan` to be set.
                '';
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

            # ── UPnP-IGD / NAT-PMP (miniupnpd) ─────────────────────
            # Optional automatic inbound port forwarding for LAN
            # clients (game consoles, P2P, some self-hosted apps).
            #
            # Disabled by default, deliberately: UPnP/NAT-PMP let LAN
            # devices punch holes in the firewall with no authentication,
            # which runs counter to the rest of the hardened design (IPS,
            # forced DNS, guest isolation). Only enable it with a concrete
            # need, and never expose it to the guest network.
            #
            # When enabled, hardened defaults are applied automatically
            # (see the services.miniupnpd block in the config section):
            #   • nftables backend (auto-selected by the module).
            #   • secure_mode — a client may only map ports to its OWN IP.
            #   • listens on the LAN bridge ONLY (guest/IoT can never
            #     request mappings).
            #   • only non-privileged ports (1024-65535) may be mapped.
            upnp = {
              enable = mkEnableOption "UPnP-IGD / NAT-PMP automatic port forwarding (miniupnpd)";

              extraConfig = mkOption {
                type = types.lines;
                default = "";
                description = "Additional miniupnpd.conf lines, appended after the hardened defaults";
              };
            };

            # ── Static port forwards (DNAT) ───────────────────────
            # Explicit inbound port forwarding from the WAN to internal
            # hosts. Unlike UPnP, every hole is declared in configuration
            # and auditable. Each entry forwards its listed ports to a
            # fixed internal IPv4 host; ports are mapped 1:1 (router port ==
            # destination port). Use the optional `source` to restrict the
            # forward to a specific WAN source prefix.
            #
            # SECURITY: each forward exposes the host directly to the
            # internet. When Suricata is enabled the inbound traffic is
            # IPS-inspected; regardless, only forward what must be reachable
            # and prefer narrowing `source` where possible.
            portForwards = mkOption {
              default = [ ];
              description = "Static inbound port forwards (DNAT) from the WAN to internal hosts. IPv4 only.";
              example = literalExpression ''
                [
                  {
                    name = "Synology DSM";
                    destination = "10.48.4.2";
                    ports = [ 5080 5443 ];
                  }
                ]
              '';
              type = types.listOf (
                types.submodule {
                  options = {
                    name = mkOption {
                      type = types.str;
                      default = "";
                      description = "Descriptive label, emitted as an nftables rule comment.";
                    };
                    protocol = mkOption {
                      type = types.enum [
                        "tcp"
                        "udp"
                      ];
                      default = "tcp";
                      description = "Transport protocol to forward.";
                    };
                    destination = mkOption {
                      type = types.str;
                      example = "10.48.4.2";
                      description = "Internal IPv4 address to forward the traffic to.";
                    };
                    ports = mkOption {
                      type = types.listOf types.port;
                      example = [
                        80
                        443
                      ];
                      description = "WAN-facing ports to forward, each mapped 1:1 to the same port on `destination`.";
                    };
                    source = mkOption {
                      type = types.nullOr types.str;
                      default = null;
                      example = "203.0.113.0/24";
                      description = "Optional WAN source prefix the forward is restricted to. Null allows any source.";
                    };
                  };
                }
              );
            };

            # ── Web admin UI — OliveTin + Netdata + Homepage ──────
            # Unified browser-based admin surface (replaces Cockpit):
            #   • OliveTin  — control actions (restart services, staged
            #     updates, DNS query search, Suricata blocks); guarded by
            #     a local-user login.
            #   • Netdata   — live system monitoring (offline; no cloud).
            #   • Homepage  — read-only landing page tying them together.
            # All reachable from trusted interfaces (LAN + WG) via the
            # nftables input chain; never exposed to the WAN. The NixOS
            # firewall is not used (nftables already accepts trusted IFs).
            webui = {
              enable = mkEnableOption "unified web admin UI (OliveTin + Netdata + Homepage)";

              olivetin = {
                port = mkOption {
                  type = types.port;
                  default = 1337;
                  description = "Port for the OliveTin control UI";
                };

                flakePath = mkOption {
                  type = types.str;
                  default = "/etc/nixos";
                  description = "Path to the flake used for system updates triggered from the web UI";
                };

                auth.secretFile = mkOption {
                  type = types.nullOr types.path;
                  default = null;
                  example = "/run/secrets/olivetin-auth.yaml";
                  description = ''
                    Path to a YAML file merged into OliveTin's config (kept out of
                    the Nix store via systemd LoadCredential) that supplies the
                    entire `authLocalUsers` block — username(s) and Argon2id
                    password hash(es). Generate a hash with the argon2 CLI, or:
                      curl -sS --json '{"password":"<pw>"}' \
                        http://<router>:1337/api/PasswordHash
                    then write, e.g.:
                      authLocalUsers:
                        enabled: true
                        users:
                          - username: admin
                            usergroup: admins
                            password: $argon2id$v=19$...
                    Required when router.webui.enable is set (enforced by assertion).
                  '';
                };

                extraActions = mkOption {
                  type = types.listOf (types.attrsOf types.anything);
                  default = [ ];
                  description = "Additional OliveTin action definitions appended to the generated set";
                };
              };

              netdata = {
                enable = mkOption {
                  type = types.bool;
                  default = true;
                  description = "Enable Netdata live monitoring as part of the web UI";
                };

                port = mkOption {
                  type = types.port;
                  default = 19999;
                  description = "Port for the Netdata dashboard";
                };
              };

              homepage = {
                enable = mkOption {
                  type = types.bool;
                  default = true;
                  description = "Enable the Homepage landing dashboard as part of the web UI";
                };

                port = mkOption {
                  type = types.port;
                  default = 8082;
                  description = "Port for the Homepage landing dashboard";
                };
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
          #   7. Web admin UI      — OliveTin + Netdata + Homepage (optional).
          #   8. Packages          — System packages (diagnostic tools, etc.).
          #   9. Logging           — journald size/retention limits.
          #  10. Hardening         — SSH lockdown, sudo policy.
          #  11. Maintenance       — Nix GC, auto-upgrade.
          # ══════════════════════════════════════════════════════════
          config = {

            # ── Network assignment validation ────────────────────
            # Catch misconfiguration of the interface/VLAN model early, with
            # clear messages, rather than producing a broken networkd config.
            assertions =
              let
                vlanIds = filter (v: v != null) (
                  [
                    cfg.wan.vlan
                    cfg.lan.vlan
                  ]
                  ++ optional cfg.guest.enable cfg.guest.vlan
                );
              in
              [
                {
                  assertion = cfg.wan.interface != null || cfg.wan.vlan != null;
                  message = "router.wan: set an `interface` (untagged uplink) and/or a `vlan` id.";
                }
                {
                  assertion = cfg.lan.interfaces != [ ] || cfg.lan.vlan != null;
                  message = "router.lan: set `interfaces` (untagged) and/or a `vlan` id.";
                }
                {
                  assertion = !cfg.guest.enable || (cfg.guest.interfaces != [ ] || cfg.guest.vlan != null);
                  message = "router.guest: when enabled, set `interfaces` (untagged) and/or a `vlan` id.";
                }
                {
                  assertion = allPhys != [ ];
                  message = "router: at least one physical interface must be assigned (no port exists to carry traffic).";
                }
                {
                  assertion = ownedPorts == unique ownedPorts;
                  message = "router: a physical interface is assigned to more than one network; each port has exactly one untagged owner.";
                }
                {
                  assertion = all (n: n.vlan == null || n.taggedPorts != [ ]) netList;
                  message = "router: a VLAN-based network has no ports to carry its tag; add to its `taggedInterfaces` (WAN: `trunkInterfaces`) or set `trunkInterfaces`.";
                }
                {
                  assertion = cfg.lan.taggedInterfaces == [ ] || cfg.lan.vlan != null;
                  message = "router.lan: `taggedInterfaces` is set but `vlan` is null; set a `vlan` id.";
                }
                {
                  assertion = cfg.guest.taggedInterfaces == [ ] || cfg.guest.vlan != null;
                  message = "router.guest: `taggedInterfaces` is set but `vlan` is null; set a `vlan` id.";
                }
                {
                  assertion = vlanIds == unique vlanIds;
                  message = "router: two networks share a VLAN id; each network's VLAN id must be distinct.";
                }
                {
                  assertion = all (v: v >= 1 && v <= 4094) vlanIds;
                  message = "router: VLAN ids must be in the range 1–4094.";
                }
                {
                  assertion = all (c: stringLength c.child <= 15) allChildren;
                  message = "router: a VLAN sub-interface name (<port>.<vid>) exceeds the 15-char kernel limit (IFNAMSIZ); use a shorter parent interface name.";
                }
                {
                  assertion = !cfg.webui.enable || cfg.webui.olivetin.auth.secretFile != null;
                  message = "router.webui.enable requires router.webui.olivetin.auth.secretFile — the YAML file providing OliveTin's authLocalUsers login block (kept out of the Nix store).";
                }
              ];

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

            # ── 3. systemd-networkd — interfaces + bridge ────────
            # All network configuration is handled by systemd-networkd.
            # NixOS's built-in DHCP, NAT, and firewall are disabled to
            # avoid conflicts with our explicit networkd + nftables setup.
            #
            # Interface topology:
            #   Each network (wan/lan/guest) claims UNTAGGED traffic on its
            #   assigned `interfaces` and/or TAGGED traffic for its `vlan` id on
            #   the trunk (`trunkInterfaces`) plus its own `taggedInterfaces`. A
            #   port can carry both at once — untagged frames go to the owner's
            #   bridge, tagged frames to the <port>.<vid> sub-interface (kernel
            #   802.1q demux precedes the bridge), so one wire feeds many networks.
            #
            #   WAN ─── DHCPv4 client (on the uplink, or br-wan when VLAN-based)
            #   LAN ports / <port>.<lanVid> ──── br-lan ─── static IP (gateway)
            #   Guest ports / <port>.<guestVid> ─ br-guest ─ static IP (gateway)
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

              # ── Virtual devices (bridges + VLANs) ──────────────
              # The LAN bridge aggregates LAN members (untagged ports and/or
              # tagged VLAN sub-interfaces) into one L2 domain. Guest bridge is
              # created only when guest.enable = true. br-wan is created only
              # when WAN is VLAN-based / has no untagged uplink. One VLAN netdev
              # (<port>.<vid>) is created per (VLAN network × other port) pair.
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
              }
              // optionalAttrs wanIsBridged {
                "22-br-wan" = {
                  netdevConfig = {
                    Kind = "bridge";
                    Name = brWAN;
                  };
                };
              }
              // listToAttrs (
                map (
                  c:
                  nameValuePair "60-${c.child}" {
                    netdevConfig = {
                      Kind = "vlan";
                      Name = c.child;
                    };
                    vlanConfig.Id = c.net.vlan;
                  }
                ) allChildren
              );

              # ── Network units ────────────────────────────────────
              networks = {
                # WAN interface: DHCP client for upstream connectivity.
                # • IPv4Forwarding: enables kernel forwarding sysctl for this IF.
                # • IPv4ReversePathFilter=strict: drops packets with spoofed
                #   source addresses (BCP38/RFC3704 compliance).
                # • IPv6AcceptRA=true: accept Router Advertisements from ISP.
                # • IPv6Forwarding=true: enables kernel IPv6 forwarding sysctl.
                # • IgnoreCarrierLoss=3s: tolerates brief cable/modem blips
                #   without tearing down DHCP lease and routes.
                # • KeepConfiguration=dynamic-on-stop: preserves DHCP addresses
                #   and routes during networkd restarts (avoids brief outages).
                # • dhcpV4Config: prevents ISP DHCP from overriding local DNS
                #   (UseDNS/UseHostname/UseDomains=false), while still sending
                #   our hostname to the ISP for lease identification.
                #   RouteMetric=100 gives WAN routes explicit priority.
                # • dhcpV6Config: requests prefix delegation (/60) from ISP
                #   for distributing IPv6 subnets to LAN/guest bridges.
                # • ipv6AcceptRAConfig: always start DHCPv6 client (some ISPs
                #   require it even when RA M-flag is set).
                # The shared DHCP-client config (wanNetworkBase) is applied to
                # the untagged uplink, or to the br-wan bridge when WAN is
                # VLAN-based. Other networks' VLAN sub-interfaces that ride on
                # the untagged WAN port are attached via the `vlan` list.
                "10-wan" = wanNetworkBase // {
                  matchConfig.Name = wanIf;
                  vlan = optionals (!wanIsBridged) (childrenOnPort cfg.wan.interface);
                };

                # LAN bridge: the router's internal gateway interface.
                # • Static IP address (lanGW/lanPrefix) — this is the default
                #   gateway and DNS server for all LAN clients.
                # • DHCPServer=true: networkd serves DHCP directly on the bridge,
                #   eliminating startup-ordering issues with external DHCP daemons.
                # • dhcpServerConfig: pool range via PoolOffset/PoolSize,
                #   DNS points clients to the gateway (AGH on :53), EmitRouter
                #   auto-advertises the bridge IP as the default gateway.
                # • ConfigureWithoutCarrier: keeps config stable even if all
                #   physical ports are unplugged momentarily.
                # • IPv4Forwarding: enables IP forwarding on this interface.
                # • IPv4ReversePathFilter=no: relaxed because traffic arrives
                #   from bridged ports with various source subnets.
                # • IPv6AcceptRA=false: blocks rogue IPv6 RAs on the bridge.
                # • IPv6SendRA=true: advertise delegated IPv6 prefix to LAN
                #   clients via Router Advertisements (SLAAC).
                # • DHCPPrefixDelegation=true: assign a /64 from the WAN-delegated
                #   prefix to this bridge for LAN client use.
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
                    DHCPPrefixDelegation = true;
                    IPv4Forwarding = true;
                    IPv6Forwarding = true;
                    IPv4ReversePathFilter = "no";
                    IPv6AcceptRA = false;
                    IPv6SendRA = true;
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
                  dhcpPrefixDelegationConfig = {
                    UplinkInterface = wanIf;
                    SubnetId = 0;
                    Announce = true;
                  };
                  ipv6SendRAConfig = {
                    EmitDNS = false;
                  };
                  linkConfig.RequiredForOnline = "no";
                };
              }
              # Physical ports: one parent .network per port. An owned port
              # enslaves to its owner network's bridge (untagged); a trunk-only
              # port is a pure carrier. Each attaches (via the `vlan` list) the
              # VLAN sub-interfaces of other networks that ride on it. The kernel
              # delivers tagged frames to those children before the bridge sees
              # them, so untagged + tagged coexist on one wire. (The untagged WAN
              # uplink is handled by 10-wan above.)
              // listToAttrs (map (p: nameValuePair "30-port-${p}" (mkPortUnit p)) parentPorts)
              # VLAN sub-interfaces (<port>.<vid>): each enslaved to the bridge
              # of the network that owns the VLAN id (br-lan/br-guest/br-wan).
              // listToAttrs (
                map (
                  c:
                  nameValuePair "61-${c.child}" {
                    matchConfig.Name = c.child;
                    networkConfig = {
                      Bridge = childBridgeOf c.net;
                      ConfigureWithoutCarrier = true;
                      LinkLocalAddressing = "no";
                      IPv6AcceptRA = false;
                    };
                    linkConfig.RequiredForOnline = "enslaved";
                  }
                ) allChildren
              )
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
                # Guest bridge — same config pattern as br-lan, but on
                # a separate subnet with a different PD SubnetId.
                # nftables isolates guest from LAN/WG.
                # DHCPServer config mirrors LAN but with guest-specific pool
                # and shorter lease time for address rotation.
                "41-br-guest" = {
                  matchConfig.Name = brGuest;
                  address = [ "${guestGW}/${guestPrefix}" ];
                  networkConfig = {
                    ConfigureWithoutCarrier = true;
                    DHCPServer = true;
                    DHCPPrefixDelegation = true;
                    IPv4Forwarding = true;
                    IPv6Forwarding = true;
                    IPv4ReversePathFilter = "no";
                    IPv6AcceptRA = false;
                    IPv6SendRA = true;
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
                  dhcpPrefixDelegationConfig = {
                    UplinkInterface = wanIf;
                    SubnetId = 1;
                    Announce = true;
                  };
                  ipv6SendRAConfig = {
                    EmitDNS = false;
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
            # systemd-resolved must be disabled to free port 53 for AGH.
            networking.nameservers = [
              "127.0.0.1"
              "::1"
            ];
            services.resolved.enable = false;

            services.adguardhome = mkIf cfg.dns.adguard.enable {
              enable = true;
              mutableSettings = false; # disable runtime changes via AGH UI (managed by NixOS config)
              # Web UI/API binds to localhost only when the unified web UI is
              # enabled — AGH's own UI is hidden from the LAN and surfaced
              # exclusively through OliveTin (DNS views) + Homepage (widget),
              # both of which reach it over 127.0.0.1. Otherwise bind to lanGW.
              host = if cfg.webui.enable then "127.0.0.1" else lanGW;
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

                  # Query log + statistics power the OliveTin DNS views and the
                  # Homepage AdGuard widget (read via the REST API on localhost).
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

            # ── UPnP-IGD / NAT-PMP — miniupnpd ───────────────────
            # Active only when router.upnp.enable = true. The NixOS
            # module auto-selects the nftables backend (because
            # networking.nftables.enable = true) and adds an
            # `inet miniupnpd` table to the ruleset, into which the daemon
            # installs DNAT mappings at runtime. The `ct status dnat accept`
            # rule in the nftRuleset forward chain lets that redirected
            # traffic cross the drop-policy forward chain.
            #
            # Hardened defaults:
            #   • secure_mode=yes — a client may only forward a port to its
            #     OWN IP, never to another host on the LAN.
            #   • internalIPs = LAN bridge only — the guest/IoT network can
            #     never request mappings.
            #   • allow/deny — only ports 1024-65535 from the LAN subnet may
            #     be mapped; everything else is denied.
            #
            # NOTE: when the nftables ruleset reloads (e.g. on a
            # `nixos-rebuild switch`) it is flushed (flushRuleset defaults
            # on for a monolithic ruleset), clearing miniupnpd's live
            # mappings. Clients re-request them on their next renewal; the
            # lease_file + partOf binding lets a miniupnpd restart restore
            # them from disk immediately.
            services.miniupnpd = mkIf cfg.upnp.enable {
              enable = true;
              externalInterface = wanIf;
              internalIPs = [ brLAN ];
              natpmp = true;
              upnp = true;
              appendConfig = ''
                secure_mode=yes
                friendly_name=NixOS Router
                lease_file=/var/lib/miniupnpd/upnp.leases
                # Only non-privileged ports from the LAN subnet may be mapped.
                allow 1024-65535 ${lanCIDR} 1024-65535
                deny 0-65535 0.0.0.0/0 0-65535
                ${cfg.upnp.extraConfig}
              '';
            };

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
            environment.etc = mkIf cfg.suricata.enable {
              "suricata/rules/local.rules".text = localSuricataRules;
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

            systemd.services = mkMerge [
              {
                flake-update = {
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
              }
              # Suricata service overrides and other systemd services.
              (mkIf cfg.suricata.enable {
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
                };

                # Reload Suricata after rule updates (uses + prefix for
                # root privileges since suricata-update runs as limited user)
                suricata-update.serviceConfig.ExecStartPost = "+${pkgs.systemd}/bin/systemctl try-reload-or-restart suricata.service";
              })
              # miniupnpd: start after the firewall is up (so its
              # `inet miniupnpd` table exists) and follow firewall restarts.
              # StateDirectory provisions /var/lib/miniupnpd for the lease_file.
              (mkIf cfg.upnp.enable {
                miniupnpd = {
                  after = [ "nftables.service" ];
                  partOf = [ "nftables.service" ];
                  serviceConfig.StateDirectory = "miniupnpd";
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

            # ── 7. Web admin UI — OliveTin + Netdata + Homepage ──
            # Unified admin surface (replaces Cockpit). All three bind to
            # the LAN/WG-trusted interfaces only — the nftables input chain
            # accepts trusted IFs while the WAN drops new connections, so
            # openFirewall stays false everywhere (nftables, not the NixOS
            # firewall, governs exposure). OliveTin gates control actions
            # behind a local login; Netdata and Homepage are read-only.
            services.olivetin = mkIf cfg.webui.enable {
              enable = true;
              package = pkgs.olivetin-3k;
              extraConfigFiles = optional (
                cfg.webui.olivetin.auth.secretFile != null
              ) cfg.webui.olivetin.auth.secretFile;
              path = with pkgs; [
                bash
                coreutils
                jq
                curl
                gnugrep
                gnused
                gawk
                iproute2
                systemd
                avahi
                nix
              ];
              settings = olivetinSettings;
            };

            # OliveTin reads the journal via group membership (no sudo) and
            # runs privileged ops only through the sudo-allowlisted wrappers.
            users.users.olivetin.extraGroups = mkIf cfg.webui.enable [ "systemd-journal" ];
            security.sudo.extraRules = mkIf cfg.webui.enable [
              {
                users = [ "olivetin" ];
                commands = map (w: {
                  command = getExe w;
                  options = [ "NOPASSWD" ];
                }) (builtins.attrValues otWrappers);
              }
            ];

            # Netdata — live monitoring (offline; no cloud claiming/telemetry).
            services.netdata = mkIf (cfg.webui.enable && cfg.webui.netdata.enable) {
              enable = true;
              config = {
                global = {
                  "update every" = "1";
                };
                web = {
                  "default port" = toString cfg.webui.netdata.port;
                };
                ml = {
                  "enabled" = "yes";
                };
              };
            };

            # Homepage — read-only landing page (no built-in auth; LAN/WG trust).
            services.homepage-dashboard = mkIf (cfg.webui.enable && cfg.webui.homepage.enable) {
              enable = true;
              listenPort = cfg.webui.homepage.port;
              openFirewall = false;
              allowedHosts = concatStringsSep "," [
                "localhost:${toString cfg.webui.homepage.port}"
                "127.0.0.1:${toString cfg.webui.homepage.port}"
                "${lanGW}:${toString cfg.webui.homepage.port}"
                "${cfg.hostName}.${cfg.lan.domain}:${toString cfg.webui.homepage.port}"
                "${cfg.hostName}.local:${toString cfg.webui.homepage.port}"
              ];
              settings = {
                title = "${cfg.hostName} admin";
                headerStyle = "boxed";
              };
              widgets = [
                {
                  resources = {
                    cpu = true;
                    memory = true;
                    disk = "/";
                  };
                }
                {
                  search = {
                    provider = "duckduckgo";
                    target = "_blank";
                  };
                }
              ];
              services = [
                {
                  "Control" = [
                    {
                      "OliveTin" = {
                        href = "http://${lanGW}:${toString cfg.webui.olivetin.port}/";
                        description = "System actions & control";
                        siteMonitor = "http://127.0.0.1:${toString cfg.webui.olivetin.port}";
                      };
                    }
                  ];
                }
              ]
              ++ optional cfg.webui.netdata.enable {
                "Monitoring" = [
                  {
                    "Netdata" = {
                      href = "http://${lanGW}:${toString cfg.webui.netdata.port}/";
                      description = "Live system metrics";
                      widget = {
                        type = "netdata";
                        url = "http://127.0.0.1:${toString cfg.webui.netdata.port}";
                      };
                    };
                  }
                ];
              }
              ++ optional cfg.dns.adguard.enable {
                "DNS" = [
                  {
                    "AdGuard Home" = {
                      href = "http://${lanGW}:${toString cfg.webui.olivetin.port}/";
                      description = "Filtering — manage via OliveTin";
                      widget = {
                        type = "adguard";
                        url = aghBase;
                      };
                    };
                  }
                ];
              };
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
                (writeShellScriptBin "system-upgrade" ''
                  sudo sh -c 'cd /etc/nixos && nix flake update && nixos-rebuild switch --impure'
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
                flake = "/etc/nixos/";
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
        };
    };

}
