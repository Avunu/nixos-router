# Eval-only regression check — split-horizon DNS zone grouping and guardrails.
#
# Everything this feature does that can go silently wrong happens in Nix, before
# a single API call: which zone a record lands in, whether that zone forwards
# the rest of its domain onward or blackholes it, and whether a device name that
# is not a DNS label is dropped rather than published as garbage. The reconciler
# only executes the list it is handed, so this is the layer worth pinning.
#
# The one behaviour it CANNOT cover is what Technitium does with a Forwarder
# zone that also holds records — that is asserted live in tests/technitium.nix.
{
  pkgs,
  routerModule,
  baseSettings,
}:
let
  inherit (pkgs) lib;

  evalWith =
    extra:
    (import "${pkgs.path}/nixos/lib/eval-config.nix" {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        routerModule
        (
          { lib, ... }:
          {
            config = lib.mkMerge [
              { router = lib.mkDefault baseSettings; }
              {
                router.wan.interface = "eth1";
                router.lan.interfaces = [ "eth2" ];
                router.lan.domain = lib.mkForce "example.test";
                disko.enableConfig = lib.mkForce false;
                boot.loader.systemd-boot.enable = lib.mkForce false;
                boot.loader.grub.enable = lib.mkForce false;
                fileSystems."/" = {
                  device = "/dev/vda";
                  fsType = "ext4";
                };
              }
              extra
            ];
          }
        )
      ];
    }).config;

  base = evalWith {
    router.dns.technitium.enable = lib.mkForce true;
    router.dns.technitium.upstreamServers = lib.mkForce [ "https://dns.example.net/dns-query" ];
    router.dns.registerStaticHosts = true;
    router.dns.overrides = [
      # No declared root covers it: gets its own zone.
      {
        name = "nas.corp.example.com";
        value = "10.48.4.20";
      }
      # Apex of a registrable domain — the case the Forwarder-zone model exists
      # for, and the one that would blackhole a whole domain under a Primary.
      {
        name = "example.com";
        value = "10.48.4.21";
      }
      {
        name = "sip.example.com";
        type = "SRV";
        value = "10 5 5060 pbx.example.com";
      }
      # Sits under a DECLARED root (the LAN domain), so it joins that zone
      # instead of getting one of its own.
      {
        name = "vpn.example.test";
        type = "ANAME";
        value = "nas.example.test";
      }
    ];
    router.dns.forwardZones = [
      {
        zone = "ad.example.org";
        forwarders = [ "10.48.4.5" ];
      }
    ];
    router.hosts = lib.mkForce [
      {
        mac = "aa:bb:cc:dd:ee:01";
        name = "Lab Printer";
        staticIp = "10.48.4.50";
      }
      # Slugifies to the same label as the one above — neither may be published.
      {
        mac = "aa:bb:cc:dd:ee:02";
        name = "lab_printer";
        staticIp = "10.48.4.51";
      }
      {
        mac = "aa:bb:cc:dd:ee:03";
        name = "NAS";
        staticIp = "10.48.4.52";
      }
      # No reservation: nothing to publish.
      {
        mac = "aa:bb:cc:dd:ee:04";
        name = "roamer";
      }
    ];
  };

  off = evalWith {
    router.dns.technitium.enable = lib.mkForce false;
    router.dns.registerStaticHosts = false;
    router.dns.overrides = [
      {
        name = "nas.example.test";
        value = "10.48.4.20";
      }
    ];
  };

  zones = base.router._localDnsZones;
  zoneNames = map (z: z.zone) zones;
  zoneOf = name: lib.findFirst (z: z.zone == name) null zones;
  recordsOf = z: if z == null then [ ] else z.records;
  recordNames = z: lib.sort (a: b: a < b) (map (r: r.name) (recordsOf z));

  # An assertion/warning is only useful if it FIRES; evaluate a deliberately
  # broken config and look for the message rather than trusting the code path.
  messagesOf =
    extra:
    let
      c = evalWith extra;
    in
    map (a: a.message) (lib.filter (a: !a.assertion) c.assertions) ++ c.warnings;

  hasMsg = extra: needle: lib.any (m: lib.hasInfix needle m) (messagesOf extra);

  checks = [
    {
      name = "unmatched-override-gets-its-own-zone";
      ok = (zoneOf "nas.corp.example.com") != null;
      detail = "zones: ${lib.concatStringsSep ", " zoneNames}";
    }
    {
      # The whole point of the design: a zone this feature creates forwards
      # what it does not answer, so siblings keep resolving publicly.
      name = "override-zones-are-forwarders-with-upstream-fwd";
      ok =
        let
          z = zoneOf "example.com";
        in
        z != null
        && z.type == "Forwarder"
        && map (f: f.forwarder) z.forwarders == [ "https://dns.example.net/dns-query" ];
      detail = "an override zone is not a Forwarder mirroring dns.technitium.upstreamServers";
    }
    {
      # A DECLARED root (a forward zone, or the LAN domain when static hosts
      # are published) attracts every name beneath it.
      name = "records-join-the-declared-root-above-them";
      ok =
        recordNames (zoneOf "example.test") == [
          "nas.example.test"
          "vpn.example.test"
        ];
      detail = "example.test holds ${lib.concatStringsSep ", " (recordNames (zoneOf "example.test"))}";
    }
    {
      # An override with no declared root above it owns its own name and
      # nothing else — the narrowest zone that can answer it, so a neighbouring
      # name is never caught in the blast radius.
      name = "unrooted-override-zone-holds-only-its-own-name";
      ok =
        recordNames (zoneOf "example.com") == [ "example.com" ]
        && recordNames (zoneOf "sip.example.com") == [ "sip.example.com" ];
      detail = "an unrooted override pulled in a neighbouring name";
    }
    {
      name = "forward-zone-uses-its-own-forwarders";
      ok =
        let
          z = zoneOf "ad.example.org";
        in
        z != null && map (f: f.forwarder) z.forwarders == [ "10.48.4.5" ] && z.records == [ ];
      detail = "the conditional forward zone lost its forwarders";
    }
    {
      name = "static-hosts-publish-into-the-lan-domain-zone";
      ok = lib.elem "nas.example.test" (recordNames (zoneOf "example.test"));
      detail = "example.test holds ${lib.concatStringsSep ", " (recordNames (zoneOf "example.test"))}";
    }
    {
      # Publishing one of a colliding pair would hand an admin a name that
      # silently points at the wrong device.
      name = "colliding-host-slugs-are-skipped-with-a-warning";
      ok =
        lib.any (w: lib.hasInfix "slugify to the same" w) base.warnings
        && !(lib.elem "lab-printer.example.test" (recordNames (zoneOf "example.test")));
      detail = "'Lab Printer' and 'lab_printer' collide but one was published anyway";
    }
    {
      name = "static-host-records-carry-a-ptr";
      ok = lib.any (r: r.name == "nas.example.test" && r.ptr) (recordsOf (zoneOf "example.test"));
      detail = "reverse lookups for reservations were not requested";
    }
    {
      name = "apex-override-warns";
      ok = lib.any (w: lib.hasInfix "override a whole" w) base.warnings;
      detail = "overriding example.com itself passed without a word";
    }
    {
      # A forward zone hands the whole subtree away, so a local override under
      # it is dead configuration — better rejected than silently ignored.
      name = "override-shadowed-by-a-forward-zone-is-rejected";
      ok = hasMsg {
        router.dns.forwardZones = [
          {
            zone = "ad.example.org";
            forwarders = [ "10.48.4.5" ];
          }
        ];
        router.dns.overrides = [
          {
            name = "dc1.ad.example.org";
            value = "10.48.4.6";
          }
        ];
      } "forwards the entire subtree";
      detail = "an override inside a forward zone was accepted";
    }
    {
      name = "duplicate-override-is-rejected";
      ok = hasMsg {
        router.dns.overrides = [
          {
            name = "nas.example.test";
            value = "10.48.4.20";
          }
          {
            name = "NAS.example.test";
            value = "10.48.4.20";
          }
        ];
      } "duplicate record";
      detail = "the same record twice was accepted";
    }
    {
      name = "non-fqdn-override-is-rejected";
      ok = hasMsg {
        router.dns.overrides = [
          {
            name = "nas.example.test.";
            value = "10.48.4.20";
          }
        ];
      } "not a fully-qualified name";
      detail = "a trailing dot was accepted";
    }
    {
      name = "forward-zone-without-forwarders-is-rejected";
      ok = hasMsg {
        router.dns.forwardZones = [
          {
            zone = "ad.example.org";
            forwarders = [ ];
          }
        ];
      } "no forwarders given";
      detail = "a forward zone pointing nowhere was accepted";
    }
    {
      # The validation lives outside the mkIf so a settings file stays fixable
      # while the engine is off.
      name = "spec-still-evaluates-with-filtering-disabled";
      ok = map (z: z.zone) off.router._localDnsZones == [ "nas.example.test" ];
      detail = "the zone model is gated on dns.technitium.enable";
    }
    {
      # [DHCPServer] Domain=, singular, with EmitDomain= explicitly on (it
      # defaults to no). The plural EmitDomains=/Domains= pair is an
      # [IPv6SendRA] directive; nixpkgs rejects it in this section, which is
      # exactly the mistake this check exists to catch.
      name = "lan-clients-get-the-search-domain";
      ok =
        let
          dhcp = net: base.systemd.network.networks.${net}.dhcpServerConfig;
        in
        ((dhcp "40-br-lan").Domain or null) == "example.test"
        && ((dhcp "40-br-lan").EmitDomain or false)
        && ((dhcp "41-br-guest").Domain or null) == "example.test";
      detail = "DHCP does not advertise the LAN domain, so bare hostnames will not resolve";
    }
    {
      name = "config-instantiates";
      ok = builtins.isString base.system.build.toplevel.drvPath;
      detail = "the system closure does not instantiate with split-horizon DNS configured";
    }
  ];

  failures = lib.filter (c: !c.ok) checks;
in
pkgs.runCommand "router-dns-overrides" { } (
  if failures == [ ] then
    "touch $out"
  else
    ''
      echo "split-horizon DNS regressed:" >&2
      ${lib.concatMapStringsSep "\n" (f: ''
        echo "  FAIL ${f.name}" >&2
        echo "       ${f.detail}" >&2
      '') failures}
      exit 1
    ''
)
