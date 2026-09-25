# Eval-only regression check — host-based, dual-stack port forwards.
#
# Port forwards reference a router.hosts device and open its ports over IPv4
# (DNAT to the staticIp) and IPv6 (a pinhole to the device's own address,
# matched on its interface ID because the delegated prefix is dynamic). Almost
# everything that can go wrong here is config GENERATION and fails silently: a
# pinhole on the wrong bridge, a source prefix leaking into the other family's
# rule, a public host name LAN clients cannot reach for lack of NAT loopback.
# tests/port-forwards.nix proves the rules work on the wire; this
# pins what they say, that nftables accepts them (the ruleset script's own
# `nft --check` runs as a build dependency of this check), and that every
# misconfiguration fails with a message naming the forward.
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
                router.wan.vlan = null;
                router.lan.interfaces = [ "eth2" ];
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

  hosts = [
    {
      mac = "aa:bb:cc:dd:ee:01";
      name = "nas";
      staticIp = "10.48.4.2";
      # Deliberately un-normalized: the rules must carry "::42".
      ipv6Suffix = "::0042";
      publicHostname = "nas.example.com";
    }
    {
      mac = "aa:bb:cc:dd:ee:02";
      name = "cam";
      network = "guest";
      staticIp = "192.168.20.5";
      ipv6Suffix = "::A8BB:CCFF:FEDD:EE01";
    }
    {
      mac = "aa:bb:cc:dd:ee:03";
      name = "printer";
      staticIp = "10.48.4.3";
    }
    {
      mac = "aa:bb:cc:dd:ee:04";
      name = "laptop";
    }
  ];

  sys = evalWith {
    router.hosts = hosts;
    router.ddns = {
      enable = true;
      names = [ "home.example.com" ];
      cloudflare.apiTokenFile = "/etc/router/secrets/cloudflare-ddns.token";
    };
    router.portForwards = [
      {
        name = "DSM";
        host = "nas";
        ports = [
          5080
          5443
        ];
      }
      {
        name = "Cam RTSP";
        host = "cam";
        protocol = "udp";
        family = "ipv6";
        ports = [ 554 ];
      }
      {
        name = "SSH office";
        host = "nas";
        ports = [ 22 ];
        sources = [
          "203.0.113.0/24"
          "2001:db8:100::/48"
        ];
      }
      {
        name = "v4-only sources";
        host = "nas";
        ports = [ 2222 ];
        sources = [ "198.51.100.7" ];
      }
    ];
  };

  wan = sys.router._internal.wanIf;
  ruleset = sys.networking.nftables.ruleset;
  # The nftables unit's rules script: its checkPhase runs `nft --check` over
  # the whole generated ruleset, so interpolating it into the check below makes
  # a syntax error fail this build without a VM.
  rulesScript = lib.elemAt sys.systemd.services.nftables.serviceConfig.ExecStart 1;

  # Split-horizon record for a public host name (see dns-technitium.nix).
  publicRecord = lib.findFirst (r: r.name == "nas.example.com") null (
    lib.concatMap (z: z.records) sys.router._localDnsZones
  );

  failedAssertions = c: map (a: a.message) (lib.filter (a: !a.assertion) c.assertions);
  warns = s: lib.any (lib.hasInfix s) sys.warnings;
  has = s: lib.hasInfix s ruleset;

  pinhole = "ip6 daddr & ::ffff:ffff:ffff:ffff ==";

  # DDNS turned off: with the token still set, router-ddns stays installed to
  # delete the records; with no token there is nothing it could do. Only the
  # unit and timer names are forced, not a whole system.
  ddnsOff = evalWith {
    router.ddns.cloudflare.apiTokenFile = "/etc/router/secrets/cloudflare-ddns.token";
  };
  ddnsNone = evalWith { };
  hasDdnsUnit = c: c.systemd.services ? router-ddns && c.systemd.timers ? router-ddns;

  # Every misconfiguration at once, in ONE evaluation: each full NixOS eval
  # costs about a gigabyte, and none of these interfere with each other's
  # assertion. Each check below looks for the message naming its own culprit.
  bad = evalWith {
    router.ddns = {
      enable = true; # and no token file
      names = [
        "bad_name.example.com"
        "NAS.example.com" # nas's publicHostname, differently cased
      ];
      ttl = 30;
    };
    router.hosts = hosts ++ [
      {
        mac = "aa:bb:cc:dd:ee:05";
        name = "bad-suffix";
        ipv6Suffix = "2001:db8::1";
      }
      {
        mac = "aa:bb:cc:dd:ee:06";
        name = "dup-suffix-one";
        ipv6Suffix = "::7";
      }
      {
        mac = "aa:bb:cc:dd:ee:07";
        name = "dup-suffix-two";
        ipv6Suffix = "::0007";
      }
      {
        mac = "aa:bb:cc:dd:ee:08";
        name = "bad-public-name";
        publicHostname = "no_underscores.example.com";
      }
    ];
    router.wireguard.wg0 = {
      address = "10.100.0.1/24";
      privateKeyFile = "/etc/wireguard/wg0.key";
    };
    router.portForwards = [
      {
        name = "ghost";
        host = "ghost";
        ports = [ 80 ];
      }
      {
        name = "no-static";
        host = "laptop";
        family = "ipv4";
        ports = [ 81 ];
      }
      {
        name = "no-suffix";
        host = "printer";
        ports = [ 82 ];
      }
      {
        name = "dup-a";
        host = "nas";
        ports = [ 443 ];
      }
      {
        name = "dup-b";
        host = "printer";
        family = "ipv4";
        ports = [ 443 ];
      }
      {
        name = "wg";
        host = "printer";
        protocol = "udp";
        family = "ipv4";
        ports = [ 51820 ];
      }
      {
        name = "src";
        host = "nas";
        ports = [ 83 ];
        sources = [ "not-a-prefix" ];
      }
    ];
  };
  badMessages = failedAssertions bad;
  rejects = name: want: {
    inherit name;
    ok = lib.any (lib.hasInfix want) badMessages;
    detail = "want an assertion containing '${want}', got: ${lib.concatStringsSep " | " badMessages}";
  };

  checks = [
    {
      name = "evaluates";
      ok = failedAssertions sys == [ ];
      detail = "assertions failed: ${lib.concatStringsSep " | " (failedAssertions sys)}";
    }
    {
      name = "v4-dnat-to-host-static-ip";
      ok = has ''iifname "${wan}" tcp dport { 5080, 5443 } dnat ip to 10.48.4.2 comment "DSM"'';
      detail = "no DNAT of 5080/5443 to nas's staticIp";
    }
    {
      # `ct status dnat` keeps the accept from also admitting packets routed
      # straight at 10.48.4.2 from the WAN segment without being DNAT'd.
      name = "v4-accept-limited-to-dnat";
      ok = has ''iifname "${wan}" ip daddr 10.48.4.2 tcp dport { 5080, 5443 } ct status dnat accept comment "DSM"'';
      detail = "the forward-chain accept for DSM is missing or not limited to DNAT'd flows";
    }
    {
      name = "v6-pinhole-on-host-bridge-with-normalized-suffix";
      ok = has ''iifname "${wan}" oifname "br-lan" ${pinhole} ::42 tcp dport { 5080, 5443 } ct state new accept comment "DSM"'';
      detail = "no IPv6 pinhole to ::42 on br-lan for DSM";
    }
    {
      name = "guest-host-pinhole-on-guest-bridge";
      ok = has ''oifname "br-guest" ${pinhole} ::a8bb:ccff:fedd:ee01 udp dport 554 ct state new accept'';
      detail = "the guest host's pinhole is missing or not on br-guest";
    }
    {
      name = "ipv6-only-forward-has-no-dnat";
      ok = !(has "dnat ip to 192.168.20.5");
      detail = "family = ipv6 still produced an IPv4 DNAT";
    }
    {
      name = "sources-split-by-family";
      ok =
        has "ip saddr { 203.0.113.0/24 } tcp dport 22 dnat ip to 10.48.4.2"
        && has ''oifname "br-lan" ip6 saddr { 2001:db8:100::/48 } ${pinhole} ::42 tcp dport 22'';
      detail = "a mixed source list was not split into its ip / ip6 halves";
    }
    {
      name = "ipv4-only-sources-keep-ipv6-closed";
      ok = has "tcp dport 2222 dnat ip to 10.48.4.2" && !(has "::42 tcp dport 2222");
      detail = "restricting to IPv4 sources still opened an IPv6 pinhole (to any source)";
    }
    {
      name = "ipv4-only-sources-warned";
      ok = warns "forward 'v4-only sources' includes IPv6, but its sources are all IPv4";
      detail = "no warning that the IPv6 half of 'v4-only sources' stays closed";
    }
    {
      # No NAT loopback: LAN clients must get the host's LAN address for its
      # public name, or its own port forward is unreachable from inside.
      name = "public-hostname-split-horizon";
      ok = publicRecord != null && publicRecord.type == "A" && publicRecord.value == "10.48.4.2";
      detail = "want a local A record nas.example.com → 10.48.4.2, got ${builtins.toJSON publicRecord}";
    }
    {
      name = "ddns-unit-gets-token-by-credential";
      ok =
        sys.systemd.services.router-ddns.serviceConfig.LoadCredential or [ ] == [
          "cf-api-token:/etc/router/secrets/cloudflare-ddns.token"
        ];
      detail = "router-ddns does not receive the token file through LoadCredential";
    }
    {
      name = "ddns-disabled-with-token-keeps-unit-for-teardown";
      ok =
        hasDdnsUnit ddnsOff
        && !ddnsOff.router._ddnsConfig.ddns.enable
        && sys.router._ddnsConfig.ddns.enable
        &&
          ddnsOff.systemd.services.router-ddns.serviceConfig.LoadCredential == [
            "cf-api-token:/etc/router/secrets/cloudflare-ddns.token"
          ];
      detail = "with DDNS off but a token set, router-ddns (unit, timer, token, enable=false) is not there to delete the records";
    }
    {
      # Off, a token path whose file is missing (Set token… then Cancel)
      # must skip the unit, not fail credential setup and with it every
      # switch; on, a missing token must still fail.
      name = "ddns-disabled-skips-unit-without-token-file";
      ok =
        ddnsOff.systemd.services.router-ddns.unitConfig.ConditionPathExists or null
        == "/etc/router/secrets/cloudflare-ddns.token"
        && !(sys.systemd.services.router-ddns.unitConfig ? ConditionPathExists);
      detail = "router-ddns is not conditioned on its token file while DDNS is off, or is while it is on";
    }
    {
      name = "ddns-disabled-without-token-has-no-unit";
      ok = !(ddnsNone.systemd.services ? router-ddns) && !(ddnsNone.systemd.timers ? router-ddns);
      detail = "router-ddns is installed although DDNS is off and has no token";
    }
    {
      name = "system-toplevel-instantiates";
      ok = builtins.isString sys.system.build.toplevel.drvPath;
      detail = "the system closure does not instantiate";
    }

    (rejects "unknown-host" "forward 'ghost' references unknown host 'ghost'")
    (rejects "ipv4-needs-static-ip" "forwards IPv4 to host 'laptop', which has no staticIp")
    (rejects "ipv6-needs-suffix" "forwards IPv6 to host 'printer', which has no ipv6Suffix")
    (rejects "suffix-must-be-interface-id" "IPv6 suffix '2001:db8::1' is not an interface identifier")
    (rejects "suffix-unique-per-network" "duplicate IPv6 suffix(es) on one network: lan/::7")
    (rejects "public-hostname-valid" "public hostname 'no_underscores.example.com' is not a valid DNS name")
    (rejects "duplicate-unrestricted-v4-port" "more than one unrestricted IPv4 forward claims tcp/443")
    (rejects "wireguard-port-clash" "forward 'wg' forwards a WireGuard listen port")
    (rejects "invalid-source" "forward 'src' has an invalid source prefix")
    (rejects "ddns-needs-token" "router.ddns: enabled without router.ddns.cloudflare.apiTokenFile")
    (rejects "ddns-name-valid" "router.ddns.names: not a valid DNS name: bad_name.example.com")
    (rejects "ddns-name-not-a-host-name" "nas.example.com is also a host's publicHostname")
    (rejects "ddns-ttl-range" "router.ddns.ttl must be 1 (automatic) or between 60 and 86400")
  ];

  failures = lib.filter (c: !c.ok) checks;
in
pkgs.runCommand "router-port-forwards-eval" { } (
  if failures == [ ] then
    ''
      # Built for its checkPhase: `nft --check` over the generated ruleset.
      echo ${rulesScript} > /dev/null
      touch $out
    ''
  else
    ''
      echo "Port-forward generation regressed:" >&2
      ${lib.concatMapStringsSep "\n" (f: ''
        echo "  FAIL ${f.name}" >&2
        echo ${lib.escapeShellArg "       ${f.detail}"} >&2
      '') failures}
      exit 1
    ''
)
