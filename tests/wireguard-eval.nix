# Eval-only regression check — WireGuard tunnels.
#
# Two definitions describe each tunnel's systemd-networkd unit: nixpkgs'
# wireguard-networkd module writes "40-<name>.network" with the address, and
# modules/network.nix adds forwarding, the relaxed rp_filter and the extra
# routes. networkd applies only the FIRST .network file that matches an
# interface, so the two must land in one file. When the router's half lived
# in "50-<name>.network", nixpkgs' file shadowed it: the tunnel came up with
# its address, `net.ipv4.conf.wg0.forwarding` stayed 0, and nothing that
# arrived through the tunnel was forwarded — silently, with every unit loaded
# and no error anywhere. tests/guest-access.nix proves the merged unit takes
# effect on a booted router; this pins what the generated config says.
#
# It also pins Cockpit's origin list: setting WebService.Origins makes it the
# exclusive allow-list, so a tunnel address missing from it refuses the login
# of a remote client that opened Cockpit by that address. cockpit-ws matches
# each entry as an fnmatch() glob, so the rendered cockpit.conf is also run
# through libc's fnmatch against the Origin a browser sends: an IPv6 entry
# that merely reads right, "https://[fd00:100::1]:9090", is a character class
# that refuses that browser and accepts "https://f:9090".
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
                router.cockpit.enable = true;
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

  peer = {
    publicKey = "CsExnGzNn3h4vcqD/M8i0Kzj19AlEfpUW1vrQFq5DU4=";
    allowedIPs = [
      "10.100.0.2/32"
      "192.168.2.0/24"
    ];
  };

  sys = evalWith {
    router.wireguard = {
      wg0 = {
        address = "10.100.0.1/30";
        privateKeyFile = "/etc/wireguard/wg0.key";
        routes = [ "192.168.9.0/24" ];
        peers = [ peer ];
      };
      # An IPv6 tunnel address, which an origin must bracket, with the
      # brackets escaped for fnmatch.
      wg1 = {
        address = "fd00:100::1/64";
        listenPort = 51821;
        privateKeyFile = "/etc/wireguard/wg1.key";
      };
    };
  };

  # What the UI writes for a tunnel it has only just created. It fails the
  # build (nixpkgs asserts a prefix length), but the origin list is computed
  # regardless and must not gain a hostless "https://:9090".
  fresh = evalWith {
    router.wireguard.wg0 = {
      address = "";
      privateKeyFile = "/etc/wireguard/wg0.key";
    };
  };

  failedAssertions = c: map (a: a.message) (lib.filter (a: !a.assertion) c.assertions);

  # The unit networkd would actually apply to an interface: the lowest-sorting
  # .network file whose [Match] Name= is that interface.
  unitsFor =
    name:
    lib.sort lib.lessThan (
      lib.attrNames (
        lib.filterAttrs (_: n: (n.matchConfig.Name or null) == name) sys.systemd.network.networks
      )
    );
  wg0Units = unitsFor "wg0";
  wg0 = sys.systemd.network.networks.${lib.head wg0Units};
  wg0File = sys.systemd.network.units."${lib.head wg0Units}.network".text;
  fileLines = lib.splitString "\n" wg0File;

  port = toString sys.services.cockpit.port;
  originsOf = c: lib.splitString " " c.services.cockpit.settings.WebService.Origins;
  origins = originsOf sys;
  freshOrigins = originsOf fresh;

  checks = [
    {
      name = "evaluates";
      ok = failedAssertions sys == [ ];
      detail = "assertions failed: ${lib.concatStringsSep " | " (failedAssertions sys)}";
    }

    # ── networkd unit ──
    {
      # A second unit matching the tunnel is shadowed by, or shadows, the
      # first — which one depends only on how the names sort.
      name = "one-network-unit-per-tunnel";
      ok = lib.length wg0Units == 1 && lib.length (unitsFor "wg1") == 1;
      detail = "units matching wg0: ${builtins.toJSON wg0Units}, wg1: ${builtins.toJSON (unitsFor "wg1")}";
    }
    {
      name = "tunnel-forwards";
      ok = wg0.networkConfig.IPv4Forwarding or null == true;
      detail = "${lib.head wg0Units}: networkConfig = ${builtins.toJSON wg0.networkConfig}";
    }
    {
      # Replies to a remote site leave by the route its Allowed IPs installed,
      # not necessarily the interface they arrived on.
      name = "tunnel-rp-filter-relaxed";
      ok = wg0.networkConfig.IPv4ReversePathFilter or null == "no";
      detail = "${lib.head wg0Units}: networkConfig = ${builtins.toJSON wg0.networkConfig}";
    }
    {
      name = "tunnel-routes";
      ok = lib.elem "192.168.9.0/24" (map (r: r.Destination or null) wg0.routes);
      detail = "${lib.head wg0Units}: routes = ${builtins.toJSON wg0.routes}";
    }
    {
      name = "tunnel-address-once";
      ok = wg0.address == [ "10.100.0.1/30" ];
      detail = "${lib.head wg0Units}: address = ${builtins.toJSON wg0.address}";
    }
    {
      # The same four facts in the file networkd reads.
      name = "rendered-unit";
      ok =
        lib.count (l: l == "Address=10.100.0.1/30") fileLines == 1
        && lib.elem "IPv4Forwarding=true" fileLines
        && lib.elem "IPv4ReversePathFilter=no" fileLines
        && lib.elem "Destination=192.168.9.0/24" fileLines;
      detail = "${lib.head wg0Units}.network:\n${wg0File}";
    }

    # ── Cockpit ──
    {
      name = "cockpit-accepts-tunnel-address";
      ok = lib.all (o: lib.elem o origins) [
        "https://10.100.0.1:${port}"
        "https://10.100.0.1"
      ];
      detail = "Origins = ${lib.concatStringsSep " " origins}";
    }
    {
      name = "cockpit-escapes-ipv6-tunnel-address";
      ok = lib.elem "https://\\[fd00:100::1\\]:${port}" origins;
      detail = "Origins = ${lib.concatStringsSep " " origins}";
    }
    {
      name = "cockpit-skips-empty-tunnel-address";
      ok = !(lib.any (o: o == "https://" || lib.hasPrefix "https://:" o) freshOrigins);
      detail = "Origins = ${lib.concatStringsSep " " freshOrigins}";
    }
    {
      name = "system-toplevel-instantiates";
      ok = builtins.isString sys.system.build.toplevel.drvPath;
      detail = "the system closure does not instantiate";
    }
  ];

  failures = lib.filter (c: !c.ok) checks;

  # ── Cockpit's origin match, on the rendered file ──
  # The file nixpkgs writes to /etc/cockpit/cockpit.conf, and the match
  # cockpit-ws makes against the Origin header (src/ws/websocketserver.c).
  # Its config parser (src/common/cockpitconf.c) takes the value raw, so the
  # patterns here are byte for byte the ones cockpit-ws sees.
  cockpitConf = sys.environment.etc."cockpit/cockpit.conf".source;
  originMatch = pkgs.writeText "origin-match.c" ''
    /* origin-match CONF ORIGIN: exit 0 if Cockpit accepts ORIGIN. */
    #define _GNU_SOURCE
    #include <fnmatch.h>
    #include <stdio.h>
    #include <string.h>

    int main (int argc, char **argv)
    {
      static char line[65536];
      FILE *f = argc == 3 ? fopen (argv[1], "r") : NULL;
      if (!f)
        return 2;
      while (fgets (line, sizeof line, f))
        if (strncmp (line, "Origins=", 8) == 0)
          {
            line[strcspn (line, "\n")] = '\0';
            for (char *p = strtok (line + 8, " "); p; p = strtok (NULL, " "))
              if (fnmatch (p, argv[2], FNM_CASEFOLD) == 0)
                return 0;
          }
      return 1;
    }
  '';
  # What a browser sends as Origin after opening each tunnel address.
  acceptedOrigins = [
    "https://10.100.0.1:${port}"
    "https://10.100.0.1"
    "https://[fd00:100::1]:${port}"
    "https://[fd00:100::1]"
  ];
  # What an unescaped "[fd00:100::1]" accepts instead (any one of its
  # characters), and the tunnel's neighbour.
  refusedOrigins = [
    "https://f:${port}"
    "https://[fd00:100::2]:${port}"
  ];
in
pkgs.runCommandCC "router-wireguard-eval" { } ''
  failed=
  fail() {
    [ -n "$failed" ] || echo "WireGuard generation regressed:" >&2
    failed=1
    echo "  FAIL $1" >&2
    echo "       $2" >&2
  }
  ${lib.concatMapStringsSep "\n" (
    f: "fail ${lib.escapeShellArg f.name} ${lib.escapeShellArg f.detail}"
  ) failures}

  $CC -Wall -Werror -o origin-match ${originMatch}
  conf=${cockpitConf}
  for o in ${lib.escapeShellArgs acceptedOrigins}; do
    ./origin-match "$conf" "$o" \
      || fail cockpit-matches-tunnel-origin "refuses $o: $(grep '^Origins=' "$conf")"
  done
  for o in ${lib.escapeShellArgs refusedOrigins}; do
    rc=0
    ./origin-match "$conf" "$o" || rc=$?
    [ "$rc" = 1 ] \
      || fail cockpit-refuses-stray-origin "accepts $o (exit $rc): $(grep '^Origins=' "$conf")"
  done

  [ -z "$failed" ] || exit 1
  touch $out
''
