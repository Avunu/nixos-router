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
# of a remote client that opened Cockpit by that address.
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
      # An IPv6 tunnel address, which an origin must bracket.
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
      name = "cockpit-brackets-ipv6-tunnel-address";
      ok = lib.elem "https://[fd00:100::1]:${port}" origins;
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
in
pkgs.runCommand "router-wireguard-eval" { } (
  if failures == [ ] then
    "touch $out"
  else
    ''
      echo "WireGuard generation regressed:" >&2
      ${lib.concatMapStringsSep "\n" (f: ''
        echo "  FAIL ${f.name}" >&2
        echo ${lib.escapeShellArg "       ${f.detail}"} >&2
      '') failures}
      exit 1
    ''
)
