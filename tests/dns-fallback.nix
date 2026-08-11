# Eval-only regression check — something must always answer LAN :53.
#
# Two things point every LAN client at this router's gateway address, and
# NEITHER is gated on `dns.technitium.enable`:
#   • modules/network.nix advertises the gateway as the client's DNS server
#     (EmitDNS + DNS = [ lanGW ]);
#   • modules/firewall.nix DNATs all LAN :53 traffic to that address.
# So the option cannot mean "no DNS" — with nothing bound there, clients are
# told to use an address they are then forcibly redirected to, where nothing
# listens. That is not degraded filtering, it is a dead LAN.
#
# This pins both halves of the contract, including the one that would bite in
# the other direction: Technitium and resolved must never BOTH claim :53.
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

  # mkForce: the sample settings JSON sets dns.technitium.enable explicitly, so
  # a plain definition would collide with it — and, as the legacy-adguard check
  # learned the hard way, silently assert the sample file instead of the module.
  filtering = evalWith { router.dns.technitium.enable = lib.mkForce true; };
  fallback = evalWith { router.dns.technitium.enable = lib.mkForce false; };

  lanGW = filtering.router.lan.address;
  stubExtra = fallback.services.resolved.settings.Resolve.DNSStubListenerExtra or [ ];

  checks = [
    {
      name = "fallback-resolver-enabled";
      ok = fallback.services.resolved.enable;
      detail = "technitium is off and systemd-resolved is off — nothing answers LAN :53";
    }
    {
      # The default stub listener is 127.0.0.53 only, which no LAN client can
      # reach; without this the fallback exists but is unreachable.
      name = "fallback-listens-on-lan-gateway";
      ok = builtins.elem lanGW stubExtra;
      detail = "DNSStubListenerExtra = ${lib.concatStringsSep "," (map toString stubExtra)} (want ${lanGW})";
    }
    {
      # Both binding :53 would be a startup race, not a fallback.
      name = "no-double-bind-when-filtering";
      ok = !filtering.services.resolved.enable;
      detail = "resolved is enabled alongside Technitium — both would claim :53";
    }
    {
      name = "technitium-serves-when-enabled";
      ok = filtering.systemd.services ? technitium-dns-server;
      detail = "the technitium-dns-server unit is missing with enable = true";
    }
    {
      # Running unfiltered is a legitimate choice, but never a silent one.
      name = "unfiltered-mode-warns";
      ok = lib.any (w: lib.hasInfix "NO content filtering" w) fallback.warnings;
      detail = "disabling filtering emits no warning";
    }
    {
      name = "both-modes-instantiate";
      ok =
        builtins.isString filtering.system.build.toplevel.drvPath
        && builtins.isString fallback.system.build.toplevel.drvPath;
      detail = "one of the two system closures does not instantiate";
    }
  ];

  failures = lib.filter (c: !c.ok) checks;
in
pkgs.runCommand "router-dns-fallback" { } (
  if failures == [ ] then
    "touch $out"
  else
    ''
      echo "LAN :53 coverage regressed:" >&2
      ${lib.concatMapStringsSep "\n" (f: ''
        echo "  FAIL ${f.name}" >&2
        echo "       ${f.detail}" >&2
      '') failures}
      exit 1
    ''
)
