# Eval-only regression check — the settings loader (lib/settings.nix).
#
# Every router reads router-settings.json through nixos-router.lib, so this is
# the path by which a JSON file written for an older module keeps rebuilding
# after an upgrade. It has failed once already: a port forward still naming a
# raw `destination` stopped 948-router's upgrade on an unknown option. Pinned:
#
#   • each migration upgrades the old shape, leaves current JSON untouched and
#     is idempotent;
#   • a migration that cannot resolve an entry stops evaluation (an upgrade
#     that stops leaves the running system alone) instead of guessing;
#   • a router evaluating an old-shape file builds, and forwards as before;
#   • a router installed before the loader, which applies its JSON directly,
#     still evaluates the retired DNS listen port every install was seeded
#     with, which stays ignored and warns unless it is 53;
#   • the activation step really rewrites the file on disk — run here against
#     a copy — keeps a backup and the file's mode, and never touches a file
#     edited since the evaluation;
#   • the module plus the settings file alone — what an installer-image
#     router's /etc/nixos flake imports — keeps Cockpit, and keeps the
#     settings file root-only.
{
  pkgs,
  routerModule,
  settingsLib,
  baseSettings,
}:
let
  inherit (pkgs) lib;
  inherit (settingsLib) migrateSettings settingsModule;

  nas = {
    mac = "aa:bb:cc:dd:ee:01";
    name = "nas";
    staticIp = "10.48.4.2";
  };

  # A forward exactly as the previous Cockpit wrote it.
  legacyForward = {
    name = "Synology DSM";
    protocol = "tcp";
    destination = "10.48.4.2";
    ports = [
      5080
      5443
    ];
    source = "203.0.113.0/24";
  };
  upgradedForward = {
    name = "Synology DSM";
    protocol = "tcp";
    host = "nas";
    family = "ipv4";
    ports = [
      5080
      5443
    ];
    sources = [ "203.0.113.0/24" ];
  };

  # The retired DNS listen port, as the old DNS form saved it.
  legacyDns = lib.recursiveUpdate baseSettings.dns { technitium.listenPort = 53; };

  legacy = baseSettings // {
    hosts = [ nas ];
    portForwards = [ legacyForward ];
    dns = legacyDns;
  };
  migrated = migrateSettings legacy;

  unresolvable = migrateSettings {
    hosts = [ ];
    portForwards = [ (legacyForward // { destination = "10.48.4.77"; }) ];
  };

  # A router with the test machine's stand-ins, plus `modules`.
  evalRouter =
    modules:
    (import "${pkgs.path}/nixos/lib/eval-config.nix" {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        routerModule
        (
          { lib, ... }:
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
        )
      ]
      ++ modules;
    }).config;
  failedAssertionsOf = s: map (a: a.message) (lib.filter (a: !a.assertion) s.assertions);

  # The router, built from an old-shape file through the loader. The settings
  # path is relative so the activation snippet can be run in the build dir.
  legacyFile = builtins.toFile "router-settings.json" (builtins.toJSON legacy);
  sys = evalRouter [
    (settingsModule legacyFile)
    { router.cockpit.settingsFile = "router-settings.json"; }
  ];
  # The same router with the settings file where a real one keeps it.
  sysInstalled = evalRouter [ (settingsModule legacyFile) ];

  failedAssertions = failedAssertionsOf sys;

  # A router installed before the loader: its flake applies the JSON straight
  # to the module (`{ router = lib.mkDefault settings; }`), so no migration
  # runs, and every seeded file carries the retired DNS listen port.
  preLoader =
    port:
    evalRouter [
      (
        { lib, ... }:
        {
          router = lib.mkDefault (lib.recursiveUpdate baseSettings { dns.technitium.listenPort = port; });
        }
      )
    ];
  preLoaderSeeded = preLoader 53;
  preLoaderMoved = preLoader 5353;
  listenPortWarnings = s: lib.filter (lib.hasInfix "router.dns.technitium.listenPort") s.warnings;
  # What router-technitium-reconcile sets Technitium's listeners to.
  endpointsOf =
    s:
    (builtins.fromJSON (builtins.unsafeDiscardStringContext s.router._dnsToolsConfig.text))
    .settings.dnsServerLocalEndPoints;

  # A plain-string activation entry stays a string; a { text; } one does not.
  activationEntry = sys.system.activationScripts.routerSettingsMigrate or null;
  activation =
    if builtins.isString activationEntry then activationEntry else activationEntry.text or null;
  expectedFile = pkgs.writeText "expected.json" (builtins.toJSON migrated);

  checks = [
    {
      name = "legacy-forward-upgraded";
      ok = migrated.portForwards == [ upgradedForward ];
      detail = "got ${builtins.toJSON migrated.portForwards}";
    }
    {
      name = "migrations-idempotent";
      ok = migrateSettings migrated == migrated;
      detail = "a second pass changed the already-migrated settings";
    }
    {
      name = "current-settings-untouched";
      ok = migrateSettings baseSettings == baseSettings;
      detail = "the sample settings, already current, were changed";
    }
    {
      name = "source-only-entry-keeps-host";
      ok =
        (migrateSettings {
          portForwards = [
            {
              host = "nas";
              ports = [ 22 ];
              source = "198.51.100.0/24";
            }
          ];
        }).portForwards == [
          {
            host = "nas";
            ports = [ 22 ];
            sources = [ "198.51.100.0/24" ];
          }
        ];
      detail = "a forward carrying only the old `source` was not upgraded in place";
    }
    {
      name = "dns-listen-port-dropped";
      ok = migrated.dns == baseSettings.dns;
      detail = "got dns = ${builtins.toJSON migrated.dns}";
    }
    {
      # Only the retired key goes, whatever its value; the rest of the
      # section, and a second pass, are left alone.
      name = "dns-listen-port-only-key-removed";
      ok =
        let
          once = migrateSettings {
            dns.technitium = {
              enable = true;
              listenPort = 5353;
            };
          };
        in
        once == { dns.technitium.enable = true; } && migrateSettings once == once;
      detail = "dropping dns.technitium.listenPort changed other keys or was not idempotent";
    }
    {
      name = "dns-absent-stays-absent";
      ok =
        migrateSettings { hostName = "router"; } == {
          hostName = "router";
        }
        && migrateSettings { dns.technitium.enable = false; } == { dns.technitium.enable = false; };
      detail = "settings without dns.technitium.listenPort were changed";
    }
    {
      name = "unresolvable-forward-stops-evaluation";
      ok = !(builtins.tryEval (builtins.deepSeq unresolvable unresolvable)).success;
      detail = "a forward to an address no host reserves evaluated anyway";
    }
    {
      name = "legacy-file-evaluates";
      ok = failedAssertions == [ ];
      detail = "assertions failed: ${lib.concatStringsSep " | " failedAssertions}";
    }
    {
      name = "legacy-file-still-forwards";
      ok = lib.hasInfix ''tcp dport { 5080, 5443 } dnat ip to 10.48.4.2 comment "Synology DSM"'' sys.networking.nftables.ruleset;
      detail = "the upgraded forward does not DNAT to the reserved address";
    }
    {
      # Evaluating is the check: without the shim the seeded key is an
      # unknown option, and this aborts with Nix's own error naming it.
      name = "pre-loader-listen-port-evaluates";
      ok = failedAssertionsOf preLoaderSeeded == [ ];
      detail = "assertions failed: ${lib.concatStringsSep " | " (failedAssertionsOf preLoaderSeeded)}";
    }
    {
      # Every pre-loader router carries 53, so it must not warn.
      name = "pre-loader-listen-port-53-quiet";
      ok = listenPortWarnings preLoaderSeeded == [ ];
      detail = "warned: ${lib.concatStrings (listenPortWarnings preLoaderSeeded)}";
    }
    {
      name = "pre-loader-listen-port-other-warns";
      ok = lib.any (lib.hasInfix "listenPort = 5353 is ignored") (listenPortWarnings preLoaderMoved);
      detail = "no warning that listenPort = 5353 is ignored; warnings: ${lib.concatStrings preLoaderMoved.warnings}";
    }
    {
      name = "pre-loader-listen-port-inert";
      ok = endpointsOf preLoaderMoved == "0.0.0.0:53,[::]:53";
      detail = "listenPort = 5353 moved Technitium to ${endpointsOf preLoaderMoved}";
    }
    {
      name = "installed-router-keeps-cockpit";
      ok = sys.services.cockpit.enable;
      detail = "Cockpit is off in a router built from the module and its settings file alone";
    }
    {
      name = "settings-file-kept-root-only";
      ok = lib.elem "z /etc/nixos/router-settings.json 0600 root root -" sysInstalled.systemd.tmpfiles.rules;
      detail = "no tmpfiles rule resets the settings file to 0600";
    }
    {
      name = "relative-settings-path-no-tmpfiles";
      ok = !lib.any (lib.hasInfix "router-settings.json") sys.systemd.tmpfiles.rules;
      detail = "a tmpfiles rule names the relative settings path";
    }
    {
      name = "activation-rewrites-file";
      ok = activation != null;
      detail = "no routerSettingsMigrate activation step although a migration changed the settings";
    }
  ];

  failures = lib.filter (c: !c.ok) checks;
in
pkgs.runCommand "router-settings-loader" { nativeBuildInputs = [ pkgs.jq ]; } (
  if failures != [ ] then
    ''
      echo "Settings loader regressed:" >&2
      ${lib.concatMapStringsSep "\n" (f: ''
        echo "  FAIL ${f.name}" >&2
        echo ${lib.escapeShellArg "       ${f.detail}"} >&2
      '') failures}
      exit 1
    ''
  else
    ''
      activate() { bash -euo pipefail -c ${lib.escapeShellArg activation}; }
      same() { [ "$(jq -S . "$1")" = "$(jq -S . "$2")" ]; }

      # The file as evaluated: rewritten to the upgraded settings.
      install -m 0640 ${legacyFile} router-settings.json
      activate
      same router-settings.json ${expectedFile} \
        || { echo "FAIL the file was not rewritten to the upgraded settings" >&2; exit 1; }
      cmp -s router-settings.json.pre-migration ${legacyFile} \
        || { echo "FAIL no faithful router-settings.json.pre-migration backup" >&2; exit 1; }
      [ "$(stat -c %a router-settings.json)" = 640 ] \
        || { echo "FAIL the rewrite changed the file's mode" >&2; exit 1; }

      # Booting again (activation reruns) must leave the upgraded file alone.
      cp router-settings.json upgraded.json
      activate
      cmp -s router-settings.json upgraded.json \
        || { echo "FAIL a second activation rewrote the file again" >&2; exit 1; }

      # A file edited after the build is never overwritten.
      install -m 0640 ${legacyFile} router-settings.json
      echo ' ' >> router-settings.json
      cp router-settings.json edited.json
      activate
      cmp -s router-settings.json edited.json \
        || { echo "FAIL a file edited since the evaluation was overwritten" >&2; exit 1; }

      touch $out
    ''
)
