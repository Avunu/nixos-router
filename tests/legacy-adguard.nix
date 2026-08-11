# Eval-only regression check — the AdGuard Home → Technitium migration.
#
# This branch switches the DNS engine for EVERY user, not just those adopting a
# new feature, so the compatibility shim in modules/access-policies.nix is the
# single piece of code every existing deployment runs through. It had no test:
# a settings JSON still carrying `dns.adguard` had to keep evaluating, keep
# serving DNS, and keep filtering the same domains, and nothing checked any of
# that.
#
# Deliberately an eval, not a VM boot. What can actually regress here is config
# GENERATION — the shim silently dropping a list, a legacy key that no longer
# type-checks, or Technitium not being enabled so a rebuild leaves the router
# with no resolver at all. tests/technitium.nix already proves that a compiled
# policy filters correctly at runtime; this proves the legacy path produces one.
{
  pkgs,
  routerModule,
  baseSettings,
}:
let
  inherit (pkgs) lib;
  catalog = import ../modules/filter-catalog.nix;

  # An existing AdGuard user's settings JSON: none of the branch-era sections
  # exist yet, and dns.adguard still carries the whole filtering config.
  #
  # `dns.technitium` has to go too, and that is not cosmetic: the sample
  # local/router-settings.json sets `dns.technitium.enable = true`, so leaving
  # it in makes the "technitium-enabled-by-default" check assert the sample file
  # rather than the module default — it kept passing under a mutation that
  # flipped that default to false. A pre-migration JSON has no dns.technitium
  # block at all, which is the whole point of checking the default.
  legacyBase =
    builtins.removeAttrs baseSettings [
      "accessPolicies"
      "directory"
      "reporting"
      "hosts"
      "hostGroups"
    ]
    // {
      dns = builtins.removeAttrs (baseSettings.dns or { }) [ "technitium" ];
    };

  sys = import "${pkgs.path}/nixos/lib/eval-config.nix" {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      routerModule
      (
        { lib, ... }:
        {
          config = lib.mkMerge [
            { router = lib.mkDefault legacyBase; }
            {
              router.wan.interface = "eth1";
              router.lan.interfaces = [ "eth2" ];

              # Moved under dns.technitium on this branch. An existing JSON
              # still has it here, so mkRenamedOptionModule has to carry it.
              router.dns.upstreamServers = [ "https://legacy.example/dns-query" ];

              # The legacy block exactly as it sits in a pre-migration JSON.
              router.dns.adguard = {
                standardFilters = {
                  adguard_ads = true;
                  adguard_malware = true;
                  steven_black = true;
                  adaway = false; # must NOT be expanded
                };
                utCapitoleCategories = [
                  "adult"
                  "gambling"
                ];
                blockList = [ "bad.example.com" ];
                allowList = [ "good.example.com" ];
                extraUserRules = [
                  "||blocked.example^"
                  "@@||allowed.example^"
                  "||has/a/path^" # not exact-domain: must be dropped, not mangled
                ];
                extraFilters = [
                  {
                    name = "extra";
                    url = "https://example.invalid/list.txt";
                  }
                ];
              };

              # Hardware-only bits the eval does not need.
              disko.enableConfig = lib.mkForce false;
              boot.loader.systemd-boot.enable = lib.mkForce false;
              boot.loader.grub.enable = lib.mkForce false;
              fileSystems."/" = {
                device = "/dev/vda";
                fsType = "ext4";
              };
            }
          ];
        }
      )
    ];
  };

  cfg = sys.config;

  # unsafeDiscardStringContext: these files are Nix-generated store paths, and
  # values parsed out of them carry that path as string context. The failure
  # messages below interpolate those values into the check's own script, which
  # Nix refuses if they still reference a store path. Nothing here needs the
  # dependency — only the text.
  readJSON = path: builtins.fromJSON (builtins.unsafeDiscardStringContext (builtins.readFile path));

  static = readJSON cfg.router._policyStaticInputs;
  policy = builtins.head static.policies;
  dnsTools = readJSON cfg.router._dnsToolsConfig;

  failedAssertions = map (a: a.message) (lib.filter (a: !a.assertion) cfg.assertions);
  has = xs: x: builtins.elem x xs;

  checks = [
    {
      name = "evaluates";
      ok = failedAssertions == [ ];
      detail = "assertions failed: ${lib.concatStringsSep " | " failedAssertions}";
    }
    {
      # Without this the rebuild succeeds and the router silently has no resolver.
      name = "technitium-enabled-by-default";
      ok = cfg.router.dns.technitium.enable;
      detail = "dns.technitium.enable is false — a migrated router would serve no DNS";
    }
    {
      name = "adguard-unit-removed";
      ok = !(cfg.systemd.services ? adguardhome);
      detail = "the adguardhome service is still defined";
    }
    {
      name = "one-synthesized-base-policy";
      ok = builtins.length static.policies == 1 && policy.name == "Base";
      detail = "expected a single synthesized 'Base' policy, got ${toString (builtins.length static.policies)}";
    }
    {
      name = "blocklist-migrated";
      ok = has policy.blocked "bad.example.com" && has policy.blocked "blocked.example";
      detail = "blocked = ${lib.concatStringsSep "," policy.blocked}";
    }
    {
      name = "allowlist-migrated";
      ok = has policy.allowed "good.example.com" && has policy.allowed "allowed.example";
      detail = "allowed = ${lib.concatStringsSep "," policy.allowed}";
    }
    {
      # The rule parser is naive by design; it must drop what it cannot map
      # rather than emit a broken domain.
      name = "non-exact-rule-dropped";
      ok = !(lib.any (d: lib.hasInfix "/" d) policy.blocked);
      detail = "a non exact-domain rule leaked into blocked: ${lib.concatStringsSep "," policy.blocked}";
    }
    {
      name = "enabled-standard-filters-expanded";
      ok = lib.all (k: has policy.adblockListUrls catalog.standardFilters.${k}.url) [
        "adguard_ads"
        "adguard_malware"
        "steven_black"
      ];
      detail = "adblockListUrls = ${lib.concatStringsSep "," policy.adblockListUrls}";
    }
    {
      # `adaway = false` in the legacy attrset must not become a filter.
      name = "disabled-standard-filter-excluded";
      ok = !(has policy.blockListUrls catalog.standardFilters.adaway.url);
      detail = "a filter set to false was expanded anyway";
    }
    {
      name = "ut-capitole-categories-expanded";
      ok = lib.all (c: has policy.blockListUrls (catalog.utCapitole.urlFor c)) [
        "adult"
        "gambling"
      ];
      detail = "blockListUrls = ${lib.concatStringsSep "," policy.blockListUrls}";
    }
    {
      name = "extra-filter-url-preserved";
      ok = has policy.adblockListUrls "https://example.invalid/list.txt";
      detail = "extraFilters url was lost";
    }
    {
      # dns.upstreamServers moved under dns.technitium. The rename has to keep
      # feeding Technitium's forwarders, or an upgraded router quietly reverts
      # to the default resolvers instead of the ones the admin chose.
      name = "renamed-upstream-servers-still-applied";
      ok = lib.hasInfix "https://legacy.example/dns-query" dnsTools.settings.forwarders;
      detail = "forwarders = ${dnsTools.settings.forwarders}";
    }
    {
      # Silent migration is worse than none: the admin must be told to finish it.
      name = "migration-warning-emitted";
      ok = lib.any (w: lib.hasInfix "dns.adguard" w) cfg.warnings;
      detail = "no warning mentions dns.adguard";
    }
    {
      # The one that matters most: `nixos-rebuild switch` on a legacy config
      # must instantiate. Compared as a bool so the drvPath is forced without
      # becoming a build dependency of this check.
      name = "system-toplevel-instantiates";
      ok = builtins.isString cfg.system.build.toplevel.drvPath;
      detail = "the system closure does not instantiate from a legacy config";
    }
  ];

  failures = lib.filter (c: !c.ok) checks;
in
pkgs.runCommand "router-legacy-adguard" { } (
  if failures == [ ] then
    "touch $out"
  else
    ''
      echo "AdGuard Home → Technitium migration regressed:" >&2
      ${lib.concatMapStringsSep "\n" (f: ''
        echo "  FAIL ${f.name}" >&2
        echo "       ${f.detail}" >&2
      '') failures}
      exit 1
    ''
)
