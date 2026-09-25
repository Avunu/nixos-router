---
title: Settings migrations
description: How to change the shape of a router option safely, with a loader migration in lib/settings.nix and a test in tests/settings-loader.nix.
code:
  - lib/settings.nix
  - modules/system.nix
  - modules/dns-technitium.nix
  - pkgs/cockpit-router/src/settings-json.ts
  - tests/settings-loader.nix
  - flake.nix
---

# Settings migrations

Deployed routers keep their settings in `router-settings.json`, written in whatever format was current when they last saved it. When a change renames, removes or reshapes a `router.*` option that the file can hold, those routers must keep rebuilding. This page explains how: with a migration in the settings loader, `lib/settings.nix`.

## The rule

**A schema change needs a loader migration, never a compatibility shim in the modules.**

Change the option to its new shape only, and upgrade the old shape in the loader. Don't keep the retired option alive in a module, and don't make a module accept both shapes. That way:

- **The options describe only the current format,** and so does the Cockpit schema generated from them. The web UI validates the file against that schema, so it could not edit an old-shape file anyway.
- **Old files are rewritten once.** After the first rebuild, the file on disk is in the current format, and nothing else ever has to know about the old one.
- **Routers keep upgrading.** Routers rebuild from `main` every night, and their files may hold any older shape. A migration upgrades them in place; a missing one stops their upgrades with an unknown-option error.

**The one exception** is a key that new installs were seeded with. Routers installed before the loader apply their JSON to the module directly, so no migration reaches them, and removing the option would stop their upgrades. Keep that option declared as well: hidden with `visible = false`, so the schema leaves it out, its value ignored, and a warning when it holds anything but the seeded value. `dns.technitium.listenPort` is one. `dropDnsListenPort` removes it from files the loader reads, `modules/dns-technitium.nix` still declares it, and Cockpit drops it when it loads the settings (`dropRetiredKeys` in `settings-json.ts`), so its next save writes the current shape.

User-facing behavior, including what an admin sees, is described in [The settings file](/docs/start/settings-file/#automatic-migrations).

## How the loader works

Host flakes load the file with `nixos-router.lib.settingsModule ./router-settings.json`. The loader in `lib/settings.nix`:

1. reads and parses the JSON;
2. passes it through every function in `migrations`, oldest first (`migrateSettings`);
3. applies the result as `router = lib.mkDefault migrated`, so anything set in Nix still wins;
4. records `router._settingsFile`: a hash of the file it read, and the migrated settings if a migration changed anything.

When `_settingsFile.migrated` is set, `modules/system.nix` adds the `routerSettingsMigrate` activation script. At activation it rewrites the file with the migrated settings, pretty-printed, keeping its owner and mode and saving the old contents as `router-settings.json.pre-migration`. It does this only if the file still has the hash the build read, so an edit made after the build is never overwritten.

The loader also exports `readSettings`, for a flake that needs a value outside a module, and `settingsModules.router`, which is how the host flake that nixos-install-helper generates finds the loader.

## Write a migration

1. **Change the option** in its module to the new shape only.
2. **Append a migration** to `migrations` in `lib/settings.nix`, with a comment giving the date and the old and new shapes. A migration is a function from the raw settings attrset to the upgraded one, and it must:
   - **pass current JSON through unchanged,** because every migration runs on every evaluation;
   - **be idempotent,** so running it twice gives the same result as once;
   - **leave absent sections absent,** so a file that never mentioned the option doesn't grow a key;
   - **`throw` an actionable message rather than guess,** when an entry can't be upgraded unambiguously. The build then stops, the running system is untouched, and the admin is told what to fix.
3. **Regenerate the settings schema;** see [Development](/docs/develop/#the-settings-schema).
4. **Cover it in `tests/settings-loader.nix`,** then run the check:
   ```bash
   nix build .#checks.x86_64-linux.settings-loader
   ```
5. **Add a row** to the migrations table in `docs/start/settings-file.md`.

## An existing migration

`portForwardsToHosts` (2026-09) moved port forwards from an address to a registered host. An old forward:

```json
{ "name": "Synology DSM", "protocol": "tcp", "destination": "10.48.4.2", "ports": [5080, 5443], "source": "203.0.113.0/24" }
```

becomes:

```json
{ "name": "Synology DSM", "protocol": "tcp", "host": "nas", "family": "ipv4", "ports": [5080, 5443], "sources": ["203.0.113.0/24"] }
```

where `nas` is the host whose `staticIp` is `10.48.4.2`. Its structure, with the error message shortened:

```nix
portForwardsToHosts =
  settings:
  let
    hosts = settings.hosts or [ ];
    reserving = ip: lib.findFirst (h: (h.staticIp or null) == ip) null hosts;
    migrate =
      f:
      let
        destination = f.destination or null;
        source = f.source or null;
        host = reserving destination;
      in
      if !(f ? destination || f ? source) then
        f # already current: passed through untouched
      else
        removeAttrs f [ "destination" "source" ]
        // lib.optionalAttrs (destination != null) {
          host = if host != null then host.name else throw "…"; # names the forward and the address
          family = "ipv4";
        }
        // lib.optionalAttrs (source != null) { sources = (f.sources or [ ]) ++ [ source ]; };
  in
  if settings ? portForwards then
    settings // { portForwards = map migrate settings.portForwards; }
  else
    settings;

# Oldest first. Append new migrations at the end.
migrations = [
  portForwardsToHosts
  dropDnsListenPort
];
```

It shows each rule at work:

- a forward with neither old key is returned as it is, which makes the migration idempotent;
- a file without `portForwards` is returned unchanged;
- the forward stays IPv4-only, since that is all an address-based forward ever opened;
- a forward to an address no host reserves `throw`s, telling the admin to register the device, rather than guessing a host.

## A new migration, step by step

Suppose, hypothetically, that `upnp.extraConfig` were renamed `upnp.extraLines`. The migration:

```nix
# 2026-11 — upnp.extraConfig is renamed upnp.extraLines.
upnpExtraLines =
  settings:
  let
    upnp = settings.upnp or { };
  in
  if upnp ? extraConfig then
    settings
    // {
      upnp = removeAttrs upnp [ "extraConfig" ] // {
        extraLines = upnp.extraLines or upnp.extraConfig;
      };
    }
  else
    settings;

migrations = [
  portForwardsToHosts
  dropDnsListenPort
  upnpExtraLines
];
```

In `tests/settings-loader.nix`, each entry in `checks` has a `name`, a boolean `ok` and a `detail` printed on failure. Add checks that the old shape is upgraded, that current settings pass through, and that a second pass changes nothing:

```nix
{
  name = "upnp-extra-lines-renamed";
  ok = (migrateSettings { upnp.extraConfig = "secure_mode=yes"; }).upnp == { extraLines = "secure_mode=yes"; };
  detail = "upnp.extraConfig was not renamed to upnp.extraLines";
}
```

The test file already checks, for every migration together, that:

- `local/router-settings.json`, which is current, passes through unchanged (`current-settings-untouched`);
- migrating twice changes nothing (`migrations-idempotent`);
- a router built from an old-shape file evaluates without failed assertions, and its upgraded forward still DNATs to the reserved address;
- the activation script rewrites the file, keeps a faithful `.pre-migration` backup and the file's mode, does nothing on a second run, and leaves a file edited since the build alone.

Extend the `legacy` settings in the test with your old shape, so those checks cover it too. For a migration that can `throw`, add a check that evaluation fails, as `unresolvable-forward-stops-evaluation` does with `builtins.tryEval`.
