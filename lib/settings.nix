# ── Router settings loader & migrations ────────────────────────────────────────
# The one place the settings JSON (router-settings.json, the file Cockpit edits)
# enters Nix. Exposed as the flake's `lib`; a router's host flake loads its
# settings through it instead of `builtins.fromJSON`:
#
#   settings = nixos-router.lib.readSettings ./router-settings.json;
#   ...
#   modules = [
#     nixos-router.nixosModules.router
#     (nixos-router.lib.settingsModule ./router-settings.json)
#   ];
#
# When the router.* options change shape, the old shape is upgraded HERE, by a
# migration appended to `migrations` below — never by keeping retired options
# alive in the modules. So the options (and the Cockpit schema generated from
# them) only ever describe the current format, and a router whose JSON still
# holds an old shape keeps rebuilding. When a migration changed something,
# settingsModule also has the module rewrite the file on disk at activation
# (see `_settingsFile` in modules/system.nix), so Cockpit — which validates
# against the current schema — never sees the old shape either.
#
# The one exception is a retired key that was seeded into every new install's
# settings file: routers installed before this loader feed their JSON to the
# module directly, so no migration reaches them. Such an option stays declared
# as well, hidden (visible = false keeps it out of the schema) and ignored,
# next to its migration, and Cockpit drops the key when it reads the file
# (RETIRED_KEYS in pkgs/cockpit-router/src/settings-json.ts) — see
# dns.technitium.listenPort.
#
# Every migration takes and returns the raw settings attrset and must be
# idempotent: all of them run on every evaluation, including over JSON that is
# already current. A migration that cannot produce a valid current shape must
# `throw` a message saying what to fix — an upgrade that stops with clear
# instructions leaves the running system untouched, whereas guessing would
# silently change what the router does.
{ lib }:
let
  # 2026-09 — port forwards name a router.hosts device instead of an address.
  #   { destination = "10.48.4.2"; source = "203.0.113.0/24"; ... }
  #   → { host = "<device reserving 10.48.4.2>"; family = "ipv4";
  #       sources = [ "203.0.113.0/24" ]; ... }
  # IPv4-only, since that is all an address-based forward ever opened; setting
  # the host's ipv6Suffix and the family afterwards opens IPv6 too.
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
          label = if (f.name or "") != "" then f.name else toString destination;
          host = reserving destination;
        in
        if !(f ? destination || f ? source) then
          f
        else
          removeAttrs f [
            "destination"
            "source"
          ]
          // lib.optionalAttrs (destination != null) {
            host =
              if host != null then
                host.name
              else
                throw ''
                  router-settings.json: port forward '${label}' targets ${destination}, but no
                  host reserves that address, and forwards now point at a registered host.
                  Register the device with staticIp ${destination} (Cockpit → Hosts, or an entry
                  in "hosts" with its MAC address), then rebuild.
                '';
            family = "ipv4";
          }
          // lib.optionalAttrs (source != null) { sources = (f.sources or [ ]) ++ [ source ]; };
    in
    if settings ? portForwards then
      settings // { portForwards = map migrate settings.portForwards; }
    else
      settings;

  # 2026-09 — dns.technitium.listenPort is removed; Technitium always listens
  # on 53, the only port clients can be pointed at.
  #   { dns.technitium = { listenPort = 53; ... }; } → { dns.technitium = { ... }; }
  # Any other value broke DNS, since clients still query :53, so dropping the
  # key restores what they expect rather than guessing. New installs were
  # seeded with the key, so modules/dns-technitium.nix also keeps an ignored,
  # hidden listenPort option for routers that bypass this loader.
  dropDnsListenPort =
    settings:
    let
      dns = settings.dns or { };
      technitium = dns.technitium or { };
    in
    if technitium ? listenPort then
      settings
      // {
        dns = dns // {
          technitium = removeAttrs technitium [ "listenPort" ];
        };
      }
    else
      settings;

  # Oldest first. Append new migrations at the end.
  migrations = [
    portForwardsToHosts
    dropDnsListenPort
  ];

  migrateSettings = settings: lib.foldl' (s: m: m s) settings migrations;

  readSettings = path: migrateSettings (builtins.fromJSON (builtins.readFile path));

  settingsModule =
    path:
    let
      raw = builtins.fromJSON (builtins.readFile path);
      migrated = migrateSettings raw;
    in
    { lib, ... }:
    {
      router = lib.mkMerge [
        # Defaults, so anything set in Nix overrides the JSON — and shows as
        # locked in Cockpit.
        (lib.mkDefault migrated)
        {
          _settingsFile = {
            # What this evaluation read, so activation only rewrites a file
            # nobody has edited since.
            rawHash = builtins.hashFile "sha256" path;
            migrated = if migrated == raw then null else migrated;
          };
        }
      ];
    };
in
{
  inherit migrateSettings readSettings settingsModule;

  # The nixos-install-helper convention: the flake its ISO seeds into
  # /etc/nixos loads each option root's settings file through
  # `lib.settingsModules.<root>` when the project exports one.
  settingsModules.router = settingsModule;
}
