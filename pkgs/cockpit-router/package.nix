{
  lib,
  buildNpmPackage,
  importNpmLock,
  nodejs,
  cockpit,
  runCommand,
  iproute2,
  iputils,
  dnsutils,
  mtr,
  traceroute,
  systemd,
  avahi,
  nmap,
  wireguard-tools,
}:

# Two derivations, so that the expensive one is the same on every router.
#
#   • This one is the bundle: the npm build, host-independent, and therefore
#     one store path per nixpkgs rev that CI builds and pushes to the binary
#     cache (.github/workflows/checks.yml).
#   • `passthru.withConfig { … }` is the per-router part: the bundle symlinked
#     into place plus a generated config.js with that router's endpoints and
#     paths. A file write, not a build.
#
# Baking config.js into the bundle itself, as this package used to, made every
# router's hostName and ports an input of the npm build, so no two routers
# shared the output and none could ever substitute it.
buildNpmPackage (finalAttrs: {
  pname = "cockpit-router";
  version = "0.1.0";

  src = lib.cleanSourceWith {
    src = ./.;
    filter =
      path: _type:
      let
        base = baseNameOf path;
      in
      base != "node_modules" && base != "dist";
  };

  # Deps come straight from the committed package-lock.json (integrity hashes
  # already in the lockfile), so there is no fixed-output dep hash to maintain.
  npmDeps = importNpmLock { npmRoot = ./.; };
  npmConfigHook = importNpmLock.npmConfigHook;

  inherit nodejs;
  npmBuildScript = "build";

  # nixpkgs' npmConfigHook unconditionally exports the node-gyp `npm_config_nodedir`
  # env var, which npm 11 warns is an unknown config. This package builds with
  # esbuild and has no native modules, so node-gyp/nodedir is unused — quiet npm's
  # own warnings (esbuild's build output is on stdout and unaffected).
  npm_config_loglevel = "error";

  # Vendor Cockpit's own pkg/lib (matching the deployed cockpit version) so the
  # build resolves `cockpit-dark-theme`, `patternfly/patternfly-6-cockpit.scss`
  # and `page.scss` from it — this is what gives the plugin Cockpit's native
  # theming (light/dark, spacing, fonts) instead of stock PatternFly.
  #
  # NOTE the singular `pkg` on BOTH sides, and leave it alone: it is Cockpit's
  # own directory name upstream, not this repository's `pkgs/` tree. A global
  # pkg -> pkgs rename has already broken this once, rewriting the source path
  # to a directory that does not exist in cockpit and failing the build at
  # `cp: cannot stat .../pkgs/lib`.
  postPatch = ''
    mkdir -p pkg
    ln -s ${cockpit.src}/pkg/lib pkg/lib
  '';

  # This is a Cockpit static package, not an npm library — install the bundled
  # dist/ into the cockpit share tree instead of running `npm install` to $out.
  # No config.js here; see `withConfig` below.
  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/cockpit/router
    cp -r dist/* $out/share/cockpit/router/
    runHook postInstall
  '';

  # The exact source `npm run vendor:lib` must copy from, so a local build
  # vendors the same cockpit as this derivation. Deliberately NOT a separate
  # flake input: pkg/lib ships code that runs inside the page cockpit-ws serves
  # (cockpit-dark-theme, page.scss, journal.js), and taking it from
  # pkgs.cockpit.src keeps it in lockstep with services.cockpit.package by
  # construction. A tag-pinned input would drift the moment nixpkgs moved, the
  # way the technitium apps do — but there the input is unavoidable, since
  # nixpkgs ships only the DNS server binary and never the app sources.
  passthru.cockpitSrc = cockpit.src;

  # The plugin as a router installs it: the bundle above plus config.js, the
  # local service endpoints/paths the frontend reads at load time — Technitium
  # web API port + the read-only dashboard token, router-logd's port + query
  # token, the directory sync state files, the reports dir, the dynamic DNS
  # status file, and where the editable JSON config, the host name and the
  # flake for nixos-rebuild live. Defaults match the standard deployment
  # layout. Carries the bundle's passthru, so Cockpit's plugin buildEnv still
  # finds `cockpitPath` on it.
  passthru.withConfig =
    {
      technitiumPort ? 5380,
      technitiumTokenPath ? "/var/lib/cockpit-router/technitium-token",
      logdPort ? 8067,
      logdTokenPath ? "/var/lib/router-technitium/logd-query.token",
      directoryStatePath ? "/var/lib/router-directory/directory.json",
      directoryStatusPath ? "/var/lib/router-directory/status.json",
      reportsDir ? "/var/lib/router-reports",
      # router-ddns's last-run summary (a DynamicUser StateDirectory, so the
      # real directory is /var/lib/private/router-ddns; root reads it via the
      # symlink).
      ddnsStatusPath ? "/var/lib/router-ddns/status.json",
      hostName ? "",
      flakePath ? "/etc/nixos",
      settingsFile ? "/etc/nixos/router-settings.json",
    }:
    let
      config = builtins.toJSON {
        inherit
          technitiumPort
          technitiumTokenPath
          logdPort
          logdTokenPath
          directoryStatePath
          directoryStatusPath
          reportsDir
          ddnsStatusPath
          hostName
          flakePath
          settingsFile
          ;
        macPrefixesPath = "${nmap}/share/nmap/nmap-mac-prefixes";
      };
    in
    runCommand "cockpit-router-${finalAttrs.version}"
      {
        inherit (finalAttrs) meta;
        passthru = removeAttrs finalAttrs.passthru [ "withConfig" ] // {
          bundle = finalAttrs.finalPackage;
        };
      }
      ''
        mkdir -p $out
        # Real directories, symlinked files; the directories come over with
        # the store's read-only mode, and config.js has to go in one of them.
        cp -rs ${finalAttrs.finalPackage}/share $out/share
        find $out -type d -exec chmod u+w {} +
        echo ${lib.escapeShellArg "window.cockpitRouterConfig = ${config};"} \
          > $out/share/cockpit/router/config.js
      '';

  # CLI tools the plugin spawns via cockpit-bridge (made available on Cockpit's
  # PATH through the module's plugin buildEnv).
  passthru.cockpitPath = [
    iproute2
    iputils
    dnsutils
    mtr
    traceroute
    systemd
    avahi
    nmap
    wireguard-tools # `wg genkey`/`wg pubkey` for the Network → WireGuard keypair helper
  ];

  meta = {
    description = "Cockpit plugin with router views (hosts, policies, reports, Suricata, diagnostics)";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
})
