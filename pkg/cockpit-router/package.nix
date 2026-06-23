{
  lib,
  buildNpmPackage,
  importNpmLock,
  nodejs,
  cockpit,
  iproute2,
  iputils,
  dnsutils,
  mtr,
  traceroute,
  systemd,
  avahi,
  nmap,
  wireguard-tools,
  # The AdGuard Home web/API port the plugin talks to on localhost. Baked into
  # config.js at install time so the frontend knows where to reach it.
  adguardPort ? 3000,
  # Baked into config.js so the frontend knows where the editable JSON config
  # lives, the host name, and the flake path for nixos-rebuild. Defaults match
  # the standard deployment layout.
  hostName ? "",
  flakePath ? "/etc/nixos",
  settingsFile ? "/etc/nixos/router-settings.json",
}:

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

  # Vendor Cockpit's own pkg/lib (matching the deployed cockpit version) so the
  # build resolves `cockpit-dark-theme`, `patternfly/patternfly-6-cockpit.scss`
  # and `page.scss` from it — this is what gives the plugin Cockpit's native
  # theming (light/dark, spacing, fonts) instead of stock PatternFly.
  postPatch = ''
    mkdir -p pkg
    cp -r ${cockpit.src}/pkg/lib pkg/lib
    chmod -R u+w pkg
  '';

  # This is a Cockpit static package, not an npm library — install the bundled
  # dist/ into the cockpit share tree instead of running `npm install` to $out.
  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/cockpit/router
    cp -r dist/* $out/share/cockpit/router/
    echo 'window.cockpitRouterConfig = { adguardPort: ${toString adguardPort}, macPrefixesPath: "${nmap}/share/nmap/nmap-mac-prefixes", hostName: "${hostName}", flakePath: "${flakePath}", settingsFile: "${settingsFile}" };' \
      > $out/share/cockpit/router/config.js
    runHook postInstall
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
    description = "Cockpit plugin with router views (hosts, Suricata, AdGuard, diagnostics)";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
})
