{
  lib,
  buildNpmPackage,
  importNpmLock,
  nodejs,
  iproute2,
  iputils,
  dnsutils,
  mtr,
  traceroute,
  systemd,
  avahi,
  # The AdGuard Home web/API port the plugin talks to on localhost. Baked into
  # config.js at install time so the frontend knows where to reach it.
  adguardPort ? 3000,
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

  # This is a Cockpit static package, not an npm library — install the bundled
  # dist/ into the cockpit share tree instead of running `npm install` to $out.
  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/cockpit/router
    cp -r dist/* $out/share/cockpit/router/
    echo 'window.cockpitRouterConfig = { adguardPort: ${toString adguardPort} };' \
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
  ];

  meta = {
    description = "Cockpit plugin with router views (hosts, Suricata, AdGuard, diagnostics)";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
})
