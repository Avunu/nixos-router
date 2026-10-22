{
  lib,
  buildNpmPackage,
  importNpmLock,
  nodejs,
}:

# The nixos-router Block Page browser extension (Chrome/Edge/Brave + Firefox).
#
# Not part of any router's system — it runs in the browsers on the LAN. It is
# built here so CI gates it and so the store packages come out of a pinned
# build: build.js writes deterministic zips, so a given source always yields
# byte-identical chrome.zip / firefox.zip.
#
#   $out/chrome.zip   $out/chrome/    upload to the Chrome Web Store / load unpacked
#   $out/firefox.zip  $out/firefox/   upload to addons.mozilla.org / about:debugging
buildNpmPackage {
  pname = "router-browser-extension";
  # One source of truth: package.json's version is also the manifest's.
  inherit (lib.importJSON ./package.json) version;

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

  # As for cockpit-router: npmConfigHook exports the node-gyp `npm_config_nodedir`,
  # which npm 11 warns is unknown; nothing here is native, so quiet npm's own logs.
  npm_config_loglevel = "error";

  # The packages, not an npm library — no `npm install` into $out.
  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp dist/chrome.zip dist/firefox.zip $out/
    cp -r dist/chrome dist/firefox $out/
    runHook postInstall
  '';

  meta = {
    description = "Browser extension that shows a nixos-router's block page instead of a certificate error";
    homepage = "https://avunu.github.io/nixos-router/docs/access-policies/browser-extension/";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
