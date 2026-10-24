# ── Technitium DNS Server ───────────────────────────────────────────────────────
# The router's DNS server, compiled from the `technitium-dns` flake input
# instead of taken from nixpkgs, so the router is no longer tied to the release
# nixpkgs carries. The library it links is the sibling `technitium-library` input
# (../technitium-library); the apps it loads are built from this same tree
# (../technitium-apps), so server, library and apps are one release by
# construction — checks.technitium-version guards the one pairing a flake
# cannot enforce, the two input refs.
#
# Differences from nixpkgs' package, all deliberate:
#   • build-options.nix — ReadyToRun, diagnostics feature switches.
#   • No web console. The router never opens it: reconcile, policy push, logd
#     and Cockpit all speak the HTTP API, which is separate from the static
#     files. `www/` holds the console and `dohwww/` the DNS-over-HTTPS landing
#     page; both are emptied below.
#   • Only the daemon is installed, not the helper scripts and unit files the
#     publish step copies beside it.
{
  lib,
  buildDotnetModule,
  dotnetCorePackages,
  libmsquic,
  technitium-dns-server-library,
  technitiumSrc,
  technitiumVersion,
}:
let
  buildOptions = import ./build-options.nix;
in
buildDotnetModule (finalAttrs: {
  pname = "technitium-dns-server";
  version = technitiumVersion;

  src = technitiumSrc;

  dotnet-sdk = dotnetCorePackages.sdk_10_0;
  dotnet-runtime = dotnetCorePackages.aspnetcore_10_0;

  nugetDeps = ./nuget-deps.json;

  projectFile = [ "DnsServerApp/DnsServerApp.csproj" ];

  inherit (buildOptions) dotnetFlags;

  # The project references the library's DLLs by a HintPath to a sibling
  # ../../TechnitiumLibrary/bin; stage them there. Compile-time only.
  preBuild = ''
    mkdir -p ../TechnitiumLibrary/bin
    cp -r ${technitium-dns-server-library}/lib/${technitium-dns-server-library.pname}/* ../TechnitiumLibrary/bin/
  '';

  # Wrap the daemon only; the publish folder also carries start.sh / start.bat
  # and the systemd and openrc units, none of which belong in a Nix closure.
  executables = [ "DnsServerApp" ];

  # The web service builds a PhysicalFileProvider over <app>/www on start, which
  # throws if the directory is missing — so the console's files go, but empty
  # directories stay (and dohwww/ likewise, for the day DNS-over-HTTPS is
  # switched on; the /dns-query endpoint itself is code, not a file).
  # named.root and root-anchors.xml are the DNS data the server ships, and stay.
  postInstall = ''
    appDir="$out/lib/${finalAttrs.pname}"
    rm -rf "$appDir/www" "$appDir/dohwww"
    mkdir "$appDir/www" "$appDir/dohwww"
    rm -f "$appDir"/{start.sh,start.bat,systemd.service,openrc.service}
  '';

  postFixup = ''
    mv $out/bin/DnsServerApp $out/bin/technitium-dns-server
  '';

  # DNS-over-QUIC (a forwarder protocol the router exposes) loads libmsquic
  # lazily; nothing else needs it.
  runtimeDeps = [ libmsquic ];

  meta = {
    changelog = "https://github.com/TechnitiumSoftware/DnsServer/blob/master/CHANGELOG.md";
    description = "Authoritative and recursive DNS server, built from source without its web console";
    homepage = "https://technitium.com/dns/";
    license = lib.licenses.gpl3Only;
    mainProgram = "technitium-dns-server";
    platforms = lib.platforms.linux;
  };
})
