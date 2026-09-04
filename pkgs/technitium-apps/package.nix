# ── Technitium DNS Apps ─────────────────────────────────────────────────────────
# Compiles the DNS apps this router uses — Advanced Blocking, Log Exporter,
# Block Page, and this repo's own Router Live DNS — from the Technitium DnsServer
# source (`technitium-dns` flake input) instead of downloading the pre-built app
# zips. Router Live DNS is NOT part of upstream Technitium: its source lives in
# ./RouterLiveDnsApp and is copied into the build tree below.
#
# Built exactly like nixpkgs' technitium-dns-server: buildDotnetModule with the
# ASP.NET Core 10 runtime (Block Page uses it) and the TechnitiumLibrary DLLs
# staged from `technitium-dns-server-library` (the same package the server uses).
#
# Output layout matches what the DNS server expects under <state>/apps/: one
# folder per app, named as Technitium names it (folder name == app name), each
# containing the app dll + deps.json + any NuGet dependencies + dnsApp.config
# and assets. DnsServerCore.ApplicationCommon and TechnitiumLibrary are marked
# Private=false in the csproj, so publish omits them (the server provides them).
{
  lib,
  buildDotnetModule,
  dotnetCorePackages,
  technitium-dns-server-library,
  technitiumSrc,
}:
buildDotnetModule (finalAttrs: {
  pname = "technitium-dns-apps";
  # Tracks the SERVER these apps are ABI-matched to, rather than repeating the
  # `technitium-dns` input's tag here — a hand-written copy silently went stale
  # when the server moved 15.2.0 → 15.4.0. `nix run .#update-deps` is what
  # enforces that the input's ref equals this version; given that, the two are
  # the same number and this one cannot drift.
  inherit (technitium-dns-server-library) version;

  src = technitiumSrc;

  dotnet-sdk = dotnetCorePackages.sdk_10_0;
  dotnet-runtime = dotnetCorePackages.aspnetcore_10_0;

  nugetDeps = ./nuget-deps.json;

  projectFile = [
    "Apps/AdvancedBlockingApp/AdvancedBlockingApp.csproj"
    "Apps/LogExporterApp/LogExporterApp.csproj"
    "Apps/BlockPageApp/BlockPageApp.csproj"
    "Apps/RouterLiveDnsApp/RouterLiveDnsApp.csproj"
  ];

  # Router Live DNS isn't part of the upstream checkout — its source (this
  # repo's ./RouterLiveDnsApp) has to land in the build tree BEFORE
  # dotnetConfigureHook's `dotnet restore` runs (configurePhase), since
  # restore needs the .csproj listed in `projectFile` to already exist —
  # postPatch (end of patchPhase) is the latest hook that still runs early
  # enough.
  postPatch = ''
    mkdir -p Apps/RouterLiveDnsApp
    cp -r ${./RouterLiveDnsApp}/* Apps/RouterLiveDnsApp/
  '';

  # The apps reference pre-built TechnitiumLibrary DLLs via a HintPath to a
  # sibling ../../../TechnitiumLibrary/bin — stage them there (as the server
  # does). This is only needed at compile time, so preBuild (unlike the
  # postPatch source copy above) is late enough.
  preBuild = ''
    mkdir -p ../TechnitiumLibrary/bin
    cp -r ${technitium-dns-server-library}/lib/${technitium-dns-server-library.pname}/* ../TechnitiumLibrary/bin/
  '';

  # Publish each app into its own store folder named as Technitium expects.
  # Packages are already restored (buildDotnetModule's configure step), so
  # publish with --no-restore.
  installPhase = ''
    runHook preInstall

    publishApp() {
      local proj="$1" name="$2"
      dotnet publish "$proj" \
        --configuration Release --no-restore --no-self-contained \
        -p:UseAppHost=false \
        --output "$out/$name"
    }

    publishApp "Apps/AdvancedBlockingApp/AdvancedBlockingApp.csproj" "Advanced Blocking"
    publishApp "Apps/LogExporterApp/LogExporterApp.csproj" "Log Exporter"
    publishApp "Apps/BlockPageApp/BlockPageApp.csproj" "Block Page"
    publishApp "Apps/RouterLiveDnsApp/RouterLiveDnsApp.csproj" "Router Live DNS"

    runHook postInstall
  '';

  meta = {
    description = "Technitium DNS Apps (Advanced Blocking, Log Exporter, Block Page, Router Live DNS) built from source";
    homepage = "https://github.com/TechnitiumSoftware/DnsServer";
    license = lib.licenses.gpl3Only;
    platforms = lib.platforms.linux;
  };
})
