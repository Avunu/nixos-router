# ── Technitium DNS Apps ─────────────────────────────────────────────────────────
# Compiles the three DNS apps this router uses — Advanced Blocking, Log Exporter,
# and Block Page — from the Technitium DnsServer source (`technitium-dns` flake
# input) instead of downloading the pre-built app zips.
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
  version = "15.2.0";

  src = technitiumSrc;

  dotnet-sdk = dotnetCorePackages.sdk_10_0;
  dotnet-runtime = dotnetCorePackages.aspnetcore_10_0;

  nugetDeps = ./nuget-deps.json;

  projectFile = [
    "Apps/AdvancedBlockingApp/AdvancedBlockingApp.csproj"
    "Apps/LogExporterApp/LogExporterApp.csproj"
    "Apps/BlockPageApp/BlockPageApp.csproj"
  ];

  # The apps reference pre-built TechnitiumLibrary DLLs via a HintPath to a
  # sibling ../../../TechnitiumLibrary/bin — stage them there (as the server does).
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

    runHook postInstall
  '';

  meta = {
    description = "Technitium DNS Apps (Advanced Blocking, Log Exporter, Block Page) built from source";
    homepage = "https://github.com/TechnitiumSoftware/DnsServer";
    license = lib.licenses.gpl3Only;
    platforms = lib.platforms.linux;
  };
})
