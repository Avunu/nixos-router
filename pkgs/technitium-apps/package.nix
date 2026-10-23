# ── Technitium DNS Apps ─────────────────────────────────────────────────────────
# Compiles the DNS apps this router uses — Advanced Blocking, Log Exporter,
# Block Page, and this repo's own Router Live DNS — from the Technitium DnsServer
# source (`technitium-dns` flake input) instead of downloading the pre-built app
# zips. Router Live DNS is NOT part of upstream Technitium: its source lives in
# ./RouterLiveDnsApp and is copied into the build tree below.
#
# Built from the same tree, with the same options and against the same library
# as the server (../technitium-dns-server): buildDotnetModule with the ASP.NET
# Core 10 runtime (Block Page uses it) and the TechnitiumLibrary DLLs staged from
# `technitium-dns-server-library`. Being one release by construction is what
# lets the apps link DnsServerCore.ApplicationCommon without an ABI mismatch.
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
  technitiumVersion,
}:
let
  buildOptions = import ../technitium-dns-server/build-options.nix;
in
buildDotnetModule (finalAttrs: {
  pname = "technitium-dns-apps";
  # The release of the source tree these are compiled from — the same number
  # the server carries, since both read it from the one `technitium-dns` input.
  version = technitiumVersion;

  src = technitiumSrc;

  dotnet-sdk = dotnetCorePackages.sdk_10_0;
  dotnet-runtime = dotnetCorePackages.aspnetcore_10_0;

  nugetDeps = ./nuget-deps.json;

  inherit (buildOptions) dotnetFlags;

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
  # publish with --no-restore. This phase replaces the hook's, which would
  # publish every project into one folder, so the options and the runtime id
  # the hook would have supplied are passed here: ReadyToRun compiles only for
  # a known runtime, and publish must see the same properties restore did.
  installPhase = ''
    runHook preInstall

    publishApp() {
      local proj="$1" name="$2"
      dotnet publish "$proj" \
        --configuration Release --no-restore --no-self-contained \
        --runtime "$dotnetRuntimeIds" \
        -p:UseAppHost=false \
        ${lib.escapeShellArgs buildOptions.dotnetFlags} \
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
