# ── TechnitiumLibrary ───────────────────────────────────────────────────────────
# The class libraries the DNS server and its apps compile against, built from
# the `technitium-library` flake input. Replaces nixpkgs'
# technitium-dns-server-library (same projects, same install layout) so the
# library is always the release the server source asks for, instead of whatever
# nixpkgs happens to carry.
#
# Deliberately a plain IL build: the DLLs are staged into the server's and the
# apps' build trees, and their own publish is where ReadyToRun compiles them
# (see ../technitium-dns-server/build-options.nix). Compiling here as well would
# hand crossgen2 an already-compiled input.
{
  buildDotnetModule,
  dotnetCorePackages,
  lib,
  technitiumLibrarySrc,
  technitiumVersion,
}:
buildDotnetModule {
  pname = "technitium-dns-server-library";
  version = technitiumVersion;

  src = technitiumLibrarySrc;

  dotnet-sdk = dotnetCorePackages.sdk_10_0;

  nugetDeps = ./nuget-deps.json;

  projectFile = [
    "TechnitiumLibrary.ByteTree/TechnitiumLibrary.ByteTree.csproj"
    "TechnitiumLibrary.Net/TechnitiumLibrary.Net.csproj"
    "TechnitiumLibrary.Security.OTP/TechnitiumLibrary.Security.OTP.csproj"
  ];

  meta = {
    description = "Class library of the Technitium DNS Server, built from source";
    homepage = "https://github.com/TechnitiumSoftware/TechnitiumLibrary";
    license = lib.licenses.gpl3Only;
    platforms = lib.platforms.linux;
  };
}
