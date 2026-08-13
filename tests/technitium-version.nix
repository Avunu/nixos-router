# Eval-only regression check — the DNS apps must match the DNS server.
#
# pkgs/technitium-apps compiles Advanced Blocking, Log Exporter and Block Page
# from the `technitium-dns` source input, but they are loaded by the
# technitium-dns-server binary that comes from nixpkgs. Those are two
# independently-moving pins, and the apps link against DnsServerCore — so when
# they drift, the failure is a runtime type/method mismatch inside the DNS
# server rather than anything a build catches.
#
# This is exactly what dependency automation breaks: the input is pinned to a
# TAG, which never moves, while nixpkgs advances freely. A bot bumping nixpkgs
# therefore silently desyncs the pair. `nix run .#update-deps` printed a warning
# about this, but a warning in an interactive helper cannot gate a pull request.
{
  pkgs,
  technitiumSrc,
}:
let
  inherit (pkgs) lib;

  # The server the router actually runs.
  serverVersion = pkgs.technitium-dns-server.version;

  # The tag the apps are compiled from. Not exposed as an input attribute —
  # a `flake = false` input surfaces outPath/rev/narHash but not the ref — so
  # it is read from the lock, which is where the tag is recorded.
  lock = builtins.fromJSON (builtins.readFile ../flake.lock);
  appsRef = lock.nodes."technitium-dns".original.ref or null;

  # What that tag actually contains. Checking the source's own declared version
  # as well as the tag STRING catches a ref that does not hold what it claims —
  # a typo, or an upstream retag — which a pure string comparison would pass.
  csproj = builtins.readFile "${technitiumSrc}/DnsServerCore/DnsServerCore.csproj";
  versionLine = lib.findFirst (l: lib.hasInfix "<Version>" l) null (lib.splitString "\n" csproj);
  srcMatch =
    if versionLine == null then null else builtins.match ".*<Version>([0-9.]+)</Version>.*" versionLine;
  srcVersion = if srcMatch == null then null else builtins.head srcMatch;

  # DnsServerCore.csproj declares major.minor ("15.4") where nixpkgs carries a
  # patch component ("15.4.0"). Compare at major.minor, which is also the right
  # granularity for the ABI: a patch release does not move the app interface.
  majorMinor = v: lib.concatStringsSep "." (lib.take 2 (lib.splitString "." v));

  checks = [
    {
      name = "apps-tag-matches-server-version";
      ok = appsRef == "v${serverVersion}";
      detail = "technitium-dns input ref is ${toString appsRef}, but nixpkgs ships technitium-dns-server ${serverVersion} (want ref v${serverVersion})";
    }
    {
      name = "pinned-source-declares-that-version";
      ok = srcVersion != null && majorMinor srcVersion == majorMinor serverVersion;
      detail = "DnsServerCore.csproj declares ${toString srcVersion}, server is ${serverVersion} — the tag does not contain the version it names";
    }
  ];

  failures = lib.filter (c: !c.ok) checks;
in
pkgs.runCommand "router-technitium-version" { } (
  if failures == [ ] then
    "touch $out"
  else
    ''
      echo "Technitium apps and server have drifted apart:" >&2
      ${lib.concatMapStringsSep "\n" (f: ''
        echo "  FAIL ${f.name}" >&2
        echo "       ${f.detail}" >&2
      '') failures}
      echo >&2
      echo "  The apps are compiled from the technitium-dns input and loaded by" >&2
      echo "  nixpkgs' technitium-dns-server; a mismatch fails at runtime inside" >&2
      echo "  the DNS server, not at build time. Bump the input ref in flake.nix" >&2
      echo "  to match, then run 'nix run .#update-deps' to refresh nuget-deps." >&2
      exit 1
    ''
)
