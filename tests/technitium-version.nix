# Eval-only regression check — the two Technitium source inputs are one release.
#
# The router compiles the DNS server, its apps and their class library from two
# flake inputs: DnsServer, at the tag `vX.Y.Z`, and TechnitiumLibrary, at the
# tag `dns-server-vX.Y.Z` that upstream cuts for each server release. Nothing
# but this check ties the two refs together. A flake cannot derive one input's
# URL from another's, and Dependabot bumps each tag in a pull request of its
# own — so a bump of one that forgets the other is easy, and silent. A library
# from a different release than the server can still compile and then fail at
# runtime.
#
# (The server no longer has to match nixpkgs, which is the whole point of
# building it here; the apps and the server are built from one tree, so they
# cannot drift either. The pair of refs is the only coupling left.)
{
  pkgs,
  # What the `technitium-dns` input declares in its own project file, which is
  # where the router's packages take their version from.
  technitiumVersion,
}:
let
  inherit (pkgs) lib;

  # A `flake = false` input surfaces outPath/rev/narHash but not the ref it was
  # fetched at, so the ref is read from the lock, which records it.
  lock = builtins.fromJSON (builtins.readFile ../flake.lock);
  refOf = input: lock.nodes.${input}.original.ref or null;

  checks = [
    {
      # The source's own declared version, not just the tag STRING, is what
      # `technitiumVersion` holds — so this catches a ref that does not contain
      # what it claims (a typo, or an upstream retag), which comparing two
      # strings written by hand would pass.
      name = "server-tag-matches-source";
      ok = refOf "technitium-dns" == "v${technitiumVersion}";
      detail = "technitium-dns input ref is ${toString (refOf "technitium-dns")}, but that tree declares ${technitiumVersion} (want ref v${technitiumVersion})";
    }
    {
      name = "library-tag-matches-server";
      ok = refOf "technitium-library" == "dns-server-v${technitiumVersion}";
      detail = "technitium-library input ref is ${toString (refOf "technitium-library")}, but the server is ${technitiumVersion} (want ref dns-server-v${technitiumVersion})";
    }
  ];

  failures = lib.filter (c: !c.ok) checks;
in
pkgs.runCommand "router-technitium-version" { } (
  if failures == [ ] then
    "touch $out"
  else
    ''
      echo "The Technitium source inputs are not one release:" >&2
      ${lib.concatMapStringsSep "\n" (f: ''
        echo "  FAIL ${f.name}" >&2
        echo "       ${f.detail}" >&2
      '') failures}
      echo >&2
      echo "  Move both refs in flake.nix together — DnsServer at vX.Y.Z and" >&2
      echo "  TechnitiumLibrary at dns-server-vX.Y.Z — or run" >&2
      echo "  'nix develop -c update-deps --keep-technitium', which moves the library" >&2
      echo "  to the server's release and refreshes the NuGet locks." >&2
      exit 1
    ''
)
