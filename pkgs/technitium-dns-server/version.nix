# The Technitium release the `technitium-dns` input holds, read from the
# source's own project file rather than written out a second time: a hand-kept
# copy would be one more number to go stale (the apps' version comment did,
# across 15.2.0 → 15.4.0).
#
# Upstream spells a `.0` release with two components (v15.6.0 declares `15.6`)
# and later ones with three (`15.6.1`), so the result is padded to the tag
# form, `MAJOR.MINOR.PATCH`.
{ lib, src }:
let
  csproj = builtins.readFile "${src}/DnsServerApp/DnsServerApp.csproj";
  line = lib.findFirst (l: lib.hasInfix "<Version>" l) null (lib.splitString "\n" csproj);
  m =
    if line == null then null else builtins.match ".*<Version>([0-9]+(\\.[0-9]+)*)</Version>.*" line;
  parts = lib.splitString "." (builtins.head m);
in
if m == null then
  throw "technitium-dns: no <Version> in DnsServerApp/DnsServerApp.csproj"
else
  lib.concatStringsSep "." (lib.take 3 (parts ++ lib.replicate (3 - lib.length parts) "0"))
