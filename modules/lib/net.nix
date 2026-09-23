# ── Network value validators ──────────────────────────────────────────────────
# Pure helpers shared by hosts.nix, firewall.nix and ddns.nix. A plain function
# file rather than a module: `router._internal` is topology.nix's read-only
# attrset, and nothing here depends on configuration — only on lib.
{ lib }:
with lib;
let
  # parseV6:
  #   lib.network.ipv6.fromString, or null when the string is not IPv6. The
  #   parser throws LAZILY — `tryEval (fromString "zz")` reports success and
  #   only blows up when a field is read — so the result is forced with
  #   deepSeq inside the tryEval. Returns { address; prefixLength; } with the
  #   address fully expanded, lower-case and without leading zeros
  #   ("0:0:0:0:a8bb:ccff:fedd:ee01").
  parseV6 =
    s:
    if !(isString s) || s == "" then
      null
    else
      let
        r = builtins.tryEval (
          let
            v = network.ipv6.fromString s;
          in
          deepSeq v v
        );
      in
      if r.success then r.value else null;

  # parseSuffix:
  #   An IPv6 interface identifier — the low 64 bits a host combines with
  #   whatever /64 the ISP currently delegates (e.g. "::42", or an EUI-64 like
  #   "::a8bb:ccff:fedd:ee01"). Returns the normalized "::…" form, or null
  #   when the value is not a bare address, sets any of the upper 64 bits, or
  #   is all zero. The normalized form drops the leading zero hextets of the
  #   low half; with the upper half all zero that always leaves at least five
  #   zero hextets for the `::` to stand in for, so it round-trips exactly.
  parseSuffix =
    s:
    let
      p = parseV6 s;
      hextets = if p == null then [ ] else splitString ":" p.address;
      upper = take 4 hextets;
      lower = drop 4 hextets;
      significant = dropWhile' (h: h == "0") lower;
    in
    if p == null || p.prefixLength != 128 || any (h: h != "0") upper || significant == [ ] then
      null
    else
      "::" + concatStringsSep ":" significant;

  # lib has no dropWhile.
  dropWhile' =
    pred: xs:
    if xs == [ ] then
      [ ]
    else if pred (head xs) then
      dropWhile' pred (tail xs)
    else
      xs;

  # isV4Prefix:
  #   An IPv4 address or CIDR prefix ("203.0.113.7", "203.0.113.0/24").
  #   lib.network has no IPv4 parser, so this is a regex plus range checks. The
  #   regex refuses leading zeros up front, because lib.toInt throws on them
  #   ("010") rather than returning a value the range check could reject.
  isV4Prefix =
    s:
    let
      octet = "(0|[1-9][0-9]{0,2})";
      m =
        if isString s then
          builtins.match "${octet}\\.${octet}\\.${octet}\\.${octet}(/(0|[1-9][0-9]?))?" s
        else
          null;
    in
    m != null && all (o: toInt o <= 255) (take 4 m) && (elemAt m 5 == null || toInt (elemAt m 5) <= 32);

  # isV6Prefix:
  #   An IPv6 address or CIDR prefix ("2001:db8::/32").
  isV6Prefix = s: parseV6 s != null;

  # isPrefix / familyOf:
  #   Source restrictions may mix families; `familyOf` routes each one to the
  #   ip / ip6 half of a rule. A colon can only appear in an IPv6 literal.
  isPrefix = s: isV4Prefix s || isV6Prefix s;
  familyOf = s: if hasInfix ":" s then "ipv6" else "ipv4";

  # isHostname:
  #   A public DNS name in strict LDH form: at least two labels, each 1-63
  #   characters of letters, digits and inner hyphens, 253 characters at most,
  #   no trailing dot. Stricter than dns-technitium.nix's isFqdn, which admits
  #   `_` for SRV-style names that have no business in an A/AAAA record.
  isHostname =
    s:
    let
      label = "[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?";
    in
    isString s && stringLength s <= 253 && builtins.match "${label}(\\.${label})+" s != null;
in
{
  inherit
    parseV6
    parseSuffix
    isV4Prefix
    isV6Prefix
    isPrefix
    familyOf
    isHostname
    ;
}
