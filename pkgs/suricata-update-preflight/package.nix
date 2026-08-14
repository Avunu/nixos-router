# ── suricata-update source-index preflight ────────────────────────────────────
# suricata-update resolves every rule source through a cached copy of the
# upstream source index, and it loads that cache before doing anything —
# `enable-source`, `update-sources` and `update` alike. So an unparseable index
# wedges the unit permanently rather than for one run: even `update-sources`,
# whose entire job is to replace the file, dies parsing the old one first, and
# no other code path ever rewrites it. Nothing short of deleting the file by
# hand brings rule updates back.
#
# The realistic way to get one is a crash or power cut mid-write. The file's
# size is committed to the filesystem journal while its data is still in page
# cache, so the survivor is a correctly-sized, entirely NUL-filled index — an
# unclean reboot during the daily update timer produces exactly that.
#
# This preflight parses the cache and deletes it when it does not load as a
# source index, so the next run re-fetches a good copy and the unit self-heals.
# The index path is an argument rather than baked in, so the check in
# tests/suricata-update-preflight.nix can exercise it against scratch files.
{
  writeShellApplication,
  python3,
}:
let
  python = python3.withPackages (ps: [ ps.pyyaml ]);
in
writeShellApplication {
  name = "suricata-update-preflight";
  text = ''
    index="''${1:?usage: suricata-update-preflight <path-to-index.yaml>}"

    # Nothing cached yet is the healthy first-run state, not a fault.
    [ -e "$index" ] || exit 0

    # Parsing is not enough on its own: an empty file is valid YAML that loads
    # as None, and truncation can leave a fragment that parses but carries no
    # sources. Require the shape suricata-update actually needs.
    if ${python.interpreter} -c '
    import sys, yaml
    try:
        doc = yaml.safe_load(open(sys.argv[1]))
    except Exception:
        sys.exit(1)
    sys.exit(0 if isinstance(doc, dict) and "sources" in doc else 1)
    ' "$index" 2>/dev/null; then
      exit 0
    fi

    echo "suricata-update-preflight: $index is not a usable source index;" \
         "removing it so the next update re-fetches it" >&2
    rm -f "$index"
  '';
}
