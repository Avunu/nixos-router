# Unit check — the suricata-update source-index preflight.
#
# Guards the self-heal path for a wedged suricata-update (see the package's own
# comment for how the unit gets wedged). Both directions matter: keeping a
# corrupt index leaves rule updates failing forever, while deleting a healthy
# one would re-download the index on every single run.
{ pkgs }:
pkgs.runCommand "suricata-update-preflight-check" { } ''
  preflight=${pkgs.suricata-update-preflight}/bin/suricata-update-preflight
  cd "$(mktemp -d)"

  fail() { echo "FAIL: $*" >&2; exit 1; }

  # The real thing, trimmed to the two keys the preflight looks for.
  cat > good.yaml <<'EOF'
  # This is a version 1 formatted index.
  version: 1

  sources:
    et/open:
      summary: Emerging Threats Open Ruleset
      url: https://rules.emergingthreats.net/open/suricata-%(__version__)s/emerging.rules.tar.gz
  EOF

  # What an unclean reboot mid-write actually leaves behind: right size, all NULs.
  head -c 16228 /dev/zero > nul.yaml
  : > empty.yaml
  # Parses cleanly as YAML, but carries no sources — a truncated write that
  # happened to land on a document boundary.
  printf 'version: 1\n' > headless.yaml
  printf 'sources: [oh no\n' > malformed.yaml

  echo "== a healthy index is left alone =="
  $preflight good.yaml || fail "preflight errored on a good index"
  test -e good.yaml || fail "preflight deleted a good index"
  grep -q "et/open" good.yaml || fail "preflight altered a good index"

  echo "== a NUL-filled index is removed =="
  $preflight nul.yaml || fail "preflight errored on a NUL-filled index"
  test ! -e nul.yaml || fail "preflight kept a NUL-filled index"

  echo "== an empty index is removed =="
  $preflight empty.yaml || fail "preflight errored on an empty index"
  test ! -e empty.yaml || fail "preflight kept an empty index (loads as None)"

  echo "== an index with no sources key is removed =="
  $preflight headless.yaml || fail "preflight errored on a sourceless index"
  test ! -e headless.yaml || fail "preflight kept an index with no sources"

  echo "== a syntactically broken index is removed =="
  $preflight malformed.yaml || fail "preflight errored on malformed YAML"
  test ! -e malformed.yaml || fail "preflight kept malformed YAML"

  echo "== a missing index is not an error (healthy first run) =="
  $preflight absent.yaml || fail "preflight errored when the index does not exist"

  echo "== the index path is required =="
  if $preflight 2>/dev/null; then fail "preflight accepted a missing argument"; fi

  touch $out
''
