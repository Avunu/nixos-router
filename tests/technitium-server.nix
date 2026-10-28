# Build-output check — what the compiled DNS server and apps actually contain.
#
# The package options in pkgs/technitium-dns-server/build-options.nix, and the
# removal of the web console, are properties of the OUTPUT that nothing else
# looks at, and each fails silently:
#
#   • ReadyToRun that quietly stopped applying (an SDK change, a dropped flag)
#     leaves a server that works and merely starts slower.
#   • A console file that survives the strip, or a renamed `www` folder the
#     strip no longer matches, leaves an HTTP surface nobody meant to ship.
#   • The strip removing too much — the web service builds its file provider
#     over <app>/www at start and fails if the folder is gone — is only found
#     by booting the server, which the VM test does, but late.
#
# Cheap to run: it reads the two packages, which the VM test builds anyway.
{
  pkgs,
  server,
  apps,
}:
pkgs.runCommand "router-technitium-server-check"
  {
    nativeBuildInputs = [
      pkgs.jq
      pkgs.python3
    ];
    probe = ./technitium-r2r-probe.py;
  }
  ''
    app=${server}/lib/technitium-dns-server
    fail() { echo "FAIL: $*" >&2; exit 1; }

    echo "== the daemon is installed and nothing else is wrapped =="
    test -x ${server}/bin/technitium-dns-server || fail "no bin/technitium-dns-server"
    test "$(ls ${server}/bin | wc -l)" = 1 || fail "bin/ holds more than the daemon: $(ls ${server}/bin)"

    echo "== no web console =="
    # Any page, script, stylesheet, font or image is console (or DoH landing
    # page). Judged by content, not by the two folder names the strip knows.
    stray=$(find "$app" -type f \( -name '*.html' -o -name '*.js' -o -name '*.css' \
      -o -name '*.map' -o -name '*.woff*' -o -name '*.ttf' -o -name '*.eot' \
      -o -name '*.svg' -o -name '*.png' -o -name '*.gif' -o -name '*.ico' \))
    test -z "$stray" || fail "web console files shipped: $stray"

    echo "== ...but the folders the web service opens at start still exist =="
    for d in www dohwww; do
      test -d "$app/$d" || fail "$d/ is gone; the web service fails to start without it"
      test -z "$(ls -A "$app/$d")" || fail "$d/ is not empty"
    done

    echo "== the DNS data the server ships is kept =="
    for f in named.root root-anchors.xml; do
      test -s "$app/$f" || fail "$f is missing"
    done

    echo "== no launcher scripts or service units beside the daemon =="
    for f in start.sh start.bat systemd.service openrc.service; do
      test ! -e "$app/$f" || fail "$f was left in the package"
    done

    echo "== runtime feature switches =="
    cfg="$app/DnsServerApp.runtimeconfig.json"
    for sw in System.Diagnostics.Tracing.EventSource.IsSupported System.Diagnostics.Metrics.Meter.IsSupported; do
      test "$(jq -r --arg k "$sw" '.runtimeOptions.configProperties[$k]' "$cfg")" = false \
        || fail "$sw is not false in runtimeconfig.json"
    done

    echo "== ReadyToRun =="
    r2r=$(python3 -I $probe \
      "$app"/DnsServerCore.dll "$app"/DnsServerApp.dll "$app"/TechnitiumLibrary.Net.dll \
      ${apps}/*/*App.dll)
    echo "$r2r"
    if echo "$r2r" | grep -q '^IL '; then fail "an assembly was not compiled ReadyToRun"; fi

    touch $out
  ''
