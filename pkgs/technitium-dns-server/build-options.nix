# Build options for everything this flake compiles from the Technitium tree —
# the DNS server and the apps it loads (../technitium-apps). One place, so the
# two can never be built with different assumptions about the runtime they share.
#
# Chosen for what this is: a long-running resolver on a router, restarted on
# every upgrade, with the web console unused (everything is driven through the
# HTTP API), built once in CI and cached.
#
# Passed as `dotnetFlags`, i.e. to restore, build AND publish. They have to
# agree: restore resolves packs from these properties, and publish runs with
# --no-restore.
{
  dotnetFlags = [
    # ── Performance ──────────────────────────────────────────────────────────
    # ReadyToRun: ship precompiled native code next to the IL. The server is
    # restarted whenever its closure changes (every upgrade that moves the
    # package, apps or block page), and until it is back every LAN client has
    # no DNS; JIT-compiling the resolver's hot paths on the first queries after
    # a restart is the slow part of that window. Steady state is unchanged —
    # tiered compilation still re-JITs hot methods with profile data (PGO) — so
    # this trades build time, paid once in CI, for startup and first-query
    # latency. The crossgen2 and runtime packs come with nixpkgs' SDK
    # (dotnet-sdk.packages), so no extra NuGet downloads are locked for it.
    "-p:PublishReadyToRun=true"

    # ── Security / attack surface ────────────────────────────────────────────
    # No EventSource and no Meters: nothing here collects runtime telemetry
    # (EventPipe, dotnet-counters, OpenTelemetry), and the diagnostics IPC
    # socket is already disabled in the unit (DOTNET_EnableDiagnostics=0).
    # Turning the providers off also removes their startup and allocation
    # cost. Written to runtimeconfig.json as feature switches.
    "-p:EventSourceSupport=false"
    "-p:MetricsSupport=false"

    # No ICU. Globalization runs in invariant mode: ordinal, locale-independent
    # string handling, and libicu never loaded into a daemon that answers the
    # network. That removes a native dependency and the dependence of string
    # handling on the process locale (the server calls culture-sensitive
    # ToUpper() in its API and log code; the Turkish-i problem is the classic
    # way that goes wrong). Measured: ~10 MB less resident memory, no change in
    # speed.
    #
    # The cost is IDN normalisation: converting NON-ASCII names (e.g. an
    # upper-case "BÜCHER.de", or a decomposed ü) yields different punycode than
    # with ICU. That conversion happens only in the API handlers that take
    # admin-typed zone and record names, and the router only ever sends them
    # ASCII — modules/dns-technitium.nix rejects anything else (isFqdn), and
    # names on the wire are already punycode. Nothing in the server or the apps
    # constructs a specific culture, which invariant mode would reject.
    "-p:InvariantGlobalization=true"
  ];
}
