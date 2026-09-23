# Build-sandbox check of router-ddns against the fake Cloudflare API — no VM.
#
# The first real deployment failed on names that already existed as CNAMEs:
# DNS allows nothing beside a CNAME, so Cloudflare refused every A/AAAA record
# router-ddns tried to create. A configured name belongs to the router, so the
# CNAME is replaced; and since that CNAME may have been doing real work (an apex
# pointing at a website), it is remembered and put back once the name is
# dropped from the configuration. Pinned here, through the packaged CLI:
#
#   • an apex CNAME (proxied, with a TXT record beside it) and a subdomain CNAME
#     are replaced by A records; the TXT record is untouched;
#   • a second run with nothing changed writes nothing;
#   • dropping a name deletes its A record and restores its CNAME exactly —
#     target, proxying and comment — while the other name stays taken over.
#
# The sandbox has no WAN, so the IPv4 address comes from the fake's trace
# endpoint (the path a router behind another NAT takes), and IPv6 is off.
{
  pkgs,
  routerDnsTools,
}:
let
  inherit (pkgs) lib;

  seed = pkgs.writeText "cloudflare-seed.json" (
    builtins.toJSON [
      {
        type = "CNAME";
        name = "example.com";
        content = "site.example.net";
        ttl = 1;
        proxied = true;
        comment = "website";
      }
      {
        type = "TXT";
        name = "example.com";
        content = "v=spf1 -all";
        ttl = 1;
        proxied = false;
      }
      {
        type = "CNAME";
        name = "nas.example.com";
        content = "old-ddns.example.net";
        ttl = 300;
        proxied = false;
      }
    ]
  );

  configFor =
    names:
    pkgs.writeText "router-ddns.json" (
      builtins.toJSON {
        ddns = {
          stateDir = "state";
          records = map (name: {
            inherit name;
            v4 = true;
            v6 = null;
          }) names;
          ipv4 = true;
          ipv6 = false;
          ttl = 1;
          proxied = false;
          wanInterface = "wan0";
          routerV6Fallback = "br-lan";
          apiTokenFile = null;
        };
      }
    );
  both = configFor [
    "example.com"
    "nas.example.com"
  ];
  nasOnly = configFor [ "nas.example.com" ];
  none = configFor [ ];
in
pkgs.runCommand "router-ddns-cloudflare"
  {
    nativeBuildInputs = [
      pkgs.python3
      pkgs.iproute2
      pkgs.curl
      pkgs.jq
      routerDnsTools
    ];
  }
  ''
    export FAKE_CF_BIND=127.0.0.1 FAKE_CF_PORT=8053 FAKE_CF_SEED=${seed}
    python3 ${./fake-cloudflare.py} &
    trap 'kill $!' EXIT
    api=http://127.0.0.1:8053
    curl -s --retry-connrefused --retry 50 --retry-delay 0 --retry-max-time 30 $api/__state >/dev/null

    export ROUTER_DDNS_API_BASE=$api/client/v4 ROUTER_DDNS_TRACE_URL=$api/cdn-cgi/trace
    mkdir creds && echo test-token > creds/cf-api-token
    export CREDENTIALS_DIRECTORY=$PWD/creds

    fail() { echo "FAIL $*" >&2; exit 1; }
    live() { curl -sf $api/__state | jq -c '.result'; }
    records() { live | jq -c '[.records[] | {type, name, content}] | sort_by(.name, .type)'; }
    writes() { live | jq '.writes'; }
    want() { [ "$(records)" = "$1" ] || fail "$2: records are $(records), want $1"; }

    # 1 — both names start as CNAMEs; both are taken over.
    router-ddns --config ${both} || fail "the run over two CNAME-held names failed"
    want '[{"type":"A","name":"example.com","content":"203.0.113.1"},{"type":"TXT","name":"example.com","content":"v=spf1 -all"},{"type":"A","name":"nas.example.com","content":"203.0.113.1"}]' \
      "after taking both names over"
    jq -e '.replaced["example.com"] == [{"type":"CNAME","name":"example.com","content":"site.example.net","ttl":1,"proxied":true,"comment":"website"}]' state/state.json >/dev/null \
      || fail "the apex CNAME was not remembered faithfully: $(jq -c .replaced state/state.json)"
    jq -e '[.records[] | select(.name == "example.com" and .type == "A") | .detail] == ["replaced CNAME → site.example.net (restored if the name is dropped)"]' state/status.json >/dev/null \
      || fail "the status file does not say what was replaced: $(jq -c .records state/status.json)"

    # 2 — nothing changed: nothing written.
    before=$(writes)
    router-ddns --config ${both} || fail "the no-change run failed"
    [ "$(writes)" = "$before" ] || fail "a run with nothing changed wrote $(( $(writes) - before )) time(s)"

    # 3 — the apex is dropped: its A record goes, its CNAME comes back as it was.
    router-ddns --config ${nasOnly} || fail "the run dropping example.com failed"
    want '[{"type":"CNAME","name":"example.com","content":"site.example.net"},{"type":"TXT","name":"example.com","content":"v=spf1 -all"},{"type":"A","name":"nas.example.com","content":"203.0.113.1"}]' \
      "after dropping example.com"
    live | jq -e '[.records[] | select(.name == "example.com" and .type == "CNAME")] | .[0] | .proxied == true and .comment == "website"' >/dev/null \
      || fail "the restored CNAME lost its proxying or comment: $(records)"
    jq -e '.replaced | has("example.com") | not' state/state.json >/dev/null \
      || fail "a restored CNAME is still remembered as replaced"

    # 4 — the last name is dropped: back to where it started.
    router-ddns --config ${none} || fail "the run dropping every name failed"
    want '[{"type":"CNAME","name":"example.com","content":"site.example.net"},{"type":"TXT","name":"example.com","content":"v=spf1 -all"},{"type":"CNAME","name":"nas.example.com","content":"old-ddns.example.net"}]' \
      "after dropping every name"

    touch $out
  ''
