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
#   • a second run with nothing changed writes nothing, and neither does the
#     one verifying run that a pre-upgrade state file (whose fingerprint
#     lacks TTL and proxying) forces; that run stamps the state version;
#   • a TTL change alone, then a proxying change alone, reaches Cloudflare at
#     once instead of waiting for the 6-hourly check;
#   • dropping a name deletes its A record and restores its CNAME exactly —
#     target, proxying and comment — while the other name stays taken over;
#   • enable=false over state from before the upgrade (no version stamp:
#     dynamic DNS was turned off when that kept the records) writes nothing
#     and says how to clean up;
#   • after an enabled run has stamped the state, enable=false deletes the
#     remaining records and restores their CNAMEs without looking up an
#     address; a second disabled run does nothing;
#   • a replaced CNAME already put back by hand is left as it is, not
#     refused as a duplicate.
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
    {
      names,
      enable ? true,
      ttl ? 1,
      proxied ? false,
    }:
    pkgs.writeText "router-ddns.json" (
      builtins.toJSON {
        ddns = {
          inherit enable ttl proxied;
          stateDir = "state";
          records = map (name: {
            inherit name;
            v4 = true;
            v6 = null;
          }) names;
          ipv4 = true;
          ipv6 = false;
          wanInterface = "wan0";
          routerV6Fallback = "br-lan";
          apiTokenFile = null;
        };
      }
    );
  bothNames = [
    "example.com"
    "nas.example.com"
  ];
  both = configFor { names = bothNames; };
  ttl300 = configFor {
    names = bothNames;
    ttl = 300;
  };
  proxiedOn = configFor {
    names = bothNames;
    ttl = 300;
    proxied = true;
  };
  nasOnly = configFor {
    names = [ "nas.example.com" ];
    ttl = 300;
    proxied = true;
  };
  off = configFor {
    names = [ "nas.example.com" ];
    enable = false;
    ttl = 300;
    proxied = true;
  };
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

    # A state file from before TTL and proxying joined the fingerprint (bare
    # addresses) and before the state version: one run verifies every record,
    # writes nothing, and stores the new fingerprint and the version.
    jq '.lastPushed |= map_values(.[0]) | del(.version)' state/state.json > old-state.json && mv old-state.json state/state.json
    router-ddns --config ${both} || fail "the run after an upgrade failed"
    [ "$(writes)" = "$before" ] || fail "the verifying run after an upgrade wrote $(( $(writes) - before )) time(s)"
    jq -e '.lastPushed["example.com/A"] == ["203.0.113.1", 1, false]' state/state.json >/dev/null \
      || fail "the fingerprint was not rewritten: $(jq -c .lastPushed state/state.json)"
    jq -e '.version == 2' state/state.json >/dev/null \
      || fail "an enabled run did not stamp the state version: $(jq -c .version state/state.json)"

    # 3 — a TTL change alone, then a proxying change alone, is written at once:
    # one PATCH per record, not a wait for the 6-hourly check.
    before=$(writes)
    router-ddns --config ${ttl300} || fail "the TTL-change run failed"
    [ "$(writes)" = $(( before + 2 )) ] || fail "a TTL change made $(( $(writes) - before )) write(s), want 2"
    live | jq -e '[.records[] | select(.type == "A")] | length == 2 and all(.ttl == 300 and .proxied == false)' >/dev/null \
      || fail "the records do not carry the new TTL: $(live | jq -c .records)"
    before=$(writes)
    router-ddns --config ${proxiedOn} || fail "the proxying-change run failed"
    [ "$(writes)" = $(( before + 2 )) ] || fail "a proxying change made $(( $(writes) - before )) write(s), want 2"
    live | jq -e '[.records[] | select(.type == "A")] | length == 2 and all(.ttl == 300 and .proxied == true)' >/dev/null \
      || fail "the records are not proxied: $(live | jq -c .records)"
    before=$(writes)
    router-ddns --config ${proxiedOn} || fail "the no-change run after the option changes failed"
    [ "$(writes)" = "$before" ] || fail "a run after the option changes wrote $(( $(writes) - before )) time(s)"

    # 4 — the apex is dropped: its A record goes, its CNAME comes back as it was.
    router-ddns --config ${nasOnly} || fail "the run dropping example.com failed"
    want '[{"type":"CNAME","name":"example.com","content":"site.example.net"},{"type":"TXT","name":"example.com","content":"v=spf1 -all"},{"type":"A","name":"nas.example.com","content":"203.0.113.1"}]' \
      "after dropping example.com"
    live | jq -e '[.records[] | select(.name == "example.com" and .type == "CNAME")] | .[0] | .proxied == true and .comment == "website"' >/dev/null \
      || fail "the restored CNAME lost its proxying or comment: $(records)"
    jq -e '.replaced | has("example.com") | not' state/state.json >/dev/null \
      || fail "a restored CNAME is still remembered as replaced"

    # 5 — dynamic DNS was turned off before the upgrade, when that kept the
    # records (no version stamp): the disabled run leaves Cloudflare and
    # state.json as they are and says how to clean up.
    jq 'del(.version)' state/state.json > old-state.json && mv old-state.json state/state.json
    cp state/state.json legacy-state.json
    before=$(writes)
    router-ddns --config ${off} || fail "the disabled run over pre-upgrade state failed"
    [ "$(writes)" = "$before" ] || fail "the disabled run over pre-upgrade state wrote $(( $(writes) - before )) time(s)"
    want '[{"type":"CNAME","name":"example.com","content":"site.example.net"},{"type":"TXT","name":"example.com","content":"v=spf1 -all"},{"type":"A","name":"nas.example.com","content":"203.0.113.1"}]' \
      "after a disabled run over pre-upgrade state"
    cmp -s state/state.json legacy-state.json || fail "the disabled run over pre-upgrade state rewrote state.json: $(jq -c . state/state.json)"
    jq -e '.ok and .records == [] and (.message | startswith("records from before the upgrade are left in Cloudflare"))' state/status.json >/dev/null \
      || fail "status.json does not say the pre-upgrade records were kept: $(cat state/status.json)"

    # The cleanup it names: turn dynamic DNS on and apply (a no-change run,
    # which stamps the version) ...
    router-ddns --config ${nasOnly} || fail "the enabled run before the cleanup failed"
    [ "$(writes)" = "$before" ] || fail "the enabled run before the cleanup wrote $(( $(writes) - before )) time(s)"

    # ... then off again (the name is still in the config): the last A record
    # goes and its CNAME comes back, so the zone is back to where it started.
    # No address is looked up.
    router-ddns --config ${off} || fail "the teardown run failed"
    want '[{"type":"CNAME","name":"example.com","content":"site.example.net"},{"type":"TXT","name":"example.com","content":"v=spf1 -all"},{"type":"CNAME","name":"nas.example.com","content":"old-ddns.example.net"}]' \
      "after turning dynamic DNS off"
    live | jq -e '[.records[] | select(.name == "nas.example.com")] | .[0] | .ttl == 300 and .proxied == false' >/dev/null \
      || fail "the restored CNAME lost its TTL or proxying: $(live | jq -c .records)"
    jq -e '.managed == [] and .replaced == {}' state/state.json >/dev/null \
      || fail "state still tracks records after teardown: $(jq -c . state/state.json)"
    jq -e '.ok and .addresses == {"ipv4": null, "ipv4Source": "disabled", "ipv6": null}
      and ([.records[] | "\(.state) \(.type)"] | sort) == ["created CNAME", "removed A"]' state/status.json >/dev/null \
      || fail "status.json after teardown is wrong: $(cat state/status.json)"

    # 6 — disabled with nothing left to tear down: no API call, no status write.
    before=$(writes)
    rm state/status.json
    router-ddns --config ${off} || fail "a second disabled run failed"
    [ "$(writes)" = "$before" ] || fail "a second disabled run wrote to the API"
    [ ! -e state/status.json ] || fail "a disabled run with nothing to tear down wrote status.json"

    # 7 — a replaced CNAME someone already put back by hand, as the docs once
    # said to, is left as it is rather than refused as a duplicate (which
    # would fail this run and every one after it).
    router-ddns --config ${nasOnly} || fail "taking nas.example.com over again failed"
    auth='Authorization: Bearer test-token'
    a=$(live | jq -r '.records[] | select(.name == "nas.example.com" and .type == "A") | .id')
    curl -sf -X DELETE -H "$auth" $api/client/v4/zones/zone-1/dns_records/$a >/dev/null
    curl -sf -X POST -H "$auth" -H 'Content-Type: application/json' \
      -d '{"type":"CNAME","name":"nas.example.com","content":"old-ddns.example.net","ttl":300,"proxied":false}' \
      $api/client/v4/zones/zone-1/dns_records >/dev/null
    router-ddns --config ${off} || fail "restoring a CNAME already put back by hand failed: $(cat state/status.json)"
    want '[{"type":"CNAME","name":"example.com","content":"site.example.net"},{"type":"TXT","name":"example.com","content":"v=spf1 -all"},{"type":"CNAME","name":"nas.example.com","content":"old-ddns.example.net"}]' \
      "after restoring a CNAME already put back by hand"
    jq -e '.managed == [] and .replaced == {}' state/state.json >/dev/null \
      || fail "state still tracks the CNAME put back by hand: $(jq -c . state/state.json)"
    jq -e '.ok and ([.records[] | "\(.state) \(.type)"] | sort) == ["removed A", "unchanged CNAME"]' state/status.json >/dev/null \
      || fail "status.json claims the CNAME put back by hand was created: $(cat state/status.json)"

    touch $out
  ''
