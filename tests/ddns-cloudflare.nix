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
#     refused as a duplicate, and so is a different CNAME put there by hand;
#   • a name taken over again after a hand edit, which remembers two CNAMEs,
#     gets back only the one taken over last;
#   • a name moved between the tunnel and dynamic DNS in one apply, with the
#     tool taking it over running first, in both directions: the taker does
#     not remember the other tool's record, and the one letting go keeps the
#     owner's CNAME — through its disabled and idle runs too — until the name
#     is free, then puts it back.
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
      stateDir ? "state",
    }:
    pkgs.writeText "router-ddns.json" (
      builtins.toJSON {
        ddns = {
          inherit
            enable
            ttl
            proxied
            stateDir
            ;
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

  # Steps 10 and 11: wiki.example.com moves between router-ddns and
  # router-cloudflare-tunnel, each with its own state directory, as on a
  # router.
  ddnsWiki = configFor {
    names = [ "wiki.example.com" ];
    stateDir = "move-ddns";
  };
  ddnsNone = configFor {
    names = [ ];
    stateDir = "move-ddns";
  };
  ddnsOff = configFor {
    names = [ ];
    enable = false;
    stateDir = "move-ddns";
  };
  tunnelFor =
    {
      enable ? true,
      hostnames,
    }:
    pkgs.writeText "router-cloudflare-tunnel.json" (
      builtins.toJSON {
        tunnel = {
          inherit enable hostnames;
          stateDir = "move-tunnel";
          name = "router";
          apiTokenFile = null;
        };
      }
    );
  tunnelWiki = tunnelFor { hostnames = [ "wiki.example.com" ]; };
  tunnelNone = tunnelFor { hostnames = [ ]; };
  tunnelOff = tunnelFor {
    enable = false;
    hostnames = [ ];
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
    auth='Authorization: Bearer test-token'
    # By hand: swap the router's A record at nas.example.com for a CNAME.
    handCname() {
      a=$(live | jq -r '.records[] | select(.name == "nas.example.com" and .type == "A") | .id')
      curl -sf -X DELETE -H "$auth" $api/client/v4/zones/zone-1/dns_records/$a >/dev/null
      curl -sf -X POST -H "$auth" -H 'Content-Type: application/json' \
        -d "{\"type\":\"CNAME\",\"name\":\"nas.example.com\",\"content\":\"$1\",\"ttl\":300,\"proxied\":false}" \
        $api/client/v4/zones/zone-1/dns_records >/dev/null
    }
    router-ddns --config ${nasOnly} || fail "taking nas.example.com over again failed"
    handCname old-ddns.example.net
    router-ddns --config ${off} || fail "restoring a CNAME already put back by hand failed: $(cat state/status.json)"
    want '[{"type":"CNAME","name":"example.com","content":"site.example.net"},{"type":"TXT","name":"example.com","content":"v=spf1 -all"},{"type":"CNAME","name":"nas.example.com","content":"old-ddns.example.net"}]' \
      "after restoring a CNAME already put back by hand"
    jq -e '.managed == [] and .replaced == {}' state/state.json >/dev/null \
      || fail "state still tracks the CNAME put back by hand: $(jq -c . state/state.json)"
    jq -e '.ok and ([.records[] | "\(.state) \(.type)"] | sort) == ["removed A", "unchanged CNAME"]' state/status.json >/dev/null \
      || fail "status.json claims the CNAME put back by hand was created: $(cat state/status.json)"

    # 8 — a different CNAME put at the name by hand is left as it is too. A
    # name holds one CNAME, so Cloudflare would refuse the remembered one.
    router-ddns --config ${nasOnly} || fail "taking nas.example.com over a third time failed"
    handCname new-ddns.example.net
    router-ddns --config ${off} || fail "tearing down beside a different hand-made CNAME failed: $(cat state/status.json)"
    want '[{"type":"CNAME","name":"example.com","content":"site.example.net"},{"type":"TXT","name":"example.com","content":"v=spf1 -all"},{"type":"CNAME","name":"nas.example.com","content":"new-ddns.example.net"}]' \
      "after tearing down beside a different hand-made CNAME"
    jq -e '.managed == [] and .replaced == {}' state/state.json >/dev/null \
      || fail "state still tracks the CNAME left out: $(jq -c . state/state.json)"
    jq -e '.ok and [.records[] | select(.type == "CNAME") | [.state, .content, .detail]]
      == [["unchanged", "old-ddns.example.net", "a CNAME is already back: the name is no longer configured"]]' state/status.json >/dev/null \
      || fail "status.json does not say the remembered CNAME was left out: $(cat state/status.json)"

    # 9 — a name taken over again after a hand edit remembers each CNAME it
    # lost. The full check takes over the one put there by hand, so
    # nas.example.com remembers new-ddns and then old-ddns; teardown restores
    # only old-ddns, the owner's latest intent, instead of both (Cloudflare
    # would refuse the second on this run and every one after it).
    router-ddns --config ${nasOnly} || fail "taking the different hand-made CNAME over failed"
    handCname old-ddns.example.net
    router-ddns --force --config ${nasOnly} || fail "the full check over a hand-made CNAME failed"
    jq -e '.replaced["nas.example.com"] | map(.content) == ["new-ddns.example.net", "old-ddns.example.net"]' state/state.json >/dev/null \
      || fail "the name does not remember both CNAMEs: $(jq -c .replaced state/state.json)"
    router-ddns --config ${off} || fail "tearing down with two CNAMEs remembered failed: $(cat state/status.json)"
    want '[{"type":"CNAME","name":"example.com","content":"site.example.net"},{"type":"TXT","name":"example.com","content":"v=spf1 -all"},{"type":"CNAME","name":"nas.example.com","content":"old-ddns.example.net"}]' \
      "after tearing down with two CNAMEs remembered"
    jq -e '.managed == [] and .replaced == {}' state/state.json >/dev/null \
      || fail "state still tracks CNAMEs after teardown: $(jq -c . state/state.json)"
    jq -e '.ok and [.records[] | select(.type == "CNAME") | [.state, .content, .detail]]
      == [["unchanged", "new-ddns.example.net", "superseded by a CNAME taken over later: the name is no longer configured"],
          ["created", "old-ddns.example.net", "restored: the name is no longer configured"]]' state/status.json >/dev/null \
      || fail "status.json does not say which CNAME was restored: $(cat state/status.json)"

    # 10 — wiki moves from the tunnel to dynamic DNS in one apply, and
    # router-ddns happens to run first. It takes the tunnel's CNAME over
    # without remembering it (that was never the owner's). The tunnel then
    # finds router-ddns's A record at wiki: the router's own, not the owner's
    # choice, so it keeps the owner's CNAME instead of forgetting it, and
    # puts it back once dynamic DNS lets go of the name.
    at() { live | jq -c '[.records[] | select(.name == "wiki.example.com") | {type, content}] | sort_by(.type)'; }
    wantAt() { [ "$(at)" = "$1" ] || fail "$2: wiki.example.com holds $(at), want $1"; }
    ownerWiki='{"type":"CNAME","name":"wiki.example.com","content":"owner-wiki.example.net","ttl":300,"proxied":false,"comment":"owner"}'
    remembers() {
      jq -e --argjson r "$ownerWiki" '.replaced == {"wiki.example.com": [$r]}' "$1/state.json" >/dev/null \
        || fail "$2: $1 remembers $(jq -c .replaced "$1/state.json"), want the owner's CNAME"
    }
    curl -sf -X POST -H "$auth" -H 'Content-Type: application/json' -d "$ownerWiki" \
      $api/client/v4/zones/zone-1/dns_records >/dev/null
    router-cloudflare-tunnel --config ${tunnelWiki} || fail "the tunnel taking wiki over failed"
    remembers move-tunnel "after the tunnel took wiki over"
    router-ddns --config ${ddnsWiki} || fail "dynamic DNS taking wiki from the tunnel failed"
    wantAt '[{"type":"A","content":"203.0.113.1"}]' "after dynamic DNS took wiki from the tunnel"
    jq -e '.replaced == {}' move-ddns/state.json >/dev/null \
      || fail "dynamic DNS remembered the tunnel's CNAME as replaced: $(jq -c .replaced move-ddns/state.json)"
    router-cloudflare-tunnel --config ${tunnelNone} || fail "the tunnel letting go of wiki held by dynamic DNS failed: $(cat move-tunnel/status.json)"
    wantAt '[{"type":"A","content":"203.0.113.1"}]' "after the tunnel let go of wiki held by dynamic DNS"
    remembers move-tunnel "while dynamic DNS holds wiki"
    jq -e '.ok and .records["wiki.example.com"].ok
      and (.records["wiki.example.com"].message | endswith("1 replaced record(s) waiting until dynamic DNS releases the name"))' move-tunnel/status.json >/dev/null \
      || fail "the tunnel's status does not say wiki is waiting: $(cat move-tunnel/status.json)"
    # Turned off meanwhile: the tunnel goes but the entry stays, and a later
    # disabled run, with only that entry left, tries again without a write.
    router-cloudflare-tunnel --config ${tunnelOff} || fail "tearing the tunnel down with wiki waiting failed: $(cat move-tunnel/status.json)"
    [ ! -e move-tunnel/credentials.json ] || fail "the teardown with wiki waiting kept the credentials"
    remembers move-tunnel "after the teardown with wiki waiting"
    before=$(writes)
    router-cloudflare-tunnel --config ${tunnelOff} || fail "the disabled run with wiki waiting failed: $(cat move-tunnel/status.json)"
    [ "$(writes)" = "$before" ] || fail "the disabled run with wiki waiting wrote $(( $(writes) - before )) time(s)"
    remembers move-tunnel "after the disabled run with wiki waiting"
    # wiki leaves dynamic DNS too, which has nothing of its own to put back;
    # the tunnel's next run (on again, idle with no hostnames) puts the
    # owner's CNAME back as it was.
    router-ddns --config ${ddnsNone} || fail "dynamic DNS dropping wiki failed"
    wantAt '[]' "after dynamic DNS dropped wiki"
    router-cloudflare-tunnel --config ${tunnelNone} || fail "the tunnel putting the owner's CNAME back failed: $(cat move-tunnel/status.json)"
    live | jq -e --argjson r "$ownerWiki" '[.records[] | select(.name == "wiki.example.com") | del(.id)] == [$r]' >/dev/null \
      || fail "the owner's CNAME did not come back as it was: wiki.example.com holds $(at)"
    jq -e '.replaced == {} and .managed == []' move-tunnel/state.json >/dev/null \
      || fail "the tunnel still tracks wiki: $(jq -c . move-tunnel/state.json)"

    # 11 — and back the other way: wiki moves from dynamic DNS to the tunnel,
    # and the tunnel runs first. It takes router-ddns's A record over without
    # remembering it, and router-ddns, finding the tunnel's CNAME at wiki,
    # keeps the owner's CNAME until the tunnel lets go of the name.
    router-ddns --config ${ddnsWiki} || fail "dynamic DNS taking wiki over failed"
    remembers move-ddns "after dynamic DNS took wiki over"
    router-cloudflare-tunnel --config ${tunnelWiki} || fail "the tunnel taking wiki from dynamic DNS failed"
    wantAt "[{\"type\":\"CNAME\",\"content\":\"$(jq -r .TunnelID move-tunnel/credentials.json).cfargotunnel.com\"}]" \
      "after the tunnel took wiki from dynamic DNS"
    jq -e '.replaced == {}' move-tunnel/state.json >/dev/null \
      || fail "the tunnel remembered dynamic DNS's A record as replaced: $(jq -c .replaced move-tunnel/state.json)"
    router-ddns --config ${ddnsNone} || fail "dynamic DNS letting go of wiki held by the tunnel failed: $(cat move-ddns/status.json)"
    remembers move-ddns "while the tunnel holds wiki"
    jq -e '.ok and [.records[] | select(.type == "CNAME") | [.state, .content, .detail]]
      == [["unchanged", "owner-wiki.example.net", "waiting until the tunnel releases the name"]]' move-ddns/status.json >/dev/null \
      || fail "dynamic DNS's status does not say wiki is waiting: $(cat move-ddns/status.json)"
    # Dynamic DNS turned off meanwhile: the disabled run still has the entry
    # to put back, and tries again without a write.
    before=$(writes)
    router-ddns --config ${ddnsOff} || fail "the disabled run with wiki waiting failed: $(cat move-ddns/status.json)"
    [ "$(writes)" = "$before" ] || fail "the disabled run with wiki waiting wrote $(( $(writes) - before )) time(s)"
    remembers move-ddns "after the disabled run with wiki waiting"
    # wiki leaves the tunnel, which has nothing of its own to put back; the
    # next dynamic DNS run puts the owner's CNAME back as it was.
    router-cloudflare-tunnel --config ${tunnelNone} || fail "the tunnel dropping wiki failed: $(cat move-tunnel/status.json)"
    wantAt '[]' "after the tunnel dropped wiki"
    router-ddns --config ${ddnsOff} || fail "dynamic DNS putting the owner's CNAME back failed: $(cat move-ddns/status.json)"
    live | jq -e --argjson r "$ownerWiki" '[.records[] | select(.name == "wiki.example.com") | del(.id)] == [$r]' >/dev/null \
      || fail "the owner's CNAME did not come back as it was: wiki.example.com holds $(at)"
    jq -e '.managed == [] and .replaced == {}' move-ddns/state.json >/dev/null \
      || fail "dynamic DNS still tracks wiki: $(jq -c . move-ddns/state.json)"
    jq -e '.ok and [.records[] | [.state, .type, .detail]] == [["created", "CNAME", "restored: the name is no longer configured"]]' move-ddns/status.json >/dev/null \
      || fail "dynamic DNS's status does not say the owner's CNAME was restored: $(cat move-ddns/status.json)"

    touch $out
  ''
