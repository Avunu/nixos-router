# Build-sandbox check of router-cloudflare-tunnel against the fake Cloudflare
# API — no VM. Pinned here, through the packaged CLI:
#
#   • enabled with no hostnames and no tunnel yet, a run succeeds without an
#     API write and reports itself idle — there is no zone to name the
#     account, and nothing to serve;
#   • the first run creates the tunnel, writes cloudflared's credentials
#     (mode 0600, the secret the API was given) and one proxied CNAME per
#     hostname (case and duplicates folded), taking over a hand-made A record;
#   • a second run with nothing changed writes nothing and keeps the tunnel;
#   • dropping a name deletes its CNAME and restores the A record exactly;
#   • a tunnel deleted behind the router's back is created again, and the DNS
#     follows the new id;
#   • a name edited by hand while the tunnel held it gets back only the
#     record taken over last, and a dropped name keeps a record put there by
#     hand that the remembered one cannot sit beside;
#   • dropping the last hostname releases its CNAME but keeps the tunnel;
#   • enable=false removes the CNAMEs, deletes the tunnel (cleaning up its
#     still-open connection first) and the credentials; a second teardown
#     is a no-op;
#   • status.json reports the tunnel, its connections and each hostname, and
#     is written — with a non-zero exit — when the run fails.
{
  pkgs,
  routerDnsTools,
}:
let
  seed = pkgs.writeText "cloudflare-seed.json" (
    builtins.toJSON [
      {
        type = "A";
        name = "wiki.example.com";
        content = "192.0.2.10";
        ttl = 300;
        proxied = false;
        comment = "hand-made";
      }
      {
        type = "TXT";
        name = "wiki.example.com";
        content = "keep me";
        ttl = 1;
        proxied = false;
      }
    ]
  );

  configFor =
    {
      enable ? true,
      hostnames,
      stateDir ? "state",
    }:
    pkgs.writeText "router-cloudflare-tunnel.json" (
      builtins.toJSON {
        tunnel = {
          inherit enable hostnames stateDir;
          name = "router";
          apiTokenFile = null;
        };
      }
    );
  both = configFor {
    hostnames = [
      "app.example.com"
      "wiki.example.com"
      "App.Example.com"
    ];
  };
  appOnly = configFor { hostnames = [ "app.example.com" ]; };
  empty = configFor { hostnames = [ ]; };
  emptyFresh = configFor {
    hostnames = [ ];
    stateDir = "state-empty";
  };
  off = configFor {
    enable = false;
    hostnames = [ "app.example.com" ];
  };
  noToken = configFor {
    hostnames = [ "app.example.com" ];
    stateDir = "state-notoken";
  };
in
pkgs.runCommand "router-cloudflare-tunnel"
  {
    nativeBuildInputs = [
      pkgs.python3
      pkgs.curl
      pkgs.jq
      routerDnsTools
    ];
  }
  ''
    export FAKE_CF_BIND=127.0.0.1 FAKE_CF_PORT=8054 FAKE_CF_SEED=${seed}
    python3 ${./fake-cloudflare.py} &
    trap 'kill $!' EXIT
    api=http://127.0.0.1:8054
    curl -s --retry-connrefused --retry 50 --retry-delay 0 --retry-max-time 30 $api/__state >/dev/null

    export ROUTER_CLOUDFLARE_API_BASE=$api/client/v4
    mkdir creds && echo test-token > creds/cf-api-token
    export CREDENTIALS_DIRECTORY=$PWD/creds

    fail() { echo "FAIL $*" >&2; exit 1; }
    live() { curl -sf $api/__state | jq -c '.result'; }
    records() { live | jq -c '[.records[] | {type, name, content}] | sort_by(.name, .type)'; }
    writes() { live | jq '.writes'; }
    want() { [ "$(records)" = "$1" ] || fail "$2: records are $(records), want $1"; }
    tid() { jq -r .TunnelID state/credentials.json; }
    cname() { echo "{\"type\":\"CNAME\",\"name\":\"$1\",\"content\":\"$(tid).cfargotunnel.com\"}"; }
    wikiA='{"type":"A","name":"wiki.example.com","content":"192.0.2.10"}'
    wikiTXT='{"type":"TXT","name":"wiki.example.com","content":"keep me"}'
    fakeDelete() {
      curl -sf -X DELETE -H 'Authorization: Bearer test-token' "$api/client/v4/accounts/acct1/cfd_tunnel/$1$2" >/dev/null
    }

    # 0 — enabled, but no hostnames and no tunnel yet: idle, nothing created.
    router-cloudflare-tunnel --config ${emptyFresh} || fail "the run with no hostnames failed"
    [ "$(writes)" = 0 ] || fail "the run with no hostnames wrote $(writes) time(s) to the API"
    live | jq -e '.tunnels == []' >/dev/null || fail "a tunnel was created with no hostnames: $(live | jq -c .tunnels)"
    [ ! -e state-empty/credentials.json ] || fail "credentials were written with no hostnames"
    jq -e '.ok == true and .error == null and .tunnel == null and .records == {}
      and .message == "add a hostname to create the tunnel"' state-empty/status.json >/dev/null \
      || fail "status.json of the idle run is wrong: $(cat state-empty/status.json)"

    # 1 — first run: tunnel, credentials, CNAMEs; the hand-made A is taken over.
    router-cloudflare-tunnel --config ${both} || fail "the first run failed"
    [ "$(stat -c %a state/credentials.json)" = 600 ] || fail "credentials.json is mode $(stat -c %a state/credentials.json)"
    first=$(tid)
    # The secret is 32 random bytes: canonical base64 of that is 43 characters
    # and one "=". (Not `@base64d | length` — jq decodes to text and counts
    # characters, which for random bytes is almost never 32.)
    live | jq -e --slurpfile c state/credentials.json '
      [.tunnels[] | select(.deleted_at == null)] as $t
      | ($t | length) == 1 and $t[0].id == $c[0].TunnelID and $t[0].name == "router"
        and $t[0].config_src == "local" and $t[0].tunnel_secret == $c[0].TunnelSecret
        and $c[0].AccountTag == "acct1" and ($c[0].TunnelSecret | test("^[A-Za-z0-9+/]{43}=$"))' >/dev/null \
      || fail "the tunnel or its credentials are wrong: $(live | jq -c .tunnels) vs $(jq -c 'del(.TunnelSecret)' state/credentials.json)"
    want "[$(cname app.example.com),$(cname wiki.example.com),$wikiTXT]" "after the first run"
    live | jq -e '[.records[] | select(.type == "CNAME")] | all(.proxied == true and .ttl == 1 and .comment == "managed by nixos-router")' >/dev/null \
      || fail "the CNAMEs are not proxied managed records: $(live | jq -c .records)"
    jq -e '.replaced["wiki.example.com"] == [{"type":"A","name":"wiki.example.com","content":"192.0.2.10","ttl":300,"proxied":false,"comment":"hand-made"}]' state/state.json >/dev/null \
      || fail "the A record was not remembered faithfully: $(jq -c .replaced state/state.json)"
    jq -e --arg id "$first" '
      .ok == true and .error == null
      and .tunnel == {"id": $id, "name": "router", "status": "healthy"}
      and .connections == [{"colo":"ams01","originIp":"198.51.100.7","openedAt":"2026-01-01T00:00:05Z","clientVersion":"2026.9.0"}]
      and (.records | keys) == ["app.example.com","wiki.example.com"]
      and (.records | all(.ok))
      and (.records["wiki.example.com"].message | contains("replaced A → 192.0.2.10"))
      and (.updated | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z$"))' state/status.json >/dev/null \
      || fail "status.json is wrong: $(cat state/status.json)"
    grep -rqF "$(jq -r .TunnelSecret state/credentials.json)" state/status.json state/state.json \
      && fail "the tunnel secret leaked outside credentials.json"

    # 2 — nothing changed: nothing written, same tunnel.
    before=$(writes)
    router-cloudflare-tunnel --config ${both} || fail "the no-change run failed"
    [ "$(writes)" = "$before" ] || fail "a run with nothing changed wrote $(( $(writes) - before )) time(s)"
    [ "$(tid)" = "$first" ] || fail "the tunnel changed on a no-change run"
    want "[$(cname app.example.com),$(cname wiki.example.com),$wikiTXT]" "after the no-change run"

    # 3 — wiki is dropped: its CNAME goes, the A record comes back as it was.
    router-cloudflare-tunnel --config ${appOnly} || fail "the run dropping wiki failed"
    want "[$(cname app.example.com),$wikiA,$wikiTXT]" "after dropping wiki"
    live | jq -e '[.records[] | select(.type == "A")] | length == 1 and .[0].ttl == 300 and .[0].proxied == false and .[0].comment == "hand-made"' >/dev/null \
      || fail "the restored A record lost its ttl, proxying or comment: $(live | jq -c .records)"
    jq -e '.replaced == {} and .managed == ["app.example.com"]' state/state.json >/dev/null \
      || fail "state still tracks wiki: $(jq -c . state/state.json)"

    # 4 — the tunnel is deleted behind the router's back: a new one, DNS follows.
    fakeDelete "$first" /connections && fakeDelete "$first" "" || fail "the fake refused the out-of-band delete"
    router-cloudflare-tunnel --config ${appOnly} || fail "the run after the tunnel vanished failed"
    [ "$(tid)" != "$first" ] || fail "the deleted tunnel was not replaced"
    want "[$(cname app.example.com),$wikiA,$wikiTXT]" "after recreating the tunnel"
    jq -e --arg id "$(tid)" '.ok and .tunnel.id == $id' state/status.json >/dev/null \
      || fail "status.json does not name the new tunnel: $(cat state/status.json)"

    # 5 — the owner swaps wiki's managed CNAME for one of their own, which the
    # next sync takes over too: wiki now remembers the A record and then that
    # CNAME. Dropping wiki restores only the CNAME, taken over last, since the
    # A record cannot sit beside it (Cloudflare would refuse the second).
    swap() {
      r=$(live | jq -r --arg n "$1" '.records[] | select(.name == $n and .comment == "managed by nixos-router") | .id')
      curl -sf -X DELETE -H 'Authorization: Bearer test-token' "$api/client/v4/zones/zone-1/dns_records/$r" >/dev/null
      curl -sf -X POST -H 'Authorization: Bearer test-token' -H 'Content-Type: application/json' -d "$2" \
        "$api/client/v4/zones/zone-1/dns_records" >/dev/null
    }
    wikiHost='{"type":"CNAME","name":"wiki.example.com","content":"wiki-host.example.net"}'
    router-cloudflare-tunnel --config ${both} || fail "taking wiki over again failed"
    swap wiki.example.com "$wikiHost"
    router-cloudflare-tunnel --config ${both} || fail "taking the hand-made CNAME over failed"
    jq -e '.replaced["wiki.example.com"] | map("\(.type) \(.content)") == ["A 192.0.2.10", "CNAME wiki-host.example.net"]' state/state.json >/dev/null \
      || fail "wiki does not remember both records: $(jq -c .replaced state/state.json)"
    router-cloudflare-tunnel --config ${appOnly} || fail "dropping wiki with two records remembered failed: $(cat state/status.json)"
    want "[$(cname app.example.com),$wikiHost,$wikiTXT]" "after dropping wiki with two records remembered"

    # And back: wiki is taken over again (remembering that CNAME), and the
    # owner puts the A record back by hand. Dropping wiki leaves it as it is.
    router-cloudflare-tunnel --config ${both} || fail "taking wiki over a third time failed"
    swap wiki.example.com '{"type":"A","name":"wiki.example.com","content":"192.0.2.10","ttl":300,"proxied":false,"comment":"hand-made"}'
    router-cloudflare-tunnel --config ${appOnly} || fail "dropping wiki beside a hand-made A record failed: $(cat state/status.json)"
    want "[$(cname app.example.com),$wikiA,$wikiTXT]" "after dropping wiki beside a hand-made A record"
    jq -e '.replaced == {} and .managed == ["app.example.com"]' state/state.json >/dev/null \
      || fail "state still tracks wiki: $(jq -c . state/state.json)"

    # 6 — the last hostname is dropped: its CNAME goes, the tunnel stays.
    kept=$(tid)
    router-cloudflare-tunnel --config ${empty} || fail "the run dropping the last hostname failed"
    [ "$(tid)" = "$kept" ] || fail "the tunnel changed when its last hostname was dropped"
    want "[$wikiA,$wikiTXT]" "after dropping the last hostname"
    jq -e --arg id "$kept" '.ok and .tunnel.id == $id and .records == {} and (has("message") | not)' state/status.json >/dev/null \
      || fail "status.json with the tunnel kept is wrong: $(cat state/status.json)"

    # 7 — disabled: records, tunnel (open connection and all) and credentials go.
    router-cloudflare-tunnel --config ${off} || fail "the teardown run failed"
    want "[$wikiA,$wikiTXT]" "after teardown"
    live | jq -e '.tunnels | all(.deleted_at != null)' >/dev/null || fail "a tunnel survived teardown: $(live | jq -c .tunnels)"
    [ ! -e state/credentials.json ] || fail "credentials.json survived teardown"
    jq -e '.ok == true and .tunnel == null and .connections == []' state/status.json >/dev/null \
      || fail "status.json after teardown is wrong: $(cat state/status.json)"
    before=$(writes)
    router-cloudflare-tunnel --config ${off} || fail "a second teardown failed"
    [ "$(writes)" = "$before" ] || fail "a second teardown wrote to the API"

    # 8 — a failed run still writes status.json, and exits non-zero.
    rm creds/cf-api-token
    router-cloudflare-tunnel --config ${noToken} && fail "a run without a token succeeded"
    jq -e '.ok == false and (.error | contains("no Cloudflare API token")) and .tunnel == null' state-notoken/status.json >/dev/null \
      || fail "status.json of the failed run is wrong: $(cat state-notoken/status.json)"

    touch $out
  ''
