# NixOS VM test — Technitium access-protection stack end-to-end.
#
# Boots the router with the full new stack (Technitium + Advanced Blocking +
# Log Exporter + Block Page, router-logd, reporting) and verifies, hermetically
# (no internet — test policies use only static blockDomains, no list URLs):
#   • first-boot env seeding + app pre-seeding + reconcile all succeed;
#   • the new router.* sections surface in /etc/router/effective.json;
#   • DHCP reservations render as [DHCPServerStaticLease] networkd sections;
#   • directory identity resolves through SSSD against a local OpenLDAP: the
#     test user exists ONLY in LDAP, so getent/getgrouplist prove the real path;
#   • policy precedence end-to-end via dig from netns "LAN clients":
#       - pinned device in a host group → its group policy (NXDOMAIN),
#       - directory-group tier activates after a directory sync + policy push,
#       - unpinned client → the default policy (block page address answer);
#   • the Log Exporter → router-logd ingest pipeline records the blocked query
#     WITH group attribution;
#   • the block page is served and the exception-request portal round-trips;
#   • split-horizon DNS: overrides answer locally, a name inside an overridden
#     domain that was NOT overridden still falls through to the forwarder
#     rather than going NXDOMAIN (the one thing an eval check cannot pin), a
#     conditional forward zone reaches an internal DNS server, static
#     reservations get forward and reverse names, and removing an override
#     reaps its zone;
#   • a report service produces a PDF offline (Typst).
{
  pkgs,
  routerModule,
  baseSettings,
}:
let
  # Minimal, deliberately non-RFC-6762-faithful mDNS stand-in for the
  # resolveMdns subtests below: a stand-in like vmtest-internal-dns is for
  # split-horizon forwarding, just at the mDNS layer instead of unicast DNS.
  # It only needs to prove the Router Live DNS app's raw multicast query/parse
  # round-trips correctly against a real UDP multicast exchange — it answers
  # ONE fixed name and replies to the multicast group (matching real mDNS
  # responder behavior, and required so the reply reaches the resolver's
  # per-query socket regardless of how the kernel's SO_REUSEPORT unicast
  # hashing would otherwise split traffic with avahi-daemon's own listener).
  mdnsTestResponder = pkgs.writers.writePython3Bin "mdns-test-responder" { } ''
    import socket
    import struct

    TARGET = "test-device.local"
    ANSWER_IP = "10.48.4.90"


    def encode_name(name):
        out = b""
        for label in name.split("."):
            out += bytes([len(label)]) + label.encode("ascii")
        return out + b"\x00"


    def decode_name(data, offset):
        labels = []
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            end = offset + length
            labels.append(data[offset:end].decode("ascii"))
            offset += length
        return ".".join(labels), offset


    def main():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("0.0.0.0", 5353))
        group = socket.inet_aton("224.0.0.251")
        # The join's interface selector must be a real local address - "0.0.0.0"
        # (kernel picks the default-route interface) raises ENODEV in a netns
        # with no default route, which this fixture's netns deliberately has
        # none of. ANSWER_IP is this netns's own veth address, so it always
        # resolves to the one interface that matters here.
        iface = socket.inet_aton(ANSWER_IP)
        mreq = struct.pack("4s4s", group, iface)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        # Same reasoning for SENDING: with no default route in this netns,
        # the kernel has no way to pick an outgoing interface for a multicast
        # destination unless told explicitly.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, iface)

        while True:
            data, addr = sock.recvfrom(4096)
            if len(data) < 12:
                continue
            qdcount = struct.unpack(">H", data[4:6])[0]
            if qdcount < 1:
                continue
            name, _ = decode_name(data, 12)
            if name != TARGET:
                continue

            ident = data[0:2]
            counts = struct.pack(">HHHH", 0, 1, 0, 0)
            header = ident + b"\x84\x00" + counts
            rr_head = struct.pack(">HHIH", 1, 1, 120, 4)
            rdata = socket.inet_aton(ANSWER_IP)
            answer = encode_name(TARGET) + rr_head + rdata
            # Reply to the multicast group (RFC 6762 SS6), not unicast to the
            # querier: avahi-daemon and the resolver's per-query socket both
            # bind :5353 with SO_REUSEPORT, which load-balances a UNICAST
            # packet to exactly one of them by hash - it could land on either.
            # A multicast reply is delivered to every group member instead,
            # so the resolver (having joined 224.0.0.251) always gets it.
            sock.sendto(header + answer, ("224.0.0.251", 5353))


    if __name__ == "__main__":
        main()
  '';
in
pkgs.testers.runNixOSTest {
  name = "router-technitium";

  nodes.router =
    { lib, ... }:
    {
      imports = [ routerModule ];

      config = lib.mkMerge [
        { router = lib.mkDefault baseSettings; }

        {
          router.wan.interface = "eth1";
          router.lan.interfaces = [ "eth2" ];
          router.guest.enable = false;
          router.cockpit.enable = true;
          router.suricata.enable = false;

          router.hostGroups = [
            {
              name = "Kids";
              description = "restricted devices";
            }
          ];
          router.hosts = [
            {
              mac = "aa:bb:cc:dd:ee:01";
              name = "lab-1";
              staticIp = "10.48.4.50";
              network = "lan";
              group = "Kids";
            }
            {
              mac = "aa:bb:cc:dd:ee:02";
              name = "jdoe-laptop";
              staticIp = "10.48.4.60";
              network = "lan";
              user = "jdoe"; # POSIX login, resolved through SSSD
            }
            {
              # Deliberately dangling: proves an unresolvable reference is a
              # WARNING, not a sync failure (directory_sync/__init__.py).
              mac = "aa:bb:cc:dd:ee:03";
              name = "ghost-laptop";
              staticIp = "10.48.4.61";
              network = "lan";
              user = "ghost";
            }
            {
              # No staticIp: adopted but DHCP-dynamic. Only ever resolves via
              # the Router Live DNS app's live ARP/NDP lookup (Gap 1) — proves
              # "adopted hosts should always resolve" independent of
              # registerStaticHosts, which stays true above for the static
              # hosts' explicit-record/PTR path.
              mac = "aa:bb:cc:dd:ee:04";
              name = "dyn-1";
              network = "lan";
            }
          ];

          router.dns.technitium.resolveMdns = true;

          # Hermetic policies: static domains only, no list downloads.
          router.accessPolicies = {
            defaultPolicy = "Base";
            blockPage = {
              enable = true;
              heading = "VM-TEST Blocked";
            };
            policies = [
              {
                name = "Base";
                blockDomains = [ "lan-blocked.vmtest" ];
                responseType = "blockingAddress";
              }
              {
                name = "Strict";
                priority = 10;
                blockDomains = [ "kids-blocked.vmtest" ];
                responseType = "nxdomain";
                assignments = {
                  hostGroups = [ "Kids" ];
                  directoryGroups = [ "Students" ];
                };
              }
              {
                # Covers the GROUP arm of status.json's unresolved list.
                name = "Ghosts";
                priority = 20;
                blockDomains = [ "ghost-blocked.vmtest" ];
                responseType = "nxdomain";
                assignments.directoryGroups = [ "NoSuchGroup" ];
              }
            ];
          };

          # A genuinely end-to-end identity path: a local OpenLDAP holds jdoe
          # and Students, SSSD is the ONLY way to resolve them (neither name
          # exists in /etc/passwd or /etc/group), and router-directory-sync
          # reaches them through NSS exactly as it would against a real DC.
          #
          # NB: proxy_lib_name = "files" would be a useless test here —
          # /etc/nsswitch.conf is "passwd: files sss" with files forced first,
          # so a local user would be answered by `files` and never reach sss.
          router.directory = {
            provider = "sssd";
            syncIntervalMinutes = 5;
            sssd = {
              domain = "vmtest";
              servers = [ "ldap://127.0.0.1:389" ];
              baseDn = "dc=vmtest";
              schema = "rfc2307";
              idMapping = false; # the fixture carries real uidNumber/gidNumber
              tlsReqCert = "never"; # hermetic VM only; never in production
              # Identity is for POLICY ASSIGNMENT ONLY — asserted below.
              adminGroup = "";
              extraDomainSettings.ldap_id_use_start_tls = "False";
            };
          };

          # ── Split-horizon DNS ──────────────────────────────
          # The one thing an eval check cannot pin: what Technitium actually
          # does with a Forwarder zone that also holds records. The whole
          # design rests on a name inside an overridden domain that is NOT
          # declared here falling THROUGH to the forwarder rather than being
          # answered NXDOMAIN by the zone.
          router.dns.overrides = [
            {
              name = "nas.example.vmtest";
              value = "10.48.4.20";
            }
            # A registrable apex — under a Primary zone this would blackhole
            # every other name in the domain.
            {
              name = "example.vmtest";
              value = "10.48.4.21";
            }
            {
              # CNAME is illegal at a zone apex, which is what an unrooted
              # override always is.
              name = "alias.example.vmtest";
              type = "ANAME";
              value = "nas.example.vmtest";
            }
            {
              name = "txt.example.vmtest";
              type = "TXT";
              value = "split-horizon-ok";
            }
            {
              # Under the LAN domain, which registerStaticHosts declares as a
              # root — so this also proves records join a declared zone instead
              # of each getting one of their own (and avoids a zone name that
              # starts with an underscore).
              name = "_sip._udp.lan";
              type = "SRV";
              value = "10 5 5060 nas.example.vmtest";
            }
          ];

          router.dns.forwardZones = [
            {
              zone = "corp.vmtest";
              forwarders = [ "127.0.0.1:5354" ];
            }
          ];

          router.reporting.schedules = [
            {
              name = "vmtest";
              frequency = "daily";
              sections = [
                "overview"
                "topBlocked"
                "perGroup"
              ];
            }
          ];
        }

        # Test-only overrides: disko/bootloader are for real hardware.
        {
          disko.enableConfig = lib.mkForce false;
          boot.loader.systemd-boot.enable = lib.mkForce false;
          boot.loader.grub.enable = lib.mkForce false;

          virtualisation = {
            vlans = [
              1
              2
            ]; # eth1 = WAN, eth2 = LAN
            memorySize = 3072;
            cores = 2;
          };
          # jdoe's PRIMARY group (gid 4001) appears in no memberUid anywhere —
          # exactly like Active Directory's Domain Users, which records primary
          # membership in primaryGroupID and never in the group's member list.
          # Students (4100) is supplementary via memberUid. A gr_mem scan would
          # find only Students; os.getgrouplist must return both.
          services.openldap = {
            enable = true;
            urlList = [ "ldap://127.0.0.1:389" ];
            settings.children = {
              "cn=schema".includes = [
                "${pkgs.openldap}/etc/schema/core.ldif"
                "${pkgs.openldap}/etc/schema/cosine.ldif"
                "${pkgs.openldap}/etc/schema/inetorgperson.ldif"
                "${pkgs.openldap}/etc/schema/nis.ldif"
              ];
              "olcDatabase={1}mdb".attrs = {
                objectClass = [
                  "olcDatabaseConfig"
                  "olcMdbConfig"
                ];
                olcDatabase = "{1}mdb";
                olcDbDirectory = "/var/lib/openldap/db";
                olcSuffix = "dc=vmtest";
                olcRootDN = "cn=admin,dc=vmtest";
                olcRootPW = "vmtest";
                olcAccess = [ "{0}to * by * read" ]; # anonymous bind is enough
              };
            };
            declarativeContents."dc=vmtest" = ''
              dn: dc=vmtest
              objectClass: top
              objectClass: dcObject
              objectClass: organization
              o: vmtest
              dc: vmtest

              dn: ou=people,dc=vmtest
              objectClass: top
              objectClass: organizationalUnit
              ou: people

              dn: ou=groups,dc=vmtest
              objectClass: top
              objectClass: organizationalUnit
              ou: groups

              dn: uid=jdoe,ou=people,dc=vmtest
              objectClass: person
              objectClass: posixAccount
              uid: jdoe
              cn: John Doe
              sn: Doe
              gecos: John Doe,Room 1,,,
              uidNumber: 4001
              gidNumber: 4001
              homeDirectory: /home/jdoe
              loginShell: /run/current-system/sw/bin/nologin

              dn: cn=jdoe,ou=groups,dc=vmtest
              objectClass: top
              objectClass: posixGroup
              cn: jdoe
              gidNumber: 4001

              dn: cn=Students,ou=groups,dc=vmtest
              objectClass: top
              objectClass: posixGroup
              cn: Students
              gidNumber: 4100
              memberUid: jdoe
            '';
          };
          # Stand-in "internal DNS server" for the conditional-forwarder test.
          # Hermetic: it is authoritative for corp.vmtest and nothing else, so
          # an answer from it can only have come through the forward zone.
          systemd.services.vmtest-internal-dns = {
            description = "Stand-in internal DNS server (conditional forwarding fixture)";
            wantedBy = [ "multi-user.target" ];
            before = [ "technitium-reconcile.service" ];
            serviceConfig = {
              ExecStart = toString [
                "${pkgs.dnsmasq}/bin/dnsmasq"
                "--keep-in-foreground"
                "--port=5354"
                "--listen-address=127.0.0.1"
                "--bind-interfaces"
                "--no-resolv"
                "--no-hosts"
                "--address=/corp.vmtest/10.9.9.9"
              ];
              Restart = "on-failure";
            };
          };

          environment.systemPackages = [
            pkgs.iproute2
            pkgs.dnsutils
            pkgs.curl
            pkgs.jq
            pkgs.nftables
            mdnsTestResponder
          ];
        }
      ];
    };

  testScript = ''
    import json
    import re

    start_all()
    router.wait_for_unit("multi-user.target")

    with subtest("technitium + reconcile + logd come up"):
        router.wait_for_unit("technitium-dns-server.service")
        router.wait_until_succeeds(
            "curl -s -o /dev/null http://127.0.0.1:5380/api/user/login", timeout=180
        )
        # oneshot with RemainAfterExit: active == reconcile succeeded
        router.wait_for_unit("technitium-reconcile.service", timeout=300)
        router.wait_for_unit("router-logd.service")
        router.wait_until_succeeds("curl -s http://127.0.0.1:8067/healthz | grep -q true")

    with subtest("new sections reach /etc/router/effective.json"):
        eff = json.loads(router.succeed("cat /etc/router/effective.json"))
        assert eff["accessPolicies"]["defaultPolicy"] == "Base", eff["accessPolicies"]
        assert any(h["name"] == "lab-1" for h in eff["hosts"]), eff["hosts"]
        assert eff["reporting"]["retentionDays"] > 0, eff["reporting"]

    with subtest("DHCP reservations render as networkd static leases"):
        unit = router.succeed("cat /etc/systemd/network/40-br-lan.network")
        # Parse the lease sections rather than substring-matching the file:
        # separate `"<mac>" in unit` / `"<ip>" in unit` checks pass even when the
        # two land in DIFFERENT leases, which is the pairing bug this subtest
        # exists to catch. The address also appears elsewhere in the file.
        leases = {}
        for block in unit.split("[DHCPServerStaticLease]")[1:]:
            kv = dict(
                (k.strip(), v.strip())
                for k, v in (
                    line.split("=", 1)
                    for line in block.split("[")[0].splitlines()
                    if "=" in line
                )
            )
            leases[kv["MACAddress"]] = kv["Address"]
        assert leases == {
            "aa:bb:cc:dd:ee:01": "10.48.4.50",
            "aa:bb:cc:dd:ee:02": "10.48.4.60",
            "aa:bb:cc:dd:ee:03": "10.48.4.61",
        }, (leases, unit)

    with subtest("cockpit token + logd tokens are provisioned 0600"):
        for f in [
            "/var/lib/cockpit-router/technitium-token",
            "/var/lib/router-technitium/logd-query.token",
        ]:
            assert router.succeed(f"stat -c %a {f}").strip() == "600", f

    # ── netns LAN clients ────────────────────────────────────
    def add_client(name, ip):
        router.succeed(f"ip netns add {name}")
        router.succeed(f"ip link add veth-{name} type veth peer name vbr-{name}")
        router.succeed(f"ip link set vbr-{name} master br-lan up")
        router.succeed(f"ip link set veth-{name} netns {name}")
        router.succeed(f"ip -n {name} link set lo up")
        router.succeed(f"ip -n {name} addr add {ip}/24 dev veth-{name}")
        router.succeed(f"ip -n {name} link set veth-{name} up")
        router.succeed(f"ip -n {name} route add default via 10.48.4.1")

    router.wait_until_succeeds("ip -4 addr show br-lan | grep -qw 10.48.4.1", timeout=60)
    add_client("kid", "10.48.4.50")      # registry: group Kids → Strict
    add_client("jdoe", "10.48.4.60")     # registry: user jdoe@test (no group)
    add_client("guestpc", "10.48.4.99")  # unregistered → Base (default)

    # A blocked answer is served locally and returns instantly; an UNblocked
    # name has to fail through the (unreachable) forwarders first, so give both
    # room rather than racing a 3s deadline.
    dig = "ip netns exec {ns} dig +time=10 +tries=1 @10.48.4.1 {name}"
    # +short prints the ANSWER section only. Any assertion about the block-page
    # ADDRESS must use it: dig's own "SERVER: 10.48.4.1#53" trailer contains the
    # LAN gateway, so `"10.48.4.1" in out` on full output is true no matter what
    # the server answered.
    dig_short = "ip netns exec {ns} dig +short +time=10 +tries=1 @10.48.4.1 {name}"

    # The Advanced Blocking app attaches an Extended DNS Error to every response
    # it produces, carrying the policy group that matched:
    #   ; EDE: 15 (Blocked): (source=advanced-blocking-app; group=Strict; domain=…)
    # This is what makes the tier assertions specific. A bare "NXDOMAIN in out"
    # cannot tell the app apart from a special-use zone (Technitium 15.4.0 serves
    # test/invalid/local/onion itself, ahead of the app), an authoritative zone,
    # or an upstream answer — which is exactly how the fixtures silently stopped
    # testing anything when they were still *.test.
    def blocked_by(out):
        m = re.search(r"source=advanced-blocking-app; group=([^;)]+)", out)
        return m.group(1) if m else None

    with subtest("host-group tier: Kids device gets Strict (NXDOMAIN)"):
        out = router.wait_until_succeeds(
            dig.format(ns="kid", name="kids-blocked.vmtest"), timeout=60
        )
        assert "status: NXDOMAIN" in out, out
        assert blocked_by(out) == "Strict", out

    with subtest("default tier: unregistered client gets Base (block page address)"):
        out = router.succeed(dig.format(ns="guestpc", name="lan-blocked.vmtest"))
        assert blocked_by(out) == "Base", out
        answer = router.succeed(dig_short.format(ns="guestpc", name="lan-blocked.vmtest"))
        assert answer.strip() == "10.48.4.1", answer

        # Exactly-one-group check: a Strict client must NOT inherit Base's block.
        # No group blocked it, so there is no EDE at all; nothing resolves the
        # name in this hermetic VM, so the server SERVFAILs once its forwarders
        # fail and +short prints nothing.
        out = router.succeed(dig.format(ns="kid", name="lan-blocked.vmtest"))
        assert blocked_by(out) is None, out
        answer = router.succeed(dig_short.format(ns="kid", name="lan-blocked.vmtest"))
        assert answer.strip() == "", answer

    with subtest("IPv6 :53 is dropped so devices cannot escape their policy tier"):
        # The device/group/user tiers are anchored to IPv4 DHCP reservations,
        # so an IPv6-sourced query could only match the catch-all [::]/0 entry
        # and would answer the pinned "kid" client under the DEFAULT policy.
        # Technitium listens on [::]:53, so without the dns_bypass drops this
        # query WOULD be answered — that is precisely the bypass. Give both
        # ends a ULA (nodad keeps it instant) to model a client that has been
        # pointed at an IPv6 resolver by hand.
        router.succeed("ip -6 addr add fd48:4::1/64 dev br-lan nodad")
        router.succeed("ip -n kid -6 addr add fd48:4::50/64 dev veth-kid nodad")
        router.fail("ip netns exec kid dig +time=2 +tries=1 @fd48:4::1 kids-blocked.vmtest")
        # Prove the query actually hit the drop rules rather than failing for
        # some unrelated reason (no route, no address, …).
        dropped = int(
            router.succeed(
                "nft -j list table inet dns_bypass | jq '[.nftables[] | select(.rule) "
                '| .rule | select((.comment // "") | contains("IPv6 DNS")) '
                "| .expr[] | select(.counter) | .counter.packets] | add'"
            ).strip()
        )
        assert dropped > 0, f"IPv6 :53 never matched the dns_bypass drops ({dropped})"

    with subtest("SSSD is the ONLY resolver for the directory identities"):
        router.wait_for_unit("openldap.service")
        router.wait_for_unit("sssd.service")
        router.succeed("sssctl config-check")
        # If these were local accounts the rest of this subtest would prove
        # nothing: /etc/nsswitch.conf puts `files` before `sss`.
        router.fail("grep -q '^jdoe:' /etc/passwd")
        router.fail("grep -q '^Students:' /etc/group")
        nss = router.succeed("cat /etc/nsswitch.conf")
        assert re.search(r"^passwd:.*\bsss\b", nss, re.M), nss
        assert re.search(r"^group:.*\bsss\b", nss, re.M), nss

        router.wait_until_succeeds("getent passwd jdoe", timeout=180)
        router.succeed("getent group Students")
        # Primary group (gidNumber only, in no memberUid) AND supplementary
        # group must both come back — the getgrouplist-vs-gr_mem contract that
        # makes AD's "Domain Users" work.
        groups = router.succeed("id -Gn jdoe").split()
        assert "jdoe" in groups and "Students" in groups, groups

    with subtest("no enumeration: getent with no argument leaks nothing"):
        # This is why directory.json is built from policy references rather than
        # from a user listing. If this ever starts listing jdoe, the sync design
        # rests on a false premise.
        passwd = router.succeed("getent passwd")
        assert not re.search(r"^jdoe:", passwd, re.M), "domain is enumerable"

    with subtest("directory state dir is shared, not hidden under /var/lib/private"):
        # With DynamicUser the state dir would materialize as a symlink into
        # the 0700 root-only /var/lib/private, which no amount of router-data
        # group membership would let router-logd traverse. (Tolerate a
        # concurrent run from the boot timer — the assertions below, not the
        # exit status, are the contract under test.)
        router.succeed("systemctl start router-directory-sync.service || true")
        router.wait_until_succeeds("test -f /var/lib/router-directory/status.json", timeout=90)
        router.succeed("test ! -L /var/lib/router-directory")
        owner = router.succeed("stat -c %U:%G /var/lib/router-directory/status.json").strip()
        assert owner == "router-directory-sync:router-data", owner

    with subtest("the sync resolves exactly the referenced names, through NSS"):
        # The sandbox is AF_UNIX-only with PrivateNetwork=true; if NSS could not
        # reach nsncd/sssd_nss through it, nothing here would resolve.
        router.wait_until_succeeds("systemctl start router-directory-sync.service", timeout=120)
        state = json.loads(router.succeed("cat /var/lib/router-directory/directory.json"))
        assert [u["id"] for u in state["users"]] == ["jdoe"], state
        jdoe = state["users"][0]
        assert jdoe["name"] == "John Doe", jdoe          # GECOS field 1 only
        assert jdoe["email"] == "", jdoe                 # POSIX carries no mail
        assert "Students" in jdoe["groups"], jdoe        # supplementary
        assert "jdoe" in jdoe["groups"], jdoe            # primary, memberUid-less
        assert {"id": "Students", "name": "Students"} in state["groups"], state

        status = json.loads(router.succeed("cat /var/lib/router-directory/status.json"))
        # A dangling reference is a WARNING, not a failure: one typo must not
        # blank the user tier for everybody else.
        assert status["ok"] is True, status
        assert set(status["unresolved"]) == {"ghost", "NoSuchGroup"}, status
        assert router.succeed("stat -c %a /var/lib/router-directory/directory.json").strip() == "640"
        assert router.succeed("stat -c %a /var/lib/router-directory/status.json").strip() == "644"

    with subtest("directory tier activates via the path unit, no manual push"):
        # The atomic rename in _atomic_write is what fires router-policy-push;
        # starting it by hand here would leave that wiring untested.
        # Poll on the GROUP, not on the response code: jdoe reaching Strict is
        # the whole point, and an NXDOMAIN by itself would not prove the
        # directory tier ran.
        router.wait_until_succeeds(
            dig.format(ns="jdoe", name="kids-blocked.vmtest") + " | grep -q 'group=Strict'",
            timeout=90,
        )
        out = router.succeed(dig.format(ns="jdoe", name="kids-blocked.vmtest"))
        assert "status: NXDOMAIN" in out, out
        assert blocked_by(out) == "Strict", out

    with subtest("an empty adminGroup keeps SSSD out of the login path"):
        # Identity is for policy assignment only. The primary control is that
        # sssd runs no PAM responder at all...
        conf = router.succeed("cat /etc/sssd/sssd.conf")
        assert re.search(r"^services\s*=\s*nss\s*$", conf, re.M), conf
        assert re.search(r"^access_provider\s*=\s*deny\s*$", conf, re.M), conf
        # ...and, belt and braces, pam_sss.so is not even wired in.
        for svc in ["sshd", "cockpit", "login", "sudo"]:
            pam = router.succeed(f"cat /etc/pam.d/{svc}")
            assert "pam_sss.so" not in pam, f"{svc}:\n{pam}"

    with subtest("blocked queries land in router-logd with group attribution"):
        token = router.succeed("cat /var/lib/router-technitium/logd-query.token").strip()
        entry = router.wait_until_succeeds(
            f"curl -s -H 'Authorization: Bearer {token}' "
            "'http://127.0.0.1:8067/logs?blocked=1&client=10.48.4.50' "
            "| jq -e '.entries[0]'",
            timeout=120,
        )
        parsed = json.loads(entry)
        assert parsed["host_group"] == "Kids", parsed
        assert parsed["policy"] == "Strict", parsed

        # jdoe reaches Strict only through the DIRECTORY tier, so this also
        # proves router-logd (a DynamicUser) can read the state directory
        # written by router-directory-sync — the /var/lib/private trap.
        entry = router.wait_until_succeeds(
            f"curl -s -H 'Authorization: Bearer {token}' "
            "'http://127.0.0.1:8067/logs?blocked=1&client=10.48.4.60' "
            "| jq -e '.entries[0]'",
            timeout=120,
        )
        parsed = json.loads(entry)
        assert parsed["device"] == "jdoe-laptop", parsed
        assert parsed["policy"] == "Strict", parsed

    with subtest("block page is served with the branded wwwroot"):
        page = router.succeed("ip netns exec guestpc curl -s http://10.48.4.1/")
        assert "VM-TEST Blocked" in page, page[:500]

    with subtest("exception-request portal round-trips"):
        router.succeed(
            "ip netns exec kid curl -s -X POST "
            "-d 'domain=kids-blocked.vmtest&reason=needed for class' "
            "http://10.48.4.1:8067/portal/request-exception | grep -qi 'request submitted'"
        )
        token = router.succeed("cat /var/lib/router-technitium/logd-query.token").strip()
        reqs = json.loads(
            router.succeed(
                f"curl -s -H 'Authorization: Bearer {token}' http://127.0.0.1:8067/portal/requests"
            )
        )["requests"]
        assert any(
            r["domain"] == "kids-blocked.vmtest" and r["device"] == "lab-1" for r in reqs
        ), reqs

        # Approving it is the only path that depends on the store reporting how
        # many rows a statement changed. DuckDB always reports cursor.rowcount
        # as -1 and returns the count as a result set instead, so this would
        # answer {"updated": 0} — and the UI would read the approval as a
        # no-op — if that were ever read back the SQLite way again.
        rid = next(r["id"] for r in reqs if r["domain"] == "kids-blocked.vmtest")
        out = json.loads(
            router.succeed(
                f"curl -s -X POST -H 'Authorization: Bearer {token}' "
                "-d '{\"status\": \"approved\"}' "
                f"http://127.0.0.1:8067/portal/requests/{rid}/status"
            )
        )
        assert out == {"updated": 1}, out
        reqs = json.loads(
            router.succeed(
                f"curl -s -H 'Authorization: Bearer {token}' "
                "http://127.0.0.1:8067/portal/requests"
            )
        )["requests"]
        assert next(r["status"] for r in reqs if r["id"] == rid) == "approved", reqs

    with subtest("a report PDF is generated offline"):
        router.succeed("systemctl start router-report-vmtest.service")
        # `".pdf" in ls` passes on a zero-byte file, or on a stack trace saved
        # under a .pdf name — Typst failing still leaves the name behind. Check
        # the magic bytes and that there is a document's worth of content.
        pdf = router.succeed("ls /var/lib/router-reports/*.pdf").strip().splitlines()[0]
        assert router.succeed(f"head -c4 {pdf}") == "%PDF", pdf
        size = int(router.succeed(f"stat -c %s {pdf}").strip())
        assert size > 1024, f"{pdf} is only {size} bytes"

    with subtest("cockpit is reachable over plain http on the LAN"):
        # Serving the login page over http already worked before this was fixed
        # — that is why the failure looked like "signs in, then bounces back".
        # The bug was WebService.Origins: setting it at all makes it the
        # exclusive allow-list, and an https-only list refuses the WebSocket
        # upgrade that the login POST hands over to. So assert the ORIGIN list,
        # not just that a page renders.
        conf = router.succeed("cat /etc/cockpit/cockpit.conf")
        origins = next(
            (l.split("=", 1)[1] for l in conf.splitlines() if l.startswith("Origins=")), ""
        ).split()
        assert "http://10.48.4.1:9090" in origins, conf
        assert re.search(r"^AllowUnencrypted\s*=\s*true$", conf, re.M | re.I), conf

        # And no https redirect in front of it: cockpit-tls forwards plain HTTP
        # to the http wsinstance only while AllowUnencrypted is set.
        code = router.succeed(
            "curl -sS -o /dev/null -w '%{http_code}' http://10.48.4.1:9090/"
        ).strip()
        assert code == "200", code

    with subtest("cockpit router plugin is installed with the new pages"):
        manifest = "/etc/cockpit/share/cockpit/router/manifest.json"
        router.succeed(f"test -f {manifest}")
        router.succeed(f"grep -q access-policies {manifest}")
        router.succeed(f"grep -q dns.html {manifest}")

    # ── Split-horizon DNS ────────────────────────────────────────────────
    # Queried from a LAN client netns, not the router itself, so the answers
    # are the ones a real client gets through the :53 DNAT.
    with subtest("overrides answer locally"):
        assert router.succeed(
            dig_short.format(ns="guestpc", name="nas.example.vmtest")
        ).strip() == "10.48.4.20"
        # The apex of a domain the router does not own end-to-end.
        assert router.succeed(
            dig_short.format(ns="guestpc", name="example.vmtest")
        ).strip() == "10.48.4.21"
        # ANAME: Technitium resolves the target and answers with its address.
        assert router.succeed(
            dig_short.format(ns="guestpc", name="alias.example.vmtest")
        ).strip() == "10.48.4.20"
        txt = router.succeed(dig_short.format(ns="guestpc", name="txt.example.vmtest TXT"))
        assert "split-horizon-ok" in txt, txt
        srv = router.succeed(dig_short.format(ns="guestpc", name="_sip._udp.lan SRV"))
        assert "5060" in srv and "nas.example.vmtest" in srv, srv

    with subtest("the public horizon survives an override"):
        # THE assertion the whole zone model rests on. A Primary zone would
        # answer this NXDOMAIN authoritatively and silently black-hole every
        # other name in the domain; a Forwarder zone carrying the override
        # sends it upstream instead. Upstream is unreachable in this hermetic
        # VM, so "tried to forward" reads as SERVFAIL — what matters is that
        # the router did NOT claim the name for itself.
        out = router.succeed(dig.format(ns="guestpc", name="www.example.vmtest"))
        assert "NXDOMAIN" not in out, out

        # And the zone really is a forwarder carrying the global upstreams,
        # rather than something that merely behaves like one today.
        token = router.succeed("cat /var/lib/cockpit-router/technitium-token").strip()
        zones = json.loads(
            router.succeed(
                f"curl -sS -H 'Authorization: Bearer {token}' "
                "'http://127.0.0.1:5380/api/zones/list'"
            )
        )["response"]["zones"]
        by_name = {z["name"]: z for z in zones}
        assert by_name["example.vmtest"]["type"] == "Forwarder", zones
        records = json.loads(
            router.succeed(
                f"curl -sS -H 'Authorization: Bearer {token}' "
                "'http://127.0.0.1:5380/api/zones/records/get"
                "?domain=example.vmtest&zone=example.vmtest&listZone=true'"
            )
        )["response"]["records"]
        assert any(r["type"] == "FWD" for r in records), records

    with subtest("a forward zone reaches the internal DNS server"):
        assert router.succeed(
            dig_short.format(ns="guestpc", name="anything.corp.vmtest")
        ).strip() == "10.9.9.9"

    with subtest("static reservations get names and reverse lookups"):
        assert router.succeed(dig_short.format(ns="kid", name="lab-1.lan")).strip() == "10.48.4.50"
        assert "lab-1.lan" in router.succeed(
            "ip netns exec kid dig +short +time=10 +tries=1 @10.48.4.1 -x 10.48.4.50"
        )

    # ── Router Live DNS: adopted hosts + mDNS ─────────────────────────────
    with subtest(
        "an unregistered name under the LAN domain still falls through, not blocked by the app"
    ):
        # Same invariant as "the public horizon survives an override", now for
        # hostZone's apex APP record: a name the Router Live DNS app does not
        # recognize must fall through to hostZone's FWD forwarders (returning
        # null lets Technitium's own ProcessAPPAsync do this), not become an
        # authoritative NXDOMAIN the app itself claims.
        out = router.succeed(dig.format(ns="guestpc", name="nobody-adopted-this-name.lan"))
        assert "NXDOMAIN" not in out, out

    with subtest("a dynamic (non-static-IP) host resolves live, and stops once it's gone"):
        # Not yet ARP-visible: no answer.
        answer = router.succeed(dig_short.format(ns="guestpc", name="dyn-1.lan"))
        assert answer.strip() == "", answer

        router.succeed("ip netns add dynhost")
        router.succeed("ip link add veth-dynhost type veth peer name vbr-dynhost")
        router.succeed("ip link set vbr-dynhost master br-lan up")
        router.succeed("ip link set veth-dynhost netns dynhost")
        router.succeed("ip -n dynhost link set lo up")
        router.succeed("ip -n dynhost link set veth-dynhost address aa:bb:cc:dd:ee:04")
        router.succeed("ip -n dynhost link set veth-dynhost up")
        router.succeed("ip -n dynhost addr add 10.48.4.71/24 dev veth-dynhost")
        # A real ARP exchange, so the router's kernel neighbor table — what
        # NeighborCache polls via `ip -j neigh` — actually learns this MAC <->
        # IP pairing, exactly as it would for a real device joining the LAN.
        router.succeed("ip netns exec dynhost ping -c1 -W2 10.48.4.1")

        router.wait_until_succeeds(
            dig_short.format(ns="guestpc", name="dyn-1.lan") + " | grep -qx 10.48.4.71",
            timeout=60,
        )

        # Remove it from the router's neighbor table directly (deterministic,
        # rather than waiting out the kernel's own ARP aging) and confirm the
        # name stops answering once the next refresh cycle sees it gone —
        # proof this is a live lookup, not a one-time snapshot.
        router.succeed("ip neigh del 10.48.4.71 dev br-lan")
        router.wait_until_succeeds(
            f'test -z "$({dig_short.format(ns="guestpc", name="dyn-1.lan")})"',
            timeout=60,
        )

    with subtest("resolveMdns: local is an authoritative Primary zone carrying the app record"):
        zones = json.loads(
            router.succeed(
                f"curl -sS -H 'Authorization: Bearer {token}' "
                "'http://127.0.0.1:5380/api/zones/list'"
            )
        )["response"]["zones"]
        by_name = {z["name"]: z for z in zones}
        assert by_name["local"]["type"] == "Primary", zones
        records = json.loads(
            router.succeed(
                f"curl -sS -H 'Authorization: Bearer {token}' "
                "'http://127.0.0.1:5380/api/zones/records/get"
                "?domain=local&zone=local&listZone=true'"
            )
        )["response"]["records"]
        assert any(r["type"] == "APP" for r in records), records

    with subtest("resolveMdns: a live mDNS responder resolves by its broadcast name"):
        router.succeed("ip netns add mdnsdev")
        router.succeed("ip link add veth-mdnsdev type veth peer name vbr-mdnsdev")
        router.succeed("ip link set vbr-mdnsdev master br-lan up")
        router.succeed("ip link set veth-mdnsdev netns mdnsdev")
        router.succeed("ip -n mdnsdev link set lo up")
        router.succeed("ip -n mdnsdev addr add 10.48.4.90/24 dev veth-mdnsdev")
        router.succeed("ip -n mdnsdev link set veth-mdnsdev up")
        router.succeed(
            "ip netns exec mdnsdev sh -c "
            "'nohup mdns-test-responder </dev/null >/tmp/mdns-responder.log 2>&1 &'"
        )

        router.wait_until_succeeds(
            dig_short.format(ns="guestpc", name="test-device.local") + " | grep -qx 10.48.4.90",
            timeout=30,
        )

    with subtest("resolveMdns: a name nobody answers for is NXDOMAIN, not a hang"):
        out = router.succeed(dig.format(ns="guestpc", name="nobody-here.local"))
        assert "NXDOMAIN" in out, out

    with subtest("removing an override reaps its zone"):
        # Reconcile is idempotent but it is also the only thing that DELETES;
        # a removal that leaves the zone behind keeps answering forever, which
        # is the failure mode an admin cannot see from the settings file.
        unit = router.succeed("systemctl cat technitium-reconcile.service")
        cmd = next(l for l in unit.splitlines() if l.startswith("ExecStart="))
        binary, _, cfg_path = cmd[len("ExecStart=") :].partition(" --config ")
        router.succeed(
            "jq --arg z nas.example.vmtest "
            "'.localDns.zones |= map(select(.zone != $z))' "
            f"{cfg_path.strip()} > /tmp/reduced.json"
        )
        router.succeed(f"{binary} --config /tmp/reduced.json")
        zones = json.loads(
            router.succeed(
                f"curl -sS -H 'Authorization: Bearer {token}' "
                "'http://127.0.0.1:5380/api/zones/list'"
            )
        )["response"]["zones"]
        assert "nas.example.vmtest" not in {z["name"] for z in zones}, zones
        # The rest of the set is untouched.
        assert "example.vmtest" in {z["name"] for z in zones}, zones

    with subtest("toggling resolveMdns off reaps the local zone"):
        # Mirrors the override-reap test above for the other kind of zone
        # this feature creates: dropping "local" from the desired set (as Nix
        # does when router.dns.technitium.resolveMdns flips to false) must
        # delete the zone, not just stop updating it.
        router.succeed(
            "jq --arg z local "
            "'.localDns.zones |= map(select(.zone != $z))' "
            f"{cfg_path.strip()} > /tmp/reduced2.json"
        )
        router.succeed(f"{binary} --config /tmp/reduced2.json")
        zones = json.loads(
            router.succeed(
                f"curl -sS -H 'Authorization: Bearer {token}' "
                "'http://127.0.0.1:5380/api/zones/list'"
            )
        )["response"]["zones"]
        assert "local" not in {z["name"] for z in zones}, zones
        # The rest of the set (in particular hostZone) is untouched.
        assert "lan" in {z["name"] for z in zones}, zones
  '';
}
