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
#   • a report service produces a PDF offline (Typst).
{
  pkgs,
  routerModule,
  baseSettings,
}:
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
          ];

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
          environment.systemPackages = [
            pkgs.iproute2
            pkgs.dnsutils
            pkgs.curl
            pkgs.jq
            pkgs.nftables
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
        assert "DHCPServerStaticLease" in unit, unit
        assert "aa:bb:cc:dd:ee:01" in unit and "10.48.4.50" in unit, unit

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
        assert "jdoe" not in router.succeed("getent passwd"), "domain is enumerable"

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

    with subtest("a report PDF is generated offline"):
        router.succeed("systemctl start router-report-vmtest.service")
        out = router.succeed("ls /var/lib/router-reports/")
        assert ".pdf" in out, out

    with subtest("cockpit router plugin is installed with the new pages"):
        manifest = "/etc/cockpit/share/cockpit/router/manifest.json"
        router.succeed(f"test -f {manifest}")
        router.succeed(f"grep -q access-policies {manifest}")
  '';
}
