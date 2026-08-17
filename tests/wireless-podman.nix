# NixOS VM test for the container substrate the wireless controllers sit on.
#
# The controllers themselves cannot be tested here — their images come from a
# registry the sandbox cannot reach — so this exercises the plumbing the module
# generates, using one tiny locally-built image in their place. That plumbing is
# where the real risk is:
#
#   • the netavark network definition dropped into /etc/containers/networks,
#     which has to produce the pinned bridge interface and the static IPs the
#     nftables rules and the --add-host entries assume;
#   • reaching the router's own PostgreSQL/Redis across that bridge, which is
#     how the OpenWISP containers get to their datastores and which the drop
#     policy in the input chain would otherwise block;
#   • a port published on the LAN address;
#   • and — the reason this test exists at all — all of the above surviving an
#     nftables reload. The router's ruleset is monolithic and flushes on load,
#     which destroys netavark's own table. `nixos-rebuild switch` RELOADS the
#     nftables unit rather than restarting it, so the `partOf` binding used for
#     miniupnpd does not fire; modules/firewall.nix uses ReloadPropagatedFrom
#     for this, and nothing but an end-to-end test can confirm it works.
{
  pkgs,
  routerModule,
  baseSettings,
}:
let
  inherit (pkgs) lib;

  # Stands in for the OpenWISP containers: serves one known string over HTTP so
  # a published port can be probed, and carries clients for reaching back to the
  # host's datastores. redis-cli rather than busybox's nc for the round trip —
  # busybox nc tears the connection down when stdin reaches EOF, so it can prove
  # a port accepts connections but not that anything answers on it.
  probeImage = pkgs.dockerTools.buildImage {
    name = "localhost/router-wireless-probe";
    tag = "test";
    copyToRoot = pkgs.buildEnv {
      name = "router-wireless-probe-root";
      paths = [
        pkgs.busybox
        pkgs.redis
      ];
    };
    config.Cmd = [
      "/bin/sh"
      "-c"
      "mkdir -p /www && echo wireless-probe-ok > /www/index.html && exec /bin/httpd -f -p 80 -h /www"
    ];
  };

  openwispContainers = [
    "openwisp-dashboard"
    "openwisp-api"
    "openwisp-websocket"
    "openwisp-celery"
    "openwisp-celerybeat"
    "openwisp-nginx"
  ];
in
pkgs.testers.runNixOSTest {
  name = "router-wireless-podman";

  nodes.router =
    { lib, ... }:
    {
      imports = [ routerModule ];

      router = lib.mkMerge [
        (lib.mkDefault baseSettings)
        {
          wan.interface = "eth1";
          lan.interfaces = [ "eth2" ];
          # Out of scope here, and it would add a slow service plus a :53
          # listener to a test that is only about containers.
          dns.technitium.enable = lib.mkForce false;
          suricata.enable = lib.mkForce false;
          # Brings up the openwisp network definition, the firewall rules, and
          # the native PostgreSQL and Redis. The containers it also declares are
          # neutralised below.
          wireless.openwisp.enable = true;
        }
      ];

      disko.enableConfig = lib.mkForce false;
      boot.loader.systemd-boot.enable = lib.mkForce false;
      boot.loader.grub.enable = lib.mkForce false;

      # The real images are unreachable from the build sandbox. Keep every unit
      # the module declares (so its ordering and network wiring are still
      # evaluated) but never start them, and add the local probe in their place.
      virtualisation.oci-containers.containers =
        lib.genAttrs openwispContainers (_: {
          autoStart = lib.mkForce false;
        })
        // {
          wireless-probe = {
            image = "localhost/router-wireless-probe:test";
            imageFile = probeImage;
            networks = [ "openwisp" ];
            extraOptions = [ "--ip=10.89.0.50" ];
            ports = [ "${baseSettings.lan.address}:8081:80" ];
          };
        };

      # curl is in neither NixOS' corePackages nor defaultPackages, and
      # modules/system.nix strips the latter anyway — so it has to be asked for.
      environment.systemPackages = [ pkgs.curl ];

      virtualisation = {
        memorySize = 3072;
        cores = 2;
        diskSize = 4096;
      };
    };

  testScript = ''
    router.wait_for_unit("multi-user.target")

    with subtest("the netavark network definition produces the pinned bridge"):
        router.wait_for_unit("podman-wireless-probe.service")
        # network_interface in the generated JSON, which the nftables rules name.
        router.wait_until_succeeds("ip -4 addr show br-openwisp | grep -q 10.89.0.1", timeout=60)
        router.succeed("podman inspect wireless-probe | grep -q 10.89.0.50")

    with subtest("the router's datastores are reachable across the bridge"):
        # These bind the bridge gateway, which only exists because networkd
        # creates the bridge ahead of podman — without that they fail outright.
        router.wait_for_unit("redis-openwisp.service")
        router.wait_for_unit("postgresql.service")

        # Reachability first, so a failure below distinguishes "the firewall
        # dropped it" from "the protocol exchange did not complete".
        router.wait_until_succeeds(
            "podman exec wireless-probe sh -c 'nc -w 3 10.89.0.1 6379 </dev/null'",
            timeout=60,
        )
        router.succeed("podman exec wireless-probe sh -c 'nc -w 3 10.89.0.1 5432 </dev/null'")

        # Then a real round trip, authenticated — Redis' protected mode accepts
        # the connection above but refuses every command from a non-loopback
        # address unless a password is set. The containers use the same one via
        # REDIS_PASS.
        router.succeed(
            "pass=$(cat /var/lib/router-wireless/redis.pass);"
            " podman exec wireless-probe redis-cli -h 10.89.0.1 -a \"$pass\" ping"
            " | grep -q PONG"
        )

    with subtest("a port published on the LAN address answers"):
        # Deliberately no `podman network reload` first — this has to hold from
        # a cold boot, on the rules netavark installed when the container
        # started. Reloading here would mask a broken boot-time state and make
        # the reload subtest below prove nothing.
        router.wait_until_succeeds(
            "curl -sf http://${baseSettings.lan.address}:8081/ | grep -q wireless-probe-ok",
            timeout=60,
        )

    with subtest("published ports and egress survive an nftables reload"):
        # This is what a `nixos-rebuild switch` does to the ruleset: reload, not
        # restart. The reload flushes every table, netavark's included.
        router.succeed("systemctl reload nftables.service")
        router.wait_for_unit("podman-network-reload.service")
        router.wait_until_succeeds(
            "curl -sf http://${baseSettings.lan.address}:8081/ | grep -q wireless-probe-ok",
            timeout=60,
        )
        router.succeed(
            "pass=$(cat /var/lib/router-wireless/redis.pass);"
            " podman exec wireless-probe redis-cli -h 10.89.0.1 -a \"$pass\" ping"
            " | grep -q PONG"
        )

    with subtest("the UniFi database bridge is absent from the ruleset"):
        # Its isolation is the absence of a forward rule; assert the ruleset that
        # is actually loaded, not just the generated string.
        router.fail("nft list ruleset | grep -q '\"br-unifi\"'")
  '';
}
