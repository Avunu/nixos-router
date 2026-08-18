# Eval-only regression check for the wireless controllers.
#
# The container stacks themselves cannot be tested without a registry, so this
# pins the parts that are pure configuration and that fail *silently* when they
# regress — which is most of the interesting surface here:
#
#   • DHCP option 43 is the whole adoption story for UniFi. It is contributed
#     from modules/wireless-unifi.nix by merging into a networkd unit that
#     modules/network.nix owns, so an innocuous refactor over there could drop
#     it with nothing to notice.
#   • The MongoDB container's isolation is expressed as the ABSENCE of an
#     nftables forward rule. Absence is exactly what nobody reviews, and it is
#     what covers running an end-of-life 4.4 (the last release without an AVX
#     requirement).
#   • OpenWISP crashes on import if any of four environment variables is missing
#     from any one of five containers, because upstream only ever ships them via
#     a compose env_file shared by every service.
{
  pkgs,
  routerModule,
  baseSettings,
}:
let
  inherit (pkgs) lib;

  evalWith =
    extra:
    (import "${pkgs.path}/nixos/lib/eval-config.nix" {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        routerModule
        (
          { lib, ... }:
          {
            config = lib.mkMerge [
              { router = lib.mkDefault baseSettings; }
              {
                router.wan.interface = "eth1";
                router.lan.interfaces = [ "eth2" ];
                disko.enableConfig = lib.mkForce false;
                boot.loader.systemd-boot.enable = lib.mkForce false;
                boot.loader.grub.enable = lib.mkForce false;
                fileSystems."/" = {
                  device = "/dev/vda";
                  fsType = "ext4";
                };
              }
              extra
            ];
          }
        )
      ];
    }).config;

  off = evalWith { };
  both = evalWith {
    router.wireless.unifi.enable = true;
    router.wireless.openwisp.enable = true;
  };

  lanGW = off.router.lan.address;
  containers = both.virtualisation.oci-containers.containers;
  ruleset = both.networking.nftables.ruleset;
  rulesetOff = off.networking.nftables.ruleset;

  owIF = both.router._wirelessInternal.openwisp.interface;
  wlIF = both.router._wirelessInternal.unifi.interface;

  dhcpOf = c: c.systemd.network.networks."40-br-lan".dhcpServerConfig or { };

  # The five containers built from a Django image. Every one of them imports
  # openwisp.settings, which is where the crash-on-missing-var lives.
  djangoContainers = [
    "openwisp-dashboard"
    "openwisp-api"
    "openwisp-websocket"
    "openwisp-celery"
    "openwisp-celerybeat"
  ];
  requiredDjangoEnv = [
    # celery.py calls .lower() on this unconditionally; it is defined only in
    # the dashboard image, so api and websocket die on import without it.
    "USE_OPENWISP_CELERY_NETWORK"
    # Read with bare os.environ[...] but defined only in the nginx image.
    "SSL_CERT_MODE"
    "DASHBOARD_DOMAIN"
    "API_DOMAIN"
  ];

  missingEnv = lib.concatMap (
    name:
    let
      env = containers.${name}.environment or { };
    in
    map (v: "${name}:${v}") (lib.filter (v: !(env ? ${v})) requiredDjangoEnv)
  ) djangoContainers;

  # Host ports something else in this repo already binds. Cross-checked against
  # every module: sshd, Technitium (:53 and its :5380 console), the networkd
  # DHCP server, the Technitium block page on :80/:443, Avahi, router-logd and
  # Cockpit.
  reservedHostPorts = [
    22
    53
    67
    80
    443
    5353
    5380
    8067
    9090
  ];
  publishedPorts = lib.concatMap (
    c: map (p: lib.toInt (lib.elemAt (lib.splitString ":" p) 1)) (c.ports or [ ])
  ) (lib.attrValues containers);
  collidingPorts = lib.filter (p: lib.elem p reservedHostPorts) publishedPorts;

  mongo = containers.unifi-mongo;

  checks = [
    {
      name = "unifi-emits-dhcp-option-43";
      ok = (dhcpOf both).SendVendorOption or null == "1:ipv4address:${lanGW}";
      detail = ''
        want SendVendorOption = "1:ipv4address:${lanGW}" on 40-br-lan, got
        ${builtins.toJSON ((dhcpOf both).SendVendorOption or null)}. Without it,
        factory-default APs have no way to find the controller.
      '';
    }
    {
      # The option is meaningless with no controller to point at, and would be
      # actively misleading — APs would keep informing into a void.
      name = "no-dhcp-option-43-without-unifi";
      ok = !((dhcpOf off) ? SendVendorOption);
      detail = "option 43 is advertised even though router.wireless.unifi.enable is false";
    }
    {
      name = "openwisp-opens-datastores-to-its-bridge";
      ok = lib.hasInfix ''iifname "${owIF}" tcp dport { 5432, 6379 } accept'' ruleset;
      detail = "the OpenWISP containers cannot reach PostgreSQL/Redis on the bridge gateway";
    }
    {
      name = "openwisp-can-reach-lan-for-device-ssh";
      ok = lib.hasInfix ''iifname "${owIF}" oifname "br-lan" accept'' ruleset;
      detail = "celery cannot SSH to the access points it manages";
    }
    {
      # netavark's DNAT lives in its own table and cannot override this chain's
      # drop policy, so without this the dashboard is unreachable from the LAN
      # even though the port is published.
      name = "published-ports-reachable-from-lan";
      ok = lib.hasInfix ''iifname "br-lan" oifname "${owIF}" ct status dnat accept'' ruleset;
      detail = "DNAT'd traffic to a published container port is dropped by the forward chain";
    }
    {
      # A published port reached from the router itself is DNAT'd in the output
      # hook, so the reply arrives on the bridge with an ephemeral destination
      # port that matches no other rule.
      name = "container-replies-to-the-router-accepted";
      ok = lib.hasInfix ''iifname "${owIF}" ct state { established, related } accept'' ruleset;
      detail = "the input chain drops container replies to router-initiated connections";
    }
    {
      name = "no-container-rules-when-disabled";
      ok = !(lib.hasInfix owIF rulesetOff);
      detail = "the OpenWISP bridge appears in the ruleset with the controller disabled";
    }
    {
      # This is the control that makes an end-of-life MongoDB acceptable. If a
      # rule for this interface ever appears, the database becomes reachable
      # from the LAN and the risk assessment behind pinning 4.4 no longer holds.
      name = "unifi-database-has-no-forward-rule";
      ok = !(lib.hasInfix ''"${wlIF}"'' ruleset);
      detail = ''
        the UniFi database bridge ${wlIF} is named in the nftables ruleset. Its
        isolation is the absence of any rule — see modules/firewall.nix.
      '';
    }
    {
      name = "unifi-database-publishes-no-ports";
      ok = (mongo.ports or [ ]) == [ ];
      detail = "the MongoDB container publishes ${builtins.toJSON (mongo.ports or [ ])}";
    }
    {
      name = "unifi-database-image-is-pinned";
      ok = !(lib.hasSuffix ":latest" mongo.image) && lib.hasInfix ":4.4" mongo.image;
      detail = ''
        MongoDB image is ${mongo.image}. It must stay on a pinned 4.4 tag: 5.0+
        requires AVX, and a newer major refuses to start on an existing data
        directory, which a floating tag would make unrecoverable.
      '';
    }
    {
      name = "unifi-database-excluded-from-auto-update";
      ok = !((mongo.labels or { }) ? "io.containers.autoupdate");
      detail = "the MongoDB container carries an auto-update label; a major bump would brick it";
    }
    {
      # The images run as uid 1001 but a named podman volume is created
      # root-owned, so without `:U` the dashboard dies in collectstatic with
      # EACCES on /opt/openwisp/static and takes its startup with it.
      name = "writable-volumes-are-chowned-to-the-container-user";
      ok =
        let
          writers = [
            "openwisp-dashboard"
            "openwisp-api"
            "openwisp-celery"
          ];
          rw = lib.concatMap (
            n: lib.filter (v: !(lib.hasSuffix ":ro" v)) (containers.${n}.volumes or [ ])
          ) writers;
        in
        rw != [ ] && lib.all (v: lib.hasSuffix ":U" v) rw;
      detail = ''
        every read-write volume on the dashboard/api/celery containers must end
        in :U so podman chowns it to uid 1001; without it collectstatic fails
        with EACCES and the container exits under `set -e`
      '';
    }
    {
      # oci-containers' dependsOn emits Requires= as well as After=, and
      # Requires= propagates failure — one container exiting non-zero stopped
      # the whole stack and held it in a restart cycle.
      name = "container-units-are-not-coupled-by-requires";
      ok =
        let
          units = map (n: "podman-openwisp-${n}") [
            "dashboard"
            "api"
            "websocket"
            "celery"
            "celerybeat"
            "nginx"
          ];
          reqs = lib.concatMap (u: both.systemd.services.${u}.requires or [ ]) units;
        in
        !(lib.any (r: lib.hasPrefix "podman-openwisp-" r) reqs);
      detail = ''
        a container unit Requires= another container unit, so one crash will
        stop the rest of the stack instead of letting it retry
      '';
    }
    {
      name = "openwisp-env-complete-on-every-django-container";
      ok = missingEnv == [ ];
      detail = ''
        missing: ${lib.concatStringsSep ", " missingEnv}. These must be on ALL
        five Django containers — upstream only gets away with it because compose
        shares one env_file.
      '';
    }
    {
      # Identical values make nginx log "conflicting server name ... ignored"
      # and silently serve the dashboard URL from the API application.
      name = "openwisp-dashboard-and-api-domains-differ";
      ok =
        containers.openwisp-dashboard.environment.DASHBOARD_DOMAIN
        != containers.openwisp-dashboard.environment.API_DOMAIN;
      detail = "DASHBOARD_DOMAIN and API_DOMAIN are the same host";
    }
    {
      # Never rely on the ROOT_DOMAIN fallback: it becomes "." for a parent with
      # no registered domain, and then every request is a 400 DisallowedHost.
      name = "openwisp-allowed-hosts-set-explicitly";
      ok = containers.openwisp-dashboard.environment ? DJANGO_ALLOWED_HOSTS;
      detail = "DJANGO_ALLOWED_HOSTS is unset, so OpenWISP derives it from the public suffix list";
    }
    {
      name = "no-published-port-collides-with-the-router";
      ok = collidingPorts == [ ];
      detail = "published ports collide with router services: ${builtins.toJSON collidingPorts}";
    }
    {
      name = "dns-records-published-for-both-controllers";
      ok = (lib.length both.router._localDnsRecords) >= 3;
      detail = ''
        want the unifi record plus the OpenWISP dashboard and api records, got
        ${builtins.toJSON (map (r: r.name) both.router._localDnsRecords)}
      '';
    }
    {
      name = "both-modes-instantiate";
      ok =
        builtins.isString off.system.build.toplevel.drvPath
        && builtins.isString both.system.build.toplevel.drvPath;
      detail = "one of the two system closures does not instantiate";
    }
  ];

  failures = lib.filter (c: !c.ok) checks;
in
pkgs.runCommand "router-wireless-eval" { } (
  if failures == [ ] then
    "touch $out"
  else
    ''
      echo "wireless controller configuration regressed:" >&2
      ${lib.concatMapStringsSep "\n" (f: ''
        echo "  FAIL ${f.name}" >&2
        echo "       ${f.detail}" >&2
      '') failures}
      exit 1
    ''
)
