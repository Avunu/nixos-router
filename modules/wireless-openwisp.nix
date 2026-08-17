# ── OpenWISP (core) ───────────────────────────────────────────────────────────
# Six containers on their own podman bridge, backed by the router's native
# PostgreSQL (with PostGIS) and Redis:
#
#   dashboard   the admin UI, and the ONLY container that runs migrations
#   api         the device-facing controller API
#   websocket   ASGI/daphne, for live device state
#   celery      background tasks, incl. the SSH connections to devices
#   celerybeat  the periodic-task scheduler
#   nginx       TLS termination and static/media serving; the dashboard and api
#               containers speak the uwsgi binary protocol, not HTTP, so this
#               is not an optional layer that another proxy could replace
#
# Left out deliberately: monitoring (and its InfluxDB), RADIUS, firmware
# upgrades, network topology, the management OpenVPN and Postfix. None are
# needed to configure APs sitting on the router's own LAN.
#
# Two upstream behaviours dominate the shape of this file:
#
#   1. EVERY Django container gets the SAME environment attrset. This is not
#      tidiness — openwisp/__init__.py imports celery.py in every process, and
#      celery.py calls .lower() on USE_OPENWISP_CELERY_NETWORK, which is defined
#      only in the dashboard image. Omit it from api or websocket and they die
#      with AttributeError on import. SSL_CERT_MODE, DASHBOARD_DOMAIN and
#      API_DOMAIN are the mirror image: read with bare os.environ[...] but
#      defined only in the nginx image. Upstream's compose only works because
#      env_file is shared by every service.
#
#   2. The dashboard and api hostnames must differ AND their parent must be a
#      real public suffix. OpenWISP derives its session/CSRF cookie domain from
#      the registered domain of DASHBOARD_DOMAIN; for `.lan` that comes back
#      empty and every request fails. See the `domain` option in
#      modules/wireless.nix.
{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  cfg = config.router;
  wcfg = cfg.wireless.openwisp;
  w = cfg._wirelessInternal;
  inherit (config.router._internal) lanGW;

  ip = w.openwisp.ip;
  gw = w.openwisp.gateway;

  # Fixed addresses in place of aardvark-dns, which cannot run here: it would
  # bind <gateway>:53 and Technitium already owns 0.0.0.0:53.
  addr = {
    dashboard = ip 2;
    api = ip 3;
    websocket = ip 4;
    celery = ip 5;
    celerybeat = ip 6;
    nginx = ip 7;
  };

  dashboardDomain = "dashboard.${wcfg.domain}";
  apiDomain = "api.${wcfg.domain}";

  # The names the stack hardcodes. `*.internal` resolve to nginx, which is what
  # carries those aliases in upstream's compose network.
  addHosts = [
    "--add-host=dashboard:${addr.dashboard}"
    "--add-host=api:${addr.api}"
    "--add-host=websocket:${addr.websocket}"
    "--add-host=dashboard.internal:${addr.nginx}"
    "--add-host=api.internal:${addr.nginx}"
  ];

  image = name: "${wcfg.image}/openwisp-${name}:${wcfg.version}";

  # Shared by all five Django-image containers. See note 1 in the header before
  # moving anything out of here into a per-container set.
  sharedEnv = {
    DASHBOARD_DOMAIN = dashboardDomain;
    API_DOMAIN = apiDomain;
    # Never rely on the ROOT_DOMAIN fallback: when the parent has no registered
    # domain this silently becomes "." and every request is a 400.
    DJANGO_ALLOWED_HOSTS = ".${wcfg.domain},${lanGW},localhost";
    # certbot cannot work on a LAN, and `External` would force the port out of
    # the CSRF trusted origins and break login on a non-standard port.
    SSL_CERT_MODE = "SelfSigned";
    NGINX_PORT = toString wcfg.httpPort;
    NGINX_SSL_PORT = toString wcfg.httpsPort;
    TZ = cfg.timeZone;

    DASHBOARD_APP_SERVICE = "dashboard";
    DASHBOARD_APP_PORT = "8000";
    API_APP_SERVICE = "api";
    API_APP_PORT = "8001";
    WEBSOCKET_APP_SERVICE = "websocket";
    WEBSOCKET_APP_PORT = "8002";

    # No image default; an empty value makes the uwsgi ini envsubst produce a
    # broken config rather than fail loudly.
    UWSGI_PROCESSES = "2";
    UWSGI_THREADS = "2";
    UWSGI_LISTEN = "100";

    USE_OPENWISP_MONITORING = "False";
    USE_OPENWISP_RADIUS = "False";
    USE_OPENWISP_FIRMWARE = "False";
    USE_OPENWISP_TOPOLOGY = "False";
    # Keep this True: the celery container starts that worker itself, and it is
    # the queue the device SSH tasks are routed to. It must also be *present* on
    # api and websocket — see note 1.
    USE_OPENWISP_CELERY_NETWORK = "True";
    # Off by default rather than upstream's on: this router should not report
    # usage to openwisp.io, and the geocoding check makes an outbound ArcGIS
    # call on every dashboard start that stalls when the WAN is down.
    METRIC_COLLECTION = "False";
    OPENWISP_GEOCODING_CHECK = "False";
    # tldextract fetches the Public Suffix List with NO timeout by default, and
    # the container filesystem is recreated on every start so its cache never
    # survives. A blackholed route would otherwise hang startup indefinitely.
    TLDEXTRACT_CACHE_TIMEOUT = "2";

    # Empty disables the whole CA/certificate/VPN/template bootstrap. The
    # default SSH credentials and the "SSH Keys" template still get created,
    # which is what LAN-attached APs actually need.
    VPN_DOMAIN = "";

    DB_HOST = gw;
    DB_PORT = "5432";
    DB_NAME = wcfg.database.name;
    DB_USER = wcfg.database.user;

    REDIS_HOST = gw;
    REDIS_PORT = "6379";

    # Postfix is not deployed. The image default routes mail through celery to a
    # container that does not exist, so every notification would block for
    # EMAIL_TIMEOUT and then retry forever. `console` keeps password-reset links
    # recoverable from the journal, which `dummy` would not.
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend";
    EMAIL_DJANGO_DEFAULT = "openwisp@${wcfg.domain}";
  };

  mkDjangoContainer =
    {
      name,
      imageName,
      extraEnv ? { },
      volumes ? [ ],
      dependsOn ? [ ],
    }:
    {
      inherit dependsOn volumes;
      image = image imageName;
      pull = "missing";
      labels."io.containers.autoupdate" = mkIf cfg.wireless.autoUpdate.enable "registry";
      networks = [ "openwisp" ];
      extraOptions = [ "--ip=${addr.${name}}" ] ++ addHosts;
      environment = sharedEnv // extraEnv;
      environmentFiles = [ "${w.stateDir}/openwisp.env" ];
    };

  mediaVolumes = [
    "openwisp_media:/opt/openwisp/media"
    "openwisp_private_storage:/opt/openwisp/private"
  ];

  # Runs as the postgres superuser after the stock setup unit has created the
  # database and role. Covers the two things nixpkgs cannot express:
  #
  #   • CREATE EXTENSION postgis. No OpenWISP migration does this — Django's
  #     GIS backend does it in prepare_database() — and PostGIS is not a trusted
  #     extension, so it needs superuser. Creating it here makes Django's
  #     "does it already exist" probe short-circuit, so the app role never needs
  #     elevated rights. There is no services.postgresql.ensureExtensions.
  #
  #   • A password. ensureUsers creates a peer-auth-only role with none, and the
  #     containers connect over TCP.
  postgresSetup = pkgs.writeShellScript "openwisp-postgres-setup" ''
    set -euo pipefail
    psql -v ON_ERROR_STOP=1 -d ${wcfg.database.name} \
      -c 'CREATE EXTENSION IF NOT EXISTS postgis'
    # The password is hex, so single-quoting it is safe.
    psql -v ON_ERROR_STOP=1 -d postgres \
      -c "ALTER ROLE \"${wcfg.database.user}\" WITH PASSWORD '$(cat "$CREDENTIALS_DIRECTORY/db-pass")'"
  '';
in
mkIf wcfg.enable {
  # ── Native datastores ─────────────────────────────────
  services.postgresql = {
    enable = true;
    extensions = ps: [ ps.postgis ];
    ensureDatabases = [ wcfg.database.name ];
    ensureUsers = [
      {
        name = wcfg.database.user;
        ensureDBOwnership = true;
      }
    ];
    # mkForce because the module sets this unconditionally from enableTCPIP,
    # whose "on" value is "*" — that would bind the WAN interface too.
    settings.listen_addresses = mkForce "127.0.0.1,${gw}";
    # Added rules are inserted above the module's defaults.
    authentication = ''
      host ${wcfg.database.name} ${wcfg.database.user} ${w.openwisp.subnet} scram-sha-256
    '';
  };

  services.redis.servers.openwisp = {
    enable = true;
    # Both are required: a NAMED redis server defaults to port 0 (unix socket
    # only) and to binding 127.0.0.1, neither of which a container can use.
    port = 6379;
    bind = "127.0.0.1 ${gw}";
    # Not optional. Redis' protected mode accepts the TCP connection but
    # refuses every command from a non-loopback address when no password is
    # set, so without this the containers connect and then fail on their first
    # request. It is also simply correct: the bridge is shared by six
    # containers, and OpenWISP keeps its user sessions in here.
    requirePassFile = "${w.stateDir}/redis.pass";
  };

  systemd.services = {
    # Both datastores bind the container bridge's gateway address, which does
    # not exist until networkd has configured the bridge. Without this they
    # fail outright at boot — and they cannot simply be ordered after the
    # containers, since the containers depend on them.
    postgresql = {
      after = [ "router-wireless-bridges.service" ];
      requires = [ "router-wireless-bridges.service" ];
    };
    redis-openwisp = {
      after = [
        "router-wireless-bridges.service"
        # requirePassFile is read at start, so the secret has to exist first.
        "router-wireless-secrets.service"
      ];
      requires = [
        "router-wireless-bridges.service"
        "router-wireless-secrets.service"
      ];
    };

    openwisp-postgres-setup = {
      description = "Provision the OpenWISP PostgreSQL database";
      after = [
        "postgresql-setup.service"
        "router-wireless-secrets.service"
      ];
      requires = [
        "postgresql-setup.service"
        "router-wireless-secrets.service"
      ];
      wantedBy = [ "multi-user.target" ];
      path = [ config.services.postgresql.finalPackage ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        User = "postgres";
        Group = "postgres";
        LoadCredential = [ "db-pass:${w.stateDir}/openwisp-db.pass" ];
        ExecStart = postgresSetup;
      };
    };
  }
  # Every container needs the generated secrets and the datastores; the
  # dependsOn graph on the containers themselves only covers
  # container-to-container ordering.
  // listToAttrs (
    map
      (
        n:
        nameValuePair "podman-openwisp-${n}" {
          after = [
            "router-wireless-secrets.service"
            "openwisp-postgres-setup.service"
            "redis-openwisp.service"
          ];
          requires = [ "router-wireless-secrets.service" ];
        }
      )
      [
        "dashboard"
        "api"
        "websocket"
        "celery"
        "celerybeat"
        "nginx"
      ]
  );

  # ── Containers ────────────────────────────────────────
  virtualisation.oci-containers.containers = {
    openwisp-dashboard = mkDjangoContainer {
      name = "dashboard";
      imageName = "dashboard";
      volumes = [
        "openwisp_static:/opt/openwisp/static"
        "openwisp_ssh:/home/openwisp/.ssh"
      ]
      ++ mediaVolumes;
    };

    openwisp-api = mkDjangoContainer {
      name = "api";
      imageName = "api";
      dependsOn = [ "openwisp-dashboard" ];
      volumes = mediaVolumes;
    };

    openwisp-websocket = mkDjangoContainer {
      name = "websocket";
      imageName = "websocket";
      dependsOn = [ "openwisp-dashboard" ];
    };

    # Same image as the dashboard; MODULE_NAME selects the role.
    openwisp-celery = mkDjangoContainer {
      name = "celery";
      imageName = "dashboard";
      dependsOn = [ "openwisp-dashboard" ];
      extraEnv.MODULE_NAME = "celery";
      # The SSH key is what this container uses to reach devices, so it needs
      # the same volume the dashboard generated it into.
      volumes = [ "openwisp_ssh:/home/openwisp/.ssh" ] ++ mediaVolumes;
    };

    openwisp-celerybeat = mkDjangoContainer {
      name = "celerybeat";
      imageName = "dashboard";
      dependsOn = [ "openwisp-dashboard" ];
      extraEnv.MODULE_NAME = "celerybeat";
    };

    openwisp-nginx = {
      image = image "nginx";
      pull = "missing";
      labels."io.containers.autoupdate" = mkIf cfg.wireless.autoUpdate.enable "registry";
      networks = [ "openwisp" ];
      # nginx resolves its upstreams at config-parse time with no `resolver`
      # directive, so it exits outright if a name does not resolve. --add-host
      # makes that static, but the ordering below still avoids a pointless
      # restart cycle on a cold boot.
      dependsOn = [
        "openwisp-dashboard"
        "openwisp-api"
        "openwisp-websocket"
      ];
      extraOptions = [ "--ip=${addr.nginx}" ] ++ addHosts;
      # Published on the LAN address only, so nothing is offered on the WAN.
      ports = [
        "${lanGW}:${toString wcfg.httpPort}:80"
        "${lanGW}:${toString wcfg.httpsPort}:443"
      ];
      environment = sharedEnv // {
        # Leaving this at the image default would serve the admin UI over plain
        # HTTP as well; the redirect vhost is port-aware, so HTTPS-only works.
        NGINX_HTTP_ALLOW = "False";
        # The `@deny` fallback in the upstream template redirects without the
        # port, so restricting this would break the redirect. Keep it open and
        # rely on the router's own firewall.
        NGINX_HTTPS_ALLOWED_IPS = "all";
      };
      volumes = [
        "openwisp_static:/opt/openwisp/public/static:ro"
        "openwisp_media:/opt/openwisp/public/media:ro"
        "openwisp_private_storage:/opt/openwisp/public/private:ro"
        "openwisp_certs:/etc/letsencrypt"
      ];
    };
  };

  # Both hostnames resolve to the router's LAN address, where nginx publishes.
  router._localDnsRecords = [
    {
      zone = wcfg.domain;
      name = dashboardDomain;
      address = lanGW;
    }
    {
      zone = wcfg.domain;
      name = apiDomain;
      address = lanGW;
    }
  ];
}
