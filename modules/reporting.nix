# ── Reporting module ───────────────────────────────────────────────────────────
# The query-log store and the scheduled-report machinery:
#
#   • router-logd — long-running daemon owning the DuckDB query-log database
#     (DuckDB locks the file exclusively, so ALL reads/writes go through its
#     localhost HTTP API). Ingests Technitium Log Exporter batches, enriches
#     them with device/group/policy attribution, serves log search + SQL
#     aggregates to Cockpit and the report generator, handles the block-page
#     exception-request portal, and prunes by retentionDays. Always on while
#     Technitium is enabled — dashboards and the portal depend on it.
#
#   • router-report-<name> timers — one per reporting.schedules entry; each
#     renders a Typst PDF (+ CSV) into /var/lib/router-reports and optionally
#     emails it via the Cloudflare Email Sending API.
{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  cfg = config.router;
  rcfg = cfg.reporting;

  technitiumStateDir = "/var/lib/router-technitium";

  onCalendarFor =
    schedule:
    {
      daily = "*-*-* ${schedule.time}:00";
      weekly = "${schedule.dayOfWeek} *-*-* ${schedule.time}:00";
      monthly = "*-*-01 ${schedule.time}:00";
    }
    .${schedule.frequency};

  scheduleType = types.submodule {
    options = {
      name = mkOption {
        type = types.strMatching "[A-Za-z0-9_-]+";
        description = "Schedule name (unique; used in unit and file names).";
      };
      frequency = mkOption {
        type = types.enum [
          "daily"
          "weekly"
          "monthly"
        ];
        default = "weekly";
        description = "Report cadence.";
      };
      dayOfWeek = mkOption {
        type = types.enum [
          "Mon"
          "Tue"
          "Wed"
          "Thu"
          "Fri"
          "Sat"
          "Sun"
        ];
        default = "Mon";
        description = "Day of week (weekly frequency only).";
      };
      time = mkOption {
        type = types.strMatching "[0-2][0-9]:[0-5][0-9]";
        default = "06:00";
        description = "Time of day (HH:MM, local time).";
      };
      recipients = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Email recipients; empty = generate the PDF only, no delivery.";
      };
      sections = mkOption {
        type = types.listOf (
          types.enum [
            "overview"
            "topDomains"
            "topBlocked"
            "perGroup"
            "perDevice"
            "perUser"
          ]
        );
        default = [
          "overview"
          "topDomains"
          "topBlocked"
          "perGroup"
        ];
        description = "Report sections to include.";
      };
      groups = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Restrict group breakdowns to these host groups (empty = all).";
      };
    };
  };
in
{
  options.router.reporting = {
    enable = mkOption {
      type = types.bool;
      default = true;
      description = "Enable scheduled report generation (router-logd runs regardless).";
    };

    retentionDays = mkOption {
      type = types.ints.between 1 3650;
      default = 90;
      description = "Query-log retention (drives router-logd pruning and engine stats retention).";
    };

    logd.port = mkOption {
      type = types.port;
      default = 8067;
      description = ''
        router-logd HTTP port. Bound on all interfaces: the block page's
        exception-request form posts here from client browsers; data endpoints
        require a bearer token.
      '';
    };

    schedules = mkOption {
      type = types.listOf scheduleType;
      default = [ ];
      description = "Scheduled PDF reports.";
    };

    email = {
      accountId = mkOption {
        type = types.str;
        default = "";
        description = "Cloudflare account id for the Email Sending API.";
      };
      apiTokenFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Path to a root-owned file with a Cloudflare API token (Email Routing: Edit).";
      };
      fromAddress = mkOption {
        type = types.str;
        default = "";
        description = "Sender address (must belong to a Cloudflare Email Routing domain).";
      };
    };
  };

  config = mkIf cfg.dns.technitium.enable (mkMerge [
    {
      assertions = [
        {
          assertion = length (unique (map (s: s.name) rcfg.schedules)) == length rcfg.schedules;
          message = "router.reporting.schedules: duplicate schedule name(s)";
        }
      ];

      users.groups.router-data = { };

      # ── Query-log store / portal daemon ───────────────────
      systemd.services.router-logd = {
        description = "Router query-log store and exception portal";
        wantedBy = [ "multi-user.target" ];
        after = [ "router-dns-secrets.service" ];
        requires = [ "router-dns-secrets.service" ];
        restartTriggers = [ cfg._dnsToolsConfig ];
        serviceConfig = {
          ExecStart = "${cfg._dnsToolsPackage}/bin/router-logd --config ${cfg._dnsToolsConfig}";
          DynamicUser = true;
          SupplementaryGroups = [ "router-data" ]; # read directory.json (0640)
          StateDirectory = "router-logd";
          LoadCredential = [
            "ingest-token:${technitiumStateDir}/logd-ingest.token"
            "query-token:${technitiumStateDir}/logd-query.token"
          ];
          Restart = "always";
          RestartSec = 5;
          # Hardening
          CapabilityBoundingSet = [ "" ];
          LockPersonality = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateTmp = true;
          ProtectHome = true;
          ProtectSystem = "strict";
          RestrictAddressFamilies = "AF_INET AF_INET6";
          RestrictNamespaces = true;
          RestrictRealtime = true;
        };
      };

      # ── Scheduled reports ─────────────────────────────────
      systemd.tmpfiles.rules = [ "d /var/lib/router-reports 0750 root root -" ];
    }

    (mkIf rcfg.enable {
      systemd.services = listToAttrs (
        map (
          schedule:
          nameValuePair "router-report-${schedule.name}" {
            description = "Generate DNS report '${schedule.name}'";
            after = [ "router-logd.service" ];
            wants = [ "router-logd.service" ];
            # Typst bundles no fonts; point it at DejaVu (used by report.typ).
            environment.TYPST_FONT_PATHS = "${pkgs.dejavu_fonts}/share/fonts/truetype";
            serviceConfig = {
              Type = "oneshot";
              ExecStart = "${cfg._dnsToolsPackage}/bin/router-report --config ${cfg._dnsToolsConfig} --schedule ${schedule.name}";
              LoadCredential = optional (
                rcfg.email.apiTokenFile != null
              ) "cf-api-token:${rcfg.email.apiTokenFile}";
            };
          }
        ) rcfg.schedules
      );

      systemd.timers = listToAttrs (
        map (
          schedule:
          nameValuePair "router-report-${schedule.name}" {
            wantedBy = [ "timers.target" ];
            timerConfig = {
              OnCalendar = onCalendarFor schedule;
              Persistent = true;
              RandomizedDelaySec = 300;
            };
          }
        ) rcfg.schedules
      );
    })
  ]);
}
