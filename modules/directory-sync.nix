# ── Directory sync module ──────────────────────────────────────────────────────
# Pulls users and groups from the configured identity provider (LDAP/AD,
# Microsoft Entra, Google Workspace) into /var/lib/router-directory/ on a
# timer. The synced state is EXTERNAL DATA, not configuration: access policies
# reference directory group names declaratively; the policy compiler and
# router-logd consume the state file at runtime, and a path unit re-pushes
# compiled policies whenever it changes — no rebuild required for IdP churn.
#
# Identity is used ONLY for policy assignment (no admin SSO by design).
# Provider secrets are files referenced by path (never inline in settings) and
# reach the sandboxed sync unit via LoadCredential.
{
  config,
  lib,
  ...
}:
with lib;
let
  cfg = config.router;
  dcfg = cfg.directory;

  secretFile =
    {
      ldap = dcfg.ldap.bindPasswordFile;
      entra = dcfg.entra.clientSecretFile;
      google = dcfg.google.serviceAccountKeyFile;
      none = null;
    }
    .${dcfg.provider};
in
{
  options.router.directory = {
    provider = mkOption {
      type = types.enum [
        "none"
        "ldap"
        "entra"
        "google"
      ];
      default = "none";
      description = "Identity provider for user/group sync (policy assignment only).";
    };

    syncIntervalMinutes = mkOption {
      type = types.ints.between 5 1440;
      default = 60;
      description = "How often to sync users/groups from the provider.";
    };

    ldap = {
      url = mkOption {
        type = types.str;
        default = "";
        description = "LDAP URL, e.g. ldaps://dc1.example.org.";
      };
      bindDn = mkOption {
        type = types.str;
        default = "";
        description = "Bind DN for the sync account.";
      };
      bindPasswordFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Path to a root-owned file containing the bind password.";
      };
      baseDn = mkOption {
        type = types.str;
        default = "";
        description = "Search base DN.";
      };
      userFilter = mkOption {
        type = types.str;
        default = "(objectClass=person)";
        description = "LDAP filter selecting user entries.";
      };
      groupFilter = mkOption {
        type = types.str;
        default = "(objectClass=group)";
        description = "LDAP filter selecting group entries.";
      };
    };

    entra = {
      tenantId = mkOption {
        type = types.str;
        default = "";
        description = "Entra ID tenant id.";
      };
      clientId = mkOption {
        type = types.str;
        default = "";
        description = "App registration client id (needs User.Read.All + GroupMember.Read.All).";
      };
      clientSecretFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Path to a root-owned file containing the client secret.";
      };
    };

    google = {
      domain = mkOption {
        type = types.str;
        default = "";
        description = "Google Workspace primary domain.";
      };
      adminEmail = mkOption {
        type = types.str;
        default = "";
        description = "Workspace admin the service account impersonates (domain-wide delegation).";
      };
      serviceAccountKeyFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Path to the service-account JSON key file.";
      };
    };
  };

  config = mkIf (cfg.dns.technitium.enable && dcfg.provider != "none") {
    assertions = [
      {
        assertion = secretFile != null;
        message = "router.directory: provider '${dcfg.provider}' requires its secret file option to be set";
      }
    ];

    # Shared read group: the sync unit writes directory.json 0640 with this
    # group so router-logd (a different DynamicUser) can read it.
    users.groups.router-data = { };

    systemd.services.router-directory-sync = {
      # The unit name is a UI contract — Cockpit's "Sync now" button starts it.
      description = "Sync directory users/groups for access policies";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        Type = "oneshot";
        DynamicUser = true;
        Group = "router-data";
        StateDirectory = "router-directory";
        StateDirectoryMode = "0750";
        LoadCredential = [ "directory-secret:${secretFile}" ];
        ExecStart = "${cfg._dnsToolsPackage}/bin/router-directory-sync --config ${cfg._dnsToolsConfig}";
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

    systemd.timers.router-directory-sync = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "2min";
        OnUnitActiveSec = "${toString dcfg.syncIntervalMinutes}min";
        RandomizedDelaySec = 60;
        Persistent = true;
      };
    };
  };
}
