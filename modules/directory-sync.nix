# ── Directory integration (SSSD) ───────────────────────────────────────────────
# SSSD owns the connection to LDAP / Active Directory — its TLS, its
# credentials, its cache, its nested-group and referral handling. The router
# only asks NSS (getpwnam / getgrouplist / getgrnam) about the identities the
# access policies actually name, and writes the answers to
# /var/lib/router-directory/ on a timer.
#
# The synced state is EXTERNAL DATA, not configuration: access policies
# reference directory group names declaratively; the policy compiler and
# router-logd consume the state file at runtime, and a path unit re-pushes
# compiled policies whenever it changes — no rebuild required for IdP churn.
#
# NAMES ARE RESOLVED ON DEMAND, NEVER ENUMERATED. `enumerate = false` is the
# SSSD default and the only sane setting at school/business scale, so
# `getent passwd` with no argument returns nothing for directory users. The
# reference set comes from router-policy-static.json instead:
#   hosts[].user                           → users to resolve
#   policies[].assignments.directoryGroups → groups to validate
#
# Identity is used for policy assignment by default. Setting
# `router.directory.sssd.adminGroup` additionally lets that one group log in to
# the router; left empty, SSSD runs without its PAM responder and pam_sss is
# force-removed from every PAM stack, so no directory user can authenticate.
{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  cfg = config.router;
  dcfg = cfg.directory;
  scfg = dcfg.sssd;

  enabled = cfg.dns.technitium.enable && dcfg.provider == "sssd";

  # Directory members may log in to the router.
  adminMode = scfg.adminGroup != "";

  # SSSD is enabled for identity lookup ONLY. Used to force-disable the pam_sss
  # rules nixpkgs injects into every PAM service (see the option re-declaration
  # below); deliberately false when SSSD is not ours to configure.
  lookupOnly = enabled && !adminMode;

  # envsubst placeholder. services.sssd runs the generated config through
  # envsubst in its preStart, reading services.sssd.environmentFile.
  bindPwVar = "ROUTER_SSSD_BIND_PW";
  envFile = "/run/router-directory/sssd.env";

  domainSettings = {
    id_provider = "ldap";
    auth_provider = if adminMode then "ldap" else "none";
    access_provider = if adminMode then "simple" else "deny";
    chpass_provider = "none"; # the router is not a password-change kiosk

    # Explicit even though both are the defaults — the sync design depends on
    # enumeration being off, and short names keep hosts[].user predictable.
    enumerate = false;
    use_fully_qualified_names = false;

    cache_credentials = adminMode; # offline Cockpit login when the DC is down
    entry_cache_timeout = scfg.cacheTimeoutMinutes * 60;

    ldap_uri = concatStringsSep "," scfg.servers;
    ldap_search_base = scfg.baseDn;
    ldap_schema = scfg.schema;
    ldap_id_mapping = scfg.idMapping;
    ldap_tls_reqcert = scfg.tlsReqCert;
    ldap_referrals = false; # chasing referrals against AD is pure latency
  }
  // optionalAttrs (scfg.bindDn != "") {
    ldap_default_bind_dn = scfg.bindDn;
    ldap_default_authtok_type = "password";
    ldap_default_authtok = "\$${bindPwVar}";
  }
  // optionalAttrs (scfg.tlsCaCertFile != null) { ldap_tls_cacert = scfg.tlsCaCertFile; }
  // optionalAttrs (scfg.tlsClientCertFile != null) { ldap_tls_cert = scfg.tlsClientCertFile; }
  // optionalAttrs (scfg.tlsClientKeyFile != null) { ldap_tls_key = scfg.tlsClientKeyFile; }
  // optionalAttrs (scfg.userSearchBase != "") { ldap_user_search_base = scfg.userSearchBase; }
  // optionalAttrs (scfg.groupSearchBase != "") { ldap_group_search_base = scfg.groupSearchBase; }
  // optionalAttrs adminMode { simple_allow_groups = scfg.adminGroup; }
  // scfg.extraDomainSettings; # escape hatch wins

  sssdSettings = {
    sssd = {
      domains = scfg.domain;
      # MUST be explicit: the nixpkgs module runs `sssd -i` and installs no
      # sssd-{nss,pam}.socket, so no responder is socket-activated. Omitting
      # "pam" is the PRIMARY control that keeps identity policy-only.
      services = if adminMode then "nss, pam" else "nss";
    };

    nss = {
      # AD rarely populates loginShell/homeDirectory, and there is no /bin/bash
      # on NixOS — pin both rather than let libc guess. Paths are the stable
      # system-path symlinks, not store paths, so a shadow/bash update does not
      # churn sssd.conf and restart the daemon.
      default_shell =
        if adminMode then "/run/current-system/sw/bin/bash" else "/run/current-system/sw/bin/nologin";
      fallback_homedir = "/home/%u";
      homedir_substring = "/home";
    };
  }
  // optionalAttrs adminMode {
    pam = {
      pam_verbosity = 1;
    };
  };

  # The complete generated config. Built once so the stray-$ check below sees
  # every section — including [domain/…], which is where extraDomainSettings
  # lands and therefore where a literal '$' is most likely to appear.
  fullSettings = sssdSettings // {
    "domain/${scfg.domain}" = domainSettings;
  };

  generatedValues = concatMap attrValues (attrValues fullSettings);
  strayDollar = filter (v: isString v && hasInfix "$" v && v != "\$${bindPwVar}") generatedValues;

  sssdEnvScript = pkgs.writeShellScript "router-sssd-env" ''
    set -euo pipefail
    umask 077
    mkdir -p /run/router-directory
    chmod 0700 /run/router-directory
    ${
      if scfg.bindPasswordFile == null then
        # Anonymous bind: still emit the file, because services.sssd sets
        # EnvironmentFile= without a "-" prefix and a missing file fails the unit.
        ": > ${envFile}"
      else
        ''
          if [ ! -s ${escapeShellArg scfg.bindPasswordFile} ]; then
            echo "router-directory: ${scfg.bindPasswordFile} is missing or empty" >&2
            exit 1
          fi
          printf '${bindPwVar}=%s\n' \
            "$(tr -d '\r\n' < ${escapeShellArg scfg.bindPasswordFile})" > ${envFile}
        ''
    }
    chmod 0600 ${envFile}
  '';
in
{
  options.router.directory = {
    provider = mkOption {
      type = types.enum [
        "none"
        "sssd"
      ];
      default = "none";
      description = ''
        Identity source for policy assignment. "sssd" resolves users and groups
        through SSSD/NSS against LDAP or Active Directory. Only the names the
        access policies reference are looked up — the directory is never
        enumerated, so directory size costs nothing.
      '';
    };

    syncIntervalMinutes = mkOption {
      type = types.ints.between 5 1440;
      default = 60;
      description = "How often to re-resolve the referenced users/groups through NSS.";
    };

    sssd = {
      domain = mkOption {
        type = types.str;
        default = "";
        example = "school.example.org";
        description = "Directory domain name. Names the sssd.conf [domain/<name>] section.";
      };

      servers = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "ldaps://dc1.school.example.org"
          "ldaps://dc2.school.example.org"
        ];
        description = "LDAP URIs in preference order (ldap_uri). Prefer ldaps://.";
      };

      baseDn = mkOption {
        type = types.str;
        default = "";
        example = "dc=school,dc=example,dc=org";
        description = "Search base DN (ldap_search_base).";
      };

      userSearchBase = mkOption {
        type = types.str;
        default = "";
        description = "Optional narrower base for user lookups (ldap_user_search_base). Empty = baseDn.";
      };

      groupSearchBase = mkOption {
        type = types.str;
        default = "";
        description = "Optional narrower base for group lookups (ldap_group_search_base). Empty = baseDn.";
      };

      schema = mkOption {
        type = types.enum [
          "ad"
          "rfc2307bis"
          "rfc2307"
        ];
        default = "ad";
        description = ''
          Directory schema (ldap_schema). "ad" for Active Directory and Google
          Workspace Secure LDAP; "rfc2307bis" for most OpenLDAP/389-DS
          deployments; "rfc2307" for memberUid-style groups.
        '';
      };

      idMapping = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Derive POSIX uid/gid from the directory SID (ldap_id_mapping) instead
          of requiring uidNumber/gidNumber attributes. Turn this off only when
          the directory carries real POSIX attributes.
        '';
      };

      bindDn = mkOption {
        type = types.str;
        default = "";
        example = "CN=router-sync,OU=Service Accounts,DC=school,DC=example,DC=org";
        description = "Read-only bind DN (ldap_default_bind_dn). Empty binds anonymously.";
      };

      bindPasswordFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Path to a root-owned file containing ONLY the bind password. It never
          enters the Nix store: a pre-start unit copies it into a 0600 env file
          which SSSD substitutes into its config at service start.
        '';
      };

      tlsCaCertFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          PEM CA bundle validating the directory server certificate
          (ldap_tls_cacert). Active Directory LDAPS certificates are usually
          issued by an enterprise CA that is not in the system trust store.
        '';
      };

      tlsClientCertFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Client certificate for mutual-TLS bind (ldap_tls_cert). Required by
          Google Workspace Secure LDAP, which authenticates the client by
          certificate rather than by bind DN and password.
        '';
      };

      tlsClientKeyFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Private key matching tlsClientCertFile (ldap_tls_key).";
      };

      tlsReqCert = mkOption {
        type = types.enum [
          "never"
          "allow"
          "try"
          "demand"
          "hard"
        ];
        default = "demand";
        description = "Server certificate validation (ldap_tls_reqcert).";
      };

      cacheTimeoutMinutes = mkOption {
        type = types.ints.between 1 1440;
        default = 90;
        description = "How long SSSD serves a cached entry before re-querying (entry_cache_timeout).";
      };

      groups = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "Students"
          "Staff"
        ];
        description = ''
          Extra directory group names to resolve and publish even when no policy
          references them yet. Because the directory is never enumerated, the
          Cockpit directory-group picker can only offer groups it has already
          seen — list your candidates here to populate it.
        '';
      };

      adminGroup = mkOption {
        type = types.str;
        default = "";
        example = "RouterAdmins";
        description = ''
          Empty (the default): directory identities are used for POLICY
          ASSIGNMENT ONLY. SSSD runs without its PAM responder, the domain's
          access_provider is "deny", and pam_sss is force-removed from every PAM
          stack — a directory user can never authenticate to the router.

          Non-empty: members of this directory group may log in to Cockpit and
          administer the router. The name must contain no whitespace and must
          not collide with a local group.
        '';
      };

      adminSsh = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Also let adminGroup members in over SSH. This re-enables
          keyboard-interactive authentication for that group only; the router is
          otherwise SSH-key-only. Cockpit-only is the safer default.
        '';
      };

      extraDomainSettings = mkOption {
        type = types.attrsOf types.str;
        default = { };
        visible = false;
        example = {
          ldap_user_search_filter = "(memberOf=CN=Filtered,DC=school,DC=example,DC=org)";
          ldap_group_nesting_level = "5";
        };
        description = ''
          Raw keys merged last into the sssd.conf [domain/<name>] section. The
          escape hatch for setups the structured options do not cover — for
          example a real Active Directory machine join (id_provider = "ad"),
          which additionally needs a Kerberos keytab.

          Values must not contain a literal '$': sssd.conf is passed through
          envsubst, which would silently delete it. An assertion enforces this.
        '';
      };
    };
  };

  # Re-declares (does NOT define) security.pam.services purely to append one
  # module to its submodule type, so the override below reaches EVERY pam
  # service without naming any of them. `lib.mapAttrs` over
  # config.security.pam.services would be infinite recursion — computing the
  # merged attribute names would require our own definition. A type merge is
  # evaluated at declaration time and is safe.
  #
  # This declaration must carry `type` and NOTHING else: lib/modules.nix throws
  # when two declarations of the same option both set default/description/
  # example/apply, and nixpkgs' declaration sets default and description.
  options.security.pam.services = mkOption {
    type = types.attrsOf (
      types.submodule {
        config.rules = mkIf lookupOnly {
          account.sss.enable = mkForce false;
          auth.sss.enable = mkForce false;
          password.sss.enable = mkForce false;
          session.sss.enable = mkForce false;
        };
      }
    );
  };

  config = mkIf enabled (mkMerge [
    {
      assertions = [
        {
          assertion = scfg.domain != "";
          message = "router.directory.sssd.domain must be set when provider = \"sssd\".";
        }
        {
          assertion = scfg.servers != [ ];
          message = "router.directory.sssd.servers must list at least one LDAP URI.";
        }
        {
          assertion = all (u: hasPrefix "ldap://" u || hasPrefix "ldaps://" u) scfg.servers;
          message = "router.directory.sssd.servers entries must be ldap:// or ldaps:// URIs.";
        }
        {
          assertion = scfg.bindDn == "" -> scfg.bindPasswordFile == null;
          message = "router.directory.sssd.bindPasswordFile is set but bindDn is empty (anonymous bind takes no password).";
        }
        {
          assertion = scfg.bindDn != "" -> scfg.bindPasswordFile != null;
          message = "router.directory.sssd.bindDn is set but bindPasswordFile is null.";
        }
        {
          assertion = (scfg.tlsClientCertFile == null) == (scfg.tlsClientKeyFile == null);
          message = "router.directory.sssd: tlsClientCertFile and tlsClientKeyFile must be set together.";
        }
        {
          # envsubst (services.sssd preStart) would silently delete it.
          assertion = strayDollar == [ ];
          message = ''
            router.directory.sssd: the generated sssd.conf contains a literal '$'
            (${concatStringsSep ", " strayDollar}). services.sssd runs the file
            through envsubst, which would delete it. Remove the '$' or
            pre-substitute the value.
          '';
        }
        {
          assertion = adminMode -> (builtins.match ".*[[:space:]].*" scfg.adminGroup) == null;
          message = ''
            router.directory.sssd.adminGroup must not contain whitespace: sudoers
            renders it as %${scfg.adminGroup} and sshd_config AllowGroups is
            space-separated.
          '';
        }
        {
          # /etc/nsswitch.conf is "group: files sss" — a local group of the same
          # name wins every lookup and the directory group is unreachable.
          assertion = adminMode -> !(elem scfg.adminGroup (attrNames config.users.groups));
          message = ''
            router.directory.sssd.adminGroup "${scfg.adminGroup}" collides with a
            local group. NSS resolves local groups first, so the directory group
            would never be consulted.
          '';
        }
        {
          # Rename-proof: nixpkgs' formatRules filters on `enable` before it
          # touches modulePath, so if upstream renames the "sss" rule our
          # mkForce false becomes a silent no-op. Check the rendered text.
          assertion =
            !lookupOnly || !(any (s: hasInfix "pam_sss.so" s.text) (attrValues config.security.pam.services));
          message = ''
            router.directory: pam_sss is still linked into a PAM stack even though
            router.directory.sssd.adminGroup is empty (identity-lookup-only mode).
            nixpkgs' security/pam.nix has probably renamed its "sss" rule — update
            the rules.<type>.sss.enable overrides in modules/directory-sync.nix.
          '';
        }
      ];

      warnings = optional (adminMode && scfg.adminSsh) ''
        router.directory.sssd.adminSsh re-enables keyboard-interactive SSH
        authentication for directory group "${scfg.adminGroup}". The router is
        otherwise SSH-key-only.
      '';

      services.sssd = {
        enable = true;
        environmentFile = envFile;
        settings = fullSettings;
      };

      # The bind password reaches SSSD as a KEY=value env file, because
      # services.sssd substitutes secrets with envsubst rather than reading a
      # bare file. Deliberately NOT RemainAfterExit: a plain oneshot pulled in by
      # Requires= re-runs on every sssd start, so rotating the password file only
      # needs `systemctl restart sssd`. Plain mkdir, not RuntimeDirectory —
      # systemd would delete the latter the moment this oneshot exits.
      systemd.services.router-sssd-env = {
        description = "Materialize the SSSD bind password as an env file";
        before = [ "sssd.service" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = sssdEnvScript;
        };
      };

      systemd.services.sssd = {
        after = [ "router-sssd-env.service" ];
        requires = [ "router-sssd-env.service" ];
      };

      # Shared read group: the sync unit writes directory.json 0640 with this
      # group so router-logd (a DynamicUser) can read it.
      users.groups.router-data = { };

      # A STATIC user, deliberately — not DynamicUser. With DynamicUser the
      # StateDirectory would live at /var/lib/private/router-directory (the
      # /var/lib/router-directory symlink is only a facade), and /var/lib/private
      # is 0700 root:root. router-logd runs as its own DynamicUser, so no group
      # membership could get it past that directory and the user tier would
      # silently never appear in query-log attribution. A static user keeps the
      # state directory at its real path, where the router-data group works.
      users.users.router-directory-sync = {
        isSystemUser = true;
        group = "router-data";
        description = "Directory sync for router access policies";
      };

      systemd.services.router-directory-sync = {
        # The unit name is a UI contract — Cockpit's "Sync now" button starts it.
        description = "Resolve directory users/groups for access policies";
        after = [
          "sssd.service"
          "nss-user-lookup.target"
        ];
        wants = [
          "sssd.service"
          "nss-user-lookup.target"
        ];

        # NOT restartTriggers: switch-to-configuration builds its changed-unit
        # set from units that are currently active, and a timer-driven oneshot
        # without RemainAfterExit is always inactive between runs, so
        # X-Restart-Triggers would be dead code. RemainAfterExit is not a fix
        # either — it would make the timer's start job a no-op and silently kill
        # the hourly sync. Every active target IS restarted on switch, which
        # pulls in inactive Wants= members; that is what re-resolves a
        # newly-assigned user without waiting for the timer.
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          Type = "oneshot";
          User = "router-directory-sync";
          Group = "router-data";
          StateDirectory = "router-directory";
          StateDirectoryMode = "0750";
          ExecStart = "${cfg._dnsToolsPackage}/bin/router-directory-sync --config ${cfg._dnsToolsConfig}";

          # sssd.service reports ready when its monitor is up, not when the
          # backend has connected, so the first post-boot run can hit a cold
          # cache and resolve nothing.
          Restart = "on-failure";
          RestartSec = 30;

          # Hardening. There is no provider secret any more (SSSD holds it), and
          # no network I/O at all: the only syscalls that leave the process are
          # NSS lookups over the nsncd and sssd_nss UNIX sockets. Both are
          # filesystem sockets rather than abstract-namespace ones, which is what
          # makes PrivateNetwork safe here. ProtectSystem=strict does not block
          # them either — a read-only mount rejects writes to regular files and
          # directories, not connect() on a socket inode.
          CapabilityBoundingSet = [ "" ];
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateNetwork = true;
          PrivateTmp = true;
          ProtectClock = true;
          ProtectControlGroups = true;
          ProtectHome = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectSystem = "strict";
          RestrictAddressFamilies = "AF_UNIX";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [
            "@system-service"
            "~@privileged"
            "~@resources"
          ];
        };

        unitConfig = {
          StartLimitIntervalSec = 600;
          StartLimitBurst = 5;
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
    }

    # ── Directory admin login ────────────────────────────────────────────────
    # SSSD's access_provider gates authentication to adminGroup for every PAM
    # service at once. What it does NOT grant is the privilege to change
    # anything: the Cockpit router plugin drives most writes through the
    # superuser bridge (sudo) and the rest through polkit.
    (mkIf adminMode {
      security.pam.services.cockpit.makeHomeDir = true;

      security.sudo.extraRules = [
        {
          groups = [ scfg.adminGroup ];
          commands = [
            {
              command = "ALL";
              options = [ "SETENV" ];
            }
          ];
        }
      ];

      security.polkit.adminIdentities = [
        "unix-group:wheel"
        "unix-group:${scfg.adminGroup}"
      ];

      # SSH is opt-in. The router sets PasswordAuthentication = false, and
      # nixpkgs' sshd module reacts by disabling pam_unix auth — so a directory
      # user has no way in at all unless keyboard-interactive is re-enabled.
      # Scope that to the one group with a Match block; extraConfig is appended
      # after the generated settings, which is where Match must live.
      services.openssh.settings.AllowGroups = mkIf scfg.adminSsh [
        "wheel"
        scfg.adminGroup
      ];
      services.openssh.extraConfig = mkIf scfg.adminSsh (mkAfter ''

        Match Group ${scfg.adminGroup}
          KbdInteractiveAuthentication yes
          AuthenticationMethods keyboard-interactive
      '');
    })
  ]);
}
