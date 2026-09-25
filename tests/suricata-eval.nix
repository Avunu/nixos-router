# Eval-only regression check — Suricata's config file, log rotation and the
# build-time config test.
#
# Everything here used to fail silently or late:
#   • the upstream module rendered logging.outputs as a map and stats.enable
#     under the wrong key, so Suricata ignored both (modules/threat-protection.nix
#     overrides services.suricata.configFile to fix the shape);
#   • logrotate got both globs as ONE quoted pattern, which matched nothing, and
#     its postrotate reloaded rules instead of reopening the logs;
#   • a suppression host that isn't an address, or an extra rule that doesn't
#     parse, stopped Suricata only after the switch, leaving the IPS down.
# This pins the config as Suricata itself parses it (`suricata --dump-config`),
# the generated logrotate.conf, the suppression assertion, and that the
# system.checks config test passes on a good config and fails the build on a
# broken rule.
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
                router.wan.vlan = null;
                router.lan.interfaces = [ "eth2" ];
                router.suricata.enable = true;
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

  sys = evalWith {
    router.suricata = {
      mode = "ips";
      # One of each form the assertion admits, so the config test below also
      # proves Suricata's threshold parser takes them.
      suppressions = [
        {
          sid = 2100498;
          ip = "10.48.4.9";
        }
        {
          sid = 2100499;
          ip = "10.48.4.0/24";
          track = "by_dst";
        }
        {
          sid = 2100500;
          ip = "2001:db8::/32";
          track = "by_either";
        }
      ];
      extraRules = ''
        alert tcp $HOME_NET any -> $EXTERNAL_NET 3389 (msg:"LOCAL outbound RDP connection attempt"; flow:to_server; flags:S; sid:1000100; rev:1;)
      '';
    };
  };

  # Every misconfiguration at once, in ONE evaluation (each costs about a
  # gigabyte). The broken rule is caught by the config test, not an assertion,
  # so it is checked through that derivation below.
  bad = evalWith {
    router.suricata = {
      suppressions = [
        {
          sid = 2100498;
          ip = "10.0.0.256";
        }
        {
          # Would have added a second, catch-all suppress line.
          sid = 2100499;
          ip = "10.0.0.1\nsuppress gen_id 1, sig_id 2100499, track by_src, ip 0.0.0.0/0";
        }
      ];
      extraRules = ''
        alert tcp any any -> any any (msg:"LOCAL broken"; nosuchkeyword; sid:1000100; rev:1;)
      '';
    };
  };

  suricata = sys.services.suricata.package;
  configFile = sys.services.suricata.configFile;
  localRules = sys.environment.etc."suricata/rules/local.rules".source;
  logrotateConf = sys.environment.etc."logrotate.conf".source;
  configTestOf = c: lib.findFirst (d: d.name == "suricata-config-test") null c.system.checks;
  goodTest = configTestOf sys;
  badTest = configTestOf bad;

  failedAssertions = c: map (a: a.message) (lib.filter (a: !a.assertion) c.assertions);
  badMessages = failedAssertions bad;
  rejects = name: want: {
    inherit name;
    ok = lib.any (lib.hasInfix want) badMessages;
    detail = "want an assertion containing '${want}', got: ${lib.concatStringsSep " | " badMessages}";
  };
  # hasInfix builds a regex, which may not carry store-path context.
  noCtx = s: builtins.unsafeDiscardStringContext (toString s);
  reads = s: lib.hasInfix (noCtx configFile) (noCtx s);

  checks = [
    {
      name = "evaluates";
      ok = failedAssertions sys == [ ];
      detail = "assertions failed: ${lib.concatStringsSep " | " (failedAssertions sys)}";
    }
    {
      # The -T in ExecStartPre, the NFQ ExecStart and suricata-update must all
      # load the fixed file, not the upstream default.
      name = "every-consumer-reads-the-config-file";
      ok =
        reads sys.systemd.services.suricata.serviceConfig.ExecStartPre
        && reads sys.systemd.services.suricata.serviceConfig.ExecStart
        && reads sys.systemd.services.suricata-update.script;
      detail = "a Suricata consumer does not read services.suricata.configFile (${configFile})";
    }
    {
      name = "config-test-is-a-system-check";
      ok = goodTest != null && badTest != null;
      detail = "system.checks has no suricata-config-test";
    }
    {
      name = "logrotate-files-is-a-list";
      ok = lib.isList sys.services.logrotate.settings.suricata.files;
      detail = "services.logrotate.settings.suricata.files is one string, so logrotate reads one pattern";
    }

    (rejects "suppression-ip-valid" "router.suricata.suppressions: SID 2100498 has an invalid host '10.0.0.256'")
    (rejects "suppression-ip-no-newline" "router.suricata.suppressions: SID 2100499 has an invalid host")
  ];

  failures = lib.filter (c: !c.ok) checks;

  # The config test must fail the build on the broken rule, naming it.
  badTestFails = pkgs.testers.testBuildFailure badTest;
in
pkgs.runCommand "router-suricata-eval"
  {
    nativeBuildInputs = [ suricata ];
  }
  (
    if failures == [ ] then
      ''
        fail() { echo "FAIL $1" >&2; exit 1; }

        # The config as Suricata parses it: logging.outputs is a sequence of
        # one-key maps (the shape it iterates), stats under `enabled`.
        suricata --dump-config -c ${configFile} > dump.txt
        for want in \
          "logging.default-log-level = notice" \
          "logging.outputs.0 = console" \
          "logging.outputs.0.console.enabled = yes" \
          "logging.outputs.1.file.enabled = no" \
          "logging.outputs.2.syslog.enabled = no" \
          "stats.enabled = yes" \
          "stats.interval = 30"; do
          grep -Fxq "$want" dump.txt || fail "config-file: no '$want' in suricata --dump-config"
        done
        ! grep -q '^stats\.enable =' dump.txt || fail "config-file: stats.enable is still rendered"
        [ "$(grep -c '^%YAML' ${configFile})" = 1 ] || fail "config-file: want exactly one %YAML header"

        # With the old map, Suricata found no output and warned it was falling
        # back to the console. Run the same test the system check runs.
        suricata -T -c ${goodTest.testConfig} -S ${localRules} \
          -l "$TMPDIR" --set classification-file=${suricata}/etc/suricata/classification.config \
          > t.log 2>&1 || { cat t.log >&2; fail "config-test: suricata -T failed"; }
        ! grep -q 'Output_interface not supplied' t.log || fail "config-file: Suricata found no log output"

        # logrotate.conf: one quoted glob per line, and a HUP (reopen the
        # logs) once per run rather than a USR2 rule reload.
        grep -Fxq '"/var/log/suricata/*.log"' ${logrotateConf} || fail "logrotate: no *.log glob line"
        grep -Fxq '"/var/log/suricata/*.json" {' ${logrotateConf} || fail "logrotate: no *.json glob line"
        grep -Fq 'systemctl kill --kill-whom=main --signal=HUP suricata.service' ${logrotateConf} \
          || fail "logrotate: postrotate does not send SIGHUP"
        grep -Fxq '  sharedscripts' ${logrotateConf} || fail "logrotate: no sharedscripts"
        ! grep -Fq 'systemctl reload suricata' ${logrotateConf} || fail "logrotate: still reloads"

        # The build-time config test passes on the good config (a build
        # dependency) and fails on the broken rule, naming it.
        echo ${goodTest} > /dev/null
        grep -Fq 'error parsing signature' ${badTestFails}/testBuildFailure.log \
          || fail "config-test: the broken rule did not fail with a parse error"
        grep -Fq 'router.suricata: Suricata rejected the configuration' ${badTestFails}/testBuildFailure.log \
          || fail "config-test: no router.suricata hint on failure"

        touch $out
      ''
    else
      ''
        echo "Suricata config generation regressed:" >&2
        ${lib.concatMapStringsSep "\n" (f: ''
          echo "  FAIL ${f.name}" >&2
          echo ${lib.escapeShellArg "       ${f.detail}"} >&2
        '') failures}
        exit 1
      ''
  )
