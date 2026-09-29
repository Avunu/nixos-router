# ── Cockpit certificate module ─────────────────────────────────────────────────
# The router's own domain name (router.fqdn) and a Let's Encrypt certificate
# for Cockpit under it, so the web UI opens at https://<fqdn>:9090 without a
# certificate warning.
#
# Cockpit only listens on the trusted side (LAN + WireGuard), so the
# certificate proves control of the name by DNS-01 through the Cloudflare API,
# with router.acme's account and token: the name needs no public record and
# the CA never reaches the router. LAN and WireGuard clients resolve the name
# to the LAN gateway through the split-horizon DNS (dns-technitium.nix,
# routerNameRecords).
#
# Handing the certificate to Cockpit: cockpit.service's ExecStartPre
# (cockpit-certificate-ensure, as root) serves the asciibetically last *.crt in
# /etc/cockpit/ws-certs.d with its .key sibling, and fails the start if that
# file cannot be read. The nixpkgs module also cleans that directory daily
# (its tmpfiles line has age 0), so a copy made once at renewal would not
# survive, and a symlink into /var/lib/acme could dangle and keep Cockpit
# down. Instead router-cockpit-cert copies the certificate in before every
# Cockpit start, socket activation included, and removes it when there is no
# issued certificate to serve. A renewal restarts Cockpit (reloadServices),
# which signs everyone out; Cockpit's Apply survives it, since the rebuild
# runs in its own unit.
{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  cfg = config.router;
  acfg = cfg.acme;
  netLib = import ./lib/net.nix { inherit lib; };

  fqdn = if cfg.fqdn != null then toLower cfg.fqdn else null;
  wantCert = fqdn != null && cfg.cockpit.enable;

  # The certificate's name under /var/lib/acme and in its acme-* units. Route
  # certificates are named after a hostname, which always has a dot, so this
  # cannot collide with one. The System page uses the same name (src/system.tsx
  # ROUTER_CERT).
  certName = "cockpit";
  certDir = "/var/lib/acme/${certName}";
  # Sorts after Cockpit's own 0-self-signed.cert, so it wins while present.
  target = "/etc/cockpit/ws-certs.d/90-router";

  # Always exits 0: a failure here must leave Cockpit on its self-signed
  # certificate, never keep it from starting.
  installScript = pkgs.writeShellScript "router-cockpit-cert" ''
    set -u
    remove() { rm -f ${target}.crt ${target}.key ${target}.crt.new ${target}.key.new; }
    ${
      if wantCert then
        ''
          chain=${certDir}/fullchain.pem
          key=${certDir}/key.pem
          if [ ! -s "$chain" ] || [ ! -s "$key" ]; then
            echo "no certificate for ${fqdn} yet; Cockpit keeps its self-signed one"
            remove
            exit 0
          fi
          # acme-${certName}.service leaves a minica placeholder until the
          # first order succeeds. Serving it would only swap one untrusted
          # certificate for another, so keep Cockpit's own until then.
          if openssl x509 -in "$chain" -noout -issuer | grep -qi minica; then
            echo "certificate for ${fqdn} not issued yet; Cockpit keeps its self-signed one"
            remove
            exit 0
          fi
          certPub=$(openssl x509 -in "$chain" -noout -pubkey 2>/dev/null)
          keyPub=$(openssl pkey -in "$key" -pubout 2>/dev/null)
          if [ -z "$certPub" ] || [ "$certPub" != "$keyPub" ]; then
            echo "certificate and key in ${certDir} do not match; Cockpit keeps its self-signed one" >&2
            remove
            exit 0
          fi
          # Written under names Cockpit ignores, then moved into place, so it
          # never sees a partial file.
          install -D -m 0600 "$chain" ${target}.crt.new &&
            install -D -m 0600 "$key" ${target}.key.new &&
            mv -f ${target}.key.new ${target}.key &&
            mv -f ${target}.crt.new ${target}.crt ||
            { echo "could not install the certificate; Cockpit keeps its self-signed one" >&2; remove; }
        ''
      else
        "remove"
    }
    exit 0
  '';

  # Names that point somewhere else. The split-horizon record would send LAN
  # clients to the router for them, where 443 is the Block Page, not the
  # proxied or tunnelled service.
  otherNames =
    map (h: {
      name = toLower h.publicHostname;
      owner = "host '${h.name}' (publicHostname)";
    }) (filter (h: h.publicHostname != null) cfg.hosts)
    ++ concatMap (
      r:
      map (n: {
        name = toLower n;
        owner = "reverse proxy route '${if r.name != "" then r.name else head r.hostnames}'";
      }) r.hostnames
    ) (optionals cfg.reverseProxy.enable cfg.reverseProxy.routes)
    ++ map (i: {
      name = toLower i.hostname;
      owner = "Cloudflare Tunnel hostname";
    }) (optionals cfg.cloudflareTunnel.enable cfg.cloudflareTunnel.ingress);
  clashes = filter (o: o.name == fqdn) otherNames;
in
{
  options.router.fqdn = mkOption {
    type = types.nullOr types.str;
    default = null;
    example = "gw.example.com";
    description = ''
      The router's own domain name. Cockpit then serves a Let's Encrypt
      certificate for it at https://<fqdn>:9090, and the router's DNS answers
      it with the LAN address. The certificate is issued through the Cloudflare
      DNS challenge (router.acme and its cloudflare.apiTokenFile), so the name
      must be in a Cloudflare zone but needs no public record. Like every
      certificate, it is listed in public Certificate Transparency logs.
    '';
  };

  config = mkMerge [
    (mkIf (fqdn != null) {
      assertions = [
        {
          assertion = netLib.isHostname fqdn;
          message = "router.fqdn: '${cfg.fqdn}' is not a valid domain name — use a public DNS name such as gw.example.com";
        }
        {
          assertion = clashes == [ ];
          message = "router.fqdn: ${fqdn} is also used by ${
            concatMapStringsSep ", " (c: c.owner) clashes
          } — the router's own name must be a name of its own";
        }
        {
          assertion = !wantCert || acfg.cloudflare.apiTokenFile != null;
          message = "router.fqdn: Cockpit's certificate uses the dns-cloudflare challenge, but router.acme.cloudflare.apiTokenFile is not set";
        }
      ];

      warnings =
        optional (!cfg.cockpit.enable) "router.fqdn is set but Cockpit is disabled, so no certificate is requested; the name only resolves to the router on the LAN."
        ++ optional (!cfg.dns.technitium.enable) "router.fqdn: Technitium is disabled, so the router's DNS does not answer ${fqdn} — LAN clients need their own record for it.";
    })

    (mkIf wantCert {
      security.acme.certs.${certName} = {
        domain = fqdn;
        dnsProvider = "cloudflare";
        dnsPropagationCheck = true;
        # The router resolves through its own Technitium, which holds a local
        # zone for this very name (routerNameRecords). Asked there, lego would
        # take that zone for the Cloudflare zone and fail to find it.
        dnsResolver = "1.1.1.1:53";
        # Guarded so a missing path reports through the assertion above.
        credentialFiles = optionalAttrs (acfg.cloudflare.apiTokenFile != null) {
          CF_DNS_API_TOKEN_FILE = acfg.cloudflare.apiTokenFile;
        };
        reloadServices = [ "cockpit.service" ];
      };

      services.cockpit.allowed-origins = [
        "https://${fqdn}"
        "https://${fqdn}:${toString cfg.cockpit.port}"
      ];
    })

    # Defined whenever Cockpit is, so clearing router.fqdn also removes the
    # certificate it installed.
    (mkIf cfg.cockpit.enable {
      systemd.services.router-cockpit-cert = {
        description = "Install the router's certificate for Cockpit";
        # A Wants from cockpit.service re-runs this (it is inactive again once
        # done) on every Cockpit start, including restarts and socket
        # activation.
        wantedBy = [ "cockpit.service" ];
        before = [ "cockpit.service" ];
        # Not a Wants: the placeholder unit starts with the system anyway, and
        # the copy only has to wait while it writes.
        after = optional wantCert "acme-${certName}.service";
        unitConfig.StartLimitIntervalSec = 0;
        path = [ pkgs.openssl ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = installScript;
        };
      };
    })
  ];
}
