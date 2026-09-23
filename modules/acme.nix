# ── ACME module ────────────────────────────────────────────────────────────────
# Account-level settings for the TLS certificates the router obtains from an
# ACME CA (Let's Encrypt) through NixOS security.acme (lego). The certificates
# themselves are requested by the modules that need them — today only the
# reverse proxy (modules/reverse-proxy.nix), one per route — and pick one of
# two challenge types:
#
#   • dns-cloudflare — DNS-01 through the Cloudflare API. Needs no inbound
#     port, works before the name resolves to the router, and is the only way
#     to get a wildcard. The token is a path to a root-owned file, handed to
#     lego through LoadCredential (security.acme's credentialFiles).
#   • http        — HTTP-01. The CA fetches a file from http://<name>/, which
#     the proxy's :80 listener serves from lego's webroot, so the name must
#     already resolve to the router (router.reverseProxy.publishDns does that).
{
  config,
  lib,
  ...
}:
with lib;
let
  cfg = config.router;
  acfg = cfg.acme;

  # Set by the requesting modules; the account settings only apply once
  # something actually asks for a certificate.
  wanted = config.security.acme.certs != { };
in
{
  options.router.acme = {
    email = mkOption {
      type = types.str;
      default = "";
      example = "admin@example.com";
      description = "Contact address for the ACME account; the CA sends expiry warnings here.";
    };

    acceptTerms = mkOption {
      type = types.bool;
      default = false;
      description = "Accept the ACME CA's terms of service (https://letsencrypt.org/repository/). Required before any certificate is requested.";
    };

    staging = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Use Let's Encrypt's staging CA. Its certificates are not trusted by
        browsers, but its rate limits are far higher — use it while testing a
        new route, then switch back.
      '';
    };

    defaultChallenge = mkOption {
      type = types.enum [
        "dns-cloudflare"
        "http"
      ];
      default = "http";
      description = ''
        How a certificate proves control of its names when the route does not
        choose: `dns-cloudflare` (DNS-01 via the Cloudflare API — needs
        cloudflare.apiTokenFile) or `http` (HTTP-01 through the reverse proxy's
        port 80 — the name must already resolve to the router).
      '';
    };

    cloudflare.apiTokenFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/etc/router/secrets/cloudflare-ddns.token";
      description = ''
        Path to a root-owned file holding a Cloudflare API token with
        Zone → Zone → Read and Zone → DNS → Edit on the certificates' zones —
        the same scopes router.ddns needs, so its token file can be reused.
        The file holds the bare token — never put the token itself here.
      '';
    };
  };

  config = mkIf wanted {
    assertions = [
      {
        assertion = acfg.acceptTerms;
        message = "router.acme.acceptTerms must be true before the router requests certificates (see https://letsencrypt.org/repository/)";
      }
      {
        assertion = acfg.email != "";
        message = "router.acme.email must be set before the router requests certificates";
      }
    ];

    security.acme = {
      inherit (acfg) acceptTerms;
      defaults = {
        inherit (acfg) email;
        server = mkIf acfg.staging "https://acme-staging-v02.api.letsencrypt.org/directory";
      };
    };
  };
}
