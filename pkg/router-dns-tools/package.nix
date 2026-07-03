# ── router-dns-tools ───────────────────────────────────────────────────────────
# Python runtime tooling for the access-protection stack (see pyproject.toml
# for the CLI list). The Technitium DNS app payloads consumed by
# modules/dns-technitium.nix are the `technitiumApps` package (compiled from
# source — pkg/technitium-apps), re-exposed here via passthru.
#
# `typst` is wrapped onto PATH for router-report's PDF compilation.
{
  lib,
  python3Packages,
  typst,
  pyturso,
  technitiumApps,
}:
python3Packages.buildPythonApplication {
  pname = "router-dns-tools";
  version = "0.1.0";
  pyproject = true;

  src = ./.;

  build-system = [ python3Packages.setuptools ];

  dependencies = with python3Packages; [
    pyturso
    ldap3
    google-auth
    google-api-python-client
  ];

  makeWrapperArgs = [
    "--prefix PATH : ${lib.makeBinPath [ typst ]}"
  ];

  # No upstream tests; the technitium-vm NixOS test exercises everything
  # end-to-end (reconcile, compile, logd ingest/query, portal, report).
  doCheck = false;

  pythonImportsCheck = [
    "router_dns_tools.compile_policies"
    "router_dns_tools.technitium_api"
  ];

  passthru = {
    inherit technitiumApps;
    blockPageTemplate = ./router_dns_tools/blockpage/index.html;
  };

  meta = {
    description = "nixos-router access-protection runtime tooling";
    license = lib.licenses.mit;
  };
}
