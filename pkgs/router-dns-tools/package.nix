# ── router-dns-tools ───────────────────────────────────────────────────────────
# Python runtime tooling for the access-protection stack (see pyproject.toml
# for the CLI list). The Technitium DNS app payloads consumed by
# modules/dns-technitium.nix are the `technitiumApps` package (compiled from
# source — pkgs/technitium-apps), re-exposed here via passthru.
#
# `typst` is wrapped onto PATH for router-report's PDF compilation.
{
  lib,
  python3Packages,
  typst,
  technitiumApps,
}:
python3Packages.buildPythonApplication {
  pname = "router-dns-tools";
  version = "0.1.0";
  pyproject = true;

  src = ./.;

  build-system = [ python3Packages.setuptools ];

  # duckdb backs router-logd's query-log store. It comes prebuilt from the
  # binary cache, unlike the from-source Rust build pyturso needed.
  #
  # Directory integration adds nothing: it is stdlib-only (pwd/grp/os via NSS),
  # since SSSD owns the LDAP/AD connection.
  dependencies = with python3Packages; [
    duckdb
  ];

  makeWrapperArgs = [
    "--prefix PATH : ${lib.makeBinPath [ typst ]}"
  ];

  # Unit tests cover the HTTPS portal's block check (tests/test_portal.py:
  # the DNS wire format and the oracle's answers, against a fake server on
  # loopback). The technitium-vm NixOS test exercises everything end to end
  # (reconcile, compile, logd ingest/query, portal, report).
  nativeCheckInputs = [ python3Packages.unittestCheckHook ];
  unittestFlags = [
    "-s"
    "tests"
    "-v"
  ];

  pythonImportsCheck = [
    "router_dns_tools.compile_policies"
    "router_dns_tools.technitium_api"
    "router_dns_tools.local_dns"
    "router_dns_tools.portal"
    "router_dns_tools.directory_sync.sssd"
    "router_dns_tools.ddns"
    "router_dns_tools.cloudflare"
    "router_dns_tools.tunnel"
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
