# ── router-dns-tools ───────────────────────────────────────────────────────────
# Python runtime tooling for the access-protection stack (see pyproject.toml
# for the CLI list) plus the pinned Technitium DNS app payloads consumed by
# modules/dns-technitium.nix.
#
# `typst` is wrapped onto PATH for router-report's PDF compilation.
{
  lib,
  python3Packages,
  fetchurl,
  runCommand,
  unzip,
  typst,
  pyturso,
}:
let
  # Official Technitium DNS app zips, pinned by hash. Folder name = app name
  # (DnsApplicationManager loads apps from <state>/apps/<Name>/), matching the
  # store names keeps `/api/apps/...?name=` parameters consistent.
  appZips = {
    "Advanced Blocking" = fetchurl {
      url = "https://download.technitium.com/dns/apps/AdvancedBlockingApp-v11.zip";
      hash = "sha256-2/hAJpJDOAtJlgiakkQHjrKzbhi8aWniZc5PcXXoEd8=";
    };
    "Log Exporter" = fetchurl {
      url = "https://download.technitium.com/dns/apps/LogExporterApp-v3.zip";
      hash = "sha256-M3XwlapPlRKxHwu5OQNT/PIE2uSxkd5YTcPbVdoEQDY=";
    };
    "Block Page" = fetchurl {
      url = "https://download.technitium.com/dns/apps/BlockPageApp-v8.zip";
      hash = "sha256-lz/LfpbpwyhR9IJaLQR+d4A9lafBdsiP+do6ltUUxiU=";
    };
  };

  technitiumApps =
    runCommand "technitium-dns-apps"
      {
        nativeBuildInputs = [ unzip ];
      }
      (
        lib.concatStringsSep "\n" (
          lib.mapAttrsToList (name: zip: ''
            mkdir -p "$out/${name}"
            unzip -q ${zip} -d "$out/${name}"
          '') appZips
        )
      );
in
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
