# ── pyturso ────────────────────────────────────────────────────────────────────
# Turso database Python bindings (DB-API 2.0), built from the tursodatabase/turso
# workspace with maturin/PyO3. Used by router-logd — the single process allowed
# to touch the query-log database (Turso does not support multi-process access).
#
# Pinned to a specific upstream commit; the file format is SQLite-compatible, so
# stdlib sqlite3 remains a drop-in fallback should the bindings misbehave.
{
  lib,
  python3Packages,
  rustPlatform,
  fetchFromGitHub,
}:
python3Packages.buildPythonPackage rec {
  pname = "pyturso";
  version = "0.7.0-pre.14";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "tursodatabase";
    repo = "turso";
    rev = "8f157dc1181e9892eea2c3032a316333ceb33092";
    hash = "sha256-qJxAOZqlrAZB/ODiW4aqzp+aiT5Gv1QMeSYwkWZDXjc=";
  };

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = "${src}/Cargo.lock";
    allowBuiltinFetchGit = true;
  };

  buildAndTestSubdir = "bindings/python";

  nativeBuildInputs = with rustPlatform; [
    cargoSetupHook
    maturinBuildHook
  ];

  dependencies = with python3Packages; [ typing-extensions ];

  # Upstream tests need pytest fixtures and a workspace checkout; the VM test
  # exercises the bindings end-to-end through router-logd instead.
  doCheck = false;

  pythonImportsCheck = [ "turso" ];

  meta = {
    description = "Turso database Python bindings (DB-API 2.0, in-process, SQLite-compatible)";
    homepage = "https://github.com/tursodatabase/turso";
    license = lib.licenses.mit;
  };
}
