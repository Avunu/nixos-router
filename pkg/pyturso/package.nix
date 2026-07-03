# ── pyturso ────────────────────────────────────────────────────────────────────
# Turso database Python bindings (DB-API 2.0), built from the tursodatabase/turso
# workspace with maturin/PyO3. Used by router-logd — the single process allowed
# to touch the query-log database (Turso does not support multi-process access).
#
# `src` is the `turso` flake input (tracked in flake.lock); the file format is
# SQLite-compatible, so stdlib sqlite3 remains a drop-in fallback should the
# bindings misbehave.
{
  lib,
  buildPythonPackage,
  rustPlatform,
  typing-extensions,
  src,
}:
buildPythonPackage {
  pname = "pyturso";
  # Read from the source workspace so it follows the flake input.
  version = (lib.importTOML "${src}/Cargo.toml").workspace.package.version;
  pyproject = true;

  inherit src;

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = "${src}/Cargo.lock";
    allowBuiltinFetchGit = true;
  };

  buildAndTestSubdir = "bindings/python";

  nativeBuildInputs = with rustPlatform; [
    cargoSetupHook
    maturinBuildHook
  ];

  dependencies = [ typing-extensions ];

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
