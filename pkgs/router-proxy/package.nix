# ── router-proxy ───────────────────────────────────────────────────────────────
# Hostname-routing HTTPS reverse proxy built on Cloudflare's Pingora. Reads a
# JSON config (see src/config.rs) and ACME certificates provisioned by
# security.acme; SIGHUP reloads both.
#
# pingora-openssl requests openssl's `vendored` feature; OPENSSL_NO_VENDOR makes
# openssl-sys link the nixpkgs OpenSSL instead, so security updates arrive with
# nixpkgs. cmake is for libz-ng-sys (flate2's zlib-ng backend).
{
  lib,
  rustPlatform,
  pkg-config,
  openssl,
  zstd,
  cmake,
}:
rustPlatform.buildRustPackage {
  pname = "router-proxy";
  version = "0.1.0";

  # Only what cargo reads: a local `cargo build` leaves a target/ that must not
  # end up in the store path (or change its hash).
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
    ];
  };
  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [
    pkg-config
    cmake
  ];
  # zstd: nixpkgs' cargo setup hook exports ZSTD_SYS_USE_PKG_CONFIG=1 for every
  # Rust build (since d4f25a3), so zstd-sys (pulled in by pingora-core) links the
  # system libzstd and probes for it with pkg-config. Without it here the probe
  # fails: "Package libzstd was not found". Older nixpkgs compiled a bundled zstd
  # and never probed, so there the input is unused.
  buildInputs = [
    openssl
    zstd
  ];

  env.OPENSSL_NO_VENDOR = 1;

  # cmake is only a build tool for a crate's build script, not the project's.
  dontUseCmakeConfigure = true;

  doCheck = true;

  meta = {
    description = "Hostname-routing HTTPS reverse proxy for the NixOS router (Pingora)";
    mainProgram = "router-proxy";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
