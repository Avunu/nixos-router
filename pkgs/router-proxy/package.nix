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
  buildInputs = [ openssl ];

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
