//! router-proxy: hostname-routing HTTPS reverse proxy for the NixOS router.
//!
//! Runs in the foreground under systemd behind an nftables redirect
//! (WAN :80 -> listen.http, :443 -> listen.https), so it never binds
//! privileged ports. Certificates are issued externally (security.acme) and
//! only read here; `SIGHUP` re-reads the config file and all certificates.
//!
//! Usage: `router-proxy --config <file> [--check]`

mod config;
mod proxy;
mod redirect;
mod state;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use log::{error, info, warn};
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::TcpSocketOptions;
use pingora::prelude::*;
use pingora::server::configuration::ServerConf;
use pingora::server::ShutdownWatch;
use pingora::services::background::{background_service, BackgroundService};
use pingora::services::listening::Service;
use pingora::services::ServiceReadyNotifier;
use state::{Shared, State};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};

const USAGE: &str = "usage: router-proxy --config <file> [--check]";

fn main() -> ExitCode {
    // SIGHUP's default action is to terminate, and systemd counts that as a
    // CLEAN exit, so Restart=on-failure would leave the proxy down. A renewal
    // (or a rebuild) can reload the unit moments after it starts, before the
    // Reloader below has installed its handler — ignore the signal until then.
    // The Reloader's registration replaces this disposition.
    // SAFETY: called before any other thread exists; SIG_IGN is always valid.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None) // journald timestamps already
        .init();

    let (config_path, check) = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let state = match State::load(&config_path) {
        Ok(state) => state,
        Err(e) => {
            error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if check {
        println!(
            "{}: OK ({} routes)",
            config_path.display(),
            state.routes.len()
        );
        return ExitCode::SUCCESS;
    }
    run(config_path, state)
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<(PathBuf, bool), String> {
    let (mut path, mut check) = (None, false);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => path = Some(args.next().ok_or("--config needs a value")?.into()),
            "--check" => check = true,
            "-h" | "--help" => return Err("router-proxy".into()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok((path.ok_or("--config is required")?, check))
}

/// Start the listeners and block until pingora shuts down (SIGTERM/SIGINT).
fn run(config_path: PathBuf, state: State) -> ExitCode {
    let listen = state.config.listen.clone();
    let shared: Shared = Arc::new(ArcSwap::from_pointee(state));

    let conf = ServerConf {
        threads: std::thread::available_parallelism().map_or(2, |n| n.get().min(4)),
        // systemd waits for us to stop; keep shutdown well under TimeoutStopSec.
        grace_period_seconds: Some(1),
        graceful_shutdown_timeout_seconds: Some(5),
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    let mut http = Service::new("http redirect".into(), redirect::Redirector(shared.clone()));
    for addr in &listen.http {
        http.add_tcp_with_settings(addr, socket_options(addr));
    }

    let mut https = http_proxy_service(&server.configuration, proxy::HttpsProxy(shared.clone()));
    for addr in &listen.https {
        let mut tls =
            match TlsSettings::with_callbacks(Box::new(proxy::CertSelector(shared.clone()))) {
                Ok(tls) => tls,
                Err(e) => {
                    error!("TLS setup failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
        tls.enable_h2();
        https.add_tls_with_settings(addr, Some(socket_options(addr)), tls);
    }

    server.add_service(http);
    server.add_service(https);
    server.add_service(background_service(
        "reload",
        Reloader {
            config_path,
            shared,
        },
    ));
    info!(
        "listening on http {:?}, https {:?}",
        listen.http, listen.https
    );
    server.run_forever()
}

/// IPv6 sockets are v6-only so `0.0.0.0:P` and `[::]:P` can both be bound.
fn socket_options(addr: &str) -> TcpSocketOptions {
    let mut opts = TcpSocketOptions::default();
    if addr.parse::<SocketAddr>().is_ok_and(|a| a.is_ipv6()) {
        opts.ipv6_only = Some(true);
    }
    opts
}

/// Rebuilds [`State`] from disk on SIGHUP; a failed reload keeps the old state.
struct Reloader {
    config_path: PathBuf,
    shared: Shared,
}

impl Reloader {
    fn reload(&self) {
        match State::load(&self.config_path) {
            Ok(new) => {
                if new.config.listen != self.shared.load().config.listen {
                    warn!("listen addresses changed; restart router-proxy to apply them");
                }
                info!(
                    "reloaded {} ({} routes)",
                    self.config_path.display(),
                    new.routes.len()
                );
                self.shared.store(Arc::new(new));
            }
            Err(e) => error!("reload failed, keeping previous configuration: {e}"),
        }
    }
}

#[async_trait]
impl BackgroundService for Reloader {
    async fn start_with_ready_notifier(
        &self,
        mut shutdown: ShutdownWatch,
        ready: ServiceReadyNotifier,
    ) {
        let mut hangup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                error!("cannot watch SIGHUP, reload disabled: {e}");
                ready.notify_ready();
                return;
            }
        };
        ready.notify_ready();
        loop {
            tokio::select! {
                _ = hangup.recv() => self.reload(),
                _ = shutdown.changed() => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Result<(PathBuf, bool), String> {
        parse_args(v.iter().map(|s| s.to_string()))
    }

    #[test]
    fn cli() {
        assert_eq!(
            args(&["--config", "/c.json"]).unwrap(),
            ("/c.json".into(), false)
        );
        assert_eq!(
            args(&["--check", "--config", "c"]).unwrap(),
            ("c".into(), true)
        );
        assert!(args(&[]).is_err());
        assert!(args(&["--config"]).is_err());
        assert!(args(&["--bogus"]).is_err());
    }

    #[test]
    fn v6only_for_ipv6_listeners() {
        assert_eq!(socket_options("[::]:10443").ipv6_only, Some(true));
        assert_eq!(socket_options("0.0.0.0:10443").ipv6_only, None);
    }
}
