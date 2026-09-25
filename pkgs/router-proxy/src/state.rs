//! Runtime state derived from the configuration: parsed routes, loaded
//! certificates and the hostname lookup tables for both.
//!
//! A [`State`] is immutable once built; reloads build a fresh one and swap it
//! into the shared [`Shared`] handle atomically.

use crate::config::{normalize_host, CertPaths, Config};
use arc_swap::ArcSwap;
use log::warn;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

/// State shared between the listeners and the reload task.
pub type Shared = Arc<ArcSwap<State>>;

/// A validated route, ready for the proxy.
#[derive(Debug)]
pub struct Route {
    pub upstream: SocketAddr,
    pub tls: bool,
    pub tls_verify: bool,
    pub sni: String,
    pub hsts: bool,
}

/// A certificate chain (leaf first) and its private key.
pub struct CertKey {
    pub chain: Vec<X509>,
    pub key: PKey<Private>,
}

/// Everything a request needs, captured at one point in time.
pub struct State {
    pub config: Config,
    pub routes: Vec<Arc<Route>>,
    route_hosts: HostTable<usize>,
    cert_hosts: HostTable<Arc<CertKey>>,
}

impl State {
    /// Load the config file and every certificate it references.
    pub fn load(path: &Path) -> Result<State, String> {
        State::build(Config::load(path)?)
    }

    /// Build state from an already-validated config, loading certificates.
    pub fn build(config: Config) -> Result<State, String> {
        let mut routes = Vec::new();
        let mut route_hosts = HostTable::default();
        let mut cert_hosts = HostTable::default();
        let mut loaded: HashMap<&CertPaths, Arc<CertKey>> = HashMap::new();
        let mut san_names = Vec::new();

        for (i, r) in config.routes.iter().enumerate() {
            routes.push(Arc::new(Route {
                upstream: r.upstream.parse().map_err(|e| format!("route {i}: {e}"))?,
                tls: r.tls,
                tls_verify: r.tls_verify,
                sni: r.sni.clone().unwrap_or_else(|| r.hostnames[0].clone()),
                hsts: r.hsts,
            }));
            for name in &r.hostnames {
                route_hosts.insert(name, i);
            }
            let Some(paths) = &r.cert else { continue };
            let cert = match loaded.get(paths) {
                Some(c) => c.clone(),
                None => {
                    let c = Arc::new(load_cert(paths)?);
                    san_names.extend(dns_names(&c.chain[0]).into_iter().map(|n| (n, c.clone())));
                    loaded.insert(paths, c.clone());
                    c
                }
            };
            // The route's own names always select the route's cert.
            for name in &r.hostnames {
                cert_hosts.insert(name, cert.clone());
            }
        }
        // Names the certificates cover beyond their routes' hostnames fill gaps only.
        for (name, cert) in san_names {
            if cert_hosts.get_exact(&name).is_none() {
                cert_hosts.insert(&name, cert);
            }
        }
        for r in config.routes.iter().filter(|r| r.cert.is_none()) {
            for name in r
                .hostnames
                .iter()
                .filter(|n| cert_hosts.lookup(n).is_none())
            {
                warn!("hostname {name} has no certificate; HTTPS handshakes for it will fail");
            }
        }
        Ok(State {
            config,
            routes,
            route_hosts,
            cert_hosts,
        })
    }

    /// Index of the route serving `host` (already stripped of any port).
    pub fn route_index(&self, host: &str) -> Option<usize> {
        self.route_hosts.lookup(host).copied()
    }

    /// Certificate to present for a TLS server name.
    pub fn cert_for(&self, sni: &str) -> Option<&Arc<CertKey>> {
        self.cert_hosts.lookup(sni)
    }
}

/// Read a fullchain PEM (leaf first, then intermediates) and its key, and
/// check that they belong together.
fn load_cert(paths: &CertPaths) -> Result<CertKey, String> {
    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("reading {}: {e}", p.display()));
    let chain = X509::stack_from_pem(&read(&paths.fullchain)?)
        .map_err(|e| format!("parsing {}: {e}", paths.fullchain.display()))?;
    let key = PKey::private_key_from_pem(&read(&paths.key)?)
        .map_err(|e| format!("parsing {}: {e}", paths.key.display()))?;
    let leaf = chain
        .first()
        .ok_or_else(|| format!("{}: no certificates found", paths.fullchain.display()))?;
    let matches = leaf
        .public_key()
        .map(|pk| pk.public_eq(&key))
        .unwrap_or(false);
    if !matches {
        return Err(format!(
            "{} does not match certificate {}",
            paths.key.display(),
            paths.fullchain.display()
        ));
    }
    Ok(CertKey { chain, key })
}

/// DNS subject alternative names of a certificate.
fn dns_names(cert: &X509) -> Vec<String> {
    cert.subject_alt_names()
        .map(|sans| {
            sans.iter()
                .filter_map(|n| n.dnsname().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `host` (normalized, port stripped) is a DNS name: dot-separated
/// labels of 1-63 letters, digits, `-` or `_`. The Host header and SNI are
/// client input. Before this check the wildcard match accepted any first
/// label, so `evil.test/.example.com` matched `*.example.com` and then went
/// out in the redirect's `Location` and upstream as `X-Forwarded-Host`.
pub fn is_dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Remove a `:port` suffix from a Host header value (IPv6 literals keep their brackets).
pub fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host.find(']').map_or(host, |end| &host[..=end]);
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

/// Case-insensitive hostname map with single-label wildcard support.
struct HostTable<T> {
    exact: HashMap<String, T>,
    /// Keyed by the suffix after `*.`.
    wildcard: HashMap<String, T>,
}

impl<T> Default for HostTable<T> {
    fn default() -> Self {
        HostTable {
            exact: HashMap::new(),
            wildcard: HashMap::new(),
        }
    }
}

impl<T> HostTable<T> {
    fn insert(&mut self, name: &str, value: T) {
        let name = normalize_host(name);
        match name.strip_prefix("*.") {
            Some(suffix) => self.wildcard.insert(suffix.to_owned(), value),
            None => self.exact.insert(name, value),
        };
    }

    fn get_exact(&self, name: &str) -> Option<&T> {
        let name = normalize_host(name);
        match name.strip_prefix("*.") {
            Some(suffix) => self.wildcard.get(suffix),
            None => self.exact.get(&name),
        }
    }

    /// Exact match first, then a wildcard covering exactly one extra label.
    fn lookup(&self, host: &str) -> Option<&T> {
        let host = normalize_host(host);
        if !is_dns_name(&host) {
            return None;
        }
        self.exact
            .get(&host)
            .or_else(|| match host.split_once('.') {
                Some((label, rest)) if !label.is_empty() => self.wildcard.get(rest),
                _ => None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(json: &str) -> State {
        State::build(Config::parse(json).unwrap()).unwrap()
    }

    #[test]
    fn host_matching() {
        let s = state(
            r#"{"listen":{},"routes":[
                {"hostnames":["app.example.com"],"upstream":"10.0.0.1:80"},
                {"hostnames":["*.example.com"],"upstream":"10.0.0.2:80"},
                {"hostnames":["Mixed.Test"],"upstream":"10.0.0.3:80"}]}"#,
        );
        assert_eq!(s.route_index("app.example.com"), Some(0));
        assert_eq!(s.route_index("APP.Example.COM."), Some(0));
        assert_eq!(s.route_index("other.example.com"), Some(1));
        assert_eq!(s.route_index("a.b.example.com"), None);
        assert_eq!(s.route_index("example.com"), None);
        assert_eq!(s.route_index(".example.com"), None);
        // Client input: a wildcard covers one real DNS label, nothing else.
        assert_eq!(s.route_index("evil.test/.example.com"), None);
        assert_eq!(s.route_index("1869573999/.example.com"), None);
        assert_eq!(s.route_index("evil%2etest.example.com"), None);
        assert_eq!(s.route_index("a b.example.com"), None);
        assert_eq!(s.route_index("x-1_y.example.com"), Some(1));
        assert!(s.cert_for("evil.test/.example.com").is_none());
        assert_eq!(s.route_index("mixed.test"), Some(2));
        assert_eq!(s.route_index(strip_port("mixed.test:8443")), Some(2));
        assert_eq!(s.routes[2].sni, "Mixed.Test");
        assert!(s.cert_for("app.example.com").is_none());
    }

    #[test]
    fn port_stripping() {
        assert_eq!(strip_port("a.test"), "a.test");
        assert_eq!(strip_port("a.test:443"), "a.test");
        assert_eq!(strip_port("[::1]:443"), "[::1]");
        assert_eq!(strip_port("[::1]"), "[::1]");
        assert_eq!(strip_port("a.test:x"), "a.test:x");
    }

    #[test]
    fn missing_cert_is_an_error() {
        let c = Config::parse(
            r#"{"listen":{},"routes":[{"hostnames":["a.test"],"upstream":"1.1.1.1:1",
                "cert":{"fullchain":"/nonexistent/f.pem","key":"/nonexistent/k.pem"}}]}"#,
        )
        .unwrap();
        assert!(State::build(c).is_err());
    }
}
