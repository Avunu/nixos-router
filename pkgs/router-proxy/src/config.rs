//! JSON configuration, as rendered by the NixOS module.
//!
//! The field names (camelCase) are a contract with the Nix side; keep them in
//! sync with the module that writes `config.json`.

use serde::Deserialize;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Top-level configuration file.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub listen: Listen,
    /// Directory lego writes http-01 challenges into (`<webroot>/.well-known/acme-challenge/`).
    #[serde(default)]
    pub acme_webroot: Option<PathBuf>,
    #[serde(default)]
    pub routes: Vec<Route>,
}

/// Listener addresses. Only read at startup; changes need a restart.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Listen {
    #[serde(default)]
    pub http: Vec<String>,
    #[serde(default)]
    pub https: Vec<String>,
}

/// One virtual host: a set of hostnames proxied to a single upstream.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    /// Exact names or single-label wildcards (`*.example.com`).
    pub hostnames: Vec<String>,
    /// `ip:port` of the backend.
    pub upstream: String,
    /// Speak TLS to the upstream.
    #[serde(default)]
    pub tls: bool,
    /// Verify the upstream certificate and hostname (only with `tls`).
    #[serde(default)]
    pub tls_verify: bool,
    /// SNI sent upstream; defaults to the first hostname.
    #[serde(default)]
    pub sni: Option<String>,
    /// Add `Strict-Transport-Security` to responses.
    #[serde(default)]
    pub hsts: bool,
    /// Certificate served for this route's hostnames.
    #[serde(default)]
    pub cert: Option<CertPaths>,
}

/// PEM files provisioned by security.acme.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertPaths {
    pub fullchain: PathBuf,
    pub key: PathBuf,
}

impl Config {
    /// Read, parse and validate a configuration file.
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        Config::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Parse and validate configuration text.
    pub fn parse(text: &str) -> Result<Config, String> {
        let config: Config = serde_json::from_str(text).map_err(|e| e.to_string())?;
        config.validate()?;
        Ok(config)
    }

    /// Structural checks that serde cannot express.
    fn validate(&self) -> Result<(), String> {
        for addr in self.listen.http.iter().chain(&self.listen.https) {
            addr.parse::<SocketAddr>()
                .map_err(|e| format!("listen address {addr:?}: {e}"))?;
        }
        let mut seen = HashSet::new();
        for (i, route) in self.routes.iter().enumerate() {
            if route.hostnames.is_empty() {
                return Err(format!("route {i}: hostnames must not be empty"));
            }
            route
                .upstream
                .parse::<SocketAddr>()
                .map_err(|e| format!("route {i}: upstream {:?}: {e}", route.upstream))?;
            for name in &route.hostnames {
                validate_hostname(name).map_err(|e| format!("route {i}: {e}"))?;
                if !seen.insert(normalize_host(name)) {
                    return Err(format!(
                        "route {i}: hostname {name:?} appears in more than one route"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Accept `a.b.c` or `*.b.c`; reject empty labels, stray `*`, ports and whitespace.
fn validate_hostname(name: &str) -> Result<(), String> {
    let bare = name.strip_prefix("*.").unwrap_or(name);
    let ok = !bare.is_empty()
        && bare.split('.').all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        });
    if ok {
        Ok(())
    } else {
        Err(format!("invalid hostname {name:?}"))
    }
}

/// Canonical form used for all host comparisons: lower case, no trailing dot.
pub fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"{
      "listen": { "http": ["0.0.0.0:10080", "[::]:10080"], "https": ["0.0.0.0:10443", "[::]:10443"] },
      "acmeWebroot": "/var/lib/acme/acme-challenge",
      "routes": [{
        "hostnames": ["app.example.com", "www.app.example.com"],
        "upstream": "10.0.0.5:8080",
        "tls": false, "tlsVerify": false, "sni": "app.example.com", "hsts": false,
        "cert": { "fullchain": "/f.pem", "key": "/k.pem" }
      }]
    }"#;

    #[test]
    fn parses_full_contract() {
        let c = Config::parse(FULL).unwrap();
        assert_eq!(c.listen.https.len(), 2);
        assert_eq!(
            c.acme_webroot.as_deref(),
            Some(Path::new("/var/lib/acme/acme-challenge"))
        );
        let r = &c.routes[0];
        assert_eq!(r.sni.as_deref(), Some("app.example.com"));
        assert_eq!(r.cert.as_ref().unwrap().key, PathBuf::from("/k.pem"));
    }

    #[test]
    fn optional_fields_default() {
        let c = Config::parse(
            r#"{"listen":{"http":[],"https":[]},"acmeWebroot":null,
                "routes":[{"hostnames":["a.test"],"upstream":"[::1]:80","cert":null}]}"#,
        )
        .unwrap();
        assert!(c.acme_webroot.is_none());
        let r = &c.routes[0];
        assert!(!r.tls && !r.tls_verify && !r.hsts && r.sni.is_none() && r.cert.is_none());
    }

    #[test]
    fn rejects_invalid() {
        let bad = [
            r#"{"listen":{},"routes":[{"hostnames":[],"upstream":"1.2.3.4:80"}]}"#,
            r#"{"listen":{},"routes":[{"hostnames":["a.test"],"upstream":"host:80"}]}"#,
            r#"{"listen":{},"routes":[{"hostnames":["a.test"],"upstream":"1.2.3.4"}]}"#,
            r#"{"listen":{},"routes":[{"hostnames":["a.test"],"upstream":"1.2.3.4:1"},
                                      {"hostnames":["A.test"],"upstream":"1.2.3.4:2"}]}"#,
            r#"{"listen":{},"routes":[{"hostnames":["a.*.test"],"upstream":"1.2.3.4:80"}]}"#,
            r#"{"listen":{"http":["10080"]}}"#,
            r#"{"routes":[]}"#,
        ];
        for text in bad {
            assert!(Config::parse(text).is_err(), "accepted: {text}");
        }
    }
}
