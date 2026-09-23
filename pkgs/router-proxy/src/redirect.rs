//! Plain-HTTP side: serves ACME http-01 challenges and redirects everything
//! else for known hosts to HTTPS. Nothing is ever proxied over plain HTTP.

use crate::proxy::{access_log, client_ip, request_host};
use crate::state::Shared;
use async_trait::async_trait;
use http::{header, Response, StatusCode};
use log::debug;
use pingora::apps::http_app::ServeHttp;
use pingora::protocols::http::ServerSession;
use std::path::Path;
use std::time::Instant;

const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// The port-80 application.
pub struct Redirector(pub Shared);

/// ACME tokens are base64url; anything else could escape the webroot.
pub fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn respond(
    status: StatusCode,
    extra: Option<(header::HeaderName, String)>,
    body: Vec<u8>,
) -> Response<Vec<u8>> {
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::CONTENT_LENGTH, body.len());
    if let Some((name, value)) = extra {
        builder = builder.header(name, value);
    }
    builder.body(body).expect("static response parts are valid")
}

fn not_found() -> Response<Vec<u8>> {
    respond(StatusCode::NOT_FOUND, None, b"Not Found\n".to_vec())
}

/// Serve `<webroot>/.well-known/acme-challenge/<token>` if it exists.
fn challenge(webroot: Option<&Path>, token: &str) -> Response<Vec<u8>> {
    let Some(webroot) = webroot.filter(|_| valid_token(token)) else {
        return not_found();
    };
    let path = webroot.join(".well-known/acme-challenge").join(token);
    match std::fs::read(&path) {
        Ok(body) => respond(StatusCode::OK, None, body),
        Err(e) => {
            debug!("ACME challenge {}: {e}", path.display());
            not_found()
        }
    }
}

#[async_trait]
impl ServeHttp for Redirector {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let start = Instant::now();
        let state = self.0.load();
        let req = session.req_header();
        let host = request_host(req);
        let path = req.uri.path();

        let response = match path.strip_prefix(CHALLENGE_PREFIX) {
            // Challenges are answered for any Host: lego validates names that
            // may not (yet) have a route.
            Some(token) if req.method == http::Method::GET => {
                challenge(state.config.acme_webroot.as_deref(), token)
            }
            _ => match host.as_deref().filter(|h| state.route_index(h).is_some()) {
                Some(h) => {
                    let target = req.uri.path_and_query().map_or("/", |pq| pq.as_str());
                    let location = format!("https://{h}{target}");
                    respond(
                        StatusCode::PERMANENT_REDIRECT,
                        Some((header::LOCATION, location)),
                        Vec::new(),
                    )
                }
                None => not_found(),
            },
        };

        let client = client_ip(session.client_addr());
        access_log(
            host.as_deref(),
            req,
            response.status().as_u16(),
            "-",
            start,
            client,
        );
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_validation() {
        assert!(valid_token("abc-DEF_123"));
        assert!(!valid_token(""));
        assert!(!valid_token(".."));
        assert!(!valid_token("../etc/passwd"));
        assert!(!valid_token("a/b"));
        assert!(!valid_token("a.b"));
        assert!(!valid_token("a%2fb"));
    }

    #[test]
    fn challenge_file_served() {
        let dir = std::env::temp_dir().join(format!("router-proxy-test-{}", std::process::id()));
        let challenges = dir.join(".well-known/acme-challenge");
        std::fs::create_dir_all(&challenges).unwrap();
        std::fs::write(challenges.join("tok_1"), "tok_1.key").unwrap();
        assert_eq!(challenge(Some(&dir), "tok_1").body(), b"tok_1.key");
        assert_eq!(
            challenge(Some(&dir), "missing").status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            challenge(Some(&dir), "../x").status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(challenge(None, "tok_1").status(), StatusCode::NOT_FOUND);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
