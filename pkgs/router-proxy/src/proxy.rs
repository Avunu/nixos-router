//! HTTPS side: SNI certificate selection and the reverse proxy itself.

use crate::state::{strip_port, Route, Shared};
use async_trait::async_trait;
use log::{debug, info, warn};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::listeners::TlsAccept;
use pingora::prelude::*;
use pingora::protocols::tls::TlsRef;
use pingora::tls::ext;
use pingora::tls::ssl::NameType;
use std::any::Any;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Server name the client asked for in its ClientHello, attached to the
/// connection once the handshake completes.
struct Sni(String);

/// Presents the certificate matching the client's SNI.
pub struct CertSelector(pub Shared);

#[async_trait]
impl TlsAccept for CertSelector {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        let Some(sni) = ssl.servername(NameType::HOST_NAME).map(str::to_owned) else {
            debug!("TLS handshake without SNI; no certificate offered");
            return;
        };
        let state = self.0.load();
        let Some(cert) = state.cert_for(&sni) else {
            debug!("no certificate for SNI {sni:?}; handshake will fail");
            return;
        };
        let installed = ext::ssl_use_certificate(ssl, &cert.chain[0])
            .and_then(|_| {
                cert.chain[1..]
                    .iter()
                    .try_for_each(|c| ext::ssl_add_chain_cert(ssl, c))
            })
            .and_then(|_| ext::ssl_use_private_key(ssl, &cert.key));
        if let Err(e) = installed {
            warn!("installing certificate for {sni:?} failed: {e}");
        }
    }

    async fn handshake_complete_callback(
        &self,
        ssl: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        let sni = ssl.servername(NameType::HOST_NAME)?;
        Some(Arc::new(Sni(sni.to_ascii_lowercase())))
    }
}

/// What to do with a request, given the routes its Host and SNI select.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Proxy(usize),
    NotFound,
    Misdirected,
}

/// Refuse requests whose Host is served by a different route than the one the
/// TLS SNI selected, so one certificate cannot be used to reach another site.
pub fn decide(host_route: Option<usize>, sni_route: Option<usize>) -> Decision {
    match host_route {
        None => Decision::NotFound,
        Some(r) if sni_route == Some(r) => Decision::Proxy(r),
        Some(_) => Decision::Misdirected,
    }
}

/// Forwarding headers for the upstream. The router is the edge, with nothing
/// trusted in front of it (Cloudflare Tunnel reaches upstreams directly, not
/// through here), so every one of these is SET from what the proxy itself saw
/// and whatever the client sent is dropped. Appending to a client-supplied
/// `X-Forwarded-For` kept its claims, and an upstream reading the leftmost
/// entry believed them; an RFC 7239 `Forwarded` header passed straight through.
pub fn set_forwarding_headers(
    req: &mut RequestHeader,
    client: Option<IpAddr>,
    host: Option<&str>,
) -> Result<()> {
    for name in ["Forwarded", "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host"] {
        req.remove_header(name);
    }
    if let Some(ip) = client {
        let ip = ip.to_string();
        req.insert_header("X-Forwarded-For", ip.as_str())?;
        req.insert_header("X-Real-IP", ip)?;
    }
    req.insert_header("X-Forwarded-Proto", "https")?;
    if let Some(host) = host {
        req.insert_header("X-Forwarded-Host", host)?;
    }
    Ok(())
}

/// Host a request is addressed to: the Host header, else the HTTP/2 authority,
/// without port.
pub fn request_host(req: &RequestHeader) -> Option<String> {
    let raw = req
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri.authority().map(|a| a.as_str()))?;
    Some(crate::config::normalize_host(strip_port(raw)))
}

/// Client IP of a session, if it arrived over TCP.
pub fn client_ip(addr: Option<&pingora::protocols::l4::socket::SocketAddr>) -> Option<IpAddr> {
    addr.and_then(|a| a.as_inet())
        .map(|a| a.ip().to_canonical())
}

/// One access log line: `host method path status upstream duration_ms client_ip`.
pub fn access_log(
    host: Option<&str>,
    req: &RequestHeader,
    status: u16,
    upstream: &str,
    start: Instant,
    client: Option<IpAddr>,
) {
    info!(
        target: "access",
        "{} {} {} {} {} {} {}",
        host.unwrap_or("-"),
        req.method,
        req.uri.path(),
        status,
        upstream,
        start.elapsed().as_millis(),
        client.map_or_else(|| "-".to_owned(), |ip| ip.to_string()),
    );
}

/// Per-request context.
pub struct Ctx {
    start: Instant,
    host: Option<String>,
    route: Option<Arc<Route>>,
}

/// The HTTPS reverse proxy.
pub struct HttpsProxy(pub Shared);

#[async_trait]
impl ProxyHttp for HttpsProxy {
    type CTX = Ctx;

    fn new_ctx(&self) -> Ctx {
        Ctx {
            start: Instant::now(),
            host: None,
            route: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        let state = self.0.load();
        ctx.host = request_host(session.req_header());
        let sni = session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .and_then(|d| d.extension.get::<Sni>())
            .map(|s| s.0.clone());
        let host_route = ctx.host.as_deref().and_then(|h| state.route_index(h));
        let sni_route = sni.as_deref().and_then(|s| state.route_index(s));
        let status = match decide(host_route, sni_route) {
            Decision::Proxy(i) => {
                ctx.route = Some(state.routes[i].clone());
                return Ok(false);
            }
            Decision::NotFound => 404,
            Decision::Misdirected => {
                debug!("Host {:?} does not match SNI {sni:?}", ctx.host);
                421
            }
        };
        session.respond_error(status).await?;
        Ok(true)
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        let route = ctx
            .route
            .as_ref()
            .ok_or_else(|| Error::new(ErrorType::InternalError))?;
        let mut peer = HttpPeer::new(route.upstream, route.tls, route.sni.clone());
        let opts = &mut peer.options;
        opts.connection_timeout = Some(Duration::from_secs(10));
        opts.total_connection_timeout = Some(Duration::from_secs(15));
        // No read timeout: long polling and idle WebSockets must survive.
        opts.read_timeout = None;
        opts.write_timeout = Some(Duration::from_secs(60));
        opts.idle_timeout = Some(Duration::from_secs(60));
        if route.tls {
            opts.verify_cert = route.tls_verify;
            opts.verify_hostname = route.tls_verify;
        }
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        req: &mut RequestHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        set_forwarding_headers(req, client_ip(session.client_addr()), ctx.host.as_deref())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        resp: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        if ctx.route.as_ref().is_some_and(|r| r.hsts) {
            resp.insert_header("Strict-Transport-Security", "max-age=31536000")?;
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut Ctx) {
        let status = session.response_written().map_or(0, |r| r.status.as_u16());
        let upstream = ctx
            .route
            .as_ref()
            .map_or_else(|| "-".to_owned(), |r| r.upstream.to_string());
        let client = client_ip(session.client_addr());
        access_log(
            ctx.host.as_deref(),
            session.req_header(),
            status,
            &upstream,
            ctx.start,
            client,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_route_mismatch() {
        assert_eq!(decide(Some(1), Some(1)), Decision::Proxy(1));
        assert_eq!(decide(Some(1), Some(2)), Decision::Misdirected);
        assert_eq!(decide(Some(1), None), Decision::Misdirected);
        assert_eq!(decide(None, Some(1)), Decision::NotFound);
        assert_eq!(decide(None, None), Decision::NotFound);
    }

    #[test]
    fn forwarding_headers_replace_client_claims() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("X-Forwarded-For", "203.0.113.66").unwrap();
        req.append_header("X-Forwarded-For", "198.51.100.7").unwrap();
        req.insert_header("X-Real-IP", "203.0.113.66").unwrap();
        req.insert_header("Forwarded", "for=203.0.113.66").unwrap();
        req.insert_header("X-Forwarded-Host", "evil.test").unwrap();
        set_forwarding_headers(&mut req, Some("2001:db8::1".parse().unwrap()), Some("app.test"))
            .unwrap();
        let all = |name: &str| -> Vec<String> {
            req.headers
                .get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(all("x-forwarded-for"), ["2001:db8::1"]);
        assert_eq!(all("x-real-ip"), ["2001:db8::1"]);
        assert_eq!(all("x-forwarded-host"), ["app.test"]);
        assert_eq!(all("x-forwarded-proto"), ["https"]);
        assert!(all("forwarded").is_empty());

        // No peer address: the client's claims still go.
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("X-Forwarded-For", "203.0.113.66").unwrap();
        set_forwarding_headers(&mut req, None, None).unwrap();
        assert!(req.headers.get("x-forwarded-for").is_none());
        assert!(req.headers.get("x-forwarded-host").is_none());
    }

    #[test]
    fn host_from_header_or_authority() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("Host", "App.Test:10443").unwrap();
        assert_eq!(request_host(&req).as_deref(), Some("app.test"));
        let mut h2 = RequestHeader::build("GET", b"/", None).unwrap();
        h2.set_uri("https://h2.test:443/x".parse().unwrap());
        assert_eq!(request_host(&h2).as_deref(), Some("h2.test"));
    }
}
