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

/// Append the client address to an existing `X-Forwarded-For` value.
pub fn append_forwarded_for(existing: Option<&str>, client: &str) -> String {
    match existing.map(str::trim).filter(|v| !v.is_empty()) {
        Some(prior) => format!("{prior}, {client}"),
        None => client.to_owned(),
    }
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
        if let Some(ip) = client_ip(session.client_addr()) {
            let ip = ip.to_string();
            let prior: Vec<&str> = req
                .headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            let xff = append_forwarded_for(Some(prior.join(", ").as_str()), &ip);
            req.insert_header("X-Forwarded-For", xff)?;
            req.insert_header("X-Real-IP", ip)?;
        }
        req.insert_header("X-Forwarded-Proto", "https")?;
        if let Some(host) = &ctx.host {
            req.insert_header("X-Forwarded-Host", host.as_str())?;
        }
        Ok(())
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
    fn forwarded_for() {
        assert_eq!(append_forwarded_for(None, "192.0.2.1"), "192.0.2.1");
        assert_eq!(append_forwarded_for(Some(""), "192.0.2.1"), "192.0.2.1");
        assert_eq!(
            append_forwarded_for(Some("10.0.0.1"), "2001:db8::1"),
            "10.0.0.1, 2001:db8::1"
        );
        assert_eq!(
            append_forwarded_for(Some("10.0.0.1, 10.0.0.2 "), "192.0.2.1"),
            "10.0.0.1, 10.0.0.2, 192.0.2.1"
        );
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
