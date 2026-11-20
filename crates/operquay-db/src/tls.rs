#![forbid(unsafe_code)]

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream};
use tokio_rustls::client::TlsStream as RustlsStream;
use tokio_rustls::TlsConnector;

/// Returns `true` when Compliance Mode (`OPERQUAY_COMPLIANCE_MODE=1|true`) is active.
pub fn is_compliance_mode() -> bool {
    std::env::var("OPERQUAY_COMPLIANCE_MODE")
        .or_else(|_| std::env::var("COMPLIANCE_MODE"))
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Evaluate whether TLS must be negotiated for `ssl_mode`, rejecting plaintext when
/// `compliance_mode` is `true`.
pub fn should_use_tls_with_compliance(
    ssl_mode: &str,
    compliance_mode: bool,
) -> Result<bool, String> {
    let norm = ssl_mode.trim().to_ascii_lowercase();
    match norm.as_str() {
        "disable" | "off" | "none" => {
            if compliance_mode {
                Err(
                    "plaintext database connections (ssl_mode=disable) are forbidden in Compliance Mode"
                        .to_owned(),
                )
            } else {
                Ok(false)
            }
        }
        _ => Ok(true),
    }
}

pub fn should_use_tls(ssl_mode: &str) -> Result<bool, String> {
    should_use_tls_with_compliance(ssl_mode, is_compliance_mode())
}

#[derive(Debug)]
struct AcceptAnyEncryptedCert;

impl ServerCertVerifier for AcceptAnyEncryptedCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a pure-Rust TLS 1.2+ client connector (`ring` crypto provider + `webpki-roots`).
pub fn build_client_tls_connector(ssl_mode: &str) -> Result<TlsConnector, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS protocol versions error: {e}"))?;
    let norm = ssl_mode.trim().to_ascii_lowercase();
    let cfg = if matches!(norm.as_str(), "verify-ca" | "verify-full") {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyEncryptedCert))
            .with_no_client_auth()
    };
    Ok(TlsConnector::from(Arc::new(cfg)))
}

pub fn resolve_server_name(host: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(host.to_owned())
        .map_err(|e| format!("invalid TLS target host '{host}': {e}"))
}

/// Pure-Rust `tokio-postgres` TLS connector backed by `tokio-rustls` + `webpki-roots`.
#[derive(Clone)]
pub struct PgRustlsMakeTls {
    connector: TlsConnector,
}

impl PgRustlsMakeTls {
    pub fn new() -> Self {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring TLS versions")
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Self {
            connector: TlsConnector::from(Arc::new(config)),
        }
    }
}

impl Default for PgRustlsMakeTls {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PgRustlsConnect {
    connector: TlsConnector,
    domain: String,
}

pub struct PgRustlsStream<S>(RustlsStream<S>);

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for PgRustlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for PgRustlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream for PgRustlsStream<S> {
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> MakeTlsConnect<S> for PgRustlsMakeTls {
    type Stream = PgRustlsStream<S>;
    type TlsConnect = PgRustlsConnect;
    type Error = io::Error;

    fn make_tls_connect(&mut self, domain: &str) -> Result<Self::TlsConnect, Self::Error> {
        Ok(PgRustlsConnect {
            connector: self.connector.clone(),
            domain: domain.to_string(),
        })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> TlsConnect<S> for PgRustlsConnect {
    type Stream = PgRustlsStream<S>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Stream, Self::Error>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move {
            let server_name = ServerName::try_from(self.domain.clone()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid TLS host {}: {e}", self.domain),
                )
            })?;
            let tls_stream = self.connector.connect(server_name, stream).await?;
            Ok(PgRustlsStream(tls_stream))
        })
    }
}
