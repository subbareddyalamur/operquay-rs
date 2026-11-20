use std::sync::{Arc, Mutex};

use operquay_core::CertPolicy;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::Resumption;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

#[derive(Debug, Error)]
pub enum RdpTlsError {
    #[error("TLS handshake failed: {0}")]
    Handshake(#[from] std::io::Error),
    #[error("invalid server DNS/IP target: {0}")]
    InvalidTarget(String),
    #[error("server presented no leaf X.509 certificate")]
    MissingLeafCertificate,
    #[error("failed to extract X.509 public key from server certificate")]
    InvalidPublicKey,
}

#[derive(Debug)]
struct DerTlv<'a> {
    tag: u8,
    value: &'a [u8],
    total_len: usize,
}

fn parse_tlv(input: &[u8]) -> Option<DerTlv<'_>> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let first_len = input[1];
    let (len, header_len) = if first_len < 0x80 {
        (usize::from(first_len), 2)
    } else {
        let num_octets = usize::from(first_len & 0x7F);
        if num_octets == 0 || num_octets > 4 || input.len() < 2 + num_octets {
            return None;
        }
        let mut len = 0usize;
        for &b in &input[2..2 + num_octets] {
            len = (len << 8) | usize::from(b);
        }
        (len, 2 + num_octets)
    };
    let end = header_len.checked_add(len)?;
    if input.len() < end {
        return None;
    }
    Some(DerTlv {
        tag,
        value: &input[header_len..end],
        total_len: end,
    })
}

fn parse_sequence_children(seq_value: &[u8]) -> Option<Vec<DerTlv<'_>>> {
    let mut items = Vec::new();
    let mut rest = seq_value;
    while !rest.is_empty() {
        let tlv = parse_tlv(rest)?;
        rest = &rest[tlv.total_len..];
        items.push(tlv);
    }
    Some(items)
}

/// Extract leaf X.509 `SubjectPublicKeyInfo.subjectPublicKey` bit-string payload bytes
/// (stripping the leading unused-bits byte) per `[MS-CSSP] §2.2.1` for `CredSSP` binding.
#[must_use]
pub fn extract_x509_spki_pubkey(cert_der: &[u8]) -> Option<Vec<u8>> {
    let cert_seq = parse_tlv(cert_der)?;
    if cert_seq.tag != 0x30 {
        return None;
    }
    let cert_children = parse_sequence_children(cert_seq.value)?;
    let tbs = cert_children.first()?;
    if tbs.tag != 0x30 {
        return None;
    }
    let tbs_fields = parse_sequence_children(tbs.value)?;
    let mut idx = 0;
    if tbs_fields.first()?.tag == 0xA0 {
        idx += 1;
    }
    let spki = tbs_fields.get(idx + 5)?;
    if spki.tag != 0x30 {
        return None;
    }
    let spki_parts = parse_sequence_children(spki.value)?;
    let bit_string = spki_parts.get(1)?;
    if bit_string.tag != 0x03 || bit_string.value.len() < 2 {
        return None;
    }
    Some(bit_string.value[1..].to_vec())
}

#[derive(Debug)]
struct PolicyCertVerifier {
    policy: CertPolicy,
    expected_sha256: Option<[u8; 32]>,
    observed_sha256: Arc<Mutex<Option<[u8; 32]>>>,
    observed_spki_pubkey: Arc<Mutex<Option<Vec<u8>>>>,
    webpki_roots: RootCertStore,
}

impl ServerCertVerifier for PolicyCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if let Ok(mut g) = self.observed_sha256.lock() {
            *g = Some(digest);
        }
        if let Some(pubkey) = extract_x509_spki_pubkey(end_entity.as_ref()) {
            if let Ok(mut g) = self.observed_spki_pubkey.lock() {
                *g = Some(pubkey);
            }
        }

        match self.policy {
            CertPolicy::StrictCa => {
                let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(
                    self.webpki_roots.clone(),
                ))
                .build()
                .map_err(|_| rustls::Error::General("failed to build WebPKI verifier".into()))?;
                inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            }
            CertPolicy::TofuPinned => {
                if let Some(expected) = self.expected_sha256 {
                    if expected != digest {
                        return Err(rustls::Error::General(
                            "TOFU certificate SHA-256 mismatch against pinned host key".into(),
                        ));
                    }
                }
                Ok(ServerCertVerified::assertion())
            }
            CertPolicy::SsmLoopbackIgnore => Ok(ServerCertVerified::assertion()),
        }
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

pub struct TlsSessionInfo<S> {
    pub stream: TlsStream<S>,
    pub cert_sha256: [u8; 32],
    pub server_public_key: Vec<u8>,
}

/// Upgrade an established TCP or AWS SSM tunnel stream to pure-Rust TLS 1.2/1.3,
/// enforcing `StrictCa` / `TofuPinned` / `SsmLoopbackIgnore`, disabling TLS session
/// resumption per `[MS-CSSP]`, and extracting leaf SPKI public key bytes for `CredSSP` binding.
pub async fn upgrade_rdp_tls<S>(
    stream: S,
    target_host: &str,
    policy: CertPolicy,
    expected_sha256: Option<[u8; 32]>,
) -> Result<TlsSessionInfo<S>, RdpTlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let observed_sha256 = Arc::new(Mutex::new(None));
    let observed_spki_pubkey = Arc::new(Mutex::new(None));

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let verifier = Arc::new(PolicyCertVerifier {
        policy,
        expected_sha256,
        observed_sha256: observed_sha256.clone(),
        observed_spki_pubkey: observed_spki_pubkey.clone(),
        webpki_roots: roots,
    });

    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| RdpTlsError::Handshake(std::io::Error::other(e.to_string())))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
    // [MS-CSSP] CredSSP forbids TLS session resumption because SPKI channel binding is tied
    // to the handshake certificate.
    config.resumption = Resumption::disabled();

    let server_name = ServerName::try_from(target_host.to_owned())
        .or_else(|_| ServerName::try_from("localhost".to_owned()))
        .map_err(|_| RdpTlsError::InvalidTarget(target_host.to_owned()))?;

    let connector = TlsConnector::from(Arc::new(config));
    let tls_stream = connector.connect(server_name, stream).await?;

    let cert_sha256 = observed_sha256
        .lock()
        .ok()
        .and_then(|g| *g)
        .ok_or(RdpTlsError::MissingLeafCertificate)?;
    let server_public_key = observed_spki_pubkey
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .ok_or(RdpTlsError::InvalidPublicKey)?;

    Ok(TlsSessionInfo {
        stream: tls_stream,
        cert_sha256,
        server_public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_spki_pubkey_from_generated_rcgen_cert() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pubkey = extract_x509_spki_pubkey(cert.cert.der()).expect("spki pubkey");
        assert_ne!(pubkey.len(), 0);
    }
}
