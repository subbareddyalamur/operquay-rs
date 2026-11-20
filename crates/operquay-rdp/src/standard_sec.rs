#![forbid(unsafe_code)]

//! In-process pure-Rust `[MS-RDPBCGR]` §5.3–§5.4 Standard RDP Security transport
//! layer (`RC4` 40/56/128-bit + salted/unsalted `MD5`/`SHA-1` MAC + RSA PKCS/LE
//! `SecurityExchangePdu` over Proprietary v1 or X.509 v2 server certificates).
//!
//! Wraps an underlying `AsyncRead + AsyncWrite` stream behind `IronRDP` when the
//! server only offers Standard RDP Security (`SSL_NOT_ALLOWED_BY_SERVER`) or when
//! [`operquay_core::RdpSecurityMode::ClassicRdp`] is explicitly selected, with zero
//! sidecar containers and `#![forbid(unsafe_code)]`.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use ironrdp_pdu::gcc::{
    ConferenceCreateRequest, ConferenceCreateResponse, EncryptionLevel, EncryptionMethod,
    RdpVersion, ServerSecurityData,
};
use ironrdp_pdu::mcs::{ConnectInitial, ConnectResponse, SendDataIndication, SendDataRequest};
use ironrdp_pdu::rdp::server_license::cert::{CertificateType, X509CertificateChain};
use ironrdp_pdu::rdp::server_license::{LicensePdu, ServerCertificate};
use ironrdp_pdu::x224::{X224Data, X224};
use md5::{Digest as _, Md5};
use num_bigint::BigUint;
use operquay_core::OperquayError;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;

const PAD1: [u8; 40] = [0x36; 40];
const PAD2: [u8; 48] = [0x5C; 48];
const SALT_40_56: [u8; 3] = [0xD1, 0x26, 0x9E];

const SEC_EXCHANGE_PKT: u16 = 0x0001;
const SEC_TRANSPORT_REQ: u16 = 0x0002;
const SEC_TRANSPORT_RSP: u16 = 0x0004;
const SEC_ENCRYPT: u16 = 0x0008;
const SEC_INFO_PKT: u16 = 0x0040;
const SEC_LICENSE_PKT: u16 = 0x0080;
const SEC_REDIRECTION_PKT: u16 = 0x0400;
const SEC_SECURE_CHECKSUM: u16 = 0x0800;
const SEC_AUTODETECT_REQ: u16 = 0x1000;
const SEC_AUTODETECT_RSP: u16 = 0x2000;
const SEC_HEARTBEAT: u16 = 0x4000;

const KEEP_BASIC_HEADER_FLAGS: u16 = SEC_EXCHANGE_PKT
    | SEC_TRANSPORT_REQ
    | SEC_TRANSPORT_RSP
    | SEC_INFO_PKT
    | SEC_LICENSE_PKT
    | SEC_REDIRECTION_PKT
    | SEC_AUTODETECT_REQ
    | SEC_AUTODETECT_RSP
    | SEC_HEARTBEAT;

const FASTPATH_INPUT_SECURE_CHECKSUM: u8 = 0x40;
const FASTPATH_INPUT_ENCRYPTED: u8 = 0x80;
const FASTPATH_OUTPUT_SECURE_CHECKSUM: u8 = 0x40;
const FASTPATH_OUTPUT_ENCRYPTED: u8 = 0x80;

const CERT_CHAIN_VERSION_1: u32 = 0x0000_0001;
const CERT_CHAIN_VERSION_2: u32 = 0x0000_0002;
const CERT_CHAIN_VERSION_MASK: u32 = 0x7FFF_FFFF;
const BB_RSA_KEY_BLOB: u16 = 0x0006;
const MCS_GLOBAL_CHANNEL_ID: u16 = 1003;

/// Returns `true` when `IronRDP` failed X.224 negotiation specifically because the remote
/// Windows host only permits Standard RDP Security (`SSL_NOT_ALLOWED_BY_SERVER`).
#[must_use]
pub fn is_standard_rdp_only_error(err: &OperquayError) -> bool {
    let msg = err.to_string();
    msg.contains("server only supports Standard RDP Security")
        || msg.contains("SSL_NOT_ALLOWED_BY_SERVER")
}

/// Pure-Rust stateful RC4 stream cipher (`#![forbid(unsafe_code)]`).
#[derive(Clone)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (idx, slot) in s.iter_mut().enumerate() {
            *slot = idx as u8;
        }
        let mut j: u8 = 0;
        let key_len = key.len().max(1);
        for i in 0..256 {
            let k = key.get(i % key_len).copied().unwrap_or(0);
            j = j.wrapping_add(s[i]).wrapping_add(k);
            s.swap(i, usize::from(j));
        }
        Self { s, i: 0, j: 0 }
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        for b in data {
            self.i = self.i.wrapping_add(1);
            let si = self.s[usize::from(self.i)];
            self.j = self.j.wrapping_add(si);
            let sj = self.s[usize::from(self.j)];
            self.s.swap(usize::from(self.i), usize::from(self.j));
            let k = self.s[usize::from(si.wrapping_add(sj))];
            *b ^= k;
        }
    }
}

/// Extracted server RSA public key in little-endian modulus & exponent form (`MS-RDPBCGR §5.3.4`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKeyLe {
    pub modulus_le: Vec<u8>,
    pub exponent_le: Vec<u8>,
}

/// Parse RSA public key from `ServerCertificate` bytes (`CERT_CHAIN_VERSION_1` proprietary
/// terminal services certificate or `CERT_CHAIN_VERSION_2` X.509 certificate chain).
pub fn parse_server_rsa_key(server_cert: &[u8]) -> Result<RsaPublicKeyLe, io::Error> {
    if server_cert.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated RDP ServerCertificate",
        ));
    }
    let version = u32::from_le_bytes([
        server_cert[0],
        server_cert[1],
        server_cert[2],
        server_cert[3],
    ]) & CERT_CHAIN_VERSION_MASK;
    match version {
        CERT_CHAIN_VERSION_1 => parse_proprietary_rsa_key(&server_cert[4..]),
        CERT_CHAIN_VERSION_2 => parse_x509_chain_rsa_key(&server_cert[4..]),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported RDP ServerCertificate version {other}"),
        )),
    }
}

fn parse_proprietary_rsa_key(rest: &[u8]) -> Result<RsaPublicKeyLe, io::Error> {
    // dwSigAlgId(4) + dwKeyAlgId(4) + wPublicKeyBlobType(2) + wPublicKeyBlobLen(2)
    if rest.len() < 12 + 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated proprietary ServerCertificate",
        ));
    }
    let blob_type = u16::from_le_bytes([rest[8], rest[9]]);
    let blob_len = usize::from(u16::from_le_bytes([rest[10], rest[11]]));
    if blob_type != BB_RSA_KEY_BLOB || rest.len() < 12 + blob_len || blob_len < 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid proprietary public key blob (type={blob_type}, len={blob_len})"),
        ));
    }
    let blob = &rest[12..12 + blob_len];
    if &blob[0..4] != b"RSA1" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid RSA1 magic in proprietary ServerCertificate",
        ));
    }
    let keylen = usize::from(u16::from_le_bytes([blob[4], blob[5]]))
        | (usize::from(u16::from_le_bytes([blob[6], blob[7]])) << 16);
    if keylen <= 8 || blob.len() < 20 + keylen {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid proprietary RSA keylen {keylen}"),
        ));
    }
    let mod_len = keylen - 8;
    let exponent_le = blob[16..20].to_vec();
    let modulus_le = blob[20..20 + mod_len].to_vec();
    Ok(RsaPublicKeyLe {
        modulus_le,
        exponent_le,
    })
}

fn read_der_tlv<'a>(buf: &'a [u8], pos: &mut usize) -> Result<(u8, &'a [u8]), io::Error> {
    if *pos + 2 > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated DER TLV",
        ));
    }
    let tag = buf[*pos];
    let len_byte = buf[*pos + 1];
    *pos += 2;
    let len = if len_byte & 0x80 == 0 {
        usize::from(len_byte)
    } else {
        let count = usize::from(len_byte & 0x7F);
        if count == 0 || count > 4 || *pos + count > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid DER length",
            ));
        }
        let mut v = 0usize;
        for &b in &buf[*pos..*pos + count] {
            v = (v << 8) | usize::from(b);
        }
        *pos += count;
        v
    };
    if *pos + len > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DER TLV exceeds slice",
        ));
    }
    let val = &buf[*pos..*pos + len];
    *pos += len;
    Ok((tag, val))
}

fn parse_x509_chain_rsa_key(rest: &[u8]) -> Result<RsaPublicKeyLe, io::Error> {
    if rest.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing numCertBlobs in X.509 RDP chain",
        ));
    }
    let num_certs = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
    let mut off = 4usize;
    let mut last_cert: &[u8] = &[];
    for _ in 0..num_certs {
        if off + 4 > rest.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated cert length in X.509 RDP chain",
            ));
        }
        let clen =
            u32::from_le_bytes([rest[off], rest[off + 1], rest[off + 2], rest[off + 3]]) as usize;
        off += 4;
        if off + clen > rest.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated cert bytes in X.509 RDP chain",
            ));
        }
        last_cert = &rest[off..off + clen];
        off += clen;
    }
    extract_rsa_from_x509_der(last_cert)
}

/// Walk `Certificate -> TBSCertificate -> SubjectPublicKeyInfo -> BIT STRING (RSAPublicKey)`
/// and return the RSA `(modulus, exponent)` in MS-RDPBCGR little-endian byte order.
fn extract_rsa_from_x509_der(cert_der: &[u8]) -> Result<RsaPublicKeyLe, io::Error> {
    let mut p0 = 0usize;
    let (t_cert, cert_seq) = read_der_tlv(cert_der, &mut p0)?;
    if t_cert != 0x30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected X.509 Certificate SEQUENCE",
        ));
    }
    let mut p1 = 0usize;
    let (t_tbs, tbs_seq) = read_der_tlv(cert_seq, &mut p1)?;
    if t_tbs != 0x30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected X.509 TBSCertificate SEQUENCE",
        ));
    }
    let mut p2 = 0usize;
    // Optional [0] version tag
    if p2 < tbs_seq.len() && tbs_seq[p2] == 0xA0 {
        let _ = read_der_tlv(tbs_seq, &mut p2)?;
    }
    // serialNumber, signature, issuer, validity, subject (5 fields)
    for _ in 0..5 {
        let _ = read_der_tlv(tbs_seq, &mut p2)?;
    }
    let (t_spki, spki_seq) = read_der_tlv(tbs_seq, &mut p2)?;
    if t_spki != 0x30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected X.509 SubjectPublicKeyInfo SEQUENCE",
        ));
    }
    let mut p3 = 0usize;
    let (_alg_tag, alg_val) = read_der_tlv(spki_seq, &mut p3)?;
    // Verify rsaEncryption OID 1.2.840.113549.1.1.1 (06 09 2a 86 48 86 f7 0d 01 01 01)
    let rsa_oid = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    if !alg_val.starts_with(&rsa_oid) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "X.509 server certificate does not use RSA SubjectPublicKeyInfo",
        ));
    }
    let (tag_bit_str, bit_string) = read_der_tlv(spki_seq, &mut p3)?;
    if tag_bit_str != 0x03 || bit_string.is_empty() || bit_string[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SubjectPublicKey BIT STRING",
        ));
    }
    let mut p4 = 0usize;
    let (t_rsa, rsa_seq) = read_der_tlv(&bit_string[1..], &mut p4)?;
    if t_rsa != 0x30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected PKCS#1 RSAPublicKey SEQUENCE",
        ));
    }
    let mut p5 = 0usize;
    let (t_mod, mut mod_be) = read_der_tlv(rsa_seq, &mut p5)?;
    let (t_exp, mut exp_be) = read_der_tlv(rsa_seq, &mut p5)?;
    if t_mod != 0x02 || t_exp != 0x02 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected INTEGER modulus/exponent in RSAPublicKey",
        ));
    }
    while mod_be.len() > 1 && mod_be[0] == 0 {
        mod_be = &mod_be[1..];
    }
    while exp_be.len() > 1 && exp_be[0] == 0 {
        exp_be = &exp_be[1..];
    }
    let mut modulus_le = mod_be.to_vec();
    modulus_le.reverse();
    let mut exponent_le = exp_be.to_vec();
    exponent_le.reverse();
    Ok(RsaPublicKeyLe {
        modulus_le,
        exponent_le,
    })
}

/// Encrypt `input_le` using textbook little-endian RSA (`MS-RDPBCGR §5.3.4`), matching
/// `FreeRDP` `crypto_rsa_common`: reverse LE inputs -> BE `modpow` -> reverse output padded
/// with trailing zeros up to `modulus_le.len()`.
#[must_use]
pub fn rsa_public_encrypt_le(input_le: &[u8], key: &RsaPublicKeyLe) -> Vec<u8> {
    let mod_be: Vec<u8> = key.modulus_le.iter().copied().rev().collect();
    let exp_be: Vec<u8> = key.exponent_le.iter().copied().rev().collect();
    let in_be: Vec<u8> = input_le.iter().copied().rev().collect();

    let n = BigUint::from_bytes_be(&mod_be);
    let e = BigUint::from_bytes_be(&exp_be);
    let x = BigUint::from_bytes_be(&in_be);
    let y = x.modpow(&e, &n);
    let mut out_le = y.to_bytes_be();
    out_le.reverse();
    out_le.resize(key.modulus_le.len(), 0);
    out_le
}

fn push_der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut bytes = len.to_be_bytes();
        let first_nz = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        let tail = &mut bytes[first_nz..];
        out.push(0x80 | (tail.len() as u8));
        out.extend_from_slice(tail);
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + content.len());
    out.push(tag);
    push_der_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

fn der_unsigned_int_from_le(le_bytes: &[u8]) -> Vec<u8> {
    let mut be: Vec<u8> = le_bytes.iter().copied().rev().collect();
    let first_nz = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    let trimmed = &be[first_nz..];
    let mut val = Vec::with_capacity(1 + trimmed.len());
    if (trimmed[0] & 0x80) != 0 {
        val.push(0x00);
    }
    val.extend_from_slice(trimmed);
    be.clear();
    der_tlv(0x02, &val)
}

/// Wrap an extracted RSA public key in a minimal RFC 5280 DER X.509 certificate chain
/// (two certificates, satisfying `[MS-RDPELE] 2.2.1.4.2` / `IronRDP`'s `MIN_CERTIFICATE_AMOUNT`).
///
/// Used when Windows sends `ServerLicenseRequest` with `cert_blob.length == 0` under Standard
/// RDP Security (relying on `ServerSecurityData.serverCert` from `Connect-Response`) OR sends a
/// Proprietary v1 certificate whose little-endian modulus `ironrdp-pdu 0.11` mis-encodes.
fn build_synthetic_x509_chain_for_rsa_key(key: &RsaPublicKeyLe) -> X509CertificateChain {
    // sha256WithRSAEncryption: 1.2.840.113549.1.1.11 + NULL
    let sha256_rsa_alg = der_tlv(
        0x30,
        &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
        ],
    );
    // rsaEncryption: 1.2.840.113549.1.1.1 + NULL
    let rsa_alg = der_tlv(
        0x30,
        &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
        ],
    );
    let cn_attr = der_tlv(
        0x30,
        &[0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, b'r', b'd', b'p'],
    );
    let name = der_tlv(0x30, &der_tlv(0x31, &cn_attr));
    let mut validity_body = der_tlv(0x17, b"240101000000Z");
    validity_body.extend_from_slice(&der_tlv(0x17, b"350101000000Z"));
    let validity = der_tlv(0x30, &validity_body);

    let mut rsa_pub_body = der_unsigned_int_from_le(&key.modulus_le);
    rsa_pub_body.extend_from_slice(&der_unsigned_int_from_le(&key.exponent_le));
    let rsa_pub_der = der_tlv(0x30, &rsa_pub_body);

    let mut bit_string_body = Vec::with_capacity(1 + rsa_pub_der.len());
    bit_string_body.push(0x00);
    bit_string_body.extend_from_slice(&rsa_pub_der);
    let subject_pub_key_bitstr = der_tlv(0x03, &bit_string_body);

    let mut spki_body = rsa_alg;
    spki_body.extend_from_slice(&subject_pub_key_bitstr);
    let spki = der_tlv(0x30, &spki_body);

    let mut tbs_body = Vec::new();
    // [0] EXPLICIT Version v3 (2)
    tbs_body.extend_from_slice(&der_tlv(0xA0, &der_tlv(0x02, &[0x02])));
    // serialNumber INTEGER 1
    tbs_body.extend_from_slice(&der_tlv(0x02, &[0x01]));
    // signature
    tbs_body.extend_from_slice(&sha256_rsa_alg);
    // issuer
    tbs_body.extend_from_slice(&name);
    // validity
    tbs_body.extend_from_slice(&validity);
    // subject
    tbs_body.extend_from_slice(&name);
    // subjectPublicKeyInfo
    tbs_body.extend_from_slice(&spki);
    let tbs = der_tlv(0x30, &tbs_body);

    let mut cert_body = tbs;
    cert_body.extend_from_slice(&sha256_rsa_alg);
    cert_body.extend_from_slice(&der_tlv(0x03, &[0x00, 0x01]));
    let cert_der = der_tlv(0x30, &cert_body);

    X509CertificateChain {
        certificate_array: vec![cert_der.clone(), cert_der],
    }
}

fn ensure_x509_license_request_cert(
    user_data: &mut Vec<u8>,
    cached_key: Option<&RsaPublicKeyLe>,
) -> Result<(), io::Error> {
    let Ok(LicensePdu::ServerLicenseRequest(mut req)) =
        ironrdp_pdu::decode::<LicensePdu>(user_data)
    else {
        return Ok(());
    };

    let needs_x509 = match &req.server_certificate {
        None => true,
        Some(cert) => matches!(cert.certificate, CertificateType::Proprietary(_)),
    };
    if !needs_x509 {
        return Ok(());
    }

    let extracted_from_prop;
    let rsa_key = match (&req.server_certificate, cached_key) {
        (_, Some(k)) => k,
        (Some(cert), None) => match &cert.certificate {
            CertificateType::Proprietary(prop) => {
                let raw_mod = &prop.public_key.modulus;
                let mod_len = raw_mod.len().saturating_sub(8);
                extracted_from_prop = RsaPublicKeyLe {
                    modulus_le: raw_mod[..mod_len].to_vec(),
                    exponent_le: prop.public_key.public_exponent.to_le_bytes().to_vec(),
                };
                &extracted_from_prop
            }
            CertificateType::X509(_) => return Ok(()),
        },
        (None, None) => return Ok(()),
    };

    req.server_certificate = Some(ServerCertificate {
        issued_permanently: false,
        certificate: CertificateType::X509(build_synthetic_x509_chain_for_rsa_key(rsa_key)),
    });
    let total_size = req.size();
    if let Ok(preamble_size) = u16::try_from(total_size.saturating_sub(4)) {
        req.license_header.preamble_message_size = preamble_size;
    }
    *user_data = ironrdp_pdu::encode_vec(&LicensePdu::ServerLicenseRequest(req))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(())
}

fn salted_hash(salt48: &[u8; 48], input: &[u8], salt1: &[u8; 32], salt2: &[u8; 32]) -> [u8; 16] {
    let mut sha1 = Sha1::new();
    sha1.update(input);
    sha1.update(salt48);
    sha1.update(salt1);
    sha1.update(salt2);
    let sha1_digest = sha1.finalize();

    let mut md5 = Md5::new();
    md5.update(salt48);
    md5.update(sha1_digest);
    md5.finalize().into()
}

fn derive_48(salt48: &[u8; 48], labels: [&[u8]; 3], s1: &[u8; 32], s2: &[u8; 32]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[0..16].copy_from_slice(&salted_hash(salt48, labels[0], s1, s2));
    out[16..32].copy_from_slice(&salted_hash(salt48, labels[1], s1, s2));
    out[32..48].copy_from_slice(&salted_hash(salt48, labels[2], s1, s2));
    out
}

fn md5_16_32_32(in0: &[u8], in1: &[u8; 32], in2: &[u8; 32]) -> [u8; 16] {
    let mut md5 = Md5::new();
    md5.update(in0);
    md5.update(in1);
    md5.update(in2);
    md5.finalize().into()
}

fn update_rc4_key(key: &mut [u8], update_key: &[u8], key_len: usize, method: EncryptionMethod) {
    let mut sha1 = Sha1::new();
    sha1.update(&update_key[..key_len]);
    sha1.update(PAD1);
    sha1.update(&key[..key_len]);
    let sha1h = sha1.finalize();

    let mut md5 = Md5::new();
    md5.update(&update_key[..key_len]);
    md5.update(PAD2);
    md5.update(sha1h);
    let md5_out: [u8; 16] = md5.finalize().into();
    key[..16].copy_from_slice(&md5_out);

    let mut tmp = Rc4::new(&key[..key_len]);
    tmp.apply(&mut key[..key_len]);

    if method == EncryptionMethod::BIT_40 {
        key[..3].copy_from_slice(&SALT_40_56);
    } else if method == EncryptionMethod::BIT_56 {
        key[0] = SALT_40_56[0];
    }
}

/// Stateful client/server Standard RDP Security RC4 engine (`[MS-RDPBCGR] §5.3.5–§5.3.6`).
pub struct StandardRdpCipher {
    method: EncryptionMethod,
    rc4_key_len: usize,
    salted_checksum: bool,
    sign_key: [u8; 16],
    encrypt_key: [u8; 16],
    encrypt_update_key: [u8; 16],
    rc4_encrypt: Rc4,
    encrypt_use_count: u32,
    encrypt_checksum_use_count: u32,
    decrypt_key: [u8; 16],
    decrypt_update_key: [u8; 16],
    rc4_decrypt: Rc4,
    decrypt_use_count: u32,
    decrypt_checksum_use_count: u32,
}

impl StandardRdpCipher {
    pub fn from_randoms(
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        method: EncryptionMethod,
        salted_checksum: bool,
    ) -> Result<Self, io::Error> {
        let rc4_key_len = if method == EncryptionMethod::BIT_128 {
            16
        } else if method == EncryptionMethod::BIT_40 || method == EncryptionMethod::BIT_56 {
            8
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported Standard RDP encryption method {method:?}"),
            ));
        };

        let mut pre_master_secret = [0u8; 48];
        pre_master_secret[..24].copy_from_slice(&client_random[..24]);
        pre_master_secret[24..].copy_from_slice(&server_random[..24]);

        let master_secret = derive_48(
            &pre_master_secret,
            [b"A", b"BB", b"CCC"],
            client_random,
            server_random,
        );
        let session_key_blob = derive_48(
            &master_secret,
            [b"X", b"YY", b"ZZZ"],
            client_random,
            server_random,
        );

        let mut sign_key = [0u8; 16];
        sign_key.copy_from_slice(&session_key_blob[0..16]);

        let mut decrypt_key = md5_16_32_32(&session_key_blob[16..32], client_random, server_random);
        let mut encrypt_key = md5_16_32_32(&session_key_blob[32..48], client_random, server_random);

        if method == EncryptionMethod::BIT_40 {
            sign_key[..3].copy_from_slice(&SALT_40_56);
            decrypt_key[..3].copy_from_slice(&SALT_40_56);
            encrypt_key[..3].copy_from_slice(&SALT_40_56);
        } else if method == EncryptionMethod::BIT_56 {
            sign_key[0] = SALT_40_56[0];
            decrypt_key[0] = SALT_40_56[0];
            encrypt_key[0] = SALT_40_56[0];
        }

        let rc4_encrypt = Rc4::new(&encrypt_key[..rc4_key_len]);
        let rc4_decrypt = Rc4::new(&decrypt_key[..rc4_key_len]);

        Ok(Self {
            method,
            rc4_key_len,
            salted_checksum,
            sign_key,
            encrypt_key,
            encrypt_update_key: encrypt_key,
            rc4_encrypt,
            encrypt_use_count: 0,
            encrypt_checksum_use_count: 0,
            decrypt_key,
            decrypt_update_key: decrypt_key,
            rc4_decrypt,
            decrypt_use_count: 0,
            decrypt_checksum_use_count: 0,
        })
    }

    fn compute_mac(&self, plaintext: &[u8], salted: bool, use_count: u32) -> [u8; 8] {
        let mut sha1 = Sha1::new();
        sha1.update(&self.sign_key[..self.rc4_key_len]);
        sha1.update(PAD1);
        sha1.update((plaintext.len() as u32).to_le_bytes());
        sha1.update(plaintext);
        if salted {
            sha1.update(use_count.to_le_bytes());
        }
        let sha1_digest = sha1.finalize();

        let mut md5 = Md5::new();
        md5.update(&self.sign_key[..self.rc4_key_len]);
        md5.update(PAD2);
        md5.update(sha1_digest);
        let digest = md5.finalize();
        let mut mac = [0u8; 8];
        mac.copy_from_slice(&digest[..8]);
        mac
    }

    /// Compute Standard RDP MAC over `data`, encrypt `data` in place, update counters/keys, and return 8-byte MAC.
    pub fn encrypt(&mut self, data: &mut [u8]) -> [u8; 8] {
        if self.encrypt_use_count >= 4096 {
            update_rc4_key(
                &mut self.encrypt_key,
                &self.encrypt_update_key,
                self.rc4_key_len,
                self.method,
            );
            self.rc4_encrypt = Rc4::new(&self.encrypt_key[..self.rc4_key_len]);
            self.encrypt_use_count = 0;
        }
        let mac = self.compute_mac(data, self.salted_checksum, self.encrypt_checksum_use_count);
        self.rc4_encrypt.apply(data);
        self.encrypt_use_count += 1;
        self.encrypt_checksum_use_count += 1;
        mac
    }

    /// Decrypt `data` in place, update counters/keys, and verify the 8-byte MAC.
    pub fn decrypt_and_verify(
        &mut self,
        data: &mut [u8],
        mac_wire: &[u8],
        salted: bool,
    ) -> Result<(), io::Error> {
        if self.decrypt_use_count >= 4096 {
            update_rc4_key(
                &mut self.decrypt_key,
                &self.decrypt_update_key,
                self.rc4_key_len,
                self.method,
            );
            self.rc4_decrypt = Rc4::new(&self.decrypt_key[..self.rc4_key_len]);
            self.decrypt_use_count = 0;
        }
        self.rc4_decrypt.apply(data);
        self.decrypt_use_count += 1;
        self.decrypt_checksum_use_count += 1;

        let expected = self.compute_mac(data, salted, self.decrypt_checksum_use_count - 1);
        if expected.as_slice() != mac_wire {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Standard RDP MAC verification failed",
            ));
        }
        Ok(())
    }
}

/// Extract one complete Slow-Path `TPKT` or `Fast-Path` packet from `buf`.
fn extract_next_rdp_packet(buf: &mut BytesMut) -> Result<Option<Vec<u8>>, io::Error> {
    if buf.is_empty() {
        return Ok(None);
    }
    let first = buf[0];
    if first == 0x03 {
        if buf.len() < 4 {
            return Ok(None);
        }
        let total_len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
        if total_len < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid TPKT length {total_len}"),
            ));
        }
        if buf.len() < total_len {
            return Ok(None);
        }
        return Ok(Some(buf.split_to(total_len).to_vec()));
    }
    if first.trailing_zeros() >= 2 {
        if buf.len() < 2 {
            return Ok(None);
        }
        let len1 = buf[1];
        let total_len = if (len1 & 0x80) == 0 {
            usize::from(len1)
        } else {
            if buf.len() < 3 {
                return Ok(None);
            }
            (usize::from(len1 & 0x7F) << 8) | usize::from(buf[2])
        };
        if total_len < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid Fast-Path packet length {total_len}"),
            ));
        }
        if buf.len() < total_len {
            return Ok(None);
        }
        return Ok(Some(buf.split_to(total_len).to_vec()));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected RDP frame header byte 0x{first:02x}"),
    ))
}

fn encode_fastpath_packet(header_byte0: u8, payload: &[u8]) -> Vec<u8> {
    let short_total = 2 + payload.len();
    if short_total < 128 {
        let mut out = Vec::with_capacity(short_total);
        out.push(header_byte0);
        out.push(short_total as u8);
        out.extend_from_slice(payload);
        out
    } else {
        let long_total = 3 + payload.len();
        let mut out = Vec::with_capacity(long_total);
        out.push(header_byte0);
        out.push(0x80 | ((long_total >> 8) as u8 & 0x7F));
        out.push((long_total & 0xFF) as u8);
        out.extend_from_slice(payload);
        out
    }
}

fn hex_prefix(bytes: &[u8], limit: usize) -> String {
    bytes
        .iter()
        .take(limit)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn fastpath_header_len(pkt: &[u8]) -> usize {
    if pkt.len() >= 2 && (pkt[1] & 0x80) != 0 {
        3
    } else {
        2
    }
}

/// Transparent `AsyncRead + AsyncWrite` wrapper allowing `IronRDP 0.17` to operate
/// against Windows servers configured for Standard RDP Security (`SecurityLayer = 0`,
/// `MinEncryptionLevel >= 1`) in pure Rust without any sidecars.
pub struct StandardRdpSecurityStream<S> {
    inner: S,
    write_buf: BytesMut,
    wire_out: VecDeque<u8>,
    read_wire_buf: BytesMut,
    plain_in: BytesMut,
    cipher: Option<StandardRdpCipher>,
    server_rsa_key: Option<RsaPublicKeyLe>,
    pending_sec_exchange: Option<Vec<u8>>,
    io_channel_id: u16,
    static_channel_ids: Vec<u16>,
    message_channel_id: Option<u16>,
    demand_active_seen: bool,
    server_encrypted_license: bool,
}

impl<S> StandardRdpSecurityStream<S> {
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            write_buf: BytesMut::with_capacity(16 * 1024),
            wire_out: VecDeque::with_capacity(16 * 1024),
            read_wire_buf: BytesMut::with_capacity(32 * 1024),
            plain_in: BytesMut::with_capacity(32 * 1024),
            cipher: None,
            server_rsa_key: None,
            pending_sec_exchange: None,
            io_channel_id: MCS_GLOBAL_CHANNEL_ID,
            static_channel_ids: Vec::new(),
            message_channel_id: None,
            demand_active_seen: false,
            server_encrypted_license: false,
        }
    }

    fn process_outbound_packet(&mut self, pkt: &[u8]) -> Result<(), io::Error> {
        if pkt.first() == Some(&0x03) {
            if pkt.len() >= 9 && pkt[4..7] == [0x02, 0xF0, 0x80] {
                // Outbound MCS Connect-Initial
                if pkt[7] == 0x7F && pkt[8] == 0x65 {
                    let x224_data = ironrdp_pdu::decode::<X224<X224Data<'_>>>(pkt)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
                        .0;
                    let mut ci = ironrdp_pdu::decode::<ConnectInitial>(x224_data.data.as_ref())
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    let mut gcc = ci.conference_create_request.gcc_blocks().clone();
                    gcc.security.encryption_methods = EncryptionMethod::BIT_40
                        | EncryptionMethod::BIT_56
                        | EncryptionMethod::BIT_128;
                    gcc.security.ext_encryption_methods = 0;
                    ci.conference_create_request = ConferenceCreateRequest::new(gcc)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    let ci_bytes = ironrdp_pdu::encode_vec(&ci)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    let rewritten = ironrdp_pdu::encode_vec(&X224(X224Data {
                        data: Cow::Owned(ci_bytes),
                    }))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    self.wire_out.extend(rewritten);
                    return Ok(());
                }

                // Outbound MCS SendDataRequest
                if (pkt[7] & 0xFC) == 0x64 {
                    let sdr = ironrdp_pdu::decode::<X224<SendDataRequest<'_>>>(pkt)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
                        .0;
                    if let Some(exch_user_data) = self.pending_sec_exchange.take() {
                        let exch_pdu = X224(SendDataRequest {
                            initiator_id: sdr.initiator_id,
                            channel_id: self.io_channel_id,
                            user_data: Cow::Owned(exch_user_data),
                        });
                        let encoded = ironrdp_pdu::encode_vec(&exch_pdu).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?;
                        self.wire_out.extend(encoded);
                    }
                    if let Some(cipher) = self.cipher.as_mut() {
                        let user_data = sdr.user_data.as_ref();
                        let has_basic_hdr = if Some(sdr.channel_id) == self.message_channel_id {
                            user_data.len() >= 4
                                && u16::from_le_bytes([user_data[2], user_data[3]]) == 0
                                && (u16::from_le_bytes([user_data[0], user_data[1]])
                                    & (SEC_AUTODETECT_REQ | SEC_AUTODETECT_RSP | SEC_HEARTBEAT))
                                    != 0
                        } else if self.static_channel_ids.contains(&sdr.channel_id) {
                            false
                        } else {
                            !self.demand_active_seen
                                || (user_data.len() == 12
                                    && u16::from_le_bytes([user_data[0], user_data[1]])
                                        == SEC_TRANSPORT_RSP
                                    && user_data[2] == 0
                                    && user_data[3] == 0)
                                || (user_data.len() >= 10
                                    && u16::from_le_bytes([user_data[2], user_data[3]]) == 0
                                    && (u16::from_le_bytes([user_data[0], user_data[1]])
                                        & (SEC_AUTODETECT_REQ
                                            | SEC_AUTODETECT_RSP
                                            | SEC_HEARTBEAT))
                                        != 0)
                        };
                        let encrypted_user_data = if has_basic_hdr && user_data.len() >= 4 {
                            let existing_flags = u16::from_le_bytes([user_data[0], user_data[1]]);
                            if (existing_flags & SEC_LICENSE_PKT) != 0
                                && !self.server_encrypted_license
                            {
                                user_data.to_vec()
                            } else {
                                let flags = existing_flags
                                    | SEC_ENCRYPT
                                    | if cipher.salted_checksum {
                                        SEC_SECURE_CHECKSUM
                                    } else {
                                        0
                                    };
                                let mut body = user_data[4..].to_vec();
                                let mac = cipher.encrypt(&mut body);
                                let mut out = Vec::with_capacity(12 + body.len());
                                out.extend_from_slice(&flags.to_le_bytes());
                                out.extend_from_slice(&user_data[2..4]);
                                out.extend_from_slice(&mac);
                                out.extend_from_slice(&body);
                                out
                            }
                        } else {
                            let flags = SEC_ENCRYPT
                                | if cipher.salted_checksum {
                                    SEC_SECURE_CHECKSUM
                                } else {
                                    0
                                };
                            let mut body = user_data.to_vec();
                            let mac = cipher.encrypt(&mut body);
                            let mut out = Vec::with_capacity(12 + body.len());
                            out.extend_from_slice(&flags.to_le_bytes());
                            out.extend_from_slice(&0u16.to_le_bytes());
                            out.extend_from_slice(&mac);
                            out.extend_from_slice(&body);
                            out
                        };
                        let wrapped = X224(SendDataRequest {
                            initiator_id: sdr.initiator_id,
                            channel_id: sdr.channel_id,
                            user_data: Cow::Owned(encrypted_user_data),
                        });
                        let encoded = ironrdp_pdu::encode_vec(&wrapped).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?;
                        tracing::debug!(
                            kind = "outbound_x224_sdr",
                            channel_id = sdr.channel_id,
                            has_basic_hdr,
                            plain_len = user_data.len(),
                            wire_len = encoded.len(),
                            plain_hex = %hex_prefix(user_data, 20),
                            "StandardRdpSecurityStream outbound SendDataRequest"
                        );
                        self.wire_out.extend(encoded);
                        return Ok(());
                    }
                }
            }
            self.wire_out.extend(pkt);
            return Ok(());
        }

        // Outbound Fast-Path Input PDU
        if let Some(cipher) = self.cipher.as_mut() {
            let hdr_len = fastpath_header_len(pkt);
            if pkt.len() >= hdr_len {
                let mut body = pkt[hdr_len..].to_vec();
                let mac = cipher.encrypt(&mut body);
                let mut payload = Vec::with_capacity(8 + body.len());
                payload.extend_from_slice(&mac);
                payload.extend_from_slice(&body);
                let mut b0 = pkt[0] | FASTPATH_INPUT_ENCRYPTED;
                if cipher.salted_checksum {
                    b0 |= FASTPATH_INPUT_SECURE_CHECKSUM;
                }
                let wrapped = encode_fastpath_packet(b0, &payload);
                tracing::debug!(
                    kind = "outbound_fastpath_input",
                    plain_len = pkt.len(),
                    wire_len = wrapped.len(),
                    plain_b0 = pkt[0],
                    wrapped_b0 = b0,
                    plain_hex = %hex_prefix(pkt, 20),
                    "StandardRdpSecurityStream outbound FastPathInput"
                );
                self.wire_out.extend(wrapped);
                return Ok(());
            }
        }
        self.wire_out.extend(pkt);
        Ok(())
    }

    fn process_inbound_packet(&mut self, pkt: &[u8]) -> Result<(), io::Error> {
        if pkt.first() == Some(&0x03) {
            if pkt.len() >= 9 && pkt[4..7] == [0x02, 0xF0, 0x80] {
                // Inbound MCS Connect-Response
                if pkt[7] == 0x7F && pkt[8] == 0x66 {
                    let x224_data = ironrdp_pdu::decode::<X224<X224Data<'_>>>(pkt)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
                        .0;
                    let mut cr = ironrdp_pdu::decode::<ConnectResponse>(x224_data.data.as_ref())
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    let mut server_gcc = cr.conference_create_response.gcc_blocks().clone();
                    self.io_channel_id = server_gcc.global_channel_id();
                    self.static_channel_ids = server_gcc.channel_ids();
                    self.message_channel_id = server_gcc
                        .message_channel
                        .as_ref()
                        .map(|m| m.mcs_message_channel_id);
                    let salted_checksum = server_gcc.core.version != RdpVersion::V4;
                    let sec = &server_gcc.security;

                    if sec.encryption_level != EncryptionLevel::None
                        && !sec.encryption_method.is_empty()
                    {
                        let server_random = sec.server_random.ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "missing serverRandom in Standard RDP ServerSecurityData",
                            )
                        })?;
                        let rsa_key = parse_server_rsa_key(&sec.server_cert)?;
                        self.server_rsa_key = Some(rsa_key.clone());
                        let mut client_random = [0u8; 32];
                        client_random[..16].copy_from_slice(Uuid::new_v4().as_bytes());
                        client_random[16..].copy_from_slice(Uuid::new_v4().as_bytes());

                        let encrypted_random = rsa_public_encrypt_le(&client_random, &rsa_key);
                        let cipher = StandardRdpCipher::from_randoms(
                            &client_random,
                            &server_random,
                            sec.encryption_method,
                            salted_checksum,
                        )?;
                        self.cipher = Some(cipher);

                        let mut exch = Vec::with_capacity(8 + encrypted_random.len() + 8);
                        exch.extend_from_slice(&SEC_EXCHANGE_PKT.to_le_bytes());
                        exch.extend_from_slice(&0u16.to_le_bytes());
                        exch.extend_from_slice(
                            &((encrypted_random.len() + 8) as u32).to_le_bytes(),
                        );
                        exch.extend_from_slice(&encrypted_random);
                        exch.extend_from_slice(&[0u8; 8]);
                        self.pending_sec_exchange = Some(exch);
                    }

                    server_gcc.security = ServerSecurityData::no_security();
                    cr.conference_create_response = ConferenceCreateResponse::new(1001, server_gcc)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    let cr_bytes = ironrdp_pdu::encode_vec(&cr)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    let rewritten = ironrdp_pdu::encode_vec(&X224(X224Data {
                        data: Cow::Owned(cr_bytes),
                    }))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    self.plain_in.extend_from_slice(&rewritten);
                    return Ok(());
                }

                // Inbound MCS SendDataIndication
                if (pkt[7] & 0xFC) == 0x68 {
                    let sdi = ironrdp_pdu::decode::<X224<SendDataIndication<'_>>>(pkt)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
                        .0;
                    let ud = sdi.user_data.as_ref();
                    if ud.len() >= 4 {
                        let flags = u16::from_le_bytes([ud[0], ud[1]]);
                        let is_encrypted = (flags & SEC_ENCRYPT) != 0;
                        let is_salted = (flags & SEC_SECURE_CHECKSUM) != 0;
                        let is_license = (flags & SEC_LICENSE_PKT) != 0;

                        if is_encrypted {
                            if let Some(cipher) = self.cipher.as_mut() {
                                if ud.len() < 12 {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "truncated encrypted RDP SendDataIndication",
                                    ));
                                }
                                let mut body = ud[12..].to_vec();
                                cipher.decrypt_and_verify(&mut body, &ud[4..12], is_salted)?;
                                if is_license {
                                    self.server_encrypted_license = true;
                                }
                                let mut clean_user_data = if (flags & KEEP_BASIC_HEADER_FLAGS) != 0
                                {
                                    let stripped_flags =
                                        flags & !(SEC_ENCRYPT | SEC_SECURE_CHECKSUM);
                                    let mut out = Vec::with_capacity(4 + body.len());
                                    out.extend_from_slice(&stripped_flags.to_le_bytes());
                                    out.extend_from_slice(&ud[2..4]);
                                    out.extend_from_slice(&body);
                                    out
                                } else {
                                    if sdi.channel_id == self.io_channel_id
                                        && body.len() >= 4
                                        && (u16::from_le_bytes([body[2], body[3]]) & 0x000F) == 1
                                    {
                                        self.demand_active_seen = true;
                                    }
                                    body
                                };
                                if is_license {
                                    ensure_x509_license_request_cert(
                                        &mut clean_user_data,
                                        self.server_rsa_key.as_ref(),
                                    )?;
                                }
                                let wrapped = X224(SendDataIndication {
                                    initiator_id: sdi.initiator_id,
                                    channel_id: sdi.channel_id,
                                    user_data: Cow::Owned(clean_user_data),
                                });
                                let encoded = ironrdp_pdu::encode_vec(&wrapped).map_err(|e| {
                                    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                                })?;
                                self.plain_in.extend_from_slice(&encoded);
                                return Ok(());
                            }
                        } else if is_license {
                            let mut clean_user_data = ud.to_vec();
                            ensure_x509_license_request_cert(
                                &mut clean_user_data,
                                self.server_rsa_key.as_ref(),
                            )?;
                            if clean_user_data != ud {
                                let wrapped = X224(SendDataIndication {
                                    initiator_id: sdi.initiator_id,
                                    channel_id: sdi.channel_id,
                                    user_data: Cow::Owned(clean_user_data),
                                });
                                let encoded = ironrdp_pdu::encode_vec(&wrapped).map_err(|e| {
                                    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                                })?;
                                self.plain_in.extend_from_slice(&encoded);
                                return Ok(());
                            }
                        }
                    }
                }
            }
            self.plain_in.extend_from_slice(pkt);
            return Ok(());
        }

        // Inbound Fast-Path Output PDU
        if let Some(cipher) = self.cipher.as_mut() {
            let hdr_len = fastpath_header_len(pkt);
            if pkt.len() >= hdr_len && (pkt[0] & FASTPATH_OUTPUT_ENCRYPTED) != 0 {
                if pkt.len() < hdr_len + 8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated encrypted Fast-Path output PDU",
                    ));
                }
                let salted = (pkt[0] & FASTPATH_OUTPUT_SECURE_CHECKSUM) != 0;
                let mut body = pkt[hdr_len + 8..].to_vec();
                cipher.decrypt_and_verify(&mut body, &pkt[hdr_len..hdr_len + 8], salted)?;
                let clean_b0 =
                    pkt[0] & !(FASTPATH_OUTPUT_ENCRYPTED | FASTPATH_OUTPUT_SECURE_CHECKSUM);
                let clean_pkt = encode_fastpath_packet(clean_b0, &body);
                tracing::debug!(
                    kind = "inbound_fastpath_output",
                    wire_len = pkt.len(),
                    clean_b0,
                    body_len = body.len(),
                    body_hex = %hex_prefix(&body, 16),
                    "StandardRdpSecurityStream inbound FastPathOutput"
                );
                self.plain_in.extend_from_slice(&clean_pkt);
                return Ok(());
            }
        }
        self.plain_in.extend_from_slice(pkt);
        Ok(())
    }

    fn flush_wire_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while !self.wire_out.is_empty() {
            let slice = self.wire_out.as_slices().0;
            match Pin::new(&mut self.inner).poll_write(cx, slice) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "underlying RDP stream closed on write",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.wire_out.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for StandardRdpSecurityStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.wire_out.is_empty() {
            if let Poll::Ready(Err(e)) = self.flush_wire_out(cx) {
                return Poll::Ready(Err(e));
            }
        }

        loop {
            if !self.plain_in.is_empty() {
                let take = buf.remaining().min(self.plain_in.len());
                let chunk = self.plain_in.split_to(take);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }

            let mut tmp = [0u8; 8192];
            let mut rbuf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rbuf) {
                Poll::Ready(Ok(())) => {
                    let filled = rbuf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    self.read_wire_buf.extend_from_slice(filled);
                    while let Some(pkt) = extract_next_rdp_packet(&mut self.read_wire_buf)? {
                        self.process_inbound_packet(&pkt)?;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for StandardRdpSecurityStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.wire_out.len() >= 128 * 1024 {
            match self.flush_wire_out(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        self.write_buf.extend_from_slice(buf);
        while let Some(pkt) = extract_next_rdp_packet(&mut self.write_buf)? {
            self.process_outbound_packet(&pkt)?;
        }

        match self.flush_wire_out(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.flush_wire_out(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.flush_wire_out(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_matches_rfc6229_vector() {
        let key = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut rc4 = Rc4::new(&key);
        let mut buf = [0u8; 16];
        rc4.apply(&mut buf);
        assert_eq!(
            buf,
            [
                0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27, 0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11,
                0x18, 0xa8
            ]
        );
    }

    #[test]
    fn proprietary_rsa_key_parses_and_encrypts_in_little_endian() {
        // Minimal 64-byte modulus RSA1 proprietary certificate blob
        let mut mod_le = vec![0x11u8; 64];
        mod_le[63] = 0x80; // ensure high bit set
        let keylen = (64 + 8) as u32;
        let mut cert = Vec::new();
        cert.extend_from_slice(&CERT_CHAIN_VERSION_1.to_le_bytes());
        cert.extend_from_slice(&1u32.to_le_bytes()); // dwSigAlgId
        cert.extend_from_slice(&1u32.to_le_bytes()); // dwKeyAlgId
        cert.extend_from_slice(&BB_RSA_KEY_BLOB.to_le_bytes());
        cert.extend_from_slice(&((20 + keylen) as u16).to_le_bytes());
        cert.extend_from_slice(b"RSA1");
        cert.extend_from_slice(&keylen.to_le_bytes());
        cert.extend_from_slice(&512u32.to_le_bytes());
        cert.extend_from_slice(&63u32.to_le_bytes());
        cert.extend_from_slice(&65537u32.to_le_bytes());
        cert.extend_from_slice(&mod_le);
        cert.extend_from_slice(&[0u8; 8]);

        let parsed = parse_server_rsa_key(&cert).unwrap();
        assert_eq!(parsed.modulus_le, mod_le);
        assert_eq!(parsed.exponent_le, 65537u32.to_le_bytes());

        let ct = rsa_public_encrypt_le(&[0x42u8; 32], &parsed);
        assert_eq!(ct.len(), 64);
    }

    #[test]
    fn derives_128bit_rc4_keys_roundtrips_mac_and_rolls_key_at_4096() {
        let cr = [0xAAu8; 32];
        let sr = [0xBBu8; 32];
        let mut client =
            StandardRdpCipher::from_randoms(&cr, &sr, EncryptionMethod::BIT_128, true).unwrap();

        // Simulate peer with swapped keys (mirror server side)
        let mut server = StandardRdpCipher {
            method: EncryptionMethod::BIT_128,
            rc4_key_len: 16,
            salted_checksum: true,
            sign_key: client.sign_key,
            encrypt_key: client.decrypt_key,
            encrypt_update_key: client.decrypt_update_key,
            rc4_encrypt: Rc4::new(&client.decrypt_key),
            encrypt_use_count: 0,
            encrypt_checksum_use_count: 0,
            decrypt_key: client.encrypt_key,
            decrypt_update_key: client.encrypt_update_key,
            rc4_decrypt: Rc4::new(&client.encrypt_key),
            decrypt_use_count: 0,
            decrypt_checksum_use_count: 0,
        };

        for idx in 0..4100u32 {
            let orig = format!("rdp-msg-{idx}").into_bytes();
            let mut wire = orig.clone();
            let mac = client.encrypt(&mut wire);
            assert_ne!(wire, orig);
            server.decrypt_and_verify(&mut wire, &mac, true).unwrap();
            assert_eq!(wire, orig);
        }
    }

    #[test]
    fn injects_synthetic_x509_chain_when_server_license_request_lacks_cert() {
        use ironrdp_pdu::rdp::headers::{BasicSecurityHeader, BasicSecurityHeaderFlags};
        use ironrdp_pdu::rdp::server_license::{
            ClientNewLicenseRequest, LicenseHeader, LicensePdu, PreambleFlags, PreambleType,
            PreambleVersion, ProductInfo, Scope, ServerLicenseRequest,
        };

        // Valid 512-bit RSA modulus (high bit set at MSB) in little-endian.
        let mut modulus_le = vec![0x23u8; 64];
        modulus_le[0] = 0x55;
        modulus_le[63] = 0xC3;
        let rsa_key = RsaPublicKeyLe {
            modulus_le,
            exponent_le: 65537u32.to_le_bytes().to_vec(),
        };

        let req = ServerLicenseRequest {
            license_header: LicenseHeader {
                security_header: BasicSecurityHeader {
                    flags: BasicSecurityHeaderFlags::LICENSE_PKT,
                },
                preamble_message_type: PreambleType::LicenseRequest,
                preamble_flags: PreambleFlags::empty(),
                preamble_version: PreambleVersion::V3,
                preamble_message_size: 0,
            },
            server_random: vec![0x7Au8; 32],
            product_info: ProductInfo {
                version: 0x0000_0001,
                company_name: "Microsoft Corporation".to_string(),
                product_id: "A02".to_string(),
            },
            server_certificate: None,
            scope_list: vec![Scope("microsoft.com".to_string())],
        };

        let mut user_data =
            ironrdp_pdu::encode_vec(&LicensePdu::ServerLicenseRequest(req)).unwrap();
        ensure_x509_license_request_cert(&mut user_data, Some(&rsa_key)).unwrap();

        let LicensePdu::ServerLicenseRequest(decoded) =
            ironrdp_pdu::decode::<LicensePdu>(&user_data).unwrap()
        else {
            panic!("expected ServerLicenseRequest");
        };
        assert!(matches!(
            decoded.server_certificate.as_ref().map(|c| &c.certificate),
            Some(CertificateType::X509(_))
        ));

        let client_random = [0x11u8; 32];
        let premaster_secret = [0x22u8; 48];
        let (new_req, _) = ClientNewLicenseRequest::from_server_license_request(
            &decoded,
            &client_random,
            &premaster_secret,
            "Administrator",
            "OPERQUAY",
        )
        .expect("IronRDP should build ClientNewLicenseRequest from injected X509 cert");

        // Compare encrypted premaster secret prefix (64 bytes before 8-byte zero pad).
        let expected_le = rsa_public_encrypt_le(&premaster_secret, &rsa_key);
        assert_eq!(
            &new_req.encrypted_premaster_secret[..64],
            expected_le.as_slice()
        );
    }

    #[test]
    fn preserves_static_channel_and_autodetect_message_channel_headers() {
        let cr = [0x12u8; 32];
        let sr = [0x34u8; 32];
        let client =
            StandardRdpCipher::from_randoms(&cr, &sr, EncryptionMethod::BIT_128, true).unwrap();
        let mut peer_verify = StandardRdpCipher {
            method: EncryptionMethod::BIT_128,
            rc4_key_len: 16,
            salted_checksum: true,
            sign_key: client.sign_key,
            encrypt_key: client.decrypt_key,
            encrypt_update_key: client.decrypt_update_key,
            rc4_encrypt: Rc4::new(&client.decrypt_key),
            encrypt_use_count: 0,
            encrypt_checksum_use_count: 0,
            decrypt_key: client.encrypt_key,
            decrypt_update_key: client.encrypt_update_key,
            rc4_decrypt: Rc4::new(&client.encrypt_key),
            decrypt_use_count: 0,
            decrypt_checksum_use_count: 0,
        };

        let mut sec = StandardRdpSecurityStream::new(tokio::io::empty());
        sec.cipher = Some(client);
        sec.io_channel_id = 1003;
        sec.static_channel_ids = vec![1004, 1005];
        sec.message_channel_id = Some(1006);
        sec.demand_active_seen = true;

        // 1) 12-byte drdynvc static virtual channel PDU whose length bytes happen to be 0x0000_0004 (== SEC_TRANSPORT_RSP)
        let drdynvc_plain = vec![
            0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x50, 0x00, 0x03, 0x00,
        ];
        let drdynvc_wire = ironrdp_pdu::encode_vec(&X224(SendDataRequest {
            initiator_id: 1007,
            channel_id: 1004,
            user_data: Cow::Borrowed(&drdynvc_plain),
        }))
        .unwrap();
        sec.process_outbound_packet(&drdynvc_wire).unwrap();
        let out1: Vec<u8> = sec.wire_out.drain(..).collect();
        let sdr1 = ironrdp_pdu::decode::<X224<SendDataRequest<'_>>>(&out1)
            .unwrap()
            .0;
        let ud1 = sdr1.user_data.as_ref();
        assert_eq!(
            u16::from_le_bytes([ud1[0], ud1[1]]),
            SEC_ENCRYPT | SEC_SECURE_CHECKSUM
        );
        let mut dec1 = ud1[12..].to_vec();
        peer_verify
            .decrypt_and_verify(&mut dec1, &ud1[4..12], true)
            .unwrap();
        assert_eq!(dec1, drdynvc_plain);

        // 2) 18-byte AutoDetectResponse on MCS message channel 1006 carrying BasicSecurityHeader(SEC_AUTODETECT_RSP)
        let autodetect_plain = vec![
            0x00, 0x20, 0x00, 0x00, 0x0e, 0x01, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let autodetect_wire = ironrdp_pdu::encode_vec(&X224(SendDataRequest {
            initiator_id: 1007,
            channel_id: 1006,
            user_data: Cow::Borrowed(&autodetect_plain),
        }))
        .unwrap();
        sec.process_outbound_packet(&autodetect_wire).unwrap();
        let out2: Vec<u8> = sec.wire_out.drain(..).collect();
        let sdr2 = ironrdp_pdu::decode::<X224<SendDataRequest<'_>>>(&out2)
            .unwrap()
            .0;
        let ud2 = sdr2.user_data.as_ref();
        assert_eq!(
            u16::from_le_bytes([ud2[0], ud2[1]]),
            SEC_AUTODETECT_RSP | SEC_ENCRYPT | SEC_SECURE_CHECKSUM
        );
        let mut dec2 = ud2[12..].to_vec();
        peer_verify
            .decrypt_and_verify(&mut dec2, &ud2[4..12], true)
            .unwrap();
        assert_eq!(dec2, &autodetect_plain[4..]);
    }
}
