use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use constant_time_eq::constant_time_eq;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use ring::digest;
use ring::signature::{self, UnparsedPublicKey};
use sha1::{Digest as _, Sha1};

const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const EXC_C14N_WITH_COMMENTS_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const ENVELOPED_SIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

#[derive(Debug, Clone)]
pub enum XmlChild {
    Elem(XmlElem),
    Text(String),
    Comment(String),
}

#[derive(Debug, Clone)]
pub struct XmlElem {
    pub uid: u64,
    pub qname: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<XmlChild>,
}

impl XmlElem {
    #[must_use]
    pub fn local_name(&self) -> &str {
        local_name(&self.qname)
    }

    #[must_use]
    pub fn attr(&self, name_local: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| local_name(k) == name_local && !k.starts_with("xmlns"))
            .map(|(_, v)| v.as_str())
    }

    #[must_use]
    pub fn child_elems(&self) -> Vec<&Self> {
        self.children
            .iter()
            .filter_map(|c| match c {
                XmlChild::Elem(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    #[must_use]
    pub fn text_content(&self) -> String {
        let mut out = String::new();
        for c in &self.children {
            if let XmlChild::Text(t) = c {
                out.push_str(t);
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedSamlSubtree {
    pub response: XmlElem,
    pub assertion: XmlElem,
}

#[derive(Debug, Clone)]
enum ExtractedKeyKind {
    RsaPkcs1Der(Vec<u8>),
    EcP256Uncompressed(Vec<u8>),
    EcP384Uncompressed(Vec<u8>),
    Ed25519(Vec<u8>),
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

fn parse_seq_children(seq_val: &[u8]) -> Option<Vec<DerTlv<'_>>> {
    let mut out = Vec::new();
    let mut rest = seq_val;
    while !rest.is_empty() {
        let item = parse_tlv(rest)?;
        rest = &rest[item.total_len..];
        out.push(item);
    }
    Some(out)
}

fn decode_pem_certs(pem_or_b64: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let mut rest = pem_or_b64;
    while let Some(b) = rest.find(begin) {
        let after = &rest[b + begin.len()..];
        let Some(e) = after.find(end) else {
            break;
        };
        let cleaned: String = after[..e]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        if let Ok(der) = STANDARD.decode(cleaned) {
            out.push(der);
        }
        rest = &after[e + end.len()..];
    }
    if out.is_empty() {
        let trimmed: String = pem_or_b64
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        if !trimmed.is_empty() {
            if let Ok(der) = STANDARD.decode(trimmed) {
                out.push(der);
            }
        }
    }
    out
}

/// Extract signing certificates from SAML `IdP` metadata XML (`<ds:X509Certificate>`).
#[must_use]
pub fn extract_certs_from_idp_metadata(metadata_xml: &str) -> Vec<String> {
    if metadata_xml.trim().is_empty() || contains_forbidden_dtd(metadata_xml) {
        return Vec::new();
    }
    let Ok(root) = parse_xml_dom(metadata_xml) else {
        return Vec::new();
    };
    let mut pems = Vec::new();
    collect_x509_pems(&root, &mut pems);
    pems
}

fn collect_x509_pems(node: &XmlElem, out: &mut Vec<String>) {
    if node.local_name() == "X509Certificate" {
        let body: String = node
            .text_content()
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        if !body.is_empty() {
            out.push(format!(
                "-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----"
            ));
        }
    }
    for c in node.child_elems() {
        collect_x509_pems(c, out);
    }
}

fn extract_spki_key_from_cert_der(cert_der: &[u8]) -> Option<ExtractedKeyKind> {
    // Algorithm OIDs:
    const OID_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    const OID_EC: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
    const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];

    let cert_seq = parse_tlv(cert_der)?;
    if cert_seq.tag != 0x30 {
        return None;
    }
    let cert_children = parse_seq_children(cert_seq.value)?;
    let tbs = cert_children.first()?;
    if tbs.tag != 0x30 {
        return None;
    }
    let tbs_fields = parse_seq_children(tbs.value)?;
    let mut idx = 0usize;
    if tbs_fields.first()?.tag == 0xA0 {
        idx += 1;
    }
    let spki = tbs_fields.get(idx + 5)?;
    if spki.tag != 0x30 {
        return None;
    }
    let spki_parts = parse_seq_children(spki.value)?;
    let alg_id = spki_parts.first()?;
    if alg_id.tag != 0x30 {
        return None;
    }
    let alg_parts = parse_seq_children(alg_id.value)?;
    let oid = alg_parts.first()?;
    if oid.tag != 0x06 {
        return None;
    }
    let bit_str = spki_parts.get(1)?;
    if bit_str.tag != 0x03 || bit_str.value.len() < 2 {
        return None;
    }
    let key_bytes = bit_str.value[1..].to_vec();

    if oid.value == OID_RSA {
        Some(ExtractedKeyKind::RsaPkcs1Der(key_bytes))
    } else if oid.value == OID_EC {
        let curve = alg_parts.get(1)?;
        if curve.tag != 0x06 {
            return None;
        }
        if curve.value == OID_P256 {
            Some(ExtractedKeyKind::EcP256Uncompressed(key_bytes))
        } else if curve.value == OID_P384 {
            Some(ExtractedKeyKind::EcP384Uncompressed(key_bytes))
        } else {
            None
        }
    } else if oid.value == OID_ED25519 {
        Some(ExtractedKeyKind::Ed25519(key_bytes))
    } else {
        None
    }
}

fn contains_forbidden_dtd(xml: &str) -> bool {
    let upper = xml.to_ascii_uppercase();
    upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY")
}

fn parse_elem_attrs(e: &BytesStart<'_>) -> Result<Vec<(String, String)>, String> {
    let mut attrs = Vec::new();
    for attr in e.attributes() {
        let attr = attr.map_err(|err| format!("XML attribute parse error: {err}"))?;
        let key = attr.key.into_inner().to_owned();
        let val = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|err| format!("XML attribute unescape error: {err}"))?
            .into_owned();
        attrs.push((key, val));
    }
    Ok(attrs)
}

fn push_xml_text(stack: &mut [XmlElem], chunk: &str) {
    if let Some(parent) = stack.last_mut() {
        if let Some(XmlChild::Text(existing)) = parent.children.last_mut() {
            existing.push_str(chunk);
        } else {
            parent.children.push(XmlChild::Text(chunk.to_owned()));
        }
    }
}

pub fn parse_xml_dom(xml: &str) -> Result<XmlElem, String> {
    if contains_forbidden_dtd(xml) {
        return Err("XML DTD/ENTITY declarations are forbidden (XXE protection)".into());
    }
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut stack: Vec<XmlElem> = Vec::new();
    let mut root: Option<XmlElem> = None;
    let mut next_uid = 1u64;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let qname = e.name().into_inner().to_owned();
                let attrs = parse_elem_attrs(&e)?;
                let uid = next_uid;
                next_uid += 1;
                stack.push(XmlElem {
                    uid,
                    qname,
                    attrs,
                    children: Vec::new(),
                });
            }
            Ok(Event::Empty(e)) => {
                let qname = e.name().into_inner().to_owned();
                let attrs = parse_elem_attrs(&e)?;
                let uid = next_uid;
                next_uid += 1;
                let elem = XmlElem {
                    uid,
                    qname,
                    attrs,
                    children: Vec::new(),
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(XmlChild::Elem(elem));
                } else if root.is_none() {
                    root = Some(elem);
                } else {
                    return Err("multiple XML root elements rejected".into());
                }
            }
            Ok(Event::Text(t)) => {
                push_xml_text(&mut stack, t.xml10_content().as_ref());
            }
            Ok(Event::GeneralRef(r)) => {
                if let Some(ch) = r
                    .resolve_char_ref()
                    .map_err(|err| format!("XML char ref error: {err}"))?
                {
                    let mut buf = [0u8; 4];
                    push_xml_text(&mut stack, ch.encode_utf8(&mut buf));
                } else if let Some(s) = quick_xml::escape::resolve_predefined_entity(r.as_ref()) {
                    push_xml_text(&mut stack, s);
                } else {
                    return Err(format!(
                        "unsupported XML entity reference: &{};",
                        r.as_ref()
                    ));
                }
            }
            Ok(Event::CData(c)) => {
                push_xml_text(&mut stack, c.xml10_content().as_ref());
            }
            Ok(Event::Comment(c)) => {
                let txt = c.xml10_content().into_owned();
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(XmlChild::Comment(txt));
                }
            }
            Ok(Event::End(e)) => {
                let end_qname = e.name().into_inner();
                let Some(elem) = stack.pop() else {
                    return Err("unexpected closing XML tag".into());
                };
                if elem.qname != end_qname {
                    return Err(format!(
                        "mismatched closing XML tag: expected {}, got {end_qname}",
                        elem.qname
                    ));
                }
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(XmlChild::Elem(elem));
                } else if root.is_none() {
                    root = Some(elem);
                } else {
                    return Err("multiple XML root elements rejected".into());
                }
            }
            Ok(Event::Decl(_) | Event::PI(_)) => {}
            Ok(Event::Eof) => break,
            Ok(Event::DocType(_)) => {
                return Err("XML DOCTYPE declarations are forbidden".into());
            }
            Err(err) => return Err(format!("XML parse error: {err}")),
        }
    }

    if !stack.is_empty() {
        return Err("unclosed XML element".into());
    }
    root.ok_or_else(|| "empty XML document".to_owned())
}

fn split_qname(qname: &str) -> (&str, &str) {
    qname.split_once(':').map_or(("", qname), |(p, l)| (p, l))
}

fn local_name(qname: &str) -> &str {
    split_qname(qname).1
}

fn extract_ns_decls(elem: &XmlElem) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in &elem.attrs {
        if k == "xmlns" {
            out.insert(String::new(), v.clone());
        } else if let Some(pfx) = k.strip_prefix("xmlns:") {
            out.insert(pfx.to_owned(), v.clone());
        }
    }
    out
}

/// W3C Exclusive XML Canonicalization (`xml-exc-c14n#`), inheriting in-scope namespaces from
/// `ancestors` and optionally skipping one element by `uid` (for enveloped-signature transform).
#[must_use]
pub fn exclusive_canonicalize(
    node: &XmlElem,
    ancestors: &[&XmlElem],
    skip_uid: Option<u64>,
    with_comments: bool,
    inclusive_prefixes: &BTreeSet<String>,
) -> String {
    let mut in_scope: BTreeMap<String, String> = BTreeMap::new();
    for anc in ancestors {
        for (pfx, uri) in extract_ns_decls(anc) {
            if uri.is_empty() && pfx.is_empty() {
                in_scope.remove("");
            } else {
                in_scope.insert(pfx, uri);
            }
        }
    }
    let mut rendered: BTreeMap<String, String> = BTreeMap::new();
    let mut out = String::new();
    write_exc_c14n_elem(
        node,
        &in_scope,
        &rendered,
        skip_uid,
        with_comments,
        inclusive_prefixes,
        &mut out,
    );
    rendered.clear();
    out
}

fn write_exc_c14n_elem(
    node: &XmlElem,
    parent_in_scope: &BTreeMap<String, String>,
    parent_rendered: &BTreeMap<String, String>,
    skip_uid: Option<u64>,
    with_comments: bool,
    inclusive_prefixes: &BTreeSet<String>,
    out: &mut String,
) {
    if skip_uid == Some(node.uid) {
        return;
    }

    let mut cur_scope = parent_in_scope.clone();
    for (pfx, uri) in extract_ns_decls(node) {
        if uri.is_empty() && pfx.is_empty() {
            cur_scope.remove("");
        } else {
            cur_scope.insert(pfx, uri);
        }
    }

    let mut utilized: BTreeSet<String> = BTreeSet::new();
    let (elem_pfx, _) = split_qname(&node.qname);
    utilized.insert(elem_pfx.to_owned());
    for (k, _) in &node.attrs {
        if k == "xmlns" || k.starts_with("xmlns:") {
            continue;
        }
        let (attr_pfx, _) = split_qname(k);
        if !attr_pfx.is_empty() && attr_pfx != "xml" {
            utilized.insert(attr_pfx.to_owned());
        }
    }
    for p in inclusive_prefixes {
        if p == "#default" {
            utilized.insert(String::new());
        } else if cur_scope.contains_key(p) {
            utilized.insert(p.clone());
        }
    }

    let mut next_rendered = parent_rendered.clone();
    let mut ns_to_emit: BTreeMap<String, String> = BTreeMap::new();
    for pfx in &utilized {
        if pfx == "xml" {
            continue;
        }
        match cur_scope.get(pfx) {
            Some(uri) => {
                if parent_rendered.get(pfx) != Some(uri) {
                    ns_to_emit.insert(pfx.clone(), uri.clone());
                    next_rendered.insert(pfx.clone(), uri.clone());
                }
            }
            None => {
                if pfx.is_empty() && parent_rendered.get("").is_some_and(|u| !u.is_empty()) {
                    ns_to_emit.insert(String::new(), String::new());
                    next_rendered.remove("");
                }
            }
        }
    }

    let mut non_ns_attrs: Vec<(&str, &str, &str)> = Vec::new();
    for (k, v) in &node.attrs {
        if k == "xmlns" || k.starts_with("xmlns:") {
            continue;
        }
        let (pfx, loc) = split_qname(k);
        let uri = if pfx.is_empty() {
            ""
        } else if pfx == "xml" {
            "http://www.w3.org/XML/1998/namespace"
        } else {
            cur_scope.get(pfx).map_or("", String::as_str)
        };
        non_ns_attrs.push((uri, loc, k.as_str()));
        let _ = v;
    }
    non_ns_attrs.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(b.1)));

    out.push('<');
    out.push_str(&node.qname);

    for (pfx, uri) in &ns_to_emit {
        if pfx.is_empty() {
            out.push_str(" xmlns=\"");
        } else {
            out.push_str(" xmlns:");
            out.push_str(pfx);
            out.push_str("=\"");
        }
        push_escaped_attr(out, uri);
        out.push('"');
    }

    for (_, _, full_k) in non_ns_attrs {
        if let Some((_, val)) = node.attrs.iter().find(|(k, _)| k == full_k) {
            out.push(' ');
            out.push_str(full_k);
            out.push_str("=\"");
            push_escaped_attr(out, val);
            out.push('"');
        }
    }
    out.push('>');

    for child in &node.children {
        match child {
            XmlChild::Elem(e) => write_exc_c14n_elem(
                e,
                &cur_scope,
                &next_rendered,
                skip_uid,
                with_comments,
                inclusive_prefixes,
                out,
            ),
            XmlChild::Text(t) => push_escaped_text(out, t),
            XmlChild::Comment(c) => {
                if with_comments {
                    out.push_str("<!--");
                    out.push_str(c);
                    out.push_str("-->");
                }
            }
        }
    }

    out.push_str("</");
    out.push_str(&node.qname);
    out.push('>');
}

fn push_escaped_attr(out: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
}

fn push_escaped_text(out: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
}

fn count_elements_with_id<'a>(
    node: &'a XmlElem,
    target_id: &str,
    ancestors: Vec<&'a XmlElem>,
    hits: &mut Vec<(&'a XmlElem, Vec<&'a XmlElem>)>,
) {
    if node.attrs.iter().any(|(k, v)| {
        let loc = local_name(k);
        matches!(loc, "ID" | "Id" | "id") && v == target_id
    }) {
        hits.push((node, ancestors.clone()));
    }
    let mut next_anc = ancestors;
    next_anc.push(node);
    for c in node.child_elems() {
        count_elements_with_id(c, target_id, next_anc.clone(), hits);
    }
}

fn is_signature_elem(node: &XmlElem, namespaces: &BTreeMap<String, String>) -> bool {
    if node.local_name() != "Signature" {
        return false;
    }
    let (pfx, _) = split_qname(&node.qname);
    if pfx.is_empty() {
        namespaces
            .get("")
            .or_else(|| {
                node.attrs
                    .iter()
                    .find(|(k, _)| k == "xmlns")
                    .map(|(_, v)| v)
            })
            .is_some_and(|ns| ns == DS_NS)
    } else {
        let key = format!("xmlns:{pfx}");
        namespaces
            .get(pfx)
            .or_else(|| node.attrs.iter().find(|(k, _)| k == &key).map(|(_, v)| v))
            .is_some_and(|ns| ns == DS_NS)
    }
}

fn direct_signature_child(
    parent: &XmlElem,
    parent_ns: &BTreeMap<String, String>,
) -> Option<XmlElem> {
    let mut scope = parent_ns.clone();
    for (p, u) in extract_ns_decls(parent) {
        scope.insert(p, u);
    }
    parent
        .child_elems()
        .into_iter()
        .find(|c| is_signature_elem(c, &scope))
        .cloned()
}

fn compute_digest(
    alg_uri: &str,
    canonical_bytes: &[u8],
    compliance_mode: bool,
) -> Result<Vec<u8>, String> {
    match alg_uri {
        "http://www.w3.org/2001/04/xmlenc#sha256" => {
            Ok(digest::digest(&digest::SHA256, canonical_bytes)
                .as_ref()
                .to_vec())
        }
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => {
            Ok(digest::digest(&digest::SHA384, canonical_bytes)
                .as_ref()
                .to_vec())
        }
        "http://www.w3.org/2001/04/xmlenc#sha512" => {
            Ok(digest::digest(&digest::SHA512, canonical_bytes)
                .as_ref()
                .to_vec())
        }
        "http://www.w3.org/2000/09/xmldsig#sha1" => {
            if compliance_mode {
                return Err("SHA-1 XML-DSig DigestMethod forbidden in Compliance Mode".into());
            }
            Ok(Sha1::digest(canonical_bytes).to_vec())
        }
        other => Err(format!("unsupported XML-DSig DigestMethod: {other}")),
    }
}

fn verify_signature_bytes(
    key: &ExtractedKeyKind,
    sig_alg_uri: &str,
    signed_info_bytes: &[u8],
    sig_bytes: &[u8],
    compliance_mode: bool,
) -> Result<(), String> {
    match (key, sig_alg_uri) {
        (
            ExtractedKeyKind::RsaPkcs1Der(der),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        ) => UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, der)
            .verify(signed_info_bytes, sig_bytes)
            .map_err(|_| "RSA-SHA256 signature verification failed".to_owned()),
        (
            ExtractedKeyKind::RsaPkcs1Der(der),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        ) => UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA384, der)
            .verify(signed_info_bytes, sig_bytes)
            .map_err(|_| "RSA-SHA384 signature verification failed".to_owned()),
        (
            ExtractedKeyKind::RsaPkcs1Der(der),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        ) => UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA512, der)
            .verify(signed_info_bytes, sig_bytes)
            .map_err(|_| "RSA-SHA512 signature verification failed".to_owned()),
        (
            ExtractedKeyKind::RsaPkcs1Der(der),
            "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
        ) => UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, der)
            .verify(signed_info_bytes, sig_bytes)
            .map_err(|_| "RSA-PSS-SHA256 signature verification failed".to_owned()),
        (
            ExtractedKeyKind::RsaPkcs1Der(der),
            "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1",
        ) => UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA384, der)
            .verify(signed_info_bytes, sig_bytes)
            .map_err(|_| "RSA-PSS-SHA384 signature verification failed".to_owned()),
        (
            ExtractedKeyKind::RsaPkcs1Der(der),
            "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1",
        ) => UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA512, der)
            .verify(signed_info_bytes, sig_bytes)
            .map_err(|_| "RSA-PSS-SHA512 signature verification failed".to_owned()),
        (ExtractedKeyKind::RsaPkcs1Der(der), "http://www.w3.org/2000/09/xmldsig#rsa-sha1") => {
            if compliance_mode {
                return Err("RSA-SHA1 signature algorithm forbidden in Compliance Mode".into());
            }
            UnparsedPublicKey::new(
                &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
                der,
            )
            .verify(signed_info_bytes, sig_bytes)
            .map_err(|_| "RSA-SHA1 signature verification failed".to_owned())
        }
        (
            ExtractedKeyKind::EcP256Uncompressed(pt),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        ) => UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, pt)
            .verify(signed_info_bytes, sig_bytes)
            .or_else(|_| {
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, pt)
                    .verify(signed_info_bytes, sig_bytes)
            })
            .map_err(|_| "ECDSA-P256-SHA256 signature verification failed".to_owned()),
        (
            ExtractedKeyKind::EcP384Uncompressed(pt),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
        ) => UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, pt)
            .verify(signed_info_bytes, sig_bytes)
            .or_else(|_| {
                UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_ASN1, pt)
                    .verify(signed_info_bytes, sig_bytes)
            })
            .map_err(|_| "ECDSA-P384-SHA384 signature verification failed".to_owned()),
        (ExtractedKeyKind::Ed25519(pk), uri)
            if uri.contains("eddsa-ed25519") || uri.contains("Ed25519") =>
        {
            UnparsedPublicKey::new(&signature::ED25519, pk)
                .verify(signed_info_bytes, sig_bytes)
                .map_err(|_| "Ed25519 signature verification failed".to_owned())
        }
        (_, other) => Err(format!(
            "SAML signature algorithm '{other}' does not match configured IdP certificate key type"
        )),
    }
}

/// Strictly verify SAML 2.0 XML-DSig `<ds:Signature>` against pinned `IdP` X.509 certificate(s),
/// enforce anti-XSW structural checks, and return ONLY the verified Response + Assertion DOM.
pub fn verify_saml_xml_signature(
    xml: &str,
    idp_cert_pems: &[String],
    compliance_mode: bool,
) -> Result<VerifiedSamlSubtree, String> {
    let mut keys = Vec::new();
    for pem in idp_cert_pems {
        for der in decode_pem_certs(pem) {
            if let Some(k) = extract_spki_key_from_cert_der(&der) {
                keys.push(k);
            }
        }
    }
    if keys.is_empty() {
        return Err("SAML provider has no valid pinned IdP X.509 signing certificate".into());
    }

    let root = parse_xml_dom(xml)?;
    if root.local_name() != "Response" {
        return Err("SAML XML root element must be Response".into());
    }

    let root_ns = BTreeMap::new();
    let root_sig = direct_signature_child(&root, &root_ns);
    let direct_assertions: Vec<&XmlElem> = root
        .child_elems()
        .into_iter()
        .filter(|e| e.local_name() == "Assertion")
        .collect();
    if direct_assertions.len() != 1 {
        return Err("SAML Response must contain strictly 1 top-level Assertion (anti-XSW)".into());
    }
    let assertion_ref = direct_assertions[0];

    let (sig_elem, sig_ancestors, allowed_target_uid, verified_assertion) = if let Some(sig) = {
        let mut a_ns = extract_ns_decls(&root);
        for (k, v) in extract_ns_decls(assertion_ref) {
            a_ns.insert(k, v);
        }
        direct_signature_child(assertion_ref, &a_ns)
    } {
        (
            sig,
            vec![&root, assertion_ref],
            assertion_ref.uid,
            assertion_ref.clone(),
        )
    } else if let Some(sig) = root_sig {
        (sig, vec![&root], root.uid, assertion_ref.clone())
    } else {
        return Err("unsigned SAMLResponse rejected (missing top-level ds:Signature)".into());
    };

    let signed_info = sig_elem
        .child_elems()
        .into_iter()
        .find(|c| c.local_name() == "SignedInfo")
        .ok_or("ds:Signature missing ds:SignedInfo")?;

    let c14n_method = signed_info
        .child_elems()
        .into_iter()
        .find(|c| c.local_name() == "CanonicalizationMethod")
        .and_then(|c| c.attr("Algorithm"))
        .unwrap_or(EXC_C14N_NS);
    let with_comments = match c14n_method {
        EXC_C14N_NS | "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => false,
        EXC_C14N_WITH_COMMENTS_NS
        | "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" => true,
        other => {
            return Err(format!(
                "unsupported XML-DSig CanonicalizationMethod: {other}"
            ));
        }
    };
    let si_inclusive = signed_info
        .child_elems()
        .into_iter()
        .find(|c| c.local_name() == "CanonicalizationMethod")
        .and_then(|cm| {
            cm.child_elems()
                .into_iter()
                .find(|i| i.local_name() == "InclusiveNamespaces")
        })
        .and_then(|i| i.attr("PrefixList"))
        .map_or_default(|list| {
            list.split_whitespace()
                .map(str::to_owned)
                .collect::<BTreeSet<String>>()
        });

    let sig_method = signed_info
        .child_elems()
        .into_iter()
        .find(|c| c.local_name() == "SignatureMethod")
        .and_then(|c| c.attr("Algorithm"))
        .ok_or("ds:SignedInfo missing SignatureMethod Algorithm")?;

    let refs: Vec<&XmlElem> = signed_info
        .child_elems()
        .into_iter()
        .filter(|c| c.local_name() == "Reference")
        .collect();
    if refs.len() != 1 {
        return Err("SAML ds:SignedInfo must contain strictly 1 Reference (anti-XSW)".into());
    }
    let reference = refs[0];
    let uri = reference.attr("URI").unwrap_or("");
    let (target_elem, target_ancestors): (&XmlElem, Vec<&XmlElem>) = if uri.is_empty() {
        if allowed_target_uid != root.uid {
            return Err("empty Reference URI only permitted for root Response signature".into());
        }
        (&root, Vec::new())
    } else if let Some(ref_id) = uri.strip_prefix('#') {
        let mut hits = Vec::new();
        count_elements_with_id(&root, ref_id, Vec::new(), &mut hits);
        if hits.is_empty() {
            return Err(format!("SAML Signature Reference ID '#{ref_id}' not found"));
        }
        if hits.len() > 1 {
            return Err(format!(
                "duplicate XML ID '#{ref_id}' rejected (anti-XSW protection)"
            ));
        }
        let (target, anc) = hits.remove(0);
        if target.uid != allowed_target_uid {
            return Err(
                "SAML Signature Reference must target the enclosing Response or Assertion element"
                    .into(),
            );
        }
        (target, anc)
    } else {
        return Err(format!(
            "unsupported non-local XML-DSig Reference URI '{uri}'"
        ));
    };

    let mut ref_with_comments = false;
    let mut has_enveloped = false;
    let mut ref_inclusive = BTreeSet::new();
    if let Some(transforms) = reference
        .child_elems()
        .into_iter()
        .find(|c| c.local_name() == "Transforms")
    {
        for tr in transforms.child_elems() {
            if tr.local_name() != "Transform" {
                continue;
            }
            let alg = tr.attr("Algorithm").unwrap_or("");
            if alg == ENVELOPED_SIG_NS {
                has_enveloped = true;
            } else if alg == EXC_C14N_NS {
                if let Some(inc) = tr
                    .child_elems()
                    .into_iter()
                    .find(|i| i.local_name() == "InclusiveNamespaces")
                    .and_then(|i| i.attr("PrefixList"))
                {
                    for p in inc.split_whitespace() {
                        ref_inclusive.insert(p.to_owned());
                    }
                }
            } else if alg == EXC_C14N_WITH_COMMENTS_NS {
                ref_with_comments = true;
            }
        }
    }
    if !has_enveloped {
        return Err("SAML XML-DSig Reference must include enveloped-signature transform".into());
    }

    let digest_method = reference
        .child_elems()
        .into_iter()
        .find(|c| c.local_name() == "DigestMethod")
        .and_then(|c| c.attr("Algorithm"))
        .ok_or("ds:Reference missing DigestMethod Algorithm")?;
    let digest_b64: String = reference
        .child_elems()
        .into_iter()
        .find(|c| c.local_name() == "DigestValue")
        .ok_or("ds:Reference missing DigestValue")?
        .text_content()
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let expected_digest = STANDARD
        .decode(digest_b64)
        .map_err(|e| format!("invalid SAML DigestValue base64: {e}"))?;

    let canon_target = exclusive_canonicalize(
        target_elem,
        &target_ancestors,
        Some(sig_elem.uid),
        ref_with_comments,
        &ref_inclusive,
    );
    let actual_digest = compute_digest(digest_method, canon_target.as_bytes(), compliance_mode)?;
    if actual_digest.len() != expected_digest.len()
        || !constant_time_eq(&actual_digest, &expected_digest)
    {
        return Err("SAML XML-DSig DigestValue mismatch (payload modified)".into());
    }

    let sig_b64: String = sig_elem
        .child_elems()
        .into_iter()
        .find(|c| c.local_name() == "SignatureValue")
        .ok_or("ds:Signature missing SignatureValue")?
        .text_content()
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let sig_bytes = STANDARD
        .decode(sig_b64)
        .map_err(|e| format!("invalid SAML SignatureValue base64: {e}"))?;

    let mut si_anc = sig_ancestors;
    si_anc.push(&sig_elem);
    let canon_signed_info =
        exclusive_canonicalize(signed_info, &si_anc, None, with_comments, &si_inclusive);

    let mut last_err =
        "SAML XML signature verification failed against pinned IdP certificate(s)".to_owned();
    for key in &keys {
        match verify_signature_bytes(
            key,
            sig_method,
            canon_signed_info.as_bytes(),
            &sig_bytes,
            compliance_mode,
        ) {
            Ok(()) => {
                return Ok(VerifiedSamlSubtree {
                    response: root,
                    assertion: verified_assertion,
                });
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}
