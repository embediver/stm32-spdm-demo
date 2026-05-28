//! Certificates sourced from: spdm-emu/libspdm/unit_test/sample_key/ecp384/
//! - ca.cert.der: root CA
//! - inter.cert.der: intermediate CA signed by the root
//! - end_responder.cert.der: end-entity cert signed by the intermediate CA
//! - end_responder.key.der: SEC1 DER-encoded P-384 private key for the end-entity cert

pub const CA_CERT: &[u8] = include_bytes!("../certs/ca.cert.der");
/// Intermediate responder certificate
pub const INTER_CERT: &[u8] = include_bytes!("../certs/end_responder.cert.der");
/// End responder certificate
pub const END_RESPONDER_CERT: &[u8] = include_bytes!("../certs/end_responder.cert.der");
/// Responder end certificate key
pub const END_RESPONDER_KEY: &[u8] = include_bytes!("../certs/end_responder.key.der");

/// Total length of the responder certificate chain
pub const CERT_CHAIN_LEN: usize = CA_CERT.len() + INTER_CERT.len() + END_RESPONDER_CERT.len();

pub const HEX_CA_CERT_SHA384: &str = include_str!("../certs/ca.cert.der.sha384sum");
