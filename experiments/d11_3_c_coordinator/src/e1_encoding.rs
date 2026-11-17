//! E1.1 cross-language canonical encoding (Rust side).
//!
//! Scope is deliberately an *encoding layer only*: fixed byte encodings shared
//! with the Python side (canonical JSON, SHA-256 digest entry points, Pallas Fp
//! hex, uint32 <-> Fp, proof Base64, digest-format validation). It performs no
//! proof verification, computes no Poseidon commitment, and is never a
//! substitute for the frozen D11.3-B.1 Halo2 circuit.
//!
//! `serde_json::Value` is used only to PARSE inputs. Canonical serialization is
//! implemented here by hand to match Python `json.dumps(sort_keys=True,
//! separators=(",", ":"), ensure_ascii=False, allow_nan=False)` byte-for-byte;
//! we do not rely on serde_json's default serializer because its escaping and
//! number formatting are not guaranteed identical.

use halo2_proofs::pasta::Fp;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{fp_from_bytes, fp_to_bytes, FIELD_BYTES, MAX_UINT32};

/// Pallas base-field modulus, matching Python `PALLAS_FP_MODULUS` and D11.3-D.
pub const PALLAS_FP_MODULUS_DEC: &str =
    "28948022309329048855892746252171976963363056481941560715954676764349967630337";

/// Encoding-layer errors (uint32 domain, float rejection, bad hex/base64, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E1EncodingError(pub String);

impl std::fmt::Display for E1EncodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "e1 encoding error: {}", self.0)
    }
}
impl std::error::Error for E1EncodingError {}

fn err(msg: impl Into<String>) -> E1EncodingError {
    E1EncodingError(msg.into())
}

/// Append a JSON string exactly as Python `json.dumps(..., ensure_ascii=False)`.
///
/// Python escapes `"` and `\` plus control chars (`\b \f \n \r \t`, otherwise
/// `\u00xx` lowercase hex) and emits every non-ASCII code point verbatim in
/// UTF-8. It does NOT escape `/`.
fn write_json_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), E1EncodingError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // E1 credential JSON accepts integers only; floats are rejected even
            // when integral (Python side rejects any `float` instance).
            if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else {
                return Err(err("float / out-of-range number is not allowed"));
            }
        }
        Value::String(s) => write_json_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort(); // UTF-8 byte order == Unicode code-point order
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(out, key);
                out.push(':');
                write_canonical(&map[*key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Canonical UTF-8 bytes of a value, byte-identical to the Python side.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, E1EncodingError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out.into_bytes())
}

/// `sha256:` digest of the canonical bytes of the WHOLE object (flat D_E form).
pub fn digest_object(value: &Value) -> Result<String, E1EncodingError> {
    let bytes = canonical_json_bytes(value)?;
    let sum = Sha256::digest(&bytes);
    Ok(format!("sha256:{}", hex_lower(sum.as_slice())))
}

/// Digest of `{"domain": domain, "payload": payload}` (E.0 nested form).
pub fn canonical_digest(domain: &str, payload: &Value) -> Result<String, E1EncodingError> {
    let mut wrapper = serde_json::Map::new();
    wrapper.insert("domain".to_string(), Value::String(domain.to_string()));
    wrapper.insert("payload".to_string(), payload.clone());
    digest_object(&Value::Object(wrapper))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Canonical Pallas Fp -> 64-char lowercase little-endian hex (reuses crate fp bytes).
pub fn fp_to_hex(value: &Fp) -> String {
    hex_lower(&fp_to_bytes(value))
}

const LOWER_HEX: &[u8] = b"0123456789abcdef";

/// Strict inverse of `fp_to_hex`; rejects uppercase, wrong length, non-hex and
/// non-canonical (>= modulus) encodings.
pub fn fp_from_hex_strict(text: &str) -> Option<Fp> {
    if text.len() != FIELD_BYTES * 2 {
        return None;
    }
    let mut out = [0u8; FIELD_BYTES];
    for (i, slot) in out.iter_mut().enumerate() {
        // hex is little-endian byte order: first two chars = byte 0
        let hi = *text.as_bytes().get(i * 2)?;
        let lo = *text.as_bytes().get(i * 2 + 1)?;
        let hi = LOWER_HEX.iter().position(|&c| c == hi)? as u8;
        let lo = LOWER_HEX.iter().position(|&c| c == lo)? as u8;
        *slot = (hi << 4) | lo;
    }
    fp_from_bytes(&out)
}

/// E1 Q/c semantics: 1 <= uint32 <= 2^32-1, no truncation, -> Fp hex.
pub fn u32_to_fp_hex(value: u64) -> Result<String, E1EncodingError> {
    if value == 0 || value > MAX_UINT32 {
        return Err(err("Q/c must be in [1, 2^32-1]"));
    }
    let fp = Fp::from(value);
    Ok(fp_to_hex(&fp))
}

/// Strict Fp hex -> uint32; rejects 0 and values above 2^32-1.
pub fn fp_hex_to_u32(text: &str) -> Result<u32, E1EncodingError> {
    let fp = fp_from_hex_strict(text).ok_or_else(|| err("invalid canonical Fp hex"))?;
    let bytes = fp_to_bytes(&fp);
    if bytes[4..].iter().any(|b| *b != 0) {
        return Err(err("field value is above uint32 range"));
    }
    let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if value == 0 {
        return Err(err("Q/c must be nonzero"));
    }
    Ok(value)
}

/// Standard RFC 4648 Base64 encode with padding; rejects empty proof.
pub fn proof_b64_encode(data: &[u8]) -> Result<String, E1EncodingError> {
    use base64::Engine;
    if data.is_empty() {
        return Err(err("empty proof is not allowed"));
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(data))
}

/// Strict Base64 decode: alphabet/padding checked, canonical round-trip enforced.
pub fn proof_b64_decode(text: &str) -> Result<Vec<u8>, E1EncodingError> {
    use base64::Engine;
    if text.is_empty() {
        return Err(err("proof base64 must be non-empty"));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| err("invalid base64 proof"))?;
    if decoded.is_empty() {
        return Err(err("empty proof is not allowed"));
    }
    let reencoded = base64::engine::general_purpose::STANDARD.encode(&decoded);
    if reencoded != text {
        return Err(err("non-canonical base64 proof"));
    }
    Ok(decoded)
}

/// `sha256:` + 64 lowercase hex, length 71; uppercase/bad length/bad hex rejected.
pub fn is_sha256(value: &str) -> bool {
    if value.len() != 71 || !value.starts_with("sha256:") {
        return false;
    }
    value.as_bytes()[7..].iter().all(|b| LOWER_HEX.contains(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_is_sha256() {
        assert!(is_sha256(&format!("sha256:{}", "ab".repeat(32))));
        assert!(!is_sha256(&format!("sha256:{}", "AB".repeat(32))));
    }
}
