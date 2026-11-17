//! E1.1 golden-vector tests (Rust side).
//!
//! Reads the SAME shared file as the Python tests:
//!   test-vectors/e1_encoding_v1.json
//! Expected values are frozen in that file; this module only runs the module
//! under test against them and checks byte-for-byte agreement.

use std::fs;
use std::path::PathBuf;

use d11_3_c_coordinator::e1_encoding as enc;
use serde_json::Value;

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors")
        .join("e1_encoding_v1.json");
    let text = fs::read_to_string(path).expect("read golden vectors");
    serde_json::from_str(&text).expect("parse golden vectors")
}

fn g<'a>(root: &'a Value, name: &str) -> &'a Value {
    &root["groups"][name]
}

#[test]
fn g01_to_g06_canonical_and_digest() {
    let root = vectors();
    for name in ["G01", "G02", "G03", "G04", "G05", "G06"] {
        let case = g(&root, name);
        let expected_canon = case["canonical"].as_str().unwrap();
        let bytes = enc::canonical_json_bytes(&case["value"]).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            expected_canon,
            "{name} canonical"
        );
        assert_eq!(
            enc::digest_object(&case["value"]).unwrap(),
            case["digest"].as_str().unwrap(),
            "{name} digest"
        );
    }
}

#[test]
fn g07_canonical_digest_nested_form() {
    let root = vectors();
    let group = g(&root, "G07");
    for name in ["attestation", "receipt", "signature"] {
        let case = &group[name];
        assert_eq!(
            enc::canonical_digest(case["domain"].as_str().unwrap(), &case["payload"]).unwrap(),
            case["digest"].as_str().unwrap(),
            "G07.{name}"
        );
    }
}

#[test]
fn digest_forms_are_domain_separated() {
    let root = vectors();
    let flat = g(&root, "G06")["value"].clone();
    let domain = flat["domain"].as_str().unwrap().to_string();
    let mut inner = flat.clone();
    inner.as_object_mut().unwrap().remove("domain");
    assert_ne!(
        enc::digest_object(&flat).unwrap(),
        enc::canonical_digest(&domain, &inner).unwrap()
    );
}

#[test]
fn g08_fp_hex_roundtrip() {
    let root = vectors();
    for case in g(&root, "G08").as_array().unwrap() {
        let hex = case["hex"].as_str().unwrap();
        let fp = enc::fp_from_hex_strict(hex).unwrap_or_else(|| panic!("decode {hex}"));
        assert_eq!(enc::fp_to_hex(&fp), hex);
        // u32 numeric correspondence only for values in [1, 2^32-1];
        // value 0 is a valid Fp element but an invalid Q/c.
        let dec = case["value"].as_str().unwrap();
        if let Ok(v) = dec.parse::<u64>() {
            if (1..=4_294_967_295).contains(&v) {
                assert_eq!(enc::u32_to_fp_hex(v).ok(), Some(hex.to_string()));
            }
        }
    }
}

#[test]
fn g09_u32_fp_conversion() {
    let root = vectors();
    for case in g(&root, "G09").as_array().unwrap() {
        let value = case["value"].as_u64().unwrap();
        let hex = case["hex"].as_str().unwrap();
        assert_eq!(enc::u32_to_fp_hex(value).unwrap(), hex);
        assert_eq!(enc::fp_hex_to_u32(hex).unwrap(), value as u32);
    }
}

#[test]
fn g10_reject_noncanonical_fp_hex() {
    let root = vectors();
    let group = g(&root, "G10");
    for key in [
        "uppercase_hex",
        "odd_length_hex",
        "nonhex_char",
        "modulus_hex",
        "above_modulus_hex",
    ] {
        let value = group[key].as_str().unwrap();
        assert!(
            enc::fp_from_hex_strict(value).is_none(),
            "G10.{key} must be rejected"
        );
    }
    assert!(enc::u32_to_fp_hex(group["u32_zero"].as_u64().unwrap()).is_err());
    assert!(enc::u32_to_fp_hex(group["u32_overflow"].as_u64().unwrap()).is_err());
    // bool / float never reach a typed u32 function in Rust; parsing rejects them:
    assert!(group["bool_value"].as_u64().is_none());
    assert!(group["float_value"].as_u64().is_none());
}

#[test]
fn g10_fp_hex_to_u32_out_of_range() {
    let root = vectors();
    // zero from G08[0] and >u32 from G08[4] must be rejected by fp_hex_to_u32
    let g08 = g(&root, "G08").as_array().unwrap();
    assert!(enc::fp_hex_to_u32(g08[0]["hex"].as_str().unwrap()).is_err());
    assert!(enc::fp_hex_to_u32(g08[4]["hex"].as_str().unwrap()).is_err());
}

#[test]
fn g11_proof_base64_roundtrip() {
    let root = vectors();
    for case in g(&root, "G11").as_array().unwrap() {
        let raw = hex_to_bytes(case["raw_hex"].as_str().unwrap());
        let b64 = case["b64"].as_str().unwrap();
        assert_eq!(enc::proof_b64_encode(&raw).unwrap(), b64);
        assert_eq!(enc::proof_b64_decode(b64).unwrap(), raw);
    }
}

#[test]
fn g12_reject_invalid_base64() {
    let root = vectors();
    for case in g(&root, "G12").as_array().unwrap() {
        let value = case.as_str().unwrap();
        assert!(
            enc::proof_b64_decode(value).is_err(),
            "G12 {value:?} must be rejected"
        );
    }
}

#[test]
fn g13_is_sha256() {
    let root = vectors();
    let group = g(&root, "G13");
    assert!(enc::is_sha256(group["valid"].as_str().unwrap()));
    for key in ["uppercase", "short", "long", "nonhex", "nprefix"] {
        assert!(!enc::is_sha256(group[key].as_str().unwrap()), "G13.{key}");
    }
}

fn hex_to_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
