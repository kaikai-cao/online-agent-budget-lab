"""E1.1 golden-vector tests (Python side).

Every expected value is read from the single shared file
``experiments/d11_3_c_coordinator/test-vectors/e1_encoding_v1.json``. This module
never computes its own expectations; it only runs the module under test against
the frozen vectors and checks byte-for-byte agreement with the Rust side.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from online_budget import e1_encoding as enc

VECTOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "experiments"
    / "d11_3_c_coordinator"
    / "test-vectors"
    / "e1_encoding_v1.json"
)


class E1EncodingVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with VECTOR_PATH.open("r", encoding="utf-8") as handle:
            cls.data = json.load(handle)
        cls.g = cls.data["groups"]

    # ---- G01-G06 canonical bytes + whole-object digest -----------------
    def test_canonical_and_digest_groups(self):
        for name in ("G01", "G02", "G03", "G04", "G05", "G06"):
            with self.subTest(group=name):
                case = self.g[name]
                self.assertEqual(
                    enc.canonical_json_bytes(case["value"]).decode("utf-8"),
                    case["canonical"],
                )
                self.assertEqual(enc.digest_object(case["value"]), case["digest"])

    def test_canonical_digest_is_nested_form(self):
        # canonical_digest(domain, payload) == digest_object({"domain":..., "payload":...})
        for name in ("attestation", "receipt", "signature"):
            with self.subTest(case=name):
                c = self.g["G07"][name]
                self.assertEqual(
                    enc.canonical_digest(c["domain"], c["payload"]), c["digest"]
                )
                self.assertEqual(
                    enc.canonical_json_bytes(
                        {"domain": c["domain"], "payload": c["payload"]}
                    ).decode("utf-8"),
                    c["canonical"],
                )

    def test_digest_forms_are_domain_separated(self):
        # The flat D_E form must differ from the nested canonical_digest form.
        flat = self.g["G06"]["value"]
        inner = {k: v for k, v in flat.items() if k != "domain"}
        self.assertNotEqual(
            enc.digest_object(flat),
            enc.canonical_digest(flat["domain"], inner),
        )

    # ---- G08 Pallas Fp boundaries --------------------------------------
    def test_fp_hex_roundtrip(self):
        for case in self.g["G08"]:
            value = int(case["value"])
            with self.subTest(value=value):
                self.assertEqual(enc.fp_to_hex(value), case["hex"])
                self.assertEqual(enc.fp_from_hex(case["hex"]), value)

    # ---- G09 uint32 <-> Fp ---------------------------------------------
    def test_u32_fp_conversion(self):
        for case in self.g["G09"]:
            with self.subTest(value=case["value"]):
                self.assertEqual(enc.u32_to_fp_hex(case["value"]), case["hex"])
                self.assertEqual(enc.fp_hex_to_u32(case["hex"]), case["value"])

    # ---- G10 rejection cases -------------------------------------------
    def test_reject_noncanonical_fp_hex(self):
        g = self.g["G10"]
        for key in ("uppercase_hex", "odd_length_hex", "nonhex_char",
                    "modulus_hex", "above_modulus_hex"):
            with self.subTest(case=key):
                with self.assertRaises(enc.E1EncodingError):
                    enc.fp_from_hex(g[key])

    def test_reject_fp_hex_to_u32_out_of_range(self):
        self.assertEqual(enc.fp_hex_to_u32(self.g["G09"][0]["hex"]), 1)  # sanity
        with self.assertRaises(enc.E1EncodingError):
            enc.fp_hex_to_u32(self.g["G08"][0]["hex"])  # zero rejected
        with self.assertRaises(enc.E1EncodingError):
            enc.fp_hex_to_u32(self.g["G08"][4]["hex"])  # > 2^32-1 rejected

    def test_reject_bool_and_float_and_u32_bounds(self):
        g = self.g["G10"]
        with self.assertRaises(enc.E1EncodingError):
            enc.u32_to_fp_hex(g["bool_value"])      # bool is not a valid uint32
        with self.assertRaises(enc.E1EncodingError):
            enc.u32_to_fp_hex(g["u32_zero"])        # Q/c must be >= 1
        with self.assertRaises(enc.E1EncodingError):
            enc.u32_to_fp_hex(g["u32_overflow"])    # 2^32 rejected, no truncation
        with self.assertRaises(enc.E1EncodingError):
            enc.canonical_json_bytes(g["float_value"])  # floats not in E1 domain

    # ---- G11/G12 Base64 ------------------------------------------------
    def test_proof_base64_roundtrip(self):
        for case in self.g["G11"]:
            with self.subTest(raw=case["raw_hex"]):
                raw = bytes.fromhex(case["raw_hex"])
                self.assertEqual(enc.proof_b64_encode(raw), case["b64"])
                self.assertEqual(enc.proof_b64_decode(case["b64"]), raw)

    def test_reject_invalid_base64(self):
        for value in self.g["G12"]:
            with self.subTest(value=value):
                with self.assertRaises(enc.E1EncodingError):
                    enc.proof_b64_decode(value)

    # ---- G13 sha256 format ---------------------------------------------
    def test_is_sha256(self):
        g = self.g["G13"]
        self.assertTrue(enc.is_sha256(g["valid"]))
        for key in ("uppercase", "short", "long", "nonhex", "nprefix"):
            with self.subTest(case=key):
                self.assertFalse(enc.is_sha256(g[key]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
