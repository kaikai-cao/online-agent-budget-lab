"""T4 signed-value tampering: all schemes detect INVALID_SIGNATURE."""
import _base  # noqa: F401
import unittest

from r24.scenarios import TRIALS, run_trial


class TestSignatureTampering(unittest.TestCase):
    def test_t4_tampered_value_breaks_signature_in_all_schemes(self):
        for t in range(TRIALS):
            with self.subTest(trial=t):
                rec = run_trial("T4", t)
                for s in ("A", "B", "C"):
                    self.assertIn("INVALID_SIGNATURE", rec.schemes[s]["verdict_names"])
                    # tampered A(999) rejected; only B(200) billed
                    self.assertEqual(rec.schemes[s]["charged_total"], 200)
                    self.assertFalse(rec.schemes[s]["settleable"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
