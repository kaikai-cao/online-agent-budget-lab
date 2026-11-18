"""E1.9-B / B-F2 -- private-file ACL isolation tests.

Two layers, deliberately separated so no simulated result is passed off as a
real Windows ACL acceptance:

  * FileAclPolicyCase (no admin, always runs): exercises the PLATFORM-INDEPENDENT
    policy decision ``dacl_problems`` with injected ACL maps.  These prove the
    fail-closed rules but are NOT a real ACL test.
  * RealFileAclCase (env-gated by E1B_REAL_ACL=1, needs Windows + the current
    account's privileges): creates a temp file, applies ``restrict_to_sids`` to
    the current account SID, then verifies (a) verify_private_file passes for
    an allowed SID, (b) it FAILS when a forbidden SID is injected via an extra
    ACE, and (c) read_dacl sees the real DACL.  True second-account DENIAL still
    requires the administrator steps in the implementation report and is not
    claimed here.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from online_budget.journal_fileacl import (
    FileACLError,
    GENERIC_ALL,
    GENERIC_READ,
    dacl_problems,
    read_dacl,
    restrict_to_sids,
    verify_private_file,
)


_SVC = "S-1-5-21-100-SVC"
_EXEC = "S-1-5-21-100-EXEC"


class FileAclPolicyCase(unittest.TestCase):
    def test_F01_safe_acl_passes(self):
        problems = dacl_problems(
            {_SVC: GENERIC_ALL, _EXEC: 0},
            allowed_sids=(_SVC,),
            forbidden_read_sids=(_EXEC,),
            forbidden_write_sids=(_EXEC,),
        )
        self.assertEqual(problems, [])

    def test_F02_executor_read_denied_by_policy(self):
        problems = dacl_problems(
            {_SVC: GENERIC_ALL, _EXEC: GENERIC_READ},
            allowed_sids=(_SVC,),
            forbidden_read_sids=(_EXEC,),
            forbidden_write_sids=(_EXEC,),
        )
        self.assertTrue(any("READ" in p for p in problems))

    def test_F03_no_service_ace_fails_closed(self):
        problems = dacl_problems(
            {_EXEC: 0}, allowed_sids=(_SVC,),
            forbidden_read_sids=(_EXEC,), forbidden_write_sids=(_EXEC,),
        )
        self.assertTrue(any("no allow ACE" in p for p in problems))

    def test_F04_null_dacl_marker_fails_closed(self):
        # read_dacl maps a NULL DACL to Everyone/GENERIC_ALL; policy rejects it.
        problems = dacl_problems(
            {"S-1-1-0": GENERIC_ALL},
            allowed_sids=(_SVC,),
            forbidden_read_sids=("S-1-1-0",), forbidden_write_sids=("S-1-1-0",),
        )
        self.assertTrue(problems)

    def test_F05_deny_ace_marker_fails_closed(self):
        problems = dacl_problems(
            {_SVC: GENERIC_ALL, "<deny-ace-1>": 0},
            allowed_sids=(_SVC,), forbidden_read_sids=(), forbidden_write_sids=(),
        )
        self.assertTrue(any("deny ACE" in p for p in problems))

    def test_F06_config_parser_roundtrips_bf2_fields(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from _e1b_helpers import make_config

        tmp = tempfile.TemporaryDirectory()
        try:
            cfg, raw = make_config(
                base_dir=Path(tmp.name),
                journal_key=Ed25519PrivateKey.generate(),
                executor_key=Ed25519PrivateKey.generate(),
            )
            raw["journal_service_sid"] = _SVC
            raw["executor_account_sids"] = [_EXEC]
            from online_budget.journal_service_config import ServiceConfig
            cfg2 = ServiceConfig.from_dict(raw, base_dir=Path(tmp.name))
            self.assertEqual(cfg2.journal_service_sid, _SVC)
            self.assertEqual(cfg2.executor_account_sids, (_EXEC,))
            self.assertIn("journal_service_sid", cfg2.redacted_dict())
        finally:
            tmp.cleanup()


@unittest.skipUnless(
    os.environ.get("E1B_REAL_ACL") == "1",
    "real Windows ACL test gated by E1B_REAL_ACL=1",
)
class RealFileAclCase(unittest.TestCase):
    def setUp(self) -> None:
        from online_budget.journal_identity import current_process_identity

        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.current_sid = current_process_identity().sid
        self.file = self.dir / "private.key"
        self.file.write_text("secret", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_F07_restrict_to_sids_then_verify_passes(self):
        restrict_to_sids(self.file, (self.current_sid,))
        observed = read_dacl(self.file)
        self.assertIn(self.current_sid, observed)
        verify_private_file(
            self.file,
            allowed_sids=(self.current_sid,),
            forbidden_read_sids=("S-1-5-99-NOBODY",),
        )

    def test_F08_verify_fails_when_executor_sid_has_access(self):
        # We can only grant ourselves in this environment; inject a fake
        # forbidden SID that IS the current SID to prove the policy rejects an
        # observed read grant (the real second-account case needs ADMIN).
        restrict_to_sids(self.file, (self.current_sid,))
        with self.assertRaises(FileACLError):
            verify_private_file(
                self.file,
                allowed_sids=(self.current_sid,),
                forbidden_read_sids=(self.current_sid,),
            )


if __name__ == "__main__":
    unittest.main()
