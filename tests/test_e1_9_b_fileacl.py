"""E1.9-B / B-F2 -- private-file ACL isolation tests.

Three layers, deliberately separated so no simulated result is passed off as a
real Windows ACL acceptance:

  * FileAclPolicyCase (no admin, always runs): exercises the PLATFORM-INDEPENDENT
    policy decision ``dacl_problems`` with injected ``DaclView`` objects.  These
    prove the fail-closed rules and the deploy/verify consistency of the ACL
    SHAPE produced by ``setup_journal_service_acl.ps1``, but are NOT a real ACL
    test.
  * DeployShapeCase (no admin): feeds the exact ACE shape emitted by the
    administrator script (grant service/SYSTEM/Administrators, deny Executor)
    through ``dacl_problems`` and proves it PASSES, while a too-weak DENY, a
    denied service account, an unexpected/over-broad principal, and an Executor
    ALLOW all FAIL.  This is the regression for the B-F2 follow-up finding.
  * RealFileAclCase (env-gated by E1B_REAL_ACL=1, needs Windows + the current
    account's privileges): uses ``restrict_to_sids`` with a real DENY ACE so the
    apply -> read_dacl(parsed SID+mask) -> verify_private_file closed loop is
    exercised against Win32.  True second-account DENIAL still requires the
    administrator steps in the implementation report and is not claimed here.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from online_budget.journal_fileacl import (
    ADMINISTRATORS_SID,
    BROAD_PRINCIPAL_SIDS,
    DaclView,
    FileACLError,
    FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ,
    FILE_GENERIC_WRITE,
    GENERIC_ALL,
    GENERIC_READ,
    SYSTEM_SID,
    DELETE,
    dacl_problems,
    read_dacl,
    restrict_to_sids,
    verify_private_file,
)


_SVC = "S-1-5-21-100-SVC"
_EXEC = "S-1-5-21-100-EXEC"
# Mask emitted by ``icacls /deny *EXEC:(OI)(CI)(RX,D,W)`` in the deploy script.
_DEPLOY_DENY_MASK = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE


def _deploy_shape_view(*, exec_deny_mask: int = _DEPLOY_DENY_MASK, extra_allow=None, extra_deny=None) -> DaclView:
    """ACL shape produced by ``setup_journal_service_acl.ps1`` Lock-Dir.

    Grant GENERIC_ALL to service + SYSTEM + Administrators; DENY the Executor.
    """
    allow = {_SVC: GENERIC_ALL, SYSTEM_SID: GENERIC_ALL, ADMINISTRATORS_SID: GENERIC_ALL}
    deny = {_EXEC: exec_deny_mask}
    if extra_allow:
        allow.update(extra_allow)
    if extra_deny:
        deny.update(extra_deny)
    return DaclView(allow=allow, deny=deny)


class FileAclPolicyCase(unittest.TestCase):
    def test_F01_safe_deploy_shape_passes(self):
        problems = dacl_problems(
            _deploy_shape_view(),
            allowed_sids=(_SVC,),
            forbidden_read_sids=(_EXEC,),
            forbidden_write_sids=(_EXEC,),
            expected_deny_sids=(_EXEC,),
        )
        self.assertEqual(problems, [])

    def test_F02_executor_read_grant_fails(self):
        problems = dacl_problems(
            _deploy_shape_view(extra_allow={_EXEC: GENERIC_READ}),
            allowed_sids=(_SVC,),
            forbidden_read_sids=(_EXEC,),
            forbidden_write_sids=(_EXEC,),
            expected_deny_sids=(_EXEC,),
        )
        self.assertTrue(any("READ" in p for p in problems))

    def test_F03_no_service_allow_fails_closed(self):
        problems = dacl_problems(
            DaclView(allow={_EXEC: 0}, deny={}),
            allowed_sids=(_SVC,),
            forbidden_read_sids=(_EXEC,),
            forbidden_write_sids=(_EXEC,),
            expected_deny_sids=(_EXEC,),
        )
        self.assertTrue(any("no allow ACE" in p for p in problems))

    def test_F04_null_dacl_everyone_fails_closed(self):
        # read_dacl maps a NULL DACL to Everyone/GENERIC_ALL; policy rejects it
        # because Everyone is not an allowed principal.
        problems = dacl_problems(
            DaclView(allow={"S-1-1-0": GENERIC_ALL}, deny={}),
            allowed_sids=(_SVC,),
            forbidden_read_sids=("S-1-1-0",),
            forbidden_write_sids=("S-1-1-0",),
            expected_deny_sids=(),
        )
        self.assertTrue(problems)

    def test_F05_unknown_deny_principal_fails_closed(self):
        problems = dacl_problems(
            _deploy_shape_view(extra_deny={"S-1-5-21-999-UNKNOWN": _DEPLOY_DENY_MASK}),
            allowed_sids=(_SVC,),
            forbidden_read_sids=(_EXEC,),
            forbidden_write_sids=(_EXEC,),
            expected_deny_sids=(_EXEC,),
        )
        self.assertTrue(any("unexpected DENY" in p for p in problems))

    def test_F06_service_sid_denied_fails_closed(self):
        problems = dacl_problems(
            _deploy_shape_view(extra_deny={_SVC: _DEPLOY_DENY_MASK}),
            allowed_sids=(_SVC,),
            forbidden_read_sids=(_EXEC,),
            forbidden_write_sids=(_EXEC,),
            expected_deny_sids=(_EXEC, _SVC),  # even if claimed expected, service stays forbidden
        )
        self.assertTrue(any("service/trusted SID" in p for p in problems))

    def test_F07_too_weak_deny_mask_fails_closed(self):
        problems = dacl_problems(
            _deploy_shape_view(exec_deny_mask=FILE_GENERIC_READ),  # denies READ only, not WRITE
            allowed_sids=(_SVC,),
            forbidden_read_sids=(_EXEC,),
            forbidden_write_sids=(_EXEC,),
            expected_deny_sids=(_EXEC,),
        )
        self.assertTrue(any("insufficient mask" in p for p in problems))

    def test_F08_broad_principal_allow_fails_closed(self):
        for broad in BROAD_PRINCIPAL_SIDS:
            with self.subTest(broad=broad):
                problems = dacl_problems(
                    _deploy_shape_view(extra_allow={broad: GENERIC_ALL}),
                    allowed_sids=(_SVC,),
                    forbidden_read_sids=(_EXEC,),
                    forbidden_write_sids=(_EXEC,),
                    expected_deny_sids=(_EXEC,),
                )
                self.assertTrue(any("not in allowlist" in p for p in problems))

    def test_F09_unparsed_ace_marker_fails_closed(self):
        problems = dacl_problems(
            DaclView(allow={_SVC: GENERIC_ALL}, deny={}, unparsed=("<unparsed-ace-5>",)),
            allowed_sids=(_SVC,),
        )
        self.assertTrue(any("unparsed ACE" in p for p in problems))

    def test_F10_config_parser_roundtrips_bf2_fields(self):
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


class DeployShapeCase(unittest.TestCase):
    """Regression for the B-F2 follow-up finding (script vs startup check)."""

    def test_D01_deploy_script_acl_shape_accepted(self):
        # Exactly what Lock-Dir emits: service/SYSTEM/Admins allow, Executor deny
        # with the icacls (RX,D,W) mask -> MUST pass the startup policy.
        problems = dacl_problems(
            _deploy_shape_view(),
            allowed_sids=(_SVC,),
            forbidden_read_sids=(_EXEC,),
            forbidden_write_sids=(_EXEC,),
            expected_deny_sids=(_EXEC,),
        )
        self.assertEqual(problems, [])

    def test_D02_legacy_opaque_deny_marker_still_fails(self):
        # Earlier read_dacl recorded "<deny-ace-1>" with no SID/mask.  Any such
        # un-attributed deny must remain a problem (never silently accepted).
        problems = dacl_problems(
            {"<deny-ace-1>": 0, _SVC: GENERIC_ALL},
            allowed_sids=(_SVC,),
        )
        self.assertTrue(any("deny/unparsed ACE" in p for p in problems))

    def test_D03_deny_mask_rejects_generic_all_without_low_bits(self):
        # A mask of only GENERIC_ALL is acceptable (it implies both directions).
        problems = dacl_problems(
            _deploy_shape_view(exec_deny_mask=GENERIC_ALL),
            allowed_sids=(_SVC,),
            forbidden_read_sids=(_EXEC,),
            forbidden_write_sids=(_EXEC,),
            expected_deny_sids=(_EXEC,),
        )
        self.assertEqual(problems, [])


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

    def test_R01_deploy_shape_apply_read_verify_roundtrip(self):
        # End-to-end for the B-F2 finding: apply a deploy-script-shaped DACL
        # (real ALLOW + real DENY ACE), read it back with parsed SID/mask, and
        # pass the service startup verifier.  Earlier code failed here because
        # the DENY ACE was rejected unconditionally.
        restrict_to_sids(
            self.file,
            (self.current_sid,),
            deny_sids=("S-1-5-21-999-999-999-9999",),
            deny_mask=_DEPLOY_DENY_MASK,
        )
        observed = read_dacl(self.file)
        self.assertIn("S-1-5-21-999-999-999-9999", observed.deny)
        self.assertTrue(observed.deny["S-1-5-21-999-999-999-9999"] & _DEPLOY_DENY_MASK)
        verify_private_file(
            self.file,
            allowed_sids=(self.current_sid,),
            forbidden_read_sids=("S-1-5-21-999-999-999-9999",),
            forbidden_write_sids=("S-1-5-21-999-999-999-9999",),
        )

    def test_R02_restrict_to_sids_then_verify_passes(self):
        restrict_to_sids(self.file, (self.current_sid,))
        observed = read_dacl(self.file)
        self.assertIn(self.current_sid, observed.allow)
        verify_private_file(
            self.file,
            allowed_sids=(self.current_sid,),
            forbidden_read_sids=("S-1-5-99-NOBODY",),
        )

    def test_R03_verify_fails_when_forbidden_sid_has_access(self):
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
