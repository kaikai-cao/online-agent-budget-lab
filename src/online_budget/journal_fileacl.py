"""E1.9-B / B-F2 -- private-file ACL enforcement for the Journal Service.

The B2 design freezes three separate trust domains: ADMIN, the Journal service
account (JRNL_SVC_ACCT), and the Executor account (EXEC_ACCT).  B.1/B.2 covered
the Named Pipe ACL and the OS caller identity; this module covers the OTHER
half of the boundary that was missing in `e689f7d`: the signing key, the fixed
config, and both SQLite databases must be readable/writable ONLY by the service
account, so a compromised Executor account cannot read the Journal signing key
or mutate the Journal / idempotency databases.

Real Win32 primitives via ctypes (stdlib only, no pywin32).  Nothing here is an
HSM/TPM and nothing claims protection against an administrator who controls the
service account or can take ownership of files.  It implements the frozen B2
deployment assumption: an OS ACL that denies the Executor account.

Two layers:
  * ``restrict_to_sids`` (deploy time, ADMIN): set a PROTECTED DACL on a file or
    directory granting only the given SIDs; inherited ACEs are removed.  An
    optional ``deny_sids`` creates DENY ACEs matching
    ``scripts/setup_journal_service_acl.ps1`` so the Python deploy path and the
    PowerShell deploy path produce the SAME shape of ACL.
  * ``verify_private_file`` (service start, fail-closed): read each file's
    effective DACL and REFUSE to start if a forbidden SID retains read access
    to the key/config or write access to a database.  A missing/unreadable ACL
    is itself a failure (never treat "unknown" as "safe").

B-F2 deploy/verify consistency (this revision):
  The administrator script ``setup_journal_service_acl.ps1`` deliberately adds
  a DENY ACE for the Executor account (``icacls /deny ...:(RX,D,W)``).  An
  earlier revision recorded every non-allow ACE as an opaque ``<deny-ace-N>``
  marker and ``dacl_problems`` rejected ALL such markers.  That made the
  service refuse to start on an ACL produced by the project's OWN deploy
  script.  DENY ACEs are now parsed into (SID, mask) pairs, a DENY for an
  explicitly expected principal (the Executor) with a meaningful read/write
  mask is accepted, while a DENY for a service/trusted/unknown principal, an
  over-broad allow principal, an unexpected DENY mask, or unparseable ACE types
  all remain fail-closed.

The pure decision logic (``dacl_problems``) is platform-independent and unit
tested with injected ACL views; the raw Win32 reads are exercised by the
env-gated real-Windows test.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any, Mapping

_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)

SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 0x04
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
ACL_REVISION = 2
SECURITY_DESCRIPTOR_REVISION = 1

ACCESS_ALLOWED_ACE_TYPE = 0
ACCESS_DENIED_ACE_TYPE = 1

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL = 0x10000000
DELETE = 0x00010000
FILE_GENERIC_READ = 0x00120089
FILE_GENERIC_WRITE = 0x00120116
FILE_GENERIC_EXECUTE = 0x001200A0
FILE_READ_DATA = 0x00000001
FILE_WRITE_DATA = 0x00000002
# For forbidding ALLOW access, any generic or file-generic read/write bit counts.
_READ_BITS = GENERIC_READ | GENERIC_ALL | FILE_GENERIC_READ
_WRITE_BITS = GENERIC_WRITE | GENERIC_ALL | FILE_GENERIC_WRITE
# For validating a DENY mask, FILE_GENERIC_READ/WRITE share high bits
# (SYNCHRONIZE, READ_CONTROL), so comparing them would let a READ-only DENY
# masquerade as covering WRITE.  Use disjoint, meaningful data bits + the
# generic bits instead: a DENY must really block reading AND writing.
_DENY_READ_BITS = GENERIC_READ | GENERIC_ALL | FILE_READ_DATA
_DENY_WRITE_BITS = GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA

# Well-known principals the ADMIN deploy script grants FullControl to.  They
# are part of the platform TCB (SYSTEM / Administrators) and are the ONLY
# non-service principals permitted to hold an allow ACE on a private file.
SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
WELL_KNOWN_ALLOW_SIDS = (SYSTEM_SID, ADMINISTRATORS_SID)
# Everyone / Authenticated Users / Users / Creator Owner -- explicitly listed
# so a test can prove they are NOT accepted even if an admin accidentally
# grants them access.
BROAD_PRINCIPAL_SIDS = (
    "S-1-1-0",        # Everyone
    "S-1-5-11",       # Authenticated Users
    "S-1-5-32-545",   # BUILTIN\Users
    "S-1-3-0",        # CREATOR OWNER
)


class _ACE_HEADER(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", wintypes.USHORT)]


class _ACCESS_ACE(ctypes.Structure):
    """Layout shared by ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE."""

    _fields_ = [("Header", _ACE_HEADER), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]


# Backwards-compatible alias used by earlier callers/tests.
_ACCESS_ALLOWED_ACE = _ACCESS_ACE


class _ACL(ctypes.Structure):
    _fields_ = [
        ("AclRevision", ctypes.c_ubyte),
        ("Sbz1", ctypes.c_ubyte),
        ("AclSize", wintypes.USHORT),
        ("AceCount", wintypes.USHORT),
        ("Sbz2", wintypes.USHORT),
    ]


class _ACL_SIZE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    ]


class _SECURITY_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("Revision", ctypes.c_ubyte),
        ("Sbz1", ctypes.c_ubyte),
        ("Control", wintypes.USHORT),
        ("Owner", wintypes.LPVOID),
        ("Group", wintypes.LPVOID),
        ("Sacl", wintypes.LPVOID),
        ("Dacl", wintypes.LPVOID),
    ]


class FileACLError(PermissionError):
    """A private file's ACL does not satisfy the frozen B2 boundary."""


@dataclass(frozen=True)
class DaclView:
    """Parsed DACL: allow and deny masks keyed by SID, plus unparseable ACEs.

    ``allow``/``deny`` map a SID string to the OR of all matching ACE masks.
    ``unparsed`` holds markers for ACE types this module cannot interpret;
    their presence is always a policy failure (fail closed).
    """

    allow: Mapping[str, int]
    deny: Mapping[str, int]
    unparsed: tuple[str, ...] = ()


def _sid_to_string(sid_ptr: wintypes.LPVOID) -> str:
    _ADVAPI32.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    _ADVAPI32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _KERNEL32.LocalFree.argtypes = [wintypes.HLOCAL]
    _KERNEL32.LocalFree.restype = wintypes.HLOCAL
    out = wintypes.LPWSTR()
    if not _ADVAPI32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(out)):
        raise FileACLError(f"ConvertSidToStringSidW failed: {ctypes.get_last_error()}")
    try:
        return ctypes.wstring_at(out)
    finally:
        _KERNEL32.LocalFree(out)


def _sid_from_string(sid: str) -> wintypes.LPVOID:
    _ADVAPI32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
    _ADVAPI32.ConvertStringSidToSidW.restype = wintypes.BOOL
    psid = wintypes.LPVOID()
    if not _ADVAPI32.ConvertStringSidToSidW(sid, ctypes.byref(psid)):
        raise FileACLError(f"ConvertStringSidToSidW failed for {sid!r}: {ctypes.get_last_error()}")
    return psid


def read_dacl(path: str | Any) -> DaclView:
    """Return a parsed :class:`DaclView` for the effective DACL on ``path``.

    Both ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE are decoded into their SID
    and access mask.  A NULL DACL means "allow everyone" and is represented
    explicitly so the policy check rejects it; an unreadable DACL raises
    ``FileACLError`` rather than surfacing as "empty".
    """
    p = str(path)
    _ADVAPI32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    _ADVAPI32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    psid_owner = wintypes.LPVOID()
    psid_group = wintypes.LPVOID()
    p_dacl = wintypes.LPVOID()
    p_sacl = wintypes.LPVOID()
    p_sd = wintypes.LPVOID()
    rc = _ADVAPI32.GetNamedSecurityInfoW(
        p, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        ctypes.byref(psid_owner), ctypes.byref(psid_group),
        ctypes.byref(p_dacl), ctypes.byref(p_sacl), ctypes.byref(p_sd),
    )
    if rc != 0:
        raise FileACLError(f"GetNamedSecurityInfoW failed for {p!r}: win32_error={rc}")
    try:
        if not p_dacl.value:
            # NULL DACL == allow everyone -> represent explicitly so the
            # principal allowlist check rejects it; never treat as empty/safe.
            return DaclView(allow={"S-1-1-0": GENERIC_ALL}, deny={})
        _ADVAPI32.GetAclInformation.argtypes = [
            wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.c_int
        ]
        _ADVAPI32.GetAclInformation.restype = wintypes.BOOL
        info = _ACL_SIZE_INFORMATION()
        if not _ADVAPI32.GetAclInformation(p_dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
            raise FileACLError(f"GetAclInformation failed for {p!r}: {ctypes.get_last_error()}")
        _ADVAPI32.GetAce.argtypes = [wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID)]
        _ADVAPI32.GetAce.restype = wintypes.BOOL
        allow: dict[str, int] = {}
        deny: dict[str, int] = {}
        unparsed: list[str] = []
        for i in range(info.AceCount):
            p_ace = wintypes.LPVOID()
            if not _ADVAPI32.GetAce(p_dacl, i, ctypes.byref(p_ace)):
                raise FileACLError(f"GetAce({i}) failed for {p!r}")
            header = ctypes.cast(p_ace, ctypes.POINTER(_ACE_HEADER)).contents
            if header.AceType not in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE):
                # Object ACEs, audit ACEs, unknown types: we cannot attribute a
                # SID/mask, so record a marker and fail closed in the policy.
                unparsed.append(f"<unparsed-ace-{header.AceType}>")
                continue
            ace = ctypes.cast(p_ace, ctypes.POINTER(_ACCESS_ACE)).contents
            sid_ptr = ctypes.cast(
                ctypes.addressof(ace) + _ACCESS_ACE.SidStart.offset, wintypes.LPVOID
            )
            sid = _sid_to_string(sid_ptr)
            if header.AceType == ACCESS_ALLOWED_ACE_TYPE:
                allow[sid] = allow.get(sid, 0) | ace.Mask
            else:
                deny[sid] = deny.get(sid, 0) | ace.Mask
        return DaclView(allow=allow, deny=deny, unparsed=tuple(unparsed))
    finally:
        _KERNEL32.LocalFree(p_sd)


def _coerce_view(observed: DaclView | Mapping[str, int]) -> DaclView:
    """Accept a :class:`DaclView` or the legacy ``{sid: mask}`` allow map.

    Legacy marker keys beginning with ``<`` are surfaced as unparsed ACEs so
    older injected test fixtures still fail closed.
    """
    if isinstance(observed, DaclView):
        return observed
    if isinstance(observed, Mapping):
        allow: dict[str, int] = {}
        unparsed: list[str] = []
        for sid, mask in observed.items():
            if sid.startswith("<"):
                unparsed.append(sid)
            else:
                allow[sid] = mask
        return DaclView(allow=allow, deny={}, unparsed=tuple(unparsed))
    raise TypeError("observed must be a DaclView or a {sid: mask} mapping")


def dacl_problems(
    observed: DaclView | Mapping[str, int],
    *,
    allowed_sids: tuple[str, ...],
    forbidden_read_sids: tuple[str, ...] = (),
    forbidden_write_sids: tuple[str, ...] = (),
    expected_deny_sids: tuple[str, ...] = (),
    principal_allowlist: tuple[str, ...] | None = None,
) -> list[str]:
    """Pure ACL policy decision (platform independent, unit-tested).

    ``observed`` is a :class:`DaclView` (or a legacy ``{sid: mask}`` allow map).
    Returns human-readable problems; an empty list means the ACL conforms.

    Rules (all fail closed):
      1. At least one service SID in ``allowed_sids`` has an allow ACE with a
         non-zero mask.
      2. Every allow-ACE principal must be in ``principal_allowlist``.  When
         ``None`` it defaults to ``allowed_sids + SYSTEM + Administrators``;
         thus Everyone/Authenticated Users/unknown SIDs are rejected even if
         they are not in the explicit forbidden lists.
      3. Forbidden read/write SIDs must not hold the corresponding allow bits.
      4. A DENY ACE is accepted ONLY when its SID is in ``expected_deny_sids``,
         is not a service/trusted principal, and its mask denies BOTH read and
         write (the deploy script's ``(RX,D,W)`` covers both).  Everything else
         -- denied service account, unknown deny principal, too-weak mask --
         is a problem.
      5. Unparsed ACE types are always a problem.
    """
    problems: list[str] = []
    view = _coerce_view(observed)
    allow = view.allow
    deny = view.deny

    allowlist = tuple(principal_allowlist) if principal_allowlist is not None else (
        tuple(allowed_sids) + WELL_KNOWN_ALLOW_SIDS
    )
    allowlist_set = set(allowlist)

    # (5) unparseable ACE types first -- cannot reason about safety.
    for marker in view.unparsed:
        problems.append(f"unexpected deny/unparsed ACE ({marker})")

    # (1) service SID must hold a usable allow ACE.
    if not any(allow.get(sid, 0) != 0 for sid in allowed_sids):
        problems.append(f"no allow ACE for any service SID {list(allowed_sids)}")

    # (2) explicit principal allowlist -- reject broad/unknown allow principals.
    for sid, mask in allow.items():
        if sid not in allowlist_set:
            problems.append(f"unexpected allow ACE for principal {sid} (not in allowlist)")

    # (3) forbidden read/write SIDs.
    for sid in forbidden_read_sids:
        mask = allow.get(sid, 0)
        if mask & _READ_BITS:
            problems.append(f"forbidden SID {sid} retains READ access (mask=0x{mask:08x})")
    for sid in forbidden_write_sids:
        mask = allow.get(sid, 0)
        if mask & _WRITE_BITS:
            problems.append(f"forbidden SID {sid} retains WRITE access (mask=0x{mask:08x})")

    # (4) DENY ACEs.  The deploy script's Executor DENY is expected; anything
    # else is a problem.  A deny on a service/trusted principal is always bad.
    expected_deny = set(expected_deny_sids)
    service_trusted = set(allowed_sids) | set(WELL_KNOWN_ALLOW_SIDS)
    for sid, mask in deny.items():
        if sid in service_trusted:
            problems.append(f"service/trusted SID {sid} is denied (mask=0x{mask:08x})")
            continue
        if sid not in expected_deny:
            problems.append(f"unexpected DENY ACE for SID {sid} (mask=0x{mask:08x})")
            continue
        # Strength check: the DENY must actually cover both directions.  The
        # deploy script uses FILE_GENERIC_READ|WRITE (plus execute/delete),
        # which intersects _READ_BITS and _WRITE_BITS via FILE_GENERIC_*.
        # Requiring a specific full mask (e.g. GENERIC_ALL) would wrongly
        # reject the project's own script -- the very bug this fix removes.
        if not (mask & _DENY_READ_BITS) or not (mask & _DENY_WRITE_BITS):
            problems.append(
                f"DENY ACE for expected SID {sid} has insufficient mask "
                f"(0x{mask:08x}; must deny both READ and WRITE)"
            )
    return problems


def verify_private_file(
    path: str | Any,
    *,
    allowed_sids: tuple[str, ...],
    forbidden_read_sids: tuple[str, ...] = (),
    forbidden_write_sids: tuple[str, ...] = (),
) -> None:
    """Fail closed if ``path``'s DACL violates the frozen B2 file boundary.

    The Executor SIDs in the forbidden lists are the expected DENY principals:
    a DENY ACE for them (as produced by ``setup_journal_service_acl.ps1``) is
    accepted; an ALLOW ACE granting them access is not.
    """
    observed = read_dacl(path)
    expected_deny = tuple(dict.fromkeys(forbidden_read_sids + forbidden_write_sids))
    problems = dacl_problems(
        observed,
        allowed_sids=allowed_sids,
        forbidden_read_sids=forbidden_read_sids,
        forbidden_write_sids=forbidden_write_sids,
        expected_deny_sids=expected_deny,
    )
    if problems:
        raise FileACLError(f"private file {str(path)!r} ACL unsafe: " + "; ".join(problems))


def restrict_to_sids(
    path: str | Any,
    sids: tuple[str, ...],
    *,
    deny_sids: tuple[str, ...] = (),
    deny_mask: int = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
) -> None:
    """Set a PROTECTED DACL on ``path``.

    Deploy-time ADMIN operation; removes inherited ACEs so a parent directory's
    broad grant cannot leak access to the private key / databases.  ``sids``
    receive GENERIC_ALL via allow ACEs.  ``deny_sids`` receive a DENY ACE with
    ``deny_mask`` (default mirrors ``icacls :(RX,D,W)`` in the PowerShell
    deploy script), so the Python and PowerShell paths produce the same shape.
    """
    if not sids:
        raise FileACLError("restrict_to_sids requires at least one SID")
    overlap = set(sids) & set(deny_sids)
    if overlap:
        raise FileACLError(f"restrict_to_sids: SID both allowed and denied: {sorted(overlap)}")
    _ADVAPI32.GetLengthSid.argtypes = [wintypes.LPVOID]
    _ADVAPI32.GetLengthSid.restype = wintypes.DWORD
    allow_ptrs = [_sid_from_string(s) for s in sids]
    deny_ptrs = [_sid_from_string(s) for s in deny_sids]
    try:
        sizes = [_ADVAPI32.GetLengthSid(p) for p in allow_ptrs + deny_ptrs]
        ace_sizes = [ctypes.sizeof(_ACCESS_ACE) - ctypes.sizeof(wintypes.DWORD) + s for s in sizes]
        acl_size = ctypes.sizeof(_ACL) + sum(ace_sizes)
        acl_buf = ctypes.create_string_buffer(acl_size)
        _ADVAPI32.InitializeAcl.argtypes = [wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD]
        _ADVAPI32.InitializeAcl.restype = wintypes.BOOL
        if not _ADVAPI32.InitializeAcl(acl_buf, acl_size, ACL_REVISION):
            raise FileACLError(f"InitializeAcl failed: {ctypes.get_last_error()}")
        # Canonical ACL order: explicit DENY ACEs precede explicit ALLOW ACEs.
        if deny_ptrs:
            _ADVAPI32.AddAccessDeniedAce.argtypes = [
                wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID
            ]
            _ADVAPI32.AddAccessDeniedAce.restype = wintypes.BOOL
            for ptr in deny_ptrs:
                if not _ADVAPI32.AddAccessDeniedAce(acl_buf, ACL_REVISION, deny_mask, ptr):
                    raise FileACLError(f"AddAccessDeniedAce failed: {ctypes.get_last_error()}")
        _ADVAPI32.AddAccessAllowedAce.argtypes = [
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID
        ]
        _ADVAPI32.AddAccessAllowedAce.restype = wintypes.BOOL
        for ptr in allow_ptrs:
            if not _ADVAPI32.AddAccessAllowedAce(acl_buf, ACL_REVISION, GENERIC_ALL, ptr):
                raise FileACLError(f"AddAccessAllowedAce failed: {ctypes.get_last_error()}")
        _ADVAPI32.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
            wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID,
        ]
        _ADVAPI32.SetNamedSecurityInfoW.restype = wintypes.DWORD
        flags = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        rc = _ADVAPI32.SetNamedSecurityInfoW(
            str(path), SE_FILE_OBJECT, flags, None, None, acl_buf, None
        )
        if rc != 0:
            raise FileACLError(f"SetNamedSecurityInfoW failed for {str(path)!r}: win32_error={rc}")
    finally:
        for p in allow_ptrs + deny_ptrs:
            _KERNEL32.LocalFree(p)


__all__ = [
    "FileACLError", "DaclView", "read_dacl", "dacl_problems", "verify_private_file", "restrict_to_sids",
    "SYSTEM_SID", "ADMINISTRATORS_SID", "WELL_KNOWN_ALLOW_SIDS", "BROAD_PRINCIPAL_SIDS",
    "ACCESS_ALLOWED_ACE_TYPE", "ACCESS_DENIED_ACE_TYPE",
    "GENERIC_ALL", "GENERIC_READ", "GENERIC_WRITE", "FILE_GENERIC_READ", "FILE_GENERIC_WRITE",
]
