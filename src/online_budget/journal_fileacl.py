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
    directory granting only the given SIDs; inherited ACEs are removed.
  * ``verify_private_files`` (service start, fail-closed): read each file's
    effective DACL and REFUSE to start if a forbidden SID retains read access
    to the key/config or write access to a database.  A missing/unreadable ACL
    is itself a failure (never treat "unknown" as "safe").

The pure decision logic (``dacl_problems``) is platform-independent and unit
tested with injected ACL maps; the raw Win32 reads are exercised by the
env-gated real-Windows test.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import Any, Mapping

_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)

SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 0x04
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
ACL_REVISION = 2
SECURITY_DESCRIPTOR_REVISION = 1

ACCESS_ALLOWED_ACE_TYPE = 0
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_ALL = 0x10000000
FILE_GENERIC_READ = 0x00120089
FILE_GENERIC_WRITE = 0x00120116
_READ_BITS = GENERIC_READ | GENERIC_ALL | FILE_GENERIC_READ
_WRITE_BITS = GENERIC_WRITE | GENERIC_ALL | FILE_GENERIC_WRITE


class _ACE_HEADER(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", wintypes.USHORT)]


class _ACCESS_ALLOWED_ACE(ctypes.Structure):
    _fields_ = [("Header", _ACE_HEADER), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]


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


def read_dacl(path: str | Any) -> dict[str, int]:
    """Return ``{sid_string: access_mask}`` for all allow-ACEs on ``path``.

    A deny-ACE or an unreadable DACL surfaces as an error, never as "empty".
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
            # A NULL DACL means "allow everyone" -> represent explicitly so the
            # policy check rejects it; never treat it as an empty safe ACL.
            return {"S-1-1-0": GENERIC_ALL}
        _ADVAPI32.GetAclInformation.argtypes = [
            wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.c_int
        ]
        _ADVAPI32.GetAclInformation.restype = wintypes.BOOL
        info = _ACL_SIZE_INFORMATION()
        if not _ADVAPI32.GetAclInformation(p_dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
            raise FileACLError(f"GetAclInformation failed for {p!r}: {ctypes.get_last_error()}")
        _ADVAPI32.GetAce.argtypes = [wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID)]
        _ADVAPI32.GetAce.restype = wintypes.BOOL
        result: dict[str, int] = {}
        for i in range(info.AceCount):
            p_ace = wintypes.LPVOID()
            if not _ADVAPI32.GetAce(p_dacl, i, ctypes.byref(p_ace)):
                raise FileACLError(f"GetAce({i}) failed for {p!r}")
            header = ctypes.cast(p_ace, ctypes.POINTER(_ACE_HEADER)).contents
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE:
                # Deny ACEs: record with mask 0 but a distinct marker so the
                # policy layer can treat the file as non-conforming.
                result[f"<deny-ace-{header.AceType}>"] = 0
                continue
            ace = ctypes.cast(p_ace, ctypes.POINTER(_ACCESS_ALLOWED_ACE)).contents
            sid_ptr = ctypes.cast(
                ctypes.addressof(ace) + _ACCESS_ALLOWED_ACE.SidStart.offset, wintypes.LPVOID
            )
            sid = _sid_to_string(sid_ptr)
            result[sid] = result.get(sid, 0) | ace.Mask
        return result
    finally:
        _KERNEL32.LocalFree(p_sd)


def dacl_problems(
    observed: Mapping[str, int],
    *,
    allowed_sids: tuple[str, ...],
    forbidden_read_sids: tuple[str, ...],
    forbidden_write_sids: tuple[str, ...],
) -> list[str]:
    """Pure ACL policy decision (platform independent, unit-tested).

    ``observed`` is ``{sid: access_mask}``.  Returns a list of human-readable
    problems; empty list means the ACL conforms.  Unknown/deny markers always
    produce a problem (fail closed).
    """
    problems: list[str] = []
    for sid, mask in observed.items():
        if sid.startswith("<deny-ace"):
            problems.append(f"unexpected deny ACE ({sid})")
    if not any(sid in observed for sid in allowed_sids):
        problems.append(f"no allow ACE for any service SID {list(allowed_sids)}")
    for sid in forbidden_read_sids:
        mask = observed.get(sid, 0)
        if mask & _READ_BITS:
            problems.append(f"forbidden SID {sid} retains READ access (mask=0x{mask:08x})")
    for sid in forbidden_write_sids:
        mask = observed.get(sid, 0)
        if mask & _WRITE_BITS:
            problems.append(f"forbidden SID {sid} retains WRITE access (mask=0x{mask:08x})")
    return problems


def verify_private_file(
    path: str | Any,
    *,
    allowed_sids: tuple[str, ...],
    forbidden_read_sids: tuple[str, ...] = (),
    forbidden_write_sids: tuple[str, ...] = (),
) -> None:
    """Fail closed if ``path``'s DACL violates the frozen B2 file boundary."""
    observed = read_dacl(path)
    problems = dacl_problems(
        observed,
        allowed_sids=allowed_sids,
        forbidden_read_sids=forbidden_read_sids,
        forbidden_write_sids=forbidden_write_sids,
    )
    if problems:
        raise FileACLError(f"private file {str(path)!r} ACL unsafe: " + "; ".join(problems))


def restrict_to_sids(path: str | Any, sids: tuple[str, ...]) -> None:
    """Set a PROTECTED DACL on ``path`` granting GENERIC_ALL only to ``sids``.

    Deploy-time ADMIN operation; removes inherited ACEs so a parent directory's
    broad grant cannot leak access to the private key / databases.
    """
    if not sids:
        raise FileACLError("restrict_to_sids requires at least one SID")
    _ADVAPI32.GetLengthSid.argtypes = [wintypes.LPVOID]
    _ADVAPI32.GetLengthSid.restype = wintypes.DWORD
    sid_ptrs = [_sid_from_string(s) for s in sids]
    try:
        sizes = [_ADVAPI32.GetLengthSid(p) for p in sid_ptrs]
        ace_sizes = [ctypes.sizeof(_ACCESS_ALLOWED_ACE) - ctypes.sizeof(wintypes.DWORD) + s for s in sizes]
        acl_size = ctypes.sizeof(_ACL) + sum(ace_sizes)
        acl_buf = ctypes.create_string_buffer(acl_size)
        _ADVAPI32.InitializeAcl.argtypes = [wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD]
        _ADVAPI32.InitializeAcl.restype = wintypes.BOOL
        if not _ADVAPI32.InitializeAcl(acl_buf, acl_size, ACL_REVISION):
            raise FileACLError(f"InitializeAcl failed: {ctypes.get_last_error()}")
        _ADVAPI32.AddAccessAllowedAce.argtypes = [
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID
        ]
        _ADVAPI32.AddAccessAllowedAce.restype = wintypes.BOOL
        for ptr in sid_ptrs:
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
        for p in sid_ptrs:
            _KERNEL32.LocalFree(p)


__all__ = [
    "FileACLError", "read_dacl", "dacl_problems", "verify_private_file", "restrict_to_sids",
    "GENERIC_ALL", "GENERIC_READ", "GENERIC_WRITE",
]
