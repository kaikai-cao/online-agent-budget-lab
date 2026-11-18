"""E1.9-B -- OS caller identity and executor_id authorisation (B.3).

Security model (E1.9-B2 §5.3 / B2.2):
  * the caller identity is obtained by the OPERATING SYSTEM from the Named Pipe
    client token (ImpersonateNamedPipeClient + GetTokenInformation(TokenUser)),
    NEVER from a request field.  A request-supplied ``executor_id`` is only a
    *claim* and is checked against the fixed OS-identity mapping below.
  * ``IdentityAuthorizer.authorize()`` is the single choke point: an OS identity
    with no mapping, or a claimed executor_id outside that identity's allowed
    set, or an executor_id with no fixed public key -> fail closed.
  * ``StaticIdentityProvider`` exists ONLY for unit tests.  It is explicitly
    tagged ``is_os_backed = False`` so a production server can refuse to run on
    it (``require_os_backed=True``).  A simulated identity test can never be
    presented as a real Windows ACL acceptance test.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .journal_service_config import ServiceConfig, ServiceConfigError


# Use use_last_error=True so ctypes.get_last_error() reflects Win32 GetLastError.
# (ctypes.windll.* does NOT capture GetLastError reliably.)
_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)

_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_TOKEN_QUERY = 0x0008


class CallerIdentityError(PermissionError):
    """Reject a call because its authenticated identity is absent/invalid."""


@dataclass(frozen=True)
class CallerIdentity:
    """An identity asserted by the transport (not by the request body)."""

    sid: str
    account: str
    via: str
    is_os_backed: bool

    def describe(self) -> str:
        return f"{self.account}[{self.sid}] via {self.via}"


# ---------------------------------------------------------------------------
# Win32 token helpers (ctypes, stdlib only -- no pywin32 dependency)
# ---------------------------------------------------------------------------
class _SID_IDENTIFIER_AUTHORITY(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_ubyte * 6)]


class _SID(ctypes.Structure):
    _fields_ = [
        ("Revision", ctypes.c_ubyte),
        ("SubAuthorityCount", ctypes.c_ubyte),
        ("IdentifierAuthority", _SID_IDENTIFIER_AUTHORITY),
        ("SubAuthority", wintypes.DWORD * 1),
    ]


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.POINTER(_SID)), ("Attributes", wintypes.DWORD)]


class _TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", _SID_AND_ATTRIBUTES)]


_TOKEN_USER_CLASS = 1
_ERROR_INSUFFICIENT_BUFFER = 122


def _last_error() -> int:
    return ctypes.get_last_error()


def _sid_to_string(sid_ptr: ctypes.POINTER(_SID)) -> str:
    advapi32 = _ADVAPI32
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.POINTER(_SID), ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32 = _KERNEL32
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    out = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(out)):
        raise CallerIdentityError(f"ConvertSidToStringSidW failed: {_last_error()}")
    try:
        return ctypes.wstring_at(out)
    finally:
        kernel32.LocalFree(out)


def _sid_to_account(sid_ptr: ctypes.POINTER(_SID)) -> str:
    advapi32 = _ADVAPI32
    advapi32.LookupAccountSidW.argtypes = [
        wintypes.LPCWSTR, ctypes.POINTER(_SID),
        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.LookupAccountSidW.restype = wintypes.BOOL
    name_size = wintypes.DWORD(0)
    domain_size = wintypes.DWORD(0)
    use = wintypes.DWORD(0)
    ok = advapi32.LookupAccountSidW(
        None, sid_ptr, None, ctypes.byref(name_size),
        None, ctypes.byref(domain_size), ctypes.byref(use),
    )
    if ok or _last_error() != _ERROR_INSUFFICIENT_BUFFER:
        # Some SIDs have no account name (e.g. service SIDs); fall back to SID.
        return _sid_to_string(sid_ptr)
    name_buf = ctypes.create_unicode_buffer(name_size.value)
    domain_buf = ctypes.create_unicode_buffer(domain_size.value)
    if not advapi32.LookupAccountSidW(
        None, sid_ptr, name_buf, ctypes.byref(name_size),
        domain_buf, ctypes.byref(domain_size), ctypes.byref(use),
    ):
        return _sid_to_string(sid_ptr)
    if domain_buf.value:
        return f"{domain_buf.value}\\{name_buf.value}"
    return name_buf.value


def current_process_identity() -> CallerIdentity:
    """Return the SID/account of the CURRENT process (used for ACL config/test)."""
    kernel32 = _KERNEL32
    advapi32 = _ADVAPI32
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    htok = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(htok)):
        raise CallerIdentityError(f"OpenProcessToken failed: {_last_error()}")
    try:
        return _identity_from_token(htok, via="WIN32_PROCESS_TOKEN")
    finally:
        kernel32.CloseHandle(htok)


def _identity_from_token(htok: wintypes.HANDLE, *, via: str) -> CallerIdentity:
    advapi32 = ctypes.windll.advapi32
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    needed = wintypes.DWORD(0)
    advapi32.GetTokenInformation(htok, _TOKEN_USER_CLASS, None, 0, ctypes.byref(needed))
    buf = ctypes.create_string_buffer(needed.value)
    if not advapi32.GetTokenInformation(htok, _TOKEN_USER_CLASS, buf, needed.value, ctypes.byref(needed)):
        raise CallerIdentityError(f"GetTokenInformation(TokenUser) failed: {_last_error()}")
    token_user = ctypes.cast(buf, ctypes.POINTER(_TOKEN_USER)).contents
    sid_ptr = token_user.User.Sid
    return CallerIdentity(
        sid=_sid_to_string(sid_ptr),
        account=_sid_to_account(sid_ptr),
        via=via,
        is_os_backed=True,
    )


def identity_from_pipe_client_pid(pipe_handle: wintypes.HANDLE) -> CallerIdentity:
    """Resolve the Connected pipe client's OS identity via its process token.

    The server asks the OS for the connected client's PROCESS ID
    (GetNamedPipeClientProcessId), opens that process and reads its token user
    SID.  This is an OS-supplied identity (never from the request body) and,
    unlike impersonation, also works when client and server share a process
    (our in-process acceptance test).  In production the client is a separate
    Executor process and this yields that process's account SID.
    """
    kernel32 = _KERNEL32
    advapi32 = _ADVAPI32
    kernel32.GetNamedPipeClientProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetNamedPipeClientProcessId.restype = wintypes.BOOL
    pid = wintypes.DWORD(0)
    ctypes.set_last_error(0)
    if not kernel32.GetNamedPipeClientProcessId(pipe_handle, ctypes.byref(pid)):
        raise CallerIdentityError(f"GetNamedPipeClientProcessId failed: last_error={ctypes.get_last_error()}")
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    ctypes.set_last_error(0)
    hproc = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
    if not hproc:
        raise CallerIdentityError(f"OpenProcess({pid.value}) failed: last_error={ctypes.get_last_error()}")
    try:
        advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        htok = wintypes.HANDLE()
        ctypes.set_last_error(0)
        if not advapi32.OpenProcessToken(hproc, _TOKEN_QUERY, ctypes.byref(htok)):
            raise CallerIdentityError(f"OpenProcessToken failed: last_error={ctypes.get_last_error()}")
        try:
            ident = _identity_from_token(htok, via="WIN32_PIPE_CLIENT_PID")
            return CallerIdentity(sid=ident.sid, account=ident.account, via=ident.via, is_os_backed=True)
        finally:
            kernel32.CloseHandle(htok)
    finally:
        kernel32.CloseHandle(hproc)


def identity_from_impersonated_pipe(pipe_handle: wintypes.HANDLE) -> CallerIdentity:
    """Impersonate a connected Named Pipe client and read its token identity.

    Called by the server immediately after ``ConnectNamedPipe``.  Reverts the
    thread impersonation before returning.  This is the REAL OS identity path.
    """
    kernel32 = _KERNEL32
    advapi32 = _ADVAPI32
    advapi32.ImpersonateNamedPipeClient.argtypes = [wintypes.HANDLE]
    advapi32.ImpersonateNamedPipeClient.restype = wintypes.BOOL
    ctypes.set_last_error(0)
    impersonated = advapi32.ImpersonateNamedPipeClient(pipe_handle)
    impersonation_err = ctypes.get_last_error()
    if not impersonated:
        raise CallerIdentityError(f"ImpersonateNamedPipeClient failed: last_error={impersonation_err}")
    htok = wintypes.HANDLE()
    try:
        advapi32.OpenThreadToken.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, ctypes.POINTER(wintypes.HANDLE)
        ]
        advapi32.OpenThreadToken.restype = wintypes.BOOL
        if not advapi32.OpenThreadToken(
            kernel32.GetCurrentThread(), _TOKEN_QUERY, True, ctypes.byref(htok)
        ):
            raise CallerIdentityError(f"OpenThreadToken failed: {_last_error()}")
        return _identity_from_token(htok, via="WIN32_NAMED_PIPE_IMPERSONATION")
    finally:
        if htok:
            kernel32.CloseHandle(htok)
        advapi32.RevertToSelf.argtypes = []
        advapi32.RevertToSelf.restype = wintypes.BOOL
        if not advapi32.RevertToSelf():
            raise CallerIdentityError(f"RevertToSelf failed: {_last_error()}")


# ---------------------------------------------------------------------------
# Identity provider abstraction
# ---------------------------------------------------------------------------
@runtime_checkable
class IdentityProvider(Protocol):
    is_os_backed: bool
    def authenticate(self) -> CallerIdentity: ...


class StaticIdentityProvider:
    """TEST-ONLY provider; returns a fixed identity supplied by the test.

    ``is_os_backed`` is False.  A production server constructed with
    ``require_os_backed=True`` refuses this provider.
    """

    is_os_backed = False

    def __init__(self, identity: CallerIdentity) -> None:
        self._identity = identity

    def authenticate(self) -> CallerIdentity:
        return self._identity


class HandleIdentityProvider:
    """OS-backed provider that reads identity from an impersonated pipe handle."""

    is_os_backed = True

    def __init__(self, pipe_handle: wintypes.HANDLE) -> None:
        self._handle = pipe_handle

    def authenticate(self) -> CallerIdentity:
        return identity_from_impersonated_pipe(self._handle)


class PipeClientPidIdentityProvider:
    """OS-backed provider using the pipe client's process token (primary path)."""

    is_os_backed = True

    def __init__(self, pipe_handle: wintypes.HANDLE) -> None:
        self._handle = pipe_handle

    def authenticate(self) -> CallerIdentity:
        return identity_from_pipe_client_pid(self._handle)


class IdentityAuthorizer:
    """Fixed OS-identity -> executor_id -> public-key authorisation (B.3)."""

    def __init__(self, config: ServiceConfig, *, require_os_backed: bool = True) -> None:
        self._config = config
        self._require_os_backed = require_os_backed

    def authorize(self, caller: CallerIdentity, claimed_executor_id: str) -> str:
        """Return the authorised executor_id or fail closed."""
        if self._require_os_backed and not caller.is_os_backed:
            raise CallerIdentityError("caller identity is not OS-backed (simulated identities are not accepted by the production server)")
        if not isinstance(claimed_executor_id, str) or not claimed_executor_id:
            raise CallerIdentityError("claimed executor_id must be a non-empty string")

        allowed = self._config.os_identity_to_executor_ids.get(caller.account)
        if allowed is None:
            allowed = self._config.os_identity_to_executor_ids.get(caller.sid)
        if allowed is None:
            raise CallerIdentityError(f"no executor_id mapping for OS identity {caller.describe()}")
        if claimed_executor_id not in allowed:
            raise CallerIdentityError(
                f"executor_id={claimed_executor_id!r} not authorised for OS identity {caller.describe()}"
            )
        # Force the fixed key lookup; absence fails closed (B.3 rule 6).
        try:
            self._config.public_key_for(claimed_executor_id)
        except ServiceConfigError as exc:
            raise CallerIdentityError(str(exc)) from exc
        return claimed_executor_id

    def authorize_read(self, caller: CallerIdentity) -> None:
        """Read calls need a known OS identity but no executor_id claim."""
        if self._require_os_backed and not caller.is_os_backed:
            raise CallerIdentityError("caller identity is not OS-backed")
        if (
            caller.account not in self._config.os_identity_to_executor_ids
            and caller.sid not in self._config.os_identity_to_executor_ids
        ):
            raise CallerIdentityError(f"no identity mapping for {caller.describe()}")


__all__ = [
    "CallerIdentity",
    "CallerIdentityError",
    "IdentityProvider",
    "StaticIdentityProvider",
    "HandleIdentityProvider",
    "PipeClientPidIdentityProvider",
    "IdentityAuthorizer",
    "current_process_identity",
    "identity_from_pipe_client_pid",
    "identity_from_impersonated_pipe",
]
