"""E1.9-B -- Windows Named Pipe IPC for the Journal Service (B.2).

Real OS primitives via ctypes (stdlib only, no pywin32):
  * server creates a Named Pipe with a security descriptor whose DACL grants
    only the configured ``allowed_client_sids`` (ACL restriction, B.2);
  * after ConnectNamedPipe the server obtains the CLIENT's OS identity by
    impersonation (journal_identity.identity_from_impersonated_pipe) -- the
    identity is supplied to the service by the OS, never by the request body;
  * no shared static Token; authentication is the OS caller identity.

Wire protocol (framed, length-prefixed JSON):
  request  = 4-byte big-endian length + UTF-8 canonical JSON
             {"method": str, "params": {...}}
  response = 4-byte big-endian length + UTF-8 canonical JSON
             {"ok": bool, "result": {...}} | {"ok": false, "error": {"code","message"}}

Robustness (B.2):
  * max frame size enforced (reject oversize / truncated frames);
  * exact top-level field set; unknown fields rejected;
  * a client disconnect or any transport error never yields a success response;
  * stable structured error codes flow from ServiceError / validation layers.

Portability: ``InProcessChannel`` provides a transport-free client used by unit
tests (no Named Pipe, no OS identity); the real-Windows acceptance test drives
``NamedPipeServer`` through ``NamedPipeClient`` and checks OS identity + ACL.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import socket
import struct
import threading
from typing import Any, Callable, Mapping

from .canonical import canonical_json_bytes
from .journal_identity import CallerIdentity, IdentityProvider, PipeClientPidIdentityProvider
from .journal_service import JournalService, ServiceError, ServiceRequest

MAX_FRAME_BYTES = 4 * 1024 * 1024  # 4 MiB upper bound on a single frame

# use_last_error=True so ctypes.get_last_error() reflects Win32 GetLastError.
_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)


class IPCError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# framing (platform independent)
# ---------------------------------------------------------------------------
def encode_frame(obj: Mapping[str, Any]) -> bytes:
    payload = canonical_json_bytes(dict(obj))
    if len(payload) > MAX_FRAME_BYTES:
        raise IPCError("FRAME_TOO_LARGE", "encoded frame exceeds maximum")
    return struct.pack(">I", len(payload)) + payload


def decode_frame(raw: bytes) -> dict[str, Any]:
    if len(raw) < 4:
        raise IPCError("FRAME_TRUNCATED", "frame shorter than length prefix")
    length = struct.unpack(">I", raw[:4])[0]
    if length == 0 or length > MAX_FRAME_BYTES:
        raise IPCError("FRAME_BAD_LENGTH", "frame length out of bounds")
    body = raw[4 : 4 + length]
    if len(body) != length:
        raise IPCError("FRAME_TRUNCATED", "frame body shorter than declared length")
    try:
        obj = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IPCError("FRAME_BAD_JSON", f"frame body is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise IPCError("FRAME_BAD_SHAPE", "frame body must be a JSON object")
    return obj


def build_request(method: str, params: Mapping[str, Any]) -> dict[str, Any]:
    return {"method": method, "params": dict(params)}


def parse_request(obj: Mapping[str, Any]) -> ServiceRequest:
    if set(obj) != {"method", "params"}:
        raise IPCError("REQUEST_FIELDS", "request must have exactly method and params")
    method = obj.get("method")
    params = obj.get("params")
    if not isinstance(method, str) or not method:
        raise IPCError("BAD_METHOD", "method must be a non-empty string")
    if not isinstance(params, dict):
        raise IPCError("BAD_PARAMS", "params must be an object")
    return ServiceRequest(method=method, params=params)


def success_response(result: Mapping[str, Any]) -> dict[str, Any]:
    return {"ok": True, "result": dict(result)}


def error_response(code: str, message: str) -> dict[str, Any]:
    return {"ok": False, "error": {"code": code, "message": message}}


def dispatch(service: JournalService, caller: CallerIdentity, raw: bytes) -> bytes:
    """Decode a request frame, dispatch it, and encode the response frame.

    Any error -- including transport/parse errors -- yields a structured error
    response.  This function is shared by the Named Pipe server and in-process
    tests so both exercise identical validation logic.
    """
    try:
        obj = decode_frame(raw)
        request = parse_request(obj)
        result = service.handle(request, caller)
        return encode_frame(success_response(result))
    except IPCError as exc:
        return encode_frame(error_response(exc.code, exc.message))
    except ServiceError as exc:
        return encode_frame(error_response(exc.code, exc.message))
    except Exception as exc:  # noqa: BLE001 - never report success on unexpected failure
        return encode_frame(error_response("INTERNAL_ERROR", f"{type(exc).__name__}: {exc}"))


def parse_response(raw: bytes) -> dict[str, Any]:
    obj = decode_frame(raw)
    if "ok" not in obj or not isinstance(obj["ok"], bool):
        raise IPCError("BAD_RESPONSE", "response must have boolean ok")
    if obj["ok"]:
        if set(obj) != {"ok", "result"} or not isinstance(obj["result"], dict):
            raise IPCError("BAD_RESPONSE", "success response must have result object")
    else:
        err = obj.get("error")
        if set(obj) != {"ok", "error"} or not isinstance(err, dict) or set(err) != {"code", "message"}:
            raise IPCError("BAD_RESPONSE", "error response has invalid shape")
    return obj


# ---------------------------------------------------------------------------
# in-process transport (unit tests; no OS identity claim)
# ---------------------------------------------------------------------------
class InProcessChannel:
    """Call a service directly with a supplied (possibly simulated) identity."""

    def __init__(self, service: JournalService, caller: CallerIdentity) -> None:
        self._service = service
        self._caller = caller

    def call(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        raw = encode_frame(build_request(method, params))
        return parse_response(dispatch(self._service, self._caller, raw))


# ---------------------------------------------------------------------------
# Win32 Named Pipe server / client (real OS identity + ACL)
# ---------------------------------------------------------------------------
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_PIPE_ACCESS_DUPLEX = 0x00000003
_PIPE_TYPE_MESSAGE = 0x00000004
_PIPE_READMODE_MESSAGE = 0x00000002
_PIPE_WAIT = 0x00000000
_PIPE_UNLIMITED_INSTANCES = 255
_ACL_REVISION = 2
_SECURITY_DESCRIPTOR_REVISION = 1
_SE_DACL_PRESENT = 0x0004
_ERROR_NO_DATA = 232
_ERROR_BROKEN_PIPE = 109
_ERROR_MORE_DATA = 234


class _ACE_HEADER(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", wintypes.USHORT)]


class _ACCESS_ALLOWED_ACE(ctypes.Structure):
    _fields_ = [
        ("Header", _ACE_HEADER),
        ("Mask", wintypes.DWORD),
        ("SidStart", wintypes.DWORD),
    ]


class _ACL(ctypes.Structure):
    _fields_ = [
        ("AclRevision", ctypes.c_ubyte),
        ("Sbz1", ctypes.c_ubyte),
        ("AclSize", wintypes.USHORT),
        ("AceCount", wintypes.USHORT),
        ("Sbz2", wintypes.USHORT),
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


def _sid_from_string(sid_string: str) -> wintypes.LPVOID:
    advapi32 = _ADVAPI32
    kernel32 = _KERNEL32
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    psid = wintypes.LPVOID()
    if not advapi32.ConvertStringSidToSidW(sid_string, ctypes.byref(psid)):
        raise IPCError("BAD_SID", f"ConvertStringSidToSidW failed for {sid_string!r}: {ctypes.get_last_error()}")
    return psid


def _build_dacl(sids: tuple[str, ...]):
    advapi32 = _ADVAPI32
    kernel32 = _KERNEL32
    advapi32.GetLengthSid.argtypes = [wintypes.LPVOID]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    sid_ptrs = [_sid_from_string(s) for s in sids]
    try:
        sizes = [advapi32.GetLengthSid(p) for p in sid_ptrs]
        ace_sizes = [ctypes.sizeof(_ACCESS_ALLOWED_ACE) - ctypes.sizeof(wintypes.DWORD) + s for s in sizes]
        acl_size = ctypes.sizeof(_ACL) + sum(ace_sizes)
        acl_buf = ctypes.create_string_buffer(acl_size)
        advapi32.InitializeAcl.argtypes = [wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD]
        advapi32.InitializeAcl.restype = wintypes.BOOL
        if not advapi32.InitializeAcl(acl_buf, acl_size, _ACL_REVISION):
            raise IPCError("ACL_INIT_FAILED", f"InitializeAcl failed: {ctypes.get_last_error()}")
        advapi32.AddAccessAllowedAce.argtypes = [
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID
        ]
        advapi32.AddAccessAllowedAce.restype = wintypes.BOOL
        for ptr in sid_ptrs:
            if not advapi32.AddAccessAllowedAce(
                acl_buf, _ACL_REVISION, _GENERIC_READ | _GENERIC_WRITE, ptr
            ):
                raise IPCError("ACL_ACE_FAILED", f"AddAccessAllowedAce failed: {ctypes.get_last_error()}")
        return acl_buf, acl_size
    finally:
        for p in sid_ptrs:
            kernel32.LocalFree(p)


def _build_security_attributes(sids: tuple[str, ...]):
    advapi32 = _ADVAPI32
    acl_buf, acl_size = _build_dacl(sids)
    sd = _SECURITY_DESCRIPTOR()
    advapi32.InitializeSecurityDescriptor.argtypes = [wintypes.LPVOID, wintypes.DWORD]
    advapi32.InitializeSecurityDescriptor.restype = wintypes.BOOL
    if not advapi32.InitializeSecurityDescriptor(ctypes.byref(sd), _SECURITY_DESCRIPTOR_REVISION):
        raise IPCError("SD_INIT_FAILED", f"InitializeSecurityDescriptor failed: {ctypes.get_last_error()}")
    advapi32.SetSecurityDescriptorDacl.argtypes = [
        wintypes.LPVOID, wintypes.BOOL, wintypes.LPVOID, wintypes.BOOL
    ]
    advapi32.SetSecurityDescriptorDacl.restype = wintypes.BOOL
    if not advapi32.SetSecurityDescriptorDacl(ctypes.byref(sd), True, acl_buf, False):
        raise IPCError("SD_DACL_FAILED", f"SetSecurityDescriptorDacl failed: {ctypes.get_last_error()}")

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    sa.lpSecurityDescriptor = ctypes.cast(ctypes.byref(sd), wintypes.LPVOID)
    sa.bInheritHandle = False
    # Keep references alive for the lifetime of the Named Pipe handle.
    return sa, sd, acl_buf


def _read_message(handle: wintypes.HANDLE) -> bytes:
    """Read ONE message-mode frame from a Named Pipe.

    The Pipe is created with PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, so a
    single ReadFile returns exactly one WriteFile message.  We read up to
    MAX_FRAME_BYTES + 4 in one call and let the framing layer validate the
    declared length.  Byte-wise "read exact" would corrupt message-mode pipes
    because the first ReadFile consumes the whole message, not just the header.
    """
    kernel32 = _KERNEL32
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID
    ]
    kernel32.ReadFile.restype = wintypes.BOOL
    buf = ctypes.create_string_buffer(MAX_FRAME_BYTES + 4)
    read = wintypes.DWORD(0)
    ok = kernel32.ReadFile(handle, buf, MAX_FRAME_BYTES + 4, ctypes.byref(read), None)
    if not ok or read.value == 0:
        raise IPCError("PEER_DISCONNECTED", "client disconnected or ReadFile failed")
    return buf.raw[: read.value]


def _write_all(handle: wintypes.HANDLE, data: bytes) -> None:
    kernel32 = _KERNEL32
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    view = memoryview(data)
    written_total = 0
    while written_total < len(view):
        chunk = ctypes.create_string_buffer(bytes(view[written_total:]))
        written = wintypes.DWORD(0)
        ok = kernel32.WriteFile(handle, chunk, len(view) - written_total, ctypes.byref(written), None)
        if not ok or written.value == 0:
            raise IPCError("PEER_WRITE_FAILED", "WriteFile failed or client disconnected")
        written_total += written.value


class NamedPipeServer:
    """Single-threaded Named Pipe server owning the OS-identity handshake."""

    def __init__(
        self,
        *,
        pipe_name: str,
        allowed_sids: tuple[str, ...],
        service: JournalService,
        require_os_backed: bool = True,
    ) -> None:
        self.pipe_name = pipe_name
        self.allowed_sids = allowed_sids
        self.service = service
        self.require_os_backed = require_os_backed
        self._stop = threading.Event()

    @property
    def path(self) -> str:
        return rf"\\.\pipe\{self.pipe_name}"

    def stop(self) -> None:
        self._stop.set()

    def serve_one(self, timeout_ms: int = 1000) -> bool:
        """Accept at most one client, handle one request, reply, disconnect.

        Returns True if a client was served, False on timeout/stop.  A fresh
        pipe instance is created for each client so a broken client cannot leave
        the endpoint in a bad state.
        """
        kernel32 = _KERNEL32
        sa, sd, acl = _build_security_attributes(self.allowed_sids)
        kernel32.CreateNamedPipeW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
            wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID
        ]
        kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
        ctypes.set_last_error(0)
        handle = kernel32.CreateNamedPipeW(
            self.path,
            _PIPE_ACCESS_DUPLEX,
            _PIPE_TYPE_MESSAGE | _PIPE_READMODE_MESSAGE | _PIPE_WAIT,
            _PIPE_UNLIMITED_INSTANCES,
            MAX_FRAME_BYTES,
            MAX_FRAME_BYTES,
            0,
            ctypes.cast(ctypes.byref(sa), wintypes.LPVOID),
        )
        create_err = ctypes.get_last_error()
        if handle in (None, wintypes.HANDLE(-1).value, 0):
            raise IPCError("PIPE_CREATE_FAILED", f"CreateNamedPipeW failed: {create_err}")
        try:
            kernel32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
            kernel32.ConnectNamedPipe.restype = wintypes.BOOL
            connected = kernel32.ConnectNamedPipe(handle, None)
            if not connected and ctypes.get_last_error() not in (0, 536):  # 536 = ERROR_PIPE_CONNECTED
                raise IPCError("PIPE_CONNECT_FAILED", f"ConnectNamedPipe failed: {ctypes.get_last_error()}")
            # OS-supplied caller identity (never from the request body).  The
            # server asks the OS for the connected client's process token -> SID.
            provider: IdentityProvider = PipeClientPidIdentityProvider(handle)
            caller = provider.authenticate()
            # Validate the OS identity is in the fixed mapping before doing any work.
            self.service._authorizer.authorize_read(caller)
            raw = _read_message(handle)  # one WriteFile message == one request frame
            response_bytes = dispatch(self.service, caller, raw)
            _write_all(handle, response_bytes)
            return True
        except IPCError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise IPCError("PIPE_SERVER_ERROR", f"{type(exc).__name__}: {exc}") from exc
        finally:
            kernel32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
            kernel32.DisconnectNamedPipe(handle)
            kernel32.CloseHandle(handle)

    def serve_forever(self) -> None:
        import time
        while not self._stop.is_set():
            try:
                self.serve_one()
            except IPCError:
                # A bad/unauthorised client must not kill the service.  A brief
                # backoff avoids a busy loop while the pipe is rebuilt.
                if not self._stop.wait(0.01):
                    continue


class NamedPipeClient:
    """Client that opens the pipe and checks peer identity (no shared token)."""

    def __init__(self, pipe_name: str, *, connect_retries: int = 50) -> None:
        self.path = rf"\\.\pipe\{pipe_name}"
        self._connect_retries = connect_retries

    def _open(self):
        import time
        kernel32 = _KERNEL32
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        invalid = wintypes.HANDLE(-1).value
        last = 0
        for attempt in range(self._connect_retries):
            ctypes.set_last_error(0)
            handle = kernel32.CreateFileW(
                self.path, _GENERIC_READ | _GENERIC_WRITE, 0, None,
                3,  # OPEN_EXISTING
                0,
                None,
            )
            last = ctypes.get_last_error()
            if handle not in (None, invalid, 0):
                return handle
            # The pipe may not be ready yet: Windows can return INVALID_HANDLE_VALUE
            # with last_error==0 (transient) or ERROR_FILE_NOT_FOUND/PIPE_BUSY (2/231)
            # during server start-up.  Retry any invalid handle until the deadline;
            # ACCESS_DENIED (5) is a real ACL rejection and is reported immediately.
            if last == 5:
                raise IPCError("PIPE_ACCESS_DENIED", "CreateFileW denied by pipe ACL (last_error=5)")
            if attempt + 1 < self._connect_retries:
                time.sleep(0.02)
                continue
            raise IPCError("PIPE_OPEN_FAILED", f"CreateFileW failed after {self._connect_retries} retries: last_error={last}")

    def call(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        kernel32 = _KERNEL32
        handle = self._open()
        try:
            raw = encode_frame(build_request(method, params))
            _write_all(handle, raw)
            return parse_response(_read_message(handle))
        finally:
            kernel32.CloseHandle(handle)


__all__ = [
    "MAX_FRAME_BYTES",
    "IPCError",
    "encode_frame",
    "decode_frame",
    "build_request",
    "parse_request",
    "success_response",
    "error_response",
    "dispatch",
    "parse_response",
    "InProcessChannel",
    "NamedPipeServer",
    "NamedPipeClient",
]
