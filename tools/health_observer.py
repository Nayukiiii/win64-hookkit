"""Out-of-process read-only Seqlock health observer for ``hookkit::SeqlockHealthBlock``.

Opens target processes strictly with ``PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ``
(0x1010) and never suspends, resumes, terminates, or writes to target memory.

Capabilities:
- `decode_health_block` / `read_seqlock_consistent`: Torn-read-safe decoder
  matching ``hookkit::SeqlockHealthBlock`` (``HKIT_H01``, 64-byte layout).
- `resolve_pe_export_rva`: PE32+ export table RVA resolver with forwarder guard.
- `inspect_process_health`: Verifies target EXE SHA-256 and loaded module
  SHA-256, locates the loaded module base via Toolhelp32, and reads the exported
  seqlock health block out-of-process.
- `find_processes_born_after`: ``FILETIME`` process-birth-gated candidate
  discovery preventing PID reuse races.
- `get_process_thread_count`: Live thread-count polling.
- `observe_health`: State-change telemetry logger and stale-heartbeat watchdog.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import struct
import time
from ctypes import wintypes as wt
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
PROCESS_ACCESS_MASK = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPMODULE_ALL = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32

HEALTH_MAGIC = 0x3130485F54494B48  # "HKIT_H01" little-endian u64
HEALTH_BLOCK_STRUCT = struct.Struct("<QQQIIQQQQ")
HEALTH_BLOCK_SIZE = HEALTH_BLOCK_STRUCT.size  # 64 bytes

FAILURE_REASONS: Tuple[str, ...] = (
    "None",
    "InvalidState",
    "PlanPreparationFailed",
    "ThreadCensusFailed",
    "ThreadSuspendFailed",
    "ThreadContextFailed",
    "RipInsideHazardWindow",
    "CallbackNotQuiescent",
    "MemoryProtectFailed",
    "BeforeBytesMismatch",
    "AfterBytesMismatch",
    "ProtectRestoreFailed",
    "InstructionCacheFlushFailed",
    "ContextDriftedWhileStopped",
    "ThreadResumeFailed",
)


def sha256_file(path: Path) -> str:
    """Compute uppercase hexadecimal SHA-256 digest of a file."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().upper()


def decode_health_block(raw: bytes) -> Dict[str, Any]:
    """Decode and validate a 64-byte ``hookkit::SeqlockHealthBlock`` snapshot."""
    if len(raw) != HEALTH_BLOCK_SIZE:
        raise ValueError(f"Expected {HEALTH_BLOCK_SIZE} bytes for SeqlockHealthBlock, got {len(raw)}")
    outer_seq, magic, inner_seq, state, reason, attach_qpc, detach_qpc, cb_enter, cb_exit = (
        HEALTH_BLOCK_STRUCT.unpack(raw)
    )
    if outer_seq & 1:
        raise ValueError("Health block write in progress (odd seqlock sequence)")
    if magic != HEALTH_MAGIC:
        raise ValueError(f"Invalid health block magic 0x{magic:016X} (expected 0x{HEALTH_MAGIC:016X})")
    if inner_seq != outer_seq:
        raise ValueError(f"Torn health snapshot: outer_seq={outer_seq}, inner_seq={inner_seq}")

    reason_name = FAILURE_REASONS[reason] if 0 <= reason < len(FAILURE_REASONS) else f"Unknown({reason})"
    return {
        "seq": outer_seq,
        "magic": f"0x{magic:016X}",
        "state": state,
        "last_failure_reason": reason,
        "last_failure_name": reason_name,
        "attach_qpc": attach_qpc,
        "detach_qpc": detach_qpc,
        "callback_enter_count": cb_enter,
        "callback_exit_count": cb_exit,
    }


def read_seqlock_consistent(
    read_fn: Callable[[int, int], bytes],
    base_addr: int,
    max_attempts: int = 64,
) -> Dict[str, Any]:
    """Perform a torn-read-safe seqlock read loop using ``read_fn(addr, size)``."""
    last_err: Optional[Exception] = None
    for _ in range(max_attempts):
        raw = read_fn(base_addr, HEALTH_BLOCK_SIZE)
        if len(raw) != HEALTH_BLOCK_SIZE:
            raise ValueError(f"Short read from health block: {len(raw)} bytes")
        s1 = struct.unpack_from("<Q", raw, 0)[0]
        if s1 & 1:
            continue
        tail_seq_bytes = read_fn(base_addr, 8)
        if len(tail_seq_bytes) != 8:
            raise ValueError("Short read verifying trailing seqlock sequence")
        s2 = struct.unpack("<Q", tail_seq_bytes)[0]
        if s1 != s2:
            continue
        try:
            return decode_health_block(raw)
        except ValueError as exc:
            last_err = exc
            continue
    if last_err is not None:
        raise ValueError(f"Concurrent/torn health snapshot after {max_attempts} attempts: {last_err}") from last_err
    raise ValueError(f"Concurrent/torn health snapshot after {max_attempts} attempts")


def _rva_to_offset(pe_bytes: bytes, rva: int) -> int:
    if len(pe_bytes) < 0x40 or pe_bytes[:2] != b"MZ":
        raise ValueError("Not a valid MZ PE image")
    e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    if pe_bytes[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("Missing PE signature")
    num_sections = struct.unpack_from("<H", pe_bytes, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", pe_bytes, e_lfanew + 20)[0]
    sec_off = e_lfanew + 24 + opt_size
    for i in range(num_sections):
        off = sec_off + i * 40
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", pe_bytes, off + 8)
        span = max(vsize, raw_size)
        if va <= rva < va + span:
            delta = rva - va
            if delta >= raw_size:
                raise ValueError(f"RVA 0x{rva:X} lies in uninitialized section bytes")
            return raw_ptr + delta
    raise ValueError(f"RVA 0x{rva:X} not mapped in PE sections")


def resolve_pe_export_rva(pe_bytes: bytes, export_name: str) -> int:
    """Resolve a non-forwarded export symbol RVA from a PE32+ image."""
    if len(pe_bytes) < 0x40 or pe_bytes[:2] != b"MZ":
        raise ValueError("Not a valid MZ PE image")
    e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", pe_bytes, opt)[0]
    if magic != 0x20B:
        raise ValueError(f"Expected PE32+ (0x20B), got 0x{magic:X}")
    exp_rva, exp_size = struct.unpack_from("<II", pe_bytes, opt + 112)
    if not exp_rva or not exp_size:
        raise ValueError("PE image has no export directory")

    exp_off = _rva_to_offset(pe_bytes, exp_rva)
    num_funcs, num_names, funcs_rva, names_rva, ords_rva = struct.unpack_from("<IIIII", pe_bytes, exp_off + 20)
    funcs_off = _rva_to_offset(pe_bytes, funcs_rva)
    names_off = _rva_to_offset(pe_bytes, names_rva)
    ords_off = _rva_to_offset(pe_bytes, ords_rva)

    for i in range(num_names):
        name_rva = struct.unpack_from("<I", pe_bytes, names_off + i * 4)[0]
        n_off = _rva_to_offset(pe_bytes, name_rva)
        end = pe_bytes.index(b"\x00", n_off)
        sym = pe_bytes[n_off:end].decode("ascii", errors="replace")
        if sym == export_name:
            ord_idx = struct.unpack_from("<H", pe_bytes, ords_off + i * 2)[0]
            if ord_idx >= num_funcs:
                raise ValueError(f"Export ordinal out of bounds for {export_name!r}")
            fn_rva = int(struct.unpack_from("<I", pe_bytes, funcs_off + ord_idx * 4)[0])
            if exp_rva <= fn_rva < exp_rva + exp_size:
                raise ValueError(f"Export {export_name!r} is a forwarder")
            return fn_rva
    raise KeyError(f"Export {export_name!r} not found in PE image")


class _ProcessEntry32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


class _ModuleEntry32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HANDLE),
        ("szModule", wt.WCHAR * 256),
        ("szExePath", wt.WCHAR * 260),
    ]


def _win32_api() -> Any:
    if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise RuntimeError("Windows x64 is required for live process inspection")
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    specs = {
        "OpenProcess": ([wt.DWORD, wt.BOOL, wt.DWORD], wt.HANDLE),
        "GetProcessTimes": ([wt.HANDLE] + [ctypes.POINTER(wt.FILETIME)] * 4, wt.BOOL),
        "ReadProcessMemory": (
            [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)],
            wt.BOOL,
        ),
        "CloseHandle": ([wt.HANDLE], wt.BOOL),
        "CreateToolhelp32Snapshot": ([wt.DWORD, wt.DWORD], wt.HANDLE),
        "QueryFullProcessImageNameW": ([wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)], wt.BOOL),
        "Process32FirstW": ([wt.HANDLE, ctypes.POINTER(_ProcessEntry32W)], wt.BOOL),
        "Process32NextW": ([wt.HANDLE, ctypes.POINTER(_ProcessEntry32W)], wt.BOOL),
        "Module32FirstW": ([wt.HANDLE, ctypes.POINTER(_ModuleEntry32W)], wt.BOOL),
        "Module32NextW": ([wt.HANDLE, ctypes.POINTER(_ModuleEntry32W)], wt.BOOL),
        "GetTickCount64": ([], ctypes.c_ulonglong),
    }
    for name, (argtypes, restype) in specs.items():
        fn = getattr(k, name)
        fn.argtypes = argtypes
        fn.restype = restype
    return k


def _process_birth_filetime(k: Any, handle: Any) -> int:
    times = [wt.FILETIME() for _ in range(4)]
    if not k.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
        raise OSError(f"GetProcessTimes failed: {ctypes.get_last_error()}")
    return (int(times[0].dwHighDateTime) << 32) | int(times[0].dwLowDateTime)


def _query_process_image_path(k: Any, handle: Any) -> Path:
    buf = ctypes.create_unicode_buffer(32768)
    length = wt.DWORD(len(buf))
    if not k.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(length)):
        raise OSError(f"QueryFullProcessImageNameW failed: {ctypes.get_last_error()}")
    return Path(buf.value).resolve()


def get_process_thread_count(pid: int) -> Optional[int]:
    """Return the live thread count for ``pid`` using a read-only Toolhelp snapshot."""
    k = _win32_api()
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    invalid = ctypes.c_void_p(-1).value
    if snap in (None, invalid):
        return None
    try:
        entry = _ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = k.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if int(entry.th32ProcessID) == pid:
                return int(entry.cntThreads)
            entry.dwSize = ctypes.sizeof(entry)
            ok = k.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k.CloseHandle(snap)
    return None


def find_processes_born_after(exe_path: Path, not_before_filetime: int) -> List[int]:
    """Return PIDs matching ``exe_path`` whose creation FILETIME >= ``not_before_filetime``."""
    target_exe = exe_path.resolve()
    k = _win32_api()
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    invalid = ctypes.c_void_p(-1).value
    found: List[int] = []
    if snap in (None, invalid):
        return found
    try:
        entry = _ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = k.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == target_exe.name.lower():
                handle = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(entry.th32ProcessID))
                if handle:
                    try:
                        img = _query_process_image_path(k, handle)
                        if img == target_exe and _process_birth_filetime(k, handle) >= not_before_filetime:
                            found.append(int(entry.th32ProcessID))
                    except OSError:
                        pass
                    finally:
                        k.CloseHandle(handle)
            entry.dwSize = ctypes.sizeof(entry)
            ok = k.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k.CloseHandle(snap)
    return found


def inspect_process_health(
    pid: int,
    module_path: Path,
    export_name: str = "hookkit_health_block",
    *,
    expected_exe_sha256: Optional[str] = None,
    expected_module_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Read and validate the exported ``SeqlockHealthBlock`` from a live process."""
    module = module_path.resolve()
    mod_sha = sha256_file(module)
    if expected_module_sha256 is not None and mod_sha != expected_module_sha256.upper():
        raise ValueError(f"Module SHA-256 mismatch: expected {expected_module_sha256.upper()}, got {mod_sha}")

    export_rva = resolve_pe_export_rva(module.read_bytes(), export_name)
    k = _win32_api()
    handle = k.OpenProcess(PROCESS_ACCESS_MASK, False, pid)
    if not handle:
        raise OSError(f"OpenProcess(0x{PROCESS_ACCESS_MASK:X}, pid={pid}) failed: {ctypes.get_last_error()}")

    snap = None
    invalid = ctypes.c_void_p(-1).value
    try:
        creation_ft = _process_birth_filetime(k, handle)
        exe_path = _query_process_image_path(k, handle)
        exe_sha = sha256_file(exe_path)
        if expected_exe_sha256 is not None and exe_sha != expected_exe_sha256.upper():
            raise ValueError(f"Process EXE SHA-256 mismatch: expected {expected_exe_sha256.upper()}, got {exe_sha}")

        snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE_ALL, pid)
        if snap in (None, invalid):
            raise OSError(f"CreateToolhelp32Snapshot(MODULES, pid={pid}) failed: {ctypes.get_last_error()}")

        row = _ModuleEntry32W()
        row.dwSize = ctypes.sizeof(row)
        ok = k.Module32FirstW(snap, ctypes.byref(row))
        base: Optional[int] = None
        while ok:
            if Path(row.szExePath).resolve() == module:
                base = int(row.modBaseAddr)
                break
            row.dwSize = ctypes.sizeof(row)
            ok = k.Module32NextW(snap, ctypes.byref(row))
        if base is None:
            raise LookupError(f"Module {module} is not loaded in PID {pid}")

        block_addr = base + export_rva

        def _read_mem(addr: int, size: int) -> bytes:
            buf = ctypes.create_string_buffer(size)
            got = ctypes.c_size_t()
            if not k.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
                raise OSError(f"ReadProcessMemory(0x{addr:X}, {size}) failed: {ctypes.get_last_error()}")
            if got.value != size:
                raise OSError(f"Short ReadProcessMemory: expected {size}, got {got.value}")
            return buf.raw

        snapshot = read_seqlock_consistent(_read_mem, block_addr)
        snapshot.update(
            {
                "pid": pid,
                "creation_filetime": creation_ft,
                "exe_path": str(exe_path),
                "exe_sha256": exe_sha,
                "module_path": str(module),
                "module_sha256": mod_sha,
                "block_va": hex(block_addr),
                "process_access_mask": PROCESS_ACCESS_MASK,
            }
        )
        return snapshot
    finally:
        if snap not in (None, invalid):
            k.CloseHandle(snap)
        k.CloseHandle(handle)


def observe_health(
    sample_fn: Callable[[], Dict[str, Any]],
    *,
    duration_s: float = 5.0,
    poll_interval_s: float = 0.2,
    stale_timeout_s: float = 5.0,
    thread_count_fn: Optional[Callable[[], Optional[int]]] = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> Dict[str, Any]:
    """Poll health snapshots, log state transitions, and detect stale heartbeats."""
    start = monotonic_fn()
    last_key: Optional[Tuple[Any, ...]] = None
    last_progress_time = start
    last_seq: Optional[int] = None
    events: List[Dict[str, Any]] = []
    peak_threads = 0
    latest: Optional[Dict[str, Any]] = None
    status = "observed"

    while True:
        now = monotonic_fn()
        snap = sample_fn()
        latest = snap
        threads = thread_count_fn() if thread_count_fn is not None else None
        if threads is not None:
            peak_threads = max(peak_threads, threads)

        seq = snap.get("seq")
        if last_seq is None or seq != last_seq:
            last_seq = seq
            last_progress_time = now

        key = (
            snap.get("seq"),
            snap.get("state"),
            snap.get("last_failure_reason"),
            snap.get("callback_enter_count"),
            snap.get("callback_exit_count"),
            threads,
        )
        if key != last_key:
            last_key = key
            events.append({"t": round(now - start, 4), "threads": threads, **snap})

        if now - last_progress_time > stale_timeout_s:
            status = "stale"
            break
        if now - start >= duration_s:
            break
        sleep_fn(poll_interval_s)

    return {
        "schema": "hookkit-health-observer-v1",
        "observer_status": status,
        "target_modified": False,
        "peak_threads": peak_threads if thread_count_fn is not None else None,
        "latest": latest,
        "events": events,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Out-of-process read-only Hookkit Seqlock health observer")
    parser.add_argument("--pid", type=int, help="Target process PID")
    parser.add_argument("--exe", type=Path, help="Target EXE path for birth-gated PID discovery")
    parser.add_argument("--not-before", type=int, default=0, help="FILETIME lower bound for PID discovery")
    parser.add_argument("--wait-seconds", type=float, default=30.0, help="Seconds to wait for target EXE birth")
    parser.add_argument("--module", type=Path, required=True, help="Loaded module path exporting SeqlockHealthBlock")
    parser.add_argument("--export", default="hookkit_health_block", help="Export symbol name")
    parser.add_argument("--exe-sha256", help="Expected uppercase SHA-256 of target EXE")
    parser.add_argument("--module-sha256", help="Expected uppercase SHA-256 of loaded module")
    parser.add_argument("--seconds", type=float, default=0.0, help="Observation duration in seconds")
    parser.add_argument("--stale-seconds", type=float, default=5.0, help="Stale heartbeat timeout in seconds")
    parser.add_argument("--json-out", type=Path, help="Optional output JSON report path")
    args = parser.parse_args(argv)

    pid = args.pid
    if pid is None:
        if args.exe is None:
            parser.error("Either --pid or --exe must be specified")
        deadline = time.monotonic() + args.wait_seconds
        while time.monotonic() < deadline:
            candidates = find_processes_born_after(args.exe, args.not_before)
            if len(candidates) > 1:
                print(json.dumps({"observer_status": "ambiguous_pid", "candidates": candidates}))
                return 2
            if candidates:
                pid = candidates[0]
                break
            time.sleep(0.2)
        if pid is None:
            print(json.dumps({"observer_status": "timeout"}))
            return 3

    report = observe_health(
        lambda: inspect_process_health(
            pid,
            args.module,
            args.export,
            expected_exe_sha256=args.exe_sha256,
            expected_module_sha256=args.module_sha256,
        ),
        duration_s=args.seconds,
        stale_timeout_s=args.stale_seconds,
        thread_count_fn=lambda: get_process_thread_count(pid),
    )
    payload = json.dumps(report, indent=2)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(payload, encoding="utf-8")
    else:
        print(payload)
    return 2 if report["observer_status"] == "stale" else 0


if __name__ == "__main__":
    raise SystemExit(main())
