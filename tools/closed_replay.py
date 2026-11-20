"""Closed-world x64 binary replay engine and VEH single-step page write watchpoint.

Provides two Windows x64 offline execution verification primitives alongside
pure-Python x64/interval helpers (usable without Capstone or Windows):

1. Pure-Python helpers:
   - `merge_intervals`, `Span`: O(log N) binary-searched interval containment.
   - `MemorySnapshot`: Stitched recorded memory block reader.
   - `operand_access`: x86/x64 explicit memory operand read/write classifier.
   - `classify_x64_opcode`: Distinguishes true string opcodes (`movs` A4/A5,
     `stos` AA/AB, implicit string opcodes A6/A7/AC..AF/6C..6F/D7) from SSE2
     `movsd`/`cmpsd` (`F2 0F ..`) and computes element size from `REX.W`/`0x66`.
   - `string_op_ranges`, `check_string_access`: Pre-execution whole-range
     bounds validation for string instructions.

2. Live Windows x64 execution sandbox:
   - `PeSandboxEngine`: Parses PE32+, reserves and commits the image at its
     ImageBase via `VirtualAlloc`, captures current thread stack limits, TEB
     via `NtQueryInformationThread`, and allocates a scratch TLS page.
   - `ClosedWorldReplayer`: Patches `0xCC` at `entry_va`, installs a Vectored
     Exception Handler (VEH) with `EFLAGS.TF` single-stepping, saves
     callee-saved GPRs + `XMM6..XMM15` + `entry_rsp` + return address for safe
     `abort(ctx)` recovery, checks every instruction fetch, explicit memory
     operand, and `rep movs`/`stos` range before execution, supports pluggable
     `rip_hooks`, tracks an exact byte-level write set, and compares post-call
     memory against an expected exit snapshot.
   - `PageWriteWatchpoint`: Lightweight VEH `PAGE_READONLY` + `EFLAGS.TF`
     single-step re-protect write watchpoint logging writer RIPs for arbitrary
     watched `(va, size)` ranges.
"""

from __future__ import annotations

import bisect
import ctypes
import struct
import time
from collections import Counter
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    import capstone
    from capstone import x86 as _x86
except ImportError:  # pragma: no cover
    capstone = None  # type: ignore[assignment]
    _x86 = None  # type: ignore[assignment]


MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_COMMIT_RESERVE = MEM_COMMIT | MEM_RESERVE
MEM_RELEASE = 0x8000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

PAGE_GRANULE = 0x1000
ALLOC_GRANULE = 0x10000

STATUS_BREAKPOINT = 0x80000003
STATUS_SINGLE_STEP = 0x80000004
STATUS_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_CONTINUE_EXECUTION = -1
EXCEPTION_CONTINUE_SEARCH = 0

CTX_EFLAGS_OFF = 0x44
CTX_RAX_OFF = 0x78
CTX_RCX_OFF = 0x80
CTX_RDX_OFF = 0x88
CTX_RBX_OFF = 0x90
CTX_RSP_OFF = 0x98
CTX_RBP_OFF = 0xA0
CTX_RSI_OFF = 0xA8
CTX_RDI_OFF = 0xB0
CTX_R8_OFF = 0xB8
CTX_R9_OFF = 0xC0
CTX_R10_OFF = 0xC8
CTX_R11_OFF = 0xD0
CTX_R12_OFF = 0xD8
CTX_R13_OFF = 0xE0
CTX_R14_OFF = 0xE8
CTX_R15_OFF = 0xF0
CTX_RIP_OFF = 0xF8
CTX_XMM6_OFF = 0x1A0 + 6 * 16

NV_GPR_OFFSETS: Tuple[int, ...] = (
    CTX_RBX_OFF,
    CTX_RBP_OFF,
    CTX_RSI_OFF,
    CTX_RDI_OFF,
    CTX_R12_OFF,
    CTX_R13_OFF,
    CTX_R14_OFF,
    CTX_R15_OFF,
)

READ_ONLY_EXACT: Set[str] = {
    "cmp",
    "test",
    "bt",
    "push",
    "call",
    "jmp",
    "ptest",
    "vptest",
    "cmpps",
    "cmpss",
    "cmppd",
    "cmpsd",
}
READ_ONLY_PREFIX: Tuple[str, ...] = ("ucomis", "comis", "vucomis", "vcomis", "prefetch", "nop")
PURE_STORE_PREFIX: Tuple[str, ...] = ("mov", "vmov", "stos", "set", "extractps", "vextract", "pextr", "vpextr")
STORE_EXCEPT_PREFIX: Tuple[str, ...] = ("movsb", "movsw", "movsd", "movsq", "cmov", "vmaskmov", "movhlps", "movlhps")
STRING_MNEMONICS: Set[str] = {
    "movsb",
    "movsw",
    "movsd",
    "movsq",
    "stosb",
    "stosw",
    "stosd",
    "stosq",
    "lodsb",
    "lodsw",
    "lodsd",
    "lodsq",
    "scasb",
    "scasw",
    "scasd",
    "scasq",
    "cmpsb",
    "cmpsw",
    "cmpsd",
    "cmpsq",
    "insb",
    "insw",
    "insd",
    "outsb",
    "outsw",
    "outsd",
    "xlatb",
}

LEGACY_PREFIXES: Set[int] = {0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67}
SEGMENT_PREFIXES: Set[int] = {0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65}
MOVS_STOS_OPCODES: Dict[int, Tuple[str, int]] = {
    0xA4: ("movs", 1),
    0xA5: ("movs", 0),
    0xAA: ("stos", 1),
    0xAB: ("stos", 0),
}
IMPLICIT_STRING_OPCODES: Set[int] = {0xA6, 0xA7, 0xAC, 0xAD, 0xAE, 0xAF, 0x6C, 0x6D, 0x6E, 0x6F, 0xD7}
MAX_STRING_BYTES = 1 << 31


if _x86 is not None:
    _REG64_TO_CTX: Dict[int, int] = {
        _x86.X86_REG_RAX: CTX_RAX_OFF,
        _x86.X86_REG_RCX: CTX_RCX_OFF,
        _x86.X86_REG_RDX: CTX_RDX_OFF,
        _x86.X86_REG_RBX: CTX_RBX_OFF,
        _x86.X86_REG_RSP: CTX_RSP_OFF,
        _x86.X86_REG_RBP: CTX_RBP_OFF,
        _x86.X86_REG_RSI: CTX_RSI_OFF,
        _x86.X86_REG_RDI: CTX_RDI_OFF,
        _x86.X86_REG_R8: CTX_R8_OFF,
        _x86.X86_REG_R9: CTX_R9_OFF,
        _x86.X86_REG_R10: CTX_R10_OFF,
        _x86.X86_REG_R11: CTX_R11_OFF,
        _x86.X86_REG_R12: CTX_R12_OFF,
        _x86.X86_REG_R13: CTX_R13_OFF,
        _x86.X86_REG_R14: CTX_R14_OFF,
        _x86.X86_REG_R15: CTX_R15_OFF,
    }
    _REG32_TO_REG64: Dict[int, int] = {
        _x86.X86_REG_EAX: _x86.X86_REG_RAX,
        _x86.X86_REG_ECX: _x86.X86_REG_RCX,
        _x86.X86_REG_EDX: _x86.X86_REG_RDX,
        _x86.X86_REG_EBX: _x86.X86_REG_RBX,
        _x86.X86_REG_ESP: _x86.X86_REG_RSP,
        _x86.X86_REG_EBP: _x86.X86_REG_RBP,
        _x86.X86_REG_ESI: _x86.X86_REG_RSI,
        _x86.X86_REG_EDI: _x86.X86_REG_RDI,
        _x86.X86_REG_R8D: _x86.X86_REG_R8,
        _x86.X86_REG_R9D: _x86.X86_REG_R9,
        _x86.X86_REG_R10D: _x86.X86_REG_R10,
        _x86.X86_REG_R11D: _x86.X86_REG_R11,
        _x86.X86_REG_R12D: _x86.X86_REG_R12,
        _x86.X86_REG_R13D: _x86.X86_REG_R13,
        _x86.X86_REG_R14D: _x86.X86_REG_R14,
        _x86.X86_REG_R15D: _x86.X86_REG_R15,
    }
else:  # pragma: no cover
    _REG64_TO_CTX = {}
    _REG32_TO_REG64 = {}


GPR_NAME_TO_CTX: Dict[str, int] = {
    "rax": CTX_RAX_OFF,
    "rcx": CTX_RCX_OFF,
    "rdx": CTX_RDX_OFF,
    "rbx": CTX_RBX_OFF,
    "rsp": CTX_RSP_OFF,
    "rbp": CTX_RBP_OFF,
    "rsi": CTX_RSI_OFF,
    "rdi": CTX_RDI_OFF,
    "r8": CTX_R8_OFF,
    "r9": CTX_R9_OFF,
    "r10": CTX_R10_OFF,
    "r11": CTX_R11_OFF,
    "r12": CTX_R12_OFF,
    "r13": CTX_R13_OFF,
    "r14": CTX_R14_OFF,
    "r15": CTX_R15_OFF,
    "rip": CTX_RIP_OFF,
}


class ReplayFailure(Exception):
    """Structured pre-execution or fault failure raised during closed replay."""

    def __init__(self, kind: str, **detail: Any) -> None:
        super().__init__(kind)
        self.kind = kind
        self.detail = detail


def _read_only_first(mnemonic: str) -> bool:
    return mnemonic in READ_ONLY_EXACT or mnemonic.startswith(READ_ONLY_PREFIX)


def operand_access(mnemonic: str, position: int, capstone_flag: int = 0) -> int:
    """Return bitmask ``1 (read) | 2 (write)`` for an x86/x64 memory operand.

    Applies x86 operand role semantics on top of Capstone's access flag so
    read-only comparisons, pure stores, and read-modify-write instructions are
    classified consistently.
    """
    acc = capstone_flag or 0
    if position == 0 and not _read_only_first(mnemonic):
        acc |= 2
    if position == 0 and mnemonic.startswith(PURE_STORE_PREFIX) and not mnemonic.startswith(STORE_EXCEPT_PREFIX):
        acc = 2
    elif position != 0 or _read_only_first(mnemonic) or not mnemonic.startswith(PURE_STORE_PREFIX):
        acc |= 1
    if mnemonic == "xchg":
        acc |= 3
    return acc


def merge_intervals(intervals: Iterable[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Sort and coalesce overlapping or adjacent half-open intervals ``[lo, hi)``."""
    out: List[Tuple[int, int]] = []
    for lo, hi in sorted(intervals):
        if hi <= lo:
            continue
        if out and lo <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


class Span:
    """Sorted merged intervals supporting O(log N) full-range containment checks."""

    def __init__(self, intervals: Iterable[Tuple[int, int]]) -> None:
        self.iv: List[Tuple[int, int]] = merge_intervals(intervals)
        self.starts: List[int] = [lo for lo, _ in self.iv]

    def contains(self, addr: int, size: int) -> bool:
        """Return True iff ``[addr, addr + size)`` lies wholly within one interval."""
        if size <= 0:
            return True
        i = bisect.bisect_right(self.starts, addr) - 1
        return i >= 0 and addr >= self.iv[i][0] and addr + size <= self.iv[i][1]


class MemorySnapshot:
    """Byte-addressed snapshot over recorded blocks; adjacent blocks are stitched."""

    def __init__(self, blocks: Iterable[Tuple[int, bytes]]) -> None:
        raw_iv: List[List[Any]] = []
        for addr, chunk in sorted(blocks, key=lambda item: item[0]):
            if not chunk:
                continue
            n = len(chunk)
            if raw_iv and addr == raw_iv[-1][1]:
                raw_iv[-1][1] += n
                raw_iv[-1][2].extend(chunk)
            elif raw_iv and addr < raw_iv[-1][1]:
                hi = raw_iv[-1][1]
                if addr + n > hi:
                    raw_iv[-1][1] = addr + n
                    raw_iv[-1][2].extend(chunk[hi - addr :])
            else:
                raw_iv.append([addr, addr + n, bytearray(chunk)])
        self.iv: List[Tuple[int, int, bytes]] = [(lo, hi, bytes(buf)) for lo, hi, buf in raw_iv]
        self.starts: List[int] = [lo for lo, _, _ in self.iv]

    def read(self, addr: int, size: int) -> Optional[bytes]:
        """Return ``size`` bytes at ``addr`` or ``None`` if any byte is uncovered."""
        if size <= 0:
            return b""
        i = bisect.bisect_right(self.starts, addr) - 1
        if i < 0:
            return None
        lo, hi, data = self.iv[i]
        if addr < lo or addr + size > hi:
            return None
        off = addr - lo
        return data[off : off + size]

    def read_u32(self, addr: int) -> Optional[int]:
        raw = self.read(addr, 4)
        return struct.unpack("<I", raw)[0] if raw is not None else None

    def read_u64(self, addr: int) -> Optional[int]:
        raw = self.read(addr, 8)
        return struct.unpack("<Q", raw)[0] if raw is not None else None

    def intervals(self) -> List[Tuple[int, int]]:
        return [(lo, hi) for lo, hi, _ in self.iv]


def classify_x64_opcode(code_bytes: bytes) -> Tuple[str, Any]:
    """Classify raw x64 instruction bytes into string vs plain opcodes.

    Distinguishes true x64 string opcodes (``movs`` A4/A5, ``stos`` AA/AB,
    and implicit string opcodes A6/A7/AC..AF/6C..6F/D7) from SSE2 scalar
    ``movsd``/``cmpsd`` (``F2 0F ..``) which share mnemonics with string forms.

    Returns:
        - ``('string', (name, esize, has_rep, prefixes))`` for ``movs``/``stos``
        - ``('implicit', opcode_byte)`` for unsupported implicit string opcodes
        - ``('plain', None)`` for all other instructions
    """
    pre: List[int] = []
    i = 0
    while i < len(code_bytes) and code_bytes[i] in LEGACY_PREFIXES:
        pre.append(code_bytes[i])
        i += 1
    rex = code_bytes[i] if i < len(code_bytes) and 0x40 <= code_bytes[i] <= 0x4F else 0
    if rex:
        i += 1
    op = code_bytes[i] if i < len(code_bytes) else None
    if op in MOVS_STOS_OPCODES:
        name, fixed = MOVS_STOS_OPCODES[op]
        esize = fixed or (8 if (rex & 8) else (2 if 0x66 in pre else 4))
        has_rep = (0xF3 in pre) or (0xF2 in pre)
        return "string", (name, esize, has_rep, tuple(pre))
    if op in IMPLICIT_STRING_OPCODES:
        return "implicit", op
    return "plain", None


def string_op_ranges(
    name: str,
    esize: int,
    count: int,
    rsi: int,
    rdi: int,
    df: int,
) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    """Compute ``(reads, writes)`` byte intervals for a ``movs`` or ``stos`` op."""
    if count <= 0:
        return [], []
    total = count * esize
    first = (lambda ptr: ptr) if not df else (lambda ptr: ptr - (count - 1) * esize)
    writes = [(first(rdi) & 0xFFFFFFFFFFFFFFFF, total)]
    reads = [(first(rsi) & 0xFFFFFFFFFFFFFFFF, total)] if name == "movs" else []
    return reads, writes


def check_string_access(
    reads: Sequence[Tuple[int, int]],
    writes: Sequence[Tuple[int, int]],
    read_span: Span,
    write_span: Span,
    stack: Optional[Tuple[int, int]] = None,
) -> None:
    """Validate pre-execution whole-range read/write bounds for a string instruction."""

    def _in_stack(addr: int, size: int) -> bool:
        return stack is not None and stack[0] <= addr and addr + size <= stack[1]

    for addr, size in writes:
        if size > MAX_STRING_BYTES:
            raise ReplayFailure("string instruction range too large", address=hex(addr), size=size)
        if not (_in_stack(addr, size) or write_span.contains(addr, size)):
            raise ReplayFailure("string write outside recorded memory", address=hex(addr), size=size)
    for addr, size in reads:
        if size > MAX_STRING_BYTES:
            raise ReplayFailure("string instruction range too large", address=hex(addr), size=size)
        if not (_in_stack(addr, size) or read_span.contains(addr, size)):
            raise ReplayFailure("string read outside recorded memory", address=hex(addr), size=size)


def _parse_pe32_plus_layout(pe_bytes: bytes) -> Tuple[int, List[Dict[str, Any]]]:
    if len(pe_bytes) < 0x40 or pe_bytes[:2] != b"MZ":
        raise ValueError("Not a valid MZ PE image")
    e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    if pe_bytes[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("Missing PE signature")
    coff = e_lfanew + 4
    machine, num_sections = struct.unpack_from("<HH", pe_bytes, coff)
    if machine != 0x8664:
        raise ValueError(f"Expected AMD64 PE (0x8664), got 0x{machine:X}")
    opt_size = struct.unpack_from("<H", pe_bytes, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", pe_bytes, opt)[0]
    if magic != 0x20B:
        raise ValueError(f"Expected PE32+ (0x20B), got 0x{magic:X}")
    image_base = struct.unpack_from("<Q", pe_bytes, opt + 24)[0]
    sec_off = opt + opt_size
    sections: List[Dict[str, Any]] = []
    for i in range(num_sections):
        off = sec_off + i * 40
        name = pe_bytes[off : off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, rva, raw_size, raw_offset = struct.unpack_from("<IIII", pe_bytes, off + 8)
        characteristics = struct.unpack_from("<I", pe_bytes, off + 36)[0]
        sections.append(
            {
                "name": name,
                "rva": rva,
                "virtual_size": vsize,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
                "characteristics": characteristics,
            }
        )
    return image_base, sections


def _query_current_teb(kernel32: Any) -> int:
    class _ThreadBasicInfo(ctypes.Structure):
        _fields_ = [
            ("ExitStatus", ctypes.c_long),
            ("TebBaseAddress", ctypes.c_void_p),
            ("ClientId", ctypes.c_uint64 * 2),
            ("AffinityMask", ctypes.c_uint64),
            ("Priority", ctypes.c_long),
            ("BasePriority", ctypes.c_long),
        ]

    ntdll = ctypes.WinDLL("ntdll")
    tbi = _ThreadBasicInfo()
    kernel32.GetCurrentThread.restype = ctypes.c_void_p
    ntdll.NtQueryInformationThread.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    ntdll.NtQueryInformationThread.restype = ctypes.c_long
    status = ntdll.NtQueryInformationThread(
        ctypes.c_void_p(kernel32.GetCurrentThread()),
        0,
        ctypes.byref(tbi),
        ctypes.sizeof(tbi),
        None,
    )
    if status != 0 or not tbi.TebBaseAddress:
        raise RuntimeError(f"NtQueryInformationThread failed with status 0x{status & 0xFFFFFFFF:X}")
    return int(tbi.TebBaseAddress)


class PeSandboxEngine:
    """In-process PE32+ sandbox mapping image sections, stack limits, TEB, and scratch TLS."""

    def __init__(self, pe_bytes: bytes, *, image_base_override: Optional[int] = None) -> None:
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise RuntimeError("PeSandboxEngine requires 64-bit Python on Windows")
        self.pe_bytes = pe_bytes
        parsed_base, self.sections = _parse_pe32_plus_layout(pe_bytes)
        self.base: int = parsed_base if image_base_override is None else image_base_override

        k = self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
        k.VirtualAlloc.restype = ctypes.c_void_p
        k.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
        k.VirtualFree.restype = ctypes.c_int
        k.VirtualProtect.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        k.VirtualProtect.restype = ctypes.c_int
        k.GetCurrentThreadStackLimits.argtypes = [
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64),
        ]
        k.AddVectoredExceptionHandler.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
        k.AddVectoredExceptionHandler.restype = ctypes.c_void_p
        k.RemoveVectoredExceptionHandler.argtypes = [ctypes.c_void_p]
        k.RemoveVectoredExceptionHandler.restype = ctypes.c_uint32

        lo_ = ctypes.c_uint64()
        hi_ = ctypes.c_uint64()
        k.GetCurrentThreadStackLimits(ctypes.byref(lo_), ctypes.byref(hi_))
        self.stack: Tuple[int, int] = (int(lo_.value), int(hi_.value))
        self.teb: int = _query_current_teb(k)
        self.tls_array: int = int(ctypes.c_uint64.from_address(self.teb + 0x58).value)

        self.image_ranges: List[Tuple[int, int]] = []
        self.fetch_ranges: List[Tuple[int, int]] = []
        self.image_pages: Set[int] = set()
        self.granules: Dict[int, bool] = {}
        self._image_reserved = False
        self._released = False
        self.fake_tls: int = 0
        try:
            self._map_image()
            self.fake_tls = int(k.VirtualAlloc(None, PAGE_GRANULE, MEM_COMMIT_RESERVE, PAGE_READWRITE) or 0)
            if not self.fake_tls:
                raise RuntimeError("VirtualAlloc scratch TLS page failed")
        except Exception:
            self.release()
            raise

    def _map_image(self) -> None:
        k = self.k
        base = self.base
        pe_bytes = self.pe_bytes
        end = max(
            [base + PAGE_GRANULE]
            + [base + s["rva"] + s["virtual_size"] for s in self.sections if s["virtual_size"]]
        )
        span = ((end - base) + 0xFFFF) & ~0xFFFF
        reserved = k.VirtualAlloc(ctypes.c_void_p(base), span, MEM_RESERVE, PAGE_NOACCESS)
        if reserved != base:
            raise RuntimeError(f"VirtualAlloc PE image reservation at 0x{base:X} (size 0x{span:X}) failed")
        self._image_reserved = True

        if k.VirtualAlloc(ctypes.c_void_p(base), PAGE_GRANULE, MEM_COMMIT, PAGE_EXECUTE_READWRITE) != base:
            raise RuntimeError(f"VirtualAlloc PE header at 0x{base:X} failed")
        hdr_copy = min(PAGE_GRANULE, len(pe_bytes))
        ctypes.memmove(ctypes.c_void_p(base), pe_bytes[:hdr_copy], hdr_copy)
        self.image_ranges.append((base, base + PAGE_GRANULE))
        self.image_pages.add(base >> 12)

        for sec in self.sections:
            vs = sec["virtual_size"]
            if not vs:
                continue
            commit_size = (vs + PAGE_GRANULE - 1) & ~(PAGE_GRANULE - 1)
            va = base + sec["rva"]
            if k.VirtualAlloc(ctypes.c_void_p(va), commit_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE) != va:
                raise RuntimeError(f"VirtualAlloc section {sec['name']!r} at 0x{va:X} failed")
            copy_len = min(sec["raw_size"], vs)
            if copy_len > 0:
                raw_off = sec["raw_offset"]
                ctypes.memmove(ctypes.c_void_p(va), pe_bytes[raw_off : raw_off + copy_len], copy_len)
            self.image_ranges.append((va, va + vs))
            if sec["characteristics"] & 0x20000000:
                self.fetch_ranges.append((va, va + vs))
            for pg in range(va >> 12, ((va + vs - 1) >> 12) + 1):
                self.image_pages.add(pg)

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        k = self.k
        for gran in list(self.granules):
            k.VirtualFree(ctypes.c_void_p(gran), 0, MEM_RELEASE)
        self.granules.clear()
        if self._image_reserved:
            k.VirtualFree(ctypes.c_void_p(self.base), 0, MEM_RELEASE)
            self._image_reserved = False
        if self.fake_tls:
            k.VirtualFree(ctypes.c_void_p(self.fake_tls), 0, MEM_RELEASE)
            self.fake_tls = 0

    def __enter__(self) -> "PeSandboxEngine":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.release()


class ClosedWorldReplayer:
    """Single-stepping VEH replay engine enforcing closed-world memory containment."""

    def __init__(
        self,
        engine: PeSandboxEngine,
        entry_va: int,
        entry_blocks: Sequence[Tuple[int, bytes]],
        exit_memory: Optional[MemorySnapshot] = None,
        extra_read_spans: Sequence[Tuple[int, int]] = (),
        extra_write_spans: Sequence[Tuple[int, int]] = (),
        rip_hooks: Optional[Dict[int, Callable[["ClosedWorldReplayer", int, int], Optional[bool]]]] = None,
        access_observer: Optional[Callable[[str, int, int, int], None]] = None,
        max_steps: int = 200_000_000,
    ) -> None:
        if capstone is None:
            raise ImportError("capstone is required for ClosedWorldReplayer")
        self.engine = engine
        self.k = engine.k
        self.entry_va = entry_va
        self.entry_blocks: List[Tuple[int, bytes]] = [(addr, bytes(data)) for addr, data in entry_blocks]
        self.entry_memory = MemorySnapshot(self.entry_blocks)
        self.exit_memory = exit_memory
        self.extra_read_spans = list(extra_read_spans)
        self.extra_write_spans = list(extra_write_spans)
        self.rip_hooks = dict(rip_hooks) if rip_hooks else {}
        self.access_observer = access_observer
        self.max_steps = max_steps

        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        self._decode_cache: Dict[int, Optional[Tuple[int, List[Tuple[Any, ...]], str]]] = {}
        self._kind_cache: Dict[int, Tuple[str, Any]] = {}
        self.st: Dict[str, Any] = {}
        self.string_log: Dict[str, Any] = {}

        self._map_recorded()
        self.record_span = Span(self.entry_memory.intervals())
        self.read_span = Span(
            self.entry_memory.intervals()
            + engine.image_ranges
            + [engine.stack]
            + [(engine.teb, engine.teb + 0x2000)]
            + self.extra_read_spans
        )
        self.write_span = Span(
            self.entry_memory.intervals() + [engine.stack] + self.extra_write_spans
        )

    def _map_recorded(self) -> None:
        k = self.k
        for addr, chunk in self.entry_blocks:
            if not chunk:
                continue
            start_pg = addr & ~0xFFF
            end_pg = ((addr + len(chunk) - 1) & ~0xFFF) + PAGE_GRANULE
            for pg in range(start_pg, end_pg, PAGE_GRANULE):
                if (pg >> 12) in self.engine.image_pages:
                    continue
                gran = pg & ~0xFFFF
                if gran in self.engine.granules:
                    continue
                ptr = k.VirtualAlloc(ctypes.c_void_p(gran), ALLOC_GRANULE, MEM_COMMIT_RESERVE, PAGE_READWRITE)
                if ptr != gran:
                    raise RuntimeError(f"VirtualAlloc recorded granule 0x{gran:X} failed")
                self.engine.granules[gran] = True
        self.restore()

    def restore(self) -> None:
        """Reset mapped entry blocks back to their initial recorded byte contents."""
        for addr, chunk in self.entry_blocks:
            if chunk:
                ctypes.memmove(ctypes.c_void_p(addr), chunk, len(chunk))

    @staticmethod
    def get_ctx_u64(ctx: int, offset: int) -> int:
        return int(ctypes.c_uint64.from_address(ctx + offset).value)

    @staticmethod
    def set_ctx_u64(ctx: int, offset: int, value: int) -> None:
        ctypes.c_uint64.from_address(ctx + offset).value = value & 0xFFFFFFFFFFFFFFFF

    def get_reg(self, ctx: int, name: str) -> int:
        return self.get_ctx_u64(ctx, GPR_NAME_TO_CTX[name.lower()])

    def set_reg(self, ctx: int, name: str, value: int) -> None:
        self.set_ctx_u64(ctx, GPR_NAME_TO_CTX[name.lower()], value)

    @staticmethod
    def read_live(va: int, size: int) -> bytes:
        return ctypes.string_at(va, size)

    @staticmethod
    def write_live(va: int, data: bytes) -> None:
        ctypes.memmove(ctypes.c_void_p(va), data, len(data))

    def instruction_kind(self, rip: int) -> Tuple[str, Any]:
        kind = self._kind_cache.get(rip)
        if kind is None:
            kind = self._kind_cache[rip] = classify_x64_opcode(ctypes.string_at(rip, 16))
        return kind

    def decode(self, rip: int) -> Optional[Tuple[int, List[Tuple[Any, ...]], str]]:
        cached = self._decode_cache.get(rip)
        if cached is not None or rip in self._decode_cache:
            return cached
        ins = next(self.md.disasm(ctypes.string_at(rip, 16), rip), None)
        if ins is None:
            self._decode_cache[rip] = None
            return None
        ops: List[List[Any]] = []
        mn = ins.mnemonic.split()[-1]
        if not (mn in ("lea", "nop") or mn.startswith(("prefetch", "nop"))):
            for op in ins.operands:
                if op.type == _x86.X86_OP_MEM:
                    mem = op.mem
                    base_is_32 = mem.base in _REG32_TO_REG64
                    idx_is_32 = mem.index in _REG32_TO_REG64
                    br = _REG32_TO_REG64.get(mem.base, mem.base)
                    ir = _REG32_TO_REG64.get(mem.index, mem.index)
                    b_off = _REG64_TO_CTX.get(br, -1 if br == _x86.X86_REG_RIP else (None if br == 0 else -2))
                    i_off = _REG64_TO_CTX.get(ir, None if ir == 0 else -2)
                    ops.append([b_off, base_is_32, i_off, idx_is_32, mem.scale, mem.disp, op.size, mem.segment, op.access])
            mem_positions = [idx for idx, op in enumerate(ins.operands) if op.type == _x86.X86_OP_MEM]
            for entry, pos in zip(ops, mem_positions):
                entry[8] = operand_access(mn, pos, entry[8])
        frozen_ops = [tuple(o) for o in ops]
        if mn in STRING_MNEMONICS and self.instruction_kind(rip)[0] == "plain":
            mnemonic_label = f"{ins.mnemonic}/non-string-opcode"
        else:
            mnemonic_label = ins.mnemonic
        decoded = (ins.size, frozen_ops, mnemonic_label)
        self._decode_cache[rip] = decoded
        return decoded

    def check(self, ctx: int, rip: int) -> bool:
        """Validate the instruction at ``rip`` before execution.

        Returns True when a ``rip_hook`` emulated the instruction and advanced ``RIP``.
        """
        st = self.st
        if rip in self.rip_hooks:
            handled = self.rip_hooks[rip](self, ctx, rip)
            if handled:
                st["hooks_emulated"] += 1
                return True
            rip = self.get_ctx_u64(ctx, CTX_RIP_OFF)

        kind, detail = self.instruction_kind(rip)
        if kind == "implicit":
            raise ReplayFailure("implicit-memory string instruction", rip=hex(rip), opcode=hex(detail))
        if kind == "string":
            name, esize, has_rep, pre = detail
            if 0x67 in pre:
                raise ReplayFailure("string instruction with address-size prefix", rip=hex(rip))
            if any(p in SEGMENT_PREFIXES for p in pre):
                raise ReplayFailure("string instruction with segment override", rip=hex(rip))
            rcx = self.get_ctx_u64(ctx, CTX_RCX_OFF)
            rsi = self.get_ctx_u64(ctx, CTX_RSI_OFF)
            rdi = self.get_ctx_u64(ctx, CTX_RDI_OFF)
            df = (int(ctypes.c_uint32.from_address(ctx + CTX_EFLAGS_OFF).value) >> 10) & 1
            count = rcx if has_rep else 1
            reads, writes = string_op_ranges(name, esize, count, rsi, rdi, df)
            try:
                check_string_access(reads, writes, self.read_span, self.write_span, self.engine.stack)
            except ReplayFailure as exc:
                exc.detail.update(rip=hex(rip), op=name, esize=esize, rep=has_rep, count=count, df=df)
                raise
            slog = self.string_log
            slog["traps"] += 1
            first_trap = slog.get("last") != (rip, st["steps"] - 1)
            slog["last"] = (rip, st["steps"])
            if first_trap:
                slog["executions"] += 1
                if len(slog["first"]) < 16:
                    slog["first"].append(
                        {
                            "rip": hex(rip),
                            "op": name,
                            "esize": esize,
                            "rep": has_rep,
                            "count": count,
                            "df": df,
                            "writes": [[hex(a), n] for a, n in writes],
                            "reads": [[hex(a), n] for a, n in reads],
                        }
                    )
            for addr, size in writes:
                if not (self.engine.stack[0] <= addr < self.engine.stack[1]):
                    st["writes"].append((addr, size, rip, ctypes.string_at(addr, min(size, 16))))
                    if first_trap:
                        slog["bytes_written"] += size
                if self.access_observer is not None:
                    self.access_observer("write", addr, size, rip)
            for addr, size in reads:
                if self.access_observer is not None:
                    self.access_observer("read", addr, size, rip)
            return False

        decoded = self.decode(rip)
        if decoded is None:
            raise ReplayFailure("undecoded instruction", rip=hex(rip))
        insn_size, ops, mnemonic = decoded
        for b_off, b32, i_off, i32, scale, disp, size, seg, acc in ops:
            if b_off == -2 or i_off == -2:
                raise ReplayFailure("undecoded register operand", rip=hex(rip), mnemonic=mnemonic)
            if b_off == -1:
                ea = rip + insn_size + disp
            else:
                bval = self.get_ctx_u64(ctx, b_off) if b_off is not None else 0
                if b32:
                    bval &= 0xFFFFFFFF
                ival = self.get_ctx_u64(ctx, i_off) if i_off is not None else 0
                if i32:
                    ival &= 0xFFFFFFFF
                ea = bval + ival * scale + disp
            if seg == _x86.X86_REG_GS:
                ea += self.engine.teb
            elif seg == _x86.X86_REG_FS:
                ea = -1
            ea &= 0xFFFFFFFFFFFFFFFF
            if seg == _x86.X86_REG_GS and self.engine.teb <= ea < self.engine.teb + 0x2000:
                continue
            if self.engine.stack[0] <= ea < self.engine.stack[1]:
                continue
            do_read = bool(acc & 1) or acc == 0
            do_write = bool(acc & 2) or acc == 0
            if do_write:
                if not self.write_span.contains(ea, size):
                    raise ReplayFailure(
                        "write outside recorded memory",
                        rip=hex(rip),
                        address=hex(ea),
                        size=size,
                        mnemonic=mnemonic,
                        access=acc,
                    )
                st["writes"].append((ea, size, rip, ctypes.string_at(ea, min(size, 16))))
                if self.access_observer is not None:
                    self.access_observer("write", ea, size, rip)
            if do_read:
                if not self.read_span.contains(ea, size):
                    raise ReplayFailure(
                        "unrecorded memory read",
                        rip=hex(rip),
                        address=hex(ea),
                        size=size,
                        mnemonic=mnemonic,
                        access=acc,
                    )
                if self.access_observer is not None:
                    self.access_observer("read", ea, size, rip)
        return False

    def abort(self, ctx: int) -> int:
        """Restore non-volatile state and jump directly to ``entry_va`` return address."""
        st = self.st
        st["done"] = True
        st["aborted"] = True
        if st["ret"] is None:
            ctypes.c_uint32.from_address(ctx + CTX_EFLAGS_OFF).value &= ~0x100
            return EXCEPTION_CONTINUE_EXECUTION
        for off, val in zip(NV_GPR_OFFSETS, st["nv"]):
            self.set_ctx_u64(ctx, off, val)
        ctypes.memmove(ctypes.c_void_p(ctx + CTX_XMM6_OFF), st["xmm"], 10 * 16)
        self.set_ctx_u64(ctx, CTX_RIP_OFF, st["ret"])
        self.set_ctx_u64(ctx, CTX_RSP_OFF, st["entry_rsp"] + 8)
        ctypes.c_uint32.from_address(ctx + CTX_EFLAGS_OFF).value &= ~0x100
        return EXCEPTION_CONTINUE_EXECUTION

    def run(
        self,
        *args: int,
        argtypes: Optional[Sequence[Any]] = None,
        restype: Any = None,
    ) -> Dict[str, Any]:
        """Execute ``entry_va(*args)`` under VEH single-step containment."""
        k = self.k
        self.restore()
        self.string_log = {"executions": 0, "traps": 0, "bytes_written": 0, "first": []}
        st: Dict[str, Any] = {
            "steps": 0,
            "armed": False,
            "done": False,
            "aborted": False,
            "ret": None,
            "entry_rsp": None,
            "failure": None,
            "writes": [],
            "hooks_emulated": 0,
            "nv": None,
            "xmm": None,
            "return_value": None,
        }
        self.st = st

        entry = self.entry_va
        original = ctypes.string_at(entry, 1)
        old_prot = ctypes.c_uint32()
        k.VirtualProtect(ctypes.c_void_p(entry), 1, PAGE_EXECUTE_READWRITE, ctypes.byref(old_prot))
        ctypes.memmove(ctypes.c_void_p(entry), b"\xCC", 1)

        def _pre_step(ctx: int) -> int:
            rip = self.get_ctx_u64(ctx, CTX_RIP_OFF)
            while True:
                st["steps"] += 1
                if st["steps"] > self.max_steps:
                    st["failure"] = {"kind": "step limit", "steps": st["steps"]}
                    return self.abort(ctx)
                if not any(lo <= rip < hi for lo, hi in self.engine.fetch_ranges):
                    st["failure"] = {"kind": "instruction fetch outside PE executable sections", "rip": hex(rip)}
                    return self.abort(ctx)
                if not self.check(ctx, rip):
                    break
                rip = self.get_ctx_u64(ctx, CTX_RIP_OFF)
            ctypes.c_uint32.from_address(ctx + CTX_EFLAGS_OFF).value |= 0x100
            return EXCEPTION_CONTINUE_EXECUTION

        @ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
        def veh(ptr: int) -> int:
            try:
                rec = int(ctypes.c_void_p.from_address(ptr).value)
                ctx = int(ctypes.c_void_p.from_address(ptr + 8).value)
                code_ = int(ctypes.c_uint32.from_address(rec).value)
                rip = self.get_ctx_u64(ctx, CTX_RIP_OFF)
                if code_ == STATUS_BREAKPOINT and rip in (entry, entry + 1) and not st["armed"]:
                    k.VirtualProtect(ctypes.c_void_p(entry), 1, PAGE_EXECUTE_READWRITE, ctypes.byref(ctypes.c_uint32()))
                    ctypes.memmove(ctypes.c_void_p(entry), original, 1)
                    self.set_ctx_u64(ctx, CTX_RIP_OFF, entry)
                    entry_rsp = self.get_ctx_u64(ctx, CTX_RSP_OFF)
                    st["entry_rsp"] = entry_rsp
                    st["ret"] = int(ctypes.c_uint64.from_address(entry_rsp).value)
                    st["nv"] = [self.get_ctx_u64(ctx, off) for off in NV_GPR_OFFSETS]
                    st["xmm"] = ctypes.string_at(ctx + CTX_XMM6_OFF, 10 * 16)
                    st["armed"] = True
                    return _pre_step(ctx)
                if code_ == STATUS_ACCESS_VIOLATION and st["armed"] and not st["done"]:
                    nparam = int(ctypes.c_uint32.from_address(rec + 24).value)
                    info = int(ctypes.c_uint64.from_address(rec + 32).value) if nparam else 0
                    addr = int(ctypes.c_uint64.from_address(rec + 40).value) if nparam > 1 else 0
                    acc_kind = {0: "read", 1: "write", 8: "execute"}.get(info, str(info))
                    st["failure"] = {
                        "kind": "access violation",
                        "rip": hex(rip),
                        "address": hex(addr),
                        "access": acc_kind,
                    }
                    return self.abort(ctx)
                if code_ != STATUS_SINGLE_STEP or not st["armed"] or st["done"]:
                    return EXCEPTION_CONTINUE_SEARCH
                if rip == st["ret"] and self.get_ctx_u64(ctx, CTX_RSP_OFF) > st["entry_rsp"]:
                    st["done"] = True
                    ctypes.c_uint32.from_address(ctx + CTX_EFLAGS_OFF).value &= ~0x100
                    return EXCEPTION_CONTINUE_EXECUTION
                return _pre_step(ctx)
            except ReplayFailure as exc:
                st["failure"] = {"kind": exc.kind, **exc.detail}
                return self.abort(ctx)
            except Exception as exc:  # pragma: no cover
                st["failure"] = {"kind": "tool error", "detail": repr(exc)}
                return self.abort(ctx)

        veh_handle = k.AddVectoredExceptionHandler(1, veh)
        if not veh_handle:
            ctypes.memmove(ctypes.c_void_p(entry), original, 1)
            raise RuntimeError("AddVectoredExceptionHandler failed")

        c_argtypes = list(argtypes) if argtypes is not None else [ctypes.c_uint64] * len(args)
        fn_type = ctypes.WINFUNCTYPE(restype, *c_argtypes)
        t0 = time.monotonic()
        try:
            st["return_value"] = fn_type(entry)(*args)
        finally:
            k.VirtualProtect(ctypes.c_void_p(entry), 1, PAGE_EXECUTE_READWRITE, ctypes.byref(ctypes.c_uint32()))
            ctypes.memmove(ctypes.c_void_p(entry), original, 1)
            k.VirtualProtect(ctypes.c_void_p(entry), 1, old_prot.value, ctypes.byref(ctypes.c_uint32()))
            k.RemoveVectoredExceptionHandler(veh_handle)

        st["seconds"] = round(time.monotonic() - t0, 4)
        if not st["done"] and st["failure"] is None:
            st["failure"] = {"kind": "entry function did not return"}
        return st

    @staticmethod
    def _addr_in_intervals(addr: int, intervals: Sequence[Tuple[int, int]], starts: Sequence[int]) -> bool:
        i = bisect.bisect_right(starts, addr) - 1
        return i >= 0 and addr < intervals[i][1]

    def evaluate(self) -> Dict[str, Any]:
        """Compare post-replay memory against ``exit_memory`` and audit write-set containment."""
        st = self.st
        writes = merge_intervals((ea, ea + size) for ea, size, _, _ in st["writes"])
        wstarts = [lo for lo, _ in writes]
        result: Dict[str, Any] = {
            "status": "FAILED" if st["failure"] else "PENDING",
            "steps": st["steps"],
            "seconds": st["seconds"],
            "completed": bool(st["done"] and not st["aborted"]),
            "failure": st["failure"],
            "hooks_emulated": st["hooks_emulated"],
            "return_value": st.get("return_value"),
            "string_instructions": {k: v for k, v in self.string_log.items() if k != "last"},
            "write_set": {
                "bytes": sum(hi - lo for lo, hi in writes),
                "intervals": len(writes),
                "list": [[hex(lo), hi - lo] for lo, hi in writes[:4096]],
            },
        }
        if st["failure"]:
            result["bytes_compared"] = 0
            result["bytes_equal"] = 0
            result["differ"] = 0
            return result

        if self.exit_memory is None:
            result["status"] = "COMPLETED"
            return result

        compared = 0
        equal = 0
        differ: List[Dict[str, Any]] = []
        outside: List[str] = []
        missing_entry = 0
        missing_exit = 0
        unmapped = 0
        differ_total = 0
        outside_total = 0

        for addr, chunk in self.entry_blocks:
            if chunk and self.exit_memory.read(addr, len(chunk)) is None:
                missing_exit += len(chunk)

        live_span = Span(self.entry_memory.intervals() + self.engine.image_ranges + self.extra_write_spans)
        for addr, _hi, expected in self.exit_memory.iv:
            entry_bytes = self.entry_memory.read(addr, len(expected))
            if entry_bytes is None:
                missing_entry += len(expected)
            if not live_span.contains(addr, len(expected)):
                unmapped += len(expected)
                live_bytes = None
            else:
                live_bytes = ctypes.string_at(addr, len(expected))

            if entry_bytes is not None:
                for i in range(len(expected)):
                    if entry_bytes[i] != expected[i] and not self._addr_in_intervals(addr + i, writes, wstarts):
                        outside_total += 1
                        if len(outside) < 64:
                            outside.append(hex(addr + i))

            if live_bytes is not None:
                compared += len(expected)
                if live_bytes == expected:
                    equal += len(expected)
                else:
                    for i in range(len(expected)):
                        if live_bytes[i] != expected[i]:
                            differ_total += 1
                            if len(differ) < 64:
                                differ.append({"address": hex(addr + i), "exit": expected[i], "replay": live_bytes[i]})

        result.update(
            bytes_compared=compared,
            bytes_equal=equal,
            differ=differ_total,
            differ_first=differ,
            entry_missing_bytes=missing_entry,
            exit_missing_bytes=missing_exit,
            replay_unmapped_bytes=unmapped,
            entry_vs_exit_outside_write_set=outside_total,
            first_outside=outside,
        )
        if missing_entry or missing_exit or unmapped or compared != equal or outside_total:
            result["status"] = "DIFFERENT"
        else:
            result["status"] = "EXACT"
        return result


class PageWriteWatchpoint:
    """Lightweight VEH ``PAGE_READONLY`` + ``EFLAGS.TF`` single-step write watchpoint."""

    def __init__(
        self,
        watch_ranges: Sequence[Tuple[int, int]],
        labels: Optional[Sequence[str]] = None,
    ) -> None:
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise RuntimeError("PageWriteWatchpoint requires 64-bit Python on Windows")
        self.watch_ranges: List[Tuple[int, int, str]] = []
        for idx, (va, size) in enumerate(watch_ranges):
            if size <= 0:
                continue
            label = labels[idx] if labels is not None and idx < len(labels) else f"range_{idx}"
            self.watch_ranges.append((va, va + size, label))

        self.pages: Set[int] = set()
        for lo, hi, _ in self.watch_ranges:
            for pg in range(lo & ~0xFFF, ((hi - 1) & ~0xFFF) + PAGE_GRANULE, PAGE_GRANULE):
                self.pages.add(pg)

        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k.VirtualProtect.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self.k.VirtualProtect.restype = ctypes.c_int
        self.k.AddVectoredExceptionHandler.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
        self.k.AddVectoredExceptionHandler.restype = ctypes.c_void_p
        self.k.RemoveVectoredExceptionHandler.argtypes = [ctypes.c_void_p]
        self.k.RemoveVectoredExceptionHandler.restype = ctypes.c_uint32

        self.hits: List[Dict[str, Any]] = []
        self._orig_prot: Dict[int, int] = {}
        self._veh_cb: Any = None
        self._veh_handle: Any = None
        self._pending_page: Optional[int] = None

    def _protect_page(self, page: int, prot: int) -> int:
        old = ctypes.c_uint32()
        if not self.k.VirtualProtect(ctypes.c_void_p(page), PAGE_GRANULE, prot, ctypes.byref(old)):
            raise OSError(f"VirtualProtect(0x{page:X}, 0x{prot:X}) failed: {ctypes.get_last_error()}")
        return int(old.value)

    def start(self) -> None:
        if self._veh_handle is not None:
            return
        self._orig_prot.clear()
        for pg in sorted(self.pages):
            self._orig_prot[pg] = self._protect_page(pg, PAGE_READONLY)

        @ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
        def _veh(ptr: int) -> int:
            rec = int(ctypes.c_void_p.from_address(ptr).value)
            ctx = int(ctypes.c_void_p.from_address(ptr + 8).value)
            code_ = int(ctypes.c_uint32.from_address(rec).value)
            if code_ == STATUS_ACCESS_VIOLATION:
                kind = int(ctypes.c_uint64.from_address(rec + 32).value)
                addr = int(ctypes.c_uint64.from_address(rec + 40).value)
                page = addr & ~0xFFF
                if kind == 1 and page in self.pages:
                    rip = int(ctypes.c_uint64.from_address(ctx + CTX_RIP_OFF).value)
                    matched = [lbl for lo, hi, lbl in self.watch_ranges if lo <= addr < hi]
                    if matched:
                        self.hits.append({"rip": rip, "address": addr, "labels": matched})
                    self._protect_page(page, PAGE_EXECUTE_READWRITE)
                    ctypes.c_uint32.from_address(ctx + CTX_EFLAGS_OFF).value |= 0x100
                    self._pending_page = page
                    return EXCEPTION_CONTINUE_EXECUTION
            elif code_ == STATUS_SINGLE_STEP and self._pending_page is not None:
                page = self._pending_page
                self._pending_page = None
                self._protect_page(page, PAGE_READONLY)
                ctypes.c_uint32.from_address(ctx + CTX_EFLAGS_OFF).value &= ~0x100
                return EXCEPTION_CONTINUE_EXECUTION
            return EXCEPTION_CONTINUE_SEARCH

        self._veh_cb = _veh
        self._veh_handle = self.k.AddVectoredExceptionHandler(1, self._veh_cb)
        if not self._veh_handle:
            self.stop()
            raise RuntimeError("AddVectoredExceptionHandler failed")

    def stop(self) -> None:
        for pg, orig in sorted(self._orig_prot.items()):
            try:
                self._protect_page(pg, orig)
            except OSError:
                pass
        self._orig_prot.clear()
        self._pending_page = None
        if self._veh_handle is not None:
            self.k.RemoveVectoredExceptionHandler(self._veh_handle)
            self._veh_handle = None
            self._veh_cb = None

    def summary(self) -> Dict[str, Any]:
        by_label: Dict[str, Counter[str]] = {}
        for hit in self.hits:
            rip_hex = hex(hit["rip"])
            for lbl in hit["labels"]:
                by_label.setdefault(lbl, Counter())[rip_hex] += 1
        return {
            "total_hits": len(self.hits),
            "by_label": {lbl: dict(cnt.most_common()) for lbl, cnt in by_label.items()},
        }

    def __enter__(self) -> "PageWriteWatchpoint":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()
