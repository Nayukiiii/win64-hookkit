"""Static PE32+ x64 reference scanner: RIP-relative data xrefs, direct call/jump xrefs, and MSVC RTTI TypeDescriptors.

Operates on raw PE32+ binaries or memory slices without requiring IDA/Ghidra:
- `scan_riprel_refs`: Vectorized (NumPy-accelerated with pure-Python fallback)
  scanner for 32-bit `RIP + disp32` displacements targeting `[target_lo, target_hi)`.
- `scan_direct_branch_refs`: Scans `E8 rel32` (`CALL`) and `E9 rel32` (`JMP`) instructions
  targeting a function or code range.
- `scan_msvc_rtti_type_descriptors`: Scans an image buffer for 64-bit MSVC RTTI
  `TypeDescriptor` structures (`.?AV` / `.?AU` mangled class names) and computes their
  virtual addresses.
"""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence, Tuple

try:
    import numpy as np
except ImportError:  # pragma: no cover
    np = None  # type: ignore[assignment]


@dataclass(frozen=True)
class CodeRef:
    instr_va: int
    target_va: int
    kind: str


def scan_riprel_refs(
    code_bytes: bytes,
    code_base_va: int,
    target_lo: int,
    target_hi: int,
) -> List[CodeRef]:
    """Find all candidate `RIP + disp32` references into `[target_lo, target_hi)`.

    For any 4-byte displacement at offset `i` inside `code_bytes`, the next instruction
    pointer is `code_base_va + i + 4`, so `target = code_base_va + i + 4 + disp32`.
    """
    n = len(code_bytes)
    if n < 4 or target_hi <= target_lo:
        return []

    refs: List[CodeRef] = []
    if np is not None:
        arr = np.frombuffer(code_bytes, dtype=np.uint8)
        windows = np.lib.stride_tricks.sliding_window_view(arr, 4)
        disp = windows.view(np.int32).reshape(-1).astype(np.int64)
        idx = np.arange(len(disp), dtype=np.int64)
        targets = (code_base_va + 4) + idx + disp
        hits = np.nonzero((targets >= target_lo) & (targets < target_hi))[0]
        for i in hits.tolist():
            t_va = int(targets[i])
            refs.append(CodeRef(instr_va=code_base_va + i, target_va=t_va, kind="riprel32"))
        return refs

    for i in range(n - 3):
        disp = struct.unpack_from("<i", code_bytes, i)[0]
        t_va = code_base_va + i + 4 + disp
        if target_lo <= t_va < target_hi:
            refs.append(CodeRef(instr_va=code_base_va + i, target_va=t_va, kind="riprel32"))
    return refs


def scan_direct_branch_refs(
    code_bytes: bytes,
    code_base_va: int,
    target_lo: int,
    target_hi: int,
) -> List[CodeRef]:
    """Find `E8 rel32` (CALL) and `E9 rel32` (JMP) instructions targeting `[target_lo, target_hi)`."""
    n = len(code_bytes)
    if n < 5 or target_hi <= target_lo:
        return []

    refs: List[CodeRef] = []
    for i in range(n - 4):
        op = code_bytes[i]
        if op not in (0xE8, 0xE9):
            continue
        disp = struct.unpack_from("<i", code_bytes, i + 1)[0]
        t_va = code_base_va + i + 5 + disp
        if target_lo <= t_va < target_hi:
            kind = "call_rel32" if op == 0xE8 else "jmp_rel32"
            refs.append(CodeRef(instr_va=code_base_va + i, target_va=t_va, kind=kind))
    return refs


def scan_msvc_rtti_type_descriptors(
    image_bytes: bytes,
    image_base_va: int,
) -> List[Tuple[int, str]]:
    """Scan an image buffer for MSVC `.?AV` / `.?AU` RTTI TypeDescriptor strings.

    In 64-bit MSVC, `TypeDescriptor` has layout:
      +0x00: `const void* pVFTable` (8 bytes)
      +0x08: `void* spare` (8 bytes, usually 0)
      +0x10: `char name[]` starting with `.?AV` or `.?AU`
    """
    results: List[Tuple[int, str]] = []
    for prefix in (b".?AV", b".?AU"):
        start = 0
        while True:
            pos = image_bytes.find(prefix, start)
            if pos == -1:
                break
            start = pos + 1
            if pos < 0x10:
                continue
            end = image_bytes.find(b"\x00", pos, pos + 256)
            if end == -1:
                continue
            name = image_bytes[pos:end].decode("ascii", errors="replace")
            td_va = image_base_va + (pos - 0x10)
            results.append((td_va, name))
    results.sort(key=lambda item: item[0])
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan PE32+ code/data slices for xrefs and MSVC RTTI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_rip = sub.add_parser("riprel", help="Scan binary blob for RIP+disp32 references into a VA range")
    p_rip.add_argument("--bin", type=Path, required=True, help="Raw code section file")
    p_rip.add_argument("--base-va", type=lambda s: int(s, 0), required=True, help="Base VA of code blob")
    p_rip.add_argument("--target-lo", type=lambda s: int(s, 0), required=True, help="Target range low VA")
    p_rip.add_argument("--target-hi", type=lambda s: int(s, 0), required=True, help="Target range high VA")

    p_rtti = sub.add_parser("rtti", help="Scan binary blob for MSVC x64 TypeDescriptors")
    p_rtti.add_argument("--bin", type=Path, required=True, help="Raw image file")
    p_rtti.add_argument("--base-va", type=lambda s: int(s, 0), default=0, help="Base VA of image")

    args = parser.parse_args(argv)
    if args.cmd == "riprel":
        raw = args.bin.read_bytes()
        refs = scan_riprel_refs(raw, args.base_va, args.target_lo, args.target_hi)
        print(
            json.dumps(
                [{"instr_va": f"0x{r.instr_va:X}", "target_va": f"0x{r.target_va:X}"} for r in refs],
                indent=2,
            )
        )
        return 0
    if args.cmd == "rtti":
        raw = args.bin.read_bytes()
        tds = scan_msvc_rtti_type_descriptors(raw, args.base_va)
        print(json.dumps([{"td_va": f"0x{va:X}", "name": name} for va, name in tds], indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
