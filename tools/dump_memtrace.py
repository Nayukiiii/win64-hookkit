"""In-place Minidump 64 KiB Virtual Address span planner and mapper.

Provides offline binary analysis utilities on Windows x64:
1. `coalesce_ranges_64k`: Aligns and merges `(start_va, size)` ranges onto Windows
   64 KiB (`0x10000`) allocation granularity boundaries.
2. `InPlaceDumpMapper`: Plans and maps non-conflicting 64 KiB spans from a
   `MinidumpReader` into the current process at their exact original virtual
   addresses via `VirtualAlloc` so extracted functions can execute against live
   pointer graphs (see `closed_replay.py` for VEH single-stepping and page-guard
   write watchpoints).
"""

from __future__ import annotations

import argparse
import ctypes
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

try:
    from minidump import MinidumpReader
except ImportError:  # pragma: no cover
    from .minidump import MinidumpReader

ALLOC_GRANULARITY = 0x10000
PAGE_SIZE = 0x1000

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
MEM_FREE = 0x10000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40


@dataclass(frozen=True)
class CoalescedSpan:
    base_va: int
    end_va: int

    @property
    def size(self) -> int:
        return self.end_va - self.base_va


def coalesce_ranges_64k(ranges: List[Tuple[int, int]]) -> List[CoalescedSpan]:
    """Align and merge (start_va, size) pairs onto 64 KiB allocation boundaries."""
    if not ranges:
        return []
    aligned: List[Tuple[int, int]] = []
    for start_va, size in ranges:
        if size <= 0:
            continue
        base = (start_va // ALLOC_GRANULARITY) * ALLOC_GRANULARITY
        end = ((start_va + size + ALLOC_GRANULARITY - 1) // ALLOC_GRANULARITY) * ALLOC_GRANULARITY
        aligned.append((base, end))
    aligned.sort(key=lambda pair: pair[0])

    merged: List[CoalescedSpan] = []
    cur_base, cur_end = aligned[0]
    for base, end in aligned[1:]:
        if base <= cur_end:
            cur_end = max(cur_end, end)
        else:
            merged.append(CoalescedSpan(cur_base, cur_end))
            cur_base, cur_end = base, end
    merged.append(CoalescedSpan(cur_base, cur_end))
    return merged


class InPlaceDumpMapper:
    """Maps non-conflicting 64 KiB spans from a Minidump into the current process."""

    def __init__(self, reader: MinidumpReader) -> None:
        self.reader = reader
        self.allocated_bases: List[int] = []

    def plan_spans(self) -> List[CoalescedSpan]:
        raw_pairs = [(r.start_va, r.size) for r in self.reader.ranges]
        return coalesce_ranges_64k(raw_pairs)

    def map_owned_spans(self, executable_span: Tuple[int, int] | None = None) -> List[CoalescedSpan]:
        kernel32 = ctypes.windll.kernel32
        kernel32.VirtualAlloc.restype = ctypes.c_void_p
        kernel32.VirtualAlloc.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]

        mapped: List[CoalescedSpan] = []
        for span in self.plan_spans():
            protect = PAGE_READWRITE
            if executable_span is not None:
                ex_lo, ex_hi = executable_span
                if span.base_va < ex_hi and ex_lo < span.end_va:
                    protect = PAGE_EXECUTE_READWRITE

            ptr = kernel32.VirtualAlloc(
                ctypes.c_void_p(span.base_va),
                span.size,
                MEM_RESERVE | MEM_COMMIT,
                protect,
            )
            if not ptr:
                continue
            self.allocated_bases.append(span.base_va)
            mapped.append(span)

        # Populate mapped spans from dump ranges
        for rng in self.reader.ranges:
            if any(s.base_va <= rng.start_va < s.end_va for s in mapped):
                data = self.reader.read_va(rng.start_va, rng.size)
                ctypes.memmove(ctypes.c_void_p(rng.start_va), data, len(data))

        return mapped

    def release_all(self) -> None:
        if not self.allocated_bases:
            return
        kernel32 = ctypes.windll.kernel32
        kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
        for base in self.allocated_bases:
            kernel32.VirtualFree(ctypes.c_void_p(base), 0, MEM_RELEASE)
        self.allocated_bases.clear()


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect and plan 64 KiB in-place virtual address mappings for a Minidump."
    )
    parser.add_argument("--dump", type=Path, required=True, help="Path to full-memory .dmp file")
    parser.add_argument("--json-out", type=Path, help="Optional JSON summary path")
    args = parser.parse_args(argv)

    with MinidumpReader(args.dump) as reader:
        mapper = InPlaceDumpMapper(reader)
        spans = mapper.plan_spans()
        summary = {
            "dump": str(args.dump),
            "raw_range_count": len(reader.ranges),
            "coalesced_64k_span_count": len(spans),
            "total_coalesced_bytes": sum(s.size for s in spans),
            "spans": [
                {"base_va": f"0x{s.base_va:X}", "end_va": f"0x{s.end_va:X}", "size": s.size}
                for s in spans[:64]
            ],
        }
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        else:
            print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
