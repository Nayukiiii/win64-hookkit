"""Read-only parser for Windows Full-Memory Minidump (.dmp) files.

Parses `Memory64ListStream` (stream type 9) and `MemoryInfoListStream` (stream type 16)
to translate virtual addresses into file offsets and read arbitrary process memory
slices without loading the dump into a debugger.
"""

from __future__ import annotations

import mmap
import struct
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, List, Optional

MDMP_SIGNATURE = b"MDMP"
MEMORY64_LIST_STREAM = 9
MEMORY_INFO_LIST_STREAM = 16


@dataclass(frozen=True)
class MemoryRange64:
    start_va: int
    size: int
    file_offset: int

    @property
    def end_va(self) -> int:
        return self.start_va + self.size


@dataclass(frozen=True)
class MemoryRegionInfo:
    base_address: int
    region_size: int
    state: int
    protect: int
    mem_type: int


class MinidumpReader:
    """Zero-copy reader over a Windows Full-Memory Minidump."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._fh: Optional[BinaryIO] = self.path.open("rb")
        self._mm: Optional[mmap.mmap] = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
        self.ranges: List[MemoryRange64] = []
        self.regions: List[MemoryRegionInfo] = []
        self._starts: List[int] = []
        self._parse_streams()

    def close(self) -> None:
        if self._mm is not None:
            self._mm.close()
            self._mm = None
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> "MinidumpReader":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _parse_streams(self) -> None:
        assert self._mm is not None
        buf = self._mm
        if len(buf) < 32 or buf[:4] != MDMP_SIGNATURE:
            raise ValueError(f"{self.path} is not a valid MDMP file")

        _version, num_streams, dir_rva = struct.unpack_from("<III", buf, 4)
        for i in range(num_streams):
            entry_off = dir_rva + i * 12
            stream_type, data_size, rva = struct.unpack_from("<III", buf, entry_off)
            if stream_type == MEMORY64_LIST_STREAM:
                self._parse_memory64_list(rva, data_size)
            elif stream_type == MEMORY_INFO_LIST_STREAM:
                self._parse_memory_info_list(rva, data_size)

    def _parse_memory64_list(self, rva: int, _data_size: int) -> None:
        assert self._mm is not None
        buf = self._mm
        num_ranges, base_rva = struct.unpack_from("<QQ", buf, rva)
        cur_file_off = base_rva
        parsed: List[MemoryRange64] = []
        for i in range(num_ranges):
            desc_off = rva + 16 + i * 16
            start_va, size = struct.unpack_from("<QQ", buf, desc_off)
            parsed.append(MemoryRange64(start_va=start_va, size=size, file_offset=cur_file_off))
            cur_file_off += size
        parsed.sort(key=lambda r: r.start_va)
        self.ranges = parsed
        self._starts = [r.start_va for r in parsed]

    def _parse_memory_info_list(self, rva: int, _data_size: int) -> None:
        assert self._mm is not None
        buf = self._mm
        size_of_header, size_of_entry, num_entries = struct.unpack_from("<IIQ", buf, rva)
        cur = rva + size_of_header
        for _ in range(num_entries):
            base_addr, _alloc_base, _alloc_prot, _pad1, region_size, state, protect, mem_type, _pad2 = (
                struct.unpack_from("<QQIIQIIII", buf, cur)
            )
            self.regions.append(
                MemoryRegionInfo(
                    base_address=base_addr,
                    region_size=region_size,
                    state=state,
                    protect=protect,
                    mem_type=mem_type,
                )
            )
            cur += size_of_entry

    def va_to_file_offset(self, va: int) -> Optional[int]:
        idx = bisect_right(self._starts, va) - 1
        if idx < 0:
            return None
        rng = self.ranges[idx]
        if rng.start_va <= va < rng.end_va:
            return rng.file_offset + (va - rng.start_va)
        return None

    def read_va(self, va: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("size must be non-negative")
        if size == 0:
            return b""
        assert self._mm is not None
        out = bytearray()
        cur_va = va
        remaining = size
        while remaining > 0:
            idx = bisect_right(self._starts, cur_va) - 1
            if idx < 0:
                raise KeyError(f"Virtual address 0x{cur_va:X} is not mapped in minidump")
            rng = self.ranges[idx]
            if not (rng.start_va <= cur_va < rng.end_va):
                raise KeyError(f"Virtual address 0x{cur_va:X} is not mapped in minidump")
            avail = min(remaining, rng.end_va - cur_va)
            file_off = rng.file_offset + (cur_va - rng.start_va)
            out.extend(self._mm[file_off : file_off + avail])
            cur_va += avail
            remaining -= avail
        return bytes(out)

    def read_u64(self, va: int) -> int:
        return struct.unpack("<Q", self.read_va(va, 8))[0]

    def read_u32(self, va: int) -> int:
        return struct.unpack("<I", self.read_va(va, 4))[0]
