"""Unit tests for Hookkit Python offline analysis & ntdll route tools."""

from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import dump_memtrace  # noqa: E402
import minidump  # noqa: E402
import ntdll_routes  # noqa: E402
import pe_xref  # noqa: E402


def _make_synthetic_mdmp() -> bytes:
    """Create a minimal valid 32-byte header MDMP with 2 Memory64 ranges."""
    header = struct.pack("<4sIIIQQ", b"MDMP", 0xA793, 1, 32, 0, 0)
    # 1 stream directory entry at offset 32 (12 bytes): type=9, size=48, rva=44
    stream_dir = struct.pack("<III", minidump.MEMORY64_LIST_STREAM, 48, 44)
    # Memory64List at offset 44: num_ranges=2, base_rva=92 (44 + 16 + 2*16)
    mem64_hdr = struct.pack("<QQ", 2, 92)
    desc1 = struct.pack("<QQ", 0x20001000, 16)
    desc2 = struct.pack("<QQ", 0x20005000, 8)
    payload1 = b"ABCDEFGHIJKLMNOP"
    payload2 = struct.pack("<Q", 0x1122334455667788)
    return header + stream_dir + mem64_hdr + desc1 + desc2 + payload1 + payload2


class HookkitToolsTest(unittest.TestCase):
    def test_minidump_reader_and_coalesce(self) -> None:
        raw = _make_synthetic_mdmp()
        with tempfile.TemporaryDirectory() as tmp:
            dmp_path = Path(tmp) / "sample.dmp"
            dmp_path.write_bytes(raw)
            with minidump.MinidumpReader(dmp_path) as reader:
                self.assertEqual(len(reader.ranges), 2)
                self.assertEqual(reader.read_va(0x20001004, 4), b"EFGH")
                self.assertEqual(reader.read_u64(0x20005000), 0x1122334455667788)
                self.assertIsNone(reader.va_to_file_offset(0x1000))

                mapper = dump_memtrace.InPlaceDumpMapper(reader)
                spans = mapper.plan_spans()
                self.assertEqual(len(spans), 1)
                self.assertEqual(spans[0].base_va, 0x20000000)
                self.assertEqual(spans[0].end_va, 0x20010000)

    def test_pe_xref_scanners(self) -> None:
        # Instruction at base 0x10000:
        # 48 8D 0D <disp32> (7 bytes, disp32 at offset 3..7, next RIP = 0x10007)
        # Target = 0x50020 -> disp32 = 0x50020 - 0x10007 = 0x40019
        code = b"\x48\x8D\x0D" + struct.pack("<i", 0x40019) + b"\xE8" + struct.pack("<i", 0x1FF4)
        rip_refs = pe_xref.scan_riprel_refs(code, 0x10000, 0x50000, 0x50100)
        self.assertEqual(len(rip_refs), 1)
        self.assertEqual(rip_refs[0].instr_va, 0x10003)
        self.assertEqual(rip_refs[0].target_va, 0x50020)

        branch_refs = pe_xref.scan_direct_branch_refs(code, 0x10000, 0x12000, 0x12010)
        self.assertEqual(len(branch_refs), 1)
        self.assertEqual(branch_refs[0].instr_va, 0x10007)
        self.assertEqual(branch_refs[0].target_va, 0x12000)
        self.assertEqual(branch_refs[0].kind, "call_rel32")

    def test_msvc_rtti_scanner(self) -> None:
        blob = b"\x00" * 32 + struct.pack("<QQ", 0x1000, 0) + b".?AVSampleSolver@@\x00" + b"\x00" * 16
        tds = pe_xref.scan_msvc_rtti_type_descriptors(blob, 0x400000)
        self.assertEqual(len(tds), 1)
        self.assertEqual(tds[0], (0x400020, ".?AVSampleSolver@@"))

    def test_ntdll_routes_on_host_ntdll(self) -> None:
        ntdll_path = Path(r"C:\Windows\System32\ntdll.dll")
        if not ntdll_path.exists():
            self.skipTest("Windows ntdll.dll not present")
        manifest = ntdll_routes.build_manifest(ntdll_path)
        self.assertEqual(len(manifest["routes"]), 6)
        self.assertEqual(ntdll_routes.compare_manifests(manifest, manifest), [])
        cpp_inc = ntdll_routes.render_cpp_inc(manifest)
        self.assertIn("NtSuspendThread", cpp_inc)


if __name__ == "__main__":
    unittest.main()
