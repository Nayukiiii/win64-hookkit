"""Unit tests for closed_replay, pe_cfg_unwind, health_observer, detours_prepare_only, and hook_audit."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import closed_replay  # noqa: E402
import detours_prepare_only  # noqa: E402
import health_observer  # noqa: E402
import hook_audit  # noqa: E402
import minidump  # noqa: E402
import pe_cfg_unwind  # noqa: E402


def _reserve_free_64k_base(span: int = 0x30000) -> tuple[Any, int]:
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
    k.VirtualAlloc.restype = ctypes.c_void_p
    k.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
    k.VirtualFree.restype = ctypes.c_int
    ptr = k.VirtualAlloc(None, span, closed_replay.MEM_RESERVE, closed_replay.PAGE_NOACCESS)
    if not ptr:
        raise RuntimeError("VirtualAlloc probe failed")
    return k, int(ptr)


def _build_synthetic_pe32_plus(image_base: int = 0x180000000) -> bytes:
    """Construct a valid 2-section (.text @ 0x1000, .rdata @ 0x2000) PE32+ image."""
    hdr_size = 0x400
    text_rva = 0x1000
    text_raw_off = 0x400
    text_size = 0x1000
    rdata_rva = 0x2000
    rdata_raw_off = 0x1400
    rdata_size = 0x1000
    total_size = 0x2400

    buf = bytearray(total_size)
    # Fill .text with 0xCC (1-byte int3) so linear disassembly stays aligned at function starts
    buf[text_raw_off : text_raw_off + text_size] = b"\xCC" * text_size

    # .text layout:
    # 0x1000: push rdi; mov rdi, rcx; mov rax, rdx; mov ecx, 8; rep stosb; pop rdi; mov eax, 42; ret
    fn_stos = bytes.fromhex("57 48 89 CF 48 89 D0 B9 08 00 00 00 F3 AA 5F B8 2A 00 00 00 C3")
    buf[text_raw_off : text_raw_off + len(fn_stos)] = fn_stos

    # 0x1020: mov rax, qword ptr [rcx]; ret  (used for OOB read abort test)
    fn_oob = bytes.fromhex("48 8B 01 C3")
    buf[text_raw_off + 0x20 : text_raw_off + 0x20 + len(fn_oob)] = fn_oob

    # 0x1030: mov rax, qword ptr [rcx]; mov qword ptr [rdx], rax; ret
    fn_copy = bytes.fromhex("48 8B 01 48 89 02 C3")
    buf[text_raw_off + 0x30 : text_raw_off + 0x30 + len(fn_copy)] = fn_copy

    # 0x1040..0x1067: pointer-chain writers (split across two contiguous .pdata entries 0x1040..0x1050, 0x1050..0x1067)
    fn_chain = bytes.fromhex(
        "48 8B 41 08"  # 0x1040: mov rax, [rcx + 0x08]
        "48 8B 50 48"  # 0x1044: mov rdx, [rax + 0x48]
        "C7 02 01 00 00 00"  # 0x1048: mov dword ptr [rdx], 1
        "90 90"  # 0x104E: nop; nop
        "C7 42 10 02 00 00 00"  # 0x1050: mov dword ptr [rdx + 0x10], 2
        "C7 44 24 20 03 00 00 00"  # 0x1057: mov dword ptr [rsp + 0x20], 3
        "C7 43 10 04 00 00 00"  # 0x105F: mov dword ptr [rbx + 0x10], 4
        "C3"  # 0x1066: ret
    )
    buf[text_raw_off + 0x40 : text_raw_off + 0x40 + len(fn_chain)] = fn_chain

    # 0x1070: jmp 0x1040 (thunk_rel32: 0x1040 - 0x1075 = -0x35)
    buf[text_raw_off + 0x70 : text_raw_off + 0x75] = b"\xE9" + struct.pack("<i", -0x35)

    # 0x1080: mov eax, edx; ret (leaf function without .pdata)
    buf[text_raw_off + 0x80 : text_raw_off + 0x83] = bytes.fromhex("89 D0 C3")

    # 0x1090: direct call 0x1000, IAT call [0x2230], CFG call [0x2390], CFG mov r9 [0x2390]; call r9, vtable [rax+8], ret
    # 0x1090: E8 rel32 -> 0x1000 (disp = 0x1000 - 0x1095 = -0x95)
    c_off = text_raw_off + 0x90
    buf[c_off : c_off + 5] = b"\xE8" + struct.pack("<i", -0x95)
    # 0x1095: FF 15 disp32 -> 0x2230 (next RIP = 0x109B, disp = 0x2230 - 0x109B = 0x1195)
    buf[c_off + 5 : c_off + 11] = b"\xFF\x15" + struct.pack("<i", 0x1195)
    # 0x109B: FF 15 disp32 -> 0x2390 (next RIP = 0x10A1, disp = 0x2390 - 0x10A1 = 0x12EF)
    buf[c_off + 11 : c_off + 17] = b"\xFF\x15" + struct.pack("<i", 0x12EF)
    # 0x10A1: 4C 8B 0D disp32 (mov r9, [0x2390]; next RIP = 0x10A8, disp = 0x2390 - 0x10A8 = 0x12E8)
    buf[c_off + 17 : c_off + 24] = b"\x4C\x8B\x0D" + struct.pack("<i", 0x12E8)
    # 0x10A8: 41 FF D1 (call r9)
    buf[c_off + 24 : c_off + 27] = b"\x41\xFF\xD1"
    # 0x10AB: FF 50 08 (call qword ptr [rax + 8])
    buf[c_off + 27 : c_off + 30] = b"\xFF\x50\x08"
    # 0x10AE: C3 (ret)
    buf[c_off + 30] = 0xC3

    # 0x10C0: exception handler stub (xor eax, eax; ret)
    buf[text_raw_off + 0xC0 : text_raw_off + 0xC3] = bytes.fromhex("31 C0 C3")

    # .rdata layout (rva 0x2000 = file 0x1400):
    def _w(rva: int, data: bytes) -> None:
        pos = rdata_raw_off + (rva - rdata_rva)
        buf[pos : pos + len(data)] = data

    # Export Directory @ 0x2000 (size 0x90)
    # 2 exports: "RunHook" -> 0x1000, "hookkit_health_block" -> 0x2500
    exp_rva = 0x2000
    _w(
        exp_rva,
        struct.pack(
            "<IIHHIIIIIII",
            0, 0, 0, 0,
            0x2050,  # Name RVA
            1,       # OrdinalBase
            2,       # NumberOfFunctions
            2,       # NumberOfNames
            0x2028,  # AddressOfFunctions
            0x2030,  # AddressOfNames
            0x2038,  # AddressOfNameOrdinals
        ),
    )
    _w(0x2028, struct.pack("<II", 0x1000, 0x2500))
    _w(0x2030, struct.pack("<II", 0x2060, 0x2068))
    _w(0x2038, struct.pack("<HH", 0, 1))
    _w(0x2050, b"sample.dll\x00")
    _w(0x2060, b"RunHook\x00")
    _w(0x2068, b"hookkit_health_block\x00")

    # Import Directory @ 0x2200 (2 descriptors = 40 bytes)
    _w(0x2200, struct.pack("<IIIII", 0x2240, 0, 0, 0x2250, 0x2230))
    _w(0x2214, b"\x00" * 20)
    _w(0x2230, struct.pack("<Q", 0x2260))  # IAT slot 0x2230
    _w(0x2240, struct.pack("<Q", 0x2260))  # ILT
    _w(0x2250, b"kernel32.dll\x00")
    _w(0x2260, struct.pack("<H", 0) + b"GetCurrentProcessId\x00")

    # .pdata @ 0x2280 (4 entries = 48 bytes)
    pdata_entries = [
        (0x1000, 0x1015, 0x22C0),  # has EHANDLER -> 0x10C0
        (0x1040, 0x1050, 0x22D0),  # primary part
        (0x1050, 0x1067, 0x22D8),  # chained to 0x1040..0x1050
        (0x1090, 0x10AF, 0x22C0),
    ]
    for idx, (b_rva, e_rva, u_rva) in enumerate(pdata_entries):
        _w(0x2280 + idx * 12, struct.pack("<III", b_rva, e_rva, u_rva))

    # UNWIND_INFO @ 0x22C0: version=1, flags=UNW_FLAG_EHANDLER (1) => byte0 = 0x09, handler=0x10C0
    _w(0x22C0, struct.pack("<BBBBII", 0x09, 0x00, 0x00, 0x00, 0x10C0, 0x00000000))
    # UNWIND_INFO @ 0x22D0: version=1, flags=0
    _w(0x22D0, struct.pack("<BBBB", 0x01, 0x00, 0x00, 0x00))
    # UNWIND_INFO @ 0x22D8: version=1, flags=UNW_FLAG_CHAININFO (4) => byte0 = 0x21, chained to (0x1040, 0x1050, 0x22D0)
    _w(0x22D8, struct.pack("<BBBBIII", 0x21, 0x00, 0x00, 0x00, 0x1040, 0x1050, 0x22D0))

    # LoadConfig @ 0x2300 (size 152 bytes)
    lc = bytearray(152)
    struct.pack_into("<I", lc, 0, 152)
    struct.pack_into("<QQ", lc, 112, image_base + 0x2388, image_base + 0x2390)  # check, dispatch
    struct.pack_into("<I", lc, 144, 0x00000500)  # GuardFlags
    _w(0x2300, bytes(lc))
    _w(0x2388, struct.pack("<Q", image_base + 0x10C0))
    _w(0x2390, struct.pack("<Q", image_base + 0x10C0))

    # SeqlockHealthBlock @ 0x2500 (64 bytes, valid published seq=4)
    _w(
        0x2500,
        health_observer.HEALTH_BLOCK_STRUCT.pack(
            4, health_observer.HEALTH_MAGIC, 4, 2, 0, 1000, 0, 7, 7
        ),
    )

    # Headers: DOS + PE + COFF + Optional PE32+ + 2 sections
    buf[0:2] = b"MZ"
    pe_off = 0x80
    struct.pack_into("<I", buf, 0x3C, pe_off)
    buf[pe_off : pe_off + 4] = b"PE\x00\x00"
    coff = pe_off + 4
    struct.pack_into("<HHIIIHH", buf, coff, 0x8664, 2, 0, 0, 0, 240, 0x2022)
    opt = coff + 20
    struct.pack_into("<HBB", buf, opt, 0x20B, 14, 0)
    struct.pack_into("<I", buf, opt + 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<Q", buf, opt + 24, image_base)
    struct.pack_into("<II", buf, opt + 32, 0x1000, 0x200)
    struct.pack_into("<IIII", buf, opt + 56, 0x3000, hdr_size, 0, 2)
    struct.pack_into("<I", buf, opt + 108, 16)
    # Data directories: 0=Export, 1=Import, 3=Exception(.pdata), 10=LoadConfig
    struct.pack_into("<II", buf, opt + 112 + 0 * 8, 0x2000, 0x90)
    struct.pack_into("<II", buf, opt + 112 + 1 * 8, 0x2200, 40)
    struct.pack_into("<II", buf, opt + 112 + 3 * 8, 0x2280, 48)
    struct.pack_into("<II", buf, opt + 112 + 10 * 8, 0x2300, 152)

    sec_off = opt + 240
    buf[sec_off : sec_off + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", buf, sec_off + 8, text_size, text_rva, text_size, text_raw_off)
    struct.pack_into("<I", buf, sec_off + 36, 0x60000020)

    sec2 = sec_off + 40
    buf[sec2 : sec2 + 8] = b".rdata\x00\x00"
    struct.pack_into("<IIII", buf, sec2 + 8, rdata_size, rdata_rva, rdata_size, rdata_raw_off)
    struct.pack_into("<I", buf, sec2 + 36, 0x40000040)

    return bytes(buf)


class ClosedReplayUnitTest(unittest.TestCase):
    def test_span_and_memory_snapshot(self) -> None:
        sp = closed_replay.Span([(10, 20), (20, 30), (50, 60), (55, 65)])
        self.assertEqual(sp.iv, [(10, 30), (50, 65)])
        self.assertTrue(sp.contains(10, 20))
        self.assertTrue(sp.contains(52, 13))
        self.assertFalse(sp.contains(28, 5))
        self.assertFalse(sp.contains(40, 2))
        self.assertTrue(sp.contains(0, 0))

        snap = closed_replay.MemorySnapshot([
            (0x1000, b"ABCD"),
            (0x1004, b"EFGH"),
            (0x1006, b"GHXX"),
            (0x2000, struct.pack("<IQ", 0x11223344, 0xAABBCCDDEEFF0011)),
        ])
        self.assertEqual(snap.read(0x1000, 10), b"ABCDEFGHXX")
        self.assertIsNone(snap.read(0x1008, 10))
        self.assertEqual(snap.read_u32(0x2000), 0x11223344)
        self.assertEqual(snap.read_u64(0x2004), 0xAABBCCDDEEFF0011)

    def test_operand_access_and_opcode_classifier(self) -> None:
        self.assertEqual(closed_replay.operand_access("cmp", 0, 0), 1)
        self.assertEqual(closed_replay.operand_access("ucomiss", 0, 0), 1)
        self.assertEqual(closed_replay.operand_access("mov", 0, 0), 2)
        self.assertEqual(closed_replay.operand_access("mov", 1, 0), 1)
        self.assertEqual(closed_replay.operand_access("add", 0, 0), 3)
        self.assertEqual(closed_replay.operand_access("xchg", 0, 0), 3)

        self.assertEqual(closed_replay.classify_x64_opcode(b"\xA4"), ("string", ("movs", 1, False, ())))
        self.assertEqual(closed_replay.classify_x64_opcode(b"\x66\xA5"), ("string", ("movs", 2, False, (0x66,))))
        self.assertEqual(closed_replay.classify_x64_opcode(b"\xA5"), ("string", ("movs", 4, False, ())))
        self.assertEqual(closed_replay.classify_x64_opcode(b"\x48\xA5"), ("string", ("movs", 8, False, ())))
        self.assertEqual(closed_replay.classify_x64_opcode(b"\xF3\x48\xAB"), ("string", ("stos", 8, True, (0xF3,))))
        self.assertEqual(closed_replay.classify_x64_opcode(b"\xF2\x0F\x10\xC1"), ("plain", None))  # SSE2 movsd
        self.assertEqual(closed_replay.classify_x64_opcode(b"\xF2\x0F\xC2\xC1\x00"), ("plain", None))  # SSE2 cmpsd
        self.assertEqual(closed_replay.classify_x64_opcode(b"\xA6"), ("implicit", 0xA6))

    def test_string_op_ranges_and_bounds(self) -> None:
        reads, writes = closed_replay.string_op_ranges("movs", 4, 3, 0x1000, 0x2000, df=0)
        self.assertEqual(reads, [(0x1000, 12)])
        self.assertEqual(writes, [(0x2000, 12)])

        reads_df, writes_df = closed_replay.string_op_ranges("stos", 8, 3, 0, 0x2010, df=1)
        self.assertEqual(reads_df, [])
        self.assertEqual(writes_df, [(0x2000, 24)])

        rspan = closed_replay.Span([(0x1000, 0x1010)])
        wspan = closed_replay.Span([(0x2000, 0x2010)])
        closed_replay.check_string_access(reads, writes, rspan, wspan)
        with self.assertRaises(closed_replay.ReplayFailure):
            closed_replay.check_string_access([(0x1000, 32)], writes, rspan, wspan)

    @unittest.skipUnless(os.name == "nt" and ctypes.sizeof(ctypes.c_void_p) == 8, "Windows x64 required")
    @unittest.skipUnless(closed_replay.capstone is not None, "capstone not installed")
    def test_live_closed_replay_and_watchpoint(self) -> None:
        k, base = _reserve_free_64k_base(0x30000)
        pe_bytes = _build_synthetic_pe32_plus(base)
        k.VirtualFree(ctypes.c_void_p(base), 0, closed_replay.MEM_RELEASE)

        with closed_replay.PeSandboxEngine(pe_bytes) as engine:
            # Reserve a data granule outside the PE image for entry/exit buffers
            data_buf_addr = base + 0x20000
            ptr = engine.k.VirtualAlloc(
                ctypes.c_void_p(data_buf_addr),
                0x10000,
                closed_replay.MEM_COMMIT_RESERVE,
                closed_replay.PAGE_READWRITE,
            )
            self.assertEqual(ptr, data_buf_addr)
            engine.granules[data_buf_addr] = True

            # 1) Exact replay with rep stosb
            entry_blocks = [(data_buf_addr, b"\x00" * 16)]
            exit_mem = closed_replay.MemorySnapshot([(data_buf_addr, b"\x5A" * 8 + b"\x00" * 8)])
            replayer = closed_replay.ClosedWorldReplayer(
                engine,
                entry_va=base + 0x1000,
                entry_blocks=entry_blocks,
                exit_memory=exit_mem,
            )
            st = replayer.run(data_buf_addr, 0x5A, restype=ctypes.c_uint64)
            ev = replayer.evaluate()
            self.assertIsNone(st["failure"])
            self.assertEqual(st["return_value"], 42)
            self.assertEqual(ev["status"], "EXACT")
            self.assertGreaterEqual(ev["string_instructions"]["executions"], 1)
            self.assertEqual(ev["write_set"]["bytes"], 8)

            # 2) Pluggable rip_hook overriding mov eax, 42 -> 99
            def _override_rax(rp: closed_replay.ClosedWorldReplayer, ctx: int, rip: int) -> bool:
                rp.set_reg(ctx, "rax", 99)
                rp.set_reg(ctx, "rip", rip + 5)
                return True

            hooked = closed_replay.ClosedWorldReplayer(
                engine,
                entry_va=base + 0x1000,
                entry_blocks=entry_blocks,
                exit_memory=exit_mem,
                rip_hooks={base + 0x100F: _override_rax},
            )
            st_hook = hooked.run(data_buf_addr, 0x5A, restype=ctypes.c_uint64)
            self.assertEqual(st_hook["return_value"], 99)
            self.assertEqual(st_hook["hooks_emulated"], 1)
            self.assertEqual(hooked.evaluate()["status"], "EXACT")

            # 3) Safe abort on unrecorded memory read without crashing process
            oob_replayer = closed_replay.ClosedWorldReplayer(
                engine,
                entry_va=base + 0x1020,
                entry_blocks=entry_blocks,
            )
            st_oob = oob_replayer.run(0x7FFF00001000)
            self.assertIsNotNone(st_oob["failure"])
            self.assertEqual(st_oob["failure"]["kind"], "unrecorded memory read")
            self.assertTrue(st_oob["aborted"])

            # 4) PageWriteWatchpoint logging exact writer RIP
            in_addr = data_buf_addr + 0x100
            out_addr = data_buf_addr + 0x200
            ctypes.memmove(ctypes.c_void_p(in_addr), struct.pack("<Q", 0xCAFEBABEDEADBEEF), 8)
            ctypes.memmove(ctypes.c_void_p(out_addr), b"\x00" * 16, 16)
            copy_fn = ctypes.WINFUNCTYPE(None, ctypes.c_uint64, ctypes.c_uint64)(base + 0x1030)
            with closed_replay.PageWriteWatchpoint([(out_addr, 8)], labels=["target_qword"]) as wp:
                copy_fn(in_addr, out_addr)
            summ = wp.summary()
            self.assertEqual(summ["total_hits"], 1)
            self.assertIn(hex(base + 0x1033), summ["by_label"]["target_qword"])
            self.assertEqual(struct.unpack("<Q", ctypes.string_at(out_addr, 8))[0], 0xCAFEBABEDEADBEEF)


class PeCfgUnwindUnitTest(unittest.TestCase):
    @unittest.skipUnless(pe_cfg_unwind.capstone is not None, "capstone not installed")
    def test_synthetic_pe_cfg_and_unwind(self) -> None:
        pe_bytes = _build_synthetic_pe32_plus(0x180000000)
        report = pe_cfg_unwind.audit_pe_cfg_unwind(pe_bytes, roots=["RunHook"])
        summary = report["summary"]
        self.assertEqual(summary["runtime_functions"], 4)
        self.assertEqual(summary["chained_runtime_functions"], 1)
        self.assertEqual(summary["exception_handlers"], 1)
        self.assertEqual(summary["direct_calls"], 1)
        self.assertEqual(summary["iat_calls"], 1)
        self.assertEqual(summary["indirect_calls"], 3)

        classes = summary["indirect_call_classes"]
        self.assertEqual(classes.get("guard_dispatch_slot"), 1)
        self.assertEqual(classes.get("guard_dispatch_loaded_into_r9"), 1)
        self.assertEqual(classes.get("vtable_offset_call"), 1)

        self.assertIn("RunHook", report["root_flows"])
        self.assertEqual(report["load_config"]["dispatch_slot_rva"], 0x2390)
        self.assertEqual(report["load_config"]["check_slot_rva"], 0x2388)

    @unittest.skipUnless(pe_cfg_unwind.capstone is not None, "capstone not installed")
    def test_host_kernel32_cfg_unwind(self) -> None:
        k32 = Path(r"C:\Windows\System32\kernel32.dll")
        if not k32.exists():
            self.skipTest("Windows kernel32.dll not present")
        report = pe_cfg_unwind.audit_pe_cfg_unwind(k32.read_bytes(), max_instructions=25000)
        self.assertGreater(report["summary"]["runtime_functions"], 100)
        self.assertGreater(report["summary"]["unique_unwind_records"], 50)
        self.assertIsNotNone(report["load_config"])


class HealthObserverUnitTest(unittest.TestCase):
    def test_seqlock_decode_and_torn_retry(self) -> None:
        good = health_observer.HEALTH_BLOCK_STRUCT.pack(
            6, health_observer.HEALTH_MAGIC, 6, 3, 6, 100, 200, 12, 11
        )
        decoded = health_observer.decode_health_block(good)
        self.assertEqual(decoded["seq"], 6)
        self.assertEqual(decoded["state"], 3)
        self.assertEqual(decoded["last_failure_name"], "RipInsideHazardWindow")
        self.assertEqual(decoded["callback_enter_count"], 12)

        # Odd sequence rejected
        odd = health_observer.HEALTH_BLOCK_STRUCT.pack(
            7, health_observer.HEALTH_MAGIC, 6, 3, 0, 100, 0, 12, 11
        )
        with self.assertRaises(ValueError):
            health_observer.decode_health_block(odd)

        # Torn read retry: 1) odd seq, 2) outer != trailing read, 3) consistent
        reads = iter([
            odd,
            good,
            struct.pack("<Q", 8),  # trailing mismatch vs s1=6
            good,
            struct.pack("<Q", 6),  # consistent
        ])
        res = health_observer.read_seqlock_consistent(lambda _addr, _sz: next(reads), 0x1000)
        self.assertEqual(res["seq"], 6)

    def test_export_resolution_and_observe_watchdog(self) -> None:
        pe_bytes = _build_synthetic_pe32_plus()
        self.assertEqual(health_observer.resolve_pe_export_rva(pe_bytes, "hookkit_health_block"), 0x2500)

        # Stale watchdog test using simulated monotonic clock
        t = [0.0]

        def _mono() -> float:
            return t[0]

        def _sleep(dt: float) -> None:
            t[0] += dt

        rep = health_observer.observe_health(
            lambda: {"seq": 4, "state": 1, "last_failure_reason": 0, "callback_enter_count": 1, "callback_exit_count": 1},
            duration_s=10.0,
            poll_interval_s=0.5,
            stale_timeout_s=2.0,
            sleep_fn=_sleep,
            monotonic_fn=_mono,
        )
        self.assertEqual(rep["observer_status"], "stale")
        self.assertFalse(rep["target_modified"])
        self.assertEqual(len(rep["events"]), 1)

    @unittest.skipUnless(os.name == "nt" and ctypes.sizeof(ctypes.c_void_p) == 8, "Windows x64 required")
    def test_birth_gated_discovery_and_thread_count(self) -> None:
        exe = Path(sys.executable).resolve()
        pids = health_observer.find_processes_born_after(exe, 0)
        self.assertIn(os.getpid(), pids)
        far_future = 0x7FFFFFFFFFFFFFFF
        self.assertEqual(health_observer.find_processes_born_after(exe, far_future), [])
        tc = health_observer.get_process_thread_count(os.getpid())
        self.assertIsNotNone(tc)
        self.assertGreaterEqual(tc, 1)


class DetoursPrepareOnlyUnitTest(unittest.TestCase):
    def test_transform_and_directory_driver(self) -> None:
        sample_cpp = (
            '#include <windows.h>\r\n'
            '#include "detours.h"\r\n'
            'static void detour_free_trampoline(PDETOUR_TRAMPOLINE p) { VirtualFree(p, 0, MEM_RELEASE); }\r\n'
            'static BOOL detour_is_region_empty(PVOID p) { return TRUE; }\r\n'
            'LONG WINAPI DetourTransactionBegin() { return NO_ERROR; }\r\n'
            'LONG WINAPI DetourTransactionAbort() { return NO_ERROR; }\r\n'
            'LONG WINAPI DetourTransactionCommit() {\r\n'
            '    SuspendThread(h); GetThreadContext(h, &c); SetThreadContext(h, &c); ResumeThread(h);\r\n'
            '    return NO_ERROR;\r\n'
            '}\r\n'
            'static BYTE detour_align_from_trampoline(BYTE x) { return x; }\r\n'
            'LONG WINAPI DetourTransactionCommitEx(PVOID** f) { return NO_ERROR; }\r\n'
            'LONG WINAPI DetourUpdateThread(HANDLE h) { SuspendThread(h); return NO_ERROR; }\r\n'
            '///////////////////////////////////////////////////////////// Transacted APIs.\r\n'
            'LONG WINAPI DetourAttach(PVOID* pp, PVOID d) { return NO_ERROR; }\r\n'
        )
        inc_cpp = "void hookkit_helper_stub() {}\n"
        out = detours_prepare_only.transform_detours_source(sample_cpp, inc_cpp)
        self.assertIn('#include "patch_core.h"', out)
        self.assertIn("static LONG WINAPI HookkitStockPrepareBegin()", out)
        self.assertIn("hookkit_helper_stub", out)
        for forbidden in detours_prepare_only.FORBIDDEN_THREAD_APIS:
            self.assertNotIn(forbidden, out)

        with self.assertRaises(ValueError):
            detours_prepare_only.transform_detours_source(sample_cpp, "void bad() { SuspendThread(0); }")

        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src"
            out_dir = Path(tmp) / "out"
            inc_file = Path(tmp) / "patch_core.inc"
            src_dir.mkdir()
            (src_dir / "detours.cpp").write_text(sample_cpp, encoding="utf-8")
            (src_dir / "detours.h").write_text("// header\n", encoding="utf-8")
            inc_file.write_text(inc_cpp, encoding="utf-8")

            manifest = detours_prepare_only.generate_prepare_only_detours(src_dir, out_dir, inc_file)
            self.assertTrue(manifest["library_thread_control_removed"])
            self.assertTrue((out_dir / "manifest.json").is_file())
            self.assertTrue((out_dir / "detours.h").is_file())
            parsed = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(
                parsed["generated"]["detours.cpp"]["sha256"],
                hashlib.sha256((out_dir / "detours.cpp").read_bytes()).hexdigest().upper(),
            )


class HookAuditUnitTest(unittest.TestCase):
    def test_dll_contract_and_site_classification(self) -> None:
        pe_bytes = _build_synthetic_pe32_plus(0x180000000)

        ok_rep = hook_audit.audit_dll_contract(
            pe_bytes,
            expected_exports=["RunHook", "hookkit_health_block"],
            forbidden_imports=["user32.dll"],
        )
        self.assertTrue(ok_rep["ok"])

        bad_exp = hook_audit.audit_dll_contract(pe_bytes, expected_exports=["RunHook"], exact_exports=True)
        self.assertFalse(bad_exp["ok"])
        self.assertEqual(bad_exp["unexpected_exports"], ["hookkit_health_block"])

        bad_imp = hook_audit.audit_dll_contract(pe_bytes, forbidden_imports=["KERNEL32.dll"])
        self.assertFalse(bad_imp["ok"])
        self.assertEqual(bad_imp["forbidden_imports_found"], ["kernel32.dll"])

        # Hook site classification + MinidumpReader cross-check
        base = 0x180000000
        text_slice = pe_bytes[0x400 : 0x400 + 0x100]
        header = struct.pack("<4sIIIQQ", b"MDMP", 0xA793, 1, 32, 0, 0)
        sdir = struct.pack("<III", minidump.MEMORY64_LIST_STREAM, 32, 44)
        m64 = struct.pack("<QQ", 1, 76)
        desc = struct.pack("<QQ", base + 0x1000, len(text_slice))
        dmp_bytes = header + sdir + m64 + desc + text_slice

        with tempfile.TemporaryDirectory() as tmp:
            dmp_path = Path(tmp) / "site.dmp"
            dmp_path.write_bytes(dmp_bytes)
            with minidump.MinidumpReader(dmp_path) as reader:
                s_pdata = hook_audit.classify_hook_site(
                    pe_bytes,
                    base + 0x1000,
                    expected_prologue=bytes.fromhex("57 48 89 CF"),
                    expected_pdata_bounds=(base + 0x1000, base + 0x1015),
                    dump_reader=reader,
                )
                self.assertTrue(s_pdata["ok"])
                self.assertEqual(s_pdata["kind"], "pdata_function")
                self.assertTrue(s_pdata["dump_same_bytes"])

                s_thunk = hook_audit.classify_hook_site(pe_bytes, base + 0x1070, dump_reader=reader)
                self.assertTrue(s_thunk["ok"])
                self.assertEqual(s_thunk["kind"], "thunk_rel32")
                self.assertTrue(s_thunk["target_in_pdata"])

                s_leaf = hook_audit.classify_hook_site(pe_bytes, base + 0x1080, dump_reader=reader)
                self.assertTrue(s_leaf["ok"])
                self.assertEqual(s_leaf["kind"], "leaf")

    @unittest.skipUnless(hook_audit.capstone is not None, "capstone not installed")
    def test_scan_pointer_chain_writers(self) -> None:
        base = 0x180000000
        pe_bytes = _build_synthetic_pe32_plus(base)
        rep = hook_audit.scan_pointer_chain_writers(
            pe_bytes,
            code_lo=base + 0x1040,
            code_hi=base + 0x1067,
            offset_chain=(0x08, 0x48),
            entry_reg="rcx",
        )
        # Contiguous .pdata entries (0x1040..0x1050, 0x1050..0x1067) grouped into 1 function
        self.assertEqual(rep["functions_scanned"], 1)
        writer_rips = [int(w["rip"], 16) for w in rep["writers"]]
        self.assertEqual(writer_rips, [base + 0x1048, base + 0x1050])
        other_rips = [int(w["rip"], 16) for w in rep["other_non_stack_writes"]]
        self.assertEqual(other_rips, [base + 0x105F])


if __name__ == "__main__":
    unittest.main()
