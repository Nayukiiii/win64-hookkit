"""Generate and check ntdll.dll syscall stub route manifests.

Provides two operations:
1. `generate`: Reads an x64 PE image (defaulting to C:\\Windows\\System32\\ntdll.dll),
   extracts the RVA and first 24 machine bytes of the 6 thread/memory syscall stubs
   used by Hookkit, and writes a JSON manifest (and optional C++ `.inc` header).
2. `check-drift`: Compares a previously frozen JSON manifest against the current
   system `ntdll.dll`. Returns exit code 0 when identical, or exit code 3 when an
   OS update changed any stub RVA or machine bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

REQUIRED_EXPORTS: Tuple[str, ...] = (
    "NtSuspendThread",
    "NtResumeThread",
    "NtGetContextThread",
    "NtQueryInformationThread",
    "NtProtectVirtualMemory",
    "NtFlushInstructionCache",
)

STUB_WINDOW_BYTES = 24


def _rva_to_file_offset(pe_bytes: bytes, rva: int) -> int:
    if len(pe_bytes) < 0x40 or pe_bytes[:2] != b"MZ":
        raise ValueError("Not a valid MZ PE image")
    e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    if pe_bytes[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("Missing PE signature")
    num_sections = struct.unpack_from("<H", pe_bytes, e_lfanew + 6)[0]
    size_opt_hdr = struct.unpack_from("<H", pe_bytes, e_lfanew + 20)[0]
    sec_table_off = e_lfanew + 24 + size_opt_hdr
    for i in range(num_sections):
        off = sec_table_off + i * 40
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", pe_bytes, off + 8)
        span = max(vsize, raw_size)
        if va <= rva < va + span:
            return raw_ptr + (rva - va)
    raise ValueError(f"RVA 0x{rva:X} not mapped in any section")


def extract_pe_exports(pe_bytes: bytes, names: Tuple[str, ...] = REQUIRED_EXPORTS) -> Dict[str, Dict[str, Any]]:
    e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    opt_off = e_lfanew + 24
    magic = struct.unpack_from("<H", pe_bytes, opt_off)[0]
    if magic != 0x20B:
        raise ValueError(f"Expected PE32+ (0x20B), got 0x{magic:X}")
    export_rva, export_size = struct.unpack_from("<II", pe_bytes, opt_off + 112)
    if export_rva == 0 or export_size == 0:
        raise ValueError("PE image has no export directory")

    exp_off = _rva_to_file_offset(pe_bytes, export_rva)
    num_funcs, num_names, funcs_rva, names_rva, ords_rva = struct.unpack_from(
        "<IIIII", pe_bytes, exp_off + 20
    )
    funcs_off = _rva_to_file_offset(pe_bytes, funcs_rva)
    names_off = _rva_to_file_offset(pe_bytes, names_rva)
    ords_off = _rva_to_file_offset(pe_bytes, ords_rva)

    name_to_rva: Dict[str, int] = {}
    wanted = set(names)
    for i in range(num_names):
        name_rva = struct.unpack_from("<I", pe_bytes, names_off + i * 4)[0]
        n_off = _rva_to_file_offset(pe_bytes, name_rva)
        end = pe_bytes.index(b"\x00", n_off)
        sym = pe_bytes[n_off:end].decode("ascii", errors="replace")
        if sym in wanted:
            ordinal_index = struct.unpack_from("<H", pe_bytes, ords_off + i * 2)[0]
            if ordinal_index < num_funcs:
                fn_rva = struct.unpack_from("<I", pe_bytes, funcs_off + ordinal_index * 4)[0]
                name_to_rva[sym] = fn_rva

    routes: Dict[str, Dict[str, Any]] = {}
    for sym in names:
        if sym not in name_to_rva:
            raise KeyError(f"Export {sym!r} not found in PE image")
        rva = name_to_rva[sym]
        f_off = _rva_to_file_offset(pe_bytes, rva)
        window = pe_bytes[f_off : f_off + STUB_WINDOW_BYTES]
        if len(window) != STUB_WINDOW_BYTES:
            raise ValueError(f"Truncated stub window for {sym}")
        routes[sym] = {
            "rva": rva,
            "bytes_hex": window.hex(),
        }
    return routes


def build_manifest(pe_path: Path) -> Dict[str, Any]:
    raw = pe_path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    routes = extract_pe_exports(raw, REQUIRED_EXPORTS)
    return {
        "schema": "hookkit-ntdll-routes-v1",
        "image_sha256": sha256,
        "image_size": len(raw),
        "routes": routes,
    }


def compare_manifests(expected: Dict[str, Any], actual: Dict[str, Any]) -> List[str]:
    drifts: List[str] = []
    exp_routes = expected.get("routes", {})
    act_routes = actual.get("routes", {})
    for sym in REQUIRED_EXPORTS:
        if sym not in exp_routes:
            drifts.append(f"{sym}: missing in expected manifest")
            continue
        if sym not in act_routes:
            drifts.append(f"{sym}: missing in actual image")
            continue
        if exp_routes[sym]["rva"] != act_routes[sym]["rva"]:
            drifts.append(
                f"{sym}: RVA drift expected=0x{exp_routes[sym]['rva']:X} actual=0x{act_routes[sym]['rva']:X}"
            )
        if exp_routes[sym]["bytes_hex"].lower() != act_routes[sym]["bytes_hex"].lower():
            drifts.append(
                f"{sym}: stub bytes drift expected={exp_routes[sym]['bytes_hex']} actual={act_routes[sym]['bytes_hex']}"
            )
    return drifts


def render_cpp_inc(manifest: Dict[str, Any]) -> str:
    lines = [
        "// Auto-generated by ntdll_routes.py. Do not edit manually.",
        f"// Source image SHA-256: {manifest['image_sha256']}",
        "static const ::hookkit::RouteDescriptor kExpectedNtdllRoutes[] = {",
    ]
    for sym in REQUIRED_EXPORTS:
        entry = manifest["routes"][sym]
        raw_bytes = bytes.fromhex(entry["bytes_hex"])
        byte_literals = ", ".join(f"0x{b:02X}" for b in raw_bytes)
        lines.append(
            f"    {{ ::hookkit::RouteId::{sym}, \"{sym}\", 0x{entry['rva']:X}u, {{ {byte_literals} }} }},"
        )
    lines.append("};")
    return "\n".join(lines) + "\n"


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate or drift-check ntdll syscall stub routes")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("generate", help="Extract routes from ntdll and write manifest")
    p_gen.add_argument(
        "--ntdll",
        type=Path,
        default=Path(r"C:\Windows\System32\ntdll.dll"),
        help="Path to ntdll.dll image",
    )
    p_gen.add_argument("--manifest-out", type=Path, required=True, help="Output JSON manifest path")
    p_gen.add_argument("--cpp-inc-out", type=Path, help="Optional C++ .inc output path")

    p_chk = sub.add_parser("check-drift", help="Check frozen manifest against current ntdll.dll")
    p_chk.add_argument("--manifest", type=Path, required=True, help="Frozen JSON manifest path")
    p_chk.add_argument(
        "--ntdll",
        type=Path,
        default=Path(r"C:\Windows\System32\ntdll.dll"),
        help="Path to current ntdll.dll image",
    )

    args = parser.parse_args(argv)
    if args.cmd == "generate":
        manifest = build_manifest(args.ntdll)
        args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
        args.manifest_out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        if args.cpp_inc_out:
            args.cpp_inc_out.parent.mkdir(parents=True, exist_ok=True)
            args.cpp_inc_out.write_text(render_cpp_inc(manifest), encoding="utf-8")
        return 0

    if args.cmd == "check-drift":
        expected = json.loads(args.manifest.read_text(encoding="utf-8"))
        actual = build_manifest(args.ntdll)
        drifts = compare_manifests(expected, actual)
        if drifts:
            for d in drifts:
                print(f"[DRIFT] {d}", file=sys.stderr)
            return 3
        print("OK: zero ntdll route drift detected.")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
