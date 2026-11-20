"""Pre-flight static hook contract auditor and .pdata pointer-chain writer scanner.

Read-only PE32+ static verification utilities:
- `audit_dll_contract`: Verifies DLL exports (exact or subset) and checks for
  forbidden imported DLLs (e.g. ``user32.dll``).
- `classify_hook_site`: Classifies candidate hook sites into ``pdata_function``,
  ``thunk_rel32``, ``leaf``, or ``unrecognized``, verifies optional expected
  prologue bytes and ``.pdata`` bounds, and optionally cross-checks site bytes
  against a full-memory minidump via ``minidump.MinidumpReader``.
- `scan_pointer_chain_writers`: Groups contiguous chained ``.pdata`` functions
  in ``[code_lo, code_hi)`` and uses Capstone intra-function register alias
  tracking to find all instructions writing through an arbitrary pointer
  dereference chain (e.g. ``[[entry_reg + 0x08] + 0x48]``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    import capstone
    from capstone import x86 as _x86
except ImportError:  # pragma: no cover
    capstone = None  # type: ignore[assignment]
    _x86 = None  # type: ignore[assignment]

try:
    from minidump import MinidumpReader
except ImportError:  # pragma: no cover
    from .minidump import MinidumpReader  # type: ignore[no-redef]


_REG32_TO_64: Dict[str, str] = {
    "eax": "rax",
    "ecx": "rcx",
    "edx": "rdx",
    "ebx": "rbx",
    "esp": "rsp",
    "ebp": "rbp",
    "esi": "rsi",
    "edi": "rdi",
    "r8d": "r8",
    "r9d": "r9",
    "r10d": "r10",
    "r11d": "r11",
    "r12d": "r12",
    "r13d": "r13",
    "r14d": "r14",
    "r15d": "r15",
}

_READ_ONLY_MEM_FIRST: Set[str] = {
    "lea",
    "cmp",
    "test",
    "bt",
    "ucomiss",
    "comiss",
    "ucomisd",
    "comisd",
    "vucomiss",
    "vcomiss",
    "vucomisd",
    "vcomisd",
    "call",
    "jmp",
    "push",
    "ptest",
    "vptest",
}

_CLOBBER_MNEMONICS: Set[str] = {
    "xor",
    "pxor",
    "lea",
    "pop",
    "add",
    "sub",
    "and",
    "or",
    "shl",
    "shr",
    "sar",
    "imul",
    "movzx",
    "movsxd",
    "movsx",
    "cmove",
    "cmovne",
    "cmovz",
    "cmovnz",
    "xchg",
}


def _canonical_reg(name: str) -> str:
    low = name.lower()
    return _REG32_TO_64.get(low, low)


def _parse_pe(data: bytes) -> Tuple[int, Tuple[int, ...], List[Tuple[str, int, int, int, int]]]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("Not an MZ PE image")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off : pe_off + 4] != b"PE\x00\x00":
        raise ValueError("Missing PE signature")
    coff = pe_off + 4
    machine, num_sections = struct.unpack_from("<HH", data, coff)
    if machine != 0x8664:
        raise ValueError(f"Expected AMD64 PE (0x8664), got 0x{machine:X}")
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    if struct.unpack_from("<H", data, opt)[0] != 0x20B:
        raise ValueError("Expected PE32+ (0x20B)")
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    num_dirs = struct.unpack_from("<I", data, opt + 108)[0]
    dirs_list: List[int] = []
    for i in range(16):
        if i < num_dirs:
            rva, sz = struct.unpack_from("<II", data, opt + 112 + i * 8)
            dirs_list.extend((rva, sz))
        else:
            dirs_list.extend((0, 0))
    sec_off = opt + opt_size
    sections: List[Tuple[str, int, int, int, int]] = []
    for i in range(num_sections):
        off = sec_off + i * 40
        name = data[off : off + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append((name, va, max(vsize, raw_size), raw_ptr, raw_size))
    return int(image_base), tuple(dirs_list), sections


def _rva_to_off(sections: Sequence[Tuple[str, int, int, int, int]], rva: int) -> int:
    for _name, va, span, raw_ptr, raw_size in sections:
        if va <= rva < va + span:
            delta = rva - va
            if delta >= raw_size:
                raise ValueError(f"RVA 0x{rva:X} lies in zero-filled section")
            return raw_ptr + delta
    raise ValueError(f"RVA 0x{rva:X} not mapped in PE sections")


def _cstr(data: bytes, off: int) -> str:
    end = data.find(b"\x00", off)
    if end < 0:
        raise ValueError("Unterminated ASCII string in PE")
    return data[off:end].decode("ascii", "replace")


def _pe_exports(data: bytes, sections: Sequence[Tuple[str, int, int, int, int]], dirs: Tuple[int, ...]) -> List[str]:
    rva, size = dirs[0], dirs[1]
    if not rva or not size:
        return []
    base = _rva_to_off(sections, rva)
    _ord_base, _nfuncs, nnames, _addr_f, addr_names, _addr_ord = struct.unpack_from("<IIIIII", data, base + 16)
    names_table_off = _rva_to_off(sections, addr_names)
    out: List[str] = []
    for i in range(nnames):
        nrva = struct.unpack_from("<I", data, names_table_off + i * 4)[0]
        out.append(_cstr(data, _rva_to_off(sections, nrva)))
    return out


def _pe_import_dlls(data: bytes, sections: Sequence[Tuple[str, int, int, int, int]], dirs: Tuple[int, ...]) -> List[str]:
    rva, size = dirs[2], dirs[3]
    if not rva or not size:
        return []
    off = _rva_to_off(sections, rva)
    out: List[str] = []
    while True:
        desc = struct.unpack_from("<IIIII", data, off)
        if not any(desc):
            break
        out.append(_cstr(data, _rva_to_off(sections, desc[3])))
        off += 20
    return out


def _pe_pdata_ranges(
    data: bytes,
    sections: Sequence[Tuple[str, int, int, int, int]],
    dirs: Tuple[int, ...],
) -> List[Tuple[int, int, int]]:
    rva, size = dirs[6], dirs[7]
    if not rva or not size:
        return []
    off = _rva_to_off(sections, rva)
    entries = [struct.unpack_from("<III", data, off + i * 12) for i in range(size // 12)]
    return [(b, e, u) for b, e, u in entries if b or e or u]


def audit_dll_contract(
    dll_bytes: bytes,
    *,
    expected_exports: Optional[Iterable[str]] = None,
    forbidden_imports: Iterable[str] = (),
    exact_exports: bool = True,
) -> Dict[str, Any]:
    """Audit a PE32+ DLL against an export and forbidden-import contract."""
    image_base, dirs, sections = _parse_pe(dll_bytes)
    exp_list = _pe_exports(dll_bytes, sections, dirs)
    imp_list = _pe_import_dlls(dll_bytes, sections, dirs)

    forbidden_set = {name.lower() for name in forbidden_imports}
    forbidden_found = [dll for dll in imp_list if dll.lower() in forbidden_set]

    missing_exports: List[str] = []
    unexpected_exports: List[str] = []
    if expected_exports is not None:
        expected_list = list(expected_exports)
        exp_set = set(exp_list)
        expected_set = set(expected_list)
        missing_exports = [name for name in expected_list if name not in exp_set]
        if exact_exports:
            unexpected_exports = [name for name in exp_list if name not in expected_set]

    ok = not forbidden_found and not missing_exports and (not exact_exports or not unexpected_exports)
    return {
        "dll_sha256": hashlib.sha256(dll_bytes).hexdigest().upper(),
        "image_base": hex(image_base),
        "exports": exp_list,
        "imports": imp_list,
        "missing_exports": missing_exports,
        "unexpected_exports": unexpected_exports,
        "forbidden_imports_found": forbidden_found,
        "ok": ok,
    }


def _looks_like_leaf(raw: bytes, site_va: int) -> bool:
    if not raw or raw[0] == 0xE9:
        return False
    if capstone is not None:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        for ins in md.disasm(raw, site_va):
            if ins.group(capstone.CS_GRP_RET):
                return True
            if ins.group(capstone.CS_GRP_CALL) or ins.group(capstone.CS_GRP_JUMP):
                return False
        return False
    return 0xC3 in raw


def classify_hook_site(
    pe_bytes: bytes,
    site_va: int,
    *,
    expected_prologue: Optional[bytes] = None,
    expected_pdata_bounds: Optional[Tuple[int, int]] = None,
    dump_reader: Optional[MinidumpReader] = None,
) -> Dict[str, Any]:
    """Classify a candidate hook site and verify prologue, .pdata bounds, and optional dump match."""
    image_base, dirs, sections = _parse_pe(pe_bytes)
    ranges = _pe_pdata_ranges(pe_bytes, sections, dirs)
    site_rva = site_va - image_base
    off = _rva_to_off(sections, site_rva)
    raw = pe_bytes[off : off + 32]

    hit = next(((b, e, u) for b, e, u in ranges if b <= site_rva < e), None)
    out: Dict[str, Any] = {
        "va": hex(site_va),
        "rva": hex(site_rva),
        "kind": "unrecognized",
        "in_pdata": hit is not None,
        "pdata_begin": None if hit is None else hex(image_base + hit[0]),
        "pdata_end": None if hit is None else hex(image_base + hit[1]),
        "bytes": " ".join(f"{b:02X}" for b in raw),
        "ok": False,
    }

    if hit is not None:
        out["kind"] = "pdata_function"
        out["ok"] = True
    elif len(raw) >= 5 and raw[0] == 0xE9:
        rel = struct.unpack_from("<i", raw, 1)[0]
        target_va = site_va + 5 + rel
        target_rva = target_va - image_base
        out["kind"] = "thunk_rel32"
        out["target_va"] = hex(target_va)
        try:
            toff = _rva_to_off(sections, target_rva)
            out["target_bytes"] = " ".join(f"{b:02X}" for b in pe_bytes[toff : toff + 16])
            thit = next(((b, e, u) for b, e, u in ranges if b <= target_rva < e), None)
            out["target_in_pdata"] = thit is not None
            out["ok"] = True
        except ValueError as exc:
            out["target_error"] = str(exc)
            out["ok"] = False
    elif _looks_like_leaf(raw, site_va):
        out["kind"] = "leaf"
        out["ok"] = True

    if expected_prologue is not None:
        prologue_ok = raw.startswith(expected_prologue)
        out["prologue_ok"] = prologue_ok
        if not prologue_ok:
            out["ok"] = False

    if expected_pdata_bounds is not None:
        actual_bounds = None if hit is None else (image_base + hit[0], image_base + hit[1])
        bounds_ok = actual_bounds == tuple(expected_pdata_bounds)
        out["pdata_bounds_ok"] = bounds_ok
        if not bounds_ok:
            out["ok"] = False

    if dump_reader is not None:
        cmp_len = min(32, len(raw))
        dump_bytes = dump_reader.read_va(site_va, cmp_len)
        same = dump_bytes == raw[:cmp_len]
        out["dump_same_bytes"] = same
        out["dump_bytes"] = " ".join(f"{b:02X}" for b in dump_bytes)
        if not same:
            out["ok"] = False

    return out


def scan_pointer_chain_writers(
    pe_bytes: bytes,
    code_lo: int,
    code_hi: int,
    offset_chain: Sequence[int],
    entry_reg: str = "rcx",
) -> Dict[str, Any]:
    """Scan ``.pdata`` functions in ``[code_lo, code_hi)`` for pointer-chain memory writers.

    Groups contiguous chained ``.pdata`` entries into logical functions and tracks
    register aliases through ``offset_chain`` dereferences starting from
    ``entry_reg`` (e.g. ``offset_chain=(0x08, 0x48)`` tracks
    ``[[entry_reg + 0x08] + 0x48]``) to report all instructions writing through
    the final dereferenced base register.
    """
    if capstone is None:
        raise ImportError("capstone is required for scan_pointer_chain_writers")
    if code_hi <= code_lo:
        raise ValueError("code_hi must be greater than code_lo")

    image_base, dirs, sections = _parse_pe(pe_bytes)
    ranges = _pe_pdata_ranges(pe_bytes, sections, dirs)
    raw_funcs = sorted(
        (image_base + b, image_base + e)
        for b, e, _u in ranges
        if image_base + e > code_lo and image_base + b < code_hi
    )
    pdata_funcs: List[Tuple[int, int]] = []
    for f0, f1 in raw_funcs:
        if pdata_funcs and f0 == pdata_funcs[-1][1]:
            pdata_funcs[-1] = (pdata_funcs[-1][0], f1)
        else:
            pdata_funcs.append((f0, f1))

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    chain = list(offset_chain)
    entry_canon = _canonical_reg(entry_reg)
    writers: List[Dict[str, Any]] = []
    other_non_stack_writes: List[Dict[str, Any]] = []

    for f0, f1 in pdata_funcs:
        lo = max(f0, code_lo)
        hi = min(f1, code_hi)
        try:
            off = _rva_to_off(sections, lo - image_base)
        except ValueError:
            continue
        fcode = pe_bytes[off : off + (hi - lo)]

        level_regs: List[Set[str]] = [set() for _ in range(len(chain) + 1)]
        level_regs[0].add(entry_canon)
        stack_regs: Set[str] = {"rsp", "rbp", "r11"}

        for ins in md.disasm(fcode, lo):
            mn = ins.mnemonic.lower()
            ops = ins.operands
            text = f"{ins.mnemonic} {ins.op_str}"

            # Check explicit memory writes before mutating register alias sets on dst
            if len(ops) >= 1 and ops[0].type == _x86.X86_OP_MEM and mn not in _READ_ONLY_MEM_FIRST:
                if ops[0].mem.base != 0:
                    w_base = _canonical_reg(ins.reg_name(ops[0].mem.base))
                    w_disp = int(ops[0].mem.disp)
                    if w_base in level_regs[-1]:
                        writers.append(
                            {
                                "rip": hex(ins.address),
                                "function": hex(f0),
                                "base_reg": w_base,
                                "offset": hex(w_disp),
                                "size": int(ops[0].size),
                                "text": text,
                            }
                        )
                    elif w_base not in stack_regs:
                        other_non_stack_writes.append(
                            {
                                "rip": hex(ins.address),
                                "function": hex(f0),
                                "base_reg": w_base,
                                "offset": hex(w_disp),
                                "size": int(ops[0].size),
                                "text": text,
                            }
                        )

            # Update intra-function register alias sets
            if mn == "mov" and len(ops) == 2 and ops[0].type == _x86.X86_OP_REG:
                dst = _canonical_reg(ins.reg_name(ops[0].reg))
                if ops[1].type == _x86.X86_OP_REG:
                    src = _canonical_reg(ins.reg_name(ops[1].reg))
                    for rset in (*level_regs, stack_regs):
                        if src in rset:
                            rset.add(dst)
                        else:
                            rset.discard(dst)
                elif ops[1].type == _x86.X86_OP_MEM and ops[1].size == 8 and ops[1].mem.base != 0 and ops[1].mem.index == 0:
                    base = _canonical_reg(ins.reg_name(ops[1].mem.base))
                    disp = int(ops[1].mem.disp)
                    matched_levels = [k + 1 for k, expected_off in enumerate(chain) if base in level_regs[k] and disp == expected_off]
                    for rset in (*level_regs, stack_regs):
                        rset.discard(dst)
                    for lvl in matched_levels:
                        level_regs[lvl].add(dst)
                else:
                    for rset in (*level_regs, stack_regs):
                        rset.discard(dst)
            elif mn in _CLOBBER_MNEMONICS and len(ops) >= 1 and ops[0].type == _x86.X86_OP_REG:
                dst = _canonical_reg(ins.reg_name(ops[0].reg))
                for rset in level_regs:
                    rset.discard(dst)
                if not (mn == "lea" and dst in ("rbp", "r11")):
                    stack_regs.discard(dst)

    return {
        "schema": "hookkit-pointer-chain-writers-v1",
        "code_range": [hex(code_lo), hex(code_hi)],
        "entry_reg": entry_canon,
        "offset_chain": [hex(o) for o in chain],
        "functions_scanned": len(pdata_funcs),
        "writers": writers,
        "other_non_stack_writes": other_non_stack_writes,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Pre-flight PE32+ hook contract auditor and pointer-chain writer scanner")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_dll = sub.add_parser("audit-dll", help="Verify DLL export and forbidden-import contract")
    p_dll.add_argument("--dll", type=Path, required=True)
    p_dll.add_argument("--expect-export", action="append", default=[])
    p_dll.add_argument("--forbid-import", action="append", default=[])
    p_dll.add_argument("--allow-extra-exports", action="store_true")

    p_site = sub.add_parser("audit-sites", help="Classify and verify PE32+ hook site VAs")
    p_site.add_argument("--pe", type=Path, required=True)
    p_site.add_argument("--site-va", type=lambda s: int(s, 0), action="append", required=True)
    p_site.add_argument("--dump", type=Path, help="Optional full-memory .dmp for byte comparison")

    p_scan = sub.add_parser("scan-writers", help="Scan .pdata functions for pointer-chain memory writers")
    p_scan.add_argument("--pe", type=Path, required=True)
    p_scan.add_argument("--code-lo", type=lambda s: int(s, 0), required=True)
    p_scan.add_argument("--code-hi", type=lambda s: int(s, 0), required=True)
    p_scan.add_argument("--offset", type=lambda s: int(s, 0), action="append", default=[])
    p_scan.add_argument("--entry-reg", default="rcx")

    args = parser.parse_args(argv)
    if args.cmd == "audit-dll":
        rep = audit_dll_contract(
            args.dll.read_bytes(),
            expected_exports=args.expect_export or None,
            forbidden_imports=args.forbid_import,
            exact_exports=not args.allow_extra_exports,
        )
        print(json.dumps(rep, indent=2))
        return 0 if rep["ok"] else 1

    if args.cmd == "audit-sites":
        pe_bytes = args.pe.read_bytes()
        if args.dump:
            with MinidumpReader(args.dump) as reader:
                sites = [classify_hook_site(pe_bytes, va, dump_reader=reader) for va in args.site_va]
        else:
            sites = [classify_hook_site(pe_bytes, va) for va in args.site_va]
        ok = all(s["ok"] for s in sites)
        print(json.dumps({"ok": ok, "sites": sites}, indent=2))
        return 0 if ok else 1

    if args.cmd == "scan-writers":
        rep = scan_pointer_chain_writers(
            args.pe.read_bytes(),
            args.code_lo,
            args.code_hi,
            args.offset,
            entry_reg=args.entry_reg,
        )
        print(json.dumps(rep, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
