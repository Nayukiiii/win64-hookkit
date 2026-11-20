"""PE32+ static control-flow, AMD64 UNWIND_INFO, and Control Flow Guard (CFG) auditor.

Provides:
- `PeImage`: Strict PE32+ parser extracting sections, exports/export slots,
  imports/IAT map, TLS callbacks, and `.pdata` `RUNTIME_FUNCTION` entries.
- `parse_unwind_info`: Full AMD64 `UNWIND_INFO` parser with unwind code
  decoding, `UNW_FLAG_CHAININFO` chain walking, cycle-budget loop protection,
  and exception/termination handler RVA extraction.
- `parse_load_config`: Directory 10 (`IMAGE_LOAD_CONFIG_DIRECTORY64`) parser
  extracting Control Flow Guard (`__guard_check_icall_fptr` and
  `__guard_dispatch_icall_fptr`) slots and `GuardFlags`.
- Capstone-backed executable section scanner classifying direct transfers, IAT
  calls, CFG indirect dispatches, vtable offset calls (`[reg + disp]`), and
  indirect jump tables for static control-flow closure auditing.
"""

from __future__ import annotations

import argparse
import json
import struct
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    import capstone
    from capstone import x86 as _x86
except ImportError:  # pragma: no cover
    capstone = None  # type: ignore[assignment]
    _x86 = None  # type: ignore[assignment]


IMAGE_SCN_MEM_EXECUTE = 0x20000000

UNW_FLAG_NHANDLER = 0x0
UNW_FLAG_EHANDLER = 0x1
UNW_FLAG_UHANDLER = 0x2
UNW_FLAG_CHAININFO = 0x4


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


class PeImage:
    """Strict read-only PE32+ (AMD64) binary parser."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        _require(len(data) >= 64 and data[:2] == b"MZ", "Truncated or invalid DOS header")
        pe = self.u32(0x3C)
        _require(self.at(pe, 4) == b"PE\x00\x00" and self.u16(pe + 4) == 0x8664, "AMD64 PE32+ required")
        count = self.u16(pe + 6)
        opt_size = self.u16(pe + 20)
        opt = pe + 24
        _require(0 < count <= 96 and opt_size >= 112 and self.u16(opt) == 0x20B, "Unsupported PE32+ layout")
        num_dirs = self.u32(opt + 108)
        _require(1 <= num_dirs <= 16 and opt_size >= 112 + 8 * num_dirs, "Invalid PE32+ data directory count")

        self.entry_point_rva: int = self.u32(opt + 16)
        self.image_base: int = self.u64(opt + 24)
        self.headers_size: int = self.u32(opt + 60)
        self.directories: List[Tuple[int, int]] = [
            (self.u32(opt + 112 + 8 * i), self.u32(opt + 116 + 8 * i)) if i < num_dirs else (0, 0)
            for i in range(16)
        ]

        self.sections: List[Dict[str, Any]] = []
        for i in range(count):
            off = opt + opt_size + 40 * i
            name = self.at(off, 8).rstrip(b"\x00").decode("ascii", errors="replace")
            vs, va, rs, raw = struct.unpack("<IIII", self.at(off + 8, 16))
            _require(raw + rs <= len(data), f"Section {name!r} file range exceeds image")
            self.sections.append(
                {
                    "name": name,
                    "rva": va,
                    "virtual_size": vs,
                    "raw_size": rs,
                    "raw_offset": raw,
                    "flags": self.u32(off + 36),
                }
            )

        self.imports: Dict[int, Dict[str, str]] = self.read_imports()
        self.exports: Dict[str, Dict[str, Any]] = self.read_exports()

    def at(self, offset: int, size: int) -> bytes:
        _require(0 <= offset <= len(self.data) and 0 <= size <= len(self.data) - offset, "File read outside image")
        return self.data[offset : offset + size]

    def u16(self, offset: int) -> int:
        return int(struct.unpack("<H", self.at(offset, 2))[0])

    def u32(self, offset: int) -> int:
        return int(struct.unpack("<I", self.at(offset, 4))[0])

    def u64(self, offset: int) -> int:
        return int(struct.unpack("<Q", self.at(offset, 8))[0])

    def offset(self, rva: int, size: int = 1) -> int:
        _require(size >= 0 and rva >= 0, "Invalid RVA read")
        matches = [
            s["raw_offset"] + rva - s["rva"]
            for s in self.sections
            if s["rva"] <= rva and rva + size <= s["rva"] + s["raw_size"]
        ]
        if rva + size <= self.headers_size:
            matches.append(rva)
        _require(len(matches) == 1, f"RVA 0x{rva:X} is unmapped or ambiguous")
        return matches[0]

    def rbytes(self, rva: int, size: int) -> bytes:
        return self.at(self.offset(rva, size), size)

    def string(self, rva: int, max_len: int = 1024) -> str:
        out = bytearray()
        for n in range(max_len):
            ch = self.rbytes(rva + n, 1)
            if ch == b"\x00":
                return out.decode("ascii", errors="replace")
            out += ch
        raise ValueError("Unterminated PE string")

    def is_executable_rva(self, rva: int) -> bool:
        return any(
            s["rva"] <= rva < s["rva"] + min(s["virtual_size"], s["raw_size"]) and (s["flags"] & IMAGE_SCN_MEM_EXECUTE)
            for s in self.sections
        )

    def read_imports(self) -> Dict[int, Dict[str, str]]:
        base, size = self.directories[1]
        out: Dict[int, Dict[str, str]] = {}
        if not base:
            _require(size == 0, "Import directory size without RVA")
            return out
        terminated = False
        for offset in range(0, size - 19, 20):
            lookup, stamp, chain, name_rva, first_thunk = struct.unpack("<IIIII", self.rbytes(base + offset, 20))
            if not any((lookup, stamp, chain, name_rva, first_thunk)):
                terminated = True
                break
            dll = self.string(name_rva)
            _require(first_thunk != 0, "Missing FirstThunk IAT RVA")
            thunk_rva = lookup or first_thunk
            for i in range(8192):
                val = struct.unpack("<Q", self.rbytes(thunk_rva + i * 8, 8))[0]
                if not val:
                    break
                _require(bool(val >> 63) or val <= 0xFFFFFFFF, "Unsupported bound/unknown import lookup entry")
                symbol = f"#{val & 0xFFFF}" if (val >> 63) else self.string(val + 2)
                slot_rva = first_thunk + i * 8
                _require(slot_rva not in out, "Overlapping IAT slot")
                out[slot_rva] = {"dll": dll, "name": symbol}
            else:
                raise ValueError("Unterminated import thunk list")
        _require(terminated, "Unterminated import descriptor table")
        return out

    def export_slots(self) -> Dict[str, Any]:
        base, size = self.directories[0]
        if not base:
            _require(size == 0, "Export directory size without RVA")
            return {"ordinal_base": None, "function_slots": 0, "name_entries": 0, "slots": []}
        _require(size >= 40, "Truncated export directory")
        fields = struct.unpack("<IIHHIIIIIII", self.rbytes(base, 40))
        ordinal_base, functions, names, addresses, nameptrs, ordinals = fields[5:]
        _require(functions <= 65536 and names <= 65536, "Export table bound exceeded")
        aliases: Dict[int, List[str]] = {i: [] for i in range(functions)}
        used = set()
        for i in range(names):
            name = self.string(struct.unpack("<I", self.rbytes(nameptrs + 4 * i, 4))[0])
            index = struct.unpack("<H", self.rbytes(ordinals + 2 * i, 2))[0]
            _require(index < functions and name not in used, "Invalid name ordinal or duplicate export")
            used.add(name)
            aliases[index].append(name)
        slots: List[Dict[str, Any]] = []
        for index in range(functions):
            target = struct.unpack("<I", self.rbytes(addresses + 4 * index, 4))[0]
            forwarder = None
            if not target:
                kind = "null"
            elif base <= target < base + size:
                kind = "forwarder"
                forwarder = self.string(target)
            else:
                self.rbytes(target, 1)
                kind = "local_executable" if self.is_executable_rva(target) else "local_nonexecutable"
            slots.append(
                {
                    "slot_index": index,
                    "ordinal": ordinal_base + index,
                    "names": sorted(aliases[index]),
                    "rva": target,
                    "kind": kind,
                    "forwarder": forwarder,
                }
            )
        return {
            "ordinal_base": ordinal_base,
            "function_slots": functions,
            "name_entries": names,
            "slots": slots,
        }

    def read_exports(self) -> Dict[str, Dict[str, Any]]:
        slots = self.export_slots()["slots"]
        out: Dict[str, Dict[str, Any]] = {}
        for slot in slots:
            for name in slot["names"]:
                out[name] = {
                    "rva": slot["rva"],
                    "ordinal": slot["ordinal"],
                    "forwarder": slot["forwarder"],
                    "kind": slot["kind"],
                }
        return out

    def runtime_functions(self) -> List[Dict[str, int]]:
        """Parse Directory 3 (``.pdata``) AMD64 ``RUNTIME_FUNCTION`` table."""
        base, size = self.directories[3]
        if not base:
            _require(size == 0, "Exception directory size without RVA")
            return []
        _require(size % 12 == 0 and 0 < size <= 12 * 131072, "Invalid AMD64 .pdata table")
        rows: List[Dict[str, int]] = []
        previous_end = 0
        for offset in range(0, size, 12):
            begin, end, unwind = struct.unpack("<III", self.rbytes(base + offset, 12))
            if begin == 0 and end == 0 and unwind == 0:
                continue
            _require(begin < end and begin >= previous_end and unwind % 4 == 0, "Invalid or overlapping .pdata entry")
            self.rbytes(begin, 1)
            self.rbytes(end - 1, 1)
            previous_end = end
            rows.append({"begin_rva": begin, "end_rva": end, "unwind_rva": unwind})
        return rows

    def executable_regions(self) -> List[Tuple[int, bytes]]:
        return [
            (s["rva"], self.at(s["raw_offset"], min(s["virtual_size"], s["raw_size"])))
            for s in self.sections
            if (s["flags"] & IMAGE_SCN_MEM_EXECUTE) and min(s["virtual_size"], s["raw_size"]) > 0
        ]


def _decode_unwind_codes(code_bytes: bytes, slots: int) -> List[Dict[str, int]]:
    out: List[Dict[str, int]] = []
    i = 0
    while i < slots:
        code_offset = code_bytes[2 * i]
        op_byte = code_bytes[2 * i + 1]
        unwind_op = op_byte & 0x0F
        op_info = (op_byte >> 4) & 0x0F
        out.append({"slot_index": i, "code_offset": code_offset, "unwind_op": unwind_op, "op_info": op_info})
        if unwind_op == 1:  # UWOP_ALLOC_LARGE
            i += 2 if op_info == 0 else 3
        elif unwind_op in (2, 3):  # UWOP_ALLOC_SMALL / UWOP_SET_FPREG -> 1 slot
            i += 1
        elif unwind_op in (4, 6, 8):  # UWOP_SAVE_NONVOL / SAVE_XMM128 / SET_FPREG? -> 2 slots
            i += 2
        elif unwind_op in (5, 7, 9):  # *_FAR -> 3 slots
            i += 3
        else:
            i += 1
    return out


def parse_unwind_info(
    image: PeImage,
    functions: Sequence[Dict[str, int]],
    max_depth: int = 64,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Parse AMD64 ``UNWIND_INFO`` records and walk ``UNW_FLAG_CHAININFO`` chains.

    Includes cycle-budget loop protection (`max_depth`) and exception/unwind
    handler RVA extraction (`UNW_FLAG_EHANDLER` / `UNW_FLAG_UHANDLER`).
    """
    triples = {(r["begin_rva"], r["end_rva"], r["unwind_rva"]) for r in functions}
    records: Dict[int, Dict[str, Any]] = {}

    def _ensure_record(address: int) -> Dict[str, Any]:
        if address in records:
            return records[address]
        header = image.rbytes(address, 4)
        version = header[0] & 7
        flags = header[0] >> 3
        slots = header[2]
        _require(version == 1 and (flags & ~7) == 0, f"Unsupported UNWIND_INFO version/flags at 0x{address:X}")
        _require(not ((flags & UNW_FLAG_CHAININFO) and (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER))),
                 "CHAININFO conflicts with handler flags")
        aligned_code_bytes = ((slots + 1) // 2) * 4
        tail = address + 4 + aligned_code_bytes
        codes_raw = image.rbytes(address + 4, aligned_code_bytes)
        entry: Dict[str, Any] = {
            "unwind_rva": address,
            "version": version,
            "flags": flags,
            "prolog_size": header[1],
            "code_slots": slots,
            "frame_register": header[3] & 15,
            "frame_offset": header[3] >> 4,
            "header_hex": header.hex(),
            "unwind_codes": _decode_unwind_codes(codes_raw, slots),
            "optional_rva": tail,
            "handler_rva": None,
            "chained_function": None,
        }
        if flags & UNW_FLAG_CHAININFO:
            triple = struct.unpack("<III", image.rbytes(tail, 12))
            entry["chained_function"] = {
                "begin_rva": triple[0],
                "end_rva": triple[1],
                "unwind_rva": triple[2],
                "in_pdata": triple in triples,
            }
        elif flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
            handler_rva = struct.unpack("<I", image.rbytes(tail, 4))[0]
            image.rbytes(handler_rva, 1)
            entry["handler_rva"] = handler_rva
            entry["language_data_rva"] = tail + 4
        records[address] = entry
        return entry

    for row in functions:
        _ensure_record(row["unwind_rva"])

    effective: List[Dict[str, Any]] = []
    for row in functions:
        address = row["unwind_rva"]
        visited: List[int] = []
        while True:
            _require(address not in visited and len(visited) < max_depth, "Cyclic or over-budget unwind chain")
            visited.append(address)
            entry = _ensure_record(address)
            if entry["chained_function"] is None:
                break
            address = entry["chained_function"]["unwind_rva"]
        effective.append(
            {
                **row,
                "unwind_chain_rvas": visited,
                "effective_unwind_rva": address,
                "effective_handler_rva": entry["handler_rva"],
                "handler_edge_kind": (
                    "metadata_exception_or_unwind"
                    if entry["handler_rva"] is not None
                    else "no_handler_in_static_unwind_record"
                ),
            }
        )

    return list(records.values()), effective


def parse_load_config(image: PeImage) -> Optional[Dict[str, Any]]:
    """Parse Directory 10 (``LoadConfig``) and extract Control Flow Guard slots."""
    base, size = image.directories[10]
    if not base:
        _require(size == 0, "LoadConfig directory size without RVA")
        return None
    if size < 148:
        return None
    declared = struct.unpack("<I", image.rbytes(base, 4))[0]
    if declared < 148:
        return {
            "load_config_rva": base,
            "load_config_size": size,
            "declared_size": declared,
            "check_slot_rva": None,
            "dispatch_slot_rva": None,
            "guard_flags": None,
        }

    check_va, dispatch_va = struct.unpack("<QQ", image.rbytes(base + 112, 16))
    guard_flags = struct.unpack("<I", image.rbytes(base + 144, 4))[0]
    check_slot_rva: Optional[int] = None
    dispatch_slot_rva: Optional[int] = None
    default_dispatch_va: Optional[int] = None
    default_stub_rva: Optional[int] = None

    if check_va:
        _require(check_va >= image.image_base, "CFG check pointer storage VA below image base")
        check_slot_rva = check_va - image.image_base
    if dispatch_va:
        _require(dispatch_va >= image.image_base, "CFG dispatch pointer storage VA below image base")
        dispatch_slot_rva = dispatch_va - image.image_base
        default_dispatch_va = struct.unpack("<Q", image.rbytes(dispatch_slot_rva, 8))[0]
        if default_dispatch_va >= image.image_base:
            default_stub_rva = default_dispatch_va - image.image_base

    return {
        "load_config_rva": base,
        "load_config_size": size,
        "declared_size": declared,
        "check_slot_rva": check_slot_rva,
        "dispatch_slot_rva": dispatch_slot_rva,
        "file_default_dispatch_va": default_dispatch_va,
        "file_default_stub_rva": default_stub_rva,
        "guard_flags": guard_flags,
    }


def classify_transfer_target(ins: Any, imports: Dict[int, Dict[str, str]]) -> Dict[str, Any]:
    """Classify a decoded branch/call instruction target operand."""
    if len(ins.operands) != 1:
        return {"kind": "unknown_operand", "expression": ins.op_str}
    op = ins.operands[0]
    if op.type == _x86.X86_OP_IMM:
        return {"kind": "direct", "rva": int(op.imm)}
    if op.type == _x86.X86_OP_MEM:
        if op.mem.base == _x86.X86_REG_RIP and op.mem.index == 0:
            slot = int(ins.address + ins.size + op.mem.disp)
            if slot in imports:
                return {"kind": "iat", "slot_rva": slot, "imported": imports[slot]}
            return {"kind": "unresolved_rip_indirect", "slot_rva": slot, "expression": ins.op_str}
        return {
            "kind": "mem_indirect",
            "base_reg": ins.reg_name(op.mem.base) if op.mem.base else None,
            "index_reg": ins.reg_name(op.mem.index) if op.mem.index else None,
            "scale": int(op.mem.scale),
            "disp": int(op.mem.disp),
            "expression": ins.op_str,
        }
    if op.type == _x86.X86_OP_REG:
        return {"kind": "reg_indirect", "reg": ins.reg_name(op.reg), "expression": ins.op_str}
    return {"kind": "unresolved_indirect", "expression": ins.op_str}


def decode_executable_sections(
    image: PeImage,
    max_instructions: int = 200_000,
) -> Dict[str, Any]:
    """Disassemble executable sections and classify all control-flow transfers."""
    if capstone is None:
        raise ImportError("capstone is required for executable section disassembly")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    md.skipdata = True

    instructions: Dict[int, Dict[str, Any]] = {}
    gaps: List[Dict[str, Any]] = []
    calls: List[Dict[str, Any]] = []
    transfers: List[Dict[str, Any]] = []
    truncated = False

    for start, data in image.executable_regions():
        for ins in md.disasm(data, start):
            if len(instructions) + len(gaps) >= max_instructions:
                truncated = True
                break
            if not ins.id:
                gaps.append({"rva": ins.address, "bytes": bytes(ins.bytes).hex()})
                continue
            _require(ins.address not in instructions, "Overlapping executable regions")
            is_call = bool(ins.group(capstone.CS_GRP_CALL))
            is_jump = bool(ins.group(capstone.CS_GRP_JUMP))
            is_ret = bool(ins.group(capstone.CS_GRP_RET)) or ins.mnemonic in ("iret", "iretd", "iretq")
            row: Dict[str, Any] = {
                "rva": ins.address,
                "size": ins.size,
                "bytes": bytes(ins.bytes).hex(),
                "mnemonic": ins.mnemonic,
                "operands": ins.op_str,
                "call": is_call,
                "jump": is_jump,
                "return": is_ret,
            }
            if is_call or is_jump:
                row["target"] = classify_transfer_target(ins, image.imports)
                transfers.append(row)
                if is_call:
                    calls.append(row)
            instructions[ins.address] = row
        if truncated:
            break

    return {
        "instructions": instructions,
        "decode_gaps": gaps,
        "all_call_sites": calls,
        "all_transfers": transfers,
        "truncated": truncated,
    }


def classify_indirect_call(
    row: Dict[str, Any],
    previous_ins: Optional[Dict[str, Any]],
    image: PeImage,
    dispatch_slot_rva: Optional[int],
    check_slot_rva: Optional[int] = None,
) -> str:
    """Classify an indirect call site into CFG dispatch, vtable offset, or general indirect."""
    target = row["target"]
    if target["kind"] == "unresolved_rip_indirect":
        if dispatch_slot_rva is not None and target["slot_rva"] == dispatch_slot_rva:
            return "guard_dispatch_slot"
        if check_slot_rva is not None and target["slot_rva"] == check_slot_rva:
            return "guard_check_slot"

    if target["kind"] == "reg_indirect" and previous_ins is not None and capstone is not None:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        prev = next(md.disasm(image.rbytes(previous_ins["rva"], previous_ins["size"]), previous_ins["rva"], count=1), None)
        if prev and prev.mnemonic == "mov" and len(prev.operands) == 2:
            dst, src = prev.operands
            if (
                dst.type == _x86.X86_OP_REG
                and prev.reg_name(dst.reg) == target["reg"]
                and src.type == _x86.X86_OP_MEM
                and src.mem.base == _x86.X86_REG_RIP
                and src.mem.index == 0
            ):
                loaded_slot = int(prev.address + prev.size + src.mem.disp)
                if dispatch_slot_rva is not None and loaded_slot == dispatch_slot_rva:
                    return f"guard_dispatch_loaded_into_{target['reg']}"
                if check_slot_rva is not None and loaded_slot == check_slot_rva:
                    return f"guard_check_loaded_into_{target['reg']}"

    if target["kind"] == "mem_indirect":
        if target.get("base_reg") and not target.get("index_reg"):
            return "vtable_offset_call"
        if target.get("index_reg"):
            return "indexed_indirect_call"

    return "unclassified_indirect"


def classify_indirect_jump(row: Dict[str, Any]) -> str:
    """Classify an indirect jump (e.g. switch jump table vs tail-call dispatch)."""
    target = row["target"]
    if target["kind"] == "mem_indirect" and target.get("index_reg"):
        return "jump_table_indexed"
    if target["kind"] == "reg_indirect":
        return "jump_table_or_tail_reg"
    if target["kind"] == "mem_indirect":
        return "jump_mem_indirect"
    return "unclassified_indirect_jump"


def ordinary_flow(decoded: Dict[str, Any], root_rva: int, max_visits: int = 100_000) -> Dict[str, Any]:
    """Traverse direct CFG edges and fallthroughs from ``root_rva``."""
    insns = decoded["instructions"]
    pending = [root_rva]
    parents: Dict[int, Optional[Tuple[int, str]]] = {root_rva: None}
    seen = set()
    edges: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, Any]] = []
    iat_transfers: List[Dict[str, Any]] = []
    truncated = False

    def push(address: int, origin: int, kind: str) -> None:
        if address not in parents:
            parents[address] = (origin, kind)
            pending.append(address)

    def witness(address: int) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        current = address
        while parents.get(current) is not None:
            parent_info = parents[current]
            assert parent_info is not None
            origin, kind = parent_info
            if kind != "fallthrough":
                out.append({"from_rva": origin, "to_rva": current, "kind": kind})
            current = origin
        return list(reversed(out))

    while pending:
        address = pending.pop()
        if address in seen:
            continue
        if len(seen) >= max_visits:
            truncated = True
            break
        seen.add(address)
        if address not in insns:
            unresolved.append({"rva": address, "reason": "target outside canonical decoded instruction boundaries"})
            continue
        ins = insns[address]
        fall = address + ins["size"]
        if ins["call"] or ins["jump"]:
            tgt = ins["target"]
            kind = "call" if ins["call"] else "jump"
            edges.append({"from_rva": address, "kind": kind, "target": tgt})
            if tgt["kind"] == "direct":
                push(tgt["rva"], address, kind)
            elif tgt["kind"] == "iat":
                iat_transfers.append(
                    {
                        "site_rva": address,
                        "transfer": kind,
                        "slot_rva": tgt["slot_rva"],
                        "imported": tgt["imported"],
                        "ordinary_edge_witness": witness(address),
                    }
                )
            else:
                unresolved.append({"rva": address, "reason": "unresolved indirect transfer", "target": tgt})
            if ins["call"] or ins["mnemonic"] not in ("jmp", "ljmp"):
                push(fall, address, "fallthrough")
        elif ins["return"]:
            continue
        elif ins["mnemonic"] in ("int3", "ud2", "hlt", "int"):
            unresolved.append({"rva": address, "reason": f"trap/abnormal termination: {ins['mnemonic']}"})
        else:
            push(fall, address, "fallthrough")

    return {
        "root_rva": root_rva,
        "visited_instructions": len(seen),
        "edges": sorted(edges, key=lambda r: r["from_rva"]),
        "iat_transfers": sorted(iat_transfers, key=lambda r: r["site_rva"]),
        "unresolved": sorted(unresolved, key=lambda r: (r["rva"], r["reason"])),
        "traversal_truncated": truncated,
    }


def audit_pe_cfg_unwind(
    pe_bytes: bytes,
    roots: Optional[Sequence[str]] = None,
    max_instructions: int = 200_000,
) -> Dict[str, Any]:
    """Run full static PE32+ `.pdata` unwind, CFG LoadConfig, and instruction audit."""
    image = PeImage(pe_bytes)
    functions = image.runtime_functions()
    records, effective = parse_unwind_info(image, functions) if functions else ([], [])
    load_config = parse_load_config(image)
    decoded = decode_executable_sections(image, max_instructions=max_instructions)
    insns = decoded["instructions"]
    by_end = {rva + row["size"]: row for rva, row in insns.items()}

    dispatch_slot = load_config["dispatch_slot_rva"] if load_config else None
    check_slot = load_config["check_slot_rva"] if load_config else None

    indirect_calls: List[Dict[str, Any]] = []
    direct_call_count = 0
    iat_call_count = 0
    for row in decoded["all_call_sites"]:
        tkind = row["target"]["kind"]
        if tkind == "direct":
            direct_call_count += 1
            continue
        if tkind == "iat":
            iat_call_count += 1
            continue
        cls = classify_indirect_call(row, by_end.get(row["rva"]), image, dispatch_slot, check_slot)
        indirect_calls.append({"instruction": row, "structural_class": cls})

    indirect_jumps: List[Dict[str, Any]] = []
    for row in decoded["all_transfers"]:
        if row["jump"] and row["target"]["kind"] not in ("direct", "iat"):
            indirect_jumps.append({"instruction": row, "structural_class": classify_indirect_jump(row)})

    flows: Dict[str, Any] = {}
    missing_roots: List[str] = []
    for name in roots or ():
        exp = image.exports.get(name)
        if not exp or not exp["rva"] or exp["forwarder"]:
            missing_roots.append(name)
        else:
            flows[name] = ordinary_flow(decoded, exp["rva"])

    return {
        "schema": "hookkit-pe-cfg-unwind-v1",
        "image_base": hex(image.image_base),
        "sections": image.sections,
        "load_config": load_config,
        "runtime_functions": effective,
        "unwind_records": records,
        "decoded_instructions": len(insns),
        "decode_gaps": len(decoded["decode_gaps"]),
        "decode_truncated": decoded["truncated"],
        "indirect_calls": indirect_calls,
        "indirect_jumps": indirect_jumps,
        "root_flows": flows,
        "missing_roots": missing_roots,
        "summary": {
            "runtime_functions": len(functions),
            "unique_unwind_records": len(records),
            "chained_runtime_functions": sum(len(r["unwind_chain_rvas"]) > 1 for r in effective),
            "exception_handlers": len({r["handler_rva"] for r in records if r["handler_rva"] is not None}),
            "direct_calls": direct_call_count,
            "iat_calls": iat_call_count,
            "indirect_calls": len(indirect_calls),
            "indirect_call_classes": dict(Counter(r["structural_class"] for r in indirect_calls)),
            "indirect_jumps": len(indirect_jumps),
            "indirect_jump_classes": dict(Counter(r["structural_class"] for r in indirect_jumps)),
        },
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Audit PE32+ .pdata unwind, LoadConfig CFG slots, and call/jump sites")
    parser.add_argument("--pe", type=Path, required=True, help="Path to PE32+ executable or DLL")
    parser.add_argument("--root", action="append", default=[], help="Export name to trace ordinary CFG flow from")
    parser.add_argument("--max-instructions", type=int, default=200_000, help="Disassembly budget")
    parser.add_argument("--json-out", type=Path, help="Optional output JSON path")
    args = parser.parse_args(argv)

    report = audit_pe_cfg_unwind(args.pe.read_bytes(), roots=args.root, max_instructions=args.max_instructions)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
