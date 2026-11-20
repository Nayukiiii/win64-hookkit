"""Deterministic source transformer converting Microsoft Detours v4.0.1 to prepare-only mode.

Removes all internal thread suspension/context manipulation from ``detours.cpp``,
disables stock commit/abort/update-thread/trampoline-free entry points so an
external transaction coordinator owns stop-the-world execution, injects
``patch_core.h`` and an optional ``patch_core.inc`` helper implementation, and
strictly asserts that zero ``SuspendThread(``, ``ResumeThread(``,
``GetThreadContext(``, or ``SetThreadContext(`` calls remain in the generated
source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

DETOURS_V401_BLOBS: Dict[str, str] = {
    "detours.cpp": "8345c4db448d08139c2b2211dd754dfd183f3c4e",
    "disasm.cpp": "f002ff49ebe723726b2392e1bd85ed9ba7b2affc",
    "modules.cpp": "341673085f57f4ce89b361ff8e71298e27098a99",
    "detours.h": "fe7acf110b298ad8475d5a97aff0155aea3bec6a",
}

FORBIDDEN_THREAD_APIS: Tuple[str, ...] = (
    "SuspendThread(",
    "ResumeThread(",
    "GetThreadContext(",
    "SetThreadContext(",
)


def _cut_replace(source: str, start_anchor: str, end_anchor: str, replacement: str) -> str:
    if source.count(start_anchor) != 1:
        raise ValueError(f"Expected exactly 1 occurrence of start anchor {start_anchor!r}, found {source.count(start_anchor)}")
    if source.count(end_anchor) != 1:
        raise ValueError(f"Expected exactly 1 occurrence of end anchor {end_anchor!r}, found {source.count(end_anchor)}")
    a = source.index(start_anchor)
    b = source.index(end_anchor)
    if a >= b:
        raise ValueError(f"Start anchor {start_anchor!r} appears after end anchor {end_anchor!r}")
    return source[:a] + replacement + "\n\n" + source[b:]


def _git_blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\x00" + raw).hexdigest()


def _sha256_upper(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest().upper()


def transform_detours_source(
    source_text: str,
    patch_core_inc_text: str = "",
    *,
    prepare_begin_name: str = "HookkitStockPrepareBegin",
    patch_core_header: str = "patch_core.h",
) -> str:
    """Transform Microsoft Detours ``detours.cpp`` into a prepare-only source unit."""
    source = source_text.replace("\r\n", "\n")

    detours_inc = '#include "detours.h"'
    if source.count(detours_inc) != 1:
        raise ValueError(f"Expected exactly 1 occurrence of {detours_inc!r}")
    header_line = f'#include "{patch_core_header}"'
    if header_line not in source:
        source = source.replace(detours_inc, f"{detours_inc}\n{header_line}", 1)

    begin_sig = "LONG WINAPI DetourTransactionBegin()"
    if source.count(begin_sig) != 1:
        raise ValueError(f"Expected exactly 1 occurrence of {begin_sig!r}")
    source = source.replace(begin_sig, f"static LONG WINAPI {prepare_begin_name}()", 1)

    replacements = [
        (
            "static void detour_free_trampoline(",
            "static BOOL detour_is_region_empty(",
            "static void detour_free_trampoline(PDETOUR_TRAMPOLINE pTrampoline) { (void)pTrampoline; }",
        ),
        (
            "LONG WINAPI DetourTransactionAbort()",
            "LONG WINAPI DetourTransactionCommit()",
            "LONG WINAPI DetourTransactionAbort() { return ERROR_INVALID_OPERATION; }",
        ),
        (
            "LONG WINAPI DetourTransactionCommit()",
            "static BYTE detour_align_from_trampoline(",
            "LONG WINAPI DetourTransactionCommit() { return ERROR_INVALID_OPERATION; }",
        ),
        (
            "LONG WINAPI DetourTransactionCommitEx(",
            "LONG WINAPI DetourUpdateThread(",
            "LONG WINAPI DetourTransactionCommitEx(PVOID** failed) { (void)failed; return ERROR_INVALID_OPERATION; }",
        ),
        (
            "LONG WINAPI DetourUpdateThread(",
            "///////////////////////////////////////////////////////////// Transacted APIs.",
            "LONG WINAPI DetourUpdateThread(HANDLE thread) { (void)thread; return ERROR_INVALID_OPERATION; }",
        ),
    ]
    for start_anchor, end_anchor, replacement in replacements:
        source = _cut_replace(source, start_anchor, end_anchor, replacement)

    if patch_core_inc_text:
        source = source.rstrip("\n") + "\n\n" + patch_core_inc_text.replace("\r\n", "\n").lstrip("\n")

    for forbidden in FORBIDDEN_THREAD_APIS:
        if forbidden in source:
            raise ValueError(f"Transformed Detours source retains forbidden thread API call: {forbidden}")

    return source


def generate_prepare_only_detours(
    src_dir: Path,
    out_dir: Path,
    patch_core_inc: Optional[Path] = None,
    *,
    verify_official_blobs: bool = False,
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Generate a prepare-only Detours directory and ``manifest.json`` from ``src_dir``."""
    src_dir = Path(src_dir).resolve()
    out_dir = Path(out_dir).resolve()
    if out_dir.exists() and not overwrite:
        raise FileExistsError(f"Fresh output directory required (pass overwrite=True to replace): {out_dir}")

    detours_cpp_path = src_dir / "detours.cpp"
    if not detours_cpp_path.is_file():
        raise FileNotFoundError(f"Missing detours.cpp in {src_dir}")

    source_hashes: Dict[str, Dict[str, Any]] = {}
    if verify_official_blobs:
        for name, expected_sha1 in DETOURS_V401_BLOBS.items():
            fpath = src_dir / name
            if not fpath.is_file():
                raise FileNotFoundError(f"Missing official Detours v4.0.1 file {name!r} in {src_dir}")
            raw = fpath.read_bytes()
            actual_sha1 = _git_blob_sha1(raw)
            if actual_sha1 != expected_sha1:
                raise ValueError(f"Detours v4.0.1 blob SHA-1 mismatch for {name}: expected {expected_sha1}, got {actual_sha1}")
            source_hashes[name] = {"git_blob_sha1": actual_sha1, "sha256": _sha256_upper(raw)}

    inc_text = ""
    inc_meta: Optional[Dict[str, Any]] = None
    if patch_core_inc is not None:
        inc_path = Path(patch_core_inc).resolve()
        inc_bytes = inc_path.read_bytes()
        inc_text = inc_bytes.decode("utf-8")
        inc_meta = {"path": str(inc_path), "size_bytes": len(inc_bytes), "sha256": _sha256_upper(inc_bytes)}

    transformed = transform_detours_source(detours_cpp_path.read_text(encoding="utf-8"), inc_text)

    out_dir.mkdir(parents=True, exist_ok=True)
    generated: Dict[str, Dict[str, Any]] = {}

    for item in sorted(src_dir.iterdir()):
        if not item.is_file():
            continue
        if item.name == "detours.cpp":
            out_bytes = transformed.replace("\n", "\r\n").encode("utf-8")
            (out_dir / item.name).write_bytes(out_bytes)
            generated[item.name] = {"size_bytes": len(out_bytes), "sha256": _sha256_upper(out_bytes), "transformed": True}
        elif item.suffix.lower() in (".cpp", ".c", ".h", ".hpp", ".inc", ".asm"):
            raw = item.read_bytes()
            (out_dir / item.name).write_bytes(raw)
            generated[item.name] = {"size_bytes": len(raw), "sha256": _sha256_upper(raw), "transformed": False}

    manifest: Dict[str, Any] = {
        "schema": "hookkit-detours-prepare-only-v1",
        "official_ref": "microsoft/Detours v4.0.1",
        "verified_official_blobs": verify_official_blobs,
        "source_blobs": source_hashes,
        "patch_core_inc": inc_meta,
        "generated": generated,
        "library_thread_control_removed": True,
        "stock_commit_abort_disabled": True,
        "trampoline_free_disabled": True,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Transform Microsoft Detours v4.0.1 source into prepare-only mode")
    parser.add_argument("--src-dir", type=Path, required=True, help="Directory containing Microsoft Detours v4.0.1 src")
    parser.add_argument("--out-dir", type=Path, required=True, help="Output directory for prepare-only Detours")
    parser.add_argument("--patch-core-inc", type=Path, help="Optional patch_core.inc file to append to detours.cpp")
    parser.add_argument("--verify-v401-blobs", action="store_true", help="Verify official Detours v4.0.1 git blob SHA-1s")
    parser.add_argument("--overwrite", action="store_true", help="Allow writing into an existing output directory")
    args = parser.parse_args(argv)

    manifest = generate_prepare_only_detours(
        args.src_dir,
        args.out_dir,
        args.patch_core_inc,
        verify_official_blobs=args.verify_v401_blobs,
        overwrite=args.overwrite,
    )
    print(json.dumps({"ok": True, "generated_files": sorted(manifest["generated"].keys())}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
