#!/usr/bin/env python3
"""Generate the P256 blocklist database from badkeys source repositories.

Clones all known-bad-key source repositories, extracts P256 private keys,
computes BKHASH120 (truncated SHA-256 of the x-coordinate), and produces
a sorted binary database file.

Usage:
    python3 generate_blocklist.py --output data/p256_blocklist.bin [--repos-dir /tmp/badkeys-repos]
"""

import argparse
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key


# (repo_url, subdirs_to_walk, category_id, category_name, sparse_paths)
# sparse_paths: if set, use sparse checkout for only these paths (for large repos)
# Category IDs must match the Rust Category enum in src/category.rs
SOURCES = [
    (
        "https://github.com/badkeys/debianopenssl.git",
        ["ecp256/ssl/be32", "ecp256/ssl/le32", "ecp256/ssl/le64"],
        0,
        "debianssl",
        ["ecp256"],  # sparse checkout only ecp256 dir
    ),
    (
        "https://github.com/SecurityFail/kompromat.git",
        ["src/rfc"],
        1,
        "rfc",
        None,
    ),
    (
        "https://github.com/SecurityFail/kompromat.git",
        ["src/documentation"],
        2,
        "documentation",
        None,
    ),
    (
        "https://github.com/SecurityFail/kompromat.git",
        ["src/firmware"],
        3,
        "firmware",
        None,
    ),
    (
        "https://github.com/SecurityFail/kompromat.git",
        ["src/localhostcert"],
        4,
        "localhostcert",
        None,
    ),
    (
        "https://github.com/SecurityFail/kompromat.git",
        ["src/softwaretests"],
        5,
        "softwaretests",
        None,
    ),
    (
        "https://github.com/SecurityFail/kompromat.git",
        ["src/testvectors"],
        6,
        "testvectors",
        None,
    ),
    (
        "https://github.com/SecurityFail/kompromat.git",
        ["src/misc"],
        7,
        "misc",
        None,
    ),
    (
        "https://github.com/badkeys/gitkeys.git",
        ["."],
        8,
        "gitkeys",
        None,
    ),
    (
        "https://github.com/badkeys/fwkeys.git",
        ["."],
        9,
        "fwkeys",
        None,
    ),
    (
        "https://github.com/badkeys/pkgkeys.git",
        ["."],
        10,
        "pkgkeys",
        None,
    ),
    (
        "https://github.com/badkeys/webkeys.git",
        ["."],
        11,
        "webkeys",
        None,
    ),
    # Malware repo has 817k .key files but contains 0 P256 keys (all RSA).
    # Scanning it takes hours due to filesystem I/O on 5.1 GB of data.
    # Uncomment if the repo ever gains EC keys.
    # (
    #     "https://github.com/SecurityFail/malware.git",
    #     ["src"],
    #     12,
    #     "malware",
    #     None,
    # ),
]


def log(msg: str) -> None:
    """Print with flush for immediate output."""
    print(msg, flush=True)


def clone_repo(url: str, dest: Path, sparse_paths: list[str] | None = None) -> None:
    """Clone a git repository. Uses sparse checkout if sparse_paths is set."""
    if dest.exists() and any(dest.iterdir()):
        # Check if it has actual content (not just .git from a failed clone)
        has_content = any(p.name != ".git" for p in dest.iterdir())
        if has_content:
            log(f"  Repo already cloned: {dest}")
            return
        else:
            log(f"  Removing incomplete clone: {dest}")
            import shutil
            shutil.rmtree(dest)

    if sparse_paths:
        log(f"  Sparse cloning {url} (paths: {sparse_paths}) -> {dest}")
        subprocess.run(
            ["git", "clone", "--depth=1", "--filter=blob:none", "--sparse", url, str(dest)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "sparse-checkout", "set"] + sparse_paths,
            check=True,
            capture_output=True,
        )
    else:
        log(f"  Cloning {url} -> {dest}")
        subprocess.run(
            ["git", "clone", "--depth=1", url, str(dest)],
            check=True,
            capture_output=True,
        )


def repo_dir_name(url: str) -> str:
    """Extract a directory name from a repo URL."""
    parts = url.rstrip("/").removesuffix(".git").split("/")
    return f"{parts[-2]}_{parts[-1]}"


def bkhash120(x: int) -> bytes:
    """Compute BKHASH120: SHA-256 of minimum-length big-endian x, truncated to 15 bytes.

    This must match the badkeys Python implementation exactly:
        inval_b = inval.to_bytes((inval.bit_length() + 7) // 8, byteorder="big")
        sha256(inval_b).digest()[:15]
    """
    if x == 0:
        x_bytes = b"\x00"
    else:
        x_bytes = x.to_bytes((x.bit_length() + 7) // 8, byteorder="big")
    return hashlib.sha256(x_bytes).digest()[:15]


def extract_p256_keys(base_dir: Path, subdirs: list[str]) -> list[tuple[int, bytes]]:
    """Walk subdirectories for .key files, extract P256 x-coordinates.

    Returns list of (x_coordinate_int, bkhash120_bytes).
    """
    results = []
    files_scanned = 0
    errors = 0
    t0 = time.time()

    # Collect all .key files first
    all_key_files = []
    for subdir in subdirs:
        search_path = base_dir / subdir
        if not search_path.exists():
            log(f"    WARNING: subdir not found: {search_path}")
            continue
        all_key_files.extend(sorted(search_path.rglob("*.key")))

    total_files = len(all_key_files)
    log(f"    Found {total_files} .key files to scan")

    skipped = 0
    for key_file in all_key_files:
        files_scanned += 1
        if files_scanned % 10000 == 0:
            elapsed = time.time() - t0
            rate = files_scanned / elapsed if elapsed > 0 else 0
            log(f"    Progress: {files_scanned}/{total_files} ({rate:.0f} files/s, {len(results)} P256 found, {skipped} skipped)")

        try:
            # Skip files larger than 8KB - a P256 PEM private key is ~300 bytes.
            # Even PKCS#8 with extra attributes shouldn't exceed a few KB.
            try:
                if key_file.stat().st_size > 8192:
                    skipped += 1
                    continue
            except OSError:
                skipped += 1
                continue

            data = key_file.read_bytes()

            # Fast pre-filter: skip files that are clearly not PEM private keys.
            # This avoids expensive crypto parsing for RSA keys, binary files, etc.
            # EC private keys use either "BEGIN EC PRIVATE KEY" (SEC1) or
            # "BEGIN PRIVATE KEY" (PKCS#8, which could be any key type).
            # Skip files with "BEGIN RSA" or "BEGIN DSA" or "BEGIN OPENSSH"
            # or files that don't look like PEM at all.
            if b"-----BEGIN" not in data:
                skipped += 1
                continue
            if b"BEGIN RSA PRIVATE KEY" in data or b"BEGIN DSA PRIVATE KEY" in data:
                skipped += 1
                continue
            if b"BEGIN OPENSSH PRIVATE KEY" in data:
                skipped += 1
                continue

            privkey = load_pem_private_key(data, password=None)
            pubkey = privkey.public_key()

            if not isinstance(pubkey, ec.EllipticCurvePublicKey):
                continue
            if not isinstance(pubkey.curve, ec.SECP256R1):
                continue

            x = pubkey.public_numbers().x
            h = bkhash120(x)
            results.append((x, h))
        except Exception as e:
            errors += 1
            if errors <= 5:
                log(f"    WARNING: failed to parse {key_file.name}: {e}")
            elif errors == 6:
                log("    (suppressing further warnings)")

    elapsed = time.time() - t0
    log(f"    Scanned {files_scanned} .key files in {elapsed:.1f}s, found {len(results)} P256 keys, {errors} errors")
    return results


def main():
    parser = argparse.ArgumentParser(description="Generate P256 blocklist database")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/p256_blocklist.bin"),
        help="Output binary file path",
    )
    parser.add_argument(
        "--repos-dir",
        type=Path,
        default=None,
        help="Directory to clone repos into (default: tempdir)",
    )
    args = parser.parse_args()

    if args.repos_dir:
        repos_base = args.repos_dir
        repos_base.mkdir(parents=True, exist_ok=True)
    else:
        tmpdir = tempfile.mkdtemp(prefix="badkeys-repos-")
        repos_base = Path(tmpdir)
        log(f"Using temp directory: {repos_base}")

    # Determine sparse checkout paths per repo (merge from all sources)
    repo_sparse: dict[str, list[str] | None] = {}
    for url, _subdirs, _cat_id, _cat_name, sparse in SOURCES:
        if url not in repo_sparse:
            repo_sparse[url] = sparse
        elif sparse is not None:
            if repo_sparse[url] is not None:
                repo_sparse[url] = list(set(repo_sparse[url] + sparse))
            # If already None (full clone), keep None

    # Group sources by repo URL
    repo_sources: dict[str, list[tuple[list[str], int, str]]] = defaultdict(list)
    for url, subdirs, cat_id, cat_name, _sparse in SOURCES:
        repo_sources[url].append((subdirs, cat_id, cat_name))

    # Clone all unique repos
    log("\n=== Cloning repositories ===")
    repo_paths: dict[str, Path] = {}
    for url in repo_sources:
        dirname = repo_dir_name(url)
        dest = repos_base / dirname
        clone_repo(url, dest, sparse_paths=repo_sparse.get(url))
        repo_paths[url] = dest

    # Extract P256 keys from each source
    log("\n=== Extracting P256 keys ===")
    entries: dict[bytes, int] = {}
    stats: dict[str, int] = defaultdict(int)

    for url, source_list in repo_sources.items():
        repo_path = repo_paths[url]
        for subdirs, cat_id, cat_name in source_list:
            log(f"\n  [{cat_id}] {cat_name} ({url})")
            keys = extract_p256_keys(repo_path, subdirs)
            new_count = 0
            for x, h in keys:
                if h not in entries:
                    entries[h] = cat_id
                    new_count += 1
                else:
                    entries[h] = min(entries[h], cat_id)
            stats[cat_name] = len(keys)
            log(f"    {new_count} new unique entries (after dedup)")

    # Sort by hash and write binary output
    log(f"\n=== Writing database ===")
    sorted_entries = sorted(entries.items(), key=lambda kv: kv[0])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "wb") as f:
        for h, cat_id in sorted_entries:
            f.write(h)  # 15 bytes
            f.write(struct.pack("B", cat_id))  # 1 byte

    total = len(sorted_entries)
    file_size = total * 16
    log(f"Wrote {total} entries ({file_size} bytes) to {args.output}")

    log(f"\n=== Statistics ===")
    for cat_name, count in sorted(stats.items(), key=lambda kv: kv[1], reverse=True):
        log(f"  {cat_name}: {count} P256 keys found")
    log(f"  Total unique (after dedup): {total}")
    log(f"\nRepos cloned to: {repos_base}")


if __name__ == "__main__":
    main()
