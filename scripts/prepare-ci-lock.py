"""Prepare one dependency snapshot; migrate only the known pre-GUI lockfile."""

import hashlib
import os
from pathlib import Path
import subprocess
import tomllib
from typing import Callable

# One-time migration from the exact lockfile checked in at 796d634. Once the
# validated lock is committed, future runs are strictly read-only (--locked).
LEGACY_LOCK_BLOB = "a8038e0ba407c4aab83a7e3b46a1a9cacabeda44"


def git_blob_sha(data: bytes) -> str:
    """Identify a Git blob, not a password or a security signature."""
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def versions(data: bytes, name: str) -> set[str]:
    document = tomllib.loads(data.decode("utf-8"))
    return {item["version"] for item in document["package"] if item["name"] == name}


def prepare(
    root: Path, run: Callable[..., subprocess.CompletedProcess] = subprocess.run
) -> dict[str, str | bool]:
    root = root.resolve()
    lock = root / "Cargo.lock"
    original = lock.read_bytes()
    old_version = "0.8.3" in versions(original, "yoke-derive")
    recognized = git_blob_sha(original) == LEGACY_LOCK_BLOB
    if old_version and not recognized:
        raise ValueError("unrecognized legacy lockfile; update and review it explicitly")

    if recognized:
        run(
            ["cargo", "update", "--package", "yoke-derive", "--precise", "0.8.4"],
            cwd=root,
            check=True,
        )

    prepared = lock.read_bytes()
    if "0.8.3" in versions(prepared, "yoke-derive"):
        raise ValueError("withdrawn yoke-derive 0.8.3 remains in the prepared lock")
    if recognized and versions(prepared, "yoke-derive") != {"0.8.4"}:
        raise ValueError("the targeted yoke-derive update did not produce 0.8.4")
    if versions(prepared, "iced_test") != {"0.14.0"}:
        raise ValueError("iced_test 0.14.0 must already be resolved in Cargo.lock")

    run(
        ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"],
        cwd=root,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    if lock.read_bytes() != prepared:
        raise ValueError("Cargo.lock changed during locked metadata validation")
    return {"sha256": hashlib.sha256(prepared).hexdigest(), "refreshed": recognized}


def main() -> None:
    result = prepare(Path.cwd())
    report = f"sha256={result['sha256']}\nrefreshed={str(result['refreshed']).lower()}\n"
    print(report, end="")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as stream:
            stream.write(report)


if __name__ == "__main__":
    main()
