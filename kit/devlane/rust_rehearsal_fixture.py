"""Reviewed source files for the hostile core-rust rehearsal and Linux e2e fixture."""

import os
import stat
from pathlib import Path


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures/core-rust-rehearsal"
LOCKFILES = ("Cargo.lock", "fuzz/Cargo.lock", "runtime/Cargo.lock")
TESTS = {
    "root::Cargo.toml::tests::child_has_no_control_secrets_or_sockets": "case_0001",
    "runtime::runtime/crates/services/listener/Cargo.toml::tests::listener_fixture_is_reachable": "case_0002",
    "fuzz::fuzz/Cargo.toml::tests::corpus_fixture_is_present": "case_0003",
    "listener::runtime/crates/services/listener/Cargo.toml::tests::listener_fixture_is_reachable": "case_0004",
}
EXPECTED_FILES = frozenset((
    "Cargo.lock", "Cargo.toml", "build.rs", "deny.toml", "src/lib.rs",
    "crates/support/Cargo.toml", "crates/support/src/lib.rs",
    "supply-chain/audits.toml", "supply-chain/config.toml",
    "fuzz/Cargo.lock", "fuzz/Cargo.toml", "fuzz/corpus/valid-array.json",
    "fuzz/corpus/valid-object.json", "fuzz/src/main.rs",
    "runtime/Cargo.lock", "runtime/Cargo.toml",
    "runtime/crates/services/listener/Cargo.toml",
    "runtime/crates/services/listener/src/lib.rs",
    "runtime/supply-chain/audits.toml", "runtime/supply-chain/config.toml",
    "supply-chain/imports.lock", "runtime/supply-chain/imports.lock",
))


def source_files():
    """Read the fixed regular-file tree; refuse links and additions outside its contract."""
    if FIXTURE_ROOT.is_symlink() or not FIXTURE_ROOT.is_dir():
        raise ValueError("rust-fixture-root")
    result = {}
    for current, directories, filenames in os.walk(FIXTURE_ROOT, followlinks=False):
        base = Path(current)
        for name in directories:
            path = base / name
            if path.is_symlink() or not stat.S_ISDIR(path.lstat().st_mode):
                raise ValueError("rust-fixture-directory")
        for name in filenames:
            path = base / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("rust-fixture-file")
            relative = path.relative_to(FIXTURE_ROOT).as_posix()
            result[relative] = path.read_bytes()
    if set(result) != EXPECTED_FILES:
        raise ValueError("rust-fixture-files")
    return dict(sorted(result.items()))
