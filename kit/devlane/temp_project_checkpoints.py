"""State machine for temporary Cargo project checkpoints.

The supervisor supplies hashes computed from the tool-created project at the Cargo
dispatch boundary. This module validates observations without retaining source paths
or bytes.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any


EVENTS = ("before-update", "after-update", "after-metadata", "after-doc")
REGISTRY_EVENTS = ("before-metadata", "after-metadata", "after-doc")
EVENT_OPERATIONS = {
    "before-update": "update",
    "after-update": "update",
    "before-metadata": "metadata",
    "after-metadata": "metadata",
    "after-doc": "doc",
}
PROJECT_ROOT = "/scratch/semver-target/semver-checks"
PROJECT_NAME = re.compile(r"(?:local|registry)-[a-z0-9][a-z0-9._-]*\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
COMMIT = re.compile(r"[a-f0-9]{40}\Z")
BINDING_FIELDS = frozenset({
    "source_commit", "control_sha", "manifest_projection_sha256",
    "candidate_git_tree_map_sha256", "candidate_transfer_map_sha256",
    "baseline_source_map_sha256", "semver_tool_binary_sha256",
})


class CheckpointRefusal(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _refuse(code: str) -> None:
    raise CheckpointRefusal(code)


def _digest(value: object) -> bool:
    return type(value) is str and HEX.fullmatch(value) is not None


def _binding(value: object) -> dict[str, str]:
    if type(value) is not dict or set(value) != BINDING_FIELDS:
        _refuse("semver-checkpoint-binding")
    if (type(value["control_sha"]) is not str or COMMIT.fullmatch(value["control_sha"]) is None
            or not _digest(value["manifest_projection_sha256"])):
        _refuse("semver-checkpoint-binding")
    if (type(value["source_commit"]) is not str
            or COMMIT.fullmatch(value["source_commit"]) is None):
        _refuse("semver-checkpoint-binding")
    if any(not _digest(value[field]) for field in (
            "candidate_git_tree_map_sha256", "candidate_transfer_map_sha256",
            "baseline_source_map_sha256", "semver_tool_binary_sha256")):
        _refuse("semver-checkpoint-binding")
    return dict(value)


class CheckpointTracker:
    """Compare actual project snapshots across the fixed Cargo operation sequence."""

    def __init__(self, authenticated_binding: object, project_kind: str = "local"):
        self.binding = _binding(authenticated_binding)
        if project_kind not in {"local", "registry"}:
            _refuse("semver-checkpoint-project-kind")
        self.project_kind = project_kind
        self.events = EVENTS if project_kind == "local" else REGISTRY_EVENTS
        self.lock_event = "after-update" if project_kind == "local" else "after-metadata"
        self._next = 0
        self._base: tuple[str, str, int, int] | None = None
        self._post_update_lock: str | None = None
        self._post_update_map: str | None = None
        self._post_update_count: int | None = None
        self._post_update_bytes: int | None = None
        self._post_update_lock_size: int | None = None
        self._project_root: str | None = None

    def observe(self, event: object, *, operation: object, project_root: object,
                manifest_sha256: object, project_map_without_lock_sha256: object,
                project_file_count_without_lock: object,
                project_tree_bytes_without_lock: object,
                project_map_sha256: object | None,
                project_file_count: object,
                project_tree_bytes: object,
                lock_sha256: object | None, lock_size: object | None) -> dict[str, Any]:
        if self._next >= len(self.events) or event != self.events[self._next]:
            _refuse("semver-checkpoint-order")
        if operation != EVENT_OPERATIONS[event]:
            _refuse("semver-checkpoint-operation")
        if (type(project_root) is not str or not project_root.startswith(PROJECT_ROOT + "/")
                or "\\" in project_root or "\x00" in project_root):
            _refuse("semver-checkpoint-project-root")
        parts = PurePosixPath(project_root).parts
        if (PurePosixPath(project_root).is_absolute() is not True
                or PurePosixPath(project_root).as_posix() != project_root
                or any(part in ("", ".", "..") for part in parts)
                or len(parts) != len(PurePosixPath(PROJECT_ROOT).parts) + 1
                or PROJECT_NAME.fullmatch(parts[-1]) is None
                or len(parts[-1]) > 255
                or not parts[-1].startswith(self.project_kind + "-")):
            _refuse("semver-checkpoint-project-root")
        if self._project_root is not None and project_root != self._project_root:
            _refuse("semver-checkpoint-project-root")
        if not _digest(manifest_sha256) or not _digest(project_map_without_lock_sha256):
            _refuse("semver-checkpoint-snapshot")
        if (type(project_file_count_without_lock) is not int or not 1 <= project_file_count_without_lock <= 250_000
                or type(project_tree_bytes_without_lock) is not int
                or not 1 <= project_tree_bytes_without_lock <= 512 * 1024 * 1024):
            _refuse("semver-checkpoint-snapshot")
        if lock_sha256 is not None and not _digest(lock_sha256):
            _refuse("semver-checkpoint-lock")
        if lock_size is not None and (type(lock_size) is not int or not 1 <= lock_size <= 8 * 1024 * 1024):
            _refuse("semver-checkpoint-lock")
        if (type(project_file_count) is not int or not 1 <= project_file_count <= 250_000
                or type(project_tree_bytes) is not int
                or not 1 <= project_tree_bytes <= 512 * 1024 * 1024):
            _refuse("semver-checkpoint-snapshot")

        snapshot = (manifest_sha256, project_map_without_lock_sha256,
                    project_file_count_without_lock, project_tree_bytes_without_lock)
        if self._base is not None and snapshot != self._base:
            _refuse("semver-checkpoint-project-mutated")

        first_event = self.events[0]
        if event == first_event:
            if (lock_sha256 is not None or lock_size is not None
                    or project_map_sha256 != project_map_without_lock_sha256
                    or project_file_count != project_file_count_without_lock
                    or project_tree_bytes != project_tree_bytes_without_lock):
                _refuse("semver-checkpoint-lock-preexists")
        elif event == self.lock_event:
            if (lock_sha256 is None or type(lock_size) is not int
                    or not 1 <= lock_size <= 8 * 1024 * 1024
                    or not _digest(project_map_sha256)
                    or project_file_count != project_file_count_without_lock + 1
                    or project_tree_bytes != project_tree_bytes_without_lock + lock_size):
                _refuse("semver-checkpoint-lock-missing")
            self._post_update_lock = lock_sha256
            self._post_update_lock_size = lock_size
            self._post_update_map = project_map_sha256
            self._post_update_count = project_file_count
            self._post_update_bytes = project_tree_bytes
        elif (lock_sha256 != self._post_update_lock or lock_size != self._post_update_lock_size
              or project_map_sha256 != self._post_update_map
              or project_file_count != self._post_update_count
              or project_tree_bytes != self._post_update_bytes):
            _refuse("semver-checkpoint-lock-mutated")

        result = {
            "event": event,
            "source_commit": self.binding["source_commit"],
            "control_sha": self.binding["control_sha"],
            "manifest_projection_sha256": self.binding["manifest_projection_sha256"],
            "candidate_git_tree_map_sha256": self.binding["candidate_git_tree_map_sha256"],
            "candidate_transfer_map_sha256": self.binding["candidate_transfer_map_sha256"],
            "semver_tool_binary_sha256": self.binding["semver_tool_binary_sha256"],
            "manifest_sha256": manifest_sha256,
            "project_map_without_lock_sha256": project_map_without_lock_sha256,
            "project_file_count_without_lock": project_file_count_without_lock,
            "project_tree_bytes_without_lock": project_tree_bytes_without_lock,
        }
        if lock_sha256 is not None:
            result["lock_sha256"] = lock_sha256
            result["project_map_sha256"] = project_map_sha256
            result["project_file_count"] = project_file_count
            result["project_tree_bytes"] = project_tree_bytes
        if self._base is None:
            self._base = snapshot
        if self._project_root is None:
            self._project_root = project_root
        self._next += 1
        return result

    def finish(self) -> dict[str, Any]:
        if self._next != len(self.events) or self._post_update_lock is None:
            _refuse("semver-checkpoint-incomplete")
        return {
            "status": "complete",
            "checkpoint_count": len(self.events),
            "project_kind": self.project_kind,
            "source_commit": self.binding["source_commit"],
            "control_sha": self.binding["control_sha"],
            "manifest_projection_sha256": self.binding["manifest_projection_sha256"],
            "candidate_git_tree_map_sha256": self.binding["candidate_git_tree_map_sha256"],
            "candidate_transfer_map_sha256": self.binding["candidate_transfer_map_sha256"],
            "semver_tool_binary_sha256": self.binding["semver_tool_binary_sha256"],
            "temporary_manifest_sha256": self._base[0],
            "temporary_project_map_without_lock_sha256": self._base[1],
            "temporary_project_file_count_without_lock": self._base[2],
            "temporary_project_tree_bytes_without_lock": self._base[3],
            "temporary_project_map_sha256": self._post_update_map,
            "temporary_project_file_count": self._post_update_count,
            "temporary_project_tree_bytes": self._post_update_bytes,
            "temporary_lock_sha256": self._post_update_lock,
            "raw_source_retained": False,
        }
