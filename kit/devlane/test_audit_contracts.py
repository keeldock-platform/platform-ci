"""Mutation tests for the workflow dispatch and exact auditor contracts."""

import copy
import contextlib
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import public_audit as audit
import control_audit
import acceptance_diagnostics
import diagnostic_contract
import refusal_codes
import sandbox_windows


SHA = "a" * 40
IDENTITY = {
    "repository": audit.REPOSITORY,
    "repository_id": audit.REPOSITORY_ID,
    "event": "workflow_dispatch",
    "ref": "refs/heads/main",
    "control_sha": SHA,
    "run_id": "12345",
    "run_attempt": 1,
    "control_run_id": "9876",
    "profile": "core-node",
    "platform": "linux",
    "wave_id": "wave-test-0001",
    "bundle_id": "bundle-test-0001",
    "cache_baseline_sha256": "b" * 64,
}


MARK = chr(35) * 2
RUNNER_HOME = chr(47) + "home" + chr(47) + "runner"
TMP = RUNNER_HOME + "/work/_temp"
MACOS_RUNNER_HOME = chr(47) + "Users" + chr(47) + "runner"
MACOS_TMP = MACOS_RUNNER_HOME + "/work/_temp"
MACOS_WORKSPACE = MACOS_RUNNER_HOME + "/work/platform-ci/platform-ci"


def _output_row_index(log, marker):
    for index, row in enumerate(log.splitlines(keepends=True)):
        content = row.decode("utf-8").rstrip("\r\n")
        if audit.TIME_PREFIX.sub("", content, count=1) == marker:
            return index
    raise AssertionError("output marker is absent")


def _replace_output_line(log, marker, replacement):
    rows = log.splitlines(keepends=True)
    index = _output_row_index(log, marker)
    if not replacement:
        del rows[index]
    else:
        content = rows[index].decode("utf-8").rstrip("\r\n")
        ending = rows[index][len(content.encode("utf-8")):]
        prefix = content[:-len(marker)] if marker else content
        rows[index] = (prefix + replacement).encode("utf-8") + ending
    return b"".join(rows)


def _insert_output_before(log, marker, line):
    rows = log.splitlines(keepends=True)
    index = _output_row_index(log, marker)
    rows.insert(index, (line + "\n").encode("utf-8"))
    return b"".join(rows)


def _omit_step_run_group(log, identity, job_name, step_name):
    grammar = audit._Grammar(
        ".github/workflows/devlane-encrypted.yml", job_name, identity, "encrypted",
    )
    runnable_steps = [step for step in grammar.steps if not (
        step["name"] == "Install pinned Rust toolchain" and identity.get("profile") != "desktop"
        or step["name"] == "Install Tauri Linux build dependencies"
        and (identity.get("platform") != "linux" or identity.get("profile") != "desktop")
    )]
    target_index = next(index for index, step in enumerate(runnable_steps) if step["name"] == step_name)
    lines = log.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines)
              if audit.TIME_PREFIX.sub("", line.decode("utf-8"), count=1).rstrip("\r\n").startswith(
                  audit.LOG_MARKER + "[group]Run ")]
    start = starts[target_index]
    end = next(index for index in range(start + 1, len(lines))
               if audit.TIME_PREFIX.sub("", lines[index].decode("utf-8"), count=1).rstrip("\r\n")
               == audit.LOG_MARKER + "[endgroup]")
    del lines[start:end + 1]
    return b"".join(lines)


def _env_value(name, identity=IDENTITY, kind="encrypted", job_runner=None):
    platform = identity.get("platform", "linux")
    execution_runner = job_runner or audit.PLATFORM_RUNNERS.get(platform, "ubuntu-24.04")
    runner_home = (audit.WINDOWS_RUNNER_HOME if execution_runner == "windows-2025" else
                   MACOS_RUNNER_HOME if execution_runner == "macos-15" else RUNNER_HOME)
    runner_temp = (audit.WINDOWS_TEMP if execution_runner == "windows-2025" else
                   MACOS_TMP if execution_runner == "macos-15" else TMP)
    run_root = (runner_temp + "\\devlane-" + identity["run_id"] if execution_runner == "windows-2025"
                else runner_temp + "/devlane-" + identity["run_id"])
    workspace = (r"D:\a\platform-ci\platform-ci" if execution_runner == "windows-2025" else
                 runner_home + "/work/platform-ci/platform-ci")
    values = {
        "CI_REPOSITORY": audit.REPOSITORY, "CI_REPOSITORY_ID": str(audit.REPOSITORY_ID),
        "CI_REF": "refs/heads/main", "CI_SHA": identity["control_sha"], "CI_SERVER_URL": "https://github.com",
        "CI_EVENT_NAME": "workflow_dispatch", "CI_RUN_ID": identity["run_id"], "CI_RUN_ATTEMPT": "1",
        "GITHUB_RUN_ID": identity["run_id"], "GITHUB_RUN_ATTEMPT": "1",
        "CI_CONTROL_RUN_ID": identity.get("control_run_id", ""), "DEVLANE_PROFILE": identity["profile"],
        "DEVLANE_PLATFORM": platform,
        "DEVLANE_WAVE_ID": identity["wave_id"], "DEVLANE_BUNDLE_ID": identity["bundle_id"],
        "DEVLANE_BUNDLE_ASSET_ID": "111", "DEVLANE_BUNDLE_SHA256": "c" * 64, "DEVLANE_BUNDLE_SIZE": "4096",
        "DEVLANE_PROJECTION_ASSET_ID": "222", "DEVLANE_PROJECTION_SHA256": "d" * 64,
        "DEVLANE_PROJECTION_SIZE": "512", "DEVLANE_EXPIRES": "2000000000",
        "DEVLANE_CACHE_BASELINE_SHA256": identity["cache_baseline_sha256"],
        "RUN_ROOT": run_root, "PYTHONDONTWRITEBYTECODE": "1",
        "DEVLANE_DECRYPT_KEY": "***", "GITHUB_TOKEN": "***",
        "CI_WORKSPACE": workspace,
    }
    if kind == "synthetic":
        values["CI_REF"] = identity.get("ref", "refs/heads/develop")
    return values[name]


def _with_value(step, key, identity, kind):
    declared = step["with"][key]
    if "${{" not in declared:
        return declared
    if key == "path":
        platform = identity.get("platform", "linux")
        if step["name"] == "Restore exact source-free control evidence":
            return "devlane-control-evidence/permit.json"
        if step["name"] in ("Restore one-run bundle permit", "Save one-run bundle permit",
                             "Restore and verify persisted one-run permit"):
            return "devlane-bundle-permit/permit.json"
        runner_temp = (audit.WINDOWS_TEMP if platform == "windows" else
                       MACOS_TMP if platform == "macos" else TMP)
        separator = "\\" if platform == "windows" else "/"
        return runner_temp + separator + "devlane-bundle-permit" + separator + "permit.json"
    if kind == "synthetic":
        return "devlane-permit-v1-synthetic-bundle-" + identity["run_id"]
    return ("devlane-control-v1-" + identity["control_run_id"]
            if "control" in declared else "devlane-permit-v1-" + identity["bundle_id"])


def _step_outputs(step, identity, kind, records):
    name, uses = step["name"], step.get("uses") or ""
    if name == "Install Tauri Linux build dependencies" and identity["profile"] == "desktop":
        return ["tauri_linux_dependencies=installed"]
    if name == "Install pinned Rust toolchain" and identity["profile"] == "desktop":
        return ["rust_toolchain=prepared"]
    if name == "Install pinned Rust toolchain" and identity["profile"] in audit.RUST_PROFILES:
        return ["rust_offline_tools=prepared"]
    if name == "Prepare dependencies before the cut" and identity["profile"] in audit.RUST_PROFILES:
        return ["dependency_preparation=complete", "rust_offline_tools=installed"]
    key = None
    if uses.startswith("actions/cache/restore"):
        key = _with_value(step, "key", identity, kind)
        cache_outputs = ["Cache hit for: " + key, "Cache Size: ~0 MB (160 B)", "Cache restored successfully",
                "Cache restored from key: " + key] if "fail-on-cache-miss" in step["with"] else [
                "Cache not found for input keys: " + _with_value(step, "key", identity, kind)]
        if identity.get("platform") == "windows" and "fail-on-cache-miss" in step["with"]:
            cache_outputs.append(
                MARK + '[command]"C:\\Program Files\\Git\\usr\\bin\\tar.exe" -xf '
                + 'D:/a/_temp/01234567-89ab-cdef-0123-456789abcdef/cache.tzst -P -C D:/a/platform-ci/platform-ci '
                + '--force-local --use-compress-program "zstd -d"'
            )
        if identity.get("platform") == "macos" and "fail-on-cache-miss" in step["with"]:
            cache_outputs.append(
                MARK + "[command]" + audit.MACOS_GNU_TAR + " -xf "
                + MACOS_TMP + "/01234567-89ab-cdef-0123-456789abcdef/cache.tzst -P -C "
                + MACOS_WORKSPACE + " --delay-directory-restore "
                + "--use-compress-program unzstd"
            )
        return cache_outputs
    if uses.startswith("actions/cache/save"):
        key = _with_value(step, "key", identity, kind)
        cache_outputs = ["Cache saved with key: " + key, "Cache saved successfully"]
        if identity.get("platform") == "windows":
            cache_outputs.append(
                MARK + '[command]"C:\\Program Files\\Git\\usr\\bin\\tar.exe" --posix -cf cache.tzst '
                + '--exclude cache.tzst -P -C D:/a/platform-ci/platform-ci --files-from manifest.txt '
                + '--force-local --use-compress-program "zstd -T0"'
            )
        if identity.get("platform") == "macos":
            cache_outputs.append(
                MARK + "[command]" + audit.MACOS_GNU_TAR
                + " --posix -cf cache.tzst --exclude cache.tzst -P -C "
                + MACOS_WORKSPACE + " --files-from manifest.txt "
                + "--delay-directory-restore --use-compress-program zstdmt"
            )
        return cache_outputs
    if uses.startswith("actions/setup-node"):
        if identity.get("platform") == "macos":
            return ["Attempting to download 24.22.1...",
                    "Acquiring 24.22.1 - arm64 from https:" + chr(47) * 2
                    + "github.com/actions/node-versions/releases/download/"
                    "24.22.1-39619001896/node-24.22.1-darwin-arm64.tar.gz",
                    "Extracting ...",
                    MARK + "[command]/usr/bin/tar xz --strip 1 -C " + MACOS_TMP
                    + "/01234567-89ab-cdef-0123-456789abcdef -f " + MACOS_TMP
                    + "/fedcba98-7654-3210-fedc-ba9876543210",
                    "Adding to the cache ...",
                    "Successfully cached node to " + audit.MACOS_HOSTED_TOOL_CACHE,
                    "Added node to the tool cache", "Environment details", "node: v24.22.1",
                    "npm: 11.6.2", "yarn: 1.22.22"]
        if identity.get("platform") == "windows":
            return ["Found in cache @ " + audit.WINDOWS_HOSTED_TOOL_CACHE, "Environment details", "node: v24.22.1",
                    "npm: 11.19.1", "yarn: 1.22.22"]
        return ["Found in cache @ " + audit.HOSTED_TOOL_CACHE, "Environment details", "node: v24.22.1", "npm: 11.19.1",
                "yarn: 1.22.22"]
    outputs = {
        "Fetch public control and validate dispatch": ["dispatch_context=validated"] if kind == "encrypted" else [],
        "Prepare hosted Linux isolation state": ["devlane_swap=disabled"] + (
            ["devlane_cgroup_v2=ready"] if kind == "encrypted" and identity["profile"] in audit.RUST_PROFILES else []
        ),
        "Prepare hosted runner isolation state": [
            "devlane_macos=preflight-ready" if identity.get("platform") == "macos" else "devlane_swap=disabled",
        ],
        "Prepare hosted Windows isolation state": ["windows_runner=hosted-admin verified=windows-2025"],
        "Verify exact source-free control evidence": ["devlane_permit=verify_control=pass"],
        "Claim this bundle for one run before decryption": ["devlane_permit=claim=pass"],
        "Verify permit and emit bound dispatch marker": [
            "devlane_permit=consumed run-id=%s run-attempt=1" % identity["run_id"],
            "KD-DEVLANE-DISPATCH schema=1 wave-id=%s bundle-id=%s control-sha=%s run-id=%s run-attempt=1" % (
                identity["wave_id"], identity["bundle_id"], identity["control_sha"], identity["run_id"])],
        "Fetch ciphertext and sanitized dependency projection": [
            "public_asset_verified=true bytes=4096", "public_asset_verified=true bytes=512",
            "fetch_projection_valid=true"],
        "Prepare dependencies before the cut": ["dependency_preparation=complete"],
        "Prove public connectivity before the cut": ["network_positive_control=pass"],
        "Cut network and start the isolated supervisor": ["offline_supervisor=ready"],
        "Probe isolation before decryption": ["network_cut_probe=pass"],
        "Decrypt authenticated bundle": ["authenticated_decryption=pass"],
        "Execute offline profile and filter public summary": list(records),
        "Shred runner-local workspace": ["cleanup_receipt=confirmed",
                                         "devlane_job=completed public_output=filtered cleanup=confirmed"],
        "Audit exact four-job graph and public surfaces": [
            "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed"],
        "Claim a synthetic bundle permit": ["devlane_cache_permit=claimed"],
        "Verify the restored permit and refuse a second claim": ["devlane_cache_permit=restored-and-single-use"],
        "Run full source-free production-path acceptance": ["devlane_acceptance=pass"],
        "Probe the loopback-only Linux network boundary": ["devlane_linux_probe=pass"],
    }
    if identity.get("platform") == "windows":
        outputs.update({
            "Prepare dependencies before the cut": [
                "windows_prepare=complete lifecycle_scripts=disabled identity=lpac network=outbound-only",
            ],
            "Prove public connectivity before the cut": ["windows_public_connectivity=proved"],
            "Cut network and start the isolated supervisor": [
                "windows_sandbox_profile=created appcontainer=lpac capabilities=empty",
                "windows_firewall=installed direction=outbound action=block package=verified remote=any",
                "windows_network_cut=installed",
            ],
            "Probe isolation before decryption": [
                "windows_network_probe=pass ipv4=blocked ipv6=blocked dns=blocked loopback=blocked "
                "local_listener=blocked named_pipe=blocked smb=blocked outside_read=blocked "
                "outside_write=blocked other_drive_read=blocked other_drive_write=blocked firewall=verified"],
            "Decrypt authenticated bundle": ["windows_decrypt=accepted manifest=bound"],
            "Shred runner-local workspace": [
                "windows_runner_shred=confirmed files=1 bytes=1 reparse=0",
                "windows_sandbox_cleanup=confirmed firewall=removed profile=deleted",
                "cleanup_receipt=confirmed", "devlane_job=completed public_output=filtered cleanup=confirmed",
            ],
        })
    return outputs.get(name, [])


def _windows_precheckout_cleanup_outputs():
    with tempfile.TemporaryDirectory(prefix="devlane-precheckout-") as directory:
        root = Path(directory) / "run-root"
        root.mkdir()
        (root / "deadline-start").write_bytes(b"start")
        shutil.rmtree(root)
        if root.exists():
            raise AssertionError("pre-checkout cleanup left the run root")
    return [
        "windows_precheckout_cleanup=confirmed",
        "cleanup_receipt=confirmed",
        "devlane_job=completed public_output=filtered cleanup=confirmed",
    ]


def _windows_real_shred_cleanup_outputs():
    with tempfile.TemporaryDirectory(prefix="devlane-checkout-") as directory:
        root = Path(directory) / "run-root"
        root.mkdir()
        (root / "checkout-complete").write_bytes(b"complete")
        result = sandbox_windows.cleanup_runner(root / "state" / "sandbox.json", root,
                                                root / "workspace" / "source")
        if root.exists():
            raise AssertionError("sandbox shred left the run root")
    return result.splitlines() + [
        "cleanup_receipt=confirmed",
        "devlane_job=completed public_output=filtered cleanup=confirmed",
    ]


def _render_log(job_key, identity=None, *, records=(), kind="encrypted", skip=("Install pinned Rust toolchain",)):
    """A hosted-shaped log generated from the reviewed workflow itself."""
    identity = identity or IDENTITY
    workflow = ".github/workflows/devlane-synthetic.yml" if kind == "synthetic" else ".github/workflows/devlane-encrypted.yml"
    grammar = audit._Grammar(workflow, job_key, identity, kind)
    job = grammar.job
    stamp = "2026-11-10T12:00:00.1234567Z "
    lines = [MARK + "[section]Starting: Set up job",
             MARK + "[group]Runner Image Provisioner", "Hosted Compute Agent", "Version: 20251030.1",
             "Commit: 0123456789abcdef0123456789abcdef01234567", MARK + "[endgroup]",
             MARK + "[group]Operating System", "Ubuntu", "24.04.3", "LTS", MARK + "[endgroup]",
             MARK + "[group]Runner Image", "Image: ubuntu-24.04", "Version: 20251105.93.1",
             "Included Software: https:" + chr(47) * 2 + "github.com/actions/runner-images/blob/ubuntu24/20251105.93/images/ubuntu/Ubuntu2404-Readme.md",
             MARK + "[endgroup]", MARK + "[group]GITHUB_TOKEN Permissions", "Metadata: read", MARK + "[endgroup]",
             "Secret source: Actions", "Prepare workflow directory", "Prepare all required actions",
             "Getting action download info", "Complete job name: " + job_key,
             MARK + "[section]Finishing: Set up job"]
    skipped = set(skip)
    if identity["profile"] == "desktop":
        skipped.discard("Install pinned Rust toolchain")
    else:
        skipped.add("Install Tauri Linux build dependencies")
    runtime_env_names = set()
    for step in job["steps"]:
        if step["name"] in skipped or (step["uses"] and "setup-node" in step["uses"] and identity["profile"] in audit.RUST_PROFILES):
            continue
        lines.append(MARK + "[section]Starting: " + step["name"])
        if step["run"]:
            lines.append(MARK + "[group]Run " + step["run"][0].strip())
            lines.extend(step["run"])
            lines.append("shell: /usr/bin/bash -e {0}")
        else:
            lines.append(MARK + "[group]Run " + step["uses"])
            lines.append("with:")
            for key in step["with"]:
                lines.append("  %s: %s" % (key, _with_value(step, key, identity, kind)))
        env = dict(job["env"])
        env.update(step["env"])
        env.update({name: "" for name in runtime_env_names})
        if env:
            lines.append("env:")
            lines.extend("  %s: %s" % (name, _env_value(name, identity, kind)) for name in env)
        lines.append(MARK + "[endgroup]")
        outputs = _step_outputs(step, identity, kind, records)
        if (kind == "encrypted" and job_key == audit.WINDOWS_RUN_JOB
                and identity.get("platform") == "windows"
                and step["name"] == "Fetch public control and validate dispatch"):
            outputs = ["devlane_crypto_state=run-root-exported",
                       "devlane_crypto_state=checkout-complete"] + outputs
        lines.extend(outputs)
        runtime_env_names.update(grammar.environment_exports_after_step(step, outputs))
        lines.append(MARK + "[section]Finishing: " + step["name"])
    node_step = next((step for step in job["steps"] if step["uses"] and "setup-node" in step["uses"]), None)
    if node_step and identity["profile"] == "core-node":
        lines += [MARK + "[section]Starting: Post " + node_step["name"],
                  MARK + "[section]Finishing: Post " + node_step["name"]]
    lines += [MARK + "[section]Starting: Complete job", "Cleaning up orphan processes",
              MARK + "[section]Finishing: Complete job"]
    return "".join(stamp + line + "\n" for line in lines).encode("utf-8")


def _render_real_runner_encrypted_log(identity, job_key=None, early_failure=None):
    if job_key is None:
        job_key = audit.PLATFORM_RUN_JOBS[identity.get("platform", "linux")]
    grammar = audit._Grammar(
        ".github/workflows/devlane-encrypted.yml", job_key, identity, "encrypted",
    )
    marker = audit.LOG_MARKER
    lines = ["Current runner version: '2.338.2'"]

    def group(name, values):
        lines.extend([marker + "[group]" + name, *values, marker + "[endgroup]"])

    runner_images = "https://" + "github.com" + "/actions/runner-images"
    platform_runner = ("ubuntu-24.04" if job_key == audit.AUDIT_JOB else
                       audit.PLATFORM_RUNNERS[identity.get("platform", "linux")])
    if platform_runner == "macos-15":
        group("Runner Image Provisioner", [
            "Hosted Compute Agent", "Version: 20261103.629", "Commit: " + "0" * 40,
            "Build Date: 2026-11-03T17:26:59Z", "Worker ID: {4f704859-5d76-44d1-9bfa-adab3eedd3ef}",
            "Region: westus", "Cloud: MacCloud",
        ])
        group("Operating System", ["macOS", "15.8.2", "24H232"])
        group("Runner Image", [
            "Image: macos-15-arm64", "Version: 20261104.0514.1",
            "Included Software: %s/blob/macos-15-arm64/20261104.0514/images/macos/macos-15-arm64-Readme.md" % runner_images,
            "Image Release: %s/releases/tag/macos-15-arm64%%2F20261104.0514" % runner_images,
        ])
    elif platform_runner == "windows-2025":
        group("Runner Image Provisioner", [
            "Hosted Compute Agent", "Version: 20261103.629", "Commit: " + "0" * 40,
            "Build Date: 2026-11-03T17:26:59Z", "Worker ID: {4f704859-5d76-44d1-9bfa-adab3eedd3ef}",
            "Region: westus", "Cloud: Azure",
        ])
        group("Operating System", ["Microsoft Windows Server 2025", "10.0.26100", "Datacenter"])
        group("Runner Image", [
            "Image: windows-2025-vs2026", "Version: 20261103.629",
            "Included Software: %s/blob/win25-vs2026/20261103.629/images/windows/Windows2025-VS2026-Readme.md" % runner_images,
            "Image Release: %s/releases/tag/win25-vs2026%%2F20261103.629" % runner_images,
        ])
    else:
        group("Runner Image Provisioner", [
            "Hosted Compute Agent", "Version: 20261028.624", "Commit: " + "0" * 40,
            "Build Date: 2026-10-28T21:51:42Z", "Worker ID: {279bda81-5141-421a-9d8d-864e1958a8d7}",
            "Region: centralus", "Cloud: Azure",
        ])
        group("Operating System", ["Ubuntu", "24.04.5", "LTS"])
        group("Runner Image", [
            "Image: ubuntu-24.04", "Version: 20261101.360.1",
            "Included Software: %s/blob/ubuntu24/20261101.360/images/ubuntu/Ubuntu2404-Readme.md" % runner_images,
            "Image Release: %s/releases/tag/ubuntu24%%2F20261101.360" % runner_images,
        ])
    permissions = ["Metadata: read"]
    if job_key == audit.AUDIT_JOB:
        permissions = ["Actions: read", "Checks: read", "Metadata: read"]
    group("GITHUB_TOKEN Permissions", permissions)
    lines.append("Secret source: Actions")
    if job_key in audit.EXECUTION_JOBS:
        lines.append("Deployment environment: devlane-decrypt")
    lines.extend(("Cache mode: write", "Prepare workflow directory", "Prepare all required actions"))
    if any((step["uses"] or "") and not (step["uses"] or "").startswith("./")
           for step in grammar.steps):
        lines.append("Getting action download info")
    seen = set()
    for step in grammar.steps:
        uses = step["uses"] or ""
        if uses and not uses.startswith("./"):
            action, _, revision = uses.rpartition("@")
            repository = "/".join(action.split("/")[:2]) + "@" + revision
            if repository not in seen:
                seen.add(repository)
                lines.append("Download action repository '%s' (SHA:%s)" % (repository, revision))
    inputs = {
        "profile": identity["profile"], "platform": identity.get("platform", "linux"),
        "control_run_id": identity["control_run_id"],
        "wave_id": identity["wave_id"], "bundle_id": identity["bundle_id"],
        "bundle_asset_id": "111", "bundle_sha256": "c" * 64, "bundle_size": "4096",
        "projection_asset_id": "222", "projection_sha256": "d" * 64, "projection_size": "512",
        "expires": "2000000000", "cache_baseline_sha256": identity["cache_baseline_sha256"],
    }
    lines.extend([marker + "[group] Inputs"])
    lines.extend("  %s: %s" % (key, value) for key, value in inputs.items())
    lines.extend((marker + "[endgroup]", "Complete job name: " + job_key))

    failure_seen = False
    runtime_env_names = set()
    for step_index, step in enumerate(grammar.steps):
        if step["name"] == "Install pinned Rust toolchain" and identity.get("profile") != "desktop":
            continue
        if (step["name"] == "Install Tauri Linux build dependencies"
                and (platform_runner != "ubuntu-24.04" or identity.get("profile") != "desktop")):
            continue
        if failure_seen and step["name"] != "Shred runner-local workspace":
            continue
        uses = step["uses"] or ""
        run = step["run"]
        lines.append(marker + "[group]Run " + (run[0].strip() if run else uses))
        if run:
            lines.extend("\x1b[36;1m" + line + "\x1b[0m" for line in run)
            if platform_runner == "windows-2025":
                lines.append(audit.WINDOWS_PWSH)
            else:
                shell = "/bin/bash" if platform_runner == "macos-15" else "/usr/bin/bash"
                lines.append("shell: " + shell + " --noprofile --norc -e -o pipefail {0}")
        else:
            lines.append("with:")
            for key in step["with"]:
                value = _with_value(step, key, identity, "encrypted")
                if value != "":
                    lines.append("  %s: %s" % (key, value))
            if uses.startswith("actions/cache/"):
                if "enableCrossOsArchive" not in step["with"]:
                    lines.append("  enableCrossOsArchive: false")
                if "/restore@" in uses:
                    lines.append("  lookup-only: false")
        env_names = grammar.expected_env_names(step, runtime_env_names)
        if env_names:
            lines.append("env:")
            lines.extend("  %s: %s" % (key, _env_value(key, identity, "encrypted", platform_runner))
                         for key in sorted(env_names))
        lines.append(marker + "[endgroup]")
        outputs = _step_outputs(step, identity, "encrypted", ())
        if (job_key in audit.EXECUTION_JOBS and platform_runner == "windows-2025"
                and step["name"] == "Fetch public control and validate dispatch"):
            outputs = ["devlane_crypto_state=run-root-exported",
                       "devlane_crypto_state=checkout-complete"] + outputs
        if early_failure and step["name"] == early_failure["step"]:
            outputs = early_failure.get("outputs", [early_failure["marker"]])
            if (platform_runner == "windows-2025"
                    and step["name"] == "Fetch public control and validate dispatch"
                    and not any(line.startswith("devlane_crypto_state=") for line in outputs)):
                outputs = ["devlane_crypto_state=run-root-exported",
                           "devlane_crypto_state=checkout-complete"] + outputs
        elif (early_failure and step["name"] == "Shred runner-local workspace"
              and "cleanup_outputs" in early_failure):
            outputs = early_failure["cleanup_outputs"]
        if "Environment details" in outputs:
            position = outputs.index("Environment details")
            lines.extend(outputs[:position])
            lines.append(marker + "[group]Environment details")
            lines.extend(outputs[position + 1:])
            lines.append(marker + "[endgroup]")
        else:
            lines.extend(outputs)
        runtime_env_names.update(grammar.environment_exports_after_step(step, outputs))
        if early_failure and step["name"] == early_failure["step"]:
            lines.append(marker + "[error]Process completed with exit code %d." % early_failure["exit_code"])
            failure_seen = True
    lines.append("Cleaning up orphan processes")
    stamp = "2026-11-10T12:00:00.1234567Z "
    return "".join(stamp + line + "\n" for line in lines).encode("utf-8")


def _record(**fields):
    return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def _encrypted_jobs(profile="core-node", platform="linux"):
    identity = dict(IDENTITY, profile=profile, platform=platform)
    names = audit._expected_step_names(profile, identity)
    steps = []
    for name in names:
        conclusion = "success"
        if ((name == "Install pinned Rust toolchain" and profile == "core-node")
                or (name == "Install Tauri Linux build dependencies" and profile != "desktop")):
            conclusion = "skipped"
        steps.append({"name": name, "status": "completed", "conclusion": conclusion})
    active_name = audit.PLATFORM_RUN_JOBS[platform]
    output = [{
        "id": 100, "name": active_name, "run_id": 12345, "run_attempt": 1,
        "labels": [audit.PLATFORM_RUNNERS[platform]],
        "head_sha": SHA, "status": "completed", "conclusion": "success",
        "check_run_url": "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/500",
        "steps": steps,
    }, {
        "id": 101, "name": audit.AUDIT_JOB, "run_id": 12345, "run_attempt": 1,
        "labels": [audit.PLATFORM_RUNNERS["linux"]],
        "head_sha": SHA, "status": "in_progress", "conclusion": None,
        "check_run_url": "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/501",
        "steps": [
            {"name": "Set up job", "status": "completed", "conclusion": "success"},
            {"name": audit.AUDIT_STEP_NAMES[0], "status": "completed", "conclusion": "success"},
            {"name": audit.AUDIT_STEP_NAMES[1], "status": "in_progress", "conclusion": None},
            {"name": "Complete job", "status": "in_progress", "conclusion": None},
        ],
    }]
    for index, inactive_name in enumerate(set(audit.EXECUTION_JOBS) - {active_name}, 1):
        inactive_platform = next(p for p, name in audit.PLATFORM_RUN_JOBS.items() if name == inactive_name)
        output.append({
            "id": 101 + index, "name": inactive_name, "run_id": 12345, "run_attempt": 1,
            "labels": [audit.PLATFORM_RUNNERS[inactive_platform]],
            "head_sha": SHA, "status": "completed", "conclusion": "skipped",
            "check_run_url": "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/%d" % (501 + index),
            "steps": [],
        })
    return output


def _control_jobs():
    output = []
    for index, name in enumerate(sorted(control_audit.CONTROL_JOB_NAMES), 1):
        value = {
            "id": index, "name": name, "run_id": 12345, "run_attempt": 1,
            "head_sha": SHA,
            "check_run_url": "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/%d" % (800 + index),
        }
        if name == control_audit.RUN_JOB:
            value.update({
                "status": "in_progress", "conclusion": None,
                "steps": [
                    {"name": "Set up job", "status": "completed", "conclusion": "success"},
                    {"name": "Fetch public control and validate manual protected-branch dispatch",
                     "status": "completed", "conclusion": "success"},
                    {"name": "Audit the exact 18-job control graph",
                     "status": "in_progress", "conclusion": None},
                    {"name": control_audit.CONTROL_AUDIT_FINAL_STEPS[2],
                     "status": "queued", "conclusion": None},
                    {"name": "Complete job", "status": "in_progress", "conclusion": None},
                ],
            })
        else:
            steps = []
            for step_name in control_audit.CONTROL_STEP_NAMES[name]:
                skipped = (name.startswith("development-feedback-smoke / feedback-smoke-producer ")
                           and not name.endswith("macos-15")
                           and step_name in ("Upload the single macOS ciphertext fixture", "Record uploader identity"))
                steps.append({"name": step_name, "status": "completed",
                              "conclusion": "skipped" if skipped else "success"})
            value.update({"status": "completed", "conclusion": "success", "steps": steps})
        output.append(value)
    return output


def _terminal_control_jobs(require_main=True):
    jobs = copy.deepcopy(_control_jobs())
    for job in jobs:
        if job["name"] == control_audit.RUN_JOB:
            job["steps"] = [
                {"name": name, "status": "completed",
                 "conclusion": "skipped" if name == control_audit.CONTROL_AUDIT_FINAL_STEPS[2] and not require_main else "success"}
                for name in control_audit.CONTROL_AUDIT_FINAL_STEPS
            ]
        job["status"] = "completed"
        job["conclusion"] = "success"
    return jobs


class EncryptedAuditorMutationTests(unittest.TestCase):
    def test_windows_policy_imports_without_unix_only_stdlib_modules(self):
        root = Path(__file__).resolve().parents[2]
        direct_scripts = (
            "kit/bootstrap/test_policy.py",
            "kit/bootstrap/test_public_tree.py",
            "kit/devlane/test_audit_contracts.py",
            "kit/devlane/control_python.py",
            "kit/devlane/test_control_python.py",
            "kit/bootstrap/check_candidate.py",
        )
        discovery_targets = (
            ("kit/promotion", "test_*.py"),
            ("kit/selector", "test_*.py"),
            ("kit/ci", "test_*.py"),
            ("kit/confinement", "test_capsule_frame.py"),
            ("kit/confinement", "test_native_loopback_profile.py"),
            ("kit/cache", "test_*.py"),
            ("kit/bootstrap", "test_api_controls.py"),
            ("kit/confinement", "test_macos*.py"),
            ("kit/confinement", "test_confinement*.py"),
            ("kit/confinement", "test_source_bundle_preflight.py"),
            ("kit/confinement", "test_log_canary.py"),
            ("kit/confinement", "test_cargo_lock_parser.py"),
            ("kit/confinement", "test_release_build_verify.py"),
            ("kit/confinement", "test_release_evidence.py"),
            ("kit/confinement", "test_release_tool_ledger.py"),
            ("kit/baselines", "test_baselines_prepare.py"),
            ("kit/confinement", "test_role_signer.py"),
            ("kit/confinement", "test_confinement_gate_table.py"),
            ("kit/confinement", "test_windows_source_run.py"),
        )
        smoke = (
            "import runpy, sys, unittest\n"
            "from pathlib import Path\n"
            "root = Path(" + repr(str(root)) + ")\n"
            "for name in ('resource', 'fcntl', 'pwd', 'grp'):\n"
            "    sys.modules[name] = None\n"
            "sys.path[:0] = [str(root / 'kit/bootstrap'), str(root / 'kit/devlane')]\n"
        )
        targets = [("script", relative) for relative in direct_scripts]
        targets.extend(("discover", start + "|" + pattern) for start, pattern in discovery_targets)
        for kind, target in targets:
            if kind == "script":
                target_path = root / target
                code = smoke + (
                    "sys.path.insert(0, str(root / " + repr(str(target_path.parent.relative_to(root))) + "))\n"
                    "runpy.run_path(str(root / " + repr(target) + "), run_name='windows_policy_import_smoke')\n"
                )
            else:
                start, pattern = target.split("|", 1)
                code = smoke + (
                    "unittest.TestLoader().discover(str(root / " + repr(start)
                    + "), pattern=" + repr(pattern) + ")\n"
                )
            with self.subTest(kind=kind, target=target):
                result = subprocess.run(
                    [sys.executable, "-B", "-c", code],
                    cwd=str(root),
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_supervisor_refusal_exports_match_the_platform_neutral_module(self):
        if sys.platform == "win32":
            self.skipTest("the supervisor requires Unix resource limits")
        import supervisor

        for name in (
            "CLEANUP_SUBREASONS",
            "DECRYPT_CHILD_ERROR_CLASSES",
            "DECRYPT_CHILD_ERROR_CODES",
            "DECRYPT_CHILD_EXIT_CODES",
            "DECRYPT_REFUSAL_CODES",
            "NETWORK_PROBE_DIAGNOSTIC_CODES",
            "NETWORK_PROBE_REFUSAL_CODES",
            "REFUSAL_CODES",
            "STARTUP_DIAGNOSTIC_CODES",
            "STARTUP_DIAGNOSTIC_PHASES",
            "STARTUP_REFUSAL_CODES",
        ):
            with self.subTest(name=name):
                self.assertEqual(getattr(supervisor, name), getattr(refusal_codes, name))

    def test_decrypt_failed_four_job_graph_is_accepted_when_public_audit_succeeds(self):
        jobs = _encrypted_jobs()
        by_name = {job["name"]: job for job in jobs}
        run_job = by_name[audit.RUN_JOB]
        run_job["conclusion"] = "failure"
        run_steps = {step["name"]: step for step in run_job["steps"]}
        run_steps["Decrypt authenticated bundle"]["conclusion"] = "failure"
        run_steps["Execute offline profile and filter public summary"]["conclusion"] = "skipped"
        audit_job = by_name[audit.AUDIT_JOB]
        audit_job["status"] = "completed"
        audit_job["conclusion"] = "success"
        for step in audit_job["steps"]:
            step.update({"status": "completed", "conclusion": "success"})

        terminal, audit_passed = audit.validate_terminal_job_contract(jobs, IDENTITY, "core-node")
        self.assertTrue(audit_passed)
        self.assertEqual(terminal[audit.RUN_JOB]["conclusion"], "failure")
        terminal_steps = {step["name"]: step for step in terminal[audit.RUN_JOB]["steps"]}
        self.assertEqual(terminal_steps["Decrypt authenticated bundle"]["conclusion"], "failure")
        self.assertEqual(terminal_steps["Execute offline profile and filter public summary"]["conclusion"], "skipped")

    def test_run_audit_accepts_public_four_job_decrypt_failure_shape(self):
        jobs = _encrypted_jobs()
        by_name = {job["name"]: job for job in jobs}
        run_job = by_name[audit.RUN_JOB]
        run_job["conclusion"] = "failure"
        run_steps = {step["name"]: step for step in run_job["steps"]}
        run_steps["Decrypt authenticated bundle"]["conclusion"] = "failure"
        run_steps["Execute offline profile and filter public summary"]["conclusion"] = "skipped"
        failure_log = _render_real_runner_encrypted_log(IDENTITY).replace(
            b"authenticated_decryption=pass\n",
            b"devlane_supervisor_refusal=decrypt-rejected\n"
            b"decrypt_refusal=child-script-unreadable\n"
            b"decrypt_child_error=other\n"
            + (audit.LOG_MARKER + "[error]Process completed with exit code 2.\n").encode("ascii"),
            1,
        )
        lines = []
        skipping_execute = False
        grammar = audit._Grammar(
            ".github/workflows/devlane-encrypted.yml", audit.RUN_JOB, IDENTITY, "encrypted",
        )
        execute_position = next(
            index for index, step in enumerate(grammar.steps)
            if step["name"] == "Execute offline profile and filter public summary"
        )
        execute_group_index = sum(not (
            step["name"] == "Install pinned Rust toolchain" and IDENTITY.get("profile") != "desktop"
            or step["name"] == "Install Tauri Linux build dependencies"
            and (IDENTITY.get("platform") != "linux" or IDENTITY.get("profile") != "desktop")
        ) for step in grammar.steps[:execute_position])
        group_index = 0
        for line in failure_log.splitlines(keepends=True):
            normalized = audit.TIME_PREFIX.sub("", line.decode("utf-8"), count=1).rstrip("\r\n")
            if not skipping_execute and normalized.startswith(audit.LOG_MARKER + "[group]Run "):
                if group_index == execute_group_index:
                    skipping_execute = True
                    group_index += 1
                    continue
                group_index += 1
            if skipping_execute:
                if normalized == audit.LOG_MARKER + "[endgroup]":
                    skipping_execute = False
                continue
            lines.append(line)
        failure_log = b"".join(lines)

        class API:
            def json(self, endpoint):
                if endpoint.endswith("/actions/runs/" + IDENTITY["run_id"]):
                    repository = {"full_name": audit.REPOSITORY, "id": audit.REPOSITORY_ID}
                    return ({
                        "id": int(IDENTITY["run_id"]), "path": audit.WORKFLOW_PATH,
                        "event": "workflow_dispatch", "head_branch": "main",
                        "head_sha": IDENTITY["control_sha"], "run_attempt": 1,
                        "status": "in_progress", "conclusion": None,
                        "repository": repository, "head_repository": repository,
                    }, {})
                if "/jobs?" in endpoint:
                    return ({"total_count": 4, "jobs": jobs}, {})
                if "/artifacts?" in endpoint:
                    return ({"total_count": 0, "artifacts": []}, {})
                return ({}, {})

            def log_text(self, identifier):
                if identifier != run_job["id"]:
                    raise AssertionError("unexpected-run-job")
                return failure_log

        permit_key = "devlane-permit-v1-" + IDENTITY["bundle_id"]
        control_key = "devlane-control-v1-" + IDENTITY["control_run_id"]
        with patch.object(audit, "_fetch_cache_entries", return_value=[
                {"key": permit_key, "size_in_bytes": 1}, {"key": control_key, "size_in_bytes": 1}]), \
                patch.object(audit, "cache_inventory_digest", return_value=IDENTITY["cache_baseline_sha256"]), \
                patch.object(audit, "validate_check_output"), \
                patch.object(audit, "_read_annotations", return_value=[]):
            self.assertEqual(
                audit.run_audit(API(), IDENTITY),
                "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
                "disposition=run-failed-at-decrypt",
            )
        failure_surface = audit.validate_job_log_surface(failure_log, audit.RUN_JOB, IDENTITY, completed=True)
        audit.validate_job_log_metadata_binding(failure_surface, run_job, IDENTITY)
        successful_run_job = next(job for job in _encrypted_jobs() if job["name"] == audit.RUN_JOB)
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_metadata_binding(failure_surface, successful_run_job, IDENTITY)
        success_surface = audit.validate_job_log_surface(
            _render_real_runner_encrypted_log(IDENTITY), audit.RUN_JOB, IDENTITY, completed=True,
        )
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_metadata_binding(success_surface, run_job, IDENTITY)
        for mutation in ("cleanup", "downstream", "failed-step"):
            changed_job = copy.deepcopy(run_job)
            changed_steps = {step["name"]: step for step in changed_job["steps"]}
            if mutation == "cleanup":
                changed_steps["Shred runner-local workspace"]["conclusion"] = "failure"
            elif mutation == "downstream":
                changed_steps["Execute offline profile and filter public summary"]["conclusion"] = "success"
            else:
                changed_steps["Decrypt authenticated bundle"]["conclusion"] = "success"
            with self.subTest(mutation=mutation), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_metadata_binding(failure_surface, changed_job, IDENTITY)

    def test_public_audit_refusal_prints_a_fixed_check_reason(self):
        output = io.StringIO()
        with patch.object(audit, "audit_environment", side_effect=audit.AuditRefusal(
                "audit-contract", "audit-environment")), \
                contextlib.redirect_stdout(output):
            self.assertEqual(audit.main(), 1)
        refusal_line = "devlane_audit=refused code=audit-contract reason=audit-environment"
        self.assertEqual(output.getvalue(), refusal_line + "\n")
        refusal_log = _render_real_runner_encrypted_log(IDENTITY, job_key=audit.AUDIT_JOB).replace(
            b"devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed",
            refusal_line.encode("ascii"),
            1,
        )
        audit.validate_job_log_surface(refusal_log, audit.AUDIT_JOB, IDENTITY, completed=True)
        for mutation in (b"audit-contract", b"reason=audit-environment"):
            changed = (refusal_log.replace(b"audit-contract", b"private-path") if mutation == b"audit-contract"
                       else refusal_log.replace(mutation, b"reason=private-path"))
            with self.subTest(mutation=mutation), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_surface(changed, audit.AUDIT_JOB, IDENTITY, completed=True)

    def test_two_job_contract_accepts_exact_names_steps_attempt_and_cleanup(self):
        jobs = _encrypted_jobs()
        result = audit.validate_job_contract(jobs, IDENTITY, "core-node")
        self.assertEqual(set(result), set(audit.EXECUTION_JOBS) | {audit.AUDIT_JOB})

    def test_windows_crypto_refusals_use_exact_export_checkout_and_cleanup_states(self):
        identity = dict(IDENTITY, platform="windows")
        failed_step = "Fetch public control and validate dispatch"
        cleanup_step = "Shred runner-local workspace"
        cases = (
            (
                "initial-target",
                ["devlane_crypto_state=run-root-not-exported",
                 "devlane_crypto_refusal=crypto-target-invalid",
                 "devlane_deadline_refusal=crypto-dependency-seal-failed"],
                ["windows_run_root_unowned=confirmed", "cleanup_receipt=confirmed",
                 "devlane_job=completed public_output=filtered cleanup=confirmed"],
                False,
            ),
            (
                "initial-acl",
                ["devlane_crypto_state=run-root-exported",
                 "devlane_crypto_refusal=crypto-acl-protection-failed",
                 "devlane_deadline_refusal=crypto-dependency-seal-failed"],
                _windows_precheckout_cleanup_outputs(),
                True,
            ),
            (
                "later-target",
                ["devlane_crypto_state=run-root-exported", "devlane_crypto_state=checkout-complete",
                 "devlane_crypto_refusal=crypto-target-invalid",
                 "devlane_deadline_refusal=crypto-dependency-seal-failed"],
                _windows_real_shred_cleanup_outputs(),
                True,
            ),
            (
                "later-acl",
                ["devlane_crypto_state=run-root-exported", "devlane_crypto_state=checkout-complete",
                 "devlane_crypto_refusal=crypto-acl-stdout-bom-or-whitespace",
                 "devlane_deadline_refusal=crypto-dependency-seal-failed"],
                _windows_real_shred_cleanup_outputs(),
                True,
            ),
            (
                "later-seal",
                ["devlane_crypto_state=run-root-exported", "devlane_crypto_state=checkout-complete",
                 "devlane_crypto_refusal=crypto-seal-write-failed",
                 "devlane_deadline_refusal=crypto-dependency-seal-failed"],
                _windows_real_shred_cleanup_outputs(),
                True,
            ),
        )
        grammar = audit._Grammar(
            ".github/workflows/devlane-encrypted.yml", audit.PLATFORM_RUN_JOBS["windows"],
            identity, "encrypted",
        )
        bootstrap_run = next(step["run"] for step in grammar.steps if step["name"] == failed_step)
        export_index = next(index for index, line in enumerate(bootstrap_run)
                            if line.strip() == "Add-Content -LiteralPath $env:GITHUB_ENV -Value ('RUN_ROOT=' + $runRoot) -Encoding utf8")
        checkout_index = next(index for index, line in enumerate(bootstrap_run)
                              if "checkout --quiet --detach FETCH_HEAD" in line)
        marker_create_index = next(index for index, line in enumerate(bootstrap_run)
                                   if "New-Item -ItemType File -Path $checkoutMarker" in line)
        marker_output_index = bootstrap_run.index("Write-Output 'devlane_crypto_state=checkout-complete'")
        self.assertLess(export_index, checkout_index)
        self.assertLess(checkout_index, marker_create_index)
        self.assertLess(marker_create_index, marker_output_index)
        cleanup_run = next(step["run"] for step in grammar.steps if step["name"] == cleanup_step)
        precheckout_start = next(index for index, line in enumerate(cleanup_run)
                                 if line.strip() == "if (-not (Test-Path -LiteralPath $checkoutMarker -ErrorAction Stop)) {")
        precheckout_end = next(index for index, line in enumerate(cleanup_run[precheckout_start:], precheckout_start)
                               if line.strip() == "} else {")
        self.assertFalse(any("sandbox_windows.py" in line
                             for line in cleanup_run[precheckout_start:precheckout_end]))
        self.assertTrue(any(line.strip() == "Write-Output 'devlane_refusal=windows-runner-failed'"
                            for line in cleanup_run))

        for name, outputs, cleanup_outputs, cleanup_has_run_root in cases:
            with self.subTest(path=name):
                jobs = _encrypted_jobs(platform="windows")
                by_name = {job["name"]: job for job in jobs}
                run_job = by_name[audit.PLATFORM_RUN_JOBS["windows"]]
                run_job["conclusion"] = "failure"
                failed_index = next(index for index, step in enumerate(run_job["steps"])
                                    if step["name"] == failed_step)
                for index, step in enumerate(run_job["steps"]):
                    if step["name"] == cleanup_step:
                        step["conclusion"] = "success"
                    elif index < failed_index:
                        step["conclusion"] = "success"
                    elif index == failed_index:
                        step["conclusion"] = "failure"
                    else:
                        step["conclusion"] = "skipped"
                reason = outputs[-2].split("=", 1)[1]
                log = _render_real_runner_encrypted_log(
                    identity,
                    early_failure={
                        "step": failed_step, "marker": outputs[-1], "outputs": outputs,
                        "cleanup_outputs": cleanup_outputs, "exit_code": 1,
                    },
                )
                run_root_env = (
                    "  RUN_ROOT: " + _env_value("RUN_ROOT", identity, "encrypted", "windows-2025")
                ).encode("utf-8")
                self.assertEqual(log.count(run_root_env), int(cleanup_has_run_root))
                if name == "initial-acl":
                    self.assertIn(b"windows_precheckout_cleanup=confirmed", log)
                    self.assertNotIn(b"windows_runner_shred=confirmed", log)
                    self.assertNotIn(b"windows_sandbox_cleanup=confirmed", log)
                    fabricated_shred = _insert_output_before(
                        log, "windows_precheckout_cleanup=confirmed",
                        "windows_runner_shred=confirmed files=1 bytes=1 reparse=0",
                    )
                    with self.assertRaises(audit.AuditRefusal):
                        audit.validate_job_log_surface(
                            fabricated_shred, audit.PLATFORM_RUN_JOBS["windows"], identity, completed=True,
                        )
                if name in ("later-target", "later-acl", "later-seal"):
                    self.assertIn(b"windows_runner_shred=confirmed files=1 bytes=8 reparse=0", log)
                surface = audit.validate_job_log_surface(
                    log, audit.PLATFORM_RUN_JOBS["windows"], identity, completed=True,
                )
                self.assertEqual(surface["early_failure"], failed_step)
                self.assertEqual(surface["early_failure_code"], "crypto-dependency-seal-failed")
                self.assertEqual(surface["crypto_refusal_reason"], reason)
                audit.validate_job_contract(jobs, identity, "core-node")
                audit.validate_job_log_metadata_binding(surface, run_job, identity)
                self.assertFalse(audit.validate_dispatch_marker(log, identity, allow_missing=True))
                if name == "later-acl":
                    missing_checkout = log.replace(
                        b"devlane_crypto_state=checkout-complete\n", b"", 1,
                    )
                    with self.assertRaises(audit.AuditRefusal):
                        audit.validate_job_log_surface(
                            missing_checkout, audit.WINDOWS_RUN_JOB, identity, completed=True,
                        )
                    wrong_step = audit._Grammar(
                        ".github/workflows/devlane-encrypted.yml", audit.WINDOWS_RUN_JOB,
                        identity, "encrypted",
                    )
                    self.assertFalse(wrong_step.step_output_ok(
                        "Prepare hosted Windows isolation state",
                        "devlane_crypto_refusal=crypto-acl-stdout-bom-or-whitespace", {},
                    ))
                    linux_identity = dict(IDENTITY, platform="linux")
                    linux = audit._Grammar(
                        ".github/workflows/devlane-encrypted.yml", audit.RUN_JOB,
                        linux_identity, "encrypted",
                    )
                    self.assertFalse(linux.step_output_ok(
                        failed_step, "devlane_crypto_refusal=crypto-acl-stdout-bom-or-whitespace", {},
                    ))

    def test_macos_and_windows_early_failures_are_audited_with_fixed_dispositions(self):
        scenarios = (
            ("macos", "Prepare hosted runner isolation state",
             "devlane_macos_preflight_refusal=macos-user-attribute-set", 2,
             "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
             "disposition=run-failed-at-macos-preflight"),
            ("linux", "Fetch public control and validate dispatch",
             "devlane_bootstrap_refusal=bootstrap-command-failed", 1,
             "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
             "disposition=run-failed-at-bootstrap"),
            ("macos", "Fetch public control and validate dispatch",
             "devlane_bootstrap_refusal=bootstrap-command-failed", 1,
             "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
             "disposition=run-failed-at-bootstrap"),
            ("windows", "Fetch public control and validate dispatch",
             "devlane_deadline_refusal=deadline-start-invalid", 1,
             "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
             "disposition=run-failed-at-bootstrap"),
            ("windows", "Prepare hosted Windows isolation state",
             "devlane_windows_preflight_refusal=windows-admin-required", 1,
             "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
             "disposition=run-failed-at-windows-preflight"),
        )
        for platform_name, failed_step, marker, exit_code, outcome in scenarios:
            with self.subTest(platform=platform_name):
                identity = dict(IDENTITY, platform=platform_name)
                jobs = _encrypted_jobs(platform=platform_name)
                by_name = {job["name"]: job for job in jobs}
                run_job = by_name[audit.PLATFORM_RUN_JOBS[platform_name]]
                run_job["conclusion"] = "failure"
                names = [step["name"] for step in run_job["steps"]]
                failed_index = names.index(failed_step)
                for index, step in enumerate(run_job["steps"]):
                    if step["name"] == "Shred runner-local workspace":
                        step["conclusion"] = "success"
                    elif step["name"] == "Install pinned Rust toolchain" and platform_name == "macos":
                        step["conclusion"] = "skipped"
                    elif index < failed_index:
                        step["conclusion"] = "success"
                    elif index == failed_index:
                        step["conclusion"] = "failure"
                    else:
                        step["conclusion"] = "skipped"
                audit_job = by_name[audit.AUDIT_JOB]

                logs = _render_real_runner_encrypted_log(
                    identity, early_failure={"step": failed_step, "marker": marker, "exit_code": exit_code},
                )
                surface = audit.validate_job_log_surface(logs, audit.PLATFORM_RUN_JOBS[platform_name], identity,
                                                          completed=True)
                self.assertEqual(surface["early_failure"], failed_step)
                audit.validate_job_log_metadata_binding(surface, run_job, identity)
                self.assertFalse(audit.validate_dispatch_marker(logs, identity, allow_missing=True))
                with self.assertRaises(audit.AuditRefusal):
                    audit.validate_job_log_surface(
                        _replace_output_line(logs, marker, "devlane_bootstrap_refusal=private-path"),
                        audit.PLATFORM_RUN_JOBS[platform_name], identity, completed=True,
                    )

                class API:
                    def __init__(self, candidate_jobs=None, candidate_log=None):
                        self.jobs = jobs if candidate_jobs is None else candidate_jobs
                        self.log = logs if candidate_log is None else candidate_log

                    def json(self, endpoint):
                        if endpoint.endswith("/actions/runs/" + identity["run_id"]):
                            repository = {"full_name": audit.REPOSITORY, "id": audit.REPOSITORY_ID}
                            return ({
                                "id": int(identity["run_id"]), "path": audit.WORKFLOW_PATH,
                                "event": "workflow_dispatch", "head_branch": "main",
                                "head_sha": identity["control_sha"], "run_attempt": 1,
                                "status": "in_progress", "conclusion": None,
                                "repository": repository, "head_repository": repository,
                            }, {})
                        if "/jobs?" in endpoint:
                            return ({"total_count": 4, "jobs": self.jobs}, {})
                        if "/artifacts?" in endpoint:
                            return ({"total_count": 0, "artifacts": []}, {})
                        return ({}, {})

                    def log_text(self, identifier):
                        self.assert_run_id = identifier
                        return self.log

                permit_key = "devlane-permit-v1-" + identity["bundle_id"]
                control_key = "devlane-control-v1-" + identity["control_run_id"]
                with patch.object(audit, "_fetch_cache_entries", return_value=[
                        {"key": permit_key, "size_in_bytes": 1}, {"key": control_key, "size_in_bytes": 1}]), \
                        patch.object(audit, "cache_inventory_digest", return_value=identity["cache_baseline_sha256"]), \
                        patch.object(audit, "validate_check_output"), \
                        patch.object(audit, "_read_annotations", return_value=[]):
                    self.assertEqual(audit.run_audit(API(), identity), outcome)
                    with self.assertRaises(audit.AuditRefusal):
                        audit.run_audit(API(_encrypted_jobs(platform=platform_name), logs), identity)
                terminal_jobs = copy.deepcopy(jobs)
                terminal_audit = next(job for job in terminal_jobs if job["name"] == audit.AUDIT_JOB)
                terminal_audit["status"] = "completed"
                terminal_audit["conclusion"] = "success"
                for step in terminal_audit["steps"]:
                    step.update({"status": "completed", "conclusion": "success"})
                _terminal, audit_passed = audit.validate_terminal_job_contract(
                    terminal_jobs, identity, "core-node",
                )
                self.assertTrue(audit_passed)
                for mutation in ("cleanup", "downstream", "failed-step"):
                    changed = copy.deepcopy(jobs)
                    changed_run = next(job for job in changed
                                       if job["name"] == audit.PLATFORM_RUN_JOBS[platform_name])
                    changed_steps = {step["name"]: step for step in changed_run["steps"]}
                    if mutation == "cleanup":
                        changed_steps["Shred runner-local workspace"]["conclusion"] = "failure"
                    elif mutation == "downstream":
                        changed_steps["Decrypt authenticated bundle"]["conclusion"] = "success"
                    else:
                        changed_steps[failed_step]["conclusion"] = "success"
                    with self.subTest(platform=platform_name, mutation=mutation), \
                            self.assertRaises(audit.AuditRefusal):
                        audit.validate_job_log_metadata_binding(surface, changed_run, identity)

    def test_new_platform_refusal_codes_keep_their_step_bound_failure_shapes(self):
        cases = [
            ("macos", "Prepare hosted runner isolation state",
             "devlane_macos_preflight_refusal=" + code, 2)
            for code in sorted(refusal_codes.MACOS_PREFLIGHT_REFUSAL_CODES)
        ]
        cases.extend(
            ("macos", "Prepare hosted runner isolation state",
             "devlane_macos_preflight_refusal=" + code, 2)
            for code in (
                "node-runtime-version-invalid", "npm-runtime-install-failed", "npm-runtime-version-invalid",
            )
        )
        cases.extend(
            ("windows", "Prepare hosted Windows isolation state",
             "devlane_windows_preflight_refusal=" + code, 1)
            for code in (
                "windows-node-runtime-invalid", "windows-npm-runtime-install-failed",
                "windows-npm-runtime-version-invalid",
            )
        )
        for platform_name in ("macos", "windows"):
            prefix = "devlane_bootstrap_refusal=" if platform_name == "macos" else "devlane_deadline_refusal="
            cases.extend(
                (platform_name, "Fetch public control and validate dispatch", prefix + code, 1)
                for code in (
                    "crypto-dependency-install-failed", "crypto-dependency-verification-failed",
                    "crypto-python-version-invalid", "crypto-dependency-seal-failed",
                    "crypto-dependency-check-failed",
                )
            )
        cases.append(("macos", "Fetch public control and validate dispatch",
                      "devlane_bootstrap_refusal=crypto-unavailable", 1))
        cases.append(("macos", "Fetch public control and validate dispatch",
                      "devlane_bootstrap_refusal=crypto-dependency-privileged-check-failed", 1))

        for platform_name, failed_step, marker, exit_code in cases:
            with self.subTest(platform=platform_name, marker=marker):
                identity = dict(IDENTITY, platform=platform_name)
                jobs = _encrypted_jobs(platform=platform_name)
                run_job = next(job for job in jobs
                               if job["name"] == audit.PLATFORM_RUN_JOBS[platform_name])
                run_job["conclusion"] = "failure"
                names = [step["name"] for step in run_job["steps"]]
                failed_index = names.index(failed_step)
                for index, step in enumerate(run_job["steps"]):
                    if step["name"] == "Shred runner-local workspace":
                        step["conclusion"] = "success"
                    elif step["name"] == "Install pinned Rust toolchain":
                        step["conclusion"] = "skipped"
                    elif step["name"] == "Install Tauri Linux build dependencies" and platform_name != "linux":
                        step["conclusion"] = "skipped"
                    elif index < failed_index:
                        step["conclusion"] = "success"
                    elif index == failed_index:
                        step["conclusion"] = "failure"
                    else:
                        step["conclusion"] = "skipped"
                marker_code = marker.split("=", 1)[1]
                crypto_reason = {
                    "crypto-dependency-seal-failed": "crypto-seal-write-failed",
                    "crypto-dependency-check-failed": "crypto-import-invalid",
                    "crypto-dependency-privileged-check-failed": "crypto-key-present",
                }.get(marker_code)
                outputs = (["devlane_crypto_refusal=" + crypto_reason] if crypto_reason else []) + [marker]
                log = _render_real_runner_encrypted_log(
                    identity, early_failure={
                        "step": failed_step, "marker": marker, "outputs": outputs, "exit_code": exit_code,
                    },
                )
                surface = audit.validate_job_log_surface(
                    log, audit.PLATFORM_RUN_JOBS[platform_name], identity, completed=True,
                )
                self.assertEqual(surface["early_failure"], failed_step)
                self.assertEqual(surface["early_failure_code"], marker.split("=", 1)[1])
                audit.validate_job_contract(jobs, identity, "core-node")
                audit.validate_job_log_metadata_binding(surface, run_job, identity)
                audit.validate_dispatch_marker(log, identity, allow_missing=surface["early_failure"] is not None)
                with self.assertRaises(audit.AuditRefusal):
                    audit.validate_job_log_surface(
                        _replace_output_line(log, marker, "devlane_bootstrap_refusal=private-path"),
                        audit.PLATFORM_RUN_JOBS[platform_name], identity, completed=True,
                    )
                changed = copy.deepcopy(run_job)
                changed_steps = {step["name"]: step for step in changed["steps"]}
                changed_steps["Shred runner-local workspace"]["conclusion"] = "failure"
                with self.assertRaises(audit.AuditRefusal):
                    audit.validate_job_log_metadata_binding(surface, changed, identity)

    def test_asset_fetch_refusals_are_fixed_and_step_bound_on_all_platforms(self):
        failed_step = "Fetch ciphertext and sanitized dependency projection"
        outcome = (
            "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
            "disposition=run-failed-at-asset-fetch"
        )
        for platform_name in ("linux", "macos", "windows"):
            identity = dict(IDENTITY, platform=platform_name)
            for code in sorted(audit.FETCH_REFUSAL_CODES):
                marker = "devlane_refusal=" + code
                with self.subTest(platform=platform_name, code=code):
                    jobs = _encrypted_jobs(platform=platform_name)
                    run_job = next(job for job in jobs
                                   if job["name"] == audit.PLATFORM_RUN_JOBS[platform_name])
                    run_job["conclusion"] = "failure"
                    names = [step["name"] for step in run_job["steps"]]
                    failed_index = names.index(failed_step)
                    for index, step in enumerate(run_job["steps"]):
                        if step["name"] == "Shred runner-local workspace":
                            step["conclusion"] = "success"
                        elif step["name"] == "Install pinned Rust toolchain" and platform_name == "macos":
                            step["conclusion"] = "skipped"
                        elif index < failed_index:
                            step["conclusion"] = "success"
                        elif index == failed_index:
                            step["conclusion"] = "failure"
                        else:
                            step["conclusion"] = "skipped"

                    log = _render_real_runner_encrypted_log(
                        identity, early_failure={"step": failed_step, "marker": marker, "exit_code": 2},
                    )
                    surface = audit.validate_job_log_surface(
                        log, audit.PLATFORM_RUN_JOBS[platform_name], identity, completed=True,
                    )
                    self.assertEqual(surface["early_failure"], failed_step)
                    self.assertEqual(surface["early_failure_code"], code)
                    audit.validate_job_log_metadata_binding(surface, run_job, identity)
                    self.assertEqual(audit._audit_outcome_line([run_job], identity), outcome)

                    for unknown in ("download-http-418", "private-path", "download-http-" + "9" * 48):
                        mutated = _replace_output_line(log, marker, "devlane_refusal=" + unknown)
                        with self.subTest(platform=platform_name, code=code, unknown=unknown), \
                                self.assertRaises(audit.AuditRefusal):
                            audit.validate_job_log_surface(
                                mutated, audit.PLATFORM_RUN_JOBS[platform_name], identity, completed=True,
                            )

    def test_saved_macos_round_three_log_audits_as_a_step_bound_preflight_failure(self):
        identity = dict(
            IDENTITY,
            control_sha="9fc48ebd432f104e7c12349358c260553077463d",
            run_id="43449960851", control_run_id="43449059870", platform="macos",
            runner="macos-15", wave_id="wave-20261113150525-73280748",
            bundle_id="bundle-20261113150525-f7b37b88",
            cache_baseline_sha256="0d3fc3aceee6b35f8dc244cabeac7e64bd35353e892dab7b1360fdd7f09235d7",
        )
        runner_marker = bytes((35, 35))
        refusal_line, exit_line, cleanup_line, completion_line = (
            b"2026-11-13T15:21:23.5486390Z devlane_macos_preflight_refusal=developer-dir-trust-invalid",
            b"2026-11-13T15:21:23.5665770Z " + runner_marker + b"[error]Process completed with exit code 2.",
            b"2026-11-13T15:21:25.1574690Z cleanup_receipt=confirmed",
            b"2026-11-13T15:21:25.1780190Z devlane_job=completed public_output=filtered cleanup=confirmed",
        )
        log = _render_real_runner_encrypted_log(
            identity, early_failure={
                "step": "Prepare hosted runner isolation state",
                "marker": "devlane_macos_preflight_refusal=developer-dir-trust-invalid", "exit_code": 2,
            },
        )
        log_rows = log.splitlines(keepends=True)
        input_start = next(index for index, line in enumerate(log_rows)
                           if line.rstrip().endswith(runner_marker + b"[group] Inputs"))
        input_end = next(index for index in range(input_start + 1, len(log_rows))
                         if log_rows[index].rstrip().endswith(runner_marker + b"[endgroup]"))
        del log_rows[input_start:input_end + 1]
        replacements = (
            (b"devlane_macos_preflight_refusal=developer-dir-trust-invalid", refusal_line),
            (runner_marker + b"[error]Process completed with exit code 2.", exit_line),
            (b"cleanup_receipt=confirmed", cleanup_line),
            (b"devlane_job=completed public_output=filtered cleanup=confirmed", completion_line),
        )
        for marker, actual_line in replacements:
            index = next(i for i, line in enumerate(log_rows) if line.rstrip().endswith(marker))
            log_rows[index] = actual_line + b"\n"
        log = b"".join(log_rows)

        jobs = _encrypted_jobs(platform="macos")
        for job in jobs:
            job["run_id"] = int(identity["run_id"])
            job["head_sha"] = identity["control_sha"]
        by_name = {job["name"]: job for job in jobs}
        run_job = by_name[audit.MACOS_RUN_JOB]
        run_job["conclusion"] = "failure"
        failure_index = next(i for i, step in enumerate(run_job["steps"])
                             if step["name"] == "Prepare hosted runner isolation state")
        for index, step in enumerate(run_job["steps"]):
            if step["name"] == "Shred runner-local workspace":
                step["conclusion"] = "success"
            elif step["name"] == "Install pinned Rust toolchain":
                step["conclusion"] = "skipped"
            elif index < failure_index:
                step["conclusion"] = "success"
            elif index == failure_index:
                step["conclusion"] = "failure"
            else:
                step["conclusion"] = "skipped"

        expected_outcome = (
            "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
            "disposition=run-failed-at-macos-preflight"
        )
        audit_log = _render_real_runner_encrypted_log(identity, job_key=audit.AUDIT_JOB)
        audit_log = audit_log.replace(
            b"devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed",
            expected_outcome.encode("ascii"), 1,
        )

        class API:
            def json(self, endpoint):
                if endpoint.endswith("/actions/runs/" + identity["run_id"]):
                    repository = {"full_name": audit.REPOSITORY, "id": audit.REPOSITORY_ID}
                    return ({
                        "id": int(identity["run_id"]), "path": audit.WORKFLOW_PATH,
                        "event": "workflow_dispatch", "head_branch": "main",
                        "head_sha": identity["control_sha"], "run_attempt": 1,
                        "status": "in_progress", "conclusion": None,
                        "repository": repository, "head_repository": repository,
                    }, {})
                if "/jobs?" in endpoint:
                    return ({"total_count": 4, "jobs": jobs}, {})
                if "/artifacts?" in endpoint:
                    return ({"total_count": 0, "artifacts": []}, {})
                return ({}, {})

            def log_text(self, identifier):
                return log if identifier == run_job["id"] else audit_log

        permit_key = "devlane-permit-v1-" + identity["bundle_id"]
        control_key = "devlane-control-v1-" + identity["control_run_id"]
        with patch.object(audit, "_fetch_cache_entries", return_value=[
                {"key": permit_key, "size_in_bytes": 1}, {"key": control_key, "size_in_bytes": 1}]), \
                patch.object(audit, "cache_inventory_digest", return_value=identity["cache_baseline_sha256"]), \
                patch.object(audit, "validate_check_output"), \
                patch.object(audit, "_read_annotations", return_value=[]):
            self.assertEqual(audit.run_audit(API(), identity), expected_outcome)

    def test_bootstrap_refusal_vocabulary_is_fixed_and_step_bound(self):
        identity = dict(IDENTITY, platform="linux")
        valid = _render_real_runner_encrypted_log(
            identity,
            early_failure={
                "step": "Fetch public control and validate dispatch",
                "marker": "devlane_bootstrap_refusal=bootstrap-command-failed", "exit_code": 1,
            },
        )
        result = audit.validate_job_log_surface(valid, audit.RUN_JOB, identity, completed=True)
        self.assertEqual(result["early_failure"], "Fetch public control and validate dispatch")
        for changed in (
            valid.replace(b"devlane_bootstrap_refusal=bootstrap-command-failed",
                          b"devlane_bootstrap_refusal=" + b"a" * 64, 1),
            valid.replace(b"devlane_bootstrap_refusal=bootstrap-command-failed",
                          b"devlane_bootstrap_refusal=private-path", 1),
        ):
            with self.subTest(marker=changed[:180]), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_surface(changed, audit.RUN_JOB, identity, completed=True)

        linux_crypto_failure = _render_real_runner_encrypted_log(
            identity,
            early_failure={
                "step": "Fetch public control and validate dispatch",
                "marker": "devlane_bootstrap_refusal=crypto-dependency-install-failed", "exit_code": 1,
            },
        )
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(linux_crypto_failure, audit.RUN_JOB, identity, completed=True)

        after_decrypt = _render_real_runner_encrypted_log(IDENTITY).replace(
            b"authenticated_decryption=pass\n",
            b"authenticated_decryption=pass\ndevlane_bootstrap_refusal=" + b"a" * 64 + b"\n", 1,
        )
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(after_decrypt, audit.RUN_JOB, IDENTITY, completed=True)

        windows_identity = dict(IDENTITY, platform="windows")
        windows_wrong_emitter = _render_real_runner_encrypted_log(
            windows_identity,
            early_failure={
                "step": "Fetch public control and validate dispatch",
                "marker": "devlane_bootstrap_refusal=bootstrap-command-failed", "exit_code": 1,
            },
        )
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(
                windows_wrong_emitter, audit.WINDOWS_RUN_JOB, windows_identity, completed=True,
            )

    def test_terminal_public_surface_rejects_success_graph_with_bootstrap_failure_log(self):
        identity = dict(IDENTITY, platform="windows")
        jobs = _encrypted_jobs(platform="windows")
        terminal_audit = next(job for job in jobs if job["name"] == audit.AUDIT_JOB)
        terminal_audit["status"] = "completed"
        terminal_audit["conclusion"] = "success"
        for step in terminal_audit["steps"]:
            step.update({"status": "completed", "conclusion": "success"})
        failed_log = _render_real_runner_encrypted_log(
            identity,
            early_failure={
                "step": "Fetch public control and validate dispatch",
                "marker": "devlane_deadline_refusal=deadline-start-invalid", "exit_code": 1,
            },
        )
        audit_log = _render_real_runner_encrypted_log(identity, job_key=audit.AUDIT_JOB)
        by_name = {job["name"]: job for job in jobs}
        logs = {by_name[audit.WINDOWS_RUN_JOB]["id"]: failed_log,
                by_name[audit.AUDIT_JOB]["id"]: audit_log}

        class API:
            def log_text(self, identifier):
                return logs[identifier]

            def json(self, endpoint):
                return ({}, {})

        with patch.object(audit, "_read_annotations", return_value=[]), \
                patch.object(audit, "validate_check_output"), self.assertRaises(audit.AuditRefusal):
            audit.validate_final_public_surfaces(API(), jobs, identity, "core-node")

    def test_desktop_contract_runs_tauri_dependencies_and_pinned_rust_setup(self):
        identity = dict(IDENTITY, profile="desktop")
        jobs = _encrypted_jobs("desktop")
        result = audit.validate_job_contract(jobs, identity, "desktop")
        self.assertEqual(set(result), set(audit.EXECUTION_JOBS) | {audit.AUDIT_JOB})
        grammar = audit._Grammar(
            ".github/workflows/devlane-encrypted.yml", audit.RUN_JOB, identity, "encrypted",
        )
        self.assertTrue(grammar.step_output_ok(
            "Install Tauri Linux build dependencies", "tauri_linux_dependencies=installed", {}))
        self.assertTrue(grammar.step_output_ok(
            "Install pinned Rust toolchain", "rust_toolchain=prepared", {}))

    def test_extra_job_wrong_attempt_wrong_step_and_missing_cleanup_are_rejected(self):
        mutations = []
        jobs = _encrypted_jobs()
        mutations.append(jobs + [dict(jobs[0], name="unexpected-job")])
        changed = copy.deepcopy(jobs)
        changed[1]["run_attempt"] = 2
        mutations.append(changed)
        changed = copy.deepcopy(jobs)
        changed[0]["steps"][0]["name"] = "Fetch PR source"
        mutations.append(changed)
        changed = copy.deepcopy(jobs)
        changed[0]["steps"][-2]["conclusion"] = "failure"
        mutations.append(changed)
        for mutation in mutations:
            with self.subTest(names=[job["name"] for job in mutation]):
                with self.assertRaises(audit.AuditRefusal):
                    audit.validate_job_contract(mutation, IDENTITY, "core-node")

    def test_log_marker_must_bind_one_wave_and_cleanup_receipt(self):
        log = (
            b"2026-11-10T12:00:00Z KD-DEVLANE-DISPATCH schema=1 wave-id=wave-test-0001 "
            b"bundle-id=bundle-test-0001 control-sha=" + SHA.encode("ascii")
            + b" run-id=12345 run-attempt=1\ndevlane_permit=consumed run-id=12345 run-attempt=1\ncleanup_receipt=confirmed\n"
        )
        audit.validate_dispatch_marker(log, IDENTITY)
        for changed in (log.replace(b"run-attempt=1", b"run-attempt=2"),
                        log.replace(b"cleanup_receipt=confirmed", b"cleanup_receipt=unconfirmed")):
            with self.assertRaises(audit.AuditRefusal):
                audit.validate_dispatch_marker(changed, IDENTITY)

    RECORDS = (
        _record(code="TS2322", file="file_0001", kind="diagnostic", level="error", line=7, stage="unit"),
        _record(kind="test", stage="unit", test="case_0001"),
    )

    def test_pinned_cache_action_zstd_without_long_commands_match_windows_and_macos(self):
        key = "devlane-permit-v1-bundle-test-0001"
        windows_lines = (
            MARK + '[command]"C:\\Program Files\\Git\\usr\\bin\\tar.exe" --posix -cf cache.tzst '
            + '--exclude cache.tzst -P -C D:/a/platform-ci/platform-ci --files-from manifest.txt '
            + '--force-local --use-compress-program "zstd -T0"',
            MARK + '[command]"C:\\Program Files\\Git\\usr\\bin\\tar.exe" -xf '
            + 'D:/a/_temp/01234567-89ab-cdef-0123-456789abcdef/cache.tzst -P -C D:/a/platform-ci/platform-ci '
            + '--force-local --use-compress-program "zstd -d"',
        )
        windows_patterns = audit.cache_line_patterns(key, audit.WINDOWS_TEMP, "windows")
        for line in windows_lines:
            with self.subTest(platform="windows", line=line):
                self.assertTrue(any(pattern.fullmatch(line) for pattern in windows_patterns))

        macos_lines = (
            MARK + "[command]" + audit.MACOS_GNU_TAR
            + " --posix -cf cache.tzst --exclude cache.tzst -P -C "
            + MACOS_WORKSPACE + " --files-from manifest.txt "
            + "--delay-directory-restore --use-compress-program zstdmt",
            MARK + "[command]" + audit.MACOS_GNU_TAR + " -xf "
            + MACOS_TMP + "/01234567-89ab-cdef-0123-456789abcdef/cache.tzst -P -C "
            + MACOS_WORKSPACE + " --delay-directory-restore "
            + "--use-compress-program unzstd",
        )
        macos_patterns = audit.cache_line_patterns(key, audit.MACOS_TEMP, "macos")
        for line in macos_lines:
            with self.subTest(platform="macos", line=line):
                self.assertTrue(any(pattern.fullmatch(line) for pattern in macos_patterns))

    def test_windows_runner_temp_input_accepts_the_real_mixed_slash_interpolation(self):
        grammar = audit._Grammar(
            ".github/workflows/devlane-encrypted.yml", audit.WINDOWS_RUN_JOB,
            dict(IDENTITY, platform="windows"), "encrypted",
        )
        step = {
            "name": "Restore one-run bundle permit", "uses": "actions/cache/restore@pinned",
            "with": {"path": "${{ runner.temp }}/devlane-bundle-permit/permit.json"},
        }
        self.assertTrue(grammar.with_value_ok(
            step, "path", r"D:\a\_temp/devlane-bundle-permit/permit.json"))
        self.assertFalse(grammar.with_value_ok(
            step, "path", r"E:\a\_temp/devlane-bundle-permit/permit.json"))

    def _valid_run_log(self, records=None):
        return _render_log(audit.RUN_JOB, records=self.RECORDS if records is None else records)

    def test_ordinary_hosted_scaffolding_with_a_valid_summary_is_accepted(self):
        """Fails on the old auditor, which rejected env blocks, cache action output and provider notices that every normal Actions run prints."""
        result = audit.validate_job_log_surface(self._valid_run_log(), audit.RUN_JOB, IDENTITY)
        self.assertEqual(len(result["records"]), 2)
        audit.validate_job_log_surface(
            _render_log(audit.AUDIT_JOB), audit.AUDIT_JOB, IDENTITY)
        rust = dict(IDENTITY, profile="core-rust")
        audit.validate_job_log_surface(
            _render_log(audit.RUN_JOB, rust, skip=("Set up pinned Node toolchain",)), audit.RUN_JOB, rust)
        desktop = dict(IDENTITY, profile="desktop")
        audit.validate_job_log_surface(
            _render_log(audit.RUN_JOB, desktop), audit.RUN_JOB, desktop)
        macos = dict(IDENTITY, platform="macos")
        audit.validate_job_log_surface(
            _render_log(audit.MACOS_RUN_JOB, macos), audit.MACOS_RUN_JOB, macos)

    def test_known_github_sgr_is_accepted_on_the_encrypted_lane_log_path(self):
        log = self._valid_run_log()
        colored = log.replace(
            b"Run set -euo pipefail",
            b"Run \x1b[36;1mset -euo pipefail\x1b[0m",
            1,
        )
        audit.validate_job_log_surface(colored, audit.RUN_JOB, IDENTITY)
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(colored.replace(b"set -euo pipefail", b"set \x1b[2J -euo pipefail", 1),
                                           audit.RUN_JOB, IDENTITY)

    def test_github_runner_shaped_encrypted_log_accepts_its_environment_and_sgr(self):
        log = _render_real_runner_encrypted_log(IDENTITY)
        audit.validate_job_log_surface(log, audit.RUN_JOB, IDENTITY)
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(log.replace(b"\x1b[36;1m", b"\x1b[31m", 1),
                                           audit.RUN_JOB, IDENTITY)

    def test_unreviewed_pythonpath_is_rejected_from_macos_and_windows_job_environments(self):
        platform_cases = (
            ("macos", audit.MACOS_RUN_JOB, MACOS_TMP + "/devlane-12345/control-python-deps"),
            ("windows", audit.WINDOWS_RUN_JOB, audit.WINDOWS_TEMP + r"\devlane-12345\control-python-deps"),
        )
        stamp = b"2026-11-10T12:00:00.1234567Z "
        for platform_name, job_key, target in platform_cases:
            identity = dict(IDENTITY, platform=platform_name)
            log = _render_log(job_key, identity)
            anchor = stamp + b"env:\n"
            self.assertIn(anchor, log)
            mutation = log.replace(anchor, anchor + stamp + b"  PYTHONPATH: " + target.encode("utf-8") + b"\n", 1)
            with self.subTest(platform=platform_name), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_surface(mutation, job_key, identity)

    def test_real_encrypted_rehearsal_logs_and_two_job_graph_match_github_output(self):
        fixtures = Path(__file__).resolve().parent / "fixtures"
        identity = json.loads((fixtures / "encrypted-run-43284558151-identity.json").read_text(
            encoding="utf-8"))
        run_log = bytes.fromhex((fixtures / "encrypted-run-43284558151.log.hex").read_text(
            encoding="ascii"))
        audit_log = bytes.fromhex((fixtures / "encrypted-audit-43284558151.log.hex").read_text(
            encoding="ascii"))
        run_result = audit.validate_job_log_surface(run_log, audit.RUN_JOB, identity, completed=True)
        self.assertEqual(run_result["records"], [])
        audit.validate_dispatch_marker(run_log, identity)
        stage_diagnostic_log = run_log.replace(
            b"devlane_supervisor_refusal=network-probe-command-failed\n",
            b"network_probe_refusal=probe-stage-failed\n"
            b"devlane_supervisor_refusal=network-probe-stage-failed\n",
            1,
        )
        audit.validate_job_log_surface(stage_diagnostic_log, audit.RUN_JOB, identity, completed=True)

        run_jobs = json.loads(bytes.fromhex(
            (fixtures / "encrypted-run-43284558151-jobs.json.hex").read_text(
                encoding="ascii"),
        ).decode("utf-8"))["jobs"]
        jobs, audit_passed = audit.validate_terminal_job_contract(run_jobs, identity, "core-node")
        self.assertFalse(audit_passed)
        run_job = jobs[audit.RUN_JOB]
        audit_job = jobs[audit.AUDIT_JOB]
        step_by_name = {step["name"]: step for step in run_job["steps"]}
        self.assertEqual(run_job["conclusion"], "failure")
        self.assertEqual(step_by_name["Probe isolation before decryption"]["conclusion"], "failure")
        self.assertEqual(step_by_name["Decrypt authenticated bundle"]["conclusion"], "skipped")
        self.assertEqual(step_by_name["Execute offline profile and filter public summary"]["conclusion"], "skipped")
        self.assertEqual(step_by_name["Shred runner-local workspace"]["conclusion"], "success")
        self.assertEqual(audit_job["conclusion"], "failure")
        self.assertEqual(audit_job["steps"][-2]["conclusion"], "failure")
        inconsistent_audit_jobs = copy.deepcopy(run_jobs)
        inconsistent_audit_jobs[1]["conclusion"] = "success"
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_terminal_job_contract(inconsistent_audit_jobs, identity, "core-node")

        raw_audit = audit_log.decode("utf-8-sig")
        for sequence in audit.ANSI_SGR:
            raw_audit = raw_audit.replace(sequence.decode("ascii"), "")
        audit_lines = [audit.TIME_PREFIX.sub("", line, count=1).rstrip() for line in raw_audit.splitlines()]
        workflow_path = audit.REPOSITORY_ROOT / audit.LEGACY_ENCRYPTED_WORKFLOW_PATH
        grammar = audit._Grammar(workflow_path, audit.AUDIT_JOB, identity, "encrypted")
        _canonical, position = audit._hosted_preamble(
            audit_lines, grammar, audit.AUDIT_JOB, identity, str(workflow_path),
        )
        self.assertTrue(audit_lines[position].startswith(audit.LOG_MARKER + "[group]Run "))
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(audit_log, audit.AUDIT_JOB, identity, completed=True)

        success_log = _render_real_runner_encrypted_log(IDENTITY)
        success_audit_log = _render_real_runner_encrypted_log(IDENTITY, job_key=audit.AUDIT_JOB)
        audit.validate_job_log_surface(success_log, audit.RUN_JOB, IDENTITY, completed=True)
        audit.validate_job_log_surface(success_audit_log, audit.AUDIT_JOB, IDENTITY, completed=True)
        success_jobs = _encrypted_jobs()
        success_jobs[1]["status"] = "completed"
        success_jobs[1]["conclusion"] = "success"
        success_jobs[1]["steps"][-2].update({"status": "completed", "conclusion": "success"})
        success_jobs[1]["steps"][-1].update({"status": "completed", "conclusion": "success"})
        _success_by_name, success_audit_passed = audit.validate_terminal_job_contract(
            success_jobs, IDENTITY, "core-node",
        )
        self.assertTrue(success_audit_passed)

        for label, changed in (
                ("free text", run_log.replace(b"devlane_swap=disabled",
                                               b"devlane_swap=disabled\nfree text injected", 1)),
                ("path", run_log.replace(
                    b"devlane_swap=disabled",
                    b"devlane_swap=disabled\n" + bytes((47,)).join(
                        (b"home", b"runner", b"work", b"foreign", b"private"),
                    ), 1)),
                ("unknown escape", run_log.replace(b"devlane_swap=disabled",
                                                    b"devlane_swap=disabled\x1b[2J", 1)),
                ("wrong process exit code", run_log.replace(
                    b"Process completed with exit code 2.",
                    b"Process completed with exit code 3.", 1)),
                ("missing process exit code", run_log.replace(
                    audit.LOG_MARKER.encode("ascii") + b"[error]Process completed with exit code 2.\n",
                    b"", 1)),
                ("mismatched probe diagnosis", run_log.replace(
                    b"devlane_supervisor_refusal=network-probe-command-failed",
                    b"network_probe_refusal=probe-command-failed\n"
                    b"devlane_supervisor_refusal=network-probe-output-invalid", 1))):
            with self.subTest(label=label), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_surface(changed, audit.RUN_JOB, identity, completed=True)

    def test_real_decrypt_rejection_logs_match_the_failed_at_decrypt_job_shape(self):
        fixtures = Path(__file__).resolve().parent / "fixtures"
        suffix = "43296698158"
        identity = json.loads((fixtures / ("encrypted-run-" + suffix + "-identity.json")).read_text(
            encoding="utf-8"))
        run_log = bytes.fromhex((fixtures / ("encrypted-run-" + suffix + ".log.hex")).read_text(
            encoding="ascii"))
        audit_log = bytes.fromhex((fixtures / ("encrypted-audit-" + suffix + ".log.hex")).read_text(
            encoding="ascii"))
        run_result = audit.validate_job_log_surface(run_log, audit.RUN_JOB, identity, completed=True)
        self.assertEqual(run_result["records"], [])
        audit.validate_dispatch_marker(run_log, identity)

        jobs = json.loads(bytes.fromhex(
            (fixtures / ("encrypted-run-" + suffix + "-jobs.json.hex")).read_text(encoding="ascii"),
        ).decode("utf-8"))["jobs"]
        by_name, audit_passed = audit.validate_terminal_job_contract(jobs, identity, "core-node")
        run_job = by_name[audit.RUN_JOB]
        audit_job = by_name[audit.AUDIT_JOB]
        steps = {step["name"]: step for step in run_job["steps"]}
        self.assertEqual(run_job["conclusion"], "failure")
        self.assertEqual(steps["Probe isolation before decryption"]["conclusion"], "success")
        self.assertEqual(steps["Decrypt authenticated bundle"]["conclusion"], "failure")
        self.assertEqual(steps["Execute offline profile and filter public summary"]["conclusion"], "skipped")
        self.assertEqual(steps["Shred runner-local workspace"]["conclusion"], "success")
        self.assertEqual(audit_job["conclusion"], "failure")
        self.assertFalse(audit_passed)
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(audit_log, audit.AUDIT_JOB, identity, completed=True)

        replay_jobs = copy.deepcopy(jobs)
        replay_audit_job = next(job for job in replay_jobs if job["name"] == audit.AUDIT_JOB)
        replay_audit_job["status"] = "in_progress"
        replay_audit_job["conclusion"] = None
        replay_audit_job["steps"][-2].update({"status": "in_progress", "conclusion": None})
        replay_audit_job["steps"][-1].update({"status": "pending", "conclusion": None})

        class API:
            def json(self, endpoint):
                if endpoint.endswith("/actions/runs/" + identity["run_id"]):
                    repository = {"full_name": audit.REPOSITORY, "id": audit.REPOSITORY_ID}
                    return ({
                        "id": int(identity["run_id"]), "path": audit.WORKFLOW_PATH,
                        "event": "workflow_dispatch", "head_branch": "main",
                        "head_sha": identity["control_sha"], "run_attempt": 1,
                        "status": "in_progress", "conclusion": None,
                        "repository": repository, "head_repository": repository,
                    }, {})
                if "/jobs?" in endpoint:
                    return ({"total_count": 2, "jobs": replay_jobs}, {})
                if "/artifacts?" in endpoint:
                    return ({"total_count": 0, "artifacts": []}, {})
                return ({}, {})

            def log_text(self, _identifier):
                return run_log

        permit_key = "devlane-permit-v1-" + identity["bundle_id"]
        control_key = "devlane-control-v1-" + identity["control_run_id"]
        with patch.object(audit, "_fetch_cache_entries", return_value=[
                {"key": permit_key, "size_in_bytes": 1}, {"key": control_key, "size_in_bytes": 1}]), \
                patch.object(audit, "cache_inventory_digest", return_value=identity["cache_baseline_sha256"]), \
                patch.object(audit, "validate_check_output"), \
                patch.object(audit, "_read_annotations", return_value=[]):
            self.assertEqual(
                audit.run_audit(API(), identity),
                "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
                "disposition=run-failed-at-decrypt",
            )

        reasoned_log = run_log.replace(
            b"devlane_supervisor_refusal=decrypt-rejected",
            b"devlane_supervisor_refusal=decrypt-rejected\n"
            b"2026-11-12T20:05:19.9416693Z decrypt_refusal=decrypt-failed",
            1,
        )
        audit.validate_job_log_surface(reasoned_log, audit.RUN_JOB, identity, completed=True)
        invalid_reason = reasoned_log.replace(b"decrypt_refusal=decrypt-failed", b"decrypt_refusal=source-bytes", 1)
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(invalid_reason, audit.RUN_JOB, identity, completed=True)

        success_log = _render_real_runner_encrypted_log(IDENTITY)
        audit.validate_job_log_surface(success_log, audit.RUN_JOB, IDENTITY, completed=True)
    def test_macos_runner_shaped_log_from_public_control_preamble_is_accepted_and_closed(self):
        identity = dict(IDENTITY, platform="macos")
        jobs = _encrypted_jobs(platform="macos")
        audit.validate_job_contract(jobs, identity, "core-node")
        log = _render_real_runner_encrypted_log(identity)
        self.assertIn(
            (MARK + "[command]/usr/bin/tar xz --strip 1 -C " + MACOS_TMP
             + "/01234567-89ab-cdef-0123-456789abcdef -f " + MACOS_TMP
             + "/fedcba98-7654-3210-fedc-ba9876543210").encode(),
            log,
        )
        self.assertNotIn(b"\nFinished\n", log)
        audit.validate_job_log_surface(log, audit.MACOS_RUN_JOB, identity)
        audit_log = _render_real_runner_encrypted_log(identity, job_key=audit.AUDIT_JOB)
        audit.validate_job_log_surface(audit_log, audit.AUDIT_JOB, identity)
        self.assertIn(b"Ubuntu2404-Readme.md", audit_log)
        self.assertNotIn(b"macos-15-arm64-Readme.md", audit_log)
        wrong_audit_image = audit_log.replace(b"ubuntu24/20261101.360/images/ubuntu/Ubuntu2404-Readme.md",
                                               b"macos-15-arm64/20261104.0514/images/macos/macos-15-arm64-Readme.md")
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(wrong_audit_image, audit.AUDIT_JOB, identity)
        changed = log.replace(b"Cloud: MacCloud", b"Cloud: Azure", 1)
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(changed, audit.MACOS_RUN_JOB, identity)
        for changed in (
            log.replace(b"tar xz --strip 1 -C", b"tar xz --strip 2 -C", 1),
            log.replace(b"tar xz --strip 1 -C", b"tar xz --strip 1 --overwrite -C", 1),
            log.replace(b"/usr/bin/tar xz --strip 1", b"/opt/homebrew/bin/gtar xz --strip 1", 1),
            log.replace(b"/work/_temp/01234567-89ab-cdef-0123-456789abcdef -f",
                        b"/tmp/01234567-89ab-cdef-0123-456789abcdef -f", 1),
        ):
            with self.subTest(mutation=changed[:200]), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_surface(changed, audit.MACOS_RUN_JOB, identity)
        long_mode = log.replace(b"--use-compress-program zstdmt", b"--use-compress-program zstdmt --long=30", 1)
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(long_mode, audit.MACOS_RUN_JOB, identity)

    def test_windows_four_job_graph_and_pinned_cache_command_grammar(self):
        identity = dict(IDENTITY, platform="windows")
        jobs = _encrypted_jobs(platform="windows")
        by_name = audit.validate_job_contract(jobs, identity, "core-node")
        self.assertEqual(set(by_name), set(audit.EXECUTION_JOBS) | {audit.AUDIT_JOB})
        skipped = [job for job in jobs if job["name"] in audit.EXECUTION_JOBS
                   and job["name"] != audit.WINDOWS_RUN_JOB]
        self.assertEqual(len(skipped), 2)
        self.assertTrue(all(job["conclusion"] == "skipped" for job in skipped))
        log = _render_real_runner_encrypted_log(identity)
        result = audit.validate_job_log_surface(log, audit.WINDOWS_RUN_JOB, identity, completed=True)
        self.assertEqual(result["records"], [])
        self.assertIn(b"tar.exe", log)
        audit.validate_job_log_surface(log.replace(b"\n", b"\r\n"), audit.WINDOWS_RUN_JOB,
                                       identity, completed=True)
        audit_log = _render_real_runner_encrypted_log(identity, job_key=audit.AUDIT_JOB)
        audit.validate_job_log_surface(audit_log, audit.AUDIT_JOB, identity, completed=True)
        for changed in (
            log.replace(b"D:/a/platform-ci/platform-ci", b"D:/a/foreign/platform-ci", 1),
            log.replace(b"C:\\Program Files\\Git\\usr\\bin\\tar.exe", b"C:\\Windows\\System32\\tar.exe", 1),
            log.replace(b"--force-local --use-compress-program", b"--checkpoint-action=exec=bad --force-local --use-compress-program", 1),
            log.replace(b'--use-compress-program "zstd -T0"',
                        b'--use-compress-program "zstd -T0 --long=30"', 1),
        ):
            with self.subTest(mutation=changed[:100]), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_surface(changed, audit.WINDOWS_RUN_JOB, identity, completed=True)

    def test_dispatch_identity_maps_platform_to_the_reviewed_job_and_runner(self):
        for platform in ("linux", "macos", "windows"):
            identity = dict(IDENTITY, platform=platform)
            jobs = _encrypted_jobs(platform=platform)
            by_name = audit.validate_job_contract(jobs, identity, "core-node")
            active = by_name[audit.PLATFORM_RUN_JOBS[platform]]
            self.assertEqual(active["labels"], [audit.PLATFORM_RUNNERS[platform]])
            self.assertEqual(sum(job["conclusion"] == "skipped" for job in jobs), 2)
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_contract(_encrypted_jobs(), identity, "core-node")

    def test_real_github_synthetic_log_fixture_is_accepted_and_closed(self):
        fixture = Path(__file__).resolve().parent / "fixtures/control-synthetic-43245798187.log.hex"
        log = bytes.fromhex(fixture.read_text(encoding="ascii"))
        identity = {
            "run_id": "43245798187",
            "control_sha": "bda18e03c451a00ec91bb7c34d616a55295a7eee",
            "ref": "refs/heads/devlane/d211-1110",
            "wave_id": "control-20261112T151518Z-082fe3",
        }
        self.assertEqual(
            audit._legacy_synthetic_workflow_path(identity),
            audit.LEGACY_SYNTHETIC_WORKFLOW_PATH,
        )
        audit.validate_job_log_surface(log, "devlane-synthetic", identity, workflow="synthetic")
        mutations = {
            "free text": log.replace(
                b"devlane_swap=disabled",
                b"devlane_swap=disabled\nfree text injected",
                1,
            ),
            "path": log.replace(
                b"devlane_swap=disabled",
                b"devlane_swap=disabled\n" + (chr(47) + "home" + chr(47) + "runner/work/foreign/private").encode("ascii"),
                1,
            ),
            "unknown escape": log.replace(
                b"devlane_swap=disabled",
                b"devlane_swap=disabled\x1b[2J",
                1,
            ),
        }
        for label, changed in mutations.items():
            with self.subTest(label), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_surface(changed, "devlane-synthetic", identity, workflow="synthetic")

        local_sync = dict(IDENTITY, profile="local-sync-rust")
        profile = json.loads((Path(__file__).resolve().parents[2] / "ci/devlane-profiles.json").read_text())[
            "profiles"]["local-sync-rust"]
        rows = [
            _record(kind="coverage", stage=stage, suite=suite,
                    total=1, passed=1, failed=0, ignored=0)
            for suite in profile["rust_matrix"]["coverage_ids"]
            for stage in ["format" if suite.startswith("fmt-") else "audit" if suite.startswith("audit-") else "unit"]
        ]
        rows.sort()
        audit.validate_job_log_surface(
            _render_log(audit.RUN_JOB, local_sync, records=rows), audit.RUN_JOB, local_sync)

    def test_host_preflight_receipts_are_bound_to_the_right_step_and_profile(self):
        rust = dict(IDENTITY, profile="core-rust")
        grammar = audit._Grammar(
            ".github/workflows/devlane-encrypted.yml", audit.RUN_JOB, rust, "encrypted",
        )
        counts = {}
        step = "Prepare hosted Linux isolation state"
        self.assertTrue(grammar.step_output_ok(step, "devlane_swap=disabled", counts))
        mac = audit._Grammar(
            ".github/workflows/devlane-encrypted.yml", audit.MACOS_RUN_JOB,
            dict(IDENTITY, platform="macos"), "encrypted",
        )
        mac_step = "Prepare hosted runner isolation state"
        self.assertTrue(mac.step_output_ok(mac_step, "devlane_macos=preflight-ready", {}))
        self.assertFalse(mac.step_output_ok(mac_step, "devlane_swap=disabled", {}))
        self.assertTrue(grammar.step_output_ok(step, "devlane_cgroup_v2=ready", counts))
        self.assertFalse(grammar.step_output_ok(step, "devlane_cgroup_v2=ready", counts))
        self.assertFalse(grammar.step_output_ok("Probe isolation before decryption", "devlane_swap=disabled", {}))
        node = audit._Grammar(
            ".github/workflows/devlane-encrypted.yml", audit.RUN_JOB, IDENTITY, "encrypted",
        )
        self.assertFalse(node.step_output_ok(step, "devlane_cgroup_v2=ready", {}))
        synthetic_identity = dict(IDENTITY, ref="refs/heads/devlane/d211-1110")
        synthetic = audit._Grammar(
            ".github/workflows/devlane-synthetic.yml", "devlane-synthetic", synthetic_identity, "synthetic",
        )
        self.assertTrue(synthetic.step_output_ok(step, "devlane_swap=disabled", {}))
        self.assertTrue(synthetic.step_output_ok("Prepare hosted Linux isolation state", "devlane_swap=disabled", {}))
        self.assertFalse(synthetic.step_output_ok(step, "devlane_cgroup_v2=ready", {}))

    def test_environment_lines_are_accepted_only_for_the_reviewed_environment_and_job(self):
        log = self._valid_run_log().decode("utf-8")
        anchor = "Secret source: Actions\n"
        stamp = "2026-11-10T12:00:00.1234567Z "
        self.assertIn(anchor, log.replace(stamp + "Secret source: Actions\n", anchor))
        def with_line(text, line):
            return text.replace(stamp + "Secret source: Actions\n", stamp + "Secret source: Actions\n" + stamp + line + "\n", 1).encode("utf-8")
        audit.validate_job_log_surface(with_line(log, "Environment: devlane-decrypt"), audit.RUN_JOB, IDENTITY)
        audit.validate_job_log_surface(with_line(log, "Deployment environment: devlane-decrypt"), audit.RUN_JOB, IDENTITY)
        for refused in ("Environment: production", "Deployment environment: devlane-decrypt-2", "Environment: devlane-decrypt extra"):
            with self.subTest(line=refused), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_surface(with_line(log, refused), audit.RUN_JOB, IDENTITY)
        audit_log = _render_log(audit.AUDIT_JOB).decode("utf-8")
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(with_line(audit_log, "Environment: devlane-decrypt"), audit.AUDIT_JOB, IDENTITY)
        synthetic = _render_log("devlane-synthetic", dict(IDENTITY), kind="synthetic").decode("utf-8")
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(with_line(synthetic, "Environment: devlane-decrypt"), "devlane-synthetic",
                                           dict(IDENTITY), workflow="synthetic")

    def test_auditor_refuses_a_workflow_that_loses_or_changes_the_environment(self):
        import tempfile
        log = self._valid_run_log()
        source = (self.root_for_tests() / ".github/workflows/devlane-encrypted.yml").read_text(encoding="utf-8")
        for name, broken in (("lost", source.replace("    environment: devlane-decrypt\n", "")),
                             ("renamed", source.replace("environment: devlane-decrypt", "environment: other-environment"))):
            with self.subTest(change=name), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary) / ".github/workflows/devlane-encrypted.yml"
                target.parent.mkdir(parents=True)
                target.write_text(broken, encoding="utf-8")
                with patch.object(audit, "REPOSITORY_ROOT", Path(temporary)), self.assertRaises(audit.AuditRefusal):
                    audit.validate_job_log_surface(log, audit.RUN_JOB, IDENTITY)

    @staticmethod
    def root_for_tests():
        return Path(__file__).resolve().parents[2]

    def test_closed_public_log_rejects_disguised_plaintext_and_excess_records(self):
        valid = self._valid_run_log()
        stamp = b"2026-11-10T12:00:00.1234567Z "
        tool_line = b"dependency_preparation=complete"
        mutations = {
            "canary in preparation output": valid.replace(
                tool_line, b"dependency_preparation=complete /PRIVATE_SOURCE_CANARY/PRIVATE_KEY_CANARY"),
            "plaintext line": valid + stamp + b"PRIVATE_SOURCE_CANARY=unfiltered-plaintext\n",
            "plaintext inside a step": valid.replace(
                b"dependency_preparation=complete", b"dependency_preparation=complete\n" + stamp + b"PRIVATE_SOURCE_CANARY"),
            "foreign env value": valid.replace(b"CI_RUN_ATTEMPT: 1", b"CI_RUN_ATTEMPT: PRIVATE_SOURCE_CANARY", 1),
            "unknown env name": valid.replace(b"CI_RUN_ATTEMPT: 1", b"PRIVATE_SOURCE_CANARY: 1", 1),
            "wrong cache key": valid.replace(b"Cache saved with key: devlane-permit-v1-bundle-test-0001",
                                             b"Cache saved with key: devlane-permit-v1-PRIVATE_SOURCE_CANARY"),
            "record outside the execute step": valid.replace(
                b"authenticated_decryption=pass", b"authenticated_decryption=pass\n" + stamp + self.RECORDS[1].encode()),
            "bad diagnostic code": self._valid_run_log([self.RECORDS[0].replace("TS2322", "DEVLANE_PRIVATE_SOURCE"),
                                                         self.RECORDS[1]]),
            "private file id": self._valid_run_log([self.RECORDS[0].replace("file_0001", "private/path.rs"),
                                                     self.RECORDS[1]]),
            "free-text record field": self._valid_run_log([self.RECORDS[0].replace('"line":7', '"message":"source"'),
                                                            self.RECORDS[1]]),
            "section injection": valid + stamp + (MARK + "[section]PRIVATE_SOURCE_CANARY\n").encode(),
            "group injection": valid + stamp + (MARK + "[group]PRIVATE_SOURCE_CANARY\n").encode(),
            "workflow command": valid + stamp + b"::add-mask::PRIVATE_SOURCE_CANARY\n",
            "orphan process line": valid.replace(b"Cleaning up orphan processes",
                                                 b"Terminate orphan process: pid 12 (private)"),
            "unsorted records": self._valid_run_log(list(reversed(self.RECORDS))),
            "duplicate records": self._valid_run_log([self.RECORDS[1], self.RECORDS[1]]),
            "marker printed twice": valid.replace(
                b"authenticated_decryption=pass", b"authenticated_decryption=pass\n" + stamp + b"authenticated_decryption=pass"),
        }
        for label, payload in mutations.items():
            with self.subTest(label), self.assertRaises(audit.AuditRefusal):
                audit.validate_job_log_surface(payload, audit.RUN_JOB, IDENTITY)

    def test_the_summary_is_validated_as_one_unit_not_record_by_record(self):
        """Fails on the old auditor: 101 individually valid records passed."""
        many = [_record(kind="test", stage="unit", test="case_%04d" % index) for index in range(1, 102)]
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(self._valid_run_log(many), audit.RUN_JOB, IDENTITY)
        within = [_record(kind="test", stage="unit", test="case_%04d" % index) for index in range(1, 101)]
        audit.validate_job_log_surface(self._valid_run_log(within), audit.RUN_JOB, IDENTITY)
        unknown_stage = [_record(kind="control", stage="cleanup", status="fail")]
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_job_log_surface(self._valid_run_log(unknown_stage), audit.RUN_JOB,
                                           dict(IDENTITY, profile="core-node") | {"profile": "core-bad"})

    def test_completed_check_output_accepts_documented_fields_and_rejects_text(self):
        job = _encrypted_jobs()[0]
        check = {
            "head_sha": SHA, "name": audit.RUN_JOB, "status": "completed",
            "output": {
                "title": None, "summary": None, "text": None, "annotations_count": 0,
                "annotations_url": "https://api.github.com/repos/keeldock-platform/platform-ci/check-runs/500/annotations",
            },
        }
        audit.validate_check_output(check, job, IDENTITY, completed=True)
        audit.validate_check_output({**check, "output": {**check["output"], "title": audit.RUN_JOB}},
                                    job, IDENTITY, completed=True)
        for changed in (
            {**check, "output": {**check["output"], "summary": "PRIVATE_SOURCE_CANARY"}},
            {**check, "output": {**check["output"], "text": "unexpected diagnostic text"}},
            {**check, "output": {**check["output"], "annotations_count": 1}},
            {**check, "output": {**check["output"], "annotations_url": "https://example.invalid/x"}},
            {**check, "output": {**check["output"], "unexpected": 1}},
        ):
            with self.subTest(changed=changed["output"]), self.assertRaises(audit.AuditRefusal):
                audit.validate_check_output(changed, job, IDENTITY, completed=True)

    def test_synthetic_job_log_satisfies_the_same_closed_contract_in_the_control(self):
        identity = {"run_id": "12345", "control_sha": SHA, "ref": "refs/heads/devlane/d211-1110"}
        log_identity = dict(IDENTITY)
        log_identity["ref"] = identity["ref"]
        log = _render_log("devlane-synthetic", log_identity, kind="synthetic",
                          skip=("Install fixed Rust acceptance toolchain",))
        control_audit.validate_synthetic_log(log, identity)
        workflow_group = (chr(35) * 2 + "[group]KEYCANARY-73A10X\n").encode("ascii")
        failure_lines = acceptance_diagnostics.failure_tail(
            "production-path-e2e", b"\x1b[31mFAILED::error::SYNTHETIC_SOURCE_CANARY_7f8c\n" + workflow_group,
        )
        failure = "devlane_acceptance=refused stage=production-path-e2e\n" + "\n".join(failure_lines)
        before, after = log.rsplit(b"devlane_acceptance=pass", 1)
        refused = before + failure.encode("ascii") + after.replace(
            b"2026-11-10T12:00:00.1234567Z devlane_linux_probe=pass\n", b"",
        )
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_synthetic_log(refused, identity)
        control_audit.validate_synthetic_log(refused, identity, failed_acceptance=True)
        wrong_stage = refused.replace(
            b"devlane_acceptance_detail stage=production-path-e2e",
            b"devlane_acceptance_detail stage=rust-v2-public-runtime", 1,
        )
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_synthetic_log(wrong_stage, identity, failed_acceptance=True)
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_synthetic_log(
                log, {**identity, "ref": "refs/heads/main"},
            )
        for label, payload in {
            "canary": log + b"2026-11-10T12:00:00.1234567Z PRIVATE_SOURCE_CANARY\n",
            "noisy test output": log.replace(b"devlane_acceptance=pass", b"Ran 31 tests in 1.2s\nOK\ndevlane_acceptance=pass"),
            "missing probe": log.replace(b"devlane_linux_probe=pass", b"devlane_linux_probe=skipped"),
            "missing cache restore": log.replace(b"Cache restored successfully", b"Cache not found for input keys: x"),
        }.items():
            with self.subTest(label), self.assertRaises(control_audit.ControlAuditRefusal):
                control_audit.validate_synthetic_log(payload, identity)

    def test_source_free_failure_tail_is_bounded_redacted_and_workflow_safe(self):
        workflow_group = (chr(35) * 2 + "[group]KEYCANARY-73A10X\n").encode("ascii")
        payload = (b"earliest\n" + b"ordinary diagnostic\n" * 205
                   + b"\x1b[31m::error::SYNTHETIC_SOURCE_CANARY_7f8c\x1b[0m\n"
                   + workflow_group + b"x" * 400 + b"\n")
        details = acceptance_diagnostics.failure_tail("production-path-e2e", payload)
        self.assertLessEqual(len(details), 202)
        joined = "\n".join(details)
        self.assertIn("earlier lines omitted", joined)
        self.assertIn("[synthetic-canary-redacted]", joined)
        self.assertNotIn("SYNTHETIC_SOURCE_CANARY_7f8c", joined)
        self.assertNotIn("KEYCANARY-73A10X", joined)
        self.assertNotIn("::", joined)
        self.assertNotIn(chr(35) * 2 + "[", joined)
        self.assertNotIn("\x1b", joined)
        canary_tail = acceptance_diagnostics.failure_tail(
            "production-path-e2e",
            b"PRIVATE_SOURCE_CANARY SYNTHETIC_KEY_CANARY PRIVATE_KEY_CANARY "
            + b"KEYCANARY-73A10X" + bytes(range(16)),
        )
        canary_text = "\n".join(canary_tail)
        for marker in ("PRIVATE_SOURCE_CANARY", "SYNTHETIC_KEY_CANARY", "PRIVATE_KEY_CANARY", "KEYCANARY"):
            self.assertNotIn(marker, canary_text)
        self.assertTrue(all(diagnostic_contract.public_acceptance_detail(line) for line in details))
        self.assertTrue(all(diagnostic_contract.public_acceptance_detail(line) for line in canary_tail))
        self.assertTrue(all(len(line) <= diagnostic_contract.MAX_ACCEPTANCE_DETAIL_BYTES for line in details))
        with self.assertRaises(ValueError):
            acceptance_diagnostics.failure_tail("private-stage", b"detail")

    def test_source_free_failure_tail_preserves_vitest_diagnostics_before_the_general_tail(self):
        raw_log = "devlane_e2e_vitest_diag=log name=unit.log line=1 text=Error%3A%20spawn%20EPERM"
        payload = (raw_log + "\n" + "ordinary diagnostic\n" * 250).encode("ascii")
        details = acceptance_diagnostics.failure_tail("production-path-e2e", payload)
        self.assertIn(raw_log, details)
        self.assertLessEqual(len(details), 202)
        self.assertTrue(all(diagnostic_contract.public_e2e_vitest_diagnostic(line)
                            or diagnostic_contract.public_acceptance_detail(line) for line in details))

    def test_production_failure_tail_keeps_only_the_current_scenario_raw_logs(self):
        previous = "devlane_e2e_failure_diag=log name=unit.log line=1 text=previous-node-output"
        current = (
            "devlane_e2e_failure_diag=log name=compile-listener-all-features.stdout "
            "line=1 text=current-rust-output"
        )
        payload = (previous + "\n"
                   "devlane_e2e_progress=scenario=synthetic-rust-v1-refusal\n"
                   + current + "\n"
                   + "ordinary diagnostic\n" * 250).encode("ascii")
        details = acceptance_diagnostics.failure_tail("production-path-e2e", payload)
        self.assertIn(current, details)
        self.assertNotIn(previous, details)
        self.assertLessEqual(len(details), 202)
        self.assertTrue(all(diagnostic_contract.public_e2e_vitest_diagnostic(line)
                            or diagnostic_contract.public_acceptance_detail(line) for line in details))

    def test_preparation_refusal_diagnostics_are_allowlisted_and_never_count_as_acceptance(self):
        root = Path(__file__).resolve().parents[2]
        grammar = audit._Grammar(
            root / ".github/workflows/devlane-synthetic.yml", "devlane-synthetic",
            {"run_id": "12345", "control_sha": SHA}, "synthetic",
        )
        line = (
            "devlane_production_e2e=refused stage=prepare-node-toolchain-validation "
            "exception=node-toolchain-owner"
        )
        self.assertTrue(grammar.step_output_ok(
            "Run full source-free production-path acceptance", line, {},
        ))
        refusal_counts = {}
        self.assertTrue(grammar.step_output_ok(
            "Run full source-free production-path acceptance",
            "devlane_acceptance=refused stage=production-path-e2e", refusal_counts,
        ))
        detail = "devlane_acceptance_detail stage=production-path-e2e index=1 text=ModuleNotFoundError: test fixture import failed"
        self.assertTrue(grammar.step_output_ok(
            "Run full source-free production-path acceptance", detail, refusal_counts,
        ))
        self.assertFalse(grammar.step_output_ok(
            "Run full source-free production-path acceptance",
            detail.replace("production-path-e2e", "rust-v2-public-runtime"), refusal_counts,
        ))
        for invalid in (
            line.replace("node-toolchain-owner", "private-path"),
            line.replace("prepare-node-toolchain-validation", "private-path"),
            line + " cleanup=confirmed",
            line.replace("node-toolchain-owner", "node-toolchain-owner") + " KEYCANARY-73A10X",
            detail.replace("production-path-e2e", "private-stage"),
            detail.replace("ModuleNotFoundError", "::error::"),
            detail + " KEYCANARY-73A10X",
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(grammar.step_output_ok(
                    "Run full source-free production-path acceptance", invalid, {},
                ))
        self.assertFalse(grammar.step_output_ok(
            "Set up pinned Node toolchain", line, {},
        ))
        encrypted = audit._Grammar(
            Path(__file__).resolve().parents[2] / ".github/workflows/devlane-encrypted.yml",
            audit.RUN_JOB, IDENTITY, "encrypted",
        )
        self.assertFalse(encrypted.step_output_ok("Prepare dependencies before the cut", detail, {}))

    def test_e2e_progress_markers_use_fixed_phase_and_scenario_vocabulary(self):
        root = Path(__file__).resolve().parents[2]
        grammar = audit._Grammar(
            root / ".github/workflows/devlane-synthetic.yml", "devlane-synthetic",
            {"run_id": "12345", "control_sha": SHA}, "synthetic",
        )
        for line in (
            "devlane_e2e_progress=phase=variant-supervisor-probe-check",
            "devlane_e2e_progress=scenario=real-browser",
        ):
            self.assertTrue(diagnostic_contract.public_e2e_progress(line))
            self.assertTrue(grammar.step_output_ok(
                "Run full source-free production-path acceptance", line, {},
            ))
        for line in (
            "devlane_e2e_progress=phase=private-path",
            "devlane_e2e_progress=scenario=private-scenario",
            "devlane_e2e_progress=scenario=real-browser/path",
        ):
            self.assertFalse(diagnostic_contract.public_e2e_progress(line))
            self.assertFalse(grammar.step_output_ok(
                "Run full source-free production-path acceptance", line, {},
            ))
        self.assertFalse(grammar.step_output_ok(
            "Prepare dependencies before the cut", "devlane_e2e_progress=phase=fixture-load", {},
        ))

    def test_variant_execute_runtime_frame_uses_a_fixed_audited_grammar(self):
        lines = [
            ("devlane_production_e2e=refused stage=variant-execute exception=runtime-error "
             "class=RuntimeError frame=supervisor.py:1824:_execute code=summary-schema-invalid"),
            ("devlane_production_e2e=refused stage=variant-summary-validate exception=runtime-error "
             "class=RuntimeError frame=test_e2e.py:1717:_require code=rust-matrix-summary-coverage-set"),
        ]
        for line in lines:
            self.assertTrue(diagnostic_contract.public_e2e_runtime_diagnostic(line))
            self.assertFalse(diagnostic_contract.public_preparation_diagnostic(line))
        details = acceptance_diagnostics.failure_tail(
            "production-path-e2e", ("\n".join(lines) + "\n").encode("ascii"),
        )
        self.assertEqual(details, lines)

        root = Path(__file__).resolve().parents[2]
        grammar = audit._Grammar(
            root / ".github/workflows/devlane-synthetic.yml", "devlane-synthetic",
            {"run_id": "12345", "control_sha": SHA}, "synthetic",
        )
        private_frame_path = chr(47) + "private/supervisor.py"
        for line in lines:
            self.assertTrue(grammar.step_output_ok(
                "Run full source-free production-path acceptance", line, {},
            ))
        for invalid in (
            lines[0].replace("supervisor.py", private_frame_path),
            lines[0].replace("supervisor.py", "../supervisor.py"),
            lines[0].replace("runtime-error", "type-error"),
            lines[0].replace("variant-execute", "variant-decrypt"),
            lines[0].replace(":1824:", ":0:"),
            lines[0].replace("code=summary-schema-invalid", "code=private-runtime-detail"),
            lines[0] + " KEYCANARY-73A10X",
            lines[1].replace("variant-summary-validate", "variant-decrypt"),
        ):
            with self.subTest(line=invalid):
                self.assertFalse(diagnostic_contract.public_e2e_runtime_diagnostic(invalid))
                self.assertFalse(grammar.step_output_ok(
                    "Run full source-free production-path acceptance", invalid, {},
                ))

    def test_execute_command_diagnostic_uses_a_fixed_audited_grammar(self):
        command = "devlane_e2e_command=failed call=supervisor-client:execute returncode=1"
        refusal = "devlane_supervisor_refusal=execution-order"
        root = Path(__file__).resolve().parents[2]
        grammar = audit._Grammar(
            root / ".github/workflows/devlane-synthetic.yml", "devlane-synthetic",
            {"run_id": "12345", "control_sha": SHA}, "synthetic",
        )
        for line in (command, refusal,
                     "typescript_reporter_refusal=typescript-unavailable",
                     "rust_matrix=refused code=advisory-database-missing",
                     "rust_matrix=refused code=matrix-runner-failed",
                     "rust_test_adapter=refused",
                     "typescript_reporter_refusal=source-root-invalid",
                     "typescript_reporter_refusal=usage"):
            with self.subTest(line=line):
                self.assertTrue(diagnostic_contract.public_e2e_command_diagnostic(line))
                self.assertTrue(grammar.step_output_ok(
                    "Run full source-free production-path acceptance", line, {},
                ))
        details = acceptance_diagnostics.failure_tail(
            "production-path-e2e", (command + "\n" + refusal + "\nraw npm output\n").encode("ascii"),
        )
        self.assertEqual(details, [command, refusal,
                                   "devlane_acceptance_detail stage=production-path-e2e index=3 text=raw npm output"])
        for invalid in (
            command.replace("supervisor-client:execute", "private:execute"),
            command.replace("returncode=1", "returncode=01"),
            refusal.replace("execution-order", "private/path"),
            "typescript_reporter_refusal=private/path",
            "rust_matrix=refused",
            "rust_matrix=refused code=private/path",
            "rust_matrix=refused code=unlisted-reason",
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(diagnostic_contract.public_e2e_command_diagnostic(invalid))
                self.assertFalse(grammar.step_output_ok(
                    "Run full source-free production-path acceptance", invalid, {},
                ))

    def test_vitest_raw_log_diagnostics_are_bounded_to_the_synthetic_acceptance_step(self):
        log_line = (
            "devlane_e2e_vitest_diag=log name=unit.stderr.log line=120 "
            "text=Error%3A%20spawn%20EPERM"
        )
        report_line = "devlane_e2e_vitest_diag=report name=vitest.json kind=file bytes=2048"
        rust_log_line = "devlane_e2e_failure_diag=log name=compile-root-default.stdout line=1 text=cargo%20test%20failed"
        rust_refusal_log_line = (
            "devlane_e2e_failure_diag=log name=rust-matrix-adapter.log line=1 "
            "text=rust_matrix=refused code=advisory-database-missing"
        )
        bare_rust_refusal_log_line = (
            "devlane_e2e_failure_diag=log name=rust-matrix-adapter.log line=1 "
            "text=rust_matrix=refused"
        )
        unknown_rust_refusal_log_line = (
            "devlane_e2e_failure_diag=log name=rust-matrix-adapter.log line=1 "
            "text=rust_matrix=refused code=private/path"
        )
        rust_report_line = "devlane_e2e_failure_diag=report name=rust-matrix.jsonl kind=file bytes=128"
        self.assertTrue(diagnostic_contract.public_e2e_vitest_diagnostic(log_line))
        self.assertTrue(diagnostic_contract.public_e2e_vitest_diagnostic(report_line))
        self.assertTrue(diagnostic_contract.public_e2e_failure_diagnostic(rust_log_line))
        self.assertTrue(diagnostic_contract.public_e2e_failure_diagnostic(rust_refusal_log_line))
        self.assertFalse(diagnostic_contract.public_e2e_failure_diagnostic(bare_rust_refusal_log_line))
        self.assertFalse(diagnostic_contract.public_e2e_failure_diagnostic(unknown_rust_refusal_log_line))
        self.assertTrue(diagnostic_contract.public_e2e_failure_diagnostic(rust_report_line))
        long_browser_line = (
            "devlane_e2e_failure_diag=log name=browser.stderr.log line=1 text=" + ("x" * 500)
        )
        long_non_browser_line = long_browser_line.replace("browser.stderr.log", "unit.stderr.log")
        self.assertTrue(diagnostic_contract.public_e2e_failure_diagnostic(long_browser_line))
        self.assertFalse(diagnostic_contract.public_e2e_failure_diagnostic(long_non_browser_line))
        self.assertFalse(diagnostic_contract.public_e2e_failure_diagnostic(
            long_browser_line + "x" * diagnostic_contract.MAX_E2E_BROWSER_DIAGNOSTIC_BYTES
        ))
        self.assertEqual(acceptance_diagnostics.failure_tail(
            "production-path-e2e", (log_line + "\n" + report_line + "\n" + rust_log_line + "\n"
                                     + rust_refusal_log_line + "\n" + rust_report_line + "\n").encode("ascii"),
        ), [log_line, report_line, rust_log_line, rust_refusal_log_line, rust_report_line])
        root = Path(__file__).resolve().parents[2]
        synthetic = audit._Grammar(
            root / ".github/workflows/devlane-synthetic.yml", "devlane-synthetic",
            {"run_id": "12345", "control_sha": SHA}, "synthetic",
        )
        counts = {}
        self.assertTrue(synthetic.step_output_ok(
            "Run full source-free production-path acceptance", log_line, counts,
        ))
        self.assertTrue(synthetic.step_output_ok(
            "Run full source-free production-path acceptance", report_line, counts,
        ))
        self.assertTrue(synthetic.step_output_ok(
            "Run full source-free production-path acceptance", rust_log_line, counts,
        ))
        self.assertTrue(synthetic.step_output_ok(
            "Run full source-free production-path acceptance", rust_report_line, counts,
        ))
        for invalid in (
            log_line.replace("line=120", "line=0120"),
            log_line.replace("unit.stderr.log", "../unit.log"),
            log_line.replace("EPERM", "EPERM::error::"),
            log_line.replace("EPERM", "SYNTHETIC_SOURCE_CANARY_7f8c"),
            log_line.replace("EPERM", "EPERM%2g"),
            report_line.replace("kind=file", "kind=private"),
            report_line + " KEYCANARY-73A10X",
        ):
            with self.subTest(line=invalid):
                self.assertFalse(diagnostic_contract.public_e2e_vitest_diagnostic(invalid))
                self.assertFalse(synthetic.step_output_ok(
                    "Run full source-free production-path acceptance", invalid, {},
                ))
        self.assertFalse(synthetic.step_output_ok("Set up pinned Node toolchain", log_line, {}))

        encrypted = audit._Grammar(
            root / ".github/workflows/devlane-encrypted.yml", audit.RUN_JOB,
            IDENTITY, "encrypted",
        )
        self.assertFalse(encrypted.step_output_ok(
            "Run full source-free production-path acceptance", log_line, {},
        ))

        bounded = {}
        for _ in range(diagnostic_contract.MAX_E2E_VITEST_DIAGNOSTIC_LINES):
            self.assertTrue(synthetic.step_output_ok(
                "Run full source-free production-path acceptance", log_line, bounded,
            ))
        self.assertFalse(synthetic.step_output_ok(
            "Run full source-free production-path acceptance", log_line, bounded,
        ))

    def test_cleanup_incomplete_diagnostic_requires_a_fixed_subreason(self):
        for reason in diagnostic_contract.CLEANUP_SUBREASONS:
            line = ("devlane_production_e2e=refused stage=prepare-cleanup "
                    "exception=cleanup-incomplete reason=" + reason + " cleanup=unconfirmed")
            self.assertTrue(diagnostic_contract.public_preparation_diagnostic(line))
        self.assertTrue(diagnostic_contract.public_preparation_diagnostic(
            "devlane_production_e2e=refused stage=prepare-cleanup exception=prepare-os-error "
            "reason=process-alive cleanup=unconfirmed",
        ))
        invalid = (
            "devlane_production_e2e=refused stage=prepare-cleanup exception=cleanup-incomplete cleanup=unconfirmed",
            "devlane_production_e2e=refused stage=prepare-cleanup exception=cleanup-incomplete reason=private-path cleanup=unconfirmed",
            "devlane_production_e2e=refused stage=prepare-cleanup exception=cleanup-incomplete reason=umount-busy cleanup=confirmed",
        )
        for line in invalid:
            self.assertFalse(diagnostic_contract.public_preparation_diagnostic(line))

        synthetic = _render_log(
            "devlane-synthetic", {**IDENTITY, "ref": "refs/heads/devlane/d211-1110"}, kind="synthetic",
            skip=("Install fixed Rust acceptance toolchain",),
        )
        refused = synthetic.replace(
            b"devlane_acceptance=pass", line.encode("ascii"), 1,
        )
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_synthetic_log(
                refused, {"run_id": "12345", "control_sha": SHA, "ref": "refs/heads/devlane/d211-1110"},
            )

    def test_network_probe_refusals_are_bounded_and_auditor_allowlisted(self):
        root = Path(__file__).resolve().parents[2]
        grammar = audit._Grammar(
            root / ".github/workflows/devlane-encrypted.yml", audit.RUN_JOB, IDENTITY, "encrypted",
        )
        for code in sorted(audit.network_probe.REFUSAL_CODES):
            supervisor_line = "devlane_supervisor_refusal=network-probe-refusal:" + code
            self.assertTrue(grammar.step_output_ok(
                "Probe isolation before decryption", supervisor_line, {},
            ))
            self.assertTrue(grammar.step_output_ok(
                "Probe isolation before decryption", "network_probe_refusal=" + code, {},
            ))
            self.assertFalse(grammar.refusal_line_ok(
                "Probe isolation before decryption", "network_probe_refusal=" + code,
            ))
            self.assertFalse(grammar.step_output_ok(
                "Execute offline profile and filter public summary", supervisor_line, {},
            ))
            self.assertFalse(grammar.step_output_ok("Prepare hosted Linux isolation state",
                                                    "network_probe_refusal=" + code, {}))
        valid = (
            "devlane_production_e2e=refused stage=variant-supervisor-probe-check "
            "exception=network-probe-refusal:network-address-unexpected"
        )
        self.assertTrue(diagnostic_contract.public_preparation_diagnostic(valid))
        self.assertTrue(grammar.step_output_ok(
            "Run full source-free production-path acceptance", valid, {},
        ))
        for invalid in (
            valid.replace("network-address-unexpected", "private-path"),
            valid.replace("variant-supervisor-probe-check", "variant-decrypt"),
            "devlane_supervisor_refusal=network-probe-refusal:private-path",
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(diagnostic_contract.public_preparation_diagnostic(invalid))
                self.assertFalse(grammar.step_output_ok("Probe isolation before decryption", invalid, {}))
        self.assertFalse(grammar.refusal_line_ok(
            "Probe isolation before decryption", "network_probe_refusal=private-path",
        ))

        structure_refusal = "network-structure-invalid:netlink-message-port-id"
        self.assertTrue(grammar.step_output_ok(
            "Probe isolation before decryption", "network_probe_refusal=" + structure_refusal, {},
        ))
        self.assertTrue(grammar.step_output_ok(
            "Probe isolation before decryption", "devlane_supervisor_refusal=network-probe-refusal:"
            + structure_refusal, {},
        ))
        structure_line = (
            "devlane_production_e2e=refused stage=variant-supervisor-probe-check "
            "exception=network-probe-refusal:" + structure_refusal
        )
        self.assertTrue(diagnostic_contract.public_preparation_diagnostic(structure_line))
        self.assertTrue(grammar.step_output_ok(
            "Run full source-free production-path acceptance", structure_line, {},
        ))
        self.assertFalse(diagnostic_contract.public_preparation_diagnostic(
            structure_line.replace("netlink-message-port-id", "private-path"),
        ))

        route_detail = (
            "route[table=main,type=unicast,family=4,dst=0.0.0.0/0,"
            "oif=lo,proto=boot,scope=universe]"
        )
        route_refusal = "network-route-unexpected " + route_detail
        route_line = (
            "devlane_production_e2e=refused stage=variant-supervisor-probe-check "
            "exception=network-probe-refusal:" + route_refusal
        )
        self.assertTrue(diagnostic_contract.public_preparation_diagnostic(route_line))
        self.assertTrue(grammar.step_output_ok(
            "Probe isolation before decryption", "network_probe_refusal=" + route_refusal, {},
        ))
        self.assertTrue(grammar.step_output_ok(
            "Probe isolation before decryption", "devlane_supervisor_refusal=network-probe-refusal:"
            + route_refusal, {},
        ))
        for malformed in (
                route_line.replace("oif=lo", "oif=private/path"),
                route_line.replace("network-route-unexpected", "network-address-unexpected")):
            self.assertFalse(diagnostic_contract.public_preparation_diagnostic(malformed))

    def test_macos_start_and_crypto_refusals_are_step_bound_and_unknown_codes_fail(self):
        root = Path(__file__).resolve().parents[2]
        grammar = audit._Grammar(
            root / ".github/workflows/devlane-encrypted.yml", audit.MACOS_RUN_JOB,
            dict(IDENTITY, platform="macos"), "encrypted",
        )
        for code in sorted(audit.MACOS_SUPERVISOR_START_REFUSAL_CODES):
            self.assertTrue(grammar.refusal_line_ok(
                "Cut network and start the isolated supervisor", "devlane_supervisor_refusal=" + code,
            ))
        for code in ("supervisor-failed", "private-path", "macos-supervisor-start-secret"):
            self.assertFalse(grammar.refusal_line_ok(
                "Cut network and start the isolated supervisor", "devlane_supervisor_refusal=" + code,
            ))
        self.assertTrue(grammar.step_output_ok(
            "Fetch public control and validate dispatch", "devlane_crypto_refusal=crypto-acl-owner-untrusted", {},
        ))
        self.assertFalse(grammar.step_output_ok(
            "Fetch public control and validate dispatch", "devlane_crypto_refusal=crypto-acl-invalid", {},
        ))
        self.assertFalse(grammar.step_output_ok(
            "Prepare hosted runner isolation state", "devlane_crypto_refusal=crypto-acl-owner-untrusted", {},
        ))
        self.assertFalse(grammar.step_output_ok(
            "Fetch public control and validate dispatch", "devlane_crypto_refusal=private-path", {},
        ))

    def test_crypto_bootstrap_additions_are_platform_and_step_scoped(self):
        new_codes = frozenset((
            "crypto-python-version-invalid", "crypto-dependency-seal-failed",
            "crypto-dependency-check-failed", "crypto-dependency-privileged-check-failed",
        ))
        allowed_bootstrap = {
            "linux": frozenset(),
            "macos": new_codes,
            "windows": new_codes - {"crypto-dependency-privileged-check-failed"},
        }
        root = Path(__file__).resolve().parents[2]
        for platform_name in ("linux", "macos", "windows"):
            job_name = audit.PLATFORM_RUN_JOBS[platform_name]
            identity = dict(IDENTITY, platform=platform_name)
            grammar = audit._Grammar(
                root / ".github/workflows/devlane-encrypted.yml", job_name, identity, "encrypted",
            )
            bootstrap_prefix = "devlane_deadline_refusal=" if platform_name == "windows" else "devlane_bootstrap_refusal="
            for code in sorted(new_codes):
                bootstrap_line = bootstrap_prefix + code
                execution_line = "devlane_supervisor_refusal=" + code
                for step in grammar.steps:
                    step_name = step["name"]
                    counts = {}
                    accepted = grammar.step_output_ok(step_name, bootstrap_line, counts)
                    expected = (platform_name in ("macos", "windows")
                                and step_name == "Fetch public control and validate dispatch"
                                and code in allowed_bootstrap[platform_name])
                    self.assertEqual(accepted, expected, (platform_name, step_name, code, "bootstrap"))
                    self.assertFalse(
                        grammar.refusal_line_ok(step_name, execution_line),
                        (platform_name, step_name, code, "execution"),
                    )
            for code in sorted(refusal_codes.CRYPTO_CONTROL_REFUSAL_CODES):
                crypto_line = "devlane_crypto_refusal=" + code
                for step in grammar.steps:
                    step_name = step["name"]
                    accepted = grammar.step_output_ok(step_name, crypto_line, {})
                    accepted_codes = (audit.MACOS_CRYPTO_CONTROL_REFUSAL_CODES if platform_name == "macos"
                                      else refusal_codes.CRYPTO_CONTROL_REFUSAL_CODES)
                    expected = (platform_name in ("macos", "windows")
                                and step_name == "Fetch public control and validate dispatch"
                                and code in accepted_codes)
                    self.assertEqual(accepted, expected, (platform_name, step_name, code, "crypto-reason"))

    def test_macos_startup_refusals_pass_the_complete_log_and_metadata_contract(self):
        new_start_codes = sorted(audit.MACOS_SUPERVISOR_START_REFUSAL_CODES)
        identity = dict(IDENTITY, platform="macos")
        failed_step = audit.MACOS_SUPERVISOR_START_STEP
        expected_outcome = (
            "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
            "disposition=run-failed-at-macos-supervisor-start"
        )
        for code in new_start_codes:
            with self.subTest(code=code):
                jobs = _encrypted_jobs(platform="macos")
                run_job = next(job for job in jobs if job["name"] == audit.MACOS_RUN_JOB)
                run_job["conclusion"] = "failure"
                names = [step["name"] for step in run_job["steps"]]
                failed_index = names.index(failed_step)
                for index, step in enumerate(run_job["steps"]):
                    if step["name"] == "Shred runner-local workspace":
                        step["conclusion"] = "success"
                    elif step["name"] == "Install pinned Rust toolchain":
                        step["conclusion"] = "skipped"
                    elif step["name"] == "Install Tauri Linux build dependencies":
                        step["conclusion"] = "skipped"
                    elif index < failed_index:
                        step["conclusion"] = "success"
                    elif index == failed_index:
                        step["conclusion"] = "failure"
                    else:
                        step["conclusion"] = "skipped"
                log = _render_real_runner_encrypted_log(
                    identity, early_failure={
                        "step": failed_step,
                        "marker": "devlane_supervisor_refusal=" + code,
                        "exit_code": 2,
                    },
                )
                surface = audit.validate_job_log_surface(log, audit.MACOS_RUN_JOB, identity, completed=True)
                self.assertEqual(surface["early_failure"], failed_step)
                self.assertEqual(surface["early_failure_code"], code)
                self.assertEqual(surface["early_failure_exit"], 2)
                audit.validate_job_contract(jobs, identity, "core-node")
                audit.validate_job_log_metadata_binding(surface, run_job, identity)
                audit.validate_dispatch_marker(log, identity, allow_missing=False)
                self.assertEqual(audit._audit_outcome_line(jobs, identity), expected_outcome)

                wrong_exit = _render_real_runner_encrypted_log(
                    identity, early_failure={
                        "step": failed_step,
                        "marker": "devlane_supervisor_refusal=" + code,
                        "exit_code": 1,
                    },
                )
                with self.assertRaises(audit.AuditRefusal) as caught:
                    audit.validate_job_log_surface(wrong_exit, audit.MACOS_RUN_JOB, identity, completed=True)
                self.assertEqual(caught.exception.reason, "job-log-surface")

                changed = copy.deepcopy(jobs)
                changed_run = next(job for job in changed if job["name"] == audit.MACOS_RUN_JOB)
                changed_steps = {step["name"]: step for step in changed_run["steps"]}
                changed_steps["Probe isolation before decryption"]["conclusion"] = "success"
                with self.assertRaises(audit.AuditRefusal) as caught:
                    audit.validate_job_contract(changed, identity, "core-node")
                self.assertEqual(caught.exception.reason, "job-contract")

                changed = copy.deepcopy(run_job)
                changed_steps = {step["name"]: step for step in changed["steps"]}
                changed_steps["Shred runner-local workspace"]["conclusion"] = "failure"
                with self.assertRaises(audit.AuditRefusal) as caught:
                    audit.validate_job_log_metadata_binding(surface, changed, identity)
                self.assertEqual(caught.exception.reason, "step-metadata-binding")

    def test_macos_operation_refusals_pass_the_complete_step_contract(self):
        stages = (
            (audit.MACOS_PREPARE_STEP, audit.MACOS_PREPARE_REFUSAL_CODES, "macos-prepare"),
            (audit.MACOS_PROBE_STEP, audit.MACOS_PROBE_REFUSAL_CODES, "macos-probe"),
            (audit.MACOS_EXECUTE_STEP, audit.MACOS_EXECUTE_REFUSAL_CODES, "macos-execute"),
        )
        identity = dict(IDENTITY, platform="macos")
        for failed_step, codes, disposition in stages:
            expected_outcome = (
                "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
                "disposition=run-failed-at-" + disposition
            )
            for code in sorted(codes):
                with self.subTest(step=failed_step, code=code):
                    jobs = _encrypted_jobs(platform="macos")
                    run_job = next(job for job in jobs if job["name"] == audit.MACOS_RUN_JOB)
                    run_job["conclusion"] = "failure"
                    names = [step["name"] for step in run_job["steps"]]
                    failed_index = names.index(failed_step)
                    for index, step in enumerate(run_job["steps"]):
                        if step["name"] == audit.MACOS_CLEANUP_STEP:
                            step["conclusion"] = "success"
                        elif step["name"] in ("Install pinned Rust toolchain", "Install Tauri Linux build dependencies"):
                            step["conclusion"] = "skipped"
                        elif index < failed_index:
                            step["conclusion"] = "success"
                        elif index == failed_index:
                            step["conclusion"] = "failure"
                        else:
                            step["conclusion"] = "skipped"
                    marker = "devlane_supervisor_refusal=" + code
                    log = _render_real_runner_encrypted_log(
                        identity, early_failure={"step": failed_step, "marker": marker, "exit_code": 2},
                    )
                    surface = audit.validate_job_log_surface(
                        log, audit.MACOS_RUN_JOB, identity, completed=True,
                    )
                    self.assertEqual(surface["early_failure"], failed_step)
                    self.assertEqual(surface["early_failure_code"], code)
                    self.assertEqual(surface["early_failure_exit"], 2)
                    audit.validate_job_contract(jobs, identity, "core-node")
                    audit.validate_job_log_metadata_binding(surface, run_job, identity)
                    audit.validate_dispatch_marker(log, identity, allow_missing=False)
                    self.assertEqual(
                        audit._audit_outcome_line(jobs, identity, diagnosed_failure=failed_step), expected_outcome,
                    )

                    wrong_exit = _render_real_runner_encrypted_log(
                        identity, early_failure={"step": failed_step, "marker": marker, "exit_code": 1},
                    )
                    with self.assertRaises(audit.AuditRefusal):
                        audit.validate_job_log_surface(wrong_exit, audit.MACOS_RUN_JOB, identity, completed=True)

                    if code == min(codes):
                        missing_dispatch = log.replace(b"KD-DEVLANE-DISPATCH", b"KD-DEVLANE-DISPATCH-MUTATED", 1)
                        with self.assertRaises(audit.AuditRefusal):
                            audit.validate_job_log_surface(
                                missing_dispatch, audit.MACOS_RUN_JOB, identity, completed=True,
                            )
                        changed = copy.deepcopy(jobs)
                        changed_run = next(job for job in changed if job["name"] == audit.MACOS_RUN_JOB)
                        changed_steps = {step["name"]: step for step in changed_run["steps"]}
                        if failed_step == audit.MACOS_PREPARE_STEP:
                            changed_steps[audit.MACOS_PROBE_STEP]["conclusion"] = "success"
                        elif failed_step == audit.MACOS_PROBE_STEP:
                            changed_steps["Decrypt authenticated bundle"]["conclusion"] = "success"
                        else:
                            changed_steps[audit.MACOS_CLEANUP_STEP]["conclusion"] = "failure"
                        with self.assertRaises(audit.AuditRefusal):
                            audit.validate_job_contract(changed, identity, "core-node")

                    other_step = audit.MACOS_EXECUTE_STEP if failed_step != audit.MACOS_EXECUTE_STEP else audit.MACOS_PREPARE_STEP
                    grammar = audit._Grammar(
                        Path(__file__).resolve().parents[2] / ".github/workflows/devlane-encrypted.yml",
                        audit.MACOS_RUN_JOB, identity, "encrypted",
                    )
                    self.assertFalse(grammar.step_output_ok(
                        other_step, marker, {},
                    ))

    def test_shared_probe_and_execute_failures_keep_the_base_platform_contracts(self):
        cases = (
            ("linux", "Probe isolation before decryption", "Probe isolation before decryption",
             "disposition=run-failed-at-probe"),
            ("windows", "Probe isolation before decryption", "Probe isolation before decryption",
             "disposition=run-failed-at-probe"),
            ("macos", "Probe isolation before decryption", "Probe isolation before decryption",
             "disposition=run-failed-at-probe"),
            ("linux", "Execute offline profile and filter public summary", None,
             "disposition=run-failed-during-execution"),
            ("windows", "Execute offline profile and filter public summary", None,
             "disposition=run-failed-during-execution"),
            ("macos", "Execute offline profile and filter public summary", None,
             "disposition=run-failed-during-execution"),
        )
        for platform_name, failed_step, failure_stage, disposition in cases:
            with self.subTest(platform=platform_name, failed_step=failed_step):
                identity = dict(IDENTITY, platform=platform_name)
                jobs = _encrypted_jobs(platform=platform_name)
                run_job = next(job for job in jobs if job["name"] == audit.PLATFORM_RUN_JOBS[platform_name])
                run_job["conclusion"] = "failure"
                failed_index = next(index for index, step in enumerate(run_job["steps"])
                                    if step["name"] == failed_step)
                for index, step in enumerate(run_job["steps"]):
                    if step["name"] == "Shred runner-local workspace":
                        step["conclusion"] = "success"
                    elif step["name"] == "Install pinned Rust toolchain":
                        step["conclusion"] = "skipped"
                    elif step["name"] == "Install Tauri Linux build dependencies":
                        step["conclusion"] = "skipped"
                    elif index < failed_index:
                        step["conclusion"] = "success"
                    elif index == failed_index:
                        step["conclusion"] = "failure"
                    else:
                        step["conclusion"] = "skipped"
                if failed_step == "Probe isolation before decryption":
                    log = _render_real_runner_encrypted_log(
                        identity,
                        early_failure={
                            "step": failed_step,
                            "marker": "network_probe_refusal=probe-command-failed",
                            "exit_code": 2,
                        },
                    )
                else:
                    log = _omit_step_run_group(
                        _render_real_runner_encrypted_log(identity), identity,
                        audit.PLATFORM_RUN_JOBS[platform_name], failed_step,
                    )
                surface = audit.validate_job_log_surface(
                    log, audit.PLATFORM_RUN_JOBS[platform_name], identity, completed=True,
                )
                self.assertIsNone(surface["early_failure"])
                self.assertEqual(surface["failure_stage"], failure_stage)
                audit.validate_job_contract(jobs, identity, "core-node")
                audit.validate_job_log_metadata_binding(surface, run_job, identity)
                audit.validate_dispatch_marker(log, identity)
                expected = (
                    "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed " + disposition
                )
                self.assertEqual(audit._audit_outcome_line(jobs, identity), expected)

        self.assertNotIn(audit.MACOS_PREPARE_STEP, audit.EARLY_FAILURE_STEP_IDS)
        self.assertNotIn(audit.MACOS_PROBE_STEP, audit.EARLY_FAILURE_STEP_IDS)
        self.assertNotIn(audit.MACOS_EXECUTE_STEP, audit.EARLY_FAILURE_STEP_IDS)

    def test_macos_decrypt_refusal_keeps_decrypt_accounting(self):
        identity = dict(IDENTITY, platform="macos")
        failed_step = "Decrypt authenticated bundle"
        jobs = _encrypted_jobs(platform="macos")
        run_job = next(job for job in jobs if job["name"] == audit.MACOS_RUN_JOB)
        run_job["conclusion"] = "failure"
        failed_index = next(index for index, step in enumerate(run_job["steps"])
                            if step["name"] == failed_step)
        for index, step in enumerate(run_job["steps"]):
            if step["name"] == audit.MACOS_CLEANUP_STEP:
                step["conclusion"] = "success"
            elif step["name"] == "Install pinned Rust toolchain":
                step["conclusion"] = "skipped"
            elif index < failed_index:
                step["conclusion"] = "success"
            elif index == failed_index:
                step["conclusion"] = "failure"
            else:
                step["conclusion"] = "skipped"
        refusal = "devlane_supervisor_refusal=decrypt-rejected"
        log = _render_real_runner_encrypted_log(
            identity,
            early_failure={"step": failed_step, "marker": refusal, "exit_code": 2},
        ).replace(
            (refusal + "\n").encode("ascii"),
            (refusal + "\n2026-11-12T20:05:19.9416693Z decrypt_refusal=auth-tag\n").encode("ascii"),
            1,
        )
        surface = audit.validate_job_log_surface(log, audit.MACOS_RUN_JOB, identity, completed=True)
        self.assertIsNone(surface["early_failure"])
        self.assertEqual(surface["failure_stage"], failed_step)
        audit.validate_job_log_metadata_binding(surface, run_job, identity)
        audit.validate_dispatch_marker(log, identity)
        self.assertEqual(
            audit._audit_outcome_line(jobs, identity),
            "devlane_audit=accepted jobs=4 artifacts=0 cache=unchanged cleanup=confirmed "
            "disposition=run-failed-at-decrypt",
        )

    def test_macos_cleanup_refusal_codes_are_scoped_and_unconfirmed_cleanup_is_rejected(self):
        identity = dict(IDENTITY, platform="macos")
        grammar = audit._Grammar(
            Path(__file__).resolve().parents[2] / ".github/workflows/devlane-encrypted.yml",
            audit.MACOS_RUN_JOB, identity, "encrypted",
        )
        for code in sorted(audit.MACOS_CLEANUP_REFUSAL_CODES | audit.MACOS_ROOT_PF_CLEANUP_REFUSAL_CODES):
            marker = "devlane_supervisor_refusal=" + code
            self.assertTrue(grammar.step_output_ok(audit.MACOS_CLEANUP_STEP, marker, {}))
            self.assertFalse(grammar.step_output_ok(audit.MACOS_PREPARE_STEP, marker, {}))
            log = _render_real_runner_encrypted_log(
                identity, early_failure={"step": audit.MACOS_CLEANUP_STEP, "marker": marker, "exit_code": 2},
            )
            with self.subTest(code=code), self.assertRaises(audit.AuditRefusal) as caught:
                audit.validate_job_log_surface(log, audit.MACOS_RUN_JOB, identity, completed=True)
            self.assertEqual(caught.exception.reason, "job-log-surface")

    def test_new_macos_operation_codes_do_not_widen_linux_or_windows_sets(self):
        root = Path(__file__).resolve().parents[2]
        self.assertTrue(refusal_codes.MACOS_OPERATION_REFUSAL_CODES.isdisjoint(refusal_codes.REFUSAL_CODES))
        for step_name, codes in audit.MACOS_OPERATION_STEP_REFUSALS.items():
            if step_name == audit.MACOS_SUPERVISOR_START_STEP:
                continue
            for code in sorted(codes):
                line = "devlane_supervisor_refusal=" + code
                macos = audit._Grammar(
                    root / ".github/workflows/devlane-encrypted.yml", audit.MACOS_RUN_JOB,
                    dict(IDENTITY, platform="macos"), "encrypted",
                )
                self.assertTrue(macos.refusal_line_ok(step_name, line), (step_name, code, "macos"))
                for other_step in set(audit.MACOS_OPERATION_STEP_REFUSALS) - {step_name}:
                    self.assertFalse(macos.refusal_line_ok(other_step, line), (other_step, code, "macos"))
                for platform_name in ("linux", "windows"):
                    job = audit.PLATFORM_RUN_JOBS[platform_name]
                    grammar = audit._Grammar(
                        root / ".github/workflows/devlane-encrypted.yml", job,
                        dict(IDENTITY, platform=platform_name), "encrypted",
                    )
                    self.assertFalse(grammar.refusal_line_ok(step_name, line), (step_name, code, platform_name))

    def test_new_audit_contract_reasons_are_fixed_and_accepted_by_the_log_grammar(self):
        root = Path(__file__).resolve().parents[2]
        grammar = audit._Grammar(
            root / ".github/workflows/devlane-encrypted.yml", audit.AUDIT_JOB, IDENTITY, "encrypted",
        )
        self.assertEqual(audit.AUDIT_SUBREASONS, frozenset(audit.AUDIT_REASON_BY_CHECK.values()) |
                         frozenset(("audit-internal-check",)))
        for reason in sorted(audit.AUDIT_SUBREASONS):
            line = "devlane_audit=refused code=audit-contract reason=" + reason
            self.assertTrue(grammar.step_output_ok(
                "Audit exact four-job graph and public surfaces", line, {},
            ))
        for line in (
            "devlane_audit=refused code=audit-contract reason=private-path",
            "devlane_audit=refused code=audit-contract",
        ):
            self.assertFalse(grammar.step_output_ok(
                "Audit exact four-job graph and public surfaces", line, {},
            ))

    def test_bootstrap_crypto_subreason_is_bound_to_a_fixed_reason_and_failure(self):
        phases = (
            ("crypto-dependency-seal-failed", audit.CRYPTO_SEAL_REFUSAL_CODES),
            ("crypto-dependency-check-failed", audit.CRYPTO_CHECK_REFUSAL_CODES),
        )
        cases = [(platform, code, reason)
                 for platform in ("macos", "windows")
                 for code, reasons in phases
                 for reason in sorted(reasons & (audit.MACOS_CRYPTO_CONTROL_REFUSAL_CODES
                                                  if platform == "macos"
                                                  else audit.CRYPTO_CONTROL_REFUSAL_CODES))]
        cases.extend(("macos", "crypto-dependency-privileged-check-failed", reason)
                     for reason in sorted(audit.CRYPTO_CHECK_REFUSAL_CODES
                                          & audit.MACOS_CRYPTO_CONTROL_REFUSAL_CODES))
        for platform, bootstrap_code, reason in cases:
            with self.subTest(platform=platform, bootstrap_code=bootstrap_code, reason=reason):
                identity = dict(IDENTITY, platform=platform)
                prefix = "devlane_bootstrap_refusal=" if platform == "macos" else "devlane_deadline_refusal="
                marker = prefix + bootstrap_code
                outputs = ["devlane_crypto_refusal=" + reason, marker]
                log = _render_real_runner_encrypted_log(
                    identity,
                    early_failure={
                        "step": "Fetch public control and validate dispatch",
                        "marker": marker, "outputs": outputs, "exit_code": 1,
                    },
                )
                jobs = _encrypted_jobs(platform=platform)
                run_job = next(job for job in jobs if job["name"] == audit.PLATFORM_RUN_JOBS[platform])
                run_job["conclusion"] = "failure"
                steps = run_job["steps"]
                failed_index = next(index for index, step in enumerate(steps)
                                    if step["name"] == "Fetch public control and validate dispatch")
                for index, step in enumerate(steps):
                    if step["name"] == "Shred runner-local workspace":
                        step["conclusion"] = "success"
                    elif step["name"] == "Install pinned Rust toolchain":
                        step["conclusion"] = "skipped"
                    elif index < failed_index:
                        step["conclusion"] = "success"
                    elif index == failed_index:
                        step["conclusion"] = "failure"
                    else:
                        step["conclusion"] = "skipped"

                surface = audit.validate_job_log_surface(log, audit.PLATFORM_RUN_JOBS[platform], identity,
                                                         completed=True)
                self.assertEqual(surface["crypto_refusal_reason"], reason)
                audit.validate_job_contract(jobs, identity, "core-node")
                audit.validate_job_log_metadata_binding(surface, run_job, identity)
                audit.validate_dispatch_marker(log, identity, allow_missing=True)

                rejected_reasons = ["crypto-script-invalid", "private-path"]
                if bootstrap_code == "crypto-dependency-seal-failed":
                    rejected_reasons.append("crypto-import-invalid")
                else:
                    rejected_reasons.append("crypto-seal-write-failed")
                for invalid_reason in rejected_reasons:
                    invalid = _replace_output_line(
                        log, "devlane_crypto_refusal=" + reason,
                        "devlane_crypto_refusal=" + invalid_reason,
                    )
                    with self.subTest(platform=platform, bootstrap_code=bootstrap_code,
                                      reason=reason, invalid_reason=invalid_reason), \
                            self.assertRaises(audit.AuditRefusal):
                        audit.validate_job_log_surface(
                            invalid, audit.PLATFORM_RUN_JOBS[platform], identity, completed=True,
                        )
                without_reason = _replace_output_line(
                    log, "devlane_crypto_refusal=" + reason, "",
                )
                with self.assertRaises(audit.AuditRefusal):
                    audit.validate_job_log_surface(
                        without_reason, audit.PLATFORM_RUN_JOBS[platform], identity, completed=True,
                    )

    def test_audit_refusal_reason_identifies_the_contract_check(self):
        job = {"name": "audit", "status": "completed", "conclusion": "success"}
        with self.assertRaises(audit.AuditRefusal) as caught:
            audit.validate_check_output(None, job, IDENTITY, completed=True)
        self.assertEqual(caught.exception.reason, "check-run-output")

    def test_decrypt_child_diagnostics_are_fixed_and_appear_at_most_once(self):
        root = Path(__file__).resolve().parents[2]
        grammar = audit._Grammar(
            root / ".github/workflows/devlane-encrypted.yml", audit.RUN_JOB,
            IDENTITY, "encrypted",
        )
        counts = {}
        self.assertTrue(grammar.step_output_ok(
            "Decrypt authenticated bundle", "decrypt_refusal=child-signal-SIGSEGV", counts,
        ))
        self.assertTrue(grammar.step_output_ok(
            "Decrypt authenticated bundle", "decrypt_child_error=PanicException", counts,
        ))
        self.assertFalse(grammar.step_output_ok(
            "Decrypt authenticated bundle", "decrypt_child_error=ImportError", counts,
        ))
        self.assertFalse(grammar.step_output_ok(
            "Decrypt authenticated bundle", "decrypt_child_error=private-path", {},
        ))
        self.assertFalse(grammar.step_output_ok(
            "Probe isolation before decryption", "decrypt_child_error=OSError", {},
        ))
        self.assertFalse(grammar.step_output_ok(
            "Decrypt authenticated bundle", "decrypt_child_error=OSError", {},
        ))

    def test_reviewed_step_name_lists_match_the_workflow_files(self):
        root = Path(__file__).resolve().parents[2]
        encrypted = audit.parse_workflow(root / ".github/workflows/devlane-encrypted.yml")
        self.assertEqual([step["name"] for step in encrypted[audit.RUN_JOB]["steps"]], list(audit.STEP_NAMES))
        self.assertEqual([step["name"] for step in encrypted[audit.AUDIT_JOB]["steps"]], list(audit.AUDIT_STEP_NAMES))
        synthetic = audit.parse_workflow(root / ".github/workflows/devlane-synthetic.yml")
        self.assertEqual([step["name"] for step in synthetic["devlane-synthetic"]["steps"]],
                         list(control_audit.SYNTHETIC_STEP_NAMES))

    def test_final_audit_collects_every_completed_log_and_check_before_refusal(self):
        jobs = _encrypted_jobs()
        audit_job = jobs[1]
        audit_job["status"] = "completed"
        audit_job["conclusion"] = "success"
        audit_job["steps"][2].update({"status": "completed", "conclusion": "success"})
        audit_job["steps"][3].update({"status": "completed", "conclusion": "success"})

        class API:
            def __init__(self):
                self.logs = []
                self.checks = []

            def log_text(self, identifier):
                self.logs.append(identifier)
                return b"PRIVATE_SOURCE_CANARY"

            def json(self, endpoint):
                self.checks.append(endpoint)
                identifier = int(endpoint.rsplit("/", 1)[1])
                job = next(item for item in jobs if int(item["check_run_url"].rsplit("/", 1)[1]) == identifier)
                return ({"head_sha": SHA, "name": job["name"], "status": "completed", "output": {
                    "title": job["name"], "summary": None, "text": None, "annotations_count": 0,
                }}, {})

        api_client = API()
        with patch.object(audit, "_read_annotations", return_value=[]), \
                self.assertRaises(audit.AuditRefusal):
            audit.validate_final_public_surfaces(api_client, jobs, IDENTITY, "core-node")
        self.assertEqual(api_client.logs, [100, 101])
        self.assertEqual(len(api_client.checks), 2)

    def test_terminal_coordinator_contract_rechecks_final_audit_and_job_steps(self):
        jobs = _encrypted_jobs()
        jobs[1]["status"] = "completed"
        jobs[1]["conclusion"] = "success"
        jobs[1]["steps"][2]["status"] = "completed"
        jobs[1]["steps"][2]["conclusion"] = "success"
        jobs[1]["steps"][3]["status"] = "completed"
        jobs[1]["steps"][3]["conclusion"] = "success"
        result, accepted = audit.validate_terminal_job_contract(jobs, IDENTITY, "core-node")
        self.assertTrue(accepted)
        self.assertEqual(set(result), set(audit.EXECUTION_JOBS) | {audit.AUDIT_JOB})
        jobs[1]["conclusion"] = "failure"
        result, accepted = audit.validate_terminal_job_contract(jobs, IDENTITY, "core-node")
        self.assertFalse(accepted)
        self.assertEqual(set(result), set(audit.EXECUTION_JOBS) | {audit.AUDIT_JOB})
        jobs[1]["steps"][1]["name"] = "Audit an unexpected graph"
        with self.assertRaises(audit.AuditRefusal):
            audit.validate_terminal_job_contract(jobs, IDENTITY, "core-node")


class ControlAuditorMutationTests(unittest.TestCase):
    def setUp(self):
        self.identity = {
            "repository": control_audit.REPOSITORY, "repository_id": control_audit.REPOSITORY_ID,
            "ref": "refs/heads/main", "control_sha": SHA, "event": "workflow_dispatch",
            "wave_id": "control-wave-0001", "run_id": "12345", "attempt": 1,
        }

    def test_exact_18_job_graph_and_self_running_contract(self):
        self.assertEqual(len(control_audit.CONTROL_JOB_NAMES), 18)
        result = control_audit.validate_jobs(_control_jobs(), self.identity)
        self.assertEqual(len(result), 18)

    def test_unit_failure_subreason_is_audited_as_a_fixed_public_enum(self):
        accepted = '{"code":"DEVLANE_FAILURE","kind":"control","stage":"unit","status":"fail","subreason":"filter-refused"}'
        self.assertTrue(audit._record_ok(accepted))
        audit.validate_summary_records([accepted], "core-node")
        for changed in (
            accepted.replace("filter-refused", "private-filter-error"),
            accepted.replace('"stage":"unit"', '"stage":"typecheck"'),
            accepted.replace('"status":"fail"', '"status":"pass"'),
            accepted.replace('"subreason":"filter-refused"', '"subreason":"filter-refused","detail":"private"'),
        ):
            with self.subTest(changed=changed):
                self.assertFalse(audit._record_ok(changed))
                with self.assertRaises(audit.AuditRefusal):
                    audit.validate_summary_records([changed], "core-node")

    def test_control_audit_final_step_may_still_be_pending_while_the_audit_runs(self):
        """GitHub reports a later step as pending until the runner reaches it."""
        cases = (
            ("refs/heads/main", "pending", None, True), ("refs/heads/main", "queued", None, True),
            ("refs/heads/main", "completed", "skipped", False), ("refs/heads/main", "completed", "success", False),
            ("refs/heads/devlane/x", "pending", None, True), ("refs/heads/devlane/x", "queued", None, True),
            ("refs/heads/devlane/x", "completed", "skipped", True),
            ("refs/heads/devlane/x", "completed", "success", False),
            ("refs/heads/devlane/x", "in_progress", None, False), ("refs/heads/devlane/x", "pending", "skipped", False),
        )
        for ref, status, conclusion, accepted in cases:
            with self.subTest(ref=ref, status=status, conclusion=conclusion):
                identity = dict(self.identity, ref=ref)
                jobs = _control_jobs()
                audit_job = next(job for job in jobs if job["name"] == control_audit.RUN_JOB)
                final = [step for step in audit_job["steps"]
                         if step["name"] == control_audit.CONTROL_AUDIT_FINAL_STEPS[2]][0]
                final.update({"status": status, "conclusion": conclusion})
                if accepted:
                    self.assertEqual(len(control_audit.validate_jobs(jobs, identity)), 18)
                else:
                    with self.assertRaises(control_audit.ControlAuditRefusal):
                        control_audit.validate_jobs(jobs, identity)

    def test_control_graph_mutations_are_rejected(self):
        jobs = _control_jobs()
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_jobs(jobs[:-1], self.identity)
        changed = copy.deepcopy(jobs)
        changed[0]["name"] = "unexpected-control-job"
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_jobs(changed, self.identity)
        changed = copy.deepcopy(jobs)
        changed[-1]["head_sha"] = "c" * 40
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_jobs(changed, self.identity)
        changed = copy.deepcopy(jobs)
        changed[-1]["steps"][0]["name"] = "Unexpected child step"
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_jobs(changed, self.identity)
        changed = copy.deepcopy(jobs)
        changed[-1]["steps"][-2]["status"] = "in_progress"
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_jobs(changed, self.identity)

    def test_control_graph_accepts_only_the_diagnosed_synthetic_acceptance_failure(self):
        jobs = _control_jobs()
        synthetic = next(job for job in jobs if job["name"] == control_audit.SYNTHETIC_JOB)
        synthetic["conclusion"] = "failure"
        steps = {step["name"]: step for step in synthetic["steps"]}
        steps["Run full source-free production-path acceptance"]["conclusion"] = "failure"
        steps["Probe the loopback-only Linux network boundary"]["conclusion"] = "skipped"
        result = control_audit.validate_jobs(jobs, self.identity)
        self.assertEqual(result[control_audit.SYNTHETIC_JOB]["conclusion"], "failure")

        changed = copy.deepcopy(jobs)
        changed_synthetic = next(job for job in changed if job["name"] == control_audit.SYNTHETIC_JOB)
        changed_steps = {step["name"]: step for step in changed_synthetic["steps"]}
        changed_steps["Run full source-free production-path acceptance"]["conclusion"] = "success"
        changed_steps["Probe the loopback-only Linux network boundary"]["conclusion"] = "failure"
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_jobs(changed, self.identity)

    def test_terminal_graph_checks_all_child_steps_and_branch_specific_cache_step(self):
        run = {
            "id": 12345, "path": control_audit.WORKFLOW_PATH, "event": "workflow_dispatch",
            "display_title": "public control=control-wave-0001",
            "head_branch": "main", "head_sha": SHA, "run_attempt": 1,
            "status": "completed", "conclusion": "success",
            "repository": {"full_name": control_audit.REPOSITORY, "id": control_audit.REPOSITORY_ID},
            "head_repository": {"full_name": control_audit.REPOSITORY, "id": control_audit.REPOSITORY_ID},
        }
        control_audit.validate_terminal_control_run(
            run, _terminal_control_jobs(), "12345", SHA, expected_wave_id="control-wave-0001")
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_terminal_control_run(
                dict(run, display_title="public control=control-wave-0002"),
                _terminal_control_jobs(), "12345", SHA, expected_wave_id="control-wave-0001")
        in_progress = dict(run, status="in_progress", conclusion=None)
        control_audit.validate_run_record(in_progress, self.identity)
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_run_record(
                dict(in_progress, display_title="public control=control-wave-0002"), self.identity)
        develop_run = dict(run, head_branch="develop")
        jobs = _terminal_control_jobs(require_main=False)
        control_audit.validate_terminal_control_run(develop_run, jobs, "12345", SHA, require_main=False)
        feature_run = dict(run, head_branch="devlane/d211-1110")
        control_audit.validate_terminal_control_run(feature_run, jobs, "12345", SHA, require_main=False)
        for refused in ("a b", "", None, 7, "x" * 201):
            with self.subTest(branch=refused), self.assertRaises(control_audit.ControlAuditRefusal):
                control_audit.validate_terminal_control_run(
                    dict(run, head_branch=refused), jobs, "12345", SHA, require_main=False)
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_terminal_control_run(feature_run, _terminal_control_jobs(), "12345", SHA)
        jobs[0]["steps"][0]["conclusion"] = "failure"
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_terminal_control_run(develop_run, jobs, "12345", SHA, require_main=False)

    def test_composed_provider_annotations_accept_only_the_bounded_exact_macos_notice(self):
        job = "development-feedback-smoke / feedback-smoke-producer macos-15"
        macos_jobs = (
            "policy-macos-15",
            "node-lock-smoke / node-lock-smoke-macos-15",
            job,
        )
        notice = control_audit._macos_capacity_notice(SHA)
        for name in macos_jobs:
            control_audit.validate_control_annotations(name, SHA, 1, [notice])
            control_audit.validate_control_annotations(name, SHA, 64, [notice] * 64)
        for name, count, annotations in (
                (job, 65, [notice] * 65),
                (job, 1, [dict(notice, message="unexpected annotation")]),
                (job, 2, [notice])):
            with self.subTest(name=name, count=count):
                with self.assertRaises(control_audit.ControlAuditRefusal):
                    control_audit.validate_control_annotations(name, SHA, count, annotations)
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_control_annotations("policy-ubuntu-24.04", SHA, 1, [notice])

    def test_refusal_output_contains_only_a_fixed_stage_code(self):
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with patch.object(control_audit, "control_identity", side_effect=control_audit.ControlAuditRefusal()):
            with redirect_stdout(output):
                self.assertEqual(control_audit.main(), 1)
        self.assertEqual(output.getvalue(), "control_audit=refused stage=identity\n")

    def test_control_status_is_posted_once_after_the_accepted_audit_on_any_branch(self):
        from contextlib import redirect_stdout
        from io import StringIO
        identity = dict(self.identity, ref="refs/heads/devlane/d211-1110")
        events = []
        output = StringIO()
        with patch.object(control_audit, "control_identity", return_value=identity), \
                patch.object(control_audit, "GitHubAPI", return_value=object()), \
                patch.object(control_audit, "run_audit", side_effect=lambda api, value: events.append("audit")), \
                patch.object(control_audit, "post_control_status", side_effect=lambda api, value: events.append("status")) as post, \
                patch.dict("os.environ", {"GITHUB_TOKEN": "x"}, clear=False), \
                redirect_stdout(output):
            self.assertEqual(control_audit.main(), 0)
        self.assertEqual(events, ["audit", "status"])
        post.assert_called_once()
        self.assertEqual(output.getvalue(), "control_audit=accepted jobs=18 synthetic_artifacts=1\n")

    def test_control_status_post_uses_exact_sha_context_body_and_actions_bot_response(self):
        from email.message import Message
        from unittest.mock import Mock

        class Response:
            status = 201

            def __init__(self, value):
                self.headers = Message()
                self.headers["Content-Type"] = "application/json"
                self.value = value

            def read(self, limit):
                return self.value

            def close(self):
                pass

        target_url = "https://github.com/" + control_audit.REPOSITORY + "/actions/runs/12345"
        value = {
            "url": "https://api.github.com/repos/" + control_audit.REPOSITORY + "/statuses/" + SHA,
            "context": control_audit.CONTROL_STATUS_CONTEXT,
            "state": "success",
            "description": control_audit.CONTROL_STATUS_DESCRIPTION,
            "target_url": target_url,
            "creator": {"login": control_audit.CONTROL_STATUS_CREATOR, "type": "Bot"},
        }
        opener = Mock()
        opener.open.return_value = Response(json.dumps(value).encode("utf-8"))
        api = type("API", (), {"_token": "token-never-printed", "_opener": opener})()
        control_audit.post_control_status(api, self.identity)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.github.com/repos/" + control_audit.REPOSITORY + "/statuses/" + SHA)
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.get_header("Authorization"), "Bearer token-never-printed")
        self.assertEqual(json.loads(request.data), {
            "context": control_audit.CONTROL_STATUS_CONTEXT,
            "state": "success",
            "description": control_audit.CONTROL_STATUS_DESCRIPTION,
            "target_url": target_url,
        })

    def test_control_status_post_failure_has_only_the_fixed_reason(self):
        from unittest.mock import Mock
        opener = Mock()
        opener.open.side_effect = OSError("secret-bearing API error")
        api = type("API", (), {"_token": "token-never-printed", "_opener": opener})()
        with self.assertRaisesRegex(control_audit.ControlAuditRefusal, "status-post"):
            control_audit.post_control_status(api, self.identity)

    def test_audit_refusal_never_posts_the_control_status(self):
        from contextlib import redirect_stdout
        from io import StringIO
        identity = dict(self.identity, ref="refs/heads/devlane/d211-1110")
        output = StringIO()
        with patch.object(control_audit, "control_identity", return_value=identity), \
                patch.object(control_audit, "GitHubAPI", return_value=object()), \
                patch.object(control_audit, "run_audit", side_effect=control_audit.ControlAuditRefusal("job-graph")), \
                patch.object(control_audit, "post_control_status") as post, \
                patch.dict("os.environ", {"GITHUB_TOKEN": "x"}, clear=False), \
                redirect_stdout(output):
            self.assertEqual(control_audit.main(), 1)
        post.assert_not_called()
        self.assertEqual(output.getvalue(), "control_audit=refused stage=job-graph\n")

    def test_control_marker_and_synthetic_artifact_are_bound(self):
        log = (
            b"KD-PLATFORM-CONTROL schema=1 wave-id=control-wave-0001 control-sha="
            + SHA.encode("ascii") + b" run-id=12345 attempt=1 runner=Linux\n"
        )
        control_audit.validate_control_marker(log, self.identity, "Linux")
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_control_marker(log, self.identity, "Windows")
        windows_log = (b"\x1b[36;1munrelated hosted script echo\x1b[0m\r\n"
                       + log.replace(b"\n", b"\r\n"))
        control_audit.validate_control_marker(windows_log, self.identity, "Linux")
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_control_marker(windows_log.replace(b"\x1b[0m", b"\x1b[2J", 1),
                                                  self.identity, "Linux")
        artifact = {
            "total_count": 1,
            "artifacts": [{
                "id": 7, "name": "development-feedback-smoke-12345-1", "expired": False,
                "size_in_bytes": 100,
                "workflow_run": {"id": 12345, "head_sha": SHA},
            }],
        }
        control_audit.validate_artifacts(artifact, self.identity)
        artifact["artifacts"][0]["name"] = "private-source-artifact"
        with self.assertRaises(control_audit.ControlAuditRefusal):
            control_audit.validate_artifacts(artifact, self.identity)


class WorkflowStaticAcceptanceTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[2]

    def _workflow(self, name):
        return (self.root / ".github/workflows" / name).read_text(encoding="utf-8")

    def test_encrypted_and_control_entrypoints_are_manual_only_and_sha_pinned(self):
        encrypted = self._workflow("devlane-encrypted.yml")
        trigger = encrypted.split("jobs:", 1)[0]
        self.assertIn("on:\n  workflow_dispatch:", trigger)
        for forbidden in ("pull_request", "pull_request_target", "repository_dispatch", "workflow_run", "  push:"):
            self.assertNotIn(forbidden, trigger)
        self.assertIn("permissions: {}", trigger)
        self.assertIn("group: devlane-encrypted", trigger)
        concurrency = trigger.split("concurrency:", 1)[1]
        self.assertNotIn("inputs.wave_id", concurrency)
        self.assertIn("run-name: devlane wave=${{ inputs.wave_id }} bundle=${{ inputs.bundle_id }}", trigger)
        self.assertEqual(encrypted.count("secrets.DEVLANE_DECRYPT_KEY"), 3)
        self.assertLess(encrypted.index("Probe isolation before decryption"), encrypted.index("secrets.DEVLANE_DECRYPT_KEY"))
        self.assertLess(encrypted.index("secrets.DEVLANE_DECRYPT_KEY"), encrypted.index("Execute offline profile"))
        pinned = re.findall(r"(?m)^\s*uses:\s*(\S+)", encrypted)
        external = [use for use in pinned if use.startswith("actions/") or not use.startswith("./")]
        self.assertTrue(external)
        self.assertTrue(all(re.search(r"@[a-f0-9]{40}(?:\s|$)", use) for use in external))
        self.assertIn("actions/cache/restore@3edfce9056124e459a23f683a21433670d47daca", encrypted)
        self.assertIn("actions/cache/save@3edfce9056124e459a23f683a21433670d47daca", encrypted)
        self.assertIn("control_run_id", encrypted)
        graph = audit.validate_workflow_job_graph("linux")
        self.assertEqual(set(graph), set(audit.EXECUTION_JOBS) | {audit.AUDIT_JOB})
        self.assertEqual(graph[audit.AUDIT_JOB]["needs"], list(audit.EXECUTION_JOBS))
        self.assertTrue(all(graph[name]["needs"] == [] for name in audit.EXECUTION_JOBS))
        self.assertNotRegex(encrypted, r"(?m)^ {4}strategy:\s*$|^ {6}matrix:\s*$")
        self.assertEqual(
            {graph[name]["condition"] for name in audit.EXECUTION_JOBS},
            {"${{ inputs.platform == 'linux' }}", "${{ inputs.platform == 'macos' }}",
             "${{ inputs.platform == 'windows' }}"},
        )
        self.assertNotIn("upload-artifact", encrypted)
        control = self._workflow("public-policy.yml").split("jobs:", 1)[0]
        self.assertIn("on:\n  workflow_dispatch:", control)
        self.assertIn("permissions: {}", control)
        self.assertIn("group: public-control-${{ github.ref }}\n", control)
        self.assertNotIn("group: public-control\n", control)
        self.assertIn("run-name: public control=${{ inputs.control_wave_id }}", control)
        self.assertIn("inputs.control_wave_id", control)
        self.assertNotIn("pull_request", control)

    def test_macos_pinned_node_and_npm_are_provisioned_before_preflight(self):
        encrypted = audit.parse_workflow(self.root / ".github/workflows/devlane-encrypted.yml")
        steps = encrypted[audit.MACOS_RUN_JOB]["steps"]
        names = [step["name"] for step in steps]
        setup = steps[names.index("Set up pinned macOS Node runtime")]
        preflight_step = steps[names.index("Prepare hosted runner isolation state")]
        preflight = names.index(preflight_step["name"])
        self.assertEqual(setup["uses"], "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1")
        self.assertEqual(setup["with"], {
            "node-version": "24.22.1", "check-latest": "false", "cache": "",
            "package-manager-cache": "false",
        })
        self.assertLess(names.index(setup["name"]), preflight)
        self.assertNotIn("Install pinned macOS npm runtime", names)
        preflight_script = "\n".join(preflight_step["run"])
        self.assertIn("npm install --global --prefix", preflight_script)
        self.assertIn("control-npm", preflight_script)
        self.assertIn("npm-runtime-install-failed", preflight_script)
        self.assertIn('"$(node --version 2>/dev/null)" == "v24.22.1"', preflight_script)
        self.assertIn('"$(npm --version 2>/dev/null)" == "11.19.1"', preflight_script)

    def test_hosted_crypto_runtime_is_hash_pinned_and_stays_out_of_workload_env(self):
        workflow = audit.parse_workflow(self.root / ".github/workflows/devlane-encrypted.yml")
        requirements = (self.root / "kit/devlane/control-crypto-requirements.txt").read_text(encoding="ascii")
        self.assertEqual(
            [line.split("==", 1)[0] for line in requirements.splitlines() if "==" in line],
            ["cryptography", "cffi", "pycparser"],
        )
        self.assertIn("cryptography==50.0.2", requirements)
        self.assertIn("cffi==2.1.1", requirements)
        self.assertIn("pycparser==3.12", requirements)
        self.assertEqual(requirements.count("--hash=sha256:"), 5)
        for code in (
            "crypto-dependency-install-failed", "crypto-dependency-verification-failed",
            "tool-file-type-invalid", "tool-owner-invalid", "tool-mode-invalid", "tool-symlink", "tool-path-resolve-mismatch",
            "tool-file-unavailable",
            "developer-dir-unexpected", "developer-dir-trust-invalid", "clang-path-invalid", "tool-digest-mismatch",
            "developer-clang-mismatch", "node-runtime-version-invalid", "npm-runtime-install-failed",
            "npm-runtime-version-invalid", "windows-node-runtime-invalid",
            "windows-npm-runtime-install-failed", "windows-npm-runtime-version-invalid",
        ):
            self.assertIn(code, refusal_codes.REFUSAL_CODES)
        bootstrap_only = frozenset((
            "crypto-python-version-invalid", "crypto-dependency-seal-failed",
            "crypto-dependency-check-failed", "crypto-dependency-privileged-check-failed",
        ))
        self.assertTrue(bootstrap_only.isdisjoint(refusal_codes.REFUSAL_CODES))
        self.assertEqual(
            audit.MACOS_BOOTSTRAP_REFUSAL_CODES & bootstrap_only,
            bootstrap_only,
        )
        self.assertEqual(
            audit.WINDOWS_BOOTSTRAP_REFUSAL_CODES & bootstrap_only,
            bootstrap_only - {"crypto-dependency-privileged-check-failed"},
        )
        for job_key, platform_name in ((audit.MACOS_RUN_JOB, "macos"),
                                       (audit.WINDOWS_RUN_JOB, "windows")):
            steps = workflow[job_key]["steps"]
            bootstrap = next(step for step in steps
                             if step["name"] == "Fetch public control and validate dispatch")
            script = "\n".join(bootstrap["run"])
            self.assertIn("--require-hashes", script)
            self.assertIn("--only-binary=:all:", script)
            self.assertIn("--no-deps", script)
            self.assertIn("--index-url https://pypi.org/simple", script)
            self.assertIn("control-python-deps", script)
            self.assertIn("control_python.py", script)
            self.assertNotIn("PYTHONPATH", script)
            platform_scripts = "\n".join(
                line for step in workflow[job_key]["steps"] for line in step.get("run", [])
            )
            self.assertNotIn("PYTHONPATH", platform_scripts)
            if platform_name == "macos":
                self.assertIn("--require-key-absent", script)
                self.assertIn("sudo -n", script)
                self.assertIn("crypto_refuse crypto-dependency-privileged-check-failed", script)
                root_check = script.index('sudo -n "$python_bin" -B kit/devlane/control_python.py')
                self.assertIn(
                    '--platform macos --owner-uid "$runner_uid" check --require-key-absent',
                    script[root_check:],
                )
                decrypt = next(step for step in steps if step["name"] == "Decrypt authenticated bundle")
                self.assertIn(
                    'sudo -n --preserve-env=DEVLANE_DECRYPT_KEY "$python_bin" -B kit/devlane/control_python.py',
                    "\n".join(decrypt["run"]),
                )
            expected_python = "3.15" if platform_name == "macos" else "3.12"
            self.assertIn(("== \"" + expected_python + "\"") if platform_name == "macos"
                          else ("-ne '" + expected_python + "'"), script)
            self.assertIn("crypto-dependency-seal-failed", script)
            self.assertIn("crypto-dependency-check-failed", script)
            steps = workflow[job_key]["steps"]
            runtime_label = "macOS" if platform_name == "macos" else "Windows"
            node_setup_index = next(index for index, step in enumerate(steps)
                                    if step["name"] == "Set up pinned " + runtime_label + " Node runtime")
            preflight_step = next(step for step in steps
                                  if step["name"] == ("Prepare hosted runner isolation state" if platform_name == "macos"
                                                      else "Prepare hosted Windows isolation state"))
            preflight_script = "\n".join(preflight_step["run"])
            self.assertLess(node_setup_index, steps.index(preflight_step))
            self.assertIn("--global --prefix", preflight_script)
            self.assertIn("npm@11.19.1", preflight_script)
            if platform_name == "macos":
                install_index = preflight_script.index("npm install --global --prefix")
                permissions_index = preflight_script.index('chmod -R a+rX,go-w "$npm_prefix"')
                self.assertLess(install_index, permissions_index)
        windows_sandbox = (self.root / "kit/devlane/sandbox_windows.py").read_text(encoding="utf-8")
        self.assertIn('SAFE_ENVIRONMENT = frozenset((', windows_sandbox)
        safe_env = windows_sandbox.split('SAFE_ENVIRONMENT = frozenset((', 1)[1].split('))', 1)[0]
        self.assertNotIn('"PYTHONPATH"', safe_env)
        mac_sandbox = (self.root / "kit/devlane/sandbox_macos.py").read_text(encoding="utf-8")
        clean_env = mac_sandbox.split("def _clean_env(", 1)[1].split("\n\ndef ", 1)[0]
        self.assertNotIn('"PYTHONPATH"', clean_env)

    def test_bootstrap_crypto_reason_filters_match_only_exact_allowlist_literals(self):
        workflow = audit.parse_workflow(self.root / ".github/workflows/devlane-encrypted.yml")
        mac_step = next(step for step in workflow[audit.MACOS_RUN_JOB]["steps"]
                        if step["name"] == "Fetch public control and validate dispatch")
        win_step = next(step for step in workflow[audit.WINDOWS_RUN_JOB]["steps"]
                        if step["name"] == "Fetch public control and validate dispatch")
        mac_script = "\n".join(mac_step["run"])
        win_script = "\n".join(win_step["run"])

        bash_function = re.search(r"(?ms)^\s*crypto_print_reason\(\) \{\n(.*?)^\s*\}", mac_script)
        self.assertIsNotNone(bash_function)
        bash_callable = "crypto_print_reason() {\n" + bash_function.group(1) + "}\ncrypto_print_reason \"$1\"\n"
        canonical = "devlane_crypto_refusal=crypto-acl-owner-untrusted"
        bash_allowed = sorted(audit.MACOS_CRYPTO_CONTROL_REFUSAL_CODES)
        run_bash = sys.platform != "win32"
        for code in bash_allowed if run_bash else ():
            candidate = "devlane_crypto_refusal=" + code
            result = subprocess.run(
                ["bash", "-c", bash_callable, "crypto-reason-test", candidate],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, candidate + "\n")
        malformed = (
            canonical.replace("crypto-acl-owner-untrusted", "Crypto-acl-owner-untrusted"),
            canonical + " ", canonical + "\r", "prefix-" + canonical, canonical + "-suffix",
            "prefix\n" + canonical + "\nsuffix",
        )
        for candidate in malformed if run_bash else ():
            result = subprocess.run(
                ["bash", "-c", bash_callable, "crypto-reason-test", candidate],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "devlane_crypto_refusal=crypto-control-invalid\n")
            self.assertNotIn(candidate, result.stderr)

        powershell_filter = win_script.split("function Write-Crypto-Reason", 1)[1].split("$pythonVersion =", 1)[0]
        self.assertIn("[System.StringComparison]::Ordinal", powershell_filter)
        self.assertIn("Write-Output $allowedLine", powershell_filter)
        self.assertNotIn("-contains $line", powershell_filter)
        self.assertNotIn("Write-Output $line", powershell_filter)
        allowed_match = re.search(r"\$allowed = @\((.*?)\n\s*\)", powershell_filter, re.S)
        self.assertIsNotNone(allowed_match)
        powershell_allowed = re.findall(r"'([^']+)'", allowed_match.group(1))
        self.assertEqual(
            frozenset(item.removeprefix("devlane_crypto_refusal=") for item in powershell_allowed),
            refusal_codes.CRYPTO_CONTROL_REFUSAL_CODES,
        )
        for candidate in malformed:
            matched_literal = next((item for item in powershell_allowed if candidate == item), None)
            self.assertIsNone(matched_literal)
        matched_literal = next(item for item in powershell_allowed if item == canonical)
        self.assertEqual(matched_literal, canonical)

    def test_windows_deadline_starts_before_manual_checkout_and_wer_dumps_are_disabled(self):
        encrypted = self._workflow("devlane-encrypted.yml")
        windows = encrypted.split("  devlane-encrypted-run-windows:", 1)[1]
        bootstrap = windows.split("      - name: Prepare hosted Windows isolation state", 1)[0]
        positions = [bootstrap.index(token) for token in (
            "started = Join-Path $runRoot 'deadline-start'",
            "time.monotonic()",
            "git -C $env:CI_WORKSPACE fetch",
            "git -C $env:CI_WORKSPACE checkout",
            "deadline.py create --file",
            "--started-at-file $started",
        )]
        self.assertEqual(positions, sorted(positions))
        isolation = windows.split("      - name: Prepare hosted Windows isolation state", 1)[1]
        self.assertIn("Windows Error Reporting", isolation)
        self.assertIn("-Name Disabled -Value 1", isolation)

    def test_source_free_control_evidence_cache_is_cross_os_and_workspace_relative(self):
        control = self._workflow("public-policy.yml")
        save = control.split("- name: Save exact source-free control evidence", 1)[1].split(
            "- name:", 1,
        )[0]
        self.assertIn("path: devlane-control-evidence/permit.json", save)
        self.assertIn("enableCrossOsArchive: true", save)
        self.assertIn("DEVLANE_CONTROL_EVIDENCE_PATH: ${{ github.workspace }}/devlane-control-evidence/permit.json",
                      control)
        self.assertNotIn("  push:", control)

    def test_cache_authorization_paths_and_keys_are_run_independent_and_identical(self):
        """The portable path and key stay identical through claim, save, and persisted verification."""
        encrypted = audit.parse_workflow(self.root / ".github/workflows/devlane-encrypted.yml")[audit.RUN_JOB]
        steps = {step["name"]: step for step in encrypted["steps"]}
        permit_paths = {steps[name]["with"]["path"] for name in (
            "Restore one-run bundle permit", "Save one-run bundle permit", "Restore and verify persisted one-run permit")}
        self.assertEqual(permit_paths, {"devlane-bundle-permit/permit.json"})
        permit_keys = {steps[name]["with"]["key"] for name in (
            "Restore one-run bundle permit", "Save one-run bundle permit", "Restore and verify persisted one-run permit")}
        self.assertEqual(permit_keys, {"devlane-permit-v1-${{ inputs.bundle_id }}"})
        control_restore = steps["Restore exact source-free control evidence"]["with"]
        saved = audit.parse_workflow(self.root / ".github/workflows/public-policy.yml")["control-audit"]["steps"][-1]["with"]
        self.assertEqual(control_restore["path"], saved["path"])
        self.assertEqual(control_restore["path"], "devlane-control-evidence/permit.json")
        self.assertEqual(control_restore["fail-on-cache-miss"], "true")
        self.assertEqual(steps["Restore and verify persisted one-run permit"]["with"]["fail-on-cache-miss"], "true")
        self.assertNotIn("fail-on-cache-miss", steps["Restore one-run bundle permit"]["with"])
        for step in encrypted["steps"]:
            for value in step["with"].values():
                self.assertNotIn("github.run_id", value)
        names = [step["name"] for step in encrypted["steps"]]
        self.assertLess(names.index("Save one-run bundle permit"),
                        names.index("Discard local permit copy before persisted verification"))
        self.assertLess(names.index("Discard local permit copy before persisted verification"),
                        names.index("Restore and verify persisted one-run permit"))
        self.assertLess(names.index("Restore and verify persisted one-run permit"),
                        names.index("Verify permit and emit bound dispatch marker"))
        self.assertLess(names.index("Claim this bundle for one run before decryption"),
                        names.index("Fetch ciphertext and sanitized dependency projection"))

    def test_bundle_permit_cache_version_is_shared_by_every_platform_job(self):
        jobs = audit.parse_workflow(self.root / ".github/workflows/devlane-encrypted.yml")
        action_names = (
            "Restore one-run bundle permit", "Save one-run bundle permit",
            "Restore and verify persisted one-run permit",
        )
        versions = set()
        for platform, job_name in audit.PLATFORM_RUN_JOBS.items():
            steps = {step["name"]: step for step in jobs[job_name]["steps"]}
            for name in action_names:
                action = steps[name]
                self.assertEqual(action["with"]["path"], "devlane-bundle-permit/permit.json")
                self.assertEqual(action["with"]["key"], "devlane-permit-v1-${{ inputs.bundle_id }}")
                self.assertEqual(action["with"]["enableCrossOsArchive"], "true")
                versions.add((action["with"]["path"], "zstd-without-long", action["with"]["enableCrossOsArchive"]))
        self.assertEqual(len(versions), 1)

    def test_synthetic_control_exercises_the_cache_claim_restore_sequence_for_real(self):
        steps = audit.parse_workflow(self.root / ".github/workflows/devlane-synthetic.yml")["devlane-synthetic"]["steps"]
        names = [step["name"] for step in steps]
        save = steps[names.index("Save the synthetic permit through the Actions cache")]
        restore = steps[names.index("Restore the synthetic permit with the encrypted-lane path and key shape")]
        self.assertEqual(save["with"]["path"], restore["with"]["path"])
        self.assertEqual(save["with"]["key"], restore["with"]["key"])
        self.assertEqual(restore["with"]["fail-on-cache-miss"], "true")
        verify = "\n".join(steps[names.index("Verify the restored permit and refuse a second claim")]["run"])
        self.assertIn("verify-claim", verify)
        self.assertIn("then\n  exit 1", verify)

    def test_no_step_summary_or_artifact_surface_is_written_by_the_encrypted_lane(self):
        encrypted = self._workflow("devlane-encrypted.yml")
        self.assertNotIn("GITHUB_STEP_SUMMARY", encrypted)
        self.assertNotIn("upload-artifact", encrypted)

    def test_five_automatic_workflows_are_reusable_only_and_called_at_same_commit(self):
        names = (
            "node-lock-smoke.yml", "linux-confinement.yml", "windows-confinement.yml",
            "windows-handoff-synthetic.yml", "development-feedback-smoke.yml",
        )
        for name in names:
            with self.subTest(workflow=name):
                workflow = self._workflow(name)
                trigger = workflow.split("jobs:", 1)[0]
                self.assertIn("on:\n  workflow_call:", trigger)
                for forbidden in ("pull_request", "pull_request_target", "workflow_dispatch", "  push:"):
                    self.assertNotIn(forbidden, trigger)
        control = self._workflow("public-policy.yml")
        for name in names:
            self.assertIn("uses: ./.github/workflows/" + name, control)
        self.assertIn("uses: ./.github/workflows/devlane-synthetic.yml", control)
        self.assertEqual(len(control_audit.CONTROL_JOB_NAMES), 18)

    def test_synthetic_reusable_workflow_has_no_secret_and_linux_probe(self):
        workflow = self._workflow("devlane-synthetic.yml")
        self.assertIn("on:\n  workflow_call:", workflow)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertIn("kit/devlane/test_acceptance.py", workflow)
        self.assertIn("kit/devlane/test_linux_runtime.py", workflow)
        self.assertIn("kit/devlane/test_e2e.py", workflow)
        self.assertRegex(workflow, r're.fullmatch\(r"refs/heads/\[A-Za-z0-9\._/-\]\{1,200\}"')
        self.assertNotIn("(develop|uat|main)", workflow)
        self.assertNotIn("environment:", workflow)

    def test_branch_policy_matches_the_reusable_synthetic_child(self):
        policy = self._workflow("public-policy.yml")
        synthetic = self._workflow("devlane-synthetic.yml")
        expression = r"^refs/heads/[A-Za-z0-9._/-]{1,200}$"
        self.assertIn(expression, policy)
        self.assertRegex(synthetic, r're.fullmatch\(r"refs/heads/\[A-Za-z0-9\._/-\]\{1,200\}"')
        self.assertEqual(control_audit.SOURCE_FREE_BRANCH_REF.pattern, expression[1:-1] + r"\Z")

    def test_control_and_lane_workflows_request_no_write_permission(self):
        for relative in ("devlane-synthetic.yml", "devlane-encrypted.yml", "node-lock-smoke.yml",
                         "linux-confinement.yml", "windows-confinement.yml", "windows-handoff-synthetic.yml",
                         "development-feedback-smoke.yml"):
            with self.subTest(workflow=relative):
                self.assertIsNone(re.search(r"(?m)^\s+[a-z-]+: write\s*$", self._workflow(relative)))
        control = self._workflow("public-policy.yml")
        control_job = control.split("  control-audit:\n", 1)[1]
        self.assertRegex(control_job, r"(?m)^      actions: read$")
        self.assertRegex(control_job, r"(?m)^      checks: read$")
        self.assertRegex(control_job, r"(?m)^      statuses: write$")
        self.assertNotRegex(control.split("  control-audit:\n", 1)[0], r"(?m)^\s+[a-z-]+: write$")
        self.assertEqual(control.count("statuses: write"), 1)

    def test_the_acceptance_step_runs_the_rehearsal_builders(self):
        self.assertIn("kit/devlane/test_rehearsal.py", self._workflow("devlane-synthetic.yml"))
        self.assertTrue((self.root / "kit/devlane/test_rehearsal.py").is_file())

    def test_decryption_key_is_an_environment_secret_limited_to_the_run_job(self):
        encrypted = self._workflow("devlane-encrypted.yml")
        jobs = audit.parse_workflow(self.root / ".github/workflows/devlane-encrypted.yml")
        self.assertEqual(jobs[audit.RUN_JOB]["environment"], "devlane-decrypt")
        self.assertEqual(jobs[audit.AUDIT_JOB].get("environment"), None)
        self.assertEqual(encrypted.count("environment: devlane-decrypt"), 3)
        self.assertEqual(encrypted.count("environment:"), 3)
        run_block = encrypted.split("  devlane-encrypted-audit:", 1)[0]
        self.assertIn("    environment: devlane-decrypt\n", run_block)
        self.assertEqual(encrypted.count("secrets."), 3)
        for run_job in audit.EXECUTION_JOBS:
            holders = [step["name"] for step in jobs[run_job]["steps"] if "DEVLANE_DECRYPT_KEY" in step["env"]]
            self.assertEqual(holders, ["Decrypt authenticated bundle"])
        for relative in ("public-policy.yml", "devlane-synthetic.yml", "node-lock-smoke.yml", "linux-confinement.yml"):
            self.assertNotIn("environment:", self._workflow(relative))


if __name__ == "__main__":
    unittest.main()
