import argparse
import os
from pathlib import Path
import re
import sys


CONTROL_SHA = re.compile(r"[a-f0-9]{40}\Z")
SCHEMA_VERSION = 2
_CONTROL_DIRECTORY = Path(__file__).resolve(strict=True).parent
sys.path.insert(0, str(_CONTROL_DIRECTORY))

CHANNELS = (
    "https",
    "dns",
    "redirect",
    "proxy",
    "runner_ipc",
    "raw_logs",
    "artifact_upload",
    "cache_upload",
    "runner_files",
    "process_memory",
    "boundary_disablement",
)

BLOCKED_CHANNELS = frozenset(CHANNELS)
REFUSALS = frozenset((
    "app_sandbox_target_mismatch",
    "deprecated_process_sandbox",
    "incomplete_channel_evidence",
    "invalid_control_identity",
    "no_supported_boundary",
    "public_audit_incomplete",
    "runner_vm_is_not_process_boundary",
))
PUBLIC_AUDIT_REASONS = frozenset((
    "invalid_input",
    "api_unavailable",
    "api_status",
    "api_schema",
    "run_identity_mismatch",
    "pagination_incomplete",
    "inventory_changed",
    "artifact_found",
    "log_unavailable",
    "log_too_large",
    "log_format_unknown",
    "canary_exposed",
    "workflow_command_exposed",
    "receipt_invalid",
    "native_job_failed",
    "output_unavailable",
    "internal_error",
))


def _safe_refusal_reason(reason):
    if type(reason) is str and reason in REFUSALS:
        return reason
    return "no_supported_boundary"


def _safe_public_audit_reason(reason):
    if type(reason) is str and reason in PUBLIC_AUDIT_REASONS:
        return reason
    return "internal_error"


class Refusal(Exception):
    def __init__(self, reason, audit_reason=None):
        reason = _safe_refusal_reason(reason)
        super().__init__(reason)
        self.reason = reason
        self.audit_reason = (
            _safe_public_audit_reason(audit_reason)
            if reason == "public_audit_incomplete"
            else None
        )


def valid_sha(value):
    return type(value) is str and CONTROL_SHA.fullmatch(value) is not None


def refuse(reason):
    reason = _safe_refusal_reason(reason)
    return "macos-confinement=refused reason=" + reason


def format_refusal(error):
    if type(error) is not Refusal:
        return refuse("no_supported_boundary")
    reason = _safe_refusal_reason(error.reason)
    line = refuse(reason)
    if reason == "public_audit_incomplete":
        audit_reason = _safe_public_audit_reason(error.audit_reason)
        line += " audit_reason=" + audit_reason
    return line


def _public_audit_reason(audit_module, error):
    try:
        refusal_type = audit_module.AuditRefusal
        if type(refusal_type) is not type or type(error) is not refusal_type:
            return "internal_error"
        return _safe_public_audit_reason(error.reason)
    except BaseException:
        return "internal_error"


def _record_from_receipt(receipt):
    if type(receipt) is not dict or type(receipt.get("channels")) is not dict:
        raise Refusal("incomplete_channel_evidence")
    native_channels = receipt["channels"]
    if set(native_channels) != set(CHANNELS):
        raise Refusal("incomplete_channel_evidence")
    statuses = {}
    for channel in CHANNELS:
        actual = native_channels[channel]
        if channel in ("artifact_upload", "cache_upload"):
            if actual != "pending_audit":
                raise Refusal("incomplete_channel_evidence")
        elif channel == "raw_logs":
            if actual != "captured_private":
                raise Refusal("incomplete_channel_evidence")
        elif actual != "blocked":
            raise Refusal("incomplete_channel_evidence")
        statuses[channel] = "blocked"
    return {
        "boundary": "seatbelt-deny-default",
        "channel_results": statuses,
        "control_sha": receipt.get("control_sha"),
        "developer_mode": "disabled",
        "private_source_executed": False,
        "runner_isolation": "fresh_job_vm",
        "schema_version": SCHEMA_VERSION,
    }


def _validate_candidate_shape(value, control_sha, receipt):
    if not valid_sha(control_sha):
        raise Refusal("invalid_control_identity")
    expected = _record_from_receipt(receipt)
    if expected["control_sha"] != control_sha:
        raise Refusal("invalid_control_identity")
    if type(value) is not dict or set(value) != set(expected):
        raise Refusal("incomplete_channel_evidence")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise Refusal("incomplete_channel_evidence")
    if value["boundary"] == "sandbox-exec":
        raise Refusal("deprecated_process_sandbox")
    if value["boundary"] == "app-sandbox":
        raise Refusal("app_sandbox_target_mismatch")
    if value["runner_isolation"] != "fresh_job_vm":
        raise Refusal("runner_vm_is_not_process_boundary")
    if value["boundary"] != "seatbelt-deny-default":
        raise Refusal("no_supported_boundary")
    if value["developer_mode"] != "disabled":
        raise Refusal("no_supported_boundary")
    if value["private_source_executed"] is not False:
        raise Refusal("incomplete_channel_evidence")
    if type(value["channel_results"]) is not dict or set(value["channel_results"]) != set(CHANNELS):
        raise Refusal("incomplete_channel_evidence")
    if any(
        value["channel_results"].get(channel) != "blocked"
        for channel in BLOCKED_CHANNELS
    ):
        raise Refusal("incomplete_channel_evidence")
    if value != expected:
        raise Refusal("incomplete_channel_evidence")
    return value


def validate_candidate_record(value, control_sha):
    receipt_value = _verify_current_run(control_sha)
    return _validate_candidate_shape(value, control_sha, receipt_value)


def _verify_current_run(control_sha):
    if not valid_sha(control_sha):
        raise Refusal("invalid_control_identity")
    env = os.environ
    if env.get("CI_SHA") != control_sha:
        raise Refusal("invalid_control_identity")
    macos_public_audit = None
    try:
        import macos_public_audit

        audit_status = macos_public_audit.run("audit", environ=env)
        if type(audit_status) is not int or audit_status != 0:
            raise Refusal("public_audit_incomplete")
        receipt = macos_public_audit.validate_receipt(
            env.get("MACOS_NATIVE_RECEIPT_B64URL", ""),
            control_sha,
            env.get("GITHUB_RUN_ID", ""),
            env.get("GITHUB_RUN_ATTEMPT", ""),
        )
    except Refusal:
        raise
    except BaseException as error:
        audit_reason = _public_audit_reason(macos_public_audit, error)
        raise Refusal("public_audit_incomplete", audit_reason) from None
    return receipt


def run_native_probe(control_sha):
    if not valid_sha(control_sha):
        raise Refusal("invalid_control_identity")
    try:
        receipt_value = _verify_current_run(control_sha)
        candidate = _record_from_receipt(receipt_value)
        _validate_candidate_shape(candidate, control_sha, receipt_value)
    except Refusal:
        raise
    except BaseException:
        raise Refusal("public_audit_incomplete") from None
    return (
        "macos-confinement=accepted boundary=seatbelt-deny-default channels=11/11 "
        "evidence=github-native-and-public-audit"
    )


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-sha", required=True)
    arguments = parser.parse_args(argv)
    try:
        result = run_native_probe(arguments.control_sha)
    except Refusal as error:
        print(format_refusal(error))
        return 2
    print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
