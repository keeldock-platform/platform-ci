import argparse
import re
import sys


CONTROL_SHA = re.compile(r"[a-f0-9]{40}\Z")
SCHEMA_VERSION = 1

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

REFUSALS = {
    "app_sandbox_target_mismatch",
    "deprecated_process_sandbox",
    "incomplete_channel_evidence",
    "invalid_control_identity",
    "native_probe_not_authorized",
    "no_supported_boundary",
    "runner_vm_is_not_process_boundary",
}


class Refusal(Exception):
    def __init__(self, reason):
        if reason not in REFUSALS:
            reason = "no_supported_boundary"
        super().__init__(reason)
        self.reason = reason


def valid_sha(value):
    return type(value) is str and CONTROL_SHA.fullmatch(value) is not None


def refuse(reason):
    if reason not in REFUSALS:
        reason = "no_supported_boundary"
    return "macos-confinement=refused reason=" + reason


def validate_candidate_record(value, control_sha):
    if not valid_sha(control_sha):
        raise Refusal("invalid_control_identity")
    if type(value) is not dict or set(value) != {
        "boundary",
        "channel_results",
        "control_sha",
        "developer_mode",
        "runner_isolation",
        "schema_version",
    }:
        raise Refusal("incomplete_channel_evidence")
    if value["schema_version"] != SCHEMA_VERSION or type(value["schema_version"]) is not int:
        raise Refusal("incomplete_channel_evidence")
    if value["control_sha"] != control_sha:
        raise Refusal("invalid_control_identity")
    if value["developer_mode"] != "disabled":
        raise Refusal("incomplete_channel_evidence")
    if value["runner_isolation"] != "fresh_job_vm":
        raise Refusal("runner_vm_is_not_process_boundary")
    if type(value["channel_results"]) is not dict or set(value["channel_results"]) != set(CHANNELS):
        raise Refusal("incomplete_channel_evidence")
    if any(value["channel_results"].get(channel) != "blocked" for channel in CHANNELS):
        raise Refusal("incomplete_channel_evidence")
    if value["boundary"] == "sandbox-exec":
        raise Refusal("deprecated_process_sandbox")
    if value["boundary"] == "app-sandbox":
        raise Refusal("app_sandbox_target_mismatch")
    raise Refusal("no_supported_boundary")


def run_native_probe(control_sha):
    if not valid_sha(control_sha):
        raise Refusal("invalid_control_identity")
    raise Refusal("native_probe_not_authorized")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-sha", required=True)
    arguments = parser.parse_args(argv)
    try:
        result = run_native_probe(arguments.control_sha)
    except Refusal as error:
        print(refuse(error.reason))
        return 2
    print(result)
    return 2


if __name__ == "__main__":
    sys.exit(main())
