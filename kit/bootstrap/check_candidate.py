import argparse
from pathlib import Path

from policy import (
    LANE_CANDIDATE_WORKFLOWS,
    PolicyError,
    load_policy_document,
    validate_workflow_text,
    verify_git_head,
)
from public_tree import PublicTreeError, scan_tree


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--pool", required=True)
    parser.add_argument("--sha", required=True)
    arguments = parser.parse_args()
    root = Path(arguments.root)
    try:
        actual_sha = verify_git_head(root, arguments.sha)
        pool = load_policy_document(root / "ci/policy.json", arguments.pool)
        workflow_path = root / ".github/workflows/public-policy.yml"
        with workflow_path.open("rb") as source:
            workflow_payload = source.read(262145)
        if len(workflow_payload) > 262144:
            raise PolicyError("workflow-too-large")
        workflow_text = workflow_payload.decode("utf-8")
        validate_workflow_text(workflow_text, pool)
        if pool == "platform":
            macos_workflow_path = root / ".github/workflows/macos-capability.yml"
            with macos_workflow_path.open("rb") as source:
                macos_payload = source.read(262145)
            if len(macos_payload) > 262144:
                raise PolicyError("macos-workflow-too-large")
            validate_workflow_text(macos_payload.decode("utf-8"), pool, "macos-capability")
            reviewed_macos_workflow_path = root / ".github/workflows/macos-reviewed-build.yml"
            with reviewed_macos_workflow_path.open("rb") as source:
                reviewed_macos_payload = source.read(262145)
            if len(reviewed_macos_payload) > 262144:
                raise PolicyError("reviewed-macos-workflow-too-large")
            validate_workflow_text(
                reviewed_macos_payload.decode("utf-8"), pool, "macos-reviewed-build"
            )
            macos_cache_workflow_path = root / ".github/workflows/macos-cache-proof.yml"
            with macos_cache_workflow_path.open("rb") as source:
                macos_cache_payload = source.read(262145)
            if len(macos_cache_payload) > 262144:
                raise PolicyError("macos-cache-workflow-too-large")
            validate_workflow_text(macos_cache_payload.decode("utf-8"), pool, "macos-cache-proof")
            for path, workflow_kind in (
                (".github/workflows/macos-source-reader-preflight.yml", "macos-source-reader"),
                (".github/workflows/macos-rules-reader-preflight.yml", "macos-rules-source-reader"),
                (".github/workflows/macos-rules-bootstrap.yml", "macos-rules-bootstrap"),
                (".github/workflows/macos-core-bootstrap.yml", "macos-core-bootstrap"),
                (".github/workflows/node-lock-smoke.yml", "node-lock-smoke"),
                (".github/workflows/node-lock-return.yml", "node-lock-return"),
                (".github/workflows/core-rust-format-return.yml", "core-rust-format-return"),
                (".github/workflows/core-build-diagnostic-return.yml", "core-build-diagnostic-return"),
                (".github/workflows/development-feedback-smoke.yml", "development-feedback-smoke"),
            ):
                source_reader_path = root / path
                with source_reader_path.open("rb") as source:
                    source_reader_payload = source.read(262145)
                if len(source_reader_payload) > 262144:
                    raise PolicyError("source-reader-workflow-too-large")
                validate_workflow_text(
                    source_reader_payload.decode("utf-8"), pool, workflow_kind
                )
            for path, workflow_kind, too_large_code in LANE_CANDIDATE_WORKFLOWS:
                lane_workflow_path = root / path
                with lane_workflow_path.open("rb") as source:
                    lane_payload = source.read(262145)
                if len(lane_payload) > 262144:
                    raise PolicyError(too_large_code)
                validate_workflow_text(lane_payload.decode("utf-8"), pool, workflow_kind)
        scan_tree(root, pool)
        print("candidate-policy=accepted control-sha=" + actual_sha)
    except (OSError, UnicodeDecodeError, ValueError, PolicyError, PublicTreeError):
        print("candidate-policy=refused")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
