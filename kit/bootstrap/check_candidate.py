import argparse
from pathlib import Path

from policy import PolicyError, load_policy_document, validate_workflow_text, verify_git_head
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
            linux_workflow_path = root / ".github/workflows/linux-confinement.yml"
            with linux_workflow_path.open("rb") as source:
                linux_payload = source.read(262145)
            if len(linux_payload) > 262144:
                raise PolicyError("linux-workflow-too-large")
            validate_workflow_text(linux_payload.decode("utf-8"), pool, "linux-confinement")
        scan_tree(root, pool)
        print("candidate-policy=accepted control-sha=" + actual_sha)
    except (OSError, UnicodeDecodeError, ValueError, PolicyError, PublicTreeError):
        print("candidate-policy=refused")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
