"""Exact workflow digests for the encrypted dev-lane entry points."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "devlane-encrypted": "da3f79f3c7af6d75e62936925c1e1a16caf5679de0f1032327f16a7551cfe81a",
    "devlane-synthetic": "9a0e52bcad34b144e8a507af24f35c10c8408f5f85488c9f24217a057a667e13",
}
CANDIDATE_WORKFLOWS = (
    (
        ".github/workflows/devlane-encrypted.yml",
        "devlane-encrypted",
        "devlane-encrypted-workflow-too-large",
    ),
    (
        ".github/workflows/devlane-synthetic.yml",
        "devlane-synthetic",
        "devlane-synthetic-workflow-too-large",
    ),
)
