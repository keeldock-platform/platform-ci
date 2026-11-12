"""Exact workflow digests for the encrypted dev-lane entry points."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "devlane-encrypted": "8a53ac1d47e469750c7a7e25d7c7a1565e4df598063e6b42ed7565a5b1353e86",
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
