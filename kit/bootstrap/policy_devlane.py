"""Exact workflow digests for the encrypted dev-lane entry points."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "devlane-encrypted": "4cf20182bb8274ef1e98675daa74f06469cf010c4f9f89b7678c765a934cb0d1",
    "devlane-synthetic": "eba36edd34d8e4209c032216f015e28c5f67aa560af2fce26ede6b4ba0ceb9ac",
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
