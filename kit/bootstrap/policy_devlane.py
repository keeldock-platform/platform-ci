"""Exact workflow digests for the encrypted dev-lane entry points."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "devlane-encrypted": "17f0e0c6cca655a9d41040bbfce17e330a454531e1d01f1a557dd99c7e0371ab",
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
