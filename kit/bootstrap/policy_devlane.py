"""Exact workflow digests for the encrypted dev-lane entry points."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "devlane-encrypted": "8b2dccfee27fb54e3298b9336cc412a7e11078cef4e25108d9d7f4e84ab240a3",
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
