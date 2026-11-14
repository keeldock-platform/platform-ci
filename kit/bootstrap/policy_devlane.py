"""Exact workflow digests for the encrypted dev-lane entry points."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "devlane-encrypted": "1cf2a35eb02e16028568c60fd5ba4ea095ee0e713d14d8e0d5d205bb140207ba",
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
