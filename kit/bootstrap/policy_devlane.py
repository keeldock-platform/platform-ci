"""Exact workflow digests for the encrypted dev-lane entry points."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "devlane-encrypted": "f8d9b9fd98e81e8660ff83b9a47768205606cd47ac82e8fda39dd4748ed20540",
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
