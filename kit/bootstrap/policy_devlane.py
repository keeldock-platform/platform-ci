"""Exact workflow digests for the encrypted dev-lane entry points."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "devlane-encrypted": "6888ef37f83304bd2f7aa9e9ab2c176f7ad7d449f1196990c60d2a4b286b213b",
    "devlane-synthetic": "f07a27fdedbe3390456a1d067529f926a46b1cf3c4d3054dee32f06363a27639",
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
