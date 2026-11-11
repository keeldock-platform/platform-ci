"""Exact workflow digests for the encrypted dev-lane entry points."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "devlane-encrypted": "360d716f7143a23f4cc38d7e4c8d161bbcb29f2932e9ad5e1de637c29637d69b",
    "devlane-synthetic": "3da78ecb8d4f798781f50c5b6da0a1beb88879964272c073429d1b150c33e1ff",
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
