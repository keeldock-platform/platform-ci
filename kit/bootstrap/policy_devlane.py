"""Exact workflow digests for the encrypted dev-lane entry points."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "devlane-encrypted": "360d716f7143a23f4cc38d7e4c8d161bbcb29f2932e9ad5e1de637c29637d69b",
    "devlane-synthetic": "33dc694779f84e7517c28ebe21f206f00caed83320d9216ae98b1f729300e90a",
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
