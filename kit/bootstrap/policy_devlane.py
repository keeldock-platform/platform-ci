"""Exact workflow digests for the encrypted dev-lane entry points."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "devlane-encrypted": "33d0ee3d2386e37401a92ddf87b23333e9c48a34b2d84de52221820ca9d6e1a8",
    "devlane-synthetic": "58c203ea9f9cb63bb3f95ce91260e9596f6966687b9b0341cfdf8a9863c3fb1b",
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
