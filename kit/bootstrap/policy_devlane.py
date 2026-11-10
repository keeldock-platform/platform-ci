"""Exact workflow digests for the encrypted dev-lane entry points."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "devlane-encrypted": "398d45d8b731970089aa2ebdf27b48ef45177dcc462734e24d45bfedfa079373",
    "devlane-synthetic": "ad283ebf2799536cd19fed58ebda14d9577364ddbd0ec9223d321648b44813af",
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
