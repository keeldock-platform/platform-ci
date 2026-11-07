"""Retired Rust lock-return workflow lane.

Rust dependency safety now runs in ordinary CI from committed Cargo.lock files. This compatibility
module intentionally exports an empty lane interface while other platform policy code is being
consumed by older checkouts.
"""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {}
CANDIDATE_WORKFLOWS = ()
