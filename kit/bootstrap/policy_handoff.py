"""Windows handoff lane workflow validation data.

This lane registers the source-free role-signer workflows and their exact
workflow digests. It must not import the shared policy module.

Lane interface, identical in every lane module:

WORKFLOW_TEMPLATES maps a workflow kind to its exact expected text.
WORKFLOW_SHA256 maps a workflow kind to the expected SHA-256 of its text.
CANDIDATE_WORKFLOWS lists, in order, the path, workflow kind and size-failure
code that the candidate checker validates when the pool is platform.
"""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "windows-source-admission": "23a81d6d45a0a02668fad7ae2567af6414e403bd3b76d055bd2dab58d997390f",
    "lane-h-windows-receiver": "5347fcfdf29c979f7af8c63cee48f77b856fd7cc38d34ad675da75a0b806b448",
    "lane-h-linux-fetch-encrypt": "ba01a7658328b57f44eed5c1059632ef524a3462e029dca0d677451d2f64f01b",
    "lane-h-capsule-attester": "92425cb257d4ecf5317bfae2bf5df5a9f22b66f428a43f9d7f36b241579e51cc",
    "attestation-role-signer-probe": "4bf03368bdd197b8a8c749ae81defc69e56915f3eef52b8bc578552eff970c91",
}
CANDIDATE_WORKFLOWS = ()
