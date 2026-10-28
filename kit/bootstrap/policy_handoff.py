"""Exact workflow digest registry for source-free role-signing workflows."""

WORKFLOW_TEMPLATES = {}
WORKFLOW_SHA256 = {
    "windows-source-admission": "f936e1aeb541dbcd6957d3c897af44948418dc0f2844ab3127e6ac15df561b89",
    "lane-h-windows-receiver": "de59a2d8cdd1d94a84f4a3064b568e1de7ea2ac4788db79f9c15a98da025f1f8",
    "lane-h-linux-fetch-encrypt": "09a4b449f25600c32be7eff79efd7f85cb096ed22eff13565fea5d3c3fa57082",
    "lane-h-capsule-attester": "2a35af114c074e34b6d01e22b63c8076c98cba2835beebe1140bc3eb71789059",
    "attestation-role-signer-probe": "80f6fa5125f7901dd24f5257f1a472df1da33feaddfd583f6a30c486f0486be0",
}
CANDIDATE_WORKFLOWS = ()
