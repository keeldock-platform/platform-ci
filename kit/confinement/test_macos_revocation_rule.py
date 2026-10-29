import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import macos_private_validation as subject


class RevokedSignerAdmissionTests(unittest.TestCase):
    def test_current_fingerprint_list_produces_revoked_signer_file(self):
        fingerprint = "SHA256:" + "A" * 43
        fingerprints = subject._parse_fingerprint_inventory((fingerprint + "\n").encode("ascii"))
        signers = {fingerprint: (b"ssh-ed25519 key-material\n", b"key-material", ())}
        self.assertEqual(
            subject._revocation_payload(fingerprints, signers),
            b"ssh-ed25519 key-material\n",
        )

    def test_base_signer_verification_always_supplies_revocations(self):
        with patch.object(
            subject,
            "_run_process",
            return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b""),
        ) as run:
            with self.assertRaises(subject.Refusal) as refused:
                subject._verify_commit(
                    Path("repository"),
                    "/usr/bin/git",
                    {},
                    "/usr/bin/ssh-keygen",
                    Path("base-allowed-signers"),
                    Path("revoked-signers"),
                    "a" * 40,
                )
        arguments = run.call_args.args[0]
        self.assertIn("gpg.ssh.allowedSignersFile=base-allowed-signers", arguments)
        self.assertIn("gpg.ssh.revocationFile=revoked-signers", arguments)
        self.assertEqual(arguments[-2:], ("verify-commit", "a" * 40))
        self.assertEqual((refused.exception.reason, refused.exception.stage),
                         ("signature_invalid", "signature"))


if __name__ == "__main__":
    unittest.main()
