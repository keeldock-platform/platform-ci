import hashlib
import hmac
import json
import os
from pathlib import Path
import unittest

import capsule_frame as frame


ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "capsule_frame_vectors.json"
GENERATED = os.environ.get("KD_CAPSULE_FRAME_GENERATED")
BASE_POINT = bytes.fromhex(
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)


def vector_inputs():
    key_record = frame.KeyRecord(
        1,
        bytes(range(20)),
        2,
        3,
        bytes(range(16)),
        BASE_POINT,
        bytes.fromhex("66" * 32),
        4,
        5,
    )
    record_bytes = frame.encode_key_record(key_record)
    header = frame.CapsuleHeader(
        1,
        bytes(range(20)),
        2,
        3,
        bytes(range(16)),
        key_record.key_id,
        hashlib.sha256(record_bytes).digest(),
        BASE_POINT,
        bytes(range(32)),
        bytes.fromhex("a1b2c3d4"),
        4,
        5,
        bytes.fromhex("66" * 32),
        hashlib.sha256(b"windows-receiver").digest(),
    )
    manifest = frame.Manifest(
        1,
        bytes(range(20)),
        bytes.fromhex("11" * 20),
        bytes.fromhex("22" * 32),
        0,
        (
            frame.ManifestEntry(
                "src/vector.txt",
                0o100644,
                bytes.fromhex("33" * 20),
                4,
                bytes.fromhex("44" * 32),
            ),
        ),
    )
    return key_record, record_bytes, header, manifest


class IndependentCapsuleVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with FIXTURE.open("r", encoding="ascii") as stream:
            checked_in = json.load(stream)
        if GENERATED:
            with Path(GENERATED).open("r", encoding="ascii") as stream:
                generated = json.load(stream)
            if checked_in.get("status") == "generated" and checked_in != generated:
                raise AssertionError("checked-in vectors differ from C sharp CI generation")
            cls.vectors = generated
        else:
            cls.vectors = checked_in
        if cls.vectors.get("status") == "pending_ci_generation":
            raise unittest.SkipTest("independent C sharp vectors are pending Windows CI generation")
        if cls.vectors.get("status") != "generated":
            raise AssertionError("vector status is not generated")
        if cls.vectors.get("producer") != "independent-csharp":
            raise AssertionError("vectors are not marked as produced by independent C sharp")

    def test_python_structures_match_csharp_vectors(self):
        key_record, record_bytes, header, manifest = vector_inputs()
        header_bytes = frame.encode_capsule_header(header)
        manifest_bytes = frame.encode_manifest(manifest)
        self.assertEqual(self.vectors["key_record_hex"], record_bytes.hex())
        self.assertEqual(self.vectors["header_hex"], header_bytes.hex())
        self.assertEqual(self.vectors["manifest_cbor_hex"], manifest_bytes.hex())
        self.assertEqual(frame.decode_key_record(record_bytes), key_record)
        self.assertEqual(frame.decode_capsule_header(header_bytes), header)
        self.assertEqual(frame.decode_manifest(manifest_bytes), manifest)

    def test_python_crypto_derivations_match_csharp_vectors(self):
        _, _, header, _ = vector_inputs()
        header_bytes = frame.encode_capsule_header(header)
        header_sha256 = frame.header_digest(header_bytes)
        shared_x = bytes.fromhex("01" * 32)
        info = b"KDWH-v1/HKDF-AES256GCM\x00" + header_sha256
        prk = hmac.new(header.hkdf_salt, shared_x, hashlib.sha256).digest()
        aes_key = frame.derive_capsule_aes_key(shared_x, header_bytes)
        self.assertEqual(self.vectors["header_sha256"], header_sha256.hex())
        self.assertEqual(self.vectors["shared_x"], shared_x.hex())
        self.assertEqual(self.vectors["hkdf_salt"], header.hkdf_salt.hex())
        self.assertEqual(self.vectors["hkdf_info"], info.hex())
        self.assertEqual(self.vectors["hkdf_prk"], prk.hex())
        self.assertEqual(self.vectors["aes_key"], aes_key.hex())

    def test_python_nonce_and_aad_match_csharp_vectors(self):
        _, _, header, _ = vector_inputs()
        header_sha256 = frame.header_digest(frame.encode_capsule_header(header))
        expected_nonces = {
            "0": frame.make_nonce(header.nonce_prefix, 0).hex(),
            "15": frame.make_nonce(header.nonce_prefix, 15).hex(),
            "16": frame.make_nonce(header.nonce_prefix, 16).hex(),
            "271": frame.make_nonce(header.nonce_prefix, 271).hex(),
        }
        self.assertEqual(self.vectors["nonces"], expected_nonces)
        self.assertEqual(self.vectors["aad_manifest_0"], frame.make_aad(header_sha256, 0, 0).hex())
        self.assertEqual(self.vectors["aad_manifest_15"], frame.make_aad(header_sha256, 15, 0).hex())
        manifest_sha256 = bytes.fromhex(self.vectors["manifest_ciphertext_sha256"])
        self.assertEqual(
            self.vectors["aad_bundle_16"],
            frame._aad_with_digest(header_sha256, 16, 1, manifest_sha256).hex(),
        )
        self.assertEqual(
            self.vectors["aad_bundle_271"],
            frame._aad_with_digest(header_sha256, 271, 1, manifest_sha256).hex(),
        )

    def test_csharp_gcm_and_capsule_vectors_are_present(self):
        self.assertEqual(self.vectors["format"], "KDWH-v1-protocol-vectors")
        self.assertEqual(self.vectors["capsule_length"], frame.CAPSULE_LENGTH)
        self.assertEqual(len(bytes.fromhex(self.vectors["manifest_ciphertext_sha256"])), 32)
        self.assertEqual(len(bytes.fromhex(self.vectors["capsule_sha256"])), 32)
        for index in ("0", "15", "16", "271"):
            pair = self.vectors["selected_chunks"][index]
            self.assertEqual(len(bytes.fromhex(pair["ciphertext_sha256"])), 32)
            self.assertEqual(len(bytes.fromhex(pair["tag"])), frame.CHUNK_TAG_BYTES)


if __name__ == "__main__":
    unittest.main()
