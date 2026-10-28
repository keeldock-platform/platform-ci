import copy
import hashlib
import hmac
import inspect
import os
import pickle
import random
import struct
import threading
import unittest
from dataclasses import replace
from unittest import mock

import capsule_frame as frame


P256_BASE_POINT = bytes.fromhex(
    "04"
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
_TEST_CONTEXT_ACTIVE = False
INDEPENDENT_PRIMITIVE_KAT_SOURCES = {
    "hkdf_prk_okm": "RFC 5869 Appendix A.1, https://www.rfc-editor.org/rfc/rfc5869.txt",
    "sha256_abc": (
        "NIST SHA-256 worked example, message abc, "
        "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/"
        "documents/examples/SHA256.pdf"
    ),
}
PUBLISHED_POINT_FIXTURE_SOURCE = (
    "SEC 2 version 2.0 section 2.4.2, https://www.secg.org/sec2-v2.pdf"
)
DESIGN_REGRESSION_VECTOR_SOURCES = {
    "layout": "Approved capsule design, format tables at lines 61 through 95",
    "nonce_aad_key": "Approved capsule design, formulas at lines 84 through 86",
    "fake_tags_shared_x": "Test-only deterministic stub in this file; no crypto oracle",
}


def _require_unittest_context():
    current = inspect.currentframe()
    try:
        active_run = False
        while current is not None:
            if current.f_code is unittest.TestCase.run.__code__:
                active_run = True
                break
            current = current.f_back
        if not _TEST_CONTEXT_ACTIVE or not active_run:
            raise RuntimeError("test_only_fake_refused")
    finally:
        del current


class TestOnlyDeterministicFake:
    """Self-generated regression fake, not an AEAD or ECDH KAT provider."""

    def __init__(self):
        _require_unittest_context()
        self.calls = []

    def seal(self, key, nonce, plaintext, aad):
        _require_unittest_context()
        self.calls.append((nonce, aad))
        tag = hmac.new(key, nonce + aad + plaintext, hashlib.sha256).digest()[:16]
        return plaintext, tag

    def open(self, key, nonce, ciphertext, tag, aad):
        _require_unittest_context()
        expected = hmac.new(key, nonce + aad + ciphertext, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected):
            raise ValueError("fake_tag_invalid")
        return ciphertext

    def derive_shared_x(self, peer_public_point):
        _require_unittest_context()
        frame.validate_public_point(peer_public_point)
        return bytes.fromhex("0123456789abcdef" * 4)

    def sender_public_point(self):
        _require_unittest_context()
        return P256_BASE_POINT

    def destroy(self):
        _require_unittest_context()
        self.sender_key_destroyed = True


class RefusingFake:
    def open(self, key, nonce, ciphertext, tag, aad):
        _require_unittest_context()
        raise ValueError("refused")


class TestOnlyUseLedger:
    """In-memory ledger stub for contract tests; never a runtime ledger."""

    def __init__(self):
        _require_unittest_context()
        self.claimed = set()
        self.calls = []

    def claim(self, key_sha256):
        _require_unittest_context()
        self.calls.append(key_sha256)
        if key_sha256 in self.claimed:
            return False
        self.claimed.add(key_sha256)
        return True


def make_key_record(
    control_repository_id=1,
    control_sha=bytes(range(20)),
    run_id=2,
    attempt=3,
    transfer_id=bytes(range(16)),
    receiver_public_point=P256_BASE_POINT,
    workflow_ref_sha256=bytes.fromhex("66" * 32),
    created_at=4,
    expires_at=5,
):
    return frame.KeyRecord(
        control_repository_id,
        control_sha,
        run_id,
        attempt,
        transfer_id,
        receiver_public_point,
        workflow_ref_sha256,
        created_at,
        expires_at,
    )


def make_header():
    return frame.CapsuleHeader(
        1,
        bytes(range(20)),
        2,
        3,
        bytes(range(16)),
        bytes.fromhex("44" * 32),
        bytes.fromhex("55" * 32),
        P256_BASE_POINT,
        bytes(range(32)),
        bytes.fromhex("a1b2c3d4"),
        4,
        5,
        bytes.fromhex("66" * 32),
        hashlib.sha256(b"windows-receiver").digest(),
    )


def make_ephemeral_key(header):
    provider = TestOnlyDeterministicFake()
    return frame.derive_ephemeral_capsule_key(
        provider, P256_BASE_POINT, frame.encode_capsule_header(header)
    )


def make_encryption_session(provider, salt_byte, use_ledger=None):
    header = replace(make_header(), hkdf_salt=bytes((salt_byte,)) * 32)
    key = make_ephemeral_key(header)
    session = frame.EncryptionSession(provider, key, header, use_ledger)
    return session, key, header


def make_manifest(entries=()):
    return frame.Manifest(
        1,
        bytes(range(20)),
        bytes.fromhex("11" * 20),
        bytes.fromhex("22" * 32),
        0,
        tuple(entries),
    )


def random_bytes(generator, length):
    return bytes(generator.getrandbits(8) for unused in range(length))


class CapsuleFrameTests(unittest.TestCase):
    def setUp(self):
        global _TEST_CONTEXT_ACTIVE
        _TEST_CONTEXT_ACTIVE = True

    def tearDown(self):
        global _TEST_CONTEXT_ACTIVE
        _TEST_CONTEXT_ACTIVE = False

    def assert_refusal(self, reason, callback, *args):
        with self.assertRaises(frame.CapsuleRefusal) as raised:
            callback(*args)
        self.assertEqual(raised.exception.reason, reason)

    def test_key_record_design_layout_vector(self):
        record = make_key_record()
        encoded = frame.encode_key_record(record)
        expected_hex = (
            "4b4457484b455931"
            "0001"
            "0001"
            "0000000000000001"
            + bytes(range(20)).hex()
            + "0000000000000002"
            + "00000003"
            + bytes(range(16)).hex()
            + hashlib.sha256(P256_BASE_POINT).hexdigest()
            + P256_BASE_POINT.hex()
            + "66" * 32
            + hashlib.sha256(b"windows-receiver").hexdigest()
            + "0000000000000004"
            + "0000000000000005"
            + "0000000011100000"
            + hashlib.sha256(b"windows-2025").hexdigest()
            + "00" * 35
        )
        self.assertEqual(encoded.hex(), expected_hex)
        self.assertEqual(len(encoded), frame.KEY_RECORD_LENGTH)
        self.assertEqual(frame.decode_key_record(bytes.fromhex(encoded.hex())), record)

    def test_sha256_published_abc_vector(self):
        self.assertEqual(
            hashlib.sha256(b"abc").hexdigest(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_header_design_layout_vector(self):
        header = make_header()
        encoded = frame.encode_capsule_header(header)
        prefix_hex = (
            "4b44574843415031"
            "0001"
            "0001"
            "00000000"
            "0000000000000001"
            + bytes(range(20)).hex()
            + "0000000000000002"
            + "00000003"
            + bytes(range(16)).hex()
            + "44" * 32
            + "55" * 32
            + P256_BASE_POINT.hex()
            + bytes(range(32)).hex()
            + "a1b2c3d4"
            + "0000000000000004"
            + "0000000000000005"
            + "66" * 32
            + hashlib.sha256(b"windows-receiver").hexdigest()
            + "00000010"
            + "00000100"
            + "00100000"
            + "0000000011100000"
        )
        expected_hex = prefix_hex + "00" * (frame.CAPSULE_HEADER_LENGTH - 337)
        self.assertEqual(encoded.hex(), expected_hex)
        self.assertEqual(frame.decode_capsule_header(bytes.fromhex(encoded.hex())), header)

    def test_chunk_offsets_match_fixed_global_layout(self):
        self.assertEqual(frame.CAPSULE_LENGTH, 286261248)
        self.assertEqual(frame.chunk_offset(0), 65536)
        self.assertEqual(frame.chunk_offset(15), 15794416)
        self.assertEqual(frame.chunk_offset(16), 16843008)
        self.assertEqual(frame.chunk_offset(271), 284233968)
        self.assertEqual(frame.TRAILER_START, 285282560)

    def test_chunk_design_layout_vector(self):
        ciphertext = bytes.fromhex("5a") * frame.CHUNK_PLAINTEXT_BYTES
        tag = bytes.fromhex("a5") * frame.CHUNK_TAG_BYTES
        encoded = frame.encode_chunk(16, ciphertext, tag, 1)
        self.assertEqual(encoded.hex(), "5a" * frame.CHUNK_PLAINTEXT_BYTES + "a5" * 16)
        self.assertEqual(frame.decode_chunk(bytes.fromhex(encoded.hex()), 16), frame.ChunkRecord(16, 1, ciphertext, tag))

    def test_trailer_design_layout_vector(self):
        trailer = bytes.fromhex("ab") * frame.TRAILER_LENGTH
        encoded = frame.encode_trailer(trailer)
        self.assertEqual(encoded.hex(), "ab" * frame.TRAILER_LENGTH)
        self.assertEqual(frame.decode_trailer(bytes.fromhex(encoded.hex())), trailer)

    def test_manifest_design_layout_vector(self):
        manifest = make_manifest()
        encoded = frame.encode_manifest(manifest)
        expected_hex = (
            "a8"
            "01"
            "70"
            + b"KDWH-v1/manifest".hex()
            + "02"
            + "01"
            + "03"
            + "54"
            + bytes(range(20)).hex()
            + "04"
            + "64"
            + "73686131"
            + "05"
            + "54"
            + "11" * 20
            + "06"
            + "5820"
            + "22" * 32
            + "07"
            + "00"
            + "08"
            + "80"
        )
        self.assertEqual(encoded.hex(), expected_hex)
        self.assertEqual(frame.decode_manifest(bytes.fromhex(encoded.hex())), manifest)

    def test_nonce_design_formula_vectors(self):
        prefix = bytes.fromhex("01020304")
        self.assertEqual(frame.make_nonce(prefix, 0).hex(), "010203040000000000000000")
        self.assertEqual(frame.make_nonce(prefix, 16).hex(), "010203040000000000000010")
        self.assertEqual(frame.make_nonce(prefix, 271).hex(), "01020304000000000000010f")

    def test_aad_design_formula_vectors(self):
        manifest_aad = frame.make_aad(bytes(32), 0, 0)
        self.assertEqual(
            manifest_aad.hex(),
            "4b4457482d76312f47434d2d4348554e4b00"
            + "00" * 32
            + "0000000000000000"
            + "00"
            + "00000110",
        )
        manifest_region = bytes.fromhex("11") * frame.MANIFEST_REGION_LENGTH
        bundle_aad = frame.make_aad(bytes.fromhex("ff") * 32, 16, 1, manifest_region)
        expected_bundle_aad = (
            "4b4457482d76312f47434d2d4348554e4b00"
            + "ff" * 32
            + "0000000000000010"
            + "01"
            + "00000110"
            + hashlib.sha256(manifest_region).hexdigest()
        )
        self.assertEqual(bundle_aad.hex(), expected_bundle_aad)
        self.assertEqual(
            frame.manifest_ciphertext_digest(manifest_region),
            hashlib.sha256(manifest_region).digest(),
        )

    def test_hkdf_rfc_vector(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        self.assertEqual(
            hmac.new(salt, ikm, hashlib.sha256).hexdigest(),
            "077709362c2e32df0ddc3f0dc47bba6"
            "390b6c73bb50f9c3122ec844ad7c2b3e5",
        )
        output = frame._hkdf_sha256(ikm, salt, info, 42)
        self.assertEqual(
            output.hex(),
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865",
        )

    def test_capsule_key_design_formula_regression(self):
        header_bytes = frame.encode_capsule_header(make_header())
        shared_x = bytes.fromhex("01" * 32)
        header_sha256 = hashlib.sha256(header_bytes).digest()
        salt = header_bytes[201:233]
        prk = hmac.new(salt, shared_x, hashlib.sha256).digest()
        info = b"KDWH-v1/HKDF-AES256GCM\x00" + header_sha256
        expected = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
        self.assertEqual(frame.derive_capsule_aes_key(shared_x, header_bytes), expected)

    @unittest.skipIf(
        frame.INDEPENDENT_PROTOCOL_VECTORS_REQUIRED,
        "Future cross-language interop lane owns independently reviewed capsule H, shared X, PRK, AES key, GCM pairs, and whole-capsule digest",
    )
    def test_independent_protocol_vectors_from_interop_lane(self):
        self.fail("Interop lane must supply fixed independent protocol vectors before closing this gate")

    def test_downgrade_refusal_code(self):
        encoded = bytearray(frame.encode_key_record(make_key_record()))
        encoded[0] = 0
        self.assert_refusal(frame.REASON_DOWNGRADE, frame.decode_key_record, bytes(encoded))
        encoded = bytearray(frame.encode_key_record(make_key_record()))
        encoded[8:10] = b"\x00\x02"
        self.assert_refusal(frame.REASON_DOWNGRADE, frame.decode_key_record, bytes(encoded))
        header = bytearray(frame.encode_capsule_header(make_header()))
        header[frame.HEADER_VERSION_START:frame.HEADER_SUITE_START] = b"\x00\x02"
        self.assert_refusal(frame.REASON_DOWNGRADE, frame.decode_capsule_header, bytes(header))
        encoded = bytearray(frame.encode_key_record(make_key_record()))
        encoded[frame.KEY_SUITE_START:frame.KEY_CONTROL_REPOSITORY_ID_START] = b"\x00\x02"
        self.assert_refusal(frame.REASON_DOWNGRADE, frame.decode_key_record, bytes(encoded))
        header = bytearray(frame.encode_capsule_header(make_header()))
        header[frame.HEADER_SUITE_START:frame.HEADER_FLAGS_START] = b"\x00\x02"
        self.assert_refusal(frame.REASON_DOWNGRADE, frame.decode_capsule_header, bytes(header))

    def test_length_refusal_code(self):
        self.assert_refusal(frame.REASON_LENGTH, frame.decode_capsule_header, b"short")
        self.assert_refusal(frame.REASON_LENGTH, frame.decode_capsule, b"short", make_key_record())
        self.assert_refusal(
            frame.REASON_LENGTH,
            frame.decode_length_prefixed_region,
            struct.pack(">Q", 5) + bytes(8),
            16,
            4,
        )
        self.assert_refusal(
            frame.REASON_LENGTH,
            frame.decode_length_prefixed_region,
            struct.pack(">Q", 5) + bytes(4),
            12,
            10,
        )
        self.assert_refusal(
            frame.REASON_LENGTH,
            frame.decode_length_prefixed_region,
            struct.pack(">Q", 3) + bytes(3),
            12,
            4,
        )

    def test_noncanonical_refusal_code(self):
        encoded = frame.encode_manifest(make_manifest())
        noncanonical = b"\xb8\x08" + encoded[1:]
        self.assert_refusal(frame.REASON_NONCANONICAL, frame.decode_manifest, noncanonical)
        key_two_offset = 3 + len(b"KDWH-v1/manifest")
        for replacement in (0, 1):
            malformed = bytearray(encoded)
            malformed[key_two_offset] = replacement
            self.assert_refusal(frame.REASON_NONCANONICAL, frame.decode_manifest, bytes(malformed))

    def test_global_index_refusal_code(self):
        indices = list(range(frame.CHUNK_COUNT))
        indices[16] = 15
        self.assert_refusal(frame.REASON_CHUNK_INDEX, frame.validate_global_indices, indices)
        self.assert_refusal(
            frame.REASON_CHUNK_INDEX,
            frame.validate_global_indices,
            list(range(frame.CHUNK_COUNT - 1)),
        )
        indices = list(range(frame.CHUNK_COUNT))
        indices[15], indices[16] = indices[16], indices[15]
        self.assert_refusal(frame.REASON_CHUNK_INDEX, frame.validate_global_indices, indices)
        reset_indices = list(range(frame.MANIFEST_CHUNK_COUNT)) + list(range(frame.BUNDLE_CHUNK_COUNT))
        self.assert_refusal(frame.REASON_CHUNK_INDEX, frame.validate_global_indices, reset_indices)
        self.assert_refusal(frame.REASON_CHUNK_INDEX, frame.make_nonce, bytes(4), 272)

    def test_trailing_data_refusal_code(self):
        self.assert_refusal(
            frame.REASON_TRAILING,
            frame.decode_trailer,
            bytes(frame.TRAILER_LENGTH + 1),
        )
        self.assert_refusal(
            frame.REASON_TRAILING,
            frame.decode_manifest,
            frame.encode_manifest(make_manifest()) + b"\x00",
        )
        self.assert_refusal(
            frame.REASON_TRAILING,
            frame.decode_key_record,
            frame.encode_key_record(make_key_record()) + b"\x00",
        )
        self.assert_refusal(
            frame.REASON_TRAILING,
            frame.decode_capsule_header,
            frame.encode_capsule_header(make_header()) + b"\x00",
        )
        with mock.patch.object(frame, "CAPSULE_LENGTH", 4):
            self.assert_refusal(frame.REASON_TRAILING, frame.decode_capsule, bytes(5), make_key_record())

    def test_full_capsule_view_keeps_one_immutable_owner(self):
        raw = bytes(frame.CAPSULE_LENGTH)
        self.assert_refusal(frame.REASON_DOWNGRADE, frame.decode_capsule, raw, make_key_record())
        view = frame.CapsuleView(raw, make_header())
        self.assertIs(view.chunk(0).ciphertext.obj, raw)
        self.assertIs(view.chunk(271).tag.obj, raw)
        self.assertIs(view.manifest_ciphertext_region.obj, raw)
        self.assertIs(view.trailer.obj, raw)
        self.assertTrue(view.chunk(0).ciphertext.readonly)
        self.assertEqual(len(view.trailer), 978688)

    def test_manifest_limit_refusal_code(self):
        bad_path = frame.ManifestEntry("../escape", 0o100644, bytes(20), 0, bytes(32))
        self.assert_refusal(
            frame.REASON_MANIFEST_LIMIT,
            frame.encode_manifest,
            make_manifest((bad_path,)),
        )
        too_large = frame.ManifestEntry(
            "large.bin", 0o100644, bytes(20), frame.MAX_ENTRY_BYTES + 1, bytes(32)
        )
        self.assert_refusal(
            frame.REASON_MANIFEST_LIMIT,
            frame.encode_manifest,
            make_manifest((too_large,)),
        )
        def entry(path):
            return frame.ManifestEntry(path, 0o100644, bytes(20), 0, bytes(32))
        for paths in (("A", "a"), ("a", "a/b"), ("A", "a/b"), ("A/b", "a")):
            self.assert_refusal(
                frame.REASON_MANIFEST_LIMIT,
                frame.encode_manifest,
                make_manifest(tuple(entry(path) for path in paths)),
            )
        for path in ("\u00b5.txt", "\u03bc.txt", "\u00df.txt", "\u212a.txt"):
            self.assert_refusal(
                frame.REASON_MANIFEST_LIMIT,
                frame.encode_manifest,
                make_manifest((entry(path),)),
            )

    def test_invalid_point_refusal_code(self):
        self.assert_refusal(
            frame.REASON_POINT,
            frame.validate_public_point,
            b"\x04" + bytes(64),
        )
        self.assertEqual(frame.validate_public_point(P256_BASE_POINT), P256_BASE_POINT)
        self.assert_refusal(frame.REASON_POINT, frame.validate_public_point, b"\x02" + P256_BASE_POINT[1:])
        field = int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
        self.assert_refusal(
            frame.REASON_POINT,
            frame.validate_public_point,
            b"\x04" + field.to_bytes(32, "big") + P256_BASE_POINT[33:],
        )

    def test_structure_refusal_code_and_exception_conversion(self):
        self.assert_refusal(frame.REASON_STRUCTURE, frame.decode_manifest, None)
        with mock.patch.object(frame._CborReader, "read", side_effect=RuntimeError("parser_fault")):
            self.assert_refusal(frame.REASON_STRUCTURE, frame.decode_manifest, b"\xa8")
        header = bytearray(frame.encode_capsule_header(make_header()))
        header[frame.HEADER_FLAGS_START] = 1
        self.assert_refusal(frame.REASON_STRUCTURE, frame.decode_capsule_header, bytes(header))

    def test_crypto_refusal_code(self):
        chunk = frame.ChunkRecord(0, 0, bytes(frame.CHUNK_PLAINTEXT_BYTES), bytes(16))
        self.assert_refusal(
            frame.REASON_CRYPTO,
            frame.open_chunk,
            RefusingFake(),
            bytes(32),
            make_header(),
            chunk,
        )

    def test_length_prefix_round_trip_and_cap(self):
        encoded = frame.encode_length_prefixed_region(b"abc", b"z", 12, 4)
        self.assertEqual(encoded, bytes.fromhex("00000000000000036162637a"))
        self.assertEqual(frame.decode_length_prefixed_region(encoded, 12, 4), (b"abc", b"z"))
        over_cap = struct.pack(">Q", 5) + bytes(8)
        self.assert_refusal(
            frame.REASON_LENGTH,
            frame.decode_length_prefixed_region,
            over_cap,
            16,
            4,
        )

    def test_header_key_record_binding(self):
        record = make_key_record()
        record_bytes = frame.encode_key_record(record)
        header = frame.CapsuleHeader(
            record.control_repository_id,
            record.control_sha,
            record.run_id,
            record.attempt,
            record.transfer_id,
            record.key_id,
            hashlib.sha256(record_bytes).digest(),
            P256_BASE_POINT,
            bytes(32),
            bytes(4),
            record.created_at,
            record.expires_at,
            record.workflow_ref_sha256,
            hashlib.sha256(b"windows-receiver").digest(),
        )
        self.assertTrue(frame.validate_header_key_binding(header, record_bytes))
        mismatched = frame.CapsuleHeader(
            header.control_repository_id,
            header.control_sha,
            header.run_id,
            header.attempt + 1,
            header.transfer_id,
            header.receiver_key_id,
            header.key_record_sha256,
            header.sender_public_point,
            header.hkdf_salt,
            header.nonce_prefix,
            header.created_at,
            header.expires_at,
            header.workflow_ref_sha256,
            header.intended_job_sha256,
        )
        self.assert_refusal(
            frame.REASON_STRUCTURE,
            frame.validate_header_key_binding,
            mismatched,
            record,
        )
        self.assert_refusal(
            frame.REASON_STRUCTURE,
            frame.validate_header_key_binding,
            replace(header, intended_job_sha256=bytes.fromhex("77" * 32)),
            record,
        )
        encoded_header = bytearray(frame.encode_capsule_header(header))
        encoded_header[frame.HEADER_INTENDED_JOB_SHA256_START] ^= 1
        self.assert_refusal(
            frame.REASON_STRUCTURE,
            frame.decode_capsule_header,
            bytes(encoded_header),
        )

    def test_test_only_fake_refuses_outside_test_context(self):
        global _TEST_CONTEXT_ACTIVE
        retained = TestOnlyDeterministicFake()
        _TEST_CONTEXT_ACTIVE = False
        with self.assertRaisesRegex(RuntimeError, "test_only_fake_refused"):
            TestOnlyDeterministicFake()
        with self.assertRaisesRegex(RuntimeError, "test_only_fake_refused"):
            retained.seal(bytes(32), bytes(12), b"", b"")
        with self.assertRaisesRegex(RuntimeError, "test_only_fake_refused"):
            retained.open(bytes(32), bytes(12), b"", bytes(16), b"")
        with self.assertRaisesRegex(RuntimeError, "test_only_fake_refused"):
            retained.derive_shared_x(P256_BASE_POINT)
        _TEST_CONTEXT_ACTIVE = True
        self.assertIsInstance(TestOnlyDeterministicFake(), TestOnlyDeterministicFake)
        refusals = []

        def outside_unittest_stack():
            try:
                TestOnlyDeterministicFake()
            except RuntimeError as error:
                refusals.append(str(error))

        worker = threading.Thread(target=outside_unittest_stack)
        worker.start()
        worker.join()
        self.assertEqual(refusals, ["test_only_fake_refused"])

    def test_fake_chunk_seal_open_round_trip(self):
        provider = TestOnlyDeterministicFake()
        plaintext = bytes.fromhex("7c") * frame.CHUNK_PLAINTEXT_BYTES
        session, unused_key, header = make_encryption_session(provider, 0x33)
        chunk = session.seal_chunk(0, plaintext)
        self.assertEqual(chunk.kind, 0)
        shared_x = bytes.fromhex("0123456789abcdef" * 4)
        open_key = frame.derive_capsule_aes_key(shared_x, frame.encode_capsule_header(header))
        self.assertEqual(frame.open_chunk(provider, open_key, header, chunk), plaintext)

    def test_encryption_session_single_use_and_order(self):
        self.assertFalse(hasattr(frame, "seal_chunk"))
        provider = TestOnlyDeterministicFake()
        plaintext = bytes(frame.CHUNK_PLAINTEXT_BYTES)
        session, key, header = make_encryption_session(provider, 0x34)
        session.seal_chunk(0, plaintext)
        self.assert_refusal(frame.REASON_CHUNK_INDEX, session.seal_chunk, 0, plaintext)
        self.assert_refusal(frame.REASON_CRYPTO, session.seal_chunk, 1, plaintext)
        self.assertEqual(len(provider.calls), 1)
        self.assert_refusal(
            frame.REASON_CRYPTO,
            frame.EncryptionSession,
            provider,
            key,
            header,
        )

    def test_encryption_session_failure_consumes_key(self):
        provider = mock.Mock()
        provider.seal.side_effect = ValueError("provider failure")
        plaintext = bytes(frame.CHUNK_PLAINTEXT_BYTES)
        session, key, header = make_encryption_session(provider, 0x35)
        self.assert_refusal(frame.REASON_CRYPTO, session.seal_chunk, 0, plaintext)
        self.assert_refusal(frame.REASON_CRYPTO, session.seal_chunk, 0, plaintext)
        self.assertTrue(key._destroyed)
        self.assertTrue(all(value == 0 for value in key._material))
        self.assertEqual(provider.seal.call_count, 1)
        self.assert_refusal(
            frame.REASON_CRYPTO,
            frame.EncryptionSession,
            provider,
            key,
            header,
        )

    def test_duplicate_constructor_does_not_erase_active_session(self):
        provider = TestOnlyDeterministicFake()
        session, key, header = make_encryption_session(provider, 0x44)
        self.assert_refusal(
            frame.REASON_CRYPTO, frame.EncryptionSession, provider, key, header
        )
        invalid_header = replace(header, intended_job_sha256=bytes(32))
        self.assert_refusal(
            frame.REASON_STRUCTURE,
            frame.EncryptionSession,
            provider,
            key,
            invalid_header,
        )
        self.assertFalse(key._destroyed)
        session.seal_chunk(0, bytes(frame.CHUNK_PLAINTEXT_BYTES))
        self.assertEqual(len(provider.calls), 1)
        session.abort()

    def test_ephemeral_key_and_session_refuse_copy_and_pickle(self):
        provider = mock.Mock()
        header = replace(make_header(), hkdf_salt=bytes.fromhex("3c" * 32))
        key = make_ephemeral_key(header)
        self.assert_refusal(frame.REASON_CRYPTO, frame.EncryptionSession, provider, bytes(32), header)
        self.assert_refusal(
            frame.REASON_CRYPTO,
            frame.EphemeralCapsuleKey,
            bytes(32),
            bytes(32),
            None,
        )
        for operation in (bytes, copy.copy, copy.deepcopy, pickle.dumps):
            self.assert_refusal(frame.REASON_CRYPTO, operation, key)
        session = frame.EncryptionSession(provider, key, header)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            self.assert_refusal(frame.REASON_CRYPTO, operation, session)
        with self.assertRaises(TypeError):
            vars(session)
        session.abort()
        self.assertTrue(key._destroyed)
        self.assertTrue(all(value == 0 for value in key._material))

    def test_ephemeral_factory_destroys_sender_provider(self):
        sender = TestOnlyDeterministicFake()
        header = replace(make_header(), hkdf_salt=bytes.fromhex("42" * 32))
        key = frame.derive_ephemeral_capsule_key(
            sender, P256_BASE_POINT, frame.encode_capsule_header(header)
        )
        self.assertTrue(sender.sender_key_destroyed)
        key.destroy()
        failed_sender = mock.Mock()
        failed_sender.sender_public_point.return_value = P256_BASE_POINT
        failed_sender.derive_shared_x.return_value = bytes.fromhex("01" * 32)
        failed_sender.destroy.side_effect = OSError("destroy failed")
        self.assert_refusal(
            frame.REASON_CRYPTO,
            frame.derive_ephemeral_capsule_key,
            failed_sender,
            P256_BASE_POINT,
            frame.encode_capsule_header(header),
        )
        invalid_sender = mock.Mock()
        self.assert_refusal(
            frame.REASON_DOWNGRADE,
            frame.derive_ephemeral_capsule_key,
            invalid_sender,
            P256_BASE_POINT,
            bytes(frame.CAPSULE_HEADER_LENGTH),
        )
        invalid_sender.destroy.assert_called_once_with()

    def test_session_refuses_a_different_process_before_provider_use(self):
        provider = mock.Mock()
        session, key, unused_header = make_encryption_session(provider, 0x3d)
        with mock.patch.object(frame.os, "getpid", return_value=os.getpid() + 1):
            self.assert_refusal(
                frame.REASON_CRYPTO,
                session.seal_chunk,
                0,
                bytes(frame.CHUNK_PLAINTEXT_BYTES),
            )
        self.assertTrue(key._destroyed)
        self.assertTrue(all(value == 0 for value in key._material))
        provider.seal.assert_not_called()

    @unittest.skipUnless(hasattr(os, "fork"), "fork unavailable on this platform")
    def test_inherited_session_refuses_after_fork(self):
        provider = mock.Mock()
        session, key, unused_header = make_encryption_session(provider, 0x40)
        reader, writer = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(reader)
            try:
                session.seal_chunk(0, bytes(frame.CHUNK_PLAINTEXT_BYTES))
            except frame.CapsuleRefusal as error:
                result = error.reason.encode("ascii")
            except BaseException:
                result = b"unexpected_exception"
            else:
                result = b"accepted"
            os.write(writer, result)
            os.close(writer)
            os._exit(0)
        os.close(writer)
        result = os.read(reader, 64)
        os.close(reader)
        os.waitpid(child, 0)
        self.assertEqual(result, frame.REASON_CRYPTO.encode("ascii"))
        self.assertFalse(key._destroyed)
        session.abort()

    def test_ephemeral_key_is_bound_to_its_header(self):
        provider = mock.Mock()
        header = replace(make_header(), hkdf_salt=bytes.fromhex("3e" * 32))
        key = make_ephemeral_key(header)
        changed_header = replace(header, hkdf_salt=bytes.fromhex("3f" * 32))
        self.assert_refusal(
            frame.REASON_CRYPTO, frame.EncryptionSession, provider, key, changed_header
        )
        self.assertTrue(key._destroyed)
        provider.seal.assert_not_called()
        valid_header = replace(make_header(), hkdf_salt=bytes.fromhex("43" * 32))
        second_key = make_ephemeral_key(valid_header)
        invalid_header = replace(valid_header, intended_job_sha256=bytes(32))
        self.assert_refusal(
            frame.REASON_STRUCTURE,
            frame.EncryptionSession,
            provider,
            second_key,
            invalid_header,
        )
        self.assertTrue(second_key._destroyed)

    def test_optional_persistent_claim_precedes_provider_use(self):
        provider = mock.Mock()
        use_ledger = TestOnlyUseLedger()
        session, key, header = make_encryption_session(provider, 0x38, use_ledger)
        self.assertEqual(len(use_ledger.calls), 1)
        self.assertEqual(len(use_ledger.calls[0]), 32)
        provider.seal.assert_not_called()
        with mock.patch.object(frame, "_ENCRYPTION_KEYS_USED", set()):
            repeated_key = make_ephemeral_key(header)
            self.assert_refusal(
                frame.REASON_CRYPTO,
                frame.EncryptionSession,
                provider,
                repeated_key,
                header,
                use_ledger,
            )
        self.assertTrue(repeated_key._destroyed)
        self.assertEqual(len(use_ledger.calls), 2)
        self.assertEqual(use_ledger.calls[0], use_ledger.calls[1])
        provider.seal.assert_not_called()
        session.abort()

    def test_optional_persistent_claim_fails_closed(self):
        provider = mock.Mock()
        session, key, unused_header = make_encryption_session(provider, 0x39)
        self.assertFalse(key._destroyed)
        session.abort()
        self.assertTrue(key._destroyed)
        refused_ledger = mock.Mock()
        refused_ledger.claim.return_value = False
        refused_header = replace(make_header(), hkdf_salt=bytes.fromhex("3a" * 32))
        refused_key = make_ephemeral_key(refused_header)
        self.assert_refusal(
            frame.REASON_CRYPTO,
            frame.EncryptionSession,
            provider,
            refused_key,
            refused_header,
            refused_ledger,
        )
        self.assertTrue(refused_key._destroyed)
        uncertain_ledger = mock.Mock()
        uncertain_ledger.claim.side_effect = OSError("storage uncertain")
        uncertain_header = replace(make_header(), hkdf_salt=bytes.fromhex("3b" * 32))
        uncertain_key = make_ephemeral_key(uncertain_header)
        self.assert_refusal(
            frame.REASON_CRYPTO,
            frame.EncryptionSession,
            provider,
            uncertain_key,
            uncertain_header,
            uncertain_ledger,
        )
        self.assertTrue(uncertain_key._destroyed)
        provider.seal.assert_not_called()

    def test_encryption_session_context_exit_aborts_partial_attempt(self):
        provider = TestOnlyDeterministicFake()
        plaintext = bytes(frame.CHUNK_PLAINTEXT_BYTES)
        session, key, header = make_encryption_session(provider, 0x37)
        with session:
            session.seal_chunk(0, plaintext)
        self.assertTrue(key._destroyed)
        self.assert_refusal(frame.REASON_CRYPTO, session.seal_chunk, 1, plaintext)
        self.assert_refusal(
            frame.REASON_CRYPTO,
            frame.EncryptionSession,
            provider,
            key,
            header,
        )

    def test_encryption_session_bundle_aad_uses_all_manifest_records(self):
        provider = TestOnlyDeterministicFake()
        session, unused_key, unused_header = make_encryption_session(provider, 0x36)
        plaintext = bytes(frame.CHUNK_PLAINTEXT_BYTES)
        manifest_hasher = hashlib.sha256()
        for index in range(frame.MANIFEST_CHUNK_COUNT):
            chunk = session.seal_chunk(index, plaintext)
            manifest_hasher.update(chunk.ciphertext)
            manifest_hasher.update(chunk.tag)
        session.seal_chunk(frame.FIRST_BUNDLE_INDEX, plaintext)
        self.assertTrue(provider.calls[-1][1].endswith(manifest_hasher.digest()))

    def test_completed_session_erases_key_material(self):
        provider = TestOnlyDeterministicFake()
        session, key, unused_header = make_encryption_session(provider, 0x41)
        plaintext = bytes(frame.CHUNK_PLAINTEXT_BYTES)
        for index in range(frame.CHUNK_COUNT):
            session.seal_chunk(index, plaintext)
        self.assertEqual(len(provider.calls), frame.CHUNK_COUNT)
        self.assertTrue(key._destroyed)
        self.assertTrue(all(value == 0 for value in key._material))
        self.assert_refusal(frame.REASON_CRYPTO, session.seal_chunk, 0, plaintext)

    def test_seeded_round_trip_loops(self):
        generator = random.Random(731941)
        for unused in range(30):
            record = make_key_record(
                control_repository_id=generator.randrange(1, 1 << 32),
                control_sha=random_bytes(generator, 20),
                run_id=generator.randrange(1, 1 << 32),
                attempt=generator.randrange(1, 1000),
                transfer_id=random_bytes(generator, 16),
                workflow_ref_sha256=random_bytes(generator, 32),
                created_at=generator.randrange(1, 100000),
                expires_at=100001,
            )
            decoded = frame.decode_key_record(frame.encode_key_record(record))
            self.assertEqual(decoded, record)
        for unused in range(40):
            entries = []
            for index in range(generator.randrange(0, 5)):
                entries.append(
                    frame.ManifestEntry(
                        "files/{:03d}.bin".format(index),
                        generator.choice((0o100644, 0o100755)),
                        random_bytes(generator, 20),
                        generator.randrange(0, 10000),
                        random_bytes(generator, 32),
                    )
                )
            manifest = frame.Manifest(
                1,
                random_bytes(generator, 20),
                random_bytes(generator, 20),
                random_bytes(generator, 32),
                generator.randrange(0, 100000),
                tuple(entries),
            )
            self.assertEqual(frame.decode_manifest(frame.encode_manifest(manifest)), manifest)


if __name__ == "__main__":
    unittest.main(verbosity=2)
