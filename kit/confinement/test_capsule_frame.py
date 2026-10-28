import hashlib
import hmac
import random
import struct
import unittest
from unittest import mock

import capsule_frame as frame


P256_BASE_POINT = bytes.fromhex(
    "04"
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
_TEST_CONTEXT_ACTIVE = False


class TestOnlyDeterministicFake:
    def __init__(self):
        if not _TEST_CONTEXT_ACTIVE:
            raise RuntimeError("test_only_fake_refused")

    def seal(self, key, nonce, plaintext, aad):
        tag = hmac.new(key, nonce + aad + plaintext, hashlib.sha256).digest()[:16]
        return plaintext, tag

    def open(self, key, nonce, ciphertext, tag, aad):
        expected = hmac.new(key, nonce + aad + ciphertext, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected):
            raise ValueError("fake_tag_invalid")
        return ciphertext

    def derive_shared_x(self, peer_public_point):
        frame.validate_public_point(peer_public_point)
        return bytes.fromhex("0123456789abcdef" * 4)


class RefusingFake:
    def open(self, key, nonce, ciphertext, tag, aad):
        raise ValueError("refused")


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
        bytes.fromhex("77" * 32),
    )


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

    def test_key_record_known_answer_vector(self):
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
        self.assertEqual(
            hashlib.sha256(b"abc").hexdigest(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_header_known_answer_vector(self):
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
            + "77" * 32
            + "00000010"
            + "00000100"
            + "00100000"
            + "0000000011100000"
        )
        expected_hex = prefix_hex + "00" * (frame.CAPSULE_HEADER_LENGTH - 337)
        self.assertEqual(encoded.hex(), expected_hex)
        self.assertEqual(frame.decode_capsule_header(bytes.fromhex(encoded.hex())), header)

    def test_chunk_offsets_match_fixed_global_layout(self):
        self.assertEqual(frame.chunk_offset(0), 65536)
        self.assertEqual(frame.chunk_offset(15), 15794416)
        self.assertEqual(frame.chunk_offset(16), 16843008)
        self.assertEqual(frame.chunk_offset(271), 284233968)

    def test_chunk_known_answer_vector(self):
        ciphertext = bytes.fromhex("5a") * frame.CHUNK_PLAINTEXT_BYTES
        tag = bytes.fromhex("a5") * frame.CHUNK_TAG_BYTES
        encoded = frame.encode_chunk(16, ciphertext, tag, 1)
        self.assertEqual(encoded.hex(), "5a" * frame.CHUNK_PLAINTEXT_BYTES + "a5" * 16)
        self.assertEqual(frame.decode_chunk(bytes.fromhex(encoded.hex()), 16), frame.ChunkRecord(16, 1, ciphertext, tag))

    def test_trailer_known_answer_vector(self):
        trailer = bytes.fromhex("ab") * frame.TRAILER_LENGTH
        encoded = frame.encode_trailer(trailer)
        self.assertEqual(encoded.hex(), "ab" * frame.TRAILER_LENGTH)
        self.assertEqual(frame.decode_trailer(bytes.fromhex(encoded.hex())), trailer)

    def test_manifest_known_answer_vector(self):
        manifest = make_manifest()
        encoded = frame.encode_manifest(manifest)
        expected_hex = (
            "a8"
            "01"
            "70"
            + frame.MANIFEST_DOMAIN.hex()
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

    def test_nonce_known_answer_vectors(self):
        prefix = bytes.fromhex("01020304")
        self.assertEqual(frame.make_nonce(prefix, 0).hex(), "010203040000000000000000")
        self.assertEqual(frame.make_nonce(prefix, 16).hex(), "010203040000000000000010")
        self.assertEqual(frame.make_nonce(prefix, 271).hex(), "01020304000000000000010f")

    def test_aad_known_answer_vectors(self):
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
        fixed_manifest_digest = bytes.fromhex("12") * 32
        with mock.patch.object(
            frame,
            "manifest_ciphertext_digest",
            return_value=fixed_manifest_digest,
        ):
            bundle_aad = frame.make_aad(bytes.fromhex("ff") * 32, 16, 1, manifest_region)
        expected_bundle_aad = (
            "4b4457482d76312f47434d2d4348554e4b00"
            + "ff" * 32
            + "0000000000000010"
            + "01"
            + "00000110"
            + "12" * 32
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
        output = frame._hkdf_sha256(ikm, salt, info, 42)
        self.assertEqual(
            output.hex(),
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865",
        )

    def test_capsule_key_uses_header_salt_and_digest(self):
        header_bytes = frame.encode_capsule_header(make_header())
        header = frame.decode_capsule_header(header_bytes)
        shared_x = bytes.fromhex("01" * 32)
        expected = frame.derive_aes_key(
            shared_x,
            header.hkdf_salt,
            frame.header_digest(header_bytes),
        )
        self.assertEqual(frame.derive_capsule_aes_key(shared_x, header_bytes), expected)

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

    def test_length_refusal_code(self):
        self.assert_refusal(frame.REASON_LENGTH, frame.decode_capsule_header, b"short")
        self.assert_refusal(
            frame.REASON_LENGTH,
            frame.decode_length_prefixed_region,
            struct.pack(">Q", 5),
            12,
            4,
        )

    def test_noncanonical_refusal_code(self):
        encoded = frame.encode_manifest(make_manifest())
        noncanonical = b"\xb8\x08" + encoded[1:]
        self.assert_refusal(frame.REASON_NONCANONICAL, frame.decode_manifest, noncanonical)

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

    def test_invalid_point_refusal_code(self):
        self.assert_refusal(
            frame.REASON_POINT,
            frame.validate_public_point,
            b"\x04" + bytes(64),
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

    def test_every_reason_code_has_a_negative_case(self):
        covered = {
            frame.REASON_DOWNGRADE,
            frame.REASON_LENGTH,
            frame.REASON_NONCANONICAL,
            frame.REASON_CHUNK_INDEX,
            frame.REASON_TRAILING,
            frame.REASON_MANIFEST_LIMIT,
            frame.REASON_POINT,
            frame.REASON_STRUCTURE,
            frame.REASON_CRYPTO,
        }
        self.assertEqual(covered, set(frame.REASON_CODES))

    def test_length_prefix_round_trip_and_cap(self):
        encoded = frame.encode_length_prefixed_region(b"abc", b"z", 12, 4)
        self.assertEqual(encoded, bytes.fromhex("00000000000000036162637a"))
        self.assertEqual(frame.decode_length_prefixed_region(encoded, 12, 4), (b"abc", b"z"))
        over_cap = struct.pack(">Q", 5)
        self.assert_refusal(
            frame.REASON_LENGTH,
            frame.decode_length_prefixed_region,
            over_cap,
            12,
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
            bytes.fromhex("77" * 32),
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

    def test_test_only_fake_refuses_outside_test_context(self):
        global _TEST_CONTEXT_ACTIVE
        _TEST_CONTEXT_ACTIVE = False
        with self.assertRaisesRegex(RuntimeError, "test_only_fake_refused"):
            TestOnlyDeterministicFake()
        _TEST_CONTEXT_ACTIVE = True
        self.assertIsInstance(TestOnlyDeterministicFake(), TestOnlyDeterministicFake)

    def test_fake_chunk_seal_open_round_trip(self):
        provider = TestOnlyDeterministicFake()
        key = bytes.fromhex("33" * 32)
        header = make_header()
        plaintext = bytes.fromhex("7c") * frame.CHUNK_PLAINTEXT_BYTES
        chunk = frame.seal_chunk(provider, key, header, 0, plaintext)
        self.assertEqual(chunk.kind, 0)
        self.assertEqual(frame.open_chunk(provider, key, header, chunk), plaintext)

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
