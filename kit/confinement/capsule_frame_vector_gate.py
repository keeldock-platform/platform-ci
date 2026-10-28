"""Explicit CI gate for reviewed C sharp capsule vectors.

This file intentionally has no test_ prefix. Ordinary unittest discovery cannot
count a pending vector fixture as interoperability coverage.
"""

import base64
import ctypes
import ctypes.util
import gzip
import hashlib
import hmac
import json
import os
from pathlib import Path
import unittest

import capsule_frame as frame


FIXTURE = Path(__file__).with_name("capsule_frame_vectors.json")
BASE_POINT = bytes.fromhex(
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)


class SystemAesGcm:
    """Independent Python binding to the Ubuntu runner's platform OpenSSL EVP."""

    def __init__(self):
        library_name = ctypes.util.find_library("crypto")
        if not library_name:
            raise AssertionError("platform libcrypto unavailable")
        self.lib = ctypes.CDLL(library_name)
        pointer = ctypes.c_void_p
        integer = ctypes.c_int
        self.lib.EVP_CIPHER_CTX_new.restype = pointer
        self.lib.EVP_CIPHER_CTX_free.argtypes = [pointer]
        self.lib.EVP_aes_256_gcm.restype = pointer
        for name in ("EVP_EncryptInit_ex", "EVP_DecryptInit_ex"):
            function = getattr(self.lib, name)
            function.argtypes = [pointer, pointer, pointer, pointer, pointer]
            function.restype = integer
        for name in ("EVP_EncryptUpdate", "EVP_DecryptUpdate"):
            function = getattr(self.lib, name)
            function.argtypes = [pointer, pointer, pointer, pointer, integer]
            function.restype = integer
        for name in ("EVP_EncryptFinal_ex", "EVP_DecryptFinal_ex"):
            function = getattr(self.lib, name)
            function.argtypes = [pointer, pointer, pointer]
            function.restype = integer
        self.lib.EVP_CIPHER_CTX_ctrl.argtypes = [pointer, integer, integer, pointer]
        self.lib.EVP_CIPHER_CTX_ctrl.restype = integer

    def crypt(self, decrypt, key, nonce, body, aad, tag=None):
        if len(key) != 32 or len(nonce) != 12:
            raise ValueError("invalid AES-GCM input")
        if decrypt and (tag is None or len(tag) != 16):
            raise ValueError("invalid AES-GCM tag")
        context = self.lib.EVP_CIPHER_CTX_new()
        if not context:
            raise ValueError("EVP context unavailable")
        prefix = "EVP_Decrypt" if decrypt else "EVP_Encrypt"
        try:
            init = getattr(self.lib, prefix + "Init_ex")
            update = getattr(self.lib, prefix + "Update")
            final = getattr(self.lib, prefix + "Final_ex")
            if init(context, self.lib.EVP_aes_256_gcm(), None,
                    ctypes.c_char_p(key), ctypes.c_char_p(nonce)) != 1:
                raise ValueError("EVP init failed")
            count = ctypes.c_int()
            if aad and update(context, None, ctypes.byref(count),
                              ctypes.c_char_p(aad), len(aad)) != 1:
                raise ValueError("EVP AAD failed")
            output = ctypes.create_string_buffer(len(body) + 16)
            if body and update(context, output, ctypes.byref(count),
                               ctypes.c_char_p(body), len(body)) != 1:
                raise ValueError("EVP body failed")
            written = count.value if body else 0
            if decrypt:
                tag_buffer = ctypes.create_string_buffer(tag, 16)
                if self.lib.EVP_CIPHER_CTX_ctrl(context, 0x11, 16, tag_buffer) != 1:
                    raise ValueError("EVP tag setup failed")
            if final(context, ctypes.byref(output, written), ctypes.byref(count)) != 1:
                raise ValueError("AES-GCM authentication failed")
            body_result = output.raw[:written + count.value]
            if decrypt:
                return body_result
            tag_buffer = ctypes.create_string_buffer(16)
            if self.lib.EVP_CIPHER_CTX_ctrl(context, 0x10, 16, tag_buffer) != 1:
                raise ValueError("EVP tag retrieval failed")
            return body_result, tag_buffer.raw
        finally:
            self.lib.EVP_CIPHER_CTX_free(context)

    def seal(self, key, nonce, plaintext, aad):
        return self.crypt(False, bytes(key), nonce, plaintext, aad)

    def open(self, key, nonce, ciphertext, tag, aad):
        return self.crypt(True, bytes(key), nonce, ciphertext, aad, tag)


def vector_inputs():
    record = frame.KeyRecord(
        1, bytes(range(20)), 2, 3, bytes(range(16)), BASE_POINT,
        bytes.fromhex("66" * 32), 4, 5,
    )
    record_bytes = frame.encode_key_record(record)
    header = frame.CapsuleHeader(
        1, bytes(range(20)), 2, 3, bytes(range(16)), record.key_id,
        hashlib.sha256(record_bytes).digest(), BASE_POINT, bytes(range(32)),
        bytes.fromhex("a1b2c3d4"), 4, 5, bytes.fromhex("66" * 32),
        hashlib.sha256(b"windows-receiver").digest(),
    )
    manifest = frame.Manifest(
        1, bytes(range(20)), bytes.fromhex("11" * 20),
        bytes.fromhex("22" * 32), 0,
        (frame.ManifestEntry("src/vector.txt", 0o100644,
                             bytes.fromhex("33" * 20), 4,
                             bytes.fromhex("44" * 32)),),
    )
    return record, record_bytes, header, manifest


class CapsuleVectorGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with FIXTURE.open("r", encoding="ascii") as source:
            checked_in = json.load(source)
        encoded = os.environ.get("KD_CAPSULE_VECTOR_B64")
        if not encoded:
            raise AssertionError("C sharp CI vectors missing")
        generated = json.loads(gzip.decompress(base64.b64decode(encoded, validate=True)))
        if generated.get("producer") != "independent-csharp":
            raise AssertionError("vector producer invalid")
        if generated.get("format") != "KDWH-v1-protocol-vectors":
            raise AssertionError("vector format invalid")
        cls.vectors = generated
        cls.checked_in = checked_in
        cls.provider = SystemAesGcm()

    def test_reviewed_fixture_required(self):
        self.assertEqual(self.checked_in.get("status"), "generated",
                         "reviewed vectors missing or pending")
        self.assertEqual(self.vectors, self.checked_in,
                         "C sharp CI vectors differ from reviewed fixture")

    def test_published_primitive_fixtures(self):
        self.assertEqual(BASE_POINT[1:33].hex(),
                         "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
        self.assertEqual(frame.validate_public_point(BASE_POINT), BASE_POINT)
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        prk = hmac.new(salt, ikm, hashlib.sha256).digest()
        self.assertEqual(prk.hex(),
                         "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        self.assertEqual(frame._hkdf_sha256(ikm, salt, info, 42).hex(),
                         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        ciphertext, tag = self.provider.seal(bytes(32), bytes(12), b"", b"")
        self.assertEqual(ciphertext, b"")
        self.assertEqual(tag.hex(), "530f8afbc74536b9a963b4f1c4cb738b")

    def test_framing_and_derivations_match_byte_for_byte(self):
        record, record_bytes, header, manifest = vector_inputs()
        header_bytes = frame.encode_capsule_header(header)
        manifest_bytes = frame.encode_manifest(manifest)
        header_hash = frame.header_digest(header_bytes)
        shared_x = bytes.fromhex("01" * 32)
        info = b"KDWH-v1/HKDF-AES256GCM\x00" + header_hash
        prk = hmac.new(header.hkdf_salt, shared_x, hashlib.sha256).digest()
        expected = {
            "key_record_hex": record_bytes.hex(),
            "header_hex": header_bytes.hex(),
            "header_sha256": header_hash.hex(),
            "manifest_cbor_hex": manifest_bytes.hex(),
            "shared_x": shared_x.hex(),
            "hkdf_salt": header.hkdf_salt.hex(),
            "hkdf_info": info.hex(),
            "hkdf_prk": prk.hex(),
            "aes_key": frame.derive_capsule_aes_key(shared_x, header_bytes).hex(),
            "nonces": {str(i): frame.make_nonce(header.nonce_prefix, i).hex()
                       for i in (0, 15, 16, 271)},
            "aad_manifest_0": frame.make_aad(header_hash, 0, 0).hex(),
            "aad_manifest_15": frame.make_aad(header_hash, 15, 0).hex(),
        }
        for name, value in expected.items():
            self.assertEqual(self.vectors[name], value, name)
        self.assertEqual(frame.decode_key_record(record_bytes), record)
        self.assertEqual(frame.decode_capsule_header(header_bytes), header)
        self.assertEqual(frame.decode_manifest(manifest_bytes), manifest)

    def test_independent_aead_and_refusal_mutations(self):
        _, _, header, manifest = vector_inputs()
        header_bytes = frame.encode_capsule_header(header)
        header_hash = frame.header_digest(header_bytes)
        key = frame.derive_capsule_aes_key(bytes.fromhex("01" * 32), header_bytes)
        manifest_plaintext = frame.encode_manifest_region(
            manifest, bytes(frame.MANIFEST_PLAINTEXT_LENGTH - 8 - len(frame.encode_manifest(manifest))))
        capsule_hash = hashlib.sha256(header_bytes)
        manifest_region = bytearray()
        selected = {}
        for index in range(frame.CHUNK_COUNT):
            kind = 0 if index < frame.MANIFEST_CHUNK_COUNT else 1
            if index == frame.MANIFEST_CHUNK_COUNT:
                manifest_region = bytes(manifest_region)
            plaintext = (manifest_plaintext[index * frame.CHUNK_PLAINTEXT_BYTES:
                           (index + 1) * frame.CHUNK_PLAINTEXT_BYTES]
                         if kind == 0 else bytes(frame.CHUNK_PLAINTEXT_BYTES))
            nonce = frame.make_nonce(header.nonce_prefix, index)
            aad = frame.make_aad(header_hash, index, kind,
                                 manifest_region if kind else None)
            ciphertext, tag = self.provider.seal(key, nonce, plaintext, aad)
            capsule_hash.update(ciphertext)
            capsule_hash.update(tag)
            if kind == 0:
                manifest_region.extend(ciphertext)
                manifest_region.extend(tag)
            if index in (0, 15, 16, 271):
                selected[str(index)] = {
                    "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
                    "tag": tag.hex(),
                }
                if index == 16:
                    bundle_chunk = frame.ChunkRecord(index, kind, ciphertext, tag)
        capsule_hash.update(bytes.fromhex("ab") * frame.TRAILER_LENGTH)
        manifest_hash = frame.manifest_ciphertext_digest(manifest_region)
        self.assertEqual(self.vectors["manifest_ciphertext_sha256"], manifest_hash.hex())
        self.assertEqual(self.vectors["selected_chunks"], selected)
        self.assertEqual(self.vectors["capsule_length"], frame.CAPSULE_LENGTH)
        self.assertEqual(self.vectors["capsule_sha256"], capsule_hash.hexdigest())
        self.assertEqual(self.vectors["aad_bundle_16"],
                         frame.make_aad(header_hash, 16, 1, manifest_region).hex())
        self.assertEqual(self.vectors["aad_bundle_271"],
                         frame.make_aad(header_hash, 271, 1, manifest_region).hex())
        self.assertEqual(frame.open_chunk(self.provider, key, header, bundle_chunk, manifest_region),
                         bytes(frame.CHUNK_PLAINTEXT_BYTES))
        bad_tag = bytes([bundle_chunk.tag[0] ^ 1]) + bundle_chunk.tag[1:]
        with self.assertRaises(frame.CapsuleRefusal) as corrupted:
            frame.open_chunk(self.provider, key, header,
                             frame.ChunkRecord(16, 1, bundle_chunk.ciphertext, bad_tag),
                             manifest_region)
        self.assertEqual(corrupted.exception.reason, frame.REASON_CRYPTO)
        with self.assertRaises(frame.CapsuleRefusal) as reset:
            frame.open_chunk(self.provider, key, header,
                             frame.ChunkRecord(0, 0, bundle_chunk.ciphertext, bundle_chunk.tag))
        self.assertEqual(reset.exception.reason, frame.REASON_CRYPTO)


if __name__ == "__main__":
    unittest.main()
