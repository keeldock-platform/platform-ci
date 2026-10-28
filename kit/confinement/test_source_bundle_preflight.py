"""Synthetic Git bundle cases for resource preflight."""

import hashlib
import io
import unittest
import zlib
from dataclasses import replace
from unittest.mock import patch

import source_bundle_preflight as subject


def _object_id(data, kind="blob", algorithm="sha1"):
    digest = hashlib.new(algorithm)
    digest.update((kind + " " + str(len(data))).encode("ascii") + b"\x00" + data)
    return digest.digest()


def _object_header(kind, size):
    first = ((kind & 7) << 4) | (size & 15)
    size >>= 4
    result = bytearray()
    if size:
        first |= 128
    result.append(first)
    while size:
        byte = size & 127
        size >>= 7
        if size:
            byte |= 128
        result.append(byte)
    return bytes(result)


def _entry(kind, payload, base=b"", declared=None):
    size = len(payload) if declared is None else declared
    return _object_header(kind, size) + base + zlib.compress(payload)


def _varint(value):
    result = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        result.append(byte | (128 if value else 0))
        if not value:
            return bytes(result)


def _literal_delta(source_size, result):
    return _varint(source_size) + _varint(len(result)) + bytes((len(result),)) + result


def _bundle(entries, version=2, algorithm="sha1", pack_version=2,
            pack_signature=b"PACK", bundle_magic=None, capability=None, advertised=None):
    if bundle_magic is None:
        bundle_magic = bytes((35,)) + (b" v2 git bundle\n" if version == 2 else b" v3 git bundle\n")
    if capability is None:
        capability = b"@object-format=sha256\n" if algorithm == "sha256" else b""
    if advertised is None:
        advertised = _object_id(b"a", algorithm=algorithm)
    header = bundle_magic + capability + advertised.hex().encode("ascii") + b" refs/heads/main\n\n"
    pack = (pack_signature + pack_version.to_bytes(4, "big")
            + len(entries).to_bytes(4, "big") + b"".join(entries))
    return header + pack + hashlib.new(algorithm, pack).digest()


def _one_blob(data=b"a", **options):
    options.setdefault("advertised", _object_id(data, algorithm=options.get("algorithm", "sha1")))
    return _bundle((_entry(3, data),), **options)


def _offset_chain(depth):
    entries = []
    base = _entry(3, b"a")
    entries.append(base)
    previous_offset = 12
    next_offset = 12 + len(base)
    for index in range(depth):
        result = bytes((98 + index,))
        delta = _literal_delta(1, result)
        distance = next_offset - previous_offset
        if distance > 127:
            raise AssertionError("synthetic offset is too large")
        encoded = _entry(6, delta, bytes((distance,)))
        entries.append(encoded)
        previous_offset = next_offset
        next_offset += len(encoded)
    return _bundle(entries)


def _one_delta():
    base = _entry(3, b"a")
    distance = len(base)
    delta = _entry(6, _literal_delta(1, b"b"), bytes((distance,)))
    return _bundle((base, delta))


class SourceBundlePreflightTests(unittest.TestCase):
    def assert_refusal(self, bundle, reason, limits=None):
        result = subject.preflight(bundle, subject.BundleLimits() if limits is None else limits)
        self.assertIsInstance(result, subject.Refused)
        self.assertFalse(result.accepted)
        self.assertIn(result.reason, subject.REFUSAL_REASONS)
        self.assertEqual(result.reason, reason)

    def test_small_bundle_from_bytes_and_binary_stream(self):
        raw = _one_blob()
        for source in (raw, io.BytesIO(raw)):
            with self.subTest(source=type(source).__name__):
                result = subject.preflight(source)
                self.assertIsInstance(result, subject.Accepted)
                self.assertTrue(result.accepted)
                self.assertEqual(result.object_count, 1)
                self.assertEqual(result.total_inflated_bytes, 1)
                self.assertEqual(result.total_expanded_bytes, 1)
                self.assertEqual(result.bundle_sha256, hashlib.sha256(raw).hexdigest())
        empty = subject.preflight(_one_blob(b""))
        self.assertIsInstance(empty, subject.Accepted)
        self.assertEqual(empty.total_inflated_bytes, 0)

    def test_v3_sha1_and_sha256_packs_use_the_declared_hash_format(self):
        for algorithm in ("sha1", "sha256"):
            with self.subTest(algorithm=algorithm):
                raw = _one_blob(version=3, algorithm=algorithm, pack_version=3)
                result = subject.preflight(raw)
                self.assertIsInstance(result, subject.Accepted)
                self.assertEqual(result.object_count, 1)
        raw = _one_blob(version=3, algorithm="sha256")
        self.assert_refusal(raw[:-1] + bytes((raw[-1] ^ 1,)), "checksum-mismatch")

    def test_v2_prerequisite_header_is_parseable_without_thin_pack_bases(self):
        raw = _one_blob()
        magic = bytes((35,)) + b" v2 git bundle\n"
        prerequisite = b"-" + b"0" * 40 + b" earlier commit\n"
        bundle = raw.replace(magic, magic + prerequisite, 1)
        self.assertIsInstance(subject.preflight(bundle), subject.Accepted)

    def test_input_byte_limit_passes_at_limit_and_refuses_one_more(self):
        raw = _one_blob()
        at_limit = replace(subject.BundleLimits(), max_input_bytes=len(raw))
        below = replace(at_limit, max_input_bytes=len(raw) - 1)
        self.assertIsInstance(subject.preflight(raw, at_limit), subject.Accepted)
        self.assert_refusal(raw, "input-size-limit", below)

    def test_object_count_passes_at_limit_and_refuses_one_more(self):
        raw = _bundle((_entry(3, b"a"), _entry(3, b"b")))
        at_limit = replace(subject.BundleLimits(), max_objects=2)
        below = replace(at_limit, max_objects=1)
        self.assertIsInstance(subject.preflight(raw, at_limit), subject.Accepted)
        self.assert_refusal(raw, "object-count-limit", below)

    def test_blob_size_passes_at_limit_and_refuses_one_more(self):
        raw = _one_blob(b"a" * 6)
        at_limit = replace(subject.BundleLimits(), max_blob_bytes=6)
        below = replace(at_limit, max_blob_bytes=5)
        self.assertIsInstance(subject.preflight(raw, at_limit), subject.Accepted)
        self.assert_refusal(raw, "object-size-limit", below)

    def test_metadata_size_passes_at_limit_and_refuses_one_more(self):
        for kind in (1, 2, 4):
            with self.subTest(kind=kind):
                raw = _bundle((_entry(kind, b"x" * 6),),
                              advertised=_object_id(b"x" * 6, kind=subject.OBJECT_TYPES[kind]))
                at_limit = replace(subject.BundleLimits(), max_metadata_bytes=6)
                below = replace(at_limit, max_metadata_bytes=5)
                self.assertIsInstance(subject.preflight(raw, at_limit), subject.Accepted)
                self.assert_refusal(raw, "object-size-limit", below)

    def test_inflated_object_exceeding_declared_size_refuses(self):
        raw = _bundle((_entry(3, b"abcde", declared=4),))
        limits = replace(subject.BundleLimits(), max_blob_bytes=4)
        self.assert_refusal(raw, "object-size-limit", limits)
        self.assert_refusal(raw, "object-invalid")
        short = _bundle((_entry(3, b"abc", declared=4),))
        self.assert_refusal(short, "object-invalid")

    def test_total_inflation_passes_at_limit_and_refuses_one_more(self):
        raw = _one_delta()
        at_limit = replace(subject.BundleLimits(), max_total_inflated_bytes=5)
        below = replace(at_limit, max_total_inflated_bytes=4)
        result = subject.preflight(raw, at_limit)
        self.assertIsInstance(result, subject.Accepted)
        self.assertEqual(result.total_inflated_bytes, 5)
        self.assertEqual(result.total_expanded_bytes, 2)
        self.assert_refusal(raw, "total-inflated-limit", below)

    def test_total_expansion_passes_at_limit_and_refuses_one_more(self):
        raw = _bundle((_entry(3, b"aaa"), _entry(3, b"bbbb")),
                      advertised=_object_id(b"aaa"))
        at_limit = replace(subject.BundleLimits(), max_total_inflated_bytes=7)
        below = replace(at_limit, max_total_inflated_bytes=6)
        result = subject.preflight(raw, at_limit)
        self.assertIsInstance(result, subject.Accepted)
        self.assertEqual(result.total_expanded_bytes, 7)
        self.assert_refusal(raw, "total-expanded-limit", below)

    def test_highly_compressed_out_of_tree_blob_is_bounded(self):
        compressed = _entry(3, b"x" * 100000, declared=32)
        raw = _bundle((compressed,))
        limits = replace(subject.BundleLimits(), max_blob_bytes=32)
        self.assert_refusal(raw, "object-size-limit", limits)

    def test_delta_result_size_passes_at_limit_and_refuses_one_more(self):
        base = _entry(2, b"a" * 6)
        instructions = b"\x06\x07\x90\x06\x01b"
        delta = _entry(6, instructions, bytes((len(base),)))
        raw = _bundle((base, delta), advertised=_object_id(b"a" * 6, kind="tree"))
        at_limit = replace(subject.BundleLimits(), max_metadata_bytes=7)
        below = replace(at_limit, max_metadata_bytes=6)
        self.assertIsInstance(subject.preflight(raw, at_limit), subject.Accepted)
        self.assert_refusal(raw, "object-size-limit", below)

    def test_delta_result_expansion_passes_at_limit_and_refuses_one_more(self):
        base = _entry(3, b"a" * 6)
        instructions = b"\x06\x07\x90\x06\x01b"
        delta = _entry(6, instructions, bytes((len(base),)))
        raw = _bundle((base, delta), advertised=_object_id(b"a" * 6))
        at_limit = replace(subject.BundleLimits(), max_total_inflated_bytes=13)
        below = replace(at_limit, max_total_inflated_bytes=12)
        result = subject.preflight(raw, at_limit)
        self.assertIsInstance(result, subject.Accepted)
        self.assertEqual(result.total_inflated_bytes, 12)
        self.assertEqual(result.total_expanded_bytes, 13)
        self.assert_refusal(raw, "total-expanded-limit", below)

    def test_offset_delta_depth_passes_at_limit_and_refuses_one_more(self):
        raw = _offset_chain(3)
        at_limit = replace(subject.BundleLimits(), max_delta_depth=3)
        below = replace(at_limit, max_delta_depth=2)
        self.assertIsInstance(subject.preflight(raw, at_limit), subject.Accepted)
        self.assert_refusal(raw, "delta-depth-limit", below)

    def test_ref_delta_resolves_forward_base_in_the_pack(self):
        base_data = b"a"
        base_id = _object_id(base_data)
        delta = _entry(7, _literal_delta(1, b"b"), base_id)
        raw = _bundle((delta, _entry(3, base_data)))
        result = subject.preflight(raw)
        self.assertIsInstance(result, subject.Accepted)
        self.assertEqual(result.object_count, 2)
        self.assertEqual(result.total_expanded_bytes, 2)
        sha256_base = _object_id(base_data, algorithm="sha256")
        sha256_delta = _entry(7, _literal_delta(1, b"b"), sha256_base)
        sha256_raw = _bundle((sha256_delta, _entry(3, base_data)), version=3, algorithm="sha256")
        self.assertIsInstance(subject.preflight(sha256_raw), subject.Accepted)

    def test_thin_pack_ref_delta_refuses(self):
        delta = _entry(7, _literal_delta(1, b"b"), b"\x11" * 20)
        self.assert_refusal(_bundle((delta,)), "thin-pack")

    def test_invalid_offset_and_delta_instruction_refuse(self):
        invalid_offset = _bundle((_entry(3, b"a"), _entry(6, _literal_delta(1, b"b"), b"\x01")))
        self.assert_refusal(invalid_offset, "delta-base-invalid")
        base = _entry(3, b"a")
        broken_delta = _entry(6, b"\x01\x01\x00", bytes((len(base),)))
        self.assert_refusal(_bundle((base, broken_delta)), "object-invalid")
        wrong_source = _entry(6, _literal_delta(2, b"b"), bytes((len(base),)))
        self.assert_refusal(_bundle((base, wrong_source)), "object-invalid")

    def test_bundle_and_pack_header_errors_have_exact_reasons(self):
        bad_magic = bytes((35,)) + b" v4 git bundle\n"
        self.assert_refusal(_one_blob(bundle_magic=bad_magic), "bundle-header-invalid")
        self.assert_refusal(_one_blob(version=2, capability=b"@object-format=sha256\n"),
                            "bundle-header-invalid")
        self.assert_refusal(_one_blob(pack_signature=b"FAIL"), "pack-header-invalid")
        self.assert_refusal(_one_blob(pack_version=4), "pack-header-invalid")
        self.assert_refusal(_one_blob(version=3, capability=b"@unknown=value\n"),
                            "bundle-header-invalid")
        wrong_ref = _bundle((_entry(3, b"a"),), advertised=b"\x01" * 20)
        self.assert_refusal(wrong_ref, "bundle-header-invalid")

    def test_truncation_checksum_and_trailing_data_have_exact_reasons(self):
        raw = _one_blob()
        self.assert_refusal(raw[:-1], "truncated")
        self.assert_refusal(raw[:-1] + bytes((raw[-1] ^ 1,)), "checksum-mismatch")
        self.assert_refusal(raw + b"x", "trailing-data")

    def test_unknown_object_type_refuses(self):
        for kind in (0, 5):
            with self.subTest(kind=kind):
                self.assert_refusal(_bundle((_entry(kind, b"a"),)), "object-type-invalid")

    def test_scratch_peak_passes_at_limit_and_refuses_one_more(self):
        raw = _one_delta()
        peak = len(raw) + 6
        at_limit = replace(subject.BundleLimits(), max_scratch_bytes=peak)
        below = replace(at_limit, max_scratch_bytes=peak - 1)
        self.assertIsInstance(subject.preflight(raw, at_limit), subject.Accepted)
        self.assert_refusal(raw, "resource-limit", below)

    def test_wall_and_cpu_deadlines_pass_at_limit_and_refuse_one_more(self):
        raw = _one_blob()

        def clock(after):
            first = True

            def read():
                nonlocal first
                if first:
                    first = False
                    return 0
                return after

            return read

        wall_limits = replace(subject.BundleLimits(), max_wall_seconds=1)
        for after, expected in ((1, subject.Accepted), (2, subject.Refused)):
            with patch.object(subject.time, "monotonic", side_effect=clock(after)):
                with patch.object(subject.time, "process_time", return_value=0):
                    result = subject.preflight(raw, wall_limits)
            self.assertIsInstance(result, expected)
            if after == 2:
                self.assertEqual(result.reason, "resource-limit")

        cpu_limits = replace(subject.BundleLimits(), max_cpu_seconds=1)
        for after, expected in ((1, subject.Accepted), (2, subject.Refused)):
            with patch.object(subject.time, "monotonic", return_value=0):
                with patch.object(subject.time, "process_time", side_effect=clock(after)):
                    result = subject.preflight(raw, cpu_limits)
            self.assertIsInstance(result, expected)
            if after == 2:
                self.assertEqual(result.reason, "resource-limit")

    def test_invalid_stream_and_limits_return_closed_reasons(self):
        class BadStream:
            def read(self, unused_size):
                return "not bytes"

        self.assert_refusal(BadStream(), "input-invalid")
        self.assert_refusal(object(), "input-invalid")
        invalid = replace(subject.BundleLimits(), max_objects=0)
        self.assert_refusal(_one_blob(), "input-invalid", invalid)

        class FailingStream:
            def read(self, unused_size):
                raise OSError("synthetic read error")

        self.assert_refusal(FailingStream(), "input-error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
