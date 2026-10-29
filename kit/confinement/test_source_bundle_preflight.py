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


def _ofs_distance(distance):
    encoded = [distance & 127]
    distance >>= 7
    while distance:
        distance -= 1
        encoded.append(128 | (distance & 127))
        distance >>= 7
    return bytes(reversed(encoded))


def _literal_delta(source_size, result):
    return _varint(source_size) + _varint(len(result)) + bytes((len(result),)) + result


def _bundle(entries, version=2, algorithm="sha1", pack_version=2,
            pack_signature=b"PACK", bundle_magic=None, capability=None, advertised=None,
            refname=b"refs/heads/main"):
    if bundle_magic is None:
        bundle_magic = bytes((35,)) + (b" v2 git bundle\n" if version == 2 else b" v3 git bundle\n")
    if capability is None:
        capability = b"@object-format=sha256\n" if algorithm == "sha256" else b""
    if advertised is None:
        advertised = _object_id(b"a", algorithm=algorithm)
    header = bundle_magic + capability + advertised.hex().encode("ascii") + b" " + refname + b"\n\n"
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


def _offset_delta(base_data, instructions):
    base = _entry(3, base_data)
    delta = _entry(6, instructions, _ofs_distance(len(base)))
    return _bundle((base, delta), advertised=_object_id(base_data))


class SourceBundlePreflightTests(unittest.TestCase):
    def assert_refusal(self, bundle, reason, limits=None):
        result = subject.preflight(bundle, subject.BundleLimits() if limits is None else limits)
        self.assertIsInstance(result, subject.Refused)
        self.assertFalse(result.accepted)
        self.assertIn(result.reason, subject.REFUSAL_REASONS)
        self.assertEqual(result.reason, reason)

    def assert_copy_target_boundary(self, base_data, command):
        base = subject._Entry(0, 3, len(base_data), 0, 0,
                              result_size=len(base_data))
        deadline = subject._Deadline(subject.BundleLimits())
        at_limit = io.BytesIO(base_data)
        subject._apply_delta(io.BytesIO(command), at_limit, base, len(base_data),
                             hashlib.sha1(), deadline)
        self.assertEqual(at_limit.getvalue(), base_data + base_data)

        one_past = io.BytesIO(base_data)
        with self.assertRaises(subject._Refusal) as refused:
            subject._apply_delta(io.BytesIO(command), one_past, base, len(base_data) - 1,
                                 hashlib.sha1(), deadline)
        self.assertEqual(refused.exception.reason, "object-invalid")
        self.assertEqual(one_past.getvalue(), base_data)

        incomplete = io.BytesIO(base_data)
        with self.assertRaises(subject._Refusal) as refused:
            subject._apply_delta(io.BytesIO(command), incomplete, base, len(base_data) + 1,
                                 hashlib.sha1(), deadline)
        self.assertEqual(refused.exception.reason, "object-invalid")
        self.assertEqual(incomplete.getvalue(), base_data + base_data)

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

    def test_large_valid_blob_uses_repeated_bounded_inflation(self):
        data = b"a" * (subject.CHUNK_BYTES + 1)
        result = subject.preflight(_one_blob(data))
        self.assertIsInstance(result, subject.Accepted)
        self.assertEqual(result.total_inflated_bytes, len(data))
        self.assertEqual(result.total_expanded_bytes, len(data))

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

    def test_oversized_declarations_refuse_before_missing_payload(self):
        limits = replace(subject.BundleLimits(), max_blob_bytes=6,
                         max_metadata_bytes=6)
        for kind in (1, 2, 3, 4, 6, 7):
            with self.subTest(kind=kind):
                raw = _bundle((_object_header(kind, 7),))
                self.assert_refusal(raw, "object-size-limit", limits)

    def test_pack_size_varint_overflow_and_missing_continuation(self):
        self.assert_refusal(_bundle((b"\xb0" + b"\x80" * 10,)),
                            "object-size-limit")
        unterminated = _bundle((b"\xb0",))[:-20]
        self.assert_refusal(unterminated, "truncated")

    def test_pack_size_varint_last_permitted_byte(self):
        limits = replace(subject.BundleLimits(), max_blob_bytes=1 << 80)
        at_limit = _object_header(3, 1 << 60)
        one_past = _object_header(3, 1 << 67)
        self.assertEqual(len(at_limit), 10)
        self.assertEqual(len(one_past), 11)
        self.assertEqual(subject._object_header(io.BytesIO(at_limit), hashlib.sha1(), limits),
                         (3, 1 << 60))
        with self.assertRaises(subject._Refusal) as refused:
            subject._object_header(io.BytesIO(one_past), hashlib.sha1(), limits)
        self.assertEqual(refused.exception.reason, "object-size-limit")

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

    def test_delta_target_declaration_refuses_before_missing_commands(self):
        base_data = b"a" * 64
        base = _entry(3, base_data)
        at_limit = replace(subject.BundleLimits(), max_blob_bytes=65)
        accepted = _offset_delta(base_data, b"\x40\x41\x90\x40\x01b")
        self.assertIsInstance(subject.preflight(accepted, at_limit), subject.Accepted)
        oversized = _entry(6, _varint(64) + _varint(66), _ofs_distance(len(base)))
        raw = _bundle((base, oversized), advertised=_object_id(base_data))
        self.assert_refusal(raw, "object-size-limit", at_limit)

    def test_delta_size_varint_overflow_and_missing_continuation(self):
        for instructions in (b"\x01\x80", b"\x01" + b"\x80" * 11 + b"\x00"):
            with self.subTest(instructions=instructions):
                self.assert_refusal(_offset_delta(b"a", instructions), "object-invalid")

    def test_delta_size_varint_last_permitted_byte(self):
        at_limit = _varint(1 << 70)
        one_past = _varint(1 << 77)
        self.assertEqual(len(at_limit), 11)
        self.assertEqual(len(one_past), 12)
        deadline = subject._Deadline(subject.BundleLimits())
        self.assertEqual(subject._read_varint(io.BytesIO(at_limit), deadline), 1 << 70)
        with self.assertRaises(subject._Refusal) as refused:
            subject._read_varint(io.BytesIO(one_past), deadline)
        self.assertEqual(refused.exception.reason, "object-invalid")

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

    def test_multibyte_offset_distance_resolves(self):
        base_data = bytes(range(115))
        base = _object_header(3, len(base_data)) + zlib.compress(base_data, 0)
        self.assertEqual(len(base), 128)
        instructions = _varint(115) + _varint(116) + b"\x90\x73\x01x"
        delta = _entry(6, instructions, _ofs_distance(len(base)))
        raw = _bundle((base, delta), advertised=_object_id(base_data))
        result = subject.preflight(raw)
        self.assertIsInstance(result, subject.Accepted)
        self.assertEqual(result.total_expanded_bytes, 231)

    def test_invalid_offset_continuations_refuse(self):
        base = _entry(3, b"a")
        for encoded in (b"\x00", b"\x80\x00", b"\x80" * 8):
            with self.subTest(encoded=encoded):
                delta = _entry(6, _literal_delta(1, b"b"), encoded)
                self.assert_refusal(_bundle((base, delta)), "delta-base-invalid")
        unterminated = _bundle((base, _object_header(6, 3) + b"\x80"))[:-20]
        self.assert_refusal(unterminated, "truncated")

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

    def test_delta_copy_operand_and_bounds_refuse(self):
        for instructions in (b"\x02\x03\x90\x03",
                             b"\x02\x01\x90\x02",
                             b"\x02\x01\x90"):
            with self.subTest(instructions=instructions):
                self.assert_refusal(_offset_delta(b"ab", instructions), "object-invalid")
        self.assert_copy_target_boundary(b"ab", b"\x90\x02")

    def test_implicit_copy_size_is_exactly_65536(self):
        data = b"a" * 65536
        instructions = _varint(len(data)) + _varint(len(data) + 1) + b"\x80\x01b"
        result = subject.preflight(_offset_delta(data, instructions))
        self.assertIsInstance(result, subject.Accepted)
        self.assertEqual(result.total_expanded_bytes, 2 * len(data) + 1)
        oversized_copy = _varint(len(data)) + _varint(len(data) - 1) + b"\x80"
        self.assert_refusal(_offset_delta(data, oversized_copy), "object-invalid")
        self.assert_copy_target_boundary(data, b"\x80")

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

    def test_ref_components_follow_git_format_rules(self):
        invalid = (b"refs/heads/.hidden", b"refs/heads/main.lock",
                   b"refs/heads/./main", b"refs/heads/a..b",
                   b"refs/heads/a//b", b"refs/heads/a@{b",
                   b"refs/heads/a b", b"refs/heads/a.",
                   b"refs/heads/a/b.lock", b"refs/heads/a\\b")
        for name in invalid:
            with self.subTest(name=name):
                self.assert_refusal(_one_blob(refname=name), "bundle-header-invalid")
        self.assertIsInstance(subject.preflight(_one_blob(refname=b"refs/heads/a.b/c-d")),
                              subject.Accepted)
        self.assertIsInstance(subject.preflight(_one_blob(refname=b"HEAD")),
                              subject.Accepted)

    def test_header_line_passes_at_4096_bytes_and_refuses_one_more(self):
        prefix = b"refs/heads/"
        name_size = subject.HEADER_LINE_BYTES - 42
        name = prefix + b"a" * (name_size - len(prefix))
        self.assertIsInstance(subject.preflight(_one_blob(refname=name)), subject.Accepted)
        self.assert_refusal(_one_blob(refname=name + b"a"), "bundle-header-invalid")

    def test_aggregate_header_passes_at_limit_and_refuses_one_more(self):
        raw = _one_blob()
        magic = bytes((35,)) + b" v2 git bundle\n"
        ref_line = _object_id(b"a").hex().encode("ascii") + b" refs/heads/main\n"
        pack = raw.split(b"\n\n", 1)[1]
        remaining = subject.HEADER_BYTES - len(magic) - len(ref_line) - 1
        lines = []
        index = 0
        while remaining:
            size = min(subject.HEADER_LINE_BYTES - 1, remaining)
            if 0 < remaining - size < 43:
                size -= 43 - (remaining - size)
            object_id = format(index, "040x").encode("ascii")
            lines.append(b"-" + object_id + b" " + b"x" * (size - 43) + b"\n")
            remaining -= size
            index += 1
        header = magic + b"".join(lines) + ref_line + b"\n"
        self.assertEqual(len(header), subject.HEADER_BYTES)
        self.assertIsInstance(subject.preflight(header + pack), subject.Accepted)
        lines[-1] = lines[-1][:-1] + b"x\n"
        oversized = magic + b"".join(lines) + ref_line + b"\n" + pack
        self.assert_refusal(oversized, "bundle-header-invalid")

    def test_duplicate_and_misordered_bundle_records_refuse(self):
        capability = b"@object-format=sha1\n"
        prerequisite = b"-" + b"0" * 40 + b" earlier\n"
        self.assert_refusal(_one_blob(version=3, capability=capability * 2),
                            "bundle-header-invalid")
        self.assert_refusal(_one_blob(version=3, capability=prerequisite + capability),
                            "bundle-header-invalid")
        self.assert_refusal(_one_blob(capability=prerequisite * 2),
                            "bundle-header-invalid")
        late_capability = _one_blob(version=3, capability=b"").replace(
            b" refs/heads/main\n\n", b" refs/heads/main\n" + capability + b"\n", 1)
        self.assert_refusal(late_capability, "bundle-header-invalid")
        raw = _one_blob()
        late_prerequisite = raw.replace(b" refs/heads/main\n\n",
                                        b" refs/heads/main\n" + prerequisite + b"\n", 1)
        self.assert_refusal(late_prerequisite, "bundle-header-invalid")
        duplicate_ref = raw.replace(b" refs/heads/main\n\n",
                                    b" refs/heads/main\n"
                                    + _object_id(b"a").hex().encode("ascii")
                                    + b" refs/heads/main\n\n", 1)
        self.assert_refusal(duplicate_ref, "bundle-header-invalid")

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

    def test_stream_read_and_post_parse_deadlines_refuse(self):
        now = [0]

        class SlowStream:
            def read(self, unused_size):
                now[0] = 2
                return b""

        limits = replace(subject.BundleLimits(), max_wall_seconds=1)
        with patch.object(subject.time, "monotonic", side_effect=lambda: now[0]):
            with patch.object(subject.time, "process_time", return_value=0):
                self.assert_refusal(SlowStream(), "resource-limit", limits)

        now[0] = 0
        original_parse = subject._parse

        def finish_after_deadline(*args):
            result = original_parse(*args)
            now[0] = 2
            return result

        with patch.object(subject.time, "monotonic", side_effect=lambda: now[0]):
            with patch.object(subject.time, "process_time", return_value=0):
                with patch.object(subject, "_parse", side_effect=finish_after_deadline):
                    self.assert_refusal(_one_blob(), "resource-limit", limits)

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
