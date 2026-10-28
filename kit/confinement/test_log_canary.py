"""Tests for the digest-only log canary scanner."""

import base64
import hashlib
import io
import json
import unittest
from unittest import mock

import log_canary as subject


CANARY = hashlib.sha256(b"synthetic canary value one").hexdigest()
OTHER = hashlib.sha256(b"synthetic canary value two").hexdigest()
CONFIG = subject.compute_config(CANARY)


def _noise(count=120):
    parts = []
    for index in range(count):
        digest = hashlib.sha256(("noise-" + str(index)).encode("ascii")).digest()
        parts.append(digest.hex().encode("ascii"))
        parts.append(base64.b64encode(digest * 3))
        parts.append(base64.urlsafe_b64encode(digest * 2))
        parts.append(b"2026-10-28T10:00:00.1234567Z step output line " + str(index).encode("ascii"))
    return b"\n".join(parts)


def _embedded(encoder, data, before, after):
    return encoder(bytes(range(1, before + 1)) + data + bytes(range(200, 200 + after)))


def _payloads():
    text = CANARY.encode("ascii")
    binary = bytes.fromhex(CANARY)
    utf16 = CANARY.encode("utf-16-le")
    result = {
        "base64-utf16-standalone": base64.b64encode(utf16),
        "base64-utf16-unpadded": base64.b64encode(utf16).rstrip(b"="),
        "plain": text,
        "upper": text.upper(),
        "hex": text.hex().encode("ascii"),
        "hex-upper": text.hex().upper().encode("ascii"),
        "utf16le": CANARY.encode("utf-16-le"),
        "utf16le-bom": b"\xff\xfe" + CANARY.encode("utf-16-le"),
        "utf16le-base64": base64.b64encode(text).decode("ascii").encode("utf-16-le"),
        "base64-unpadded": base64.b64encode(text).rstrip(b"="),
        "base64url-unpadded": base64.urlsafe_b64encode(text).rstrip(b"="),
        "base64-bin": base64.b64encode(binary),
        "base64url-bin": base64.urlsafe_b64encode(binary),
    }
    for before in range(0, 6):
        for after in range(0, 4):
            suffix = "-" + str(before) + "-" + str(after)
            result["b64-text" + suffix] = _embedded(base64.b64encode, text, before, after)
            result["b64url-text" + suffix] = _embedded(base64.urlsafe_b64encode, text, before, after)
            result["b64-utf16" + suffix] = _embedded(base64.b64encode, utf16, before, after)
            result["b64url-utf16" + suffix] = _embedded(base64.urlsafe_b64encode, utf16, before, after)
            result["b64-bin" + suffix] = _embedded(base64.b64encode, binary, before, after)
            result["b64url-bin" + suffix] = _embedded(base64.urlsafe_b64encode, binary, before, after)
    return result


class ConfigTests(unittest.TestCase):
    def test_config_has_only_digests_and_a_length(self):
        self.assertEqual(set(CONFIG), {"digests", "text_length"})
        self.assertEqual(CONFIG["text_length"], 64)
        self.assertEqual(set(CONFIG["digests"]), set(subject.FORMS))
        self.assertEqual(subject.scan_bytes(b"x " + CANARY.encode("ascii"), CONFIG), "present")
        encoded = json.dumps(CONFIG)
        self.assertNotIn(CANARY, encoded)
        self.assertNotIn(CANARY.encode("ascii").hex(), encoded)
        self.assertNotIn(base64.b64encode(CANARY.encode("ascii")).decode("ascii"), encoded)

    def test_config_is_deterministic_and_value_specific(self):
        self.assertEqual(CONFIG, subject.compute_config(CANARY))
        self.assertNotEqual(CONFIG, subject.compute_config(OTHER))

    def test_forms_are_the_fixed_closed_set(self):
        self.assertEqual(len(subject.FORMS), 15)
        self.assertEqual(len(set(subject.FORMS)), 15)
        for name in (
            "plain", "hex", "utf16le", "base64-text-0", "base64-utf16-0", "base64-utf16-2",
            "base64-bin-1", "base64url-bin-2",
        ):
            self.assertIn(name, subject.FORMS)
        self.assertEqual([name for name in subject.FORMS if name.startswith("base64url-text")], [])
        self.assertEqual([name for name in subject.FORMS if name.startswith("base64url-utf16")], [])

    def test_redundant_url_safe_text_forms_are_equal_to_the_standard_ones(self):
        text = CANARY
        for source in ("text", "utf16"):
            data = text.encode("ascii") if source == "text" else text.encode("utf-16-le")
            for shift in subject.SHIFTS:
                self.assertEqual(
                    subject._interior(data, shift, False), subject._interior(data, shift, True),
                )

    def test_low_entropy_canaries_are_refused(self):
        for value in ("ab" * 32, "0" * 64, "0123456789a" * 6, "0123456789" * 7 + "01"):
            with self.subTest(value_size=len(value), distinct=len(set(value))):
                with self.assertRaises(subject.ScanRefusal) as caught:
                    subject.compute_config(value)
                self.assertEqual(caught.exception.reason, "config_invalid")
        accepted = subject.compute_config("0123456789ab" * 6)
        self.assertEqual(accepted["text_length"], 72)
        self.assertEqual(subject.MIN_DISTINCT_NIBBLES, 12)

    def test_canary_values_that_are_not_long_lowercase_hex_are_refused(self):
        for value in ("", "a" * 62, "a" * 66 + "0", "A" * 64, "g" * 64, "a" * 258, b"a" * 64, None, 5):
            with self.subTest(size=len(value) if hasattr(value, "__len__") else 0):
                with self.assertRaises(subject.ScanRefusal) as caught:
                    subject.compute_config(value)
                self.assertEqual(caught.exception.reason, "config_invalid")

    def test_longer_canaries_scan_correctly(self):
        long_canary = hashlib.sha256(b"a").hexdigest() + hashlib.sha256(b"b").hexdigest()
        config = subject.compute_config(long_canary)
        self.assertEqual(config["text_length"], 128)
        self.assertEqual(subject.scan_bytes(b"x " + long_canary.encode("ascii") + b" y", config), "present")
        self.assertEqual(subject.scan_bytes(long_canary[:-2].encode("ascii"), config), "absent")

    def test_malformed_configs_are_refused(self):
        bad = []
        for field in ("digests", "text_length"):
            missing = dict(CONFIG)
            del missing[field]
            bad.append(missing)
        bad.append(dict(CONFIG, extra=1))
        bad.append(dict(CONFIG, text_length=63))
        bad.append(dict(CONFIG, text_length=True))
        bad.append(dict(CONFIG, text_length=32))
        bad.append(dict(CONFIG, text_length=258))
        dropped = dict(CONFIG["digests"])
        del dropped["hex"]
        bad.append(dict(CONFIG, digests=dropped))
        bad.append(dict(CONFIG, digests=dict(CONFIG["digests"], extra="0" * 64)))
        bad.append(dict(CONFIG, digests=dict(CONFIG["digests"], hex="A" * 64)))
        bad.append(dict(CONFIG, digests=dict(CONFIG["digests"], hex="a" * 63)))
        bad.append(dict(CONFIG, digests=dict(CONFIG["digests"], hex=5)))
        bad.append([])
        bad.append(None)
        for config in bad:
            with self.subTest(config=repr(config)[:40]):
                with self.assertRaises(subject.ScanRefusal) as caught:
                    subject.scan_bytes(b"data", config)
                self.assertEqual(caught.exception.reason, "config_invalid")

    def test_unpinned_configuration_fails_closed(self):
        with mock.patch.object(subject, "PINNED_CONFIG", None):
            with self.assertRaises(subject.ScanRefusal) as caught:
                subject.pinned_config()
        self.assertEqual(caught.exception.reason, "config_unpinned")
        with mock.patch.object(subject, "PINNED_CONFIG", CONFIG):
            self.assertEqual(subject.pinned_config(), CONFIG)

    def test_refusal_reasons_are_closed(self):
        self.assertEqual(subject.ScanRefusal("anything").reason, "input_invalid")
        self.assertEqual(str(subject.ScanRefusal("scan_limit")), "scan_limit")


class DetectionTests(unittest.TestCase):
    def test_every_encoding_is_detected_with_surrounding_noise(self):
        noise = _noise(20)
        for name, payload in sorted(_payloads().items()):
            data = noise + b"\n" + b"prefix text " + payload + b" suffix text\n" + noise
            with self.subTest(form=name):
                self.assertEqual(subject.scan_bytes(data, CONFIG), "present")

    def test_every_encoding_is_detected_alone(self):
        for name, payload in sorted(_payloads().items()):
            with self.subTest(form=name):
                self.assertEqual(subject.scan_bytes(payload, CONFIG), "present")

    def test_text_input_is_scanned_as_utf8(self):
        self.assertEqual(subject.scan_bytes("line " + CANARY + " end", CONFIG), "present")
        self.assertEqual(subject.scan_texts(["clean", "line " + CANARY], CONFIG), "present")
        self.assertEqual(subject.scan_texts(["clean", "also clean", ""], CONFIG), "absent")
        self.assertEqual(subject.scan_texts([], CONFIG), "absent")

    def test_texts_are_independent_so_a_value_cannot_span_two_of_them(self):
        self.assertEqual(subject.scan_texts([CANARY[:30], CANARY[30:]], CONFIG), "absent")

    def test_every_split_position_is_detected_across_two_chunks(self):
        for name in ("plain", "hex", "utf16le", "base64-unpadded", "base64url-bin", "b64-text-1-2", "b64url-bin-2-1"):
            payload = b"abc " + _payloads()[name] + b" xyz"
            for cut in range(1, len(payload)):
                with self.subTest(form=name, cut=cut):
                    self.assertEqual(
                        subject.scan_chunks([payload[:cut], payload[cut:]], CONFIG), "present",
                    )

    def test_single_byte_chunks_are_detected(self):
        for name in ("plain", "hex", "utf16le", "base64-bin", "b64url-text-2-0", "utf16le-base64"):
            payload = b"noise " + _payloads()[name] + b" noise"
            with self.subTest(form=name):
                chunks = [payload[index:index + 1] for index in range(len(payload))]
                self.assertEqual(subject.scan_chunks(chunks, CONFIG), "present")

    def test_stream_that_starts_without_nul_and_later_turns_utf16_is_detected(self):
        payload = base64.b64encode(CANARY.encode("ascii")).decode("ascii").encode("utf-16-le")
        for cut in (1, 7, 20, 40):
            with self.subTest(cut=cut):
                chunks = [b"plain ascii start", payload[:cut], payload[cut:]]
                self.assertEqual(subject.scan_chunks(chunks, CONFIG), "present")

    def test_large_input_is_scanned_in_slices_and_still_detected_at_slice_edges(self):
        size = subject.SLICE_BYTES
        filler = b" " * size
        for offset in (size - 70, size - 64, size - 63, size - 1, size, size + 5):
            data = (filler + filler)[:offset] + CANARY.encode("ascii") + filler
            with self.subTest(offset=offset):
                self.assertEqual(subject.scan_bytes(data, CONFIG), "present")


class NoFalsePositiveTests(unittest.TestCase):
    def test_noise_alone_is_absent(self):
        self.assertEqual(subject.scan_bytes(_noise(), CONFIG), "absent")
        self.assertEqual(subject.scan_bytes(b"", CONFIG), "absent")

    def test_near_misses_are_absent(self):
        text = CANARY
        flipped = text[:20] + ("0" if text[20] != "0" else "1") + text[21:]
        near = [
            text[:-1],
            text[1:],
            flipped,
            text[::-1],
            text[:32] + " " + text[32:],
            text[:32] + "\n" + text[32:],
            OTHER,
        ]
        for value in near:
            with self.subTest(size=len(value)):
                self.assertEqual(subject.scan_bytes(b"x " + value.encode("ascii") + b" y", CONFIG), "absent")
        for value in (text[:-1], flipped):
            encoded = base64.b64encode(value.encode("ascii"))
            self.assertEqual(subject.scan_bytes(encoded, CONFIG), "absent")
            self.assertEqual(subject.scan_bytes(value.encode("utf-16-le"), CONFIG), "absent")
            self.assertEqual(subject.scan_bytes(value.encode("ascii").hex().encode("ascii"), CONFIG), "absent")

    def test_other_canary_is_absent_in_every_encoding(self):
        other_text = OTHER.encode("ascii")
        for data in (
            other_text, other_text.hex().encode("ascii"), OTHER.encode("utf-16-le"),
            base64.b64encode(other_text), base64.urlsafe_b64encode(bytes.fromhex(OTHER)),
        ):
            self.assertEqual(subject.scan_bytes(data, CONFIG), "absent")

    def test_long_runs_of_alphabet_characters_are_absent(self):
        self.assertEqual(subject.scan_bytes(b"a" * 5000, CONFIG), "absent")
        self.assertEqual(subject.scan_bytes(b"/" * 3000 + b"A" * 3000, CONFIG), "absent")


STAMP = b"2026-10-28T10:00:00.1234567Z "


def _wrapped(encoded, width, stamp=True, ending=b"\n"):
    lines = [encoded[index:index + width] for index in range(0, len(encoded), width)]
    return ending.join((STAMP if stamp else b"") + line for line in lines)


def _wrapped_sources():
    text = CANARY.encode("ascii")
    return {
        "base64-text": base64.b64encode(text).rstrip(b"="),
        "base64-utf16": base64.b64encode(CANARY.encode("utf-16-le")).rstrip(b"="),
        "base64-bin": base64.b64encode(bytes.fromhex(CANARY)).rstrip(b"="),
        "base64url-bin": base64.urlsafe_b64encode(bytes.fromhex(CANARY)).rstrip(b"="),
        "base64-offset": base64.b64encode(b"xy" + text + b"z").rstrip(b"="),
        "plain": text,
    }


class WrappedTests(unittest.TestCase):
    def test_wrapped_encodings_are_detected_at_any_column_width(self):
        for name, encoded in sorted(_wrapped_sources().items()):
            for width in (7, 20, 64, 76):
                for stamp in (True, False):
                    for ending in (b"\n", b"\r\n"):
                        data = _noise(3) + b"\n" + _wrapped(encoded, width, stamp, ending) + b"\n" + _noise(3)
                        with self.subTest(form=name, width=width, stamp=stamp, ending=ending):
                            self.assertEqual(subject.scan_bytes(data, CONFIG), "present")

    def test_wrapped_value_is_detected_when_the_last_line_has_no_newline_or_padding_is_kept(self):
        padded = base64.b64encode(CANARY.encode("ascii"))
        self.assertEqual(subject.scan_bytes(_wrapped(padded, 20), CONFIG), "present")
        self.assertEqual(subject.scan_bytes(_wrapped(padded, 76) + b"\n", CONFIG), "present")

    def test_wrapped_value_is_detected_across_every_chunk_boundary(self):
        data = b"before\n" + _wrapped(_wrapped_sources()["base64-text"], 20) + b"\nafter\n"
        for cut in range(1, len(data)):
            with self.subTest(cut=cut):
                self.assertEqual(subject.scan_chunks([data[:cut], data[cut:]], CONFIG), "present")

    def test_a_non_encoded_line_breaks_the_join(self):
        encoded = _wrapped_sources()["base64-text"]
        lines = [STAMP + encoded[index:index + 20] for index in range(0, len(encoded), 20)]
        lines.insert(2, STAMP + b"plain words here")
        self.assertEqual(subject.scan_bytes(b"\n".join(lines), CONFIG), "absent")
        blank = list(lines)
        blank[2] = b""
        self.assertEqual(subject.scan_bytes(b"\n".join(blank), CONFIG), "absent")

    def test_other_wrapped_values_are_absent(self):
        other = base64.b64encode(OTHER.encode("ascii")).rstrip(b"=")
        self.assertEqual(subject.scan_bytes(_wrapped(other, 20), CONFIG), "absent")

    def test_joined_work_counts_toward_the_window_budget(self):
        data = (b"A" * 30 + b"\n") * 200
        self.assertEqual(subject.scan_bytes(data, CONFIG), "absent")
        with mock.patch.object(subject, "MAX_WINDOWS", 10):
            with self.assertRaises(subject.ScanRefusal) as caught:
                subject.scan_bytes(data, CONFIG)
        self.assertEqual(caught.exception.reason, "scan_limit")

    def test_joined_work_counts_toward_the_byte_budget(self):
        data = (b"A" * 30 + b"\n") * 20
        with mock.patch.object(subject, "MAX_TOTAL_BYTES", len(data) + 100):
            with self.assertRaises(subject.ScanRefusal) as caught:
                subject.scan_bytes(data, CONFIG)
        self.assertEqual(caught.exception.reason, "scan_limit")

    def test_a_very_long_joined_run_is_scanned_in_bounded_pieces(self):
        encoded = _wrapped_sources()["base64-text"]
        with mock.patch.object(subject, "JOIN_LIMIT", 4096):
            for lines in range(130, 140):
                filler = (b"B" * 30 + b"\n") * lines
                data = filler + _wrapped(encoded, 20, False) + b"\n" + filler
                with self.subTest(lines=lines):
                    self.assertEqual(subject.scan_bytes(data, CONFIG), "present")

    def test_a_single_endless_line_is_bounded(self):
        with mock.patch.object(subject, "LINE_LIMIT", 100):
            scanner = subject.Scanner(CONFIG)
            scanner.feed(b"A" * 350)
            self.assertLessEqual(len(scanner._tail), 100)
            scanner.finish()
            self.assertEqual(scanner.result(), "absent")


class BoundsTests(unittest.TestCase):
    def test_non_bytes_input_is_refused(self):
        for value in (bytearray(b"abc"), 5, None, ["a"]):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises(subject.ScanRefusal) as caught:
                    subject.scan_bytes(value, CONFIG)
                self.assertEqual(caught.exception.reason, "input_invalid")

    def test_window_budget_is_enforced(self):
        with mock.patch.object(subject, "MAX_WINDOWS", 10):
            with self.assertRaises(subject.ScanRefusal) as caught:
                subject.scan_bytes(b"a" * 500, CONFIG)
        self.assertEqual(caught.exception.reason, "scan_limit")

    def test_total_byte_budget_is_enforced(self):
        with mock.patch.object(subject, "MAX_TOTAL_BYTES", 100):
            with self.assertRaises(subject.ScanRefusal) as caught:
                subject.scan_bytes(b" " * 101, CONFIG)
        self.assertEqual(caught.exception.reason, "scan_limit")
        with mock.patch.object(subject, "MAX_TOTAL_BYTES", 100):
            self.assertEqual(subject.scan_bytes(b" " * 100, CONFIG), "absent")

    def test_refusals_never_carry_scanned_text(self):
        with mock.patch.object(subject, "MAX_WINDOWS", 1):
            with self.assertRaises(subject.ScanRefusal) as caught:
                subject.scan_bytes(b"a" * 300 + CANARY.encode("ascii"), CONFIG)
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertNotIn(CANARY, repr(caught.exception.args))

    def test_scanner_reports_only_the_closed_enum(self):
        scanner = subject.Scanner(CONFIG)
        self.assertEqual(scanner.result(), "absent")
        scanner.feed(b"x" + CANARY.encode("ascii"))
        self.assertEqual(scanner.result(), "present")
        self.assertIn(scanner.result(), subject.RESULTS)
        scanner.feed(b"more")
        self.assertEqual(scanner.result(), "present")


class MainTests(unittest.TestCase):
    def test_compute_prints_the_configuration_for_a_canary_on_standard_input(self):
        output = io.StringIO()
        status = subject.main(["compute"], stdin=io.StringIO(CANARY + "\n"), stdout=output)
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue()), CONFIG)
        self.assertNotIn(CANARY, output.getvalue())

    def test_bad_input_and_arguments_fail_without_echo(self):
        output = io.StringIO()
        self.assertEqual(subject.main(["compute"], stdin=io.StringIO("not-a-canary\n"), stdout=output), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(subject.main([], stdin=io.StringIO(CANARY), stdout=output), 2)
        self.assertEqual(subject.main(["other"], stdin=io.StringIO(CANARY), stdout=output), 2)
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
