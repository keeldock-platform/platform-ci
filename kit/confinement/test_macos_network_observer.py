import contextlib
import io
import struct
import unittest
from unittest.mock import patch

import macos_network_observer as observer


CONTROL_SHA = "a" * 40
SOURCE_SHA = "b" * 40
RUN_ID = "123456"
RUN_ATTEMPT = "2"
LOCAL_V4 = "192.0.2.10"
REMOTE_V4 = "192.0.2.53"
DNS_NAME = "sample.invalid"


def valid_record(**changes):
    value = {
        "schema_version": 1,
        "status": "observed",
        "mode": "host-level",
        "control_sha": CONTROL_SHA,
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
        "source_sha": "none",
        "interface_count": 1,
        "dns_query_count": 1,
        "tcp_syn_count": 1,
        "dns_name_hashes": ("c" * 64,),
        "tcp_destination_hashes": ("d" * 64,),
        "hashes_truncated": False,
        "capture_limited": False,
        "capture": "private",
        "cleanup": "complete",
        "worker_attribution": "not-claimed",
        "completeness": "not-claimed",
        "network_blocking": "not-claimed",
    }
    value.update(changes)
    return value


def ethernet_ipv4(source, destination, protocol, segment):
    source_bytes = bytes(int(part) for part in source.split("."))
    destination_bytes = bytes(int(part) for part in destination.split("."))
    total_length = 20 + len(segment)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        protocol,
        0,
        source_bytes,
        destination_bytes,
    )
    return b"\x00" * 12 + b"\x08\x00" + header + segment


def udp_packet(source_port, destination_port, payload):
    length = 8 + len(payload)
    segment = struct.pack("!HHHH", source_port, destination_port, length, 0) + payload
    return ethernet_ipv4(LOCAL_V4, REMOTE_V4, 17, segment)


def tcp_syn_packet(source_port, destination_port):
    segment = struct.pack("!HHIIHHHH", source_port, destination_port, 1, 0, 0x5002, 4096, 0, 0)
    return ethernet_ipv4(LOCAL_V4, REMOTE_V4, 6, segment)


def pcap(frames, endian="<", original_lengths=None, linktype=1):
    magic = 0xA1B2C3D4
    content = bytearray(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 512, linktype))
    original_lengths = original_lengths or [len(frame) for frame in frames]
    for index, (frame, original_length) in enumerate(zip(frames, original_lengths)):
        content.extend(struct.pack(endian + "IIII", 1, index, len(frame), original_length))
        content.extend(frame)
    return bytes(content)


def dns_query(name):
    question = observer._encode_dns_name(name) + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", 19, 0x0100, 1, 0, 0, 0) + question


class BindingTests(unittest.TestCase):
    def test_binding_is_closed_and_preserves_exact_identity(self):
        self.assertEqual(
            observer._validated_binding(CONTROL_SHA, RUN_ID, RUN_ATTEMPT, SOURCE_SHA),
            {
                "control_sha": CONTROL_SHA,
                "run_id": RUN_ID,
                "run_attempt": RUN_ATTEMPT,
                "source_sha": SOURCE_SHA,
            },
        )
        self.assertEqual(
            observer._validated_binding(CONTROL_SHA, RUN_ID, RUN_ATTEMPT, None)["source_sha"],
            "none",
        )

    def test_binding_rejects_noncanonical_values(self):
        cases = (
            ("A" * 40, RUN_ID, RUN_ATTEMPT, SOURCE_SHA),
            (CONTROL_SHA, "0", RUN_ATTEMPT, SOURCE_SHA),
            (CONTROL_SHA, RUN_ID, "02", SOURCE_SHA),
            (CONTROL_SHA, RUN_ID, RUN_ATTEMPT, "short"),
        )
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(observer.ObserverRefusal) as caught:
                    observer._validated_binding(*values)
                self.assertEqual((caught.exception.reason, caught.exception.stage), ("binding_invalid", "binding"))


class InterfaceTests(unittest.TestCase):
    def test_hardware_and_capture_lists_are_intersected_by_system_interface(self):
        hardware = b"Hardware Port: Wi-Fi\nDevice: en0\n\nHardware Port: USB\nDevice: en7\n"
        capture = b"1.en0 [Up, Running, Wireless, Associated]\n2.en7 [Up, Running]\n3.lo0 [Up, Running]\n"
        self.assertEqual(observer._parse_hardware_devices(hardware), ("en0", "en7"))
        self.assertEqual(
            observer._parse_capture_devices(capture),
            {
                "en0": {"up": True, "running": True},
                "en7": {"up": True, "running": True},
                "lo0": {"up": True, "running": True},
            },
        )

    def test_duplicate_or_malformed_capture_rows_refuse(self):
        for output in (
            b"1.en0 [Up, Running]\n1.en0 [Up, Running]\n",
            b"device output unavailable\n",
            b"\xff\n",
        ):
            with self.subTest(output=output):
                with self.assertRaises(observer.ObserverRefusal) as caught:
                    observer._parse_capture_devices(output)
                self.assertEqual(caught.exception.reason, "interface_unavailable")

    def test_local_addresses_are_normalized_without_scope_suffix(self):
        result = observer._parse_local_addresses(
            b"inet 192.0.2.10 netmask 0xffffff00\n"
            b"inet6 fe80::1%en0 prefixlen 64\n"
            b"inet6 ::1 prefixlen 128\n"
        )
        self.assertEqual(result, frozenset(("192.0.2.10", "fe80::1", "::1")))


class PhysicalInterfaceTests(unittest.TestCase):
    def test_system_interfaces_uses_fixed_hardware_capture_and_address_commands(self):
        hardware = b"Hardware Port: Wi-Fi\nDevice: en0\n"
        capture = b"1.en0 [Up, Running, Wireless, Associated]\n2.lo0 [Up, Running, Loopback]\n"
        addresses = b"en0: flags=8863<UP,RUNNING>\n inet 192.0.2.10 netmask 0xffffff00\n inet6 fe80::1%en0 prefixlen 64\n"
        with patch.object(observer, "_run_fixed_command", side_effect=(hardware, capture, addresses)) as command:
            interfaces = observer._system_interfaces()
        self.assertEqual(
            interfaces,
            ({"name": "en0", "addresses": frozenset(("192.0.2.10", "fe80::1"))},),
        )
        self.assertEqual(
            [call.args for call in command.call_args_list],
            [
                ((observer.NETWORKSETUP_PATH, "-listallhardwareports"), "interface_hardware"),
                ((observer.TCPDUMP_PATH, "-D"), "interface_capture"),
                ((observer.IFCONFIG_PATH, "en0"), "interface_address"),
            ],
        )

    def test_system_interfaces_refuses_without_a_running_hardware_capture(self):
        hardware = b"Hardware Port: Wi-Fi\nDevice: en0\n"
        capture = b"1.en0 [Down]\n2.lo0 [Up, Running, Loopback]\n"
        with patch.object(observer, "_run_fixed_command", side_effect=(hardware, capture)):
            with self.assertRaises(observer.ObserverRefusal) as caught:
                observer._system_interfaces()
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("interface_unavailable", "interface_capture"))

    def test_system_interfaces_refuses_when_hardware_inventory_has_no_physical_device(self):
        hardware = b"Hardware Port: Wi-Fi\nDevice: bridge0\n"
        capture = b"1.en0 [Up, Running]\n"
        with patch.object(observer, "_run_fixed_command", side_effect=(hardware, capture)):
            with self.assertRaises(observer.ObserverRefusal) as caught:
                observer._system_interfaces()
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("interface_unavailable", "interface_hardware"))

    def test_system_interfaces_skips_valid_unaddressed_hardware_and_keeps_addressed_device(self):
        hardware = b"Hardware Port: Wi-Fi\nDevice: en0\nHardware Port: Ethernet\nDevice: en1\n"
        capture = b"1.en0 [Up, Running]\n2.en1 [Up, Running]\n"
        no_address = b"en0: flags=8863<UP,RUNNING> mtu 1500\n"
        address = b"en1: flags=8863<UP,RUNNING> mtu 1500\n inet 192.0.2.10 netmask 0xffffff00\n"
        with patch.object(observer, "_run_fixed_command", side_effect=(hardware, capture, no_address, address)):
            interfaces = observer._system_interfaces()
        self.assertEqual(
            interfaces,
            ({"name": "en1", "addresses": frozenset(("192.0.2.10",))},),
        )

    def test_system_interfaces_refuses_when_every_valid_hardware_device_is_unaddressed(self):
        hardware = b"Hardware Port: Wi-Fi\nDevice: en0\nHardware Port: Ethernet\nDevice: en1\n"
        capture = b"1.en0 [Up, Running]\n2.en1 [Up, Running]\n"
        first = b"en0: flags=8863<UP,RUNNING> mtu 1500\n"
        second = b"en1: flags=8863<UP,RUNNING> mtu 1500\n"
        with patch.object(observer, "_run_fixed_command", side_effect=(hardware, capture, first, second)):
            with self.assertRaises(observer.ObserverRefusal) as caught:
                observer._system_interfaces()
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("interface_unavailable", "interface_address"))

    def test_ifconfig_header_and_address_records_must_be_well_formed(self):
        cases = (
            b"",
            b"interface output unavailable\n",
            b"en1: flags=8863<UP,RUNNING> mtu 1500\n inet 192.0.2.10 netmask 0xffffff00\n",
            b"en0: flags=nothex<UP,RUNNING> mtu 1500\n",
            b"en0: flags=8863<UP,Running> mtu 1500\n",
            b"en0: flags=8863<UP,UP> mtu 1500\n",
            b"en0: flags=8863<UP,RUNNING>mtu 1500\n",
            b"en0: flags=8863<UP,RUNNING> mtu 1500\nen1: flags=8863<UP,RUNNING> mtu 1500\n",
            b"en0: flags=8863<UP,RUNNING> mtu 1500\nunexpected body\n",
            b"en0: flags=8863<UP,RUNNING> mtu 1500\n inet\n",
            b"en0: flags=8863<UP,RUNNING> mtu 1500\n inet6\n",
            b"en0: flags=8863<UP,RUNNING> mtu 1500\n inet invalid-address\n",
            b"en0: flags=8863<UP,RUNNING> mtu 1500\n inet6 192.0.2.10\n",
            b"en0: flags=8863<UP,RUNNING> mtu 1500\n inet6 fe80::1%\n",
            b"en0: flags=8863<UP,RUNNING> mtu 1500\n inet6 fe80::1%%en0\n",
            b"en0: flags=8863<UP,RUNNING> mtu 1500\n inet6 fe80::1%en1\n",
            b"en0: flags=8863<UP,RUNNING> mtu 1500\n inet 2001:db8::1\n",
            b"en0: flags=8863<UP,RUNNING> mtu 1500\n inetgarbage 192.0.2.10\n",
            b"en0: flags=8863<UP,RUNNING> mtu 1500\n inet 192.0.2.10\x1b\n",
            b"en0: flags=8863<UP,RUNNING> mtu 1500\n\xff\n",
        )
        for output in cases:
            with self.subTest(output=output), self.assertRaises(observer.ObserverRefusal) as caught:
                observer._parse_local_addresses(output, "interface_address", "en0")
            self.assertEqual((caught.exception.reason, caught.exception.stage), ("interface_unavailable", "interface_address"))

    def test_ifconfig_valid_inactive_device_has_no_usable_addresses(self):
        output = b"en0: flags=8863<BROADCAST> mtu 1500\n inet 192.0.2.10 netmask 0xffffff00\n"
        self.assertEqual(
            observer._parse_local_addresses(output, "interface_address", "en0"),
            frozenset(),
        )

    def test_physical_discovery_parser_failures_keep_their_fixed_leaf_stage(self):
        for parser, stage in (
            (observer._parse_hardware_devices, "interface_hardware"),
            (observer._parse_capture_devices, "interface_capture"),
            (observer._parse_local_addresses, "interface_address"),
        ):
            with self.subTest(stage=stage), self.assertRaises(observer.ObserverRefusal) as caught:
                parser(b"\xff\n", stage)
            self.assertEqual((caught.exception.reason, caught.exception.stage), ("interface_unavailable", stage))

    def test_address_command_refusal_uses_the_address_stage(self):
        hardware = b"Hardware Port: Wi-Fi\nDevice: en0\n"
        capture = b"1.en0 [Up, Running]\n"
        with patch.object(
            observer,
            "_run_fixed_command",
            side_effect=(hardware, capture, observer.ObserverRefusal("observer_unavailable", "interface_address")),
        ):
            with self.assertRaises(observer.ObserverRefusal) as caught:
                observer._system_interfaces()
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("observer_unavailable", "interface_address"))


class PhysicalSelftestTests(unittest.TestCase):
    def _binding(self):
        return observer._validated_binding(CONTROL_SHA, RUN_ID, RUN_ATTEMPT, None)

    def _zero_traffic_record(self, **changes):
        record = valid_record(
            interface_count=1,
            dns_query_count=0,
            tcp_syn_count=0,
            dns_name_hashes=[],
            tcp_destination_hashes=[],
        )
        record.update(changes)
        return record

    def test_physical_capture_uses_system_discovery_and_accepts_zero_traffic(self):
        class Session:
            _captures = (object(),)

            def __init__(self, record):
                self.record = record
                self.finish_calls = 0

            def finish(self):
                self.finish_calls += 1
                return self.record

        hardware = b"Hardware Port: Wi-Fi\nDevice: en0\n"
        capture = b"1.en0 [Up, Running, Wireless, Associated]\n"
        addresses = b"en0: flags=8863<UP,RUNNING>\n inet 192.0.2.10 netmask 0xffffff00\n"
        session = Session(self._zero_traffic_record())
        with patch.object(observer, "_require_macos_root"), \
                patch.object(observer, "_run_fixed_command", side_effect=(hardware, capture, addresses)), \
                patch.object(observer, "_start_session", return_value=session) as start:
            observer._physical_selftest_capture(self._binding())
        interface = {"name": "en0", "addresses": frozenset(("192.0.2.10",))}
        expression = observer._capture_filter(frozenset((53,)), frozenset((53,)))
        start.assert_called_once_with(
            self._binding(),
            (interface,),
            frozenset((53,)),
            frozenset((53,)),
            {"en0": expression},
        )
        self.assertEqual(session.finish_calls, 1)

    def test_physical_capture_requires_unlimited_complete_private_cleanup(self):
        for changes in (
            {"capture_limited": True},
            {"cleanup": "incomplete"},
            {"interface_count": 2},
        ):
            with self.subTest(changes=changes), self.assertRaises(observer.ObserverRefusal) as caught:
                observer._validate_physical_selftest_record(
                    self._zero_traffic_record(**changes), self._binding(), 1,
                )
            self.assertEqual((caught.exception.reason, caught.exception.stage), ("capture_invalid", "finish"))

    def test_physical_capture_cleanup_failure_is_preserved(self):
        class Session:
            def finish(self):
                raise observer.ObserverRefusal("cleanup_incomplete", "cleanup")

        interface = {"name": "en0", "addresses": frozenset(("192.0.2.10",))}
        with patch.object(observer, "_require_macos_root"), \
                patch.object(observer, "_system_interfaces", return_value=(interface,)), \
                patch.object(observer, "_start_session", return_value=Session()):
            with self.assertRaises(observer.ObserverRefusal) as caught:
                observer._physical_selftest_capture(self._binding())
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("cleanup_incomplete", "cleanup"))

    def test_physical_failure_stops_before_loopback_without_fallback(self):
        failure = observer.ObserverRefusal("interface_unavailable", "interface_capture")
        with patch.object(observer, "_require_macos_root"), \
                patch.object(observer, "_physical_selftest_capture", side_effect=failure) as physical, \
                patch.object(observer, "_tcpdump_interfaces") as loopback:
            with self.assertRaises(observer.ObserverRefusal) as caught:
                observer._selftest_record(self._binding())
        physical.assert_called_once_with(self._binding())
        loopback.assert_not_called()
        self.assertIs(caught.exception, failure)

    def test_loopback_positive_path_remains_required_after_physical_capture(self):
        events = []

        def physical(binding):
            events.append("physical")

        def loopback():
            events.append("loopback")
            return {}

        with patch.object(observer, "_require_macos_root"), \
                patch.object(observer, "_physical_selftest_capture", side_effect=physical), \
                patch.object(observer, "_tcpdump_interfaces", side_effect=loopback):
            with self.assertRaises(observer.ObserverRefusal) as caught:
                observer._selftest_record(self._binding())
        self.assertEqual(events, ["physical", "loopback"])
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("interface_unavailable", "interface"))


class CaptureParserTests(unittest.TestCase):
    def test_dns_and_outbound_syn_are_counted_and_only_hmacs_are_returned(self):
        query = dns_query(DNS_NAME)
        frames = (
            udp_packet(54000, 53, query),
            tcp_syn_packet(54001, 443),
        )
        key = b"k" * 32
        result = observer._parse_pcap(
            pcap(frames),
            frozenset((LOCAL_V4,)),
            key,
            frozenset((53,)),
            frozenset((53,)),
        )
        self.assertEqual(result["dns_query_count"], 1)
        self.assertEqual(result["tcp_syn_count"], 1)
        expected_dns = observer.hmac.new(
            key,
            b"dns\x00" + observer._encode_dns_name(DNS_NAME),
            observer.hashlib.sha256,
        ).hexdigest()
        expected_tcp = observer.hmac.new(
            key,
            b"tcp\x00" + REMOTE_V4.encode("ascii") + b":443",
            observer.hashlib.sha256,
        ).hexdigest()
        self.assertEqual(result["dns_name_hashes"], (expected_dns,))
        self.assertEqual(result["tcp_destination_hashes"], (expected_tcp,))
        self.assertNotIn(DNS_NAME, repr(result))
        self.assertNotIn(REMOTE_V4, repr(result))

    def test_capture_truncation_is_explicit(self):
        query = dns_query(DNS_NAME)
        frame = udp_packet(54000, 53, query)
        result = observer._parse_pcap(
            pcap((frame,), original_lengths=(len(frame) + 32,)),
            frozenset((LOCAL_V4,)),
            b"k" * 32,
            frozenset((53,)),
            frozenset((53,)),
        )
        self.assertTrue(result["capture_limited"])
        self.assertEqual(result["dns_query_count"], 1)

    def test_invalid_headers_and_truncated_records_refuse(self):
        for data in (b"", b"invalid pcap", pcap((b"\x00" * 20,))[:-3]):
            with self.subTest(length=len(data)):
                with self.assertRaises(observer.ObserverRefusal) as caught:
                    observer._parse_pcap(
                        data,
                        frozenset((LOCAL_V4,)),
                        b"k" * 32,
                        frozenset((53,)),
                        frozenset((53,)),
                    )
                self.assertEqual(caught.exception.reason, "capture_invalid")

    def test_hmacs_are_session_specific(self):
        query = dns_query(DNS_NAME)
        frame = udp_packet(54000, 53, query)
        records = []
        for key in (b"a" * 32, b"b" * 32):
            records.append(observer._parse_pcap(
                pcap((frame,)),
                frozenset((LOCAL_V4,)),
                key,
                frozenset((53,)),
                frozenset((53,)),
            )["dns_name_hashes"])
        self.assertNotEqual(records[0], records[1])


class CaptureReadinessTests(unittest.TestCase):
    def _session_and_capture(self, key):
        class Process:
            def poll(self):
                return None

        session = type("Session", (), {
            "_hash_key": key,
            "_dns_udp_ports": frozenset((53,)),
            "_dns_tcp_ports": frozenset(),
        })()
        capture = {
            "path": "capture-fixture",
            "addresses": frozenset((LOCAL_V4,)),
            "process": Process(),
        }
        return session, capture

    def test_positive_drain_requires_expected_dns_and_tcp_hmacs(self):
        key = b"q" * 32
        expected_dns = observer.hmac.new(
            key,
            b"dns\x00" + observer._encode_dns_name(DNS_NAME),
            observer.hashlib.sha256,
        ).hexdigest()
        expected_tcp = observer.hmac.new(
            key,
            b"tcp\x00" + REMOTE_V4.encode("ascii") + b":443",
            observer.hashlib.sha256,
        ).hexdigest()
        session, capture = self._session_and_capture(key)
        data = pcap((udp_packet(54000, 53, dns_query(DNS_NAME)), tcp_syn_packet(54001, 443)))
        with patch.object(observer, "_read_capture_snapshot", return_value=data) as snapshot:
            observer._wait_for_expected_fixture(session, capture, expected_dns, expected_tcp)
        snapshot.assert_called_once_with("capture-fixture")

    def test_positive_drain_refuses_unexpected_fixture_hashes(self):
        key = b"r" * 32
        session, capture = self._session_and_capture(key)
        data = pcap((udp_packet(54000, 53, dns_query("other.invalid")), tcp_syn_packet(54001, 444)))
        with patch.object(observer, "_read_capture_snapshot", return_value=data), \
                patch.object(observer.time, "monotonic", side_effect=(0.0, 4.0)):
            with self.assertRaises(observer.ObserverRefusal) as caught:
                observer._wait_for_expected_fixture(session, capture, "c" * 64, "d" * 64)
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("capture_invalid", "selftest"))

    def test_capture_readiness_requires_valid_header_with_configured_snaplen(self):
        with patch.object(observer, "_read_capture_snapshot", return_value=b"x" * 24), \
                patch.object(observer, "_pcap_header", return_value=("<", observer.MAX_SNAPSHOT_BYTES, 1)):
            self.assertTrue(observer._capture_header_ready("capture-fixture"))
        with patch.object(observer, "_read_capture_snapshot", return_value=b"x" * 24), \
                patch.object(observer, "_pcap_header", return_value=("<", observer.MAX_SNAPSHOT_BYTES - 1, 1)):
            with self.assertRaises(observer.ObserverRefusal) as caught:
                observer._capture_header_ready("capture-fixture")
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("capture_invalid", "start"))


class ObservationLifecycleTests(unittest.TestCase):
    def make_session(self):
        binding = observer._validated_binding(CONTROL_SHA, RUN_ID, RUN_ATTEMPT, SOURCE_SHA)
        capture = {"path": "capture-fixture", "addresses": frozenset((LOCAL_V4,)), "process": object()}
        return observer.ObservationSession(
            binding,
            "session-fixture",
            (capture,),
            frozenset((53,)),
            frozenset((53,)),
            100.0,
            b"z" * 32,
        )

    def test_finish_stops_parses_removes_and_returns_closed_record(self):
        parsed = {
            "dns_query_count": 2,
            "tcp_syn_count": 3,
            "dns_name_hashes": ("a" * 64,),
            "tcp_destination_hashes": ("b" * 64,),
            "hashes_truncated": False,
            "capture_limited": False,
            "packet_count": 5,
        }
        session = self.make_session()
        with patch.object(observer, "_stop_capture") as stop, \
                patch.object(observer, "_read_capture_file", return_value=b"pcap") as read, \
                patch.object(observer, "_parse_pcap", return_value=parsed) as parse, \
                patch.object(observer, "_remove_private_directory") as remove, \
                patch.object(observer.time, "monotonic", return_value=101.0):
            record = session.finish()
        stop.assert_called_once()
        read.assert_called_once_with("capture-fixture")
        parse.assert_called_once()
        remove.assert_called_once_with("session-fixture")
        self.assertEqual(record["status"], "observed")
        self.assertEqual(record["control_sha"], CONTROL_SHA)
        self.assertEqual(record["source_sha"], SOURCE_SHA)
        self.assertEqual(record["dns_query_count"], 2)
        self.assertEqual(record["tcp_syn_count"], 3)
        self.assertEqual(record["dns_name_hashes"], ["a" * 64])
        self.assertEqual(record["tcp_destination_hashes"], ["b" * 64])
        self.assertIs(type(record["dns_name_hashes"]), list)
        self.assertIs(type(record["tcp_destination_hashes"]), list)
        self.assertEqual(record["capture"], "private")
        self.assertEqual(record["cleanup"], "complete")
        self.assertEqual(record["worker_attribution"], "not-claimed")
        self.assertEqual(session._hash_key, b"")
        self.assertEqual(session.finish(), record)

    def test_cleanup_failure_overrides_observation_result(self):
        parsed = {
            "dns_query_count": 0,
            "tcp_syn_count": 0,
            "dns_name_hashes": (),
            "tcp_destination_hashes": (),
            "hashes_truncated": False,
            "capture_limited": False,
            "packet_count": 0,
        }
        session = self.make_session()
        with patch.object(observer, "_stop_capture"), \
                patch.object(observer, "_read_capture_file", return_value=b"pcap"), \
                patch.object(observer, "_parse_pcap", return_value=parsed), \
                patch.object(
                    observer,
                    "_remove_private_directory",
                    side_effect=observer.ObserverRefusal("cleanup_incomplete", "cleanup"),
                ):
            with self.assertRaises(observer.ObserverRefusal) as caught:
                session.finish()
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("cleanup_incomplete", "cleanup"))
        self.assertEqual(session._hash_key, b"")

    def test_unconfirmed_capture_termination_keeps_private_directory(self):
        session = self.make_session()
        with patch.object(
            observer,
            "_stop_capture",
            side_effect=observer.ObserverRefusal("cleanup_incomplete", "cleanup"),
        ), patch.object(observer, "_read_capture_file") as read, \
                patch.object(observer, "_remove_private_directory") as remove:
            with self.assertRaises(observer.ObserverRefusal) as caught:
                session.finish()
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("cleanup_incomplete", "cleanup"))
        read.assert_not_called()
        remove.assert_not_called()
        self.assertEqual(session._hash_key, b"")

    def test_partial_start_stops_started_capture_and_removes_directory(self):
        interfaces = (
            {"name": "en0", "addresses": frozenset((LOCAL_V4,))},
            {"name": "en1", "addresses": frozenset((LOCAL_V4,))},
        )
        capture = {"path": "capture-one", "addresses": frozenset((LOCAL_V4,)), "process": object()}
        with patch.object(observer, "_create_private_directory", return_value="session-fixture"), \
                patch.object(observer, "_start_capture", side_effect=(capture, observer.ObserverRefusal("observer_unavailable", "start"))), \
                patch.object(observer, "_stop_capture") as stop, \
                patch.object(observer, "_remove_private_directory") as remove:
            with self.assertRaises(observer.ObserverRefusal):
                observer._start_session(
                    observer._validated_binding(CONTROL_SHA, RUN_ID, RUN_ATTEMPT, SOURCE_SHA),
                    interfaces,
                    frozenset((53,)),
                    frozenset((53,)),
                    {"en0": "udp port 53", "en1": "udp port 53"},
                )
        stop.assert_called_once_with(capture)
        remove.assert_called_once_with("session-fixture")

    def test_partial_start_retains_directory_when_a_process_may_survive(self):
        interfaces = (
            {"name": "en0", "addresses": frozenset((LOCAL_V4,))},
            {"name": "en1", "addresses": frozenset((LOCAL_V4,))},
        )
        capture = {"path": "capture-one", "addresses": frozenset((LOCAL_V4,)), "process": object()}
        with patch.object(observer, "_create_private_directory", return_value="session-fixture"), \
                patch.object(
                    observer,
                    "_start_capture",
                    side_effect=(capture, observer.ObserverRefusal("cleanup_incomplete", "cleanup")),
                ), patch.object(observer, "_stop_capture") as stop, \
                patch.object(observer, "_remove_private_directory") as remove:
            with self.assertRaises(observer.ObserverRefusal) as caught:
                observer._start_session(
                    observer._validated_binding(CONTROL_SHA, RUN_ID, RUN_ATTEMPT, SOURCE_SHA),
                    interfaces,
                    frozenset((53,)),
                    frozenset((53,)),
                    {"en0": "udp port 53", "en1": "udp port 53"},
                )
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("cleanup_incomplete", "cleanup"))
        stop.assert_called_once_with(capture)
        remove.assert_not_called()

    def test_start_capture_reaps_spawned_process_when_startup_check_raises(self):
        class Process:
            def __init__(self):
                self.terminated = False
                self.waited = False
                self.signals = []

            def poll(self):
                return -2 if self.terminated else None

            def send_signal(self, value):
                self.signals.append(value)
                self.terminated = True

            def wait(self, timeout):
                self.waited = True
                return -2

            def kill(self):
                self.terminated = True

        process = Process()
        with patch.object(observer, "_create_capture_file", return_value="capture-fixture"), \
                patch.object(observer.subprocess, "Popen", return_value=process) as popen, \
                patch.object(observer, "_wait_capture_ready", side_effect=OSError) as readiness:
            with self.assertRaises(observer.ObserverRefusal) as caught:
                observer._start_capture(
                    "session-fixture",
                    0,
                    {"name": "en0", "addresses": frozenset((LOCAL_V4,))},
                    "udp port 53",
                )
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("observer_unavailable", "start"))
        self.assertEqual(process.signals, [observer.signal.SIGINT])
        self.assertTrue(process.waited)
        self.assertTrue(process.terminated)
        readiness.assert_called_once_with(process, "capture-fixture")
        arguments = popen.call_args.args[0]
        self.assertIn("--immediate-mode", arguments)
        self.assertIn("-U", arguments)

    def test_capture_start_waits_for_a_valid_pcap_header_and_live_process(self):
        class Process:
            def poll(self):
                return None

        process = Process()
        with patch.object(observer, "_capture_header_ready", side_effect=(False, True)) as ready, \
                patch.object(observer.time, "monotonic", side_effect=(0.0, 0.0, 0.1)), \
                patch.object(observer.time, "sleep") as sleep:
            observer._wait_capture_ready(process, "capture-fixture")
        self.assertEqual(ready.call_count, 2)
        sleep.assert_called_once_with(observer.STARTUP_POLL_SECONDS)

    def test_start_capture_reports_uncertain_process_cleanup(self):
        class Process:
            def poll(self):
                return None

            def send_signal(self, value):
                return

            def wait(self, timeout):
                raise observer.subprocess.TimeoutExpired("tcpdump", timeout)

            def kill(self):
                raise OSError

        with patch.object(observer, "_create_capture_file", return_value="capture-fixture"), \
                patch.object(observer.subprocess, "Popen", return_value=Process()), \
                patch.object(observer, "_wait_capture_ready", side_effect=OSError):
            with self.assertRaises(observer.ObserverRefusal) as caught:
                observer._start_capture(
                    "session-fixture",
                    0,
                    {"name": "en0", "addresses": frozenset((LOCAL_V4,))},
                    "udp port 53",
                )
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("cleanup_incomplete", "cleanup"))


class PrivateDirectoryTests(unittest.TestCase):
    def test_created_directory_is_removed_if_protection_setup_fails(self):
        root_info = type("Info", (), {
            "st_mode": observer.stat.S_IFDIR | observer.stat.S_ISVTX | 0o777,
            "st_uid": 0,
        })()
        directory_info = type("Info", (), {
            "st_mode": observer.stat.S_IFDIR | 0o700,
            "st_uid": 0,
        })()
        path = "/tmp/macos-ci-network-fixture"
        with patch.object(observer.os.path, "realpath", return_value="/tmp"), \
                patch.object(observer.os, "stat", return_value=root_info), \
                patch.object(observer.tempfile, "mkdtemp", return_value=path), \
                patch.object(observer.os, "chown", side_effect=OSError, create=True), \
                patch.object(observer.os, "lstat", return_value=directory_info), \
                patch.object(observer.shutil, "rmtree") as remove, \
                patch.object(observer.os.path, "lexists", return_value=False):
            with self.assertRaises(observer.ObserverRefusal) as caught:
                observer._create_private_directory()
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("observer_unavailable", "start"))
        remove.assert_called_once_with(path)

    def test_directory_cleanup_failure_is_not_hidden_by_setup_refusal(self):
        root_info = type("Info", (), {
            "st_mode": observer.stat.S_IFDIR | observer.stat.S_ISVTX | 0o777,
            "st_uid": 0,
        })()
        directory_info = type("Info", (), {
            "st_mode": observer.stat.S_IFDIR | 0o700,
            "st_uid": 0,
        })()
        path = "/tmp/macos-ci-network-fixture"
        with patch.object(observer.os.path, "realpath", return_value="/tmp"), \
                patch.object(observer.os, "stat", return_value=root_info), \
                patch.object(observer.tempfile, "mkdtemp", return_value=path), \
                patch.object(observer.os, "chown", side_effect=OSError, create=True), \
                patch.object(observer.os, "lstat", return_value=directory_info), \
                patch.object(observer.shutil, "rmtree", side_effect=OSError):
            with self.assertRaises(observer.ObserverRefusal) as caught:
                observer._create_private_directory()
        self.assertEqual((caught.exception.reason, caught.exception.stage), ("cleanup_incomplete", "cleanup"))


class OutputContractTests(unittest.TestCase):
    def test_success_line_is_fixed_bounded_and_contains_no_raw_endpoint(self):
        line = observer._format_selftest_record(valid_record())
        self.assertEqual(line.count(" "), 18)
        self.assertIn("macos-network-observer=selftest-passed schema=1 mode=host-level", line)
        self.assertIn("control-sha=" + CONTROL_SHA, line)
        self.assertIn("source-sha=none", line)
        self.assertIn("capture=private capture-limited=false cleanup=complete", line)
        self.assertIn("worker-attribution=not-claimed completeness=not-claimed network-blocking=not-claimed", line)
        self.assertNotIn(DNS_NAME, line)
        self.assertNotIn(REMOTE_V4, line)

    def test_success_line_refuses_extra_fields_unbounded_hashes_and_invalid_status(self):
        cases = (
            valid_record(extra="unexpected"),
            valid_record(dns_name_hashes=tuple("a" * 64 for unused in range(17))),
            valid_record(dns_name_hashes=("A" * 64,)),
            valid_record(status="blocked"),
            valid_record(network_blocking="blocked"),
            valid_record(capture_limited=True),
        )
        for record in cases:
            with self.subTest(record=record):
                with self.assertRaises(observer.ObserverRefusal) as caught:
                    observer._format_selftest_record(record)
                self.assertEqual(caught.exception.reason, "capture_invalid")

    def test_cli_selftest_has_one_line_and_exact_run_binding(self):
        record = valid_record()
        output = io.StringIO()
        with patch.object(observer, "_selftest_record", return_value=record), contextlib.redirect_stdout(output):
            status = observer.main(
                ["selftest"],
                {"CI_SHA": CONTROL_SHA, "GITHUB_RUN_ID": RUN_ID, "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT},
            )
        self.assertEqual(status, 0)
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertIn("run-id=" + RUN_ID, lines[0])
        self.assertIn("run-attempt=" + RUN_ATTEMPT, lines[0])

    def test_cli_refuses_unknown_arguments_and_missing_binding_without_raw_errors(self):
        cases = (
            (["selftest", "extra"], {"CI_SHA": CONTROL_SHA, "GITHUB_RUN_ID": RUN_ID, "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT}, "arguments_invalid"),
            (["selftest"], {}, "binding_invalid"),
        )
        for arguments, environment, reason in cases:
            with self.subTest(reason=reason):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    status = observer.main(arguments, environment)
                self.assertEqual(status, 1)
                self.assertEqual(len(output.getvalue().splitlines()), 1)
                self.assertIn("reason=" + reason, output.getvalue())
                self.assertNotIn("Traceback", output.getvalue())

    def test_physical_discovery_refusal_line_contains_only_the_closed_leaf_stage(self):
        line = observer._format_refusal_line(
            observer.ObserverRefusal("interface_unavailable", "interface_address"),
            CONTROL_SHA,
            RUN_ID,
            RUN_ATTEMPT,
        )
        self.assertIn("reason=interface_unavailable stage=interface_address", line)
        self.assertNotIn(LOCAL_V4, line)
        self.assertNotIn("Traceback", line)

    def test_refusal_diagnostics_are_fixed_and_bind_expected_fixture_hashes(self):
        details = observer._selftest_diagnostics(
            "receipt",
            valid_record(),
            "c" * 64,
            "d" * 64,
        )
        error = observer.ObserverRefusal("capture_invalid", "selftest", details)
        line = observer._format_refusal_line(error, CONTROL_SHA, RUN_ID, RUN_ATTEMPT)
        self.assertIn(
            "selftest-stage=receipt dns-query-count=1 tcp-syn-count=1 "
            "dns-expected-match=yes tcp-expected-match=yes capture-limited=false",
            line,
        )
        self.assertNotIn(DNS_NAME, line)
        self.assertNotIn(REMOTE_V4, line)

    def test_refusal_diagnostics_use_unknown_for_invalid_values(self):
        details = observer._selftest_diagnostics(
            "untrusted-stage",
            valid_record(dns_query_count=True, tcp_syn_count=-1, capture_limited="false"),
            "e" * 64,
            "f" * 64,
        )
        line = observer._format_refusal_line(
            observer.ObserverRefusal("capture_invalid", "selftest", details),
            CONTROL_SHA,
            RUN_ID,
            RUN_ATTEMPT,
        )
        self.assertIn(
            "selftest-stage=unknown dns-query-count=unknown tcp-syn-count=unknown "
            "dns-expected-match=no tcp-expected-match=no capture-limited=unknown",
            line,
        )
        self.assertNotIn("untrusted-stage", line)


if __name__ == "__main__":
    unittest.main()
