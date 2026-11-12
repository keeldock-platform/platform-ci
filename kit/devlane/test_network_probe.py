"""Executable source-free network topology and denial regressions."""

import errno
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import network_probe


HOST_NET = 100


def _snapshot(*, links=None, routes4=None, probes=None):
    return {
        "namespace_inode": 200,
        "interfaces": ["lo"] if links is None else links,
        "routes": 0 if routes4 is None else routes4,
        "loopback": True,
        "probes": probes or {
            "ipv4_https": False, "ipv6_https": False, "dns_udp": False,
            "dns_tcp": False, "doh_direct_ip": False, "metadata": False,
        },
        "proxy_environment": {},
        "extra_fds": [],
        "identity": "65534:65534",
    }


class NetworkProbeTests(unittest.TestCase):
    def test_refusal_result_parser_accepts_only_bounded_fixed_codes(self):
        code = "network-address-unexpected"
        result = network_probe.refusal_code_from_result(
            2, b"", ("network_probe_refusal=" + code + "\n").encode("ascii"),
        )
        self.assertEqual(result, code)
        for returncode, stdout, stderr in (
                (0, b"", b"network_probe_refusal=" + code.encode("ascii") + b"\n"),
                (2, b"unexpected", b"network_probe_refusal=" + code.encode("ascii") + b"\n"),
                (2, b"", b"network_probe_refusal=private-path\n"),
                (2, b"", b"network_probe_refusal=" + code.encode("ascii") + b"\nextra\n"),
                (2, b"", b"network_probe_refusal=" + code.encode("ascii")
                 + b"\n" + b"x" * network_probe.MAX_REFUSAL_OUTPUT_BYTES),
        ):
            with self.subTest(stderr=stderr[:96]):
                self.assertIsNone(network_probe.refusal_code_from_result(returncode, stdout, stderr))

    def test_reachable_external_control_is_required_before_the_cut(self):
        class Connected:
            def close(self):
                pass

        self.assertEqual(network_probe.positive_control(connector=lambda address, timeout: Connected()),
                         {"connected": True, "target": "public-tls-control"})
        for error in (TimeoutError(), OSError(errno.ECONNREFUSED, "refused"),
                      OSError(errno.ENETUNREACH, "unreachable"), OSError(errno.EACCES, "permission")):
            with self.subTest(error=type(error).__name__), self.assertRaisesRegex(
                    network_probe.ProbeRefusal, "positive-control-unavailable"):
                network_probe.positive_control(connector=lambda address, timeout, e=error: (_ for _ in ()).throw(e))
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "positive-control-error"):
            network_probe.positive_control(connector=lambda address, timeout: (_ for _ in ()).throw(RuntimeError()))

    def test_active_external_probe_classifies_block_errors_and_rejects_reachability(self):
        blocked = (
            TimeoutError(),
            OSError(errno.ETIMEDOUT, "timed out"),
            OSError(errno.ECONNREFUSED, "refused"),
            OSError(errno.ENETUNREACH, "unreachable"),
            OSError(errno.EHOSTUNREACH, "host unreachable"),
            OSError(errno.EPERM, "denied"),
            OSError(errno.EACCES, "permission"),
        )
        for error in blocked:
            with self.subTest(error=repr(error)):
                operation = lambda e=error: (_ for _ in ()).throw(e)
                self.assertFalse(network_probe.require_external_blocked(operation))
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "external-connectivity"):
            network_probe.require_external_blocked(lambda: True)
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "external-probe-error"):
            network_probe.require_external_blocked(lambda: (_ for _ in ()).throw(RuntimeError()))

    def test_actual_socket_wrappers_refuse_unexpected_oserrors(self):
        wrappers = (
            lambda: network_probe._attempt_tcp("203.0.113.10", 443),
            lambda: network_probe._attempt_https("203.0.113.10"),
            lambda: network_probe._attempt_tcp_dns("203.0.113.10"),
        )
        for wrapper in wrappers:
            with self.subTest(wrapper=wrapper), patch.object(
                    network_probe.socket, "create_connection",
                    side_effect=OSError(errno.EBADF, "bad descriptor")):
                with self.assertRaisesRegex(network_probe.ProbeRefusal, "external-probe-error"):
                    network_probe.require_external_blocked(wrapper)

        class BadDatagram:
            def settimeout(self, timeout):
                pass
            def connect(self, address):
                raise OSError(errno.EBADF, "bad descriptor")
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
        with patch.object(network_probe.socket, "socket", return_value=BadDatagram()):
            with self.assertRaisesRegex(network_probe.ProbeRefusal, "external-probe-error"):
                network_probe.require_external_blocked(lambda: network_probe._attempt_udp_dns("203.0.113.10"))

        with patch.object(network_probe.socket, "create_connection",
                          side_effect=OSError(errno.ENETUNREACH, "blocked")):
            self.assertFalse(network_probe.require_external_blocked(
                lambda: network_probe._attempt_tcp("203.0.113.10", 443)))

    def test_transport_reachability_survives_tls_http_and_dns_protocol_failures(self):
        raw = SimpleNamespace(close=lambda: None)
        with patch.object(network_probe.socket, "create_connection", return_value=raw), \
                patch.object(network_probe.ssl, "create_default_context") as context:
            context.return_value.wrap_socket.side_effect = network_probe.ssl.SSLError("synthetic handshake failure")
            with self.assertRaisesRegex(network_probe.ProbeRefusal, "external-connectivity"):
                network_probe.require_external_blocked(lambda: network_probe._attempt_https("203.0.113.10"))
        connection = SimpleNamespace(
            sendall=lambda payload: (_ for _ in ()).throw(OSError(errno.EPROTO, "synthetic DNS response failure")),
            close=lambda: None,
        )
        with patch.object(network_probe.socket, "create_connection", return_value=connection):
            with self.assertRaisesRegex(network_probe.ProbeRefusal, "external-connectivity"):
                network_probe.require_external_blocked(lambda: network_probe._attempt_tcp_dns("203.0.113.10"))

    def test_structural_readback_refuses_relaxed_interface_or_route(self):
        rows = [
            [{"ifname": "lo"}, {"ifname": "eth0"}],
            [{"ifname": "lo"}],
        ]
        with patch.object(network_probe.os, "stat", return_value=SimpleNamespace(st_ino=200)), \
                patch.object(network_probe, "_run_json", side_effect=rows + [
                [{"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host", "label": "lo"}]}],
                [{"ifname": "lo", "addr_info": [{"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host"}]}],
                [{"dst": "default", "dev": "eth0"}], []]):
            with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-interface-unexpected"):
                network_probe.structural_snapshot(HOST_NET)
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-structure-unexpected"):
            network_probe.validate_probe(_snapshot(links=["lo", "eth0"], routes4=1), HOST_NET)
        external_route = [
            [{"ifname": "lo"}],
            [{"ifname": "lo", "addr_info": [
                {"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host", "label": "lo"}
            ]}],
            [{"ifname": "lo", "addr_info": [
                {"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host"}
            ]}],
            [{"dst": "default", "dev": "eth0"}],
            [],
        ]
        with patch.object(network_probe.os, "stat", return_value=SimpleNamespace(st_ino=200)), \
                patch.object(network_probe, "_run_json", side_effect=external_route):
            with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-route-unexpected"):
                network_probe.structural_snapshot(HOST_NET)

    def test_runner_without_ipv6_loopback_address_is_a_fixed_refusal(self):
        rows = [
            [{"ifname": "lo"}],
            [{"ifname": "lo", "addr_info": [
                {"family": "inet", "local": "127.0.0.1", "prefixlen": 8,
                 "scope": "host", "label": "lo"},
            ]}],
            [], [], [],
        ]
        with patch.object(network_probe.os, "stat", return_value=SimpleNamespace(st_ino=200)), \
                patch.object(network_probe, "_run_json", side_effect=rows):
            with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-address-unexpected"):
                network_probe.structural_snapshot(HOST_NET)

    def test_firewall_readback_rejects_external_accept_rules_and_relaxed_policy(self):
        chains = {
            name: {"family": "inet", "table": "devlane", "name": name, "type": "filter",
                   "hook": name, "prio": 0, "policy": "drop"}
            for name in ("input", "output", "forward")
        }

        def rule(chain, key, device):
            return {"rule": {
                "family": "inet", "table": "devlane", "chain": chain,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": key}}, "right": device}},
                    {"accept": None},
                ],
            }}

        rows = [
            {"table": {"family": "inet", "name": "devlane"}},
            *({"chain": value} for value in chains.values()),
            rule("input", "iifname", "lo"),
            rule("output", "oifname", "lo"),
        ]
        network_probe._validate_firewall_rows({("inet", "devlane")}, chains, rows, 2)
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "firewall-rule-(?:shape|set)"):
            network_probe._validate_firewall_rows(
                {("inet", "devlane")}, chains,
                rows[:-1] + [rule("output", "oifname", "eth0")], 2,
            )
        relaxed = {name: dict(value) for name, value in chains.items()}
        relaxed["output"]["policy"] = "accept"
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "firewall-policy"):
            network_probe._validate_firewall_rows({("inet", "devlane")}, relaxed, rows, 2)

    def test_controlled_reachable_egress_fails_after_cut(self):
        positive = _snapshot(probes={
            "ipv4_https": True, "ipv6_https": False, "dns_udp": False,
            "dns_tcp": False, "doh_direct_ip": False, "metadata": False,
        })
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "external-connectivity"):
            network_probe.validate_probe(positive, HOST_NET)


if __name__ == "__main__":
    unittest.main()
