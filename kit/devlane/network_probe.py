"""Structural and active network-isolation probe for the Linux dev lane."""

import argparse
import errno
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time


class ProbeRefusal(ValueError):
    pass


REFUSAL_CODES = frozenset((
    "descriptor-probe-unavailable", "external-connectivity", "external-probe-error",
    "external-probe-result-invalid", "firewall-chain-set", "firewall-invalid",
    "firewall-policy", "firewall-rule-family", "firewall-rule-set", "firewall-rule-shape",
    "firewall-unavailable", "inherited-socket", "loopback-unavailable",
    "network-address-unexpected", "network-interface-unexpected",
    "network-namespace-not-isolated", "network-namespace-unavailable",
    "network-route-unexpected", "network-structure-invalid", "network-structure-unexpected",
    "positive-control-error", "positive-control-unavailable", "probe-evidence-shape",
    "probe-failed", "probe-identity", "probe-not-unprivileged", "probe-tool-failed",
    "probe-tool-invalid", "probe-tool-unavailable", "proxy-environment",
))
MAX_REFUSAL_OUTPUT_BYTES = 128
_REFUSAL_OUTPUT = re.compile(rb"network_probe_refusal=([a-z0-9-]{1,64})\n\Z")
PROC_ROOT = "/proc"
SYS_CLASS_NET = "/sys/class/net"
MAX_NETWORK_FILE_BYTES = 1024 * 1024
NETLINK_ROUTE = 0
RTM_NEWROUTE = 24
RTM_GETROUTE = 26
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLM_F_REQUEST = 0x1
NLM_F_DUMP = 0x300
NLM_F_DUMP_INTR = 0x10
RTA_DST = 1
RTA_OIF = 4
RTN_UNICAST = 1
RTN_LOCAL = 2
RTN_BROADCAST = 3


def refusal_code_from_result(returncode, stdout, stderr):
    """Return only the probe's fixed, one-line refusal code from a bounded result."""
    if (type(returncode) is not int or returncode != 2 or type(stdout) is not bytes
            or stdout or type(stderr) is not bytes or not stderr
            or len(stderr) > MAX_REFUSAL_OUTPUT_BYTES):
        return None
    match = _REFUSAL_OUTPUT.fullmatch(stderr)
    if match is None:
        return None
    code = match.group(1).decode("ascii")
    return code if code in REFUSAL_CODES else None


def _refuse(code):
    raise ProbeRefusal(code)


def positive_control(timeout=3.0, connector=None):
    """Before the cut, prove that the fixed external TCP probe can connect."""
    connect = connector or socket.create_connection
    for address in (("1.1.1.1", 443), ("8.8.8.8", 443)):
        try:
            connection = connect(address, timeout=timeout)
            connection.close()
            return {"connected": True, "target": "public-tls-control"}
        except (OSError, TimeoutError):
            continue
        except Exception:
            _refuse("positive-control-error")
    _refuse("positive-control-unavailable")


def require_external_blocked(operation):
    """Accept only an explicit failed external attempt; any connection is a refusal."""
    try:
        connected = operation()
    except TimeoutError:
        return False
    except OSError as error:
        if error.errno in {
            errno.ETIMEDOUT, errno.ECONNREFUSED, errno.ENETUNREACH,
            errno.EHOSTUNREACH, errno.EPERM, errno.EACCES,
        }:
            return False
        _refuse("external-probe-error")
    except Exception:
        _refuse("external-probe-error")
    if type(connected) is not bool:
        _refuse("external-probe-result-invalid")
    if connected:
        _refuse("external-connectivity")
    return False


def _read_network_file(path):
    try:
        with open(path, "rb") as source:
            payload = source.read(MAX_NETWORK_FILE_BYTES + 1)
    except OSError:
        _refuse("network-structure-invalid")
    if len(payload) > MAX_NETWORK_FILE_BYTES or b"\x00" in payload:
        _refuse("network-structure-invalid")
    try:
        return payload.decode("ascii", "strict")
    except UnicodeDecodeError:
        _refuse("network-structure-invalid")


def _ipv4_route_address(value):
    if re.fullmatch(r"[0-9a-fA-F]{8}", value) is None:
        _refuse("network-structure-invalid")
    try:
        return str(ipaddress.IPv4Address(struct.pack("<I", int(value, 16))))
    except (OverflowError, ValueError, struct.error):
        _refuse("network-structure-invalid")


def _ipv4_local_addresses(fib_trie):
    """Extract local IPv4 host routes from the kernel's fib_trie diagnostic view."""
    local = set()
    candidate = None
    for line in fib_trie.splitlines():
        leaf = re.fullmatch(r"\s*\|-- ([0-9.]+)\s*", line)
        if leaf is not None:
            try:
                candidate = str(ipaddress.IPv4Address(leaf.group(1)))
            except ipaddress.AddressValueError:
                _refuse("network-structure-invalid")
            continue
        route = re.fullmatch(r"\s*/([0-9]{1,3}) host LOCAL\s*", line)
        if route is not None and candidate is not None:
            prefix = int(route.group(1))
            if prefix > 32:
                _refuse("network-structure-invalid")
            if (candidate, prefix) != ("0.0.0.0", 0):
                local.add((candidate, prefix))
        if not re.fullmatch(r"\s*/[0-9]{1,3} [A-Za-z]+ [A-Za-z]+\s*", line):
            candidate = None
    return local


def _check_ipv4_routes(routes):
    lines = routes.splitlines()
    expected_header = ["Iface", "Destination", "Gateway", "Flags", "RefCnt", "Use",
                       "Metric", "Mask", "MTU", "Window", "IRTT"]
    if not lines or lines[0].split() != expected_header:
        _refuse("network-structure-invalid")
    for line in lines[1:]:
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 11:
            _refuse("network-structure-invalid")
        interface, destination, gateway, flags, refcnt, use, metric, mask = fields[:8]
        try:
            route_flags = int(flags, 16)
            for value in (refcnt, use, metric, *fields[8:]):
                int(value, 10)
        except ValueError:
            _refuse("network-structure-invalid")
        if (interface != "lo" or _ipv4_route_address(destination) != "127.0.0.0"
                or _ipv4_route_address(gateway) != "0.0.0.0"
                or _ipv4_route_address(mask) != "255.0.0.0" or not route_flags & 0x1):
            _refuse("network-route-unexpected")


def _check_ipv6_routes(routes):
    for line in routes.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 10:
            _refuse("network-structure-invalid")
        destination, prefix, source, source_prefix, next_hop = fields[:5]
        interface = fields[9]
        if (re.fullmatch(r"[0-9a-fA-F]{32}", destination) is None
                or re.fullmatch(r"[0-9a-fA-F]{2}", prefix) is None
                or re.fullmatch(r"[0-9a-fA-F]{32}", source) is None
                or re.fullmatch(r"[0-9a-fA-F]{2}", source_prefix) is None
                or re.fullmatch(r"[0-9a-fA-F]{32}", next_hop) is None
                or any(re.fullmatch(r"[0-9a-fA-F]{8}", value) is None for value in fields[5:9])):
            _refuse("network-structure-invalid")
        try:
            destination = str(ipaddress.IPv6Address(bytes.fromhex(destination)))
            source = str(ipaddress.IPv6Address(bytes.fromhex(source)))
            next_hop = str(ipaddress.IPv6Address(bytes.fromhex(next_hop)))
            prefix_length = int(prefix, 16)
            source_prefix_length = int(source_prefix, 16)
        except (ValueError, ipaddress.AddressValueError):
            _refuse("network-structure-invalid")
        if (destination != "::1" or prefix_length != 128 or source != "::"
                or source_prefix_length != 0 or next_hop != "::" or interface != "lo"):
            _refuse("network-route-unexpected")


def _validate_route_payload(payload, family, loopback_index):
    route_size = struct.calcsize("=BBBBBBBBI")
    if len(payload) < route_size:
        _refuse("network-structure-invalid")
    route_family, prefix, _src_prefix, _tos, _table, _protocol, _scope, route_type, _flags = struct.unpack_from(
        "=BBBBBBBBI", payload,
    )
    if route_family != family:
        _refuse("network-structure-invalid")
    address_size = 4 if family == socket.AF_INET else 16
    attributes = {}
    offset = route_size
    while offset < len(payload):
        if offset + 4 > len(payload):
            _refuse("network-structure-invalid")
        attribute_length, attribute_type = struct.unpack_from("=HH", payload, offset)
        if attribute_length < 4 or offset + attribute_length > len(payload):
            _refuse("network-structure-invalid")
        attribute_type &= 0x3fff
        if attribute_type in (RTA_DST, RTA_OIF):
            if attribute_type in attributes:
                _refuse("network-structure-invalid")
            attributes[attribute_type] = payload[offset + 4:offset + attribute_length]
        offset += (attribute_length + 3) & ~3
    raw_destination = attributes.get(RTA_DST, b"\0" * address_size)
    if len(raw_destination) != address_size:
        _refuse("network-structure-invalid")
    output_index = attributes.get(RTA_OIF)
    if output_index is None or len(output_index) != 4:
        _refuse("network-route-unexpected")
    output_index = struct.unpack("=I", output_index)[0]
    destination = str(ipaddress.ip_address(raw_destination))
    if family == socket.AF_INET:
        allowed_destinations = {
            ("127.0.0.0", 8), ("127.0.0.1", 32),
            ("127.0.0.0", 32), ("127.255.255.255", 32),
        }
    else:
        allowed_destinations = {("::1", 128)}
    if (output_index != loopback_index or (destination, prefix) not in allowed_destinations
            or route_type not in (RTN_LOCAL, RTN_BROADCAST)):
        _refuse("network-route-unexpected")


def _check_rtnetlink_routes(loopback_index):
    """Dump every route table directly from the kernel; this needs no iproute2 binary."""
    netlink_family = getattr(socket, "AF_NETLINK", 16)
    for family in (socket.AF_INET, socket.AF_INET6):
        sequence = int(time.monotonic_ns() & 0xffffffff) or 1
        route_request = struct.pack("=BBBBBBBBI", family, 0, 0, 0, 0, 0, 0, 0, 0)
        header = struct.pack("=IHHII", 16 + len(route_request), RTM_GETROUTE,
                             NLM_F_REQUEST | NLM_F_DUMP, sequence, 0)
        try:
            with socket.socket(netlink_family, socket.SOCK_RAW, NETLINK_ROUTE) as connection:
                connection.settimeout(3)
                connection.bind((0, 0))
                connection.sendto(header + route_request, (0, 0))
                received = 0
                complete = False
                while not complete:
                    packet, sender = connection.recvfrom(65536)
                    if sender[0] != 0 or not packet or len(packet) >= 65536:
                        _refuse("network-structure-invalid")
                    received += len(packet)
                    if received > MAX_NETWORK_FILE_BYTES:
                        _refuse("network-structure-invalid")
                    offset = 0
                    while offset < len(packet):
                        if offset + 16 > len(packet):
                            _refuse("network-structure-invalid")
                        length, message_type, message_flags, message_sequence, message_pid = struct.unpack_from(
                            "=IHHII", packet, offset,
                        )
                        if (length < 16 or offset + length > len(packet)
                                or message_sequence != sequence or message_pid != 0):
                            _refuse("network-structure-invalid")
                        payload = packet[offset + 16:offset + length]
                        if message_type == RTM_NEWROUTE:
                            _validate_route_payload(payload, family, loopback_index)
                        elif message_type == NLMSG_DONE:
                            if message_flags & NLM_F_DUMP_INTR:
                                _refuse("network-structure-invalid")
                            if payload and (len(payload) < 4 or struct.unpack_from("=i", payload)[0] != 0):
                                _refuse("network-structure-invalid")
                            complete = True
                        elif message_type == NLMSG_ERROR:
                            _refuse("network-structure-invalid")
                        else:
                            _refuse("network-structure-invalid")
                        offset += (length + 3) & ~3
        except ProbeRefusal:
            raise
        except (OSError, OverflowError, struct.error, ValueError):
            _refuse("network-structure-invalid")


def structural_snapshot(expected_host_net_inode):
    try:
        namespace_inode = os.stat(os.path.join(PROC_ROOT, "self/ns/net")).st_ino
    except OSError:
        _refuse("network-namespace-unavailable")
    if type(expected_host_net_inode) is not int or namespace_inode == expected_host_net_inode:
        _refuse("network-namespace-not-isolated")
    net = os.path.join(PROC_ROOT, "self/net")
    try:
        names = sorted(os.listdir(SYS_CLASS_NET))
    except OSError:
        _refuse("network-structure-invalid")
    if names != ["lo"]:
        _refuse("network-interface-unexpected")

    try:
        link_flags = int(_read_network_file(os.path.join(SYS_CLASS_NET, "lo/flags")).strip(), 16)
        link_type = int(_read_network_file(os.path.join(SYS_CLASS_NET, "lo/type")).strip(), 10)
        link_index = int(_read_network_file(os.path.join(SYS_CLASS_NET, "lo/ifindex")).strip(), 10)
    except ValueError:
        _refuse("network-structure-invalid")
    if link_type != 772 or link_index < 1 or not link_flags & 0x1 or not link_flags & 0x8:
        _refuse("loopback-unavailable")

    proc_names = []
    for line in _read_network_file(os.path.join(net, "dev")).splitlines()[2:]:
        if not line.strip():
            continue
        match = re.fullmatch(r"\s*([^:]+):\s*[0-9 ]+", line)
        if match is None:
            _refuse("network-structure-invalid")
        proc_names.append(match.group(1).strip())
    if sorted(proc_names) != names:
        _refuse("network-interface-unexpected")

    ipv4_local = _ipv4_local_addresses(_read_network_file(os.path.join(net, "fib_trie")))
    allowed_ipv4_local = {("127.0.0.0", 8), ("127.0.0.1", 32)}
    if ipv4_local != allowed_ipv4_local:
        _refuse("network-address-unexpected")

    addresses6 = []
    for line in _read_network_file(os.path.join(net, "if_inet6")).splitlines():
        fields = line.split()
        if len(fields) != 6 or re.fullmatch(r"[0-9a-fA-F]{32}", fields[0]) is None:
            _refuse("network-structure-invalid")
        try:
            address = str(ipaddress.IPv6Address(bytes.fromhex(fields[0])))
            ifindex, prefix, scope, _flags = (int(value, 16) for value in fields[1:5])
        except (ValueError, ipaddress.AddressValueError):
            _refuse("network-structure-invalid")
        addresses6.append((address, ifindex, prefix, scope, fields[5]))
    if addresses6 != [("::1", link_index, 128, 16, "lo")]:
        _refuse("network-address-unexpected")

    _check_ipv4_routes(_read_network_file(os.path.join(net, "route")))
    _check_ipv6_routes(_read_network_file(os.path.join(net, "ipv6_route")))
    _check_rtnetlink_routes(link_index)
    return {"netns_inode": namespace_inode, "interfaces": names, "routes": 0}


def firewall_snapshot():
    """Inspect the firewall as the trusted namespace supervisor, while still in its netns."""
    try:
        namespace_inode = os.stat("/proc/self/ns/net").st_ino
    except OSError:
        _refuse("network-namespace-unavailable")
    nft = subprocess.run(
        ["nft", "-j", "list", "ruleset"], check=False,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
    )
    if nft.returncode != 0:
        _refuse("firewall-unavailable")
    try:
        firewall = json.loads(nft.stdout.decode("ascii", "strict"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        _refuse("firewall-invalid")
    rules = firewall.get("nftables") if type(firewall) is dict else None
    if type(rules) is not list:
        _refuse("firewall-invalid")
    tables = set()
    chains = {}
    chain_count = 0
    rule_count = 0
    for row in rules:
        if type(row) is not dict:
            _refuse("firewall-invalid")
        chain = row.get("chain")
        rule = row.get("rule")
        table = row.get("table")
        if type(table) is dict:
            tables.add((table.get("family"), table.get("name")))
        if type(chain) is dict and chain.get("table") == "devlane":
            chain_count += 1
            chains[chain.get("name")] = chain
        if type(rule) is dict and rule.get("table") == "devlane":
            rule_count += 1
    if chain_count != 3:
        _refuse("firewall-chain-set")
    _validate_firewall_rows(tables, chains, rules, rule_count)
    return {
        "netns_inode": namespace_inode,
        "firewall_chains": 3,
        "firewall_rules": rule_count,
    }


def _validate_firewall_rows(tables, chains, rows, rule_count=None):
    if tables != {("inet", "devlane")} or set(chains) != {"input", "output", "forward"}:
        _refuse("firewall-chain-set")
    for name, hook in (("input", "input"), ("output", "output"), ("forward", "forward")):
        chain = chains[name]
        if (chain.get("family") != "inet" or chain.get("table") != "devlane"
                or chain.get("type") != "filter" or chain.get("hook") != hook
                or chain.get("prio") != 0 or chain.get("policy") != "drop"):
            _refuse("firewall-policy")
    allowed = {
        ("input", "iifname"), ("output", "oifname"),
    }
    found = set()
    actual_rule_count = 0
    for row in rows:
        if type(row) is not dict or type(row.get("rule")) is not dict:
            continue
        rule = row["rule"]
        if rule.get("table") != "devlane":
            continue
        actual_rule_count += 1
        if rule.get("family") != "inet":
            _refuse("firewall-rule-family")
        chain_name = rule.get("chain")
        expr = rule.get("expr")
        if type(expr) is not list or len(expr) != 2:
            _refuse("firewall-rule-shape")
        match = expr[0].get("match") if type(expr[0]) is dict else None
        accept = expr[1].get("accept") if type(expr[1]) is dict else "not-accept"
        if (type(match) is not dict or match.get("op") != "==" or match.get("right") != "lo"
                or type(match.get("left")) is not dict or type(match["left"].get("meta")) is not dict
                or accept is not None):
            _refuse("firewall-rule-shape")
        key = match["left"]["meta"].get("key")
        identity = (chain_name, key)
        if identity not in allowed or identity in found:
            _refuse("firewall-rule-set")
        found.add(identity)
    if rule_count is not None and rule_count != actual_rule_count:
        _refuse("firewall-rule-set")
    if found != allowed or actual_rule_count != 2:
        _refuse("firewall-rule-set")


def _attempt_tcp(host, port, timeout=0.75):
    connection = socket.create_connection((host, port), timeout=timeout)
    try:
        return True
    finally:
        try:
            connection.close()
        except OSError:
            pass


def _attempt_https(host, port=443, timeout=0.75, doh=False):
    request = (
        b"GET /dns-query?name=example.com&type=A HTTP/1.1\r\n"
        b"Host: cloudflare-dns.com\r\nAccept: application/dns-message\r\nConnection: close\r\n\r\n"
        if doh else
        b"HEAD / HTTP/1.1\r\nHost: cloudflare-dns.com\r\nConnection: close\r\n\r\n"
    )
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        try:
            with ssl.create_default_context().wrap_socket(raw, server_hostname="cloudflare-dns.com") as connection:
                connection.settimeout(timeout)
                connection.sendall(request)
                connection.recv(1)
        except (OSError, TimeoutError, ssl.SSLError):
            pass
        return True
    finally:
        try:
            raw.close()
        except OSError:
            pass


def _attempt_udp_dns(host, timeout=0.75):
    query = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(timeout)
        connection.connect((host, 53))
        connection.send(query)
    return True


def _attempt_tcp_dns(host, timeout=0.75):
    connection = socket.create_connection((host, 53), timeout=timeout)
    try:
        try:
            connection.sendall(bytes.fromhex("001c123401000001000000000000076578616d706c6503636f6d0000010001"))
        except (OSError, TimeoutError):
            pass
        return True
    finally:
        try:
            connection.close()
        except OSError:
            pass


def active_probes():
    return {
        "ipv4_https": require_external_blocked(lambda: _attempt_https("1.1.1.1")),
        "ipv6_https": require_external_blocked(lambda: _attempt_https("2606:4700:4700::1111")),
        "dns_udp": require_external_blocked(lambda: _attempt_udp_dns("1.1.1.1")),
        "dns_tcp": require_external_blocked(lambda: _attempt_tcp_dns("1.1.1.1")),
        "doh_direct_ip": require_external_blocked(lambda: _attempt_https("1.1.1.1", doh=True)),
        "metadata": require_external_blocked(lambda: _attempt_tcp("169.254.169.254", 80)),
    }


def loopback_control(timeout=1.0):
    """Prove the namespace permits local IPv4 and IPv6 client/server traffic."""
    for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((address, 0))
                listener.listen(1)
                listener.settimeout(timeout)
                with socket.socket(family, socket.SOCK_STREAM) as client:
                    client.settimeout(timeout)
                    client.connect(listener.getsockname())
                    connection, _ = listener.accept()
                    connection.close()
        except (OSError, TimeoutError):
            return False
    return True


def open_extra_descriptors():
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        _refuse("descriptor-probe-unavailable")
    extras = []
    for name in names:
        if not name.isdecimal() or int(name) <= 2:
            continue
        try:
            os.fstat(int(name))
        except OSError:
            continue
        extras.append(int(name))
    return extras


def validate_probe(evidence, expected_host_net_inode):
    if type(evidence) is not dict or set(evidence) != {
        "namespace_inode", "interfaces", "routes", "loopback", "probes",
        "proxy_environment", "extra_fds", "identity",
    }:
        _refuse("probe-evidence-shape")
    if type(evidence["namespace_inode"]) is not int or evidence["namespace_inode"] == expected_host_net_inode:
        _refuse("network-namespace-not-isolated")
    if evidence["interfaces"] != ["lo"] or evidence["routes"] != 0:
        _refuse("network-structure-unexpected")
    if evidence["loopback"] is not True:
        _refuse("loopback-unavailable")
    if type(evidence["probes"]) is not dict or set(evidence["probes"]) != {
        "ipv4_https", "ipv6_https", "dns_udp", "dns_tcp", "doh_direct_ip", "metadata",
    } or any(value is not False for value in evidence["probes"].values()):
        _refuse("external-connectivity")
    if type(evidence["proxy_environment"]) is not dict or any(evidence["proxy_environment"].values()):
        _refuse("proxy-environment")
    if evidence["extra_fds"] != []:
        _refuse("inherited-socket")
    if evidence["identity"] != "65534:65534":
        _refuse("probe-identity")
    return True


def run_current_probe(expected_host_net_inode):
    if os.geteuid() == 0:
        _refuse("probe-not-unprivileged")
    structural = structural_snapshot(expected_host_net_inode)
    proxy_names = (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy",
        "https_proxy", "all_proxy", "no_proxy",
    )
    evidence = {
        "namespace_inode": structural["netns_inode"],
        "interfaces": structural["interfaces"],
        "routes": structural["routes"],
        "loopback": loopback_control(),
        "probes": active_probes(),
        "proxy_environment": {name: os.environ.get(name, "") for name in proxy_names},
        "extra_fds": open_extra_descriptors(),
        "identity": "%d:%d" % (os.geteuid(), os.getegid()),
    }
    validate_probe(evidence, expected_host_net_inode)
    return evidence


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="operation", required=True)
    control = sub.add_parser("positive-control")
    control.add_argument("--output", required=True)
    check = sub.add_parser("check")
    check.add_argument("--host-net-inode", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "positive-control":
            value = positive_control()
            descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="ascii") as output:
                output.write(json.dumps(value, separators=(",", ":")) + "\n")
            print("network_positive_control=pass")
        else:
            run_current_probe(args.host_net_inode)
            print("network_probe=pass")
        return 0
    except ProbeRefusal as error:
        print("network_probe_refusal=" + str(error), file=sys.stderr)
        return 2
    except Exception:
        print("network_probe_refusal=probe-failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
