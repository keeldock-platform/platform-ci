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


NETWORK_STRUCTURE_INVALID_SUFFIXES = frozenset((
    "network-file-read", "network-file-size", "network-file-nul", "network-file-encoding",
    "ipv4-route-address-shape", "ipv4-route-address-value", "ipv4-fib-trie-address",
    "ipv4-fib-trie-prefix", "ipv4-route-header", "ipv6-route-empty",
    "ipv6-route-field-count", "ipv6-route-field-shape", "ipv6-route-value",
    "netlink-route-header", "netlink-route-family", "netlink-route-prefix",
    "netlink-attribute-header", "netlink-attribute-length", "netlink-attribute-padding",
    "netlink-attribute-duplicate", "netlink-attribute-flags", "netlink-destination-length",
    "netlink-output-interface-length", "netlink-table-length", "netlink-priority-length",
    "netlink-prefsrc-length", "netlink-gateway-length", "netlink-cacheinfo-length",
    "netlink-preference-length", "netlink-preference-value", "netlink-pad-length",
    "netlink-metrics-invalid",
    "netlink-socket-bind", "netlink-socket-identity", "netlink-packet-sender",
    "netlink-packet-empty", "netlink-packet-size", "netlink-packet-limit",
    "netlink-message-header", "netlink-message-length", "netlink-message-alignment",
    "netlink-message-sequence", "netlink-message-port-id", "netlink-message-flags",
    "netlink-dump-interrupted", "netlink-done-payload", "netlink-done-ack-attributes",
    "netlink-message-after-done", "netlink-kernel-error", "netlink-message-type",
    "netlink-socket-failed", "loopback-metadata", "interface-list-read",
    "interface-proc-row", "ipv6-address-proc-shape", "ipv6-address-proc-value",
))


REFUSAL_CODES = frozenset((
    "descriptor-probe-unavailable", "external-connectivity", "external-probe-error",
    "external-probe-result-invalid", "firewall-chain-set", "firewall-invalid",
    "firewall-policy", "firewall-rule-family", "firewall-rule-set", "firewall-rule-shape",
    "firewall-unavailable", "inherited-socket", "loopback-unavailable",
    "network-address-unexpected", "network-interface-unexpected",
    "network-namespace-not-isolated", "network-namespace-unavailable",
    "network-route-unexpected", "network-structure-unexpected",
    "positive-control-error", "positive-control-unavailable", "probe-evidence-shape",
    "probe-failed", "probe-identity", "probe-not-unprivileged", "probe-tool-failed",
    "probe-tool-invalid", "probe-tool-unavailable", "proxy-environment",
    *("network-structure-invalid:" + suffix for suffix in NETWORK_STRUCTURE_INVALID_SUFFIXES),
))
MAX_REFUSAL_OUTPUT_BYTES = 512
ROUTE_DIAGNOSTIC_PATTERN = (
    r"route\[table=(?:local|main|default|unspec|n[0-9]{1,10}),"
    r"type=(?:unspec|unicast|local|broadcast|anycast|multicast|blackhole|unreachable|"
    r"prohibit|throw|nat|xresolve|n[0-9]{1,3}),family=[46],"
    r"dst=(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:.]{2,39})/[0-9]{1,3},"
    r"oif=(?:none|unknown|[A-Za-z0-9_.-]{1,15}),"
    r"proto=(?:unspec|redirect|kernel|boot|static|gated|ra|mrt|zebra|bird|dhcp|mptcp|n[0-9]{1,3}),"
    r"scope=(?:universe|site|link|host|nowhere|n[0-9]{1,3})\]"
)
_ROUTE_DIAGNOSTIC = re.compile(ROUTE_DIAGNOSTIC_PATTERN)
_REFUSAL_OUTPUT = re.compile(
    rb"network_probe_refusal=([a-z0-9-]{1,64}(?::[a-z0-9-]{1,48})?)(?: (route\[[^\n]{1,320}\]))?\n\Z"
)


def valid_route_diagnostic(value):
    return type(value) is str and _ROUTE_DIAGNOSTIC.fullmatch(value) is not None
PROC_ROOT = "/proc"
SYS_CLASS_NET = "/sys/class/net"
MAX_NETWORK_FILE_BYTES = 1024 * 1024
NETLINK_ROUTE = 0
RTM_NEWROUTE = 24
RTM_GETROUTE = 26
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLM_F_REQUEST = 0x1
NLM_F_MULTI = 0x2
NLM_F_DUMP = 0x300
NLM_F_DUMP_INTR = 0x10
NLM_F_DUMP_FILTERED = 0x20
NLM_F_ACK_TLVS = 0x200
RTA_DST = 1
RTA_OIF = 4
RTA_GATEWAY = 5
RTA_PRIORITY = 6
RTA_PREFSRC = 7
RTA_METRICS = 8
RTA_MULTIPATH = 9
RTA_CACHEINFO = 12
RTA_TABLE = 15
RTA_VIA = 18
RTA_PREF = 20
RTA_ENCAP_TYPE = 21
RTA_ENCAP = 22
RTA_PAD = 24
RTA_NH_ID = 30
RTN_UNICAST = 1
RTN_LOCAL = 2
RTN_BROADCAST = 3
RTN_ANYCAST = 4
RTN_MULTICAST = 5
RT_TABLE_UNSPEC = 0
RT_TABLE_MAIN = 254
RT_TABLE_DEFAULT = 253
RT_TABLE_LOCAL = 255
RTPROT_KERNEL = 2
RTPROT_BOOT = 3
RTPROT_STATIC = 4
RTPROT_RA = 9
RT6_PREF_LOW = 3
RT6_PREF_MEDIUM = 0
RT6_PREF_HIGH = 1
RT_SCOPE_UNIVERSE = 0
RT_SCOPE_SITE = 200
RT_SCOPE_LINK = 253
RT_SCOPE_HOST = 254
RT_SCOPE_NOWHERE = 255
IFF_UP = 0x1
IFF_LOOPBACK = 0x8
IFA_F_PERMANENT = 0x80


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
    detail = match.group(2)
    if code not in REFUSAL_CODES:
        return None
    if detail is not None:
        try:
            description = detail.decode("ascii", "strict")
        except UnicodeDecodeError:
            return None
        if code != "network-route-unexpected" or _ROUTE_DIAGNOSTIC.fullmatch(description) is None:
            return None
    return code


def refusal_message_from_result(returncode, stdout, stderr):
    """Return a validated fixed refusal code and its optional sanitized route detail."""
    code = refusal_code_from_result(returncode, stdout, stderr)
    if code is None:
        return None
    match = _REFUSAL_OUTPUT.fullmatch(stderr)
    if match is None or match.group(2) is None:
        return code
    return code + " " + match.group(2).decode("ascii")


def _refuse(code, detail=None):
    raise ProbeRefusal(code if detail is None else code + " " + detail)


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


def _invalid_structure(suffix):
    """Refuse malformed structure with a finite, reviewable reason code."""
    _refuse("network-structure-invalid:" + suffix)


def _read_network_file(path):
    try:
        with open(path, "rb") as source:
            payload = source.read(MAX_NETWORK_FILE_BYTES + 1)
    except OSError:
        _invalid_structure("network-file-read")
    if len(payload) > MAX_NETWORK_FILE_BYTES:
        _invalid_structure("network-file-size")
    if b"\x00" in payload:
        _invalid_structure("network-file-nul")
    try:
        return payload.decode("ascii", "strict")
    except UnicodeDecodeError:
        _invalid_structure("network-file-encoding")


def _ipv4_route_address(value):
    if re.fullmatch(r"[0-9a-fA-F]{8}", value) is None:
        _invalid_structure("ipv4-route-address-shape")
    try:
        return str(ipaddress.IPv4Address(struct.pack("<I", int(value, 16))))
    except (OverflowError, ValueError, struct.error):
        _invalid_structure("ipv4-route-address-value")


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
                _invalid_structure("ipv4-fib-trie-address")
            continue
        route = re.fullmatch(r"\s*/([0-9]{1,3}) host LOCAL\s*", line)
        if route is not None and candidate is not None:
            prefix = int(route.group(1))
            if prefix > 32:
                _invalid_structure("ipv4-fib-trie-prefix")
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
        _invalid_structure("ipv4-route-header")
    if len(lines) != 1:
        _refuse("network-route-unexpected")


def _check_ipv6_routes(routes):
    local_count = 0
    null_count = 0
    for line in routes.splitlines():
        if not line.strip():
            _invalid_structure("ipv6-route-empty")
        fields = line.split()
        if len(fields) != 10:
            _invalid_structure("ipv6-route-field-count")
        destination, prefix, source, source_prefix, next_hop = fields[:5]
        interface = fields[9]
        if (re.fullmatch(r"[0-9a-fA-F]{32}", destination) is None
                or re.fullmatch(r"[0-9a-fA-F]{2}", prefix) is None
                or re.fullmatch(r"[0-9a-fA-F]{32}", source) is None
                or re.fullmatch(r"[0-9a-fA-F]{2}", source_prefix) is None
                or re.fullmatch(r"[0-9a-fA-F]{32}", next_hop) is None
                or any(re.fullmatch(r"[0-9a-fA-F]{8}", value) is None for value in fields[5:9])):
            _invalid_structure("ipv6-route-field-shape")
        try:
            destination = str(ipaddress.IPv6Address(bytes.fromhex(destination)))
            source = str(ipaddress.IPv6Address(bytes.fromhex(source)))
            next_hop = str(ipaddress.IPv6Address(bytes.fromhex(next_hop)))
            prefix_length = int(prefix, 16)
            source_prefix_length = int(source_prefix, 16)
            metric = int(fields[5], 16)
            route_flags = int(fields[8], 16)
        except (ValueError, ipaddress.AddressValueError):
            _invalid_structure("ipv6-route-value")
        if (source != "::" or source_prefix_length != 0 or next_hop != "::"
                or interface != "lo"):
            _refuse("network-route-unexpected")
        if (destination == "::1" and prefix_length == 128 and metric == 0
                and route_flags == 0x80200001):
            local_count += 1
        elif (destination == "::" and prefix_length == 0 and metric == 0xffffffff
              and route_flags == 0x00200200):
            null_count += 1
            if null_count > 2:
                _refuse("network-route-unexpected")
        else:
            _refuse("network-route-unexpected")
    if local_count != 1:
        _refuse("network-route-unexpected")


def _netlink_attributes(payload, malformed_suffix):
    """Read aligned nlattrs while allowing the final attribute to omit tail padding."""
    offset = 0
    while offset < len(payload):
        remaining = len(payload) - offset
        if remaining < 4:
            _invalid_structure("netlink-attribute-header")
        attribute_length, raw_type = struct.unpack_from("=HH", payload, offset)
        if attribute_length < 4 or attribute_length > remaining:
            _invalid_structure("netlink-attribute-length")
        end = offset + attribute_length
        aligned_end = offset + ((attribute_length + 3) & ~3)
        if aligned_end > len(payload):
            if end != len(payload):
                _invalid_structure(malformed_suffix)
            aligned_end = len(payload)
        yield raw_type & 0x3fff, raw_type & 0xc000, payload[offset + 4:end]
        offset = aligned_end


def _route_from_payload(payload, family):
    route_size = struct.calcsize("=BBBBBBBBI")
    if len(payload) < route_size:
        _invalid_structure("netlink-route-header")
    route_family, prefix, src_prefix, tos, table, protocol, scope, route_type, _flags = struct.unpack_from(
        "=BBBBBBBBI", payload,
    )
    if route_family != family:
        _invalid_structure("netlink-route-family")
    address_size = 4 if family == socket.AF_INET else 16
    if prefix > address_size * 8 or src_prefix > address_size * 8:
        _invalid_structure("netlink-route-prefix")
    attributes = {}
    for attribute_type, attribute_flags, value in _netlink_attributes(
            payload[route_size:], "netlink-attribute-padding"):
        if attribute_type in attributes:
            _invalid_structure("netlink-attribute-duplicate")
        if (attribute_flags and attribute_type not in (RTA_METRICS, RTA_ENCAP)):
            _invalid_structure("netlink-attribute-flags")
        if attribute_type in (RTA_DST, RTA_OIF, RTA_TABLE, RTA_GATEWAY, RTA_MULTIPATH,
                              RTA_VIA, RTA_ENCAP, RTA_ENCAP_TYPE, RTA_NH_ID,
                              RTA_PRIORITY, RTA_PREFSRC, RTA_METRICS,
                              RTA_CACHEINFO, RTA_PREF, RTA_PAD):
            attributes[attribute_type] = value
        else:
            attributes[-1] = b"unknown"

    raw_destination = attributes.get(RTA_DST, b"\0" * address_size)
    if len(raw_destination) != address_size:
        _invalid_structure("netlink-destination-length")
    output_index = attributes.get(RTA_OIF)
    if output_index is not None and len(output_index) != 4:
        _invalid_structure("netlink-output-interface-length")
    output_index = struct.unpack("=I", output_index)[0] if output_index is not None else None
    route_table = attributes.get(RTA_TABLE)
    if route_table is not None:
        if len(route_table) != 4:
            _invalid_structure("netlink-table-length")
        route_table = struct.unpack("=I", route_table)[0]
    else:
        route_table = table
    priority = attributes.get(RTA_PRIORITY)
    if priority is not None and len(priority) != 4:
        _invalid_structure("netlink-priority-length")
    priority = struct.unpack("=I", priority)[0] if priority is not None else 0
    preferred_source = attributes.get(RTA_PREFSRC)
    if preferred_source is not None and len(preferred_source) != address_size:
        _invalid_structure("netlink-prefsrc-length")
    if RTA_GATEWAY in attributes and len(attributes[RTA_GATEWAY]) != address_size:
        _invalid_structure("netlink-gateway-length")
    if RTA_CACHEINFO in attributes and len(attributes[RTA_CACHEINFO]) != 32:
        _invalid_structure("netlink-cacheinfo-length")
    if RTA_PAD in attributes and attributes[RTA_PAD]:
        _invalid_structure("netlink-pad-length")
    preference = attributes.get(RTA_PREF)
    if preference is not None:
        if len(preference) != 1:
            _invalid_structure("netlink-preference-length")
        preference = preference[0]
        if preference not in (RT6_PREF_LOW, RT6_PREF_MEDIUM, RT6_PREF_HIGH):
            _invalid_structure("netlink-preference-value")
    if RTA_METRICS in attributes and attributes[RTA_METRICS]:
        try:
            tuple(_netlink_attributes(attributes[RTA_METRICS], "netlink-metrics-invalid"))
        except (ProbeRefusal, struct.error, ValueError):
            _invalid_structure("netlink-metrics-invalid")

    destination = str(ipaddress.ip_address(raw_destination))
    preferred_source = (str(ipaddress.ip_address(preferred_source))
                        if preferred_source is not None else None)
    route = {
        "family": family,
        "table": route_table,
        "header_table": table,
        "type": route_type,
        "destination": destination,
        "prefix": prefix,
        "oif": output_index,
        "protocol": protocol,
        "scope": scope,
        "src_prefix": src_prefix,
        "tos": tos,
        "gateway": RTA_GATEWAY in attributes,
        "priority": priority,
        "preferred_source": preferred_source,
        "preference": preference,
        "alternate_nexthop": any(kind in attributes for kind in (
            RTA_MULTIPATH, RTA_VIA, RTA_ENCAP, RTA_ENCAP_TYPE, RTA_NH_ID,
        )),
        "unknown_attributes": -1 in attributes,
        "metrics": bool(attributes.get(RTA_METRICS)),
    }
    return route


def _route_name(value, names, *, fallback="n"):
    return names.get(value, fallback + str(value))


def _route_oif_name(output_index, loopback_index):
    if output_index is None:
        return "none"
    if output_index == loopback_index:
        return "lo"
    try:
        name = socket.if_indextoname(output_index)
    except (AttributeError, OSError, OverflowError, ValueError):
        return "unknown"
    return name if re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) else "unknown"


def _route_description(route, loopback_index):
    family = route["family"]
    table = _route_name(route["table"], {
        RT_TABLE_UNSPEC: "unspec", RT_TABLE_MAIN: "main",
        RT_TABLE_DEFAULT: "default", RT_TABLE_LOCAL: "local",
    })
    route_type = _route_name(route["type"], {
        0: "unspec", RTN_UNICAST: "unicast", RTN_LOCAL: "local",
        RTN_BROADCAST: "broadcast", RTN_ANYCAST: "anycast",
        RTN_MULTICAST: "multicast", 6: "blackhole", 7: "unreachable",
        8: "prohibit", 9: "throw", 10: "nat", 11: "xresolve",
    })
    protocol = _route_name(route["protocol"], {
        0: "unspec", 1: "redirect", RTPROT_KERNEL: "kernel",
        RTPROT_BOOT: "boot", RTPROT_STATIC: "static", 8: "gated",
        RTPROT_RA: "ra", 10: "mrt", 11: "zebra", 12: "bird",
        16: "dhcp", 17: "mptcp",
    })
    scope = _route_name(route["scope"], {
        RT_SCOPE_UNIVERSE: "universe", RT_SCOPE_SITE: "site",
        RT_SCOPE_LINK: "link", RT_SCOPE_HOST: "host",
        RT_SCOPE_NOWHERE: "nowhere",
    })
    destination = "%s/%d" % (route["destination"], route["prefix"])
    return "route[table=%s,type=%s,family=%d,dst=%s,oif=%s,proto=%s,scope=%s]" % (
        table, route_type, 4 if family == socket.AF_INET else 6, destination,
        _route_oif_name(route["oif"], loopback_index), protocol, scope,
    )


def _expected_route(route, loopback_index):
    if (route["src_prefix"] != 0 or route["tos"] != 0 or route["gateway"]
            or route["alternate_nexthop"]
            or route["header_table"] not in (RT_TABLE_UNSPEC, route["table"])
            or route["priority"] != 0 or route["metrics"]
            or route["unknown_attributes"]
            or route["oif"] not in (None, loopback_index)):
        return False
    if route["family"] == socket.AF_INET:
        if (route["preferred_source"] not in (None, "127.0.0.1")
                or route["preference"] is not None):
            return False
        expected = {
            (RT_TABLE_LOCAL, RTPROT_KERNEL, RT_SCOPE_HOST, RTN_LOCAL, "127.0.0.0", 8),
            (RT_TABLE_LOCAL, RTPROT_KERNEL, RT_SCOPE_HOST, RTN_LOCAL, "127.0.0.1", 32),
            (RT_TABLE_LOCAL, RTPROT_KERNEL, RT_SCOPE_LINK, RTN_BROADCAST, "127.255.255.255", 32),
        }
    else:
        if (route["preferred_source"] not in (None, "::1")
                or route["preference"] not in (None, RT6_PREF_MEDIUM)):
            return False
        expected = {
            (RT_TABLE_LOCAL, RTPROT_KERNEL, RT_SCOPE_UNIVERSE, RTN_LOCAL, "::1", 128),
        }
    identity = (route["table"], route["protocol"], route["scope"], route["type"],
                route["destination"], route["prefix"])
    return identity in expected


def _validate_route_payload(payload, family, loopback_index):
    route = _route_from_payload(payload, family)
    if not _expected_route(route, loopback_index):
        _refuse("network-route-unexpected", _route_description(route, loopback_index))
    return route


def _route_identity(route):
    return (route["family"], route["table"], route["protocol"], route["scope"],
            route["type"], route["destination"], route["prefix"])


def _route_set_is_expected(family, seen_routes):
    if family == socket.AF_INET:
        required = {
            (family, RT_TABLE_LOCAL, RTPROT_KERNEL, RT_SCOPE_HOST, RTN_LOCAL, "127.0.0.0", 8),
            (family, RT_TABLE_LOCAL, RTPROT_KERNEL, RT_SCOPE_HOST, RTN_LOCAL, "127.0.0.1", 32),
        }
        optional = {
            (family, RT_TABLE_LOCAL, RTPROT_KERNEL, RT_SCOPE_LINK, RTN_BROADCAST,
             "127.255.255.255", 32),
        }
    else:
        required = {
            (family, RT_TABLE_LOCAL, RTPROT_KERNEL, RT_SCOPE_UNIVERSE,
             RTN_LOCAL, "::1", 128),
        }
        optional = set()
    return required.issubset(seen_routes) and seen_routes.issubset(required | optional)


def _check_rtnetlink_routes(loopback_index):
    """Dump every route table directly from the kernel; this needs no iproute2 binary."""
    netlink_family = getattr(socket, "AF_NETLINK", 16)
    for family in (socket.AF_INET, socket.AF_INET6):
        seen_routes = set()
        sequence = int(time.monotonic_ns() & 0xffffffff) or 1
        route_request = struct.pack("=BBBBBBBBI", family, 0, 0, 0, 0, 0, 0, 0, 0)
        header = struct.pack("=IHHII", 16 + len(route_request), RTM_GETROUTE,
                             NLM_F_REQUEST | NLM_F_DUMP, sequence, 0)
        try:
            with socket.socket(netlink_family, socket.SOCK_RAW, NETLINK_ROUTE) as connection:
                connection.settimeout(3)
                try:
                    connection.bind((0, 0))
                except OSError:
                    _invalid_structure("netlink-socket-bind")
                try:
                    socket_name = connection.getsockname()
                except (AttributeError, OSError, TypeError, ValueError):
                    _invalid_structure("netlink-socket-identity")
                if (type(socket_name) is not tuple or len(socket_name) < 2
                        or type(socket_name[0]) is not int or socket_name[0] <= 0):
                    _invalid_structure("netlink-socket-identity")
                port_id = socket_name[0]
                connection.sendto(header + route_request, (0, 0))
                received = 0
                complete = False
                while not complete:
                    packet, sender = connection.recvfrom(65536)
                    if (type(sender) is not tuple or len(sender) < 2 or sender[0] != 0
                            or sender[1] != 0):
                        _invalid_structure("netlink-packet-sender")
                    if not packet:
                        _invalid_structure("netlink-packet-empty")
                    if len(packet) >= 65536:
                        _invalid_structure("netlink-packet-size")
                    received += len(packet)
                    if received > MAX_NETWORK_FILE_BYTES:
                        _invalid_structure("netlink-packet-limit")
                    offset = 0
                    while offset < len(packet):
                        if offset + 16 > len(packet):
                            _invalid_structure("netlink-message-header")
                        length, message_type, message_flags, message_sequence, message_pid = struct.unpack_from(
                            "=IHHII", packet, offset,
                        )
                        remaining = len(packet) - offset
                        if length < 16 or length > remaining:
                            _invalid_structure("netlink-message-length")
                        if message_sequence != sequence:
                            _invalid_structure("netlink-message-sequence")
                        if message_pid != port_id:
                            _invalid_structure("netlink-message-port-id")
                        if message_flags & NLM_F_DUMP_INTR:
                            _invalid_structure("netlink-dump-interrupted")
                        if not message_flags & NLM_F_MULTI:
                            _invalid_structure("netlink-message-flags")
                        if message_type == RTM_NEWROUTE:
                            allowed_flags = NLM_F_MULTI | NLM_F_DUMP_FILTERED
                        elif message_type == NLMSG_DONE:
                            allowed_flags = NLM_F_MULTI | NLM_F_DUMP_FILTERED | NLM_F_ACK_TLVS
                        else:
                            allowed_flags = NLM_F_MULTI | NLM_F_DUMP_FILTERED
                        if message_flags & ~allowed_flags:
                            _invalid_structure("netlink-message-flags")
                        payload = packet[offset + 16:offset + length]
                        if message_type == RTM_NEWROUTE:
                            route = _validate_route_payload(payload, family, loopback_index)
                            identity = _route_identity(route)
                            if identity in seen_routes:
                                _refuse("network-route-unexpected", _route_description(route, loopback_index))
                            seen_routes.add(identity)
                        elif message_type == NLMSG_DONE:
                            if len(payload) < 4:
                                _invalid_structure("netlink-done-payload")
                            if payload and struct.unpack_from("=i", payload)[0] != 0:
                                _invalid_structure("netlink-kernel-error")
                            if len(payload) > 4:
                                if not message_flags & NLM_F_ACK_TLVS:
                                    _invalid_structure("netlink-done-payload")
                                try:
                                    tuple(_netlink_attributes(
                                        payload[4:], "netlink-done-ack-attributes",
                                    ))
                                except (OverflowError, struct.error, ValueError):
                                    _invalid_structure("netlink-done-ack-attributes")
                            complete = True
                            if not _route_set_is_expected(family, seen_routes):
                                _refuse("network-route-unexpected")
                        elif message_type == NLMSG_ERROR:
                            _invalid_structure("netlink-kernel-error")
                        else:
                            _invalid_structure("netlink-message-type")
                        message_end = offset + length
                        aligned_end = offset + ((length + 3) & ~3)
                        if aligned_end > len(packet):
                            if message_end != len(packet):
                                _invalid_structure("netlink-message-alignment")
                            aligned_end = len(packet)
                        if complete and aligned_end != len(packet):
                            _invalid_structure("netlink-message-after-done")
                        offset = aligned_end
        except ProbeRefusal:
            raise
        except (OSError, OverflowError, struct.error, ValueError):
            _invalid_structure("netlink-socket-failed")


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
        _invalid_structure("interface-list-read")
    if names != ["lo"]:
        _refuse("network-interface-unexpected")

    try:
        link_flags = int(_read_network_file(os.path.join(SYS_CLASS_NET, "lo/flags")).strip(), 16)
        link_type = int(_read_network_file(os.path.join(SYS_CLASS_NET, "lo/type")).strip(), 10)
        link_index = int(_read_network_file(os.path.join(SYS_CLASS_NET, "lo/ifindex")).strip(), 10)
    except ValueError:
        _invalid_structure("loopback-metadata")
    if (link_type != 772 or link_index != 1
            or link_flags != IFF_UP | IFF_LOOPBACK):
        _refuse("loopback-unavailable")

    proc_names = []
    for line in _read_network_file(os.path.join(net, "dev")).splitlines()[2:]:
        if not line.strip():
            continue
        match = re.fullmatch(r"\s*([^:]+):\s*[0-9 ]+", line)
        if match is None:
            _invalid_structure("interface-proc-row")
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
            _invalid_structure("ipv6-address-proc-shape")
        try:
            address = str(ipaddress.IPv6Address(bytes.fromhex(fields[0])))
            ifindex, prefix, scope, flags = (int(value, 16) for value in fields[1:5])
        except (ValueError, ipaddress.AddressValueError):
            _invalid_structure("ipv6-address-proc-value")
        addresses6.append((address, ifindex, prefix, scope, flags, fields[5]))
    if addresses6 != [("::1", link_index, 128, 16, IFA_F_PERMANENT, "lo")]:
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
