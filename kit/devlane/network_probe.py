"""Structural and active network-isolation probe for the Linux dev lane."""

import argparse
import errno
import json
import os
import select
import socket
import ssl
import subprocess
import sys
import time


class ProbeRefusal(ValueError):
    pass


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


def _run_json(argv):
    try:
        result = subprocess.run(
            argv, check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=3, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        _refuse("probe-tool-unavailable")
    if result.returncode != 0:
        _refuse("probe-tool-failed")
    try:
        value = json.loads(result.stdout.decode("ascii", "strict"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        _refuse("probe-tool-invalid")
    return value


def structural_snapshot(expected_host_net_inode):
    try:
        namespace_inode = os.stat("/proc/self/ns/net").st_ino
    except OSError:
        _refuse("network-namespace-unavailable")
    if type(expected_host_net_inode) is not int or namespace_inode == expected_host_net_inode:
        _refuse("network-namespace-not-isolated")
    links = _run_json(["ip", "-j", "link", "show"])
    addresses4 = _run_json(["ip", "-j", "-4", "address", "show"])
    addresses6 = _run_json(["ip", "-j", "-6", "address", "show"])
    routes4 = _run_json(["ip", "-j", "-4", "route", "show", "table", "all"])
    routes6 = _run_json(["ip", "-j", "-6", "route", "show", "table", "all"])
    if any(type(value) is not list for value in (links, addresses4, addresses6, routes4, routes6)):
        _refuse("network-structure-invalid")
    names = sorted(item.get("ifname") for item in links if type(item) is dict)
    if names != ["lo"]:
        _refuse("network-interface-unexpected")
    if (len(addresses4) != 1 or addresses4[0].get("ifname") != "lo"
            or not _address_matches(addresses4[0].get("addr_info"), "inet", "127.0.0.1", 8, "lo")):
        _refuse("network-address-unexpected")
    if (len(addresses6) != 1 or addresses6[0].get("ifname") != "lo"
            or not _address_matches(addresses6[0].get("addr_info"), "inet6", "::1", 128, None)):
        _refuse("network-address-unexpected")
    def loopback_route(route, family):
        if type(route) is not dict or route.get("dev") != "lo" or route.get("type") not in ("local", "broadcast"):
            return False
        destination = route.get("dst")
        if type(destination) is not str:
            return False
        if family == 4:
            return destination in ("127.0.0.0/8", "127.0.0.1", "127.255.255.255", "127.0.0.0")
        return destination in ("::1/128", "::1")
    if any(not loopback_route(route, 4) for route in routes4) or any(not loopback_route(route, 6) for route in routes6):
        _refuse("network-route-unexpected")
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


def _address_matches(value, family, local, prefix, label):
    if type(value) is not list or len(value) != 1 or type(value[0]) is not dict:
        return False
    address = value[0]
    if (address.get("family") != family or address.get("local") != local
            or address.get("prefixlen") != prefix or address.get("scope") != "host"):
        return False
    if label is not None and address.get("label") != label:
        return False
    allowed = {"family", "local", "prefixlen", "scope", "label", "valid_life_time",
               "preferred_life_time", "flags", "broadcast", "peer", "metric"}
    return not (set(address) - allowed)


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
