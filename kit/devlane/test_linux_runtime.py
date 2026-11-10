"""GitHub-Linux-only runtime test for the loopback-only network cut."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import network_probe


NFT_RULESET = (
    "add table inet devlane\n"
    "add chain inet devlane input { type filter hook input priority 0; policy drop; }\n"
    "add chain inet devlane output { type filter hook output priority 0; policy drop; }\n"
    "add chain inet devlane forward { type filter hook forward priority 0; policy drop; }\n"
    "add rule inet devlane input iifname \"lo\" accept\n"
    "add rule inet devlane output oifname \"lo\" accept\n"
)


def _run(argv, *, input_bytes=None, timeout=15):
    result = subprocess.run(
        argv, input=input_bytes, stdin=subprocess.DEVNULL if input_bytes is None else None,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
        close_fds=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("runtime-boundary-failed")


def _inside(host_inode):
    if os.geteuid() != 0:
        raise RuntimeError("runtime-root-required")
    _run(["mount", "--make-rprivate", "/"])
    _run(["ip", "link", "set", "lo", "up"])
    _run(["nft", "-f", "-"], input_bytes=NFT_RULESET.encode("ascii"))
    firewall = network_probe.firewall_snapshot()
    if firewall["firewall_chains"] != 3 or firewall["firewall_rules"] != 2:
        raise RuntimeError("runtime-boundary-failed")
    probe = Path(__file__).with_name("network_probe.py").resolve(strict=True)
    _run([
        "setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
        "--no-new-privs", "--bounding-set=-all", "--",
        "/usr/bin/python3", "-B", "-I", "-S", str(probe), "check",
        "--host-net-inode", str(host_inode),
    ], timeout=30)
    if os.stat("/proc/self/ns/net").st_ino != firewall["netns_inode"]:
        raise RuntimeError("runtime-namespace-changed")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--inside":
        try:
            _inside(int(sys.argv[2]))
            return 0
        except Exception:
            return 2
    if not sys.platform.startswith("linux") or not shutil.which("sudo"):
        return 2
    try:
        network_probe.positive_control(timeout=3)
        host_inode = os.stat("/proc/self/ns/net").st_ino
        _run([
            "sudo", "-n", "unshare", "--net", "--mount", "--pid", "--ipc",
            "--fork", "--mount-proc", "--kill-child", sys.executable,
            str(Path(__file__).resolve()), "--inside", str(host_inode),
        ], timeout=60)
        print("devlane_network_runtime=pass")
        return 0
    except Exception:
        print("devlane_network_runtime=refused", file=sys.stderr)
        return 1
if __name__ == "__main__":
    raise SystemExit(main())
