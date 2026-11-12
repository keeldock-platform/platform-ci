"""GitHub-Linux-only runtime test for the loopback-only network cut."""

import os
import re
import shutil
import subprocess
import sys
import tempfile
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


SAFE_CODE = re.compile(r"[a-z0-9][a-z0-9 =_.:-]{0,160}")


def _codes(stderr):
    text = stderr[-2048:].decode("ascii", "replace")
    return [line for line in text.splitlines() if SAFE_CODE.fullmatch(line)][-6:]


def _run(argv, *, input_bytes=None, timeout=15, stage="runtime-boundary-failed"):
    result = subprocess.run(
        argv, input=input_bytes, stdin=subprocess.DEVNULL if input_bytes is None else None,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=timeout,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
        close_fds=True, check=False,
    )
    if result.returncode != 0:
        detail = " ".join(_codes(result.stderr))
        raise RuntimeError(stage + " rc=" + str(result.returncode) + ((" " + detail) if detail else ""))


def _inside(host_inode):
    if os.geteuid() != 0:
        raise RuntimeError("runtime-root-required")
    _run(["mount", "--make-rprivate", "/"], stage="runtime-mount-private")
    _run(["ip", "link", "set", "lo", "up"], stage="runtime-loopback-up")
    _run(["nft", "-f", "-"], input_bytes=NFT_RULESET.encode("ascii"), stage="runtime-firewall-load")
    firewall = network_probe.firewall_snapshot()
    if firewall["firewall_chains"] != 3 or firewall["firewall_rules"] != 2:
        raise RuntimeError("runtime-firewall-shape")
    source = Path(__file__).with_name("network_probe.py").resolve(strict=True)
    staging = Path(tempfile.mkdtemp(prefix="devlane-probe-"))
    try:
        os.chmod(staging, 0o755)
        probe = staging / "network_probe.py"
        shutil.copyfile(source, probe)
        os.chmod(probe, 0o444)
        _run([
            "setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
            "--no-new-privs", "--bounding-set=-all", "--",
            "/usr/bin/python3", "-B", "-I", "-S", str(probe), "check",
            "--host-net-inode", str(host_inode),
        ], timeout=30, stage="runtime-worker-probe")
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    if os.stat("/proc/self/ns/net").st_ino != firewall["netns_inode"]:
        raise RuntimeError("runtime-namespace-changed")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--inside":
        try:
            _inside(int(sys.argv[2]))
            return 0
        except Exception as error:
            print("runtime_inside_refusal=" + _safe(error), file=sys.stderr)
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
        ], timeout=60, stage="runtime-unshare")
        print("devlane_network_runtime=pass")
        return 0
    except Exception as error:
        print("devlane_network_runtime=refused reason=" + _safe(error), file=sys.stderr)
        return 1


def _safe(error):
    text = (type(error).__name__ + " " + str(error)).lower()
    text = re.sub(r"[^a-z0-9 =_.:-]", "_", text)[:400]
    return text
if __name__ == "__main__":
    raise SystemExit(main())
