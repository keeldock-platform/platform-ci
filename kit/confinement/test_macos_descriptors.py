import ctypes
import io
import stat
import subprocess
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import macos_capability

NULL_RDEV = 0x3000002
UNEXPECTED = "descriptor_channel_unexpected"
READBACK = "descriptor_readback_unavailable"
CLANG = b"/x/tc/usr/bin/clang"
POLICY = macos_capability._ToolchainPolicy(
    images=("/x/tc/usr/bin/clang", "/x/tc/usr/bin/ld"),
    storage="/x/storage",
    read_roots=("/x/storage", "/x/sdk", "/x/tc"),
)


def kernel_write(buffer, payload, size):
    if size > ctypes.sizeof(buffer):
        raise AssertionError("claimed buffer size exceeds the real buffer")
    payload = payload[:size]
    ctypes.memmove(buffer, payload, len(payload))
    return len(payload)


class FakeLibproc:
    VNODE, PIPE, SOCKET = macos_capability.PROX_FDTYPE_VNODE, macos_capability.PROX_FDTYPE_PIPE, 2

    def __init__(self, processes, images=None):
        self.processes = processes
        self.images = images or {}
        self.vnode_failures = set()
        self.vnode_types = {}
        self.duplicates = {}

    @staticmethod
    def pipe(handle, peer, flags=macos_capability.FWRITE):
        return (FakeLibproc.PIPE, ("pipe", handle, peer, flags))

    @staticmethod
    def vnode(mode, rdev, path, flags=macos_capability.FREAD):
        return (FakeLibproc.VNODE, ("vnode", mode, rdev, path, flags))

    @staticmethod
    def socket():
        return (FakeLibproc.SOCKET, ("socket",))

    @classmethod
    def null(cls):
        return cls.vnode(stat.S_IFCHR | 0o666, NULL_RDEV, b"/dev/null", macos_capability.FREAD | macos_capability.FWRITE)

    @classmethod
    def clean(cls, base=0x1000, stdin=True):
        result = {1: cls.pipe(base, base + 0x10), 2: cls.pipe(base + 1, base + 0x11)}
        if stdin:
            result[0] = cls.null()
        return result

    def proc_pidinfo(self, pid, flavor, arg, buffer, size):
        if pid not in self.processes or flavor != macos_capability.PROC_PIDLISTFDS:
            return -1
        entries = [(fd, kind) for fd, (kind, _detail) in sorted(self.processes[pid].items())]
        entries += self.duplicates.get(pid, [])
        raw = b"".join(bytes(macos_capability._ProcFdInfo(fd, kind)) for fd, kind in entries)
        return kernel_write(buffer, raw, size)

    def proc_pidpath(self, pid, buffer, size):
        image = self.images.get(pid)
        if image is None:
            return 0
        return kernel_write(buffer, image, size)

    def proc_pidfdinfo(self, pid, fd, flavor, buffer, size):
        if pid not in self.processes or fd not in self.processes[pid] or (pid, fd) in self.vnode_failures:
            return -1
        kind, detail = self.processes[pid][fd]
        if flavor == macos_capability.PROC_PIDFDPIPEINFO and detail[0] == "pipe":
            info = macos_capability._PipeFdInfo()
            info.pfi.type = kind
            info.pfi.openflags = detail[3]
            info.pipeinfo.handle = detail[1]
            info.pipeinfo.peerhandle = detail[2]
        elif flavor == macos_capability.PROC_PIDFDVNODEPATHINFO and detail[0] == "vnode":
            info = macos_capability._VnodeFdInfoWithPath()
            info.pfi.type = self.vnode_types.get((pid, fd), kind)
            info.pfi.openflags = detail[4]
            info.pvip.vnode.stat.mode = detail[1]
            info.pvip.vnode.stat.rdev = detail[2]
            info.pvip.path = detail[3]
        else:
            return -1
        if size < ctypes.sizeof(info):
            return -1
        return kernel_write(buffer, bytes(info), size)


def lsof_payload(entries):
    lines = []
    for pid, fds in entries.items():
        lines.extend(("p" + str(pid), "fcwd", "tDIR", "n/tmp", "ftxt", "tREG", "n/usr/bin/python3"))
        for fd, (kind, name) in fds.items():
            lines.extend(("f" + str(fd), "t" + kind, "n" + name))
    return "\n".join(lines) + "\n" if lines else ""


def lsof_clean(base=0xa000, stdin=True):
    result = {1: ("PIPE", "->0x%x" % base), 2: ("PIPE", "->0x%x" % (base + 1))}
    if stdin:
        result[0] = ("CHR", "/dev/null")
    return dict(sorted(result.items()))


def tool_process(extra=None):
    process = FakeLibproc.clean()
    process[4] = FakeLibproc.vnode(stat.S_IFREG | 0o644, 0, b"/x/sdk/usr/include/stdio.h")
    process[5] = FakeLibproc.vnode(
        stat.S_IFREG | 0o644, 0, b"/x/storage/capability/tmp/a.o", macos_capability.FREAD | macos_capability.FWRITE
    )
    process.update(extra or {})
    return process


def tool_entries():
    entries = lsof_clean()
    entries[4] = ("REG", "/x/sdk/usr/include/stdio.h")
    entries[5] = ("REG", "/x/storage/capability/tmp/a.o")
    return entries


class DescriptorReadbackTests(unittest.TestCase):
    def snapshot(self, processes, entries, pids=None, policy=None, images=None, setup=None):
        libproc = FakeLibproc(processes, images if images is not None else {pid: CLANG for pid in processes})
        if setup is not None:
            setup(libproc)
        result = subprocess.CompletedProcess([], 0, lsof_payload(entries).encode("utf-8"), b"")
        pids = list(processes) if pids is None else list(pids)
        with patch.object(macos_capability, "_run", return_value=result):
            with patch.object(macos_capability, "_load_libproc", return_value=libproc):
                with patch.object(macos_capability, "_null_device_rdev", return_value=NULL_RDEV):
                    return macos_capability._descriptor_snapshot(pids, policy)

    def assert_refused(self, reason, *args, **kwargs):
        with self.assertRaises(macos_capability.ProbeFailure) as raised:
            self.snapshot(*args, **kwargs)
        self.assertEqual(raised.exception.reason, reason)

    def test_realistic_readback_accepts_root_without_stdin_and_descendants_with_null_stdin(self):
        processes = {101: FakeLibproc.clean(0x1000, stdin=False), 102: FakeLibproc.clean(0x2000)}
        entries = {101: lsof_clean(0xa000, stdin=False), 102: lsof_clean(0xb000)}
        result = self.snapshot(processes, entries)
        self.assertEqual(set(result), {101, 102})
        self.assertEqual(set(result[101]), {1, 2})
        self.assertEqual(set(result[102]), {0, 1, 2})
        self.assertEqual(result[101][1]["mode"], "w")
        self.assertNotEqual(result[101][1]["name"], result[101][2]["name"])

    def test_vnode_record_layout_matches_the_kernel_structures(self):
        sizes = (macos_capability._VInfoStat, 136), (macos_capability._VnodeInfo, 152), (macos_capability._VnodePathInfo, 1176)
        for structure, size in sizes + ((macos_capability._VnodeFdInfoWithPath, 1200),):
            self.assertEqual(ctypes.sizeof(structure), size)
        self.assertEqual(macos_capability.PROC_PIDFDVNODEPATHINFO, 2)

    def test_descriptor_zero_must_be_the_null_device_by_path_type_and_device_number(self):
        cases = {
            "regular_file": FakeLibproc.vnode(stat.S_IFREG | 0o644, 0, b"/tmp/secret"),
            "other_char_device": FakeLibproc.vnode(stat.S_IFCHR | 0o666, NULL_RDEV + 1, b"/dev/tty"),
            "null_path_wrong_rdev": FakeLibproc.vnode(stat.S_IFCHR | 0o666, NULL_RDEV + 1, b"/dev/null"),
            "null_rdev_wrong_path": FakeLibproc.vnode(stat.S_IFCHR | 0o666, NULL_RDEV, b"/dev/zero"),
            "null_regular": FakeLibproc.vnode(stat.S_IFREG, NULL_RDEV, b"/dev/null"),
            "pipe": FakeLibproc.pipe(0x77, 0x78),
            "socket": FakeLibproc.socket(),
        }
        for name, stdin in cases.items():
            with self.subTest(name=name):
                self.assert_refused(UNEXPECTED, {101: {**FakeLibproc.clean(), 0: stdin}}, {101: lsof_clean()})

    def test_an_unreadable_descriptor_leaves_the_pid_uncredited_but_never_hides_a_violation(self):
        clean = {101: FakeLibproc.clean()}
        self.assertEqual(self.snapshot(clean, {101: lsof_clean()}, setup=lambda p: p.vnode_failures.add((101, 0))), {})
        self.assertEqual(
            self.snapshot(clean, {101: lsof_clean(stdin=False)}, setup=lambda p: p.vnode_failures.add((101, 0))), {}
        )
        wrong_type = lambda p: p.vnode_types.update({(101, 0): FakeLibproc.PIPE})
        self.assertEqual(self.snapshot(clean, {101: lsof_clean()}, setup=wrong_type), {})
        process = tool_process()
        process[6] = FakeLibproc.vnode(stat.S_IFREG, 0, b"/x/elsewhere/file")
        self.assertEqual(
            self.snapshot({101: tool_process()}, {101: tool_entries()}, policy=POLICY,
                          setup=lambda p: p.vnode_failures.add((101, 4))), {})
        self.assert_refused(
            UNEXPECTED, {101: process}, {101: tool_entries()}, policy=POLICY,
            setup=lambda p: p.vnode_failures.add((101, 0)),
        )
        self.assertEqual(
            self.snapshot({101: tool_process()}, {101: tool_entries()}, policy=POLICY,
                          setup=lambda p: p.vnode_failures.add((101, 5))), {})

    def test_a_duplicate_descriptor_in_the_native_list_is_refused(self):
        self.assert_refused(
            UNEXPECTED, {101: FakeLibproc.clean()}, {101: lsof_clean()},
            setup=lambda p: p.duplicates.update({101: [(2, FakeLibproc.PIPE)]}),
        )

    def test_every_extra_or_wrong_descriptor_is_refused(self):
        regular = FakeLibproc.vnode(stat.S_IFREG | 0o644, 0, b"/x/storage/f")
        extras = (FakeLibproc.pipe(0x91, 0x92), FakeLibproc.socket(), regular, FakeLibproc.null())
        for index, extra in enumerate(extras):
            with self.subTest(extra=index):
                self.assert_refused(UNEXPECTED, {101: {**FakeLibproc.clean(), 3: extra}}, {101: lsof_clean()})
                if index != 2:
                    self.assert_refused(
                        UNEXPECTED, {101: {**FakeLibproc.clean(), 3: extra}}, {101: lsof_clean()}, policy=POLICY
                    )
        mutations = {
            "missing_stderr": None,
            "stdout_file": {1: regular},
            "read_mode": {1: FakeLibproc.pipe(0x1000, 0x1010, macos_capability.FREAD)},
            "shared_pipe": {2: FakeLibproc.pipe(0x1000, 0x1010)},
            "zero_handle": {1: FakeLibproc.pipe(0, 0x1010)},
            "too_many": {fd: FakeLibproc.pipe(fd, fd + 5000) for fd in range(3, 1200)},
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                process = FakeLibproc.clean()
                if mutation is None:
                    del process[2]
                else:
                    process.update(mutation)
                self.assert_refused(UNEXPECTED, {101: process}, {101: lsof_clean()})

    def test_the_real_toolchain_image_may_read_trusted_roots_and_write_storage(self):
        result = self.snapshot({101: tool_process()}, {101: tool_entries()}, policy=POLICY)
        self.assertEqual(set(result[101]), {0, 1, 2})
        directory = FakeLibproc.vnode(stat.S_IFDIR | 0o755, 0, b"/x/tc/usr/lib")
        entries = tool_entries()
        entries[6] = ("DIR", "/x/tc/usr/lib")
        self.assertEqual(set(self.snapshot({101: tool_process({6: directory})}, {101: entries}, policy=POLICY)), {101})

    def test_the_toolchain_allowance_follows_the_image_never_the_process_name(self):
        for image in (b"/bin/sleep", b"/x/tc/usr/bin/clangx", b"/x/storage/clang", b"/x/tc/usr/bin"):
            with self.subTest(image=image):
                self.assert_refused(UNEXPECTED, {101: tool_process()}, {101: tool_entries()}, policy=POLICY, images={101: image})
        self.assert_refused(UNEXPECTED, {101: tool_process()}, {101: tool_entries()}, policy=None)
        self.assertEqual(self.snapshot({101: tool_process()}, {101: tool_entries()}, policy=POLICY, images={}), {})
        for image in (b"/x/tc/usr/bin/ld",):
            self.assertEqual(set(self.snapshot({101: tool_process()}, {101: tool_entries()}, policy=POLICY, images={101: image})), {101})

    def test_extra_descriptors_must_stay_inside_the_trusted_roots_and_storage(self):
        read, write = macos_capability.FREAD, macos_capability.FWRITE
        refused = {
            "write_outside_storage": (b"/x/other/w", write),
            "write_under_sdk": (b"/x/sdk/w", write),
            "read_write_toolchain": (b"/x/tc/usr/bin/clang", read | write),
            "read_outside_roots": (b"/x/other/r", read),
            "read_secret": (b"/etc/passwd", read),
            "storage_prefix_write": (b"/x/storage2/w", write),
            "storage_prefix_read": (b"/x/storage2/r", read),
            "sdk_prefix_read": (b"/x/sdk2/r", read),
            "toolchain_prefix_read": (b"/x/tcx/r", read),
            "dotdot_spelling": (b"/x/storage/../other/r", write),
            "not_utf8": (b"/x/storage/\xff", read),
        }
        for name, (path, flags) in refused.items():
            with self.subTest(name=name):
                node = FakeLibproc.vnode(stat.S_IFREG | 0o644, 0, path, flags)
                self.assert_refused(UNEXPECTED, {101: tool_process({6: node})}, {101: tool_entries()}, policy=POLICY)
        for mode in (stat.S_IFCHR | 0o666, stat.S_IFIFO | 0o600, stat.S_IFSOCK):
            node = FakeLibproc.vnode(mode, 0, b"/x/storage/special")
            self.assert_refused(UNEXPECTED, {101: tool_process({6: node})}, {101: tool_entries()}, policy=POLICY)
        exact = FakeLibproc.vnode(stat.S_IFDIR | 0o755, 0, b"/x/storage", macos_capability.FREAD | macos_capability.FWRITE)
        entries = tool_entries()
        entries[6] = ("DIR", "/x/storage")
        self.assertEqual(set(self.snapshot({101: tool_process({6: exact})}, {101: entries}, policy=POLICY)), {101})

    def test_lsof_side_violations_are_refused_even_when_native_readback_is_clean(self):
        for name, mutate in (
            ("extra_socket", lambda e: e.update({4: ("unix", "->0xfeed")})),
            ("extra_pipe", lambda e: e.update({3: ("PIPE", "->0xfeed")})),
            ("regular_file_without_a_grant", lambda e: e.update({3: ("REG", "/x/storage/f")})),
            ("directory_without_a_grant", lambda e: e.update({3: ("DIR", "/x/storage")})),
            ("stdout_not_pipe", lambda e: e.update({1: ("REG", "/tmp/x")})),
            ("stdin_other_device", lambda e: e.update({0: ("CHR", "/dev/tty")})),
            ("shared_pipe", lambda e: e.update({2: e[1]})),
            ("missing_stderr", lambda e: e.pop(2)),
        ):
            with self.subTest(name=name):
                entries = lsof_clean()
                mutate(entries)
                self.assert_refused(UNEXPECTED, {101: FakeLibproc.clean()}, {101: entries})
        entries = tool_entries()
        entries[6] = ("unix", "->0xfeed")
        self.assert_refused(UNEXPECTED, {101: tool_process()}, {101: entries}, policy=POLICY)

    def test_a_dirty_pid_cannot_hide_behind_a_clean_sibling_with_the_same_name(self):
        dirty = FakeLibproc.clean(0x2000)
        dirty[4] = FakeLibproc.socket()
        entries = {101: lsof_clean(0xa000), 102: lsof_clean(0xb000)}
        entries[102][4] = ("unix", "->0xbeef")
        for order in ((101, 102), (102, 101)):
            with self.subTest(order=order):
                self.assert_refused(UNEXPECTED, {101: FakeLibproc.clean(0x1000), 102: dirty}, entries, pids=order)

    def test_vanished_pids_are_ignored_and_never_refuse(self):
        clean = FakeLibproc.clean()
        entries = {101: lsof_clean()}
        self.assertEqual(set(self.snapshot({101: clean}, entries, pids=[101, 102])), {101})
        self.assertEqual(self.snapshot({101: clean}, {}, pids=[101]), {})
        self.assertEqual(self.snapshot({}, entries, pids=[101]), {})
        self.assertEqual(self.snapshot({101: {}}, {101: {}}, pids=[101]), {})
        self.assertEqual(self.snapshot({101: clean}, {101: lsof_clean(stdin=False)}, pids=[101]), {})
        processes = {101: FakeLibproc.clean(0x1000), 103: FakeLibproc.clean(0x3000)}
        both = {101: lsof_clean(0xa000), 103: lsof_clean(0xc000)}
        self.assertEqual(set(self.snapshot(processes, both, pids=[101, 102, 103])), {101, 103})

    def test_malformed_lsof_output_is_a_readback_failure_not_a_channel_verdict(self):
        base = lsof_payload({101: lsof_clean()})
        for payload, code in ((base.replace("fcwd", "fother"), 0), ("garbage\n", 0), (base + base, 0), (base, 2)):
            result = subprocess.CompletedProcess([], code, payload.encode("utf-8"), b"")
            with patch.object(macos_capability, "_run", return_value=result):
                with patch.object(macos_capability, "_load_libproc", return_value=FakeLibproc({101: FakeLibproc.clean()})):
                    with patch.object(macos_capability, "_null_device_rdev", return_value=NULL_RDEV):
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            macos_capability._descriptor_snapshot([101])
            self.assertEqual(raised.exception.reason, READBACK)
        for pids in ([], [101, 101]):
            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                macos_capability._descriptor_snapshot(pids)
            self.assertEqual(raised.exception.reason, READBACK)

    def test_null_device_identity_is_read_once_from_the_host(self):
        with patch.object(macos_capability, "_NULL_DEVICE_RDEV", []):
            info = types.SimpleNamespace(st_mode=stat.S_IFCHR | 0o666, st_rdev=0x3000002)
            with patch.object(macos_capability.os, "stat", return_value=info) as host_stat:
                self.assertEqual(macos_capability._null_device_rdev(), 0x3000002)
                self.assertEqual(macos_capability._null_device_rdev(), 0x3000002)
            host_stat.assert_called_once_with("/dev/null")
        with patch.object(macos_capability, "_NULL_DEVICE_RDEV", []):
            info = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o666, st_rdev=0)
            with patch.object(macos_capability.os, "stat", return_value=info):
                with self.assertRaises(macos_capability.ProbeFailure):
                    macos_capability._null_device_rdev()

    def test_lsof_runs_only_for_pids_not_yet_agreed_and_native_policy_runs_for_all(self):
        libproc = FakeLibproc({101: FakeLibproc.clean(0x1000), 102: FakeLibproc.clean(0x2000)})
        payload = lsof_payload({102: lsof_clean(0xb000)}).encode("utf-8")
        agreed = {101, 999}
        with patch.object(macos_capability, "_load_libproc", return_value=libproc):
            with patch.object(macos_capability, "_null_device_rdev", return_value=NULL_RDEV):
                with patch.object(macos_capability, "_run", return_value=subprocess.CompletedProcess([], 0, payload, b"")) as run:
                    result = macos_capability._descriptor_snapshot([101, 102], None, agreed)
                run.assert_called_once_with(["/usr/sbin/lsof", "-nP", "-Fpfnt", "-p", "102"], timeout=10)
                self.assertEqual((set(result), agreed), ({101, 102}, {101, 102}))
                with patch.object(macos_capability, "_run") as run:
                    macos_capability._descriptor_snapshot([101, 102], None, agreed)
                    libproc.processes[101][4] = FakeLibproc.socket()
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._descriptor_snapshot([101, 102], None, agreed)
                run.assert_not_called()
                self.assertEqual(raised.exception.reason, UNEXPECTED)
                del libproc.processes[101]
                with patch.object(macos_capability, "_run"):
                    self.assertEqual(set(macos_capability._descriptor_snapshot([101, 102], None, agreed)), {102})
                self.assertEqual(agreed, {102})

    def test_the_trusted_policy_is_built_only_from_the_resolved_toolchain_paths(self):
        with patch.object(macos_capability, "_canonical_path", side_effect=lambda path: str(path)):
            policy = macos_capability._toolchain_policy(
                "/x/tc/usr/bin/clang", "/y/ld/usr/bin/ld", "/x/sdk", "/x/storage"
            )
        self.assertEqual(policy.images, frozenset(("/x/tc/usr/bin/clang", "/y/ld/usr/bin/ld")))
        self.assertEqual(policy.storage, "/x/storage")
        self.assertEqual(policy.read_roots, ("/x/sdk", "/x/storage", "/x/tc", "/y/ld"))

    def test_every_libproc_buffer_is_at_least_as_large_as_the_kernel_record_it_receives(self):
        sizes = []

        class Recording(FakeLibproc):
            def proc_pidinfo(self, pid, flavor, arg, buffer, size):
                sizes.append(("list", size, ctypes.sizeof(buffer)))
                return super().proc_pidinfo(pid, flavor, arg, buffer, size)

            def proc_pidpath(self, pid, buffer, size):
                sizes.append(("path", size, ctypes.sizeof(buffer)))
                return super().proc_pidpath(pid, buffer, size)

            def proc_pidfdinfo(self, pid, fd, flavor, buffer, size):
                sizes.append((flavor, size, ctypes.sizeof(buffer)))
                return super().proc_pidfdinfo(pid, fd, flavor, buffer, size)

        libproc = Recording({101: tool_process()}, {101: CLANG})
        with patch.object(macos_capability, "_load_libproc", return_value=libproc):
            with patch.object(macos_capability, "_null_device_rdev", return_value=NULL_RDEV):
                self.assertIsNotNone(macos_capability._native_descriptor_snapshot(101, POLICY))
        wanted = {
            "list": (8192, 8192),
            "path": (4096, 4096),
            macos_capability.PROC_PIDFDPIPEINFO: (ctypes.sizeof(macos_capability._PipeFdInfo),) * 2,
            macos_capability.PROC_PIDFDVNODEPATHINFO: (ctypes.sizeof(macos_capability._VnodeFdInfoWithPath),) * 2,
        }
        self.assertEqual({entry[0] for entry in sizes}, set(wanted))
        for flavor, claimed, real in sizes:
            self.assertEqual((claimed, real), wanted[flavor])
        self.assertGreaterEqual(wanted["list"][0], 8 * 1024)
        self.assertEqual(ctypes.sizeof(macos_capability._PipeFdInfo), 184)
        self.assertEqual(ctypes.sizeof(macos_capability._VnodeFdInfoWithPath), 1200)

    def test_oversized_kernel_answers_are_never_written_past_the_buffer_or_trusted(self):
        buffer = ctypes.create_string_buffer(16)
        self.assertEqual(kernel_write(buffer, b"x" * 5000, 16), 16)
        with self.assertRaises(AssertionError):
            kernel_write(buffer, b"x", 17)
        libproc = FakeLibproc({}, {7: b"a" * 5000})
        self.assertIsNone(macos_capability._pid_image(libproc, 7))

    def test_the_process_image_is_read_through_proc_pidpath_and_bounded(self):
        libproc = FakeLibproc({}, {5: b"/x/tc/usr/bin/clang", 6: b"\xff\xfe", 7: b"a" * 5000})
        self.assertEqual(macos_capability._pid_image(libproc, 5), "/x/tc/usr/bin/clang")
        for pid in (6, 7, 8):
            self.assertIsNone(macos_capability._pid_image(libproc, pid))
        with patch.object(macos_capability, "_load_libproc", return_value=libproc):
            self.assertTrue(macos_capability._image_is_trusted(5, POLICY))
            self.assertFalse(macos_capability._image_is_trusted(6, POLICY))
            self.assertFalse(macos_capability._image_is_trusted(5, None))
        self.assertIn("suspended hold process", macos_capability.CLANG_ROLE_EVIDENCE)
        self.assertIn("spawn-time", macos_capability.CLANG_ROLE_EVIDENCE)

    def test_probe_requires_observed_forked_grandchild_and_all_process_roles(self):
        roles = {
            "capabilityprobe",
            "capabilitychild",
            "sh",
            "sleep",
            "capability-child",
            "forked-grandchild",
            "python3",
            "clang",
        }
        self.assertTrue(macos_capability._roles_complete(roles))
        roles.remove("forked-grandchild")
        self.assertFalse(macos_capability._roles_complete(roles))
        observed = macos_capability._observe_roles(
            {"capabilityprobe", "capabilitychild", "capability-child", "clang"},
            {"capabilityprobe": 1, "capabilitychild": 1, "capability-child": 2, "clang": 1},
        )
        self.assertIn("forked-grandchild", observed)

    def test_framework_python_process_name_counts_as_the_python_role_and_nothing_looser_does(self):
        for name in ("python", "python3.9"):
            self.assertIn("python3", macos_capability._observe_roles({name}, {name: 1}))
        for name in ("pythonx", "python2", "ython", "(python)", ""):
            self.assertNotIn("python3", macos_capability._observe_roles({name}, {name: 1}))



class MissingRolesDiagnosticTests(unittest.TestCase):
    REASON = "descriptor_readback_unavailable"
    PREFIX = "macos-capability=refused reason=descriptor_readback_unavailable"
    SUFFIX = "\nmacos-confinement=refused reason=incomplete_channel_evidence\n"
    ROLES = (
        "capabilityprobe", "capabilitychild", "sh", "sleep",
        "capability-child", "forked-grandchild", "python3", "clang",
    )

    def line(self, text):
        return self.PREFIX + text + self.SUFFIX

    def test_role_and_rejection_enums_are_fixed(self):
        self.assertEqual(macos_capability.PROBE_ROLE_ORDER, self.ROLES)
        self.assertEqual(macos_capability.PROBE_ROLE_SET, frozenset(self.ROLES))
        self.assertEqual(macos_capability.SNAPSHOT_REJECTION_BUCKETS, ("none", "some", "many"))
        self.assertTrue(macos_capability._roles_complete(set(self.ROLES)))
        for role in self.ROLES:
            self.assertEqual(macos_capability._missing_roles(set(self.ROLES) - {role}), (role,))
        self.assertEqual(
            [macos_capability._rejection_bucket(count) for count in (0, 1, 9, 10, 500)],
            ["none", "some", "some", "many", "many"],
        )

    def test_missing_roles_are_emitted_in_fixed_order_whatever_the_input_order(self):
        for roles in (self.ROLES, self.ROLES[::-1], set(self.ROLES), frozenset(self.ROLES)):
            self.assertEqual(
                macos_capability.safe_output(False, self.REASON, missing_roles=roles),
                self.line(" missing_roles=" + ",".join(self.ROLES)),
            )
            self.assertEqual(macos_capability.ProbeFailure(self.REASON, missing_roles=roles).missing_roles, self.ROLES)
        self.assertEqual(
            macos_capability.safe_output(False, self.REASON, missing_roles={"clang", "python3"}),
            self.line(" missing_roles=python3,clang"),
        )
        for bucket in macos_capability.SNAPSHOT_REJECTION_BUCKETS:
            self.assertEqual(
                macos_capability.safe_output(False, self.REASON, missing_roles=("clang",), snapshot_rejections=bucket),
                self.line(" missing_roles=clang snapshot_rejections=" + bucket),
            )
        for empty in ({}, (), None):
            self.assertEqual(macos_capability.safe_output(False, self.REASON, missing_roles=empty), self.line(""))

    def test_hostile_values_are_dropped_everywhere(self):
        class StrSubclass(str):
            pass

        hostile = (
            "other", "", "clang\nmacos-confinement=observed", "clang,python3", "clang extra=1", "CLANG",
            "/tmp/secret", "12345", 23, None, b"clang", StrSubclass("clang"), True, object(),
            ["clang"], {"python3": 1}, ("sh",),
        )
        for value in hostile:
            with self.subTest(value=repr(value)):
                roles = (value, "sleep")
                self.assertEqual(
                    macos_capability.safe_output(False, self.REASON, missing_roles=roles),
                    self.line(" missing_roles=sleep"),
                )
                self.assertEqual(macos_capability.ProbeFailure(self.REASON, missing_roles=roles).missing_roles, ("sleep",))
                for scalar in (value,) if not isinstance(value, (list, tuple, set, frozenset)) else ():
                    self.assertEqual(macos_capability.safe_output(False, self.REASON, missing_roles=scalar), self.line(""))
                    self.assertEqual(macos_capability.safe_output(False, self.REASON, snapshot_rejections=scalar), self.line(""))
                    self.assertIsNone(macos_capability.ProbeFailure(self.REASON, snapshot_rejections=scalar).snapshot_rejections)
        for value in ("none ", "Some", "many\n", "1", 3, StrSubclass("some")):
            self.assertEqual(macos_capability.safe_output(False, self.REASON, snapshot_rejections=value), self.line(""))

    def test_role_values_on_other_reasons_and_on_success_are_dropped(self):
        for reason in sorted(macos_capability.REASONS - {self.REASON}) + ["unknown_reason"]:
            self.assertEqual(
                macos_capability.safe_output(False, reason, missing_roles=self.ROLES, snapshot_rejections="many"),
                macos_capability.safe_output(False, reason),
            )
            refusal = macos_capability.ProbeFailure(reason, missing_roles=self.ROLES, snapshot_rejections="many")
            self.assertEqual((refusal.missing_roles, refusal.snapshot_rejections), ((), None))
        self.assertEqual(
            macos_capability.safe_output(True, self.REASON, missing_roles=self.ROLES),
            "macos-capability=observed" + self.SUFFIX,
        )

    def test_channel_verdict_is_a_closed_reason_with_a_bare_summary(self):
        reason = "descriptor_channel_unexpected"
        self.assertIn(reason, macos_capability.REASONS)
        bare = "macos-capability=refused reason=descriptor_channel_unexpected" + self.SUFFIX
        self.assertEqual(macos_capability.safe_output(False, reason), bare)
        self.assertEqual(
            macos_capability.safe_output(
                False, reason, missing_roles=self.ROLES, snapshot_rejections="many", sandbox_stage="probe_exit"
            ),
            bare,
        )
        refusal = macos_capability.ProbeFailure(reason, missing_roles=self.ROLES)
        self.assertEqual((refusal.reason, refusal.missing_roles, refusal.snapshot_rejections), (reason, (), None))
        for failure, expected in (
            (refusal, bare),
            (
                macos_capability.ProbeFailure(self.REASON, missing_roles=("sh", "clang"), snapshot_rejections="some"),
                self.line(" missing_roles=sh,clang snapshot_rejections=some"),
            ),
        ):
            stdout = io.StringIO()
            with patch.object(macos_capability, "run_native_probe", side_effect=failure):
                with redirect_stdout(stdout):
                    self.assertEqual(macos_capability.main(["--control-sha", "a" * 40]), 1)
            self.assertEqual(stdout.getvalue(), expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
