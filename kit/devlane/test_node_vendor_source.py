"""Synthetic archive fixtures only; no network, Node or npm execution."""
import hashlib
import io
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import node_vendor_source as v

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.budget = lambda: 60
    def tearDown(self):
        for current, directories, files in os.walk(self.base, followlinks=False):
            Path(current).chmod(0o700)
            for name in directories + files:
                p = Path(current) / name
                if not p.is_symlink():
                    p.chmod(0o700 if p.is_dir() else 0o600)
        self.tmp.cleanup()
    def archive(self, extras=(), valid=True):
        path = self.base / 'test.tar.xz'
        rows = [('', tarfile.DIRTYPE, b'', '', 0o755)]
        if valid:
            rows += [('bin/node', tarfile.REGTYPE, b'fixture only', '', 0o755),
                     ('lib/node_modules/npm/bin/npm-cli.js', tarfile.REGTYPE, b'fixture', '', 0o644),
                     ('bin/npm', tarfile.SYMTYPE, b'', '../lib/node_modules/npm/bin/npm-cli.js', 0o777)]
        with tarfile.open(path, 'w:xz') as out:
            for name, kind, body, target, mode in rows + list(extras):
                info = tarfile.TarInfo(v.ARCHIVE_PREFIX + ('/' + name if name else ''))
                info.type, info.linkname, info.mode = kind, target, mode
                info.size = len(body) if kind == tarfile.REGTYPE else 0
                out.addfile(info, io.BytesIO(body) if kind == tarfile.REGTYPE else None)
        path.chmod(0o600)
        return path
    def extract(self, path, budget=None):
        with patch.object(v, 'ARCHIVE_SHA256', hashlib.sha256(path.read_bytes()).hexdigest()):
            fd = v._verified_archive(path, budget or self.budget, os.getuid())
        try:
            v._extract(fd, self.base / 'output', budget or self.budget, os.getuid())
        finally:
            os.close(fd)
        return self.base / 'output'
    def reset(self):
        shutil.rmtree(self.base / 'output', ignore_errors=True)
    def test_valid_layout_and_seal(self):
        root = self.extract(self.archive())
        v._layout(root)
        v._seal(root, self.budget)
        for path, mode in [('bin/node', 0o555), ('bin', 0o555), ('lib/node_modules/npm/bin/npm-cli.js', 0o444)]:
            self.assertEqual(stat.S_IMODE((root / path).stat().st_mode), mode)
    def test_wrong_checksum_before_extract(self):
        with patch.object(v, 'ARCHIVE_SHA256', '0' * 64):
            with self.assertRaisesRegex(v.VendorNodeRefusal, 'checksum'):
                v._verified_archive(self.archive(), self.budget, os.getuid())
        self.assertFalse((self.base / 'output').exists())
    def test_fifo_archive_never_read(self):
        path = self.base / 'fifo'
        os.mkfifo(path, 0o600)
        with patch.object(v.os, 'read', side_effect=AssertionError('FIFO read')):
            with self.assertRaisesRegex(v.VendorNodeRefusal, 'archive-type'):
                v._verified_archive(path, self.budget, os.getuid())
    def test_hardlink_archive(self):
        path = self.archive()
        os.link(path, self.base / 'alias')
        with self.assertRaisesRegex(v.VendorNodeRefusal, 'archive-type'):
            v._verified_archive(path, self.budget, os.getuid())
    def test_symlink_archive(self):
        (self.base / 'alias').symlink_to(self.archive())
        with self.assertRaises(OSError):
            v._verified_archive(self.base / 'alias', self.budget, os.getuid())
    def test_forbidden_members(self):
        for name, kind in [('fifo', tarfile.FIFOTYPE), ('device', tarfile.CHRTYPE), ('hard', tarfile.LNKTYPE),
                           ('../escape', tarfile.REGTYPE), ('/escape', tarfile.REGTYPE), ('a/../../escape', tarfile.REGTYPE)]:
            with self.subTest(name=name), self.assertRaises(v.VendorNodeRefusal):
                self.extract(self.archive([(name, kind, b'bad', '', 0o600)], False))
            self.reset()
        self.assertFalse((self.base / 'escape').exists())
    def test_duplicate(self):
        with self.assertRaisesRegex(v.VendorNodeRefusal, 'member-count'):
            self.extract(self.archive([('bin/node', tarfile.REGTYPE, b'bad', '', 0o755)]))
    def test_link_graph(self):
        cases = [[('escape', tarfile.SYMTYPE, b'', '../outside', 0o777)],
                 [('a', tarfile.SYMTYPE, b'', 'a', 0o777)],
                 [('a', tarfile.SYMTYPE, b'', 'missing', 0o777)],
                 [('dir', tarfile.DIRTYPE, b'', '', 0o755), ('a', tarfile.SYMTYPE, b'', 'dir', 0o777),
                  ('dir/back', tarfile.SYMTYPE, b'', '..', 0o777),
                  ('escape', tarfile.SYMTYPE, b'', 'a/back/../outside', 0o777)]]
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaisesRegex(v.VendorNodeRefusal, 'link'):
                self.extract(self.archive(rows))
            self.reset()
    def test_parent_symlink(self):
        root = self.base / 'root'
        root.mkdir(mode=0o700)
        (root / 'link').symlink_to(self.base, target_is_directory=True)
        fd = os.open(root, os.O_RDONLY | v.DIRECTORY)
        try:
            with self.assertRaises(OSError):
                v._parents(fd, ['link'], os.getuid())
        finally:
            os.close(fd)
    def test_limits(self):
        for field, value, message in [('MAX_FILE_BYTES', 2, 'member-size'), ('MAX_EXPANDED_BYTES', 2, 'expanded-size'), ('MAX_ENTRIES', 1, 'member-count')]:
            with patch.object(v, field, value), self.assertRaisesRegex(v.VendorNodeRefusal, message):
                self.extract(self.archive())
            self.reset()
    def test_deadline(self):
        with self.assertRaisesRegex(v.VendorNodeRefusal, 'deadline'):
            self.extract(self.archive(), lambda: 0)
        self.assertFalse((self.base / 'output').exists())
    def test_invalid_budgets(self):
        for value in [True, None, float('nan'), float('inf'), -1]:
            with self.subTest(value=value), self.assertRaises(v.VendorNodeRefusal):
                v._tick(lambda: value)
    def test_wrong_npm_entry(self):
        root = self.extract(self.archive())
        (root / 'bin/npm').unlink()
        with self.assertRaisesRegex(v.VendorNodeRefusal, 'layout'):
            v._layout(root)
        (root / 'bin/npm').symlink_to('node')
        with self.assertRaisesRegex(v.VendorNodeRefusal, 'layout'):
            v._layout(root)
    def test_platform_refusal(self):
        with patch.object(v.sys, 'platform', 'darwin'), patch.object(v, '_open_protected_base') as opened:
            with self.assertRaisesRegex(v.VendorNodeRefusal, 'platform-or-id'):
                v.acquire_node_source('test-session', 'unused')
            opened.assert_not_called()
    def test_unprivileged_refusal(self):
        with patch.object(v.sys, 'platform', 'linux'), patch.object(v.os, 'geteuid', return_value=501):
            with self.assertRaisesRegex(v.VendorNodeRefusal, 'platform-or-id'):
                v.acquire_node_source('test-session', 'unused')

if __name__ == '__main__':
    unittest.main()
