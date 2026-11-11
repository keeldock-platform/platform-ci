"""Public API fault injection; no network, binary or root execution."""
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import node_vendor_source as v

class ReviewCorrections(unittest.TestCase):
    def exercise(self, failure):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary)
            (base/'archive').write_bytes(b'fixture')
            fd=os.open(base/'archive',os.O_RDONLY)
            time_left=[60]
            def seal(_root,_remaining):
                time_left[0]=0
            from contextlib import ExitStack
            with ExitStack() as stack:
                for p in [patch.object(v.sys,'platform','linux'),patch.object(v.os,'geteuid',return_value=0),
                          patch.object(v,'PROTECTED_BASE',base),patch.object(v,'_download'),
                          patch.object(v,'_open_protected_base',side_effect=lambda:os.open(base,os.O_RDONLY|v.DIRECTORY)),
                          patch.object(v,'_verified_archive',return_value=fd),patch.object(v,'_extract'),
                          patch.object(v,'_layout'),patch.object(v,'_seal',side_effect=seal),
                          patch.dict(sys.modules,{'deadline':types.SimpleNamespace(remaining=lambda _file:time_left[0])})]:
                    stack.enter_context(p)
                if failure=='mkdir':
                    stack.enter_context(patch.object(v.Path,'mkdir',side_effect=OSError('injected')))
                    with self.assertRaises(OSError):
                        v.acquire_node_source('test-session','unused')
                else:
                    with self.assertRaisesRegex(v.VendorNodeRefusal,'deadline'):
                        v.acquire_node_source('test-session','unused')
            with self.assertRaises(OSError):
                os.fstat(fd)
    def test_parent_mkdir_error_closes_verified_fd(self):self.exercise('mkdir')
    def test_expiry_during_seal_is_not_success(self):self.exercise('seal')

if __name__=='__main__':unittest.main()
