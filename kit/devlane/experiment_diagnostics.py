"""Experiment-only independent hosted probes; never an admission result."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent

def main():
    if os.environ.get('CI_REF') != 'refs/heads/experiment/devlane-macwin-0119':
        return 1
    if sys.platform != 'win32':
        print('experiment_diagnostics=macos native-path-required')
        return 0
    import unittest
    from unittest import mock
    import contextlib
    import io
    import test_windows_sandbox
    methods=['test_icacls_native_status_survives_formatter','test_quiescence_catch_preserves_runtime_cause']
    baseline_suite=unittest.TestSuite(test_windows_sandbox.NativeFailurePreservationTests(name) for name in methods)
    read_text=Path.read_text
    def before_read(path, *args, **kwargs):
        text=read_text(path,*args,**kwargs)
        if path.name=='sandbox_windows.ps1':
            text=text.replace("throw [Runtime.InteropServices.COMException]::new('icacls-native', [int]$LASTEXITCODE)", 'throw')
        if path.name=='sandbox_windows_native.cs':
            text=text.replace('new InvalidOperationException("cleanup_processes", error)', 'new InvalidOperationException("cleanup_processes")')
        return text
    with mock.patch.object(Path,'read_text',new=before_read):
        before=unittest.TextTestRunner(stream=io.StringIO()).run(baseline_suite)
    if len(before.failures)!=2 or before.errors:
        print('experiment_native_before=unexpected');return 1
    print('experiment_native_before=expected-refusal')
    after=unittest.TextTestRunner(stream=io.StringIO()).run(unittest.TestSuite(test_windows_sandbox.NativeFailurePreservationTests(name) for name in methods))
    if not after.wasSuccessful():
        print('experiment_native_after=failed');return 1
    print('experiment_native_after=passed')
    ps = (ROOT / 'sandbox_windows.ps1').read_text()
    serializer = re.search(r'        function Save-State \{.*?\n        \}', ps, re.S).group()
    formatter = re.search(r'function Write-BoundaryFailure.*?\n\}', ps, re.S).group()
    native = (ROOT / 'sandbox_windows_native.cs').read_text()
    # Compile the actual accessor/retry code with a deterministic native-status adapter.
    body = native[native.index('        public static int FirstProfileDeleteStatus'):native.index('        public static string GetProfileFolderPath')]
    source = 'public static class DeleteProbe { static int n; static int DeleteAppContainerProfile(string name) { return ++n == 1 ? unchecked((int)0x80070020) : unchecked((int)0x80070005); }' + body + '}'
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp) / 'state.json'
        result=subprocess.run([str(Path(os.environ['SystemRoot'])/'System32'/'icacls.exe'), tmp, '/setintegritylevel', '(OI)(CI)L', '/L', '/Q'],capture_output=True,timeout=30)
        print('experiment_icacls_direct_exit='+str(result.returncode))
        output=(result.stdout+result.stderr).lower()
        reason='access-denied' if b'access is denied' in output else 'invalid-parameter' if b'invalid parameter' in output else 'other'
        print('experiment_icacls_direct_reason='+reason)
        script = "$ErrorActionPreference='Stop'\n$statePath='"+str(state)+"'\n"
        script += "$script:BoundaryOperation='acl-rule'; $script:OwnedRoots=@('C:\\fixture')\n$state=[pscustomobject]@{owned_roots=@();acl_grants=@();integrity_grants=@()}\n$grants=[Collections.Generic.List[object]]::new(); $integrityGrants=[Collections.Generic.List[string]]::new()\n"
        script += serializer + '\n'
        baseline=serializer.replace('function Save-State', 'function Save-StateBefore').replace('$grants.ToArray()', '@($grants)').replace('$integrityGrants.ToArray()', '@($integrityGrants)')
        script += baseline+'\n'
        script += "$beforeRefused=$false; try { Save-StateBefore } catch { $beforeRefused=$true }; if (-not $beforeRefused) { throw 'baseline-serializer-did-not-refuse' }; 'experiment_serializer_before=expected-refusal'\n"
        script += "for ($i=0; $i -lt 3; $i++) { Save-State; $s=Get-Content -Raw $statePath | ConvertFrom-Json; if ($null -eq $s.acl_grants -or $s.acl_grants.Count -ne $i) { throw 'journal-count' }; $grants.Add([pscustomobject]@{path='fixture';rights='Modify';inheritance=3}) }; 'experiment_serializer=passed'\n"
        script += formatter+'\n'
        script += "$script:BoundaryTarget='profile'; $script:BoundaryPrincipal='package-sid'; $script:BoundaryOperation='profile-delete'; try { throw [Runtime.InteropServices.COMException]::new('profile-delete-native', -2147024891) } catch { $line=Write-BoundaryFailure $_; if ($line -notmatch '^windows_boundary_failure operation=profile-delete code=profile-delete-native win32=5 hresult=-2147024891 target=profile principal=package-sid$') { throw 'formatter-native' } }; 'experiment_formatter_native=passed'\n"
        script += "$script:BoundaryOperation='acl-write'; try { throw [InvalidOperationException]::new('private-root-secret', [UnauthorizedAccessException]::new('never-public')) } catch { $line=Write-BoundaryFailure $_; if ($line -match 'private-root|never-public' -or $line -notmatch 'code=other win32=5 hresult=-2147024891') { throw 'formatter-nested' } }; 'experiment_formatter_nested=passed'\n"
        script += "$script:BoundaryTarget='read-0'; $script:BoundaryPrincipal='package-sid'; $script:BoundaryOperation='acl-write'; try { throw [UnauthorizedAccessException]::new('redacted') } catch { $line=Write-BoundaryFailure $_; if ($line -notmatch '^windows_boundary_failure operation=acl-write code=other win32=5 hresult=-2147024891 target=read-0 principal=package-sid$') { throw 'formatter' }; $line }; 'experiment_formatter=passed'\n"
        script += "Add-Type -TypeDefinition @'\n"+source+"\n'@\nif ([DeleteProbe]::DeleteProfile('fixture') -ne 'access-denied' -or [DeleteProbe]::FirstProfileDeleteStatus -ne -2147024864) { throw 'first-error' }; 'experiment_first_error=passed'\n"
        path=Path(tmp)/'probe.ps1'; path.write_text(script)
        p=subprocess.run(['pwsh','-NoLogo','-NoProfile','-NonInteractive','-File',str(path)],capture_output=True,timeout=90)
        # Only a closed vocabulary leaves this fixture; unexpected PowerShell output stays private.
        lines=p.stdout.decode('utf-8',errors='replace').splitlines()
        allowed=('experiment_serializer_before=expected-refusal','experiment_serializer=passed','experiment_formatter=passed','experiment_formatter_native=passed','experiment_formatter_nested=passed','experiment_first_error=passed')
        for line in lines:
            if line in allowed or re.fullmatch(r'windows_boundary_failure operation=acl-write code=other win32=5 hresult=-2147024891 target=read-0 principal=package-sid',line): print(line)
        print('experiment_runtime_exit='+str(p.returncode))
        return 0 if p.returncode==0 and all(x in lines for x in allowed) else 1

if __name__ == '__main__':
    raise SystemExit(main())
