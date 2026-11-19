"""Native registry rehearsal invoked by hosted macOS dependency preparation.

Requires a fresh, successful sandbox_macos preflight and its public projection.
Runs as root on the approved macOS image. Leaves evidence under RUN_ROOT/
registry-rehearsal; use normal sandbox_macos cleanup afterward, even on failure.
The workflow captures raw diagnostics privately and clears the verified offline PF
record before production preparation installs its own gateway rules.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import subprocess
import sys
import threading
import time

import sandbox_macos as harness
import registry_proxy


class HeldUpstream:
    """Rehearsal-only latch: hold real upstream TLS mid-request until shutdown.

    The worker sends a complete valid request. The trusted harness withholds its
    final CRLF upstream, so even a fast registry cannot finish before the cut.
    All connection, SNI and certificate validation still use the production proxy.
    """
    def __init__(self, context):
        self.context = context
        self.ready = threading.Event()
        self.stopped = threading.Event()
        self.socket = None

    def wrap_socket(self, raw, **kwargs):
        sock = self.context.wrap_socket(raw, **kwargs)
        self.socket = sock
        owner = self

        class Exchange:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

            def sendall(self, payload):
                if not payload.endswith(b'\r\n\r\n'):
                    raise ValueError('hold-request-invalid')
                sock.sendall(payload[:-2])
                owner.ready.set()
                if not owner.stopped.wait(15):
                    raise OSError('hold-shutdown-missing')
                raise OSError('hold-shutdown')

            def shutdown(self, how):
                try:
                    sock.shutdown(how)
                finally:
                    owner.stopped.set()

            def close(self):
                sock.close()
                owner.stopped.set()

        return Exchange()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('state-dir', 'projection', 'control-sha', 'deadline-file'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    if sys.platform != 'darwin' or os.geteuid() != 0:
        parser.error('approved native macOS root session required')
    state = Path(args.state_dir).resolve(strict=True)
    ident = harness._identity(state)
    harness._validate_prepare_run_root(state, ident)
    if (state / harness.PF_STATE_FILE).exists():
        parser.error('fresh preflight state required; existing PF record refused')
    projection = harness._validate_projection_file(args.projection, harness.PROFILE_NAME, args.control_sha)
    root = state.parent / 'registry-rehearsal'
    root.mkdir(mode=0o755)
    root.chmod(0o711)
    paths = {name: root / name for name in ('project', 'prepared', 'cache', 'home', 'tmp')}
    for path in paths.values():
        path.mkdir(mode=0o700)
    project = paths['project']
    (project / 'package.json').write_bytes(harness.bundle.canonical_json(projection['npm_package']) + b'\n')
    (project / 'package-lock.json').write_bytes(harness.bundle.canonical_json(projection['npm_lock']) + b'\n')
    (project / '.npmrc').write_text('ignore-scripts=true\naudit=false\nfund=false\nregistry=https://registry.npmjs.org/\n')
    script = project / 'probe.cjs'
    shutil.copyfile(Path(__file__).with_name('registry_rehearsal.cjs'), script)
    for path in paths.values():
        harness._chown_tree(path, ident['uid'], ident['gid'])
    pins = harness._resolve_registry()


    reachable = []
    for address in pins:
        try:
            with socket.create_connection((address, 443), timeout=2):
                reachable.append(address)
                break
        except OSError:
            continue
    if not reachable:
        raise RuntimeError('registry-baseline-unreachable')
    with socket.create_connection(('1.1.1.1', 443), timeout=5):
        pass
    (root / 'inputs.json').write_text(json.dumps({
        'control_sha': args.control_sha, 'pins': pins, 'direct_control': reachable,
        'uid': ident['uid'], 'node_sha256': ident.get('node_sha256'),
        'sources': {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                    for name in ('macos_registry_rehearsal.py', 'registry_rehearsal.cjs',
                                 'registry_proxy.py', 'sandbox_macos.py')},
    }) + '\n')
    receipts = []
    responders = []
    def echo(sock):
        while True:
            try:
                data, peer = sock.recvfrom(4096)
                receipts.append(peer)
                sock.sendto(data, peer)
            except OSError:
                return
    try:
        for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
            udp = socket.socket(family, socket.SOCK_DGRAM)
            udp.bind((host, 53))
            responders.append(udp)
            threading.Thread(target=echo, args=(udp,), daemon=True).start()
            with socket.socket(family, socket.SOCK_DGRAM) as control:
                control.settimeout(2)
                control.sendto(b'baseline-dns', (host, 53))
                assert control.recv(4096) == b'baseline-dns'
        other = socket.socket()
        other.bind(('127.0.0.1', 0))
        other.listen(16)
        responders.append(other)
        with socket.create_connection(other.getsockname(), timeout=2):
            accepted, _ = other.accept()
            accepted.close()
        other6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        other6.bind(('::1', 0))
        other6.listen(16)
        responders.append(other6)
        with socket.create_connection(('::1', other6.getsockname()[1]), timeout=2):
            accepted, _ = other6.accept()
            accepted.close()
        proxy = registry_proxy.RegistryProxy(root / 'proxy-private', pins)
        try:
            ca = root / 'proxy-ca.pem'
            ca.write_bytes(proxy.cert.read_bytes())
            ca.chmod(0o444)
            profile = root / 'preparation.sb'
            profile.write_text(harness.preparation_profile_text(
                project=project, prepared=paths['prepared'], cache=paths['cache'], home=paths['home'],
                temporary=paths['tmp'], node=ident['node'], npm_cli=ident['npm_cli'],
                proxy_port=proxy.port, proxy_ca=ca))
            profile.chmod(0o444)
            env = harness._preparation_env(ident, home=paths['home'], temporary=paths['tmp'],
                                           cache=paths['cache'], prepared=paths['prepared'])
            env.update(proxy.environment(ca))
            config = json.dumps({'proxy': proxy.port, 'other': other.getsockname()[1],
                                 'pins': reachable, 'ca': str(ca), 'other6': other6.getsockname()[1]})
            harness._install_pf(state, ident, proxy_port=proxy.port)
            guard, record = harness._pf_guard_from_file(state, ident)
            (root / 'loaded-proxy.pf').write_text('\n'.join(guard.rules) + '\n')
            before = len(receipts)
            def run(mode, confined=True):
                argv = [ident['node'], str(script), config, mode]
                with (root / (mode + '.log')).open('xb') as log:
                    timeout = min(180, harness.deadline_budget.remaining(args.deadline_file))
                    if confined:
                        code = harness._run_preparation_process(argv, ident=ident, profile=profile,
                                                                cwd=project, env=env, output=log, timeout=timeout)
                    else:
                        code = subprocess.run(argv, cwd=project, env=env, stdout=log, stderr=subprocess.STDOUT,
                                              stdin=subprocess.DEVNULL, close_fds=True, start_new_session=True,
                                              user=ident['uid'], group=ident['gid'], extra_groups=(),
                                              timeout=timeout).returncode
                    if code:
                        raise RuntimeError(mode + '-failed')

            run('pf-only', confined=False)
            run('combined')
            with (root / 'npm-ci.log').open('xb') as log:
                code = harness._run_preparation_process(harness._npm_preparation_command(ident), ident=ident,
                         profile=profile, cwd=project, env=env, output=log,
                         timeout=min(600, harness.deadline_budget.remaining(args.deadline_file)))
                if code or not (project / 'node_modules').is_dir():
                    raise RuntimeError('confined-npm-ci-failed')
            counters = guard.verify()
            (root / 'proxy-counters.json').write_text(json.dumps(counters) + '\n')

            held = HeldUpstream(proxy.upstream_context)
            proxy.upstream_context = held
            hold = subprocess.Popen(['/usr/bin/sandbox-exec', '-f', str(profile), ident['node'],
                                     str(script), config, 'hold'], cwd=project, env=env,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    close_fds=True, start_new_session=True, user=ident['uid'],
                                    group=ident['gid'], extra_groups=())
            try:
                with selectors.DefaultSelector() as select:
                    select.register(hold.stdout, selectors.EVENT_READ)
                    if not select.select(10) or hold.stdout.readline() != b'existing-tls=ready\n':
                        raise RuntimeError('existing-tls-control-failed')
                if not held.ready.wait(5) or held.stopped.is_set() or held.socket.fileno() < 0:
                    raise RuntimeError('upstream-exchange-control-failed')
                (root / 'upstream-exchange.log').write_text('upstream-tls=verified\nupstream-http=held-mid-request\n')
                cut_start = time.monotonic()
                proxy.close()
                if time.monotonic() - cut_start > 3:
                    raise RuntimeError('offline-cut-too-slow')
                if not held.stopped.is_set() or held.socket.fileno() != -1:
                    raise RuntimeError('upstream-exchange-cut-failed')
                with (root / 'upstream-exchange.log').open('a') as log:
                    log.write('upstream-socket=closed\n')
                stdout, stderr = hold.communicate(timeout=3)
                if hold.returncode or stdout != b'existing-tls=cut\n' or stderr:
                    raise RuntimeError('existing-tls-cut-failed')
                (root / 'existing-tls.log').write_bytes(b'existing-tls=ready\n' + stdout)
            finally:
                harness._terminate_worker_processes(ident['uid'])
            run('offline')
            if len(receipts) != before:
                raise RuntimeError('raw-dns-reached-responder')


            harness._terminate_worker_processes(ident['uid'])
            guard.close()
            Path(record['rules_file']).unlink()
            (state / harness.PF_STATE_FILE).unlink()
            harness._install_pf(state, ident)
            offline, _ = harness._pf_guard_from_file(state, ident)
            (root / 'loaded-offline.pf').write_text('\n'.join(offline.rules) + '\n')
            run('offline-pf', confined=False)
            if len(receipts) != before:
                raise RuntimeError('offline-dns-reached-responder')
            offline.verify()
            for listener in (other, other6):
                listener.settimeout(0.5)
                try:
                    unexpected, _ = listener.accept()
                except socket.timeout:
                    pass
                else:
                    unexpected.close()
                    raise RuntimeError('unrelated-port-reached-responder')
            (root / 'result.json').write_text(json.dumps({'result': 'passed', 'registry': 'success',
                'npm_ci': 'success', 'combined': 'passed', 'pf_only': 'passed',
                'offline_existing_tls': 'cut', 'offline_active_upstream': 'cut', 'offline_new_registry': 'denied',
                'raw_dns_receipts': 0}) + '\n')
            print('macos_registry_rehearsal=passed')
        finally:
            try:
                harness._terminate_worker_processes(ident['uid'])
            finally:
                proxy.close()

    finally:
        for sock in responders:
            sock.close()


if __name__ == '__main__':
    main()
