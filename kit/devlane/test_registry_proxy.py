"""Hermetic CONNECT/TLS tests: both TLS legs use loopback and test CAs."""
import concurrent.futures
import os
import json
import selectors
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import registry_proxy as proxy


class FakeRegistry:
    """A separate TLS peer for every CONNECT, including concurrent npm requests."""
    def __init__(self, directory):
        directory.mkdir()
        self.cert = directory / 'ca.pem'
        key = directory / 'key.pem'
        config = directory / 'openssl.cnf'
        config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\n'
                          '[dn]\n[ext]\nsubjectAltName=DNS:' + proxy.HOST + '\n'
                          'basicConstraints=critical,CA:TRUE\n')
        subprocess.run(('/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(self.cert), '-days', '1',
                        '-subj', '/CN=unit-test-registry', '-config', str(config)),
                       check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, key)
        self.names = []
        context.set_servername_callback(lambda sock, name, ctx: self.names.append(name))
        self.received = []
        self.errors = []
        self.prefix_ready = threading.Event()
        self.cut = threading.Event()
        self.release = threading.Event()
        self.respond = True
        self.abrupt = False
        self.body = b'{}'
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.settimeout(3)
                    with context.wrap_socket(self.request, server_side=True) as tls:
                        data = bytearray()
                        while not data.endswith(b'\r\n\r\n'):
                            chunk = tls.recv(1)
                            if not chunk:
                                owner.cut.set()
                                return
                            data.extend(chunk)
                            if data.endswith(b'Connection: close\r\n'):
                                owner.prefix_ready.set()
                        owner.received.append(bytes(data))
                        if not owner.respond:
                            owner.release.wait(3)
                            return
                        body = owner.body
                        head = (b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                                + f'Content-Length: {len(body)}\r\n'.encode()
                                + b'Connection: close\r\n\r\n')
                        tls.sendall(head + body)
                        if not owner.abrupt:
                            tls.unwrap().close()
                except (OSError, ValueError) as error:
                    owner.errors.append(error)

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = False
            block_on_close = True
            request_queue_size = 16
        self.server = Server(('127.0.0.1', 0), Handler)
        self.address = self.server.server_address
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)


class RegistryProxyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.upstream = FakeRegistry(Path(self.temp.name) / 'upstream')
        self.addCleanup(self.upstream.close)
        self.gateway = proxy.RegistryProxy(Path(self.temp.name) / 'private', ['104.16.24.34'])
        self.addCleanup(self.gateway.close)
        self.gateway.upstream_context = ssl.create_default_context(cafile=str(self.upstream.cert))
        self.context = ssl.create_default_context(cafile=str(self.gateway.cert))
        real_connect = socket.create_connection

        def loopback_only(address, *args, **kwargs):
            if address == ('104.16.24.34', 443):
                return real_connect(self.upstream.address, *args, **kwargs)
            if address == ('127.0.0.1', self.gateway.port):
                return real_connect(address, *args, **kwargs)
            raise AssertionError(f'non-hermetic connection: {address!r}')

        patch = mock.patch.object(proxy.socket, 'create_connection', side_effect=loopback_only)
        self.dial = patch.start()
        self.addCleanup(patch.stop)
        self.addCleanup(self.gateway.close)

    def receive(self, payload=b'GET /-/ping HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n'):
        with self.tls() as tls:
            tls.sendall(payload)
            data = bytearray()
            while chunk := tls.recv(65536):
                data.extend(chunk)
            return bytes(data)

    def connect(self, authority=proxy.AUTHORITY):
        sock = socket.create_connection(('127.0.0.1', self.gateway.port), timeout=3)
        sock.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode())
        return sock

    def tls(self, name=proxy.HOST):
        sock = self.connect()
        self.assertEqual(proxy.headers(sock)[0], 'HTTP/1.1 200 Connection Established')
        try:
            self.context.check_hostname = name == proxy.HOST
            return self.context.wrap_socket(sock, server_hostname=name)
        except BaseException:
            sock.close()
            raise

    def test_unrelated_host_port_and_ip_connect_refused_before_upstream(self):
        with mock.patch.object(self.gateway.upstream_context, 'wrap_socket') as upstream:
            for authority in ('example.com:443', '104.16.24.34:443', proxy.HOST + ':80',
                              proxy.HOST + ':53', '127.0.0.1:443'):
                with self.subTest(authority=authority), self.connect(authority) as sock:
                    self.assertEqual(sock.recv(1), b'')
            upstream.assert_not_called()

    def test_raw_dns_and_non_connect_protocols_are_not_forwarded(self):
        with mock.patch.object(self.gateway.upstream_context, 'wrap_socket') as upstream:
            for payload in (b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n',
                            bytes.fromhex('123401000001000000000000')):
                with socket.create_connection(('127.0.0.1', self.gateway.port), timeout=3) as sock:
                    sock.sendall(payload)
                    sock.shutdown(socket.SHUT_WR)
                    self.assertEqual(sock.recv(1), b'')
            upstream.assert_not_called()

    def test_other_or_absent_sni_refused(self):
        with mock.patch.object(self.gateway.upstream_context, 'wrap_socket') as upstream:
            for name in ('example.com', '104.16.24.34', None):
                with self.subTest(name=name), self.assertRaises(ssl.SSLError):
                    self.tls(name)
            upstream.assert_not_called()

    def test_wrong_host_and_smuggling_refused_before_upstream(self):
        requests = [
            b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
            b'GET / HTTP/1.1\r\nHost: 104.16.24.34\r\n\r\n',
            b'GET https://example.com/ HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n',
            b'GET / HTTP/1.1\r\nHost: registry.npmjs.org\r\nHost: example.com\r\n\r\n',
            b'GET / HTTP/1.1\r\nHost: registry.npmjs.org\r\nTransfer-Encoding: chunked\r\n\r\n',
            b'POST / HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n',
        ]
        with mock.patch.object(self.gateway.upstream_context, 'wrap_socket') as upstream:
            for payload in requests:
                with self.subTest(payload=payload), self.tls() as tls:
                    tls.sendall(payload)
                    self.assertEqual(tls.recv(1), b'')
            upstream.assert_not_called()

    def test_get_uses_only_pinned_ip_and_verified_registry_sni(self):
        data = self.receive(b'GET /-/ping HTTP/1.1\r\nHost: registry.npmjs.org\r\nAuthorization: secret\r\n\r\n')
        self.assertTrue(data.endswith(b'\r\n\r\n{}'))
        self.dial.assert_any_call(('104.16.24.34', 443), timeout=10)
        self.assertEqual(self.upstream.names, [proxy.HOST])
        self.assertEqual(self.upstream.received, [
            b'GET /-/ping HTTP/1.1\r\nHost: registry.npmjs.org\r\nConnection: close\r\n\r\n'])
        self.assertTrue(self.gateway.upstream_context.check_hostname)
        self.assertEqual(self.gateway.upstream_context.verify_mode, ssl.CERT_REQUIRED)

    def test_untrusted_upstream_certificate_is_refused(self):
        self.gateway.upstream_context = ssl.create_default_context(cafile=str(self.gateway.cert))
        self.assertEqual(self.receive(), b'')
        self.assertEqual(self.upstream.received, [])

    def test_concurrent_connects_have_independent_upstream_tls(self):
        barrier = threading.Barrier(8)
        def get(index):
            barrier.wait(3)
            payload = f'GET /test-{index} HTTP/1.1\r\nHost: {proxy.HOST}\r\n\r\n'.encode()
            return self.receive(payload)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(get, range(8)))
        self.assertTrue(all(data.endswith(b'\r\n\r\n{}') for data in responses))
        self.assertEqual(len(self.upstream.names), 8)
        self.assertEqual({request.split(b'\r\n')[0] for request in self.upstream.received},
                         {f'GET /test-{i} HTTP/1.1'.encode() for i in range(8)})

    def test_upstream_tls_shutdown_and_tcp_half_close_deliver_full_body(self):
        self.upstream.body = b'x' * (256 * 1024)
        for abrupt in (False, True):
            with self.subTest(abrupt=abrupt):
                self.upstream.abrupt = abrupt
                data = self.receive()
                self.assertEqual(data.split(b'\r\n\r\n', 1)[1], self.upstream.body)

    def test_stalled_upstream_read_times_out_without_hanging_worker(self):
        self.upstream.respond = False
        wrap = self.gateway.upstream_context.wrap_socket
        def short_timeout(*args, **kwargs):
            sock = wrap(*args, **kwargs)
            sock.settimeout(0.2)
            return sock
        started = time.monotonic()
        with mock.patch.object(self.gateway.upstream_context, 'wrap_socket', side_effect=short_timeout):
            self.assertEqual(self.receive(), b'')
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(len(self.upstream.received), 1)
        self.upstream.release.set()

    @unittest.skipUnless(shutil.which('npm'), 'npm required')
    def test_real_npm_ping_uses_local_tls_upstream_without_worker_dns(self):
        env = {'PATH': os.environ['PATH'], 'HOME': self.temp.name,
               'NPM_CONFIG_CACHE': self.temp.name + '/cache', 'NPM_CONFIG_UPDATE_NOTIFIER': 'false',
               **self.gateway.environment(self.gateway.cert)}
        result = subprocess.run([shutil.which('npm'), 'ping', '--registry=https://registry.npmjs.org/',
                                 '--fetch-retries=0', '--fetch-timeout=5000'],
                                cwd=self.temp.name, env=env, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(len(self.upstream.received), 1)
        self.assertTrue(self.upstream.received[0].startswith(b'GET /-/ping'))

    @unittest.skipUnless(shutil.which('node'), 'node required')
    def test_rehearsal_holds_real_upstream_exchange_across_shutdown(self):
        from macos_registry_rehearsal import HeldUpstream
        held = HeldUpstream(self.gateway.upstream_context)
        self.gateway.upstream_context = held
        config = json.dumps({'proxy': self.gateway.port, 'ca': str(self.gateway.cert)})
        worker = subprocess.Popen([shutil.which('node'),
            str(Path(__file__).with_name('registry_rehearsal.cjs')), config, 'hold'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as select:
                select.register(worker.stdout, selectors.EVENT_READ)
                self.assertTrue(select.select(5), 'worker readiness timeout')
                self.assertEqual(worker.stdout.readline(), b'existing-tls=ready\n')
            self.assertTrue(held.ready.wait(3), 'no upstream request')
            self.assertTrue(self.upstream.prefix_ready.wait(3), 'upstream did not receive partial header')
            self.assertEqual(self.upstream.received, [])
            self.assertFalse(held.stopped.is_set())
            self.assertNotEqual(held.socket.fileno(), -1)
            self.assertIsNone(worker.poll())
            started = time.monotonic()
            self.gateway.close()
            self.assertLess(time.monotonic() - started, 3)
            self.assertTrue(held.stopped.is_set())
            self.assertEqual(held.socket.fileno(), -1)
            self.assertTrue(self.upstream.cut.wait(3))
            stdout, stderr = worker.communicate(timeout=3)
            self.assertEqual((worker.returncode, stdout, stderr), (0, b'existing-tls=cut\n', b''))
            with self.assertRaises(OSError):
                socket.create_connection(('127.0.0.1', self.gateway.port), timeout=1)
        finally:
            self.gateway.close()
            if worker.poll() is None:
                worker.kill()
            worker.communicate(timeout=3)

    def test_close_cuts_existing_tls_and_new_connections(self):
        tls = self.tls()
        self.gateway.close()
        self.assertEqual(tls.recv(1), b'')
        tls.close()
        with self.assertRaises(OSError):
            self.connect()


if __name__ == '__main__':
    unittest.main()
