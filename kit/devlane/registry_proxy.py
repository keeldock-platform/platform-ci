"""Trusted, read-only npm registry gateway. Never forwards an opaque tunnel.

Worker input cannot select upstream DNS, address, SNI, Host or port. One HTTP
request per TLS connection avoids request smuggling and connection reuse ambiguity.
"""
import ipaddress
import socket
import socketserver
import ssl
import subprocess
import threading
import time
from pathlib import Path

HOST = 'registry.npmjs.org'
AUTHORITY = HOST + ':443'
HEADER_LIMIT = 32768


def headers(sock):
    data = bytearray()

    while not data.endswith(b'\r\n\r\n'):
        chunk = sock.recv(1)
        if not chunk or len(data) >= HEADER_LIMIT:
            raise ValueError('header-limit')
        data.extend(chunk)
    lines = bytes(data[:-4]).decode('ascii').split('\r\n')
    fields = {}
    for line in lines[1:]:
        key, value = line.split(':', 1)
        if not key or any(c not in 'abcdefghijklmnopqrstuvwxyz-' for c in key.lower()):
            raise ValueError('header-name')
        key = key.lower()
        if key in fields or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('header-value')
        fields[key] = value.strip()
    return lines[0], fields


def request(sock):
    line, fields = headers(sock)
    method, path, version = line.split(' ')
    if (method not in ('GET', 'HEAD') or version != 'HTTP/1.1'
            or not path.startswith('/') or path.startswith('//')
            or fields.get('host') not in (HOST, AUTHORITY)
            or any(ord(c) <= 32 or ord(c) >= 127 for c in path)
            or 'transfer-encoding' in fields or fields.get('content-length', '0') != '0'
            or 'upgrade' in fields):
        raise ValueError('registry-request-only')

    return (f'{method} {path} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n').encode('ascii')


class RegistryProxy:
    def __init__(self, directory, addresses):
        if not isinstance(addresses, (tuple, list)) or not 1 <= len(addresses) <= 32:
            raise ValueError('bounded-registry-pins-required')
        self.addresses = tuple(str(ipaddress.ip_address(a)) for a in addresses)
        if not self.addresses or any(not ipaddress.ip_address(a).is_global
                                     or ipaddress.ip_address(a).is_multicast
                                     or ipaddress.ip_address(a).is_reserved for a in self.addresses):
            raise ValueError('public-registry-pins-required')
        directory = Path(directory)
        directory.mkdir(mode=0o700)
        self.cert = directory / 'registry.pem'
        key = directory / 'registry.key'


        config = directory / 'openssl.cnf'
        config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\n[ext]\nsubjectAltName=DNS:' + HOST + '\nbasicConstraints=critical,CA:TRUE\n')
        subprocess.run(('/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(self.cert), '-days', '1',
                        '-subj', '/CN=' + HOST, '-config', str(config)),
                       check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        key.chmod(0o600)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(self.cert, key)
        def sni(sock, name, context):
            if name != HOST:
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        self.context.set_servername_callback(sni)
        self.upstream_context = ssl.create_default_context()
        self.slots = threading.BoundedSemaphore(16)
        self.active = set()
        self.stopping = False
        self.lock = threading.Lock()
        owner = self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                if not owner.slots.acquire(blocking=False):
                    return
                try:
                    owner.handle(self.request)
                finally:
                    owner.slots.release()
        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = False
            block_on_close = True
            allow_reuse_address = False
            request_queue_size = 16
        self.server = Server(('127.0.0.1', 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def environment(self, ca):
        return {"NPM_CONFIG_HTTPS_PROXY": "http://127.0.0.1:" + str(self.port),
                "HTTPS_PROXY": "http://127.0.0.1:" + str(self.port),
                "NPM_CONFIG_NOPROXY": "", "NO_PROXY": "",
                "NODE_EXTRA_CA_CERTS": str(ca)}

    def track(self, sock):
        with self.lock:
            if self.stopping:
                sock.close()
                raise OSError('proxy-stopped')
            self.active.add(sock)

    def handle(self, client):
        tls = None
        upstream = None
        try:
            self.track(client)
            client.settimeout(10)
            line, fields = headers(client)
            if (line != 'CONNECT ' + AUTHORITY + ' HTTP/1.1'
                    or fields.get('host') != AUTHORITY
                    or 'transfer-encoding' in fields or fields.get('content-length', '0') != '0'):
                raise ValueError('registry-connect-only')
            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            with self.context.wrap_socket(client, server_side=True, do_handshake_on_connect=False) as tls:
                self.track(tls)
                tls.do_handshake()
                payload = request(tls)
                upstream = None
                for address in self.addresses:
                    if self.stopping:
                        raise OSError('proxy-stopped')
                    try:
                        raw = socket.create_connection((address, 443), timeout=10)
                        try:
                            upstream = self.upstream_context.wrap_socket(raw, server_hostname=HOST)
                        except BaseException:
                            raw.close()
                            raise
                        break
                    except OSError:
                        continue
                if upstream is None:
                    raise OSError('registry-unreachable')
                self.track(upstream)
                with upstream:
                    end = time.monotonic() + 60
                    upstream.sendall(payload)
                    while True:
                        if time.monotonic() > end:
                            raise OSError('response-deadline')
                        data = upstream.recv(65536)
                        if not data:
                            break
                        tls.sendall(data)
        except (OSError, ValueError, UnicodeError):
            pass

        finally:
            with self.lock:
                for sock in (client, tls, upstream):
                    self.active.discard(sock)

    def close(self):
        with self.lock:
            if self.stopping:
                return
            self.stopping = True
        self.server.shutdown()
        with self.lock:
            for sock in self.active:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
        self.server.server_close()
        self.thread.join(timeout=2)
        (self.cert.parent / "registry.key").unlink(missing_ok=True)
