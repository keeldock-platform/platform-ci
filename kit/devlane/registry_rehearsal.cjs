"use strict";
// Run only by macos_registry_rehearsal.py, under the preflight worker UID.
const net = require('node:net'), tls = require('node:tls'), fs = require('node:fs');
const dgram = require('node:dgram'), assert = require('node:assert/strict');
const c = JSON.parse(process.argv[2]), mode = process.argv[3];
function tcp(host, port) {
  return new Promise((resolve, reject) => {
    const s = net.connect({host, port});
    s.setTimeout(1200, () => s.destroy(new Error('timeout')));
    s.once('connect', () => resolve(s)); s.once('error', reject);
  });
}
async function tunnel(authority = 'registry.npmjs.org:443', name = 'registry.npmjs.org') {
  const s = await tcp('127.0.0.1', c.proxy);
  await new Promise((resolve, reject) => {
    let data = '';
    function read(chunk) {
      data += chunk.toString('ascii');
      if (data.includes('\r\n\r\n')) {
        s.removeListener('data', read);
        data.startsWith('HTTP/1.1 200 ') ? resolve() : reject(new Error('CONNECT denied'));
      }
    }
    s.on('data', read); s.once('error', reject); s.once('close', () => reject(new Error('closed')));
    s.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
  });
  return new Promise((resolve, reject) => {
    const t = tls.connect({socket:s, servername:name, ca:fs.readFileSync(c.ca), rejectUnauthorized:name === 'registry.npmjs.org'}, () => {t.setTimeout(10000); resolve(t);});
    t.once('error', reject);
  });
}
async function get(host = 'registry.npmjs.org') {
  const t = await tunnel();
  return new Promise((resolve, reject) => {
    let data = '';
    t.on('data', b => data += b.toString('ascii'));
    t.once('error', reject);
    t.once('close', () => data.startsWith('HTTP/1.1 200 ') ? resolve() : reject(new Error('HTTP denied')));
    t.write(`GET /-/ping HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
  });
}
async function denied(label, action) {
  try { const s = await action(); if (s && s.destroy) s.destroy(); }
  catch (_) { console.log(label + '=denied'); return; }
  throw new Error(label + ' unexpectedly allowed');
}
function dns(host, family) {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket(family);
    let done = false;
    const timer = setTimeout(() => finish(new Error('DNS denied')), 700);
    function finish(error) {
      if (done) return; done = true;
      clearTimeout(timer); s.close(); error ? reject(error) : resolve();
    }
    s.once('error', finish); s.once('message', () => finish());
    // Valid registry.npmjs.org A query, deterministic ID.
    s.send(Buffer.from('123401000001000000000000087265676973747279056e706d6a73036f72670000010001','hex'), 53, host,
      e => {if(e) finish(e);});
  });
}
(async () => {
  if (mode === 'hold') {
    const t = await tunnel();
    t.write('GET /-/ping HTTP/1.1\r\nHost: registry.npmjs.org\r\nConnection: close\r\n\r\n');
    console.log('existing-tls=ready');
    await new Promise((resolve, reject) => {
      t.once('close', resolve); t.once('error', resolve);
      setTimeout(() => {t.destroy(); reject(new Error('offline cut missing'));}, 15000).unref();
    });
    console.log('existing-tls=cut'); return;
  }
  if (mode === 'combined') { await get(); console.log('registry=success'); }
  if (mode.startsWith('offline')) await denied('registry-offline', () => get());
  for (const ip of c.pins) {
    // Fail on TCP connect, even if the TLS peer later rejects the wrong SNI.
    await denied('direct-pinned-ip-other-SNI-Host-' + ip, () => new Promise((resolve, reject) => {
      const t = tls.connect({host:ip, port:443, servername:'example.com', rejectUnauthorized:false});
      t.setTimeout(1200, () => t.destroy(new Error('timeout')));
      t.once('secureConnect', () => t.write('GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'));
      t.once('connect', () => resolve(t)); t.once('error', reject);
    }));
  }
  await denied('unrelated-ip', () => tcp('1.1.1.1',443));
  await denied('unrelated-port', () => tcp('127.0.0.1',c.other));
  await denied('unrelated-port-ipv6', () => tcp('::1',c.other6));
  for (const [ip, family] of [['127.0.0.1','udp4'],['::1','udp6']])
    await denied('raw-dns-' + family, () => dns(ip,family));
  if (mode !== 'pf-only' && !mode.startsWith('offline')) {
    await denied('CONNECT-ip', () => tunnel(c.pins[0] + ':443'));
    await denied('CONNECT-other-host', () => tunnel('example.com:443'));
    await denied('CONNECT-other-port', () => tunnel('registry.npmjs.org:80'));
    await denied('other-SNI', () => tunnel(undefined, 'example.com'));
    await denied('other-Host', () => get('example.com'));
  }
  console.log(mode + '=passed');
})().catch(e => {console.error(e.message); process.exitCode = 1;});
