import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import {
  closeSync,
  fstatSync,
  mkdtempSync,
  openSync,
  realpathSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { encryptDevelopmentFeedback } from './development_feedback.mjs';
import { RETURN_PROFILES } from './node_lock_envelope.mjs';
import { handleRequest } from './feedback_admin_crypto.mjs';

const NOW = 1_800_000_000;
const POSIX_OWNER_FILESYSTEM = process.platform !== 'win32' && typeof process.getuid === 'function';
const lockExpectation = {
  root: {
    name: 'fixture-root',
    version: '1.0.0',
    workspaces: ['packages/*'],
    devDependencies: { typescript: '6.0.3' },
  },
  workspaces: [{
    path: 'packages/client-api',
    name: '@fixture/client-api',
    version: '1.0.0',
    dependencies: { '@fixture/shared': '1.0.0' },
  }, { path: 'packages/shared', name: '@fixture/shared', version: '1.0.0' }],
};

function lockBytes() {
  return Buffer.from(`${JSON.stringify({
    name: 'fixture-root',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': {
        name: 'fixture-root', version: '1.0.0', workspaces: ['packages/*'],
        devDependencies: { typescript: '6.0.3' },
      },
      'packages/client-api': {
        name: '@fixture/client-api', version: '1.0.0',
        dependencies: { '@fixture/shared': '1.0.0' },
      },
      'packages/shared': { name: '@fixture/shared', version: '1.0.0' },
      'node_modules/@fixture/client-api': { resolved: 'packages/client-api', link: true },
      'node_modules/@fixture/shared': { resolved: 'packages/shared', link: true },
      'node_modules/typescript': {
        version: '6.0.3',
        resolved: 'https://registry.npmjs.org/typescript/-/typescript-6.0.3.tgz',
        integrity: `sha512-${'A'.repeat(86)}==`,
      },
    },
  })}\n`, 'utf8');
}

function makeContext(fingerprint) {
  const profile = RETURN_PROFILES['core-node-lock-return'];
  return {
    request_id: '1'.repeat(64),
    nonce: '2'.repeat(64),
    recipient_fingerprint: fingerprint,
    concern: profile.concern,
    repository_id: '1430959909',
    source_sha: 'd'.repeat(40),
    base_sha: 'e'.repeat(40),
    control_sha: 'f'.repeat(40),
    base_branch: 'develop',
    reviewed_diff_sha256: 'a'.repeat(64),
    workflow_ref: 'refs/heads/main',
    run_id: '24680',
    producer_job: profile.producerJob,
    run_attempt: 1,
    expiry: NOW + 3600,
  };
}

async function setup() {
  const directory = mkdtempSync(join(realpathSync(tmpdir()), 'feedback-admin-'));
  const keyPath = join(directory, `key-${'2'.repeat(64)}.der`);
  const keyInfo = await handleRequest({ operation: 'keygen', private_key_path: keyPath });
  const publicKey = createPublicKey({
    key: Buffer.from(keyInfo.public_spki_base64, 'base64'), format: 'der', type: 'spki',
  });
  return { directory, keyPath, keyInfo, publicKey, context: makeContext(keyInfo.recipient_fingerprint) };
}

function encryptFixture(context, publicKey) {
  return encryptDevelopmentFeedback({
    payloadBytes: lockBytes(),
    context,
    recipientPublicKey: publicKey,
    expectedManifest: lockExpectation,
    now: NOW,
  });
}

async function decryptFixture(state, envelope, overrides = {}) {
  const outputPath = join(state.directory, `output-${Math.random().toString(16).slice(2)}.payload`);
  const fd = openSync(outputPath, 'wx', 0o600);
  try {
    const result = await handleRequest({
      operation: 'decrypt',
      private_key_path: overrides.privateKeyPath ?? state.keyPath,
      context: overrides.context ?? state.context,
      now: overrides.now ?? NOW,
      envelope_base64: Buffer.from(envelope).toString('base64'),
      plaintext_fd: fd,
      expected_manifest: lockExpectation,
    });
    return { result, outputPath };
  } finally {
    closeSync(fd);
  }
}

test('creates a private one-use key file and exposes only public metadata',
  { skip: !POSIX_OWNER_FILESYSTEM }, async (t) => {
  const state = await setup();
  t.after(() => rmSync(state.directory, { recursive: true, force: true }));
  const fd = openSync(state.keyPath, 'r');
  const info = fstatSync(fd);
  closeSync(fd);
  assert.equal(info.isFile(), true);
  assert.equal(info.nlink, 1);
  assert.equal(info.mode & 0o777, 0o400);
  assert.equal(state.keyInfo.modulus_length, 3072);
  assert.equal(state.keyInfo.public_exponent, '65537');
  assert.equal(Object.hasOwn(state.keyInfo, 'private_key'), false);
});

test('decrypts only an authenticated payload matching the exact context',
  { skip: !POSIX_OWNER_FILESYSTEM }, async (t) => {
  const state = await setup();
  t.after(() => rmSync(state.directory, { recursive: true, force: true }));
  const envelope = encryptFixture(state.context, state.publicKey);
  const { result, outputPath } = await decryptFixture(state, envelope);
  assert.deepEqual(result, { schema_version: 1, ok: true });
  assert.deepEqual(readFileSync(outputPath), lockBytes());
});

test('rejects truncated, modified, expired, or context-mismatched ciphertext',
  { skip: !POSIX_OWNER_FILESYSTEM }, async (t) => {
  const state = await setup();
  t.after(() => rmSync(state.directory, { recursive: true, force: true }));
  const envelope = encryptFixture(state.context, state.publicKey);
  const tampered = Buffer.from(envelope);
  tampered[tampered.length - 1] ^= 1;
  const wrongContext = { ...state.context, source_sha: 'c'.repeat(40) };
  for (const [candidate, overrides] of [
    [envelope.subarray(0, envelope.length - 1), {}],
    [tampered, {}],
    [envelope, { context: wrongContext }],
    [envelope, { now: state.context.expiry }],
  ]) {
    await assert.rejects(() => decryptFixture(state, candidate, overrides));
  }
});

test('rejects a different recipient key, a symbolic link, and oversized envelopes',
  { skip: !POSIX_OWNER_FILESYSTEM }, async (t) => {
  const state = await setup();
  t.after(() => rmSync(state.directory, { recursive: true, force: true }));
  const envelope = encryptFixture(state.context, state.publicKey);
  const otherPath = join(state.directory, `key-${'3'.repeat(64)}.der`);
  await handleRequest({ operation: 'keygen', private_key_path: otherPath });
  await assert.rejects(() => decryptFixture(state, envelope, { privateKeyPath: otherPath }));
  // The expected key name is fixed by the request nonce; a link cannot replace it.
  rmSync(state.keyPath);
  const replacement = join(state.directory, `key-${'5'.repeat(64)}.der`);
  await handleRequest({ operation: 'keygen', private_key_path: replacement });
  const aliasPath = join(state.directory, `key-${'6'.repeat(64)}.der`);
  symlinkSync(replacement, aliasPath);
  await assert.rejects(() => handleRequest({
    operation: 'decrypt', private_key_path: aliasPath, context: state.context,
    now: NOW, envelope_base64: Buffer.from(envelope).toString('base64'), plaintext_fd: 3,
  }));
  await assert.rejects(() => handleRequest({
    operation: 'decrypt', private_key_path: otherPath, context: state.context,
    now: NOW, envelope_base64: Buffer.alloc((4 * 1024 * 1024) + 1).toString('base64'), plaintext_fd: 3,
  }));
});

test('refuses hosts without POSIX owner and no-follow filesystem semantics',
  { skip: POSIX_OWNER_FILESYSTEM }, async () => {
    await assert.rejects(() => handleRequest({
      operation: 'keygen', private_key_path: join(tmpdir(), 'synthetic-key.der'),
    }));
  });
