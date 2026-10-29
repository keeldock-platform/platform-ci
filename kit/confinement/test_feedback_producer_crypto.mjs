import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { encryptFeedbackPayload } from './feedback_producer_crypto.mjs';

const NOW = 1_798_000_000;
const SOURCE_SHA = 'a'.repeat(40);
const BASE_SHA = 'b'.repeat(40);
const CONTROL_SHA = 'c'.repeat(40);
const DIFF_SHA = 'd'.repeat(64);
const REQUEST_ID = 'e'.repeat(64);
const NONCE = 'f'.repeat(64);
const CRYPTO_SCRIPT = fileURLToPath(new URL('./feedback_producer_crypto.mjs', import.meta.url));

function fixture(kind = 'build_diagnostics') {
  const pair = generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 65537 });
  const der = pair.publicKey.export({ format: 'der', type: 'spki' });
  const fingerprint = createHash('sha256').update(der).digest('hex');
  const profiles = {
    lock: { concern: 'core-node-lock-return', producerJob: 'node-lock-return' },
    rust_patch: { concern: 'core-rust-format-return', producerJob: 'core-rust-format-return' },
    build_diagnostics: {
      concern: 'core-build-diagnostic-return', producerJob: 'core-build-diagnostic-return',
    },
    cargo_lock: { concern: 'core-rust-lock-return', producerJob: 'core-rust-lock-return' },
  };
  const profile = profiles[kind];
  const context = {
    request_id: REQUEST_ID,
    nonce: NONCE,
    recipient_fingerprint: fingerprint,
    concern: profile.concern,
    repository_id: '67890',
    source_sha: SOURCE_SHA,
    base_sha: BASE_SHA,
    control_sha: CONTROL_SHA,
    base_branch: 'develop',
    reviewed_diff_sha256: DIFF_SHA,
    workflow_ref: 'refs/heads/main',
    run_id: '12345',
    producer_job: profile.producerJob,
    run_attempt: 1,
    expiry: NOW + 3600,
  };
  if (kind !== 'lock') context.kind = kind;
  let payload;
  const input = {
    schema_version: 1,
    kind,
    context,
    recipient_spki_b64: Buffer.from(der).toString('base64'),
    now: NOW,
  };
  if (kind === 'lock') {
    payload = Buffer.from(JSON.stringify({
      name: 'synthetic-root',
      version: '1.0.0',
      lockfileVersion: 3,
      requires: true,
      packages: {
        '': { name: 'synthetic-root', version: '1.0.0', workspaces: ['packages/*'] },
        'packages/host-api': { name: '@synthetic/host-api', version: '1.0.0' },
      },
    }));
    input.expected_manifest = {
      root: { name: 'synthetic-root', version: '1.0.0', workspaces: ['packages/*'] },
      workspaces: [{ path: 'packages/host-api', name: '@synthetic/host-api', version: '1.0.0' }],
    };
  } else if (kind === 'rust_patch') {
    payload = Buffer.from('diff --git a/src/lib.rs b/src/lib.rs\n'
      + '--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n');
    input.reviewed_rust_paths = ['src/lib.rs'];
  } else if (kind === 'cargo_lock') {
    payload = Buffer.from(JSON.stringify({
      evidence_b64: Buffer.from('{"schema_version":1}', 'ascii').toString('base64'),
      lock_b64: Buffer.from('version = 4\n', 'ascii').toString('base64'),
      receipt_b64: Buffer.from('{"schema_version":1}', 'ascii').toString('base64'),
      schema_version: 1,
    }));
  } else {
    payload = Buffer.from('bounded synthetic diagnostic\n');
  }
  input.payload_b64 = payload.toString('base64');
  return { pair, der: Buffer.from(der).toString('base64'), context, input };
}

test('producer encrypts only a profile-bound bounded payload', () => {
  const value = fixture();
  const ciphertext = encryptFeedbackPayload(value.input);
  assert.ok(Buffer.isBuffer(ciphertext));
  assert.ok(ciphertext.length > 0 && ciphertext.length <= 4 * 1024 * 1024);
  assert.equal(ciphertext.subarray(0, 4).toString('ascii'), 'KDLE');
  assert.equal(ciphertext.includes(Buffer.from('bounded synthetic diagnostic')), false);
});

test('producer validates lock and reviewed Rust patch profiles before encryption', () => {
  const lock = fixture('lock');
  const lockCiphertext = encryptFeedbackPayload(lock.input);
  assert.equal(lockCiphertext[5], 1);
  assert.equal(lockCiphertext.includes(Buffer.from('synthetic-root')), false);

  const patch = fixture('rust_patch');
  const patchCiphertext = encryptFeedbackPayload(patch.input);
  assert.equal(patchCiphertext[5], 2);
  assert.equal(patchCiphertext.includes(Buffer.from('src/lib.rs')), false);
});

function sizedRustPatch(totalBytes) {
  const width = 4000;
  const prefix = [
    'diff --git a/src/lib.rs b/src/lib.rs',
    '--- a/src/lib.rs',
    '+++ b/src/lib.rs',
    '',
  ].join('\n');
  const pairs = Math.floor((totalBytes - 512) / (2 * (width + 2)));
  const header = `@@ -1,${pairs} +1,${pairs} @@\n`;
  const extra = totalBytes - prefix.length - header.length - pairs * 2 * (width + 2);
  const removed = Array.from({ length: pairs }, () => `-${'x'.repeat(width)}\n`).join('');
  const added = Array.from({ length: pairs },
    (_, index) => `+${'y'.repeat(index === pairs - 1 ? width + extra : width)}\n`).join('');
  const patch = Buffer.from(prefix + header + removed + added, 'ascii');
  assert.equal(patch.length, totalBytes);
  return patch;
}

test('producer encrypts a Rust patch of exactly the byte limit and refuses one byte more', () => {
  const limit = 4 * 1024 * 1024 - 64 * 1024;
  const atLimit = fixture('rust_patch');
  atLimit.input.payload_b64 = sizedRustPatch(limit).toString('base64');
  const ciphertext = encryptFeedbackPayload(atLimit.input);
  assert.equal(ciphertext[5], 2);
  assert.ok(ciphertext.length <= 4 * 1024 * 1024);

  const over = fixture('rust_patch');
  over.input.payload_b64 = sizedRustPatch(limit + 1).toString('base64');
  assert.throws(() => encryptFeedbackPayload(over.input));
});

test('producer base64 shape check refuses malformed padding, length, alphabet, and whitespace', () => {
  for (const bad of ['eA=', 'eA=A', '=eA=', 'e===', 'eA==\n', 'eA== ', 'e_==', 'eB==', 'eA']) {
    const input = fixture('rust_patch').input;
    input.payload_b64 = bad;
    assert.throws(() => encryptFeedbackPayload(input), { code: 'invalid_payload' }, bad);
  }
});

test('producer refuses a mismatched key, profile, and unclosed input shape', () => {
  const wrongKey = fixture();
  wrongKey.input.context.recipient_fingerprint = '0'.repeat(64);
  assert.throws(() => encryptFeedbackPayload(wrongKey.input));

  const wrongProfile = fixture();
  wrongProfile.input.kind = 'rust_patch';
  assert.throws(() => encryptFeedbackPayload(wrongProfile.input));

  const extraField = fixture();
  extraField.input.output_path = '/tmp/unchecked';
  assert.throws(() => encryptFeedbackPayload(extraField.input));
});

test('CLI asynchronously reads bounded stdin and emits only ciphertext or a generic refusal', () => {
  const value = fixture();
  const validInput = Buffer.from(JSON.stringify(value.input), 'utf8');
  const positive = spawnSync(process.execPath, [CRYPTO_SCRIPT], {
    input: validInput,
    timeout: 15_000,
    maxBuffer: 4 * 1024 * 1024 + 1024,
    env: { PATH: process.env.PATH ?? '', LANG: 'C', LC_ALL: 'C' },
  });
  assert.equal(positive.error, undefined);
  assert.equal(positive.status, 0);
  assert.equal(positive.stderr.length, 0);
  assert.equal(positive.stdout.subarray(0, 4).toString('ascii'), 'KDLE');
  assert.equal(positive.stdout.includes(Buffer.from('bounded synthetic diagnostic')), false);

  const oversized = spawnSync(process.execPath, [CRYPTO_SCRIPT], {
    input: Buffer.alloc(6 * 1024 * 1024 + 1, 0x41),
    timeout: 15_000,
    maxBuffer: 4 * 1024 * 1024 + 1024,
    env: { PATH: process.env.PATH ?? '', LANG: 'C', LC_ALL: 'C' },
  });
  assert.equal(oversized.error, undefined);
  assert.equal(oversized.status, 1);
  assert.equal(oversized.stdout.length, 0);
  assert.deepEqual(oversized.stderr, Buffer.from('KD-FEEDBACK-ENCRYPTION-REFUSAL\n'));
});

test('producer encrypts a cargo lock bundle under its own profile and refuses expectations', () => {
  const value = fixture('cargo_lock');
  const ciphertext = encryptFeedbackPayload(value.input);
  assert.equal(ciphertext[5], 4);
  assert.equal(ciphertext.includes(Buffer.from('version = 4')), false);

  const withManifest = fixture('cargo_lock');
  withManifest.input.expected_manifest = { root: {}, workspaces: [] };
  assert.throws(() => encryptFeedbackPayload(withManifest.input));

  const withPaths = fixture('cargo_lock');
  withPaths.input.reviewed_rust_paths = ['src/lib.rs'];
  assert.throws(() => encryptFeedbackPayload(withPaths.input));

  const oversized = fixture('cargo_lock');
  oversized.input.payload_b64 = Buffer.alloc(1024 * 1024 + 1, 0x20).toString('base64');
  assert.throws(() => encryptFeedbackPayload(oversized.input));

  const wrongKind = fixture('cargo_lock');
  wrongKind.input.kind = 'build_diagnostics';
  assert.throws(() => encryptFeedbackPayload(wrongKind.input));
});
