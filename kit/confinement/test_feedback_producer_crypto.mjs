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

const QUICK_BYTES = 4 * 1024 * 1024 - 64 * 1024;

function quickPayload(body = '{"gates":[],"tier":"quick"}', total = QUICK_BYTES) {
  const header = `KD-LINUX-QUICK-PAYLOAD 1 ${String(body.length).padStart(8, '0')}\n`;
  return Buffer.from(header + body + ' '.repeat(total - header.length - body.length), 'ascii');
}

function fixture(kind = 'build_diagnostics') {
  const pair = generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 65537 });
  const der = pair.publicKey.export({ format: 'der', type: 'spki' });
  const fingerprint = createHash('sha256').update(der).digest('hex');
  const profiles = {
    rust_patch: { concern: 'core-rust-format-return', producerJob: 'core-rust-format-return' },
    build_diagnostics: {
      concern: 'core-build-diagnostic-return', producerJob: 'core-build-diagnostic-return',
    },
    linux_quick: {
      concern: 'core-linux-quick-return', producerJob: 'core-linux-quick-return-producer',
      workflowRef: 'refs/heads/untrusted',
    },
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
    workflow_ref: profile.workflowRef ?? 'refs/heads/main',
    run_id: '12345',
    producer_job: profile.producerJob,
    run_attempt: 1,
    expiry: NOW + 3600,
  };
  context.kind = kind;
  let payload;
  const input = {
    schema_version: 1,
    kind,
    context,
    recipient_spki_b64: Buffer.from(der).toString('base64'),
    now: NOW,
  };
  if (kind === 'rust_patch') {
    payload = Buffer.from('diff --git a/src/lib.rs b/src/lib.rs\n'
      + '--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n');
    input.reviewed_rust_paths = ['src/lib.rs'];
  } else if (kind === 'linux_quick') {
    payload = quickPayload();
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

test('producer validates reviewed Rust patch profiles before encryption', () => {
  const patch = fixture('rust_patch');
  const patchCiphertext = encryptFeedbackPayload(patch.input);
  assert.equal(patchCiphertext[5], 2);
  assert.equal(patchCiphertext.includes(Buffer.from('src/lib.rs')), false);
});

test('producer validates captured Rust source bytes before exempting credential-shaped context', () => {
  const value = fixture('rust_patch');
  const original = 'let token=CancellationToken::new();\n';
  value.input.payload_b64 = Buffer.from([
    'diff --git a/src/lib.rs b/src/lib.rs',
    '--- a/src/lib.rs',
    '+++ b/src/lib.rs',
    '@@ -1,1 +1,1 @@',
    '-let token=CancellationToken::new();',
    '+let token = CancellationToken::new();',
    '',
  ].join('\n'), 'utf8').toString('base64');
  value.input.original_rust_files_b64 = [{
    path: 'src/lib.rs',
    content_b64: Buffer.from(original, 'utf8').toString('base64'),
  }];
  const ciphertext = encryptFeedbackPayload(value.input);
  assert.equal(ciphertext[5], 2);

  const changed = fixture('rust_patch');
  changed.input.payload_b64 = Buffer.from([
    'diff --git a/src/lib.rs b/src/lib.rs',
    '--- a/src/lib.rs',
    '+++ b/src/lib.rs',
    '@@ -1,1 +1,2 @@',
    ' fn run() {}',
    '+let token = "synthetic-secret-value";',
    '',
  ].join('\n'), 'utf8').toString('base64');
  changed.input.original_rust_files_b64 = [{
    path: 'src/lib.rs',
    content_b64: Buffer.from('fn run() {}\n', 'utf8').toString('base64'),
  }];
  assert.throws(() => encryptFeedbackPayload(changed.input), { code: 'credential_like_content' });
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

test('producer reports the specific invalid-payload class for raw control bytes and still refuses them', () => {
  const cases = [
    [Buffer.from([0x61, 0xe2, 0x8e]), 'invalid_payload_utf8'],
    [Buffer.from('a\0b\n'), 'invalid_payload_nul'],
    [Buffer.from('a\rb\n'), 'invalid_payload_cr'],
    [Buffer.from('a\u001b[31mb\n'), 'invalid_payload_c0'],
    [Buffer.from('a\u0085b\n'), 'invalid_payload_c1'],
  ];
  for (const [payload, code] of cases) {
    const input = fixture('build_diagnostics').input;
    input.payload_b64 = payload.toString('base64');
    assert.throws(() => encryptFeedbackPayload(input), { code }, code);
  }
  const success = fixture('build_diagnostics').input;
  success.payload_b64 = Buffer.from(
    'KD-BUILD-DIAGNOSTICS schema=1 selected_gates=format,clippy completed_gates=format,clippy result=all-gates-completed\n',
  ).toString('base64');
  assert.doesNotThrow(() => encryptFeedbackPayload(success));
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
  assert.deepEqual(oversized.stderr, Buffer.from('KD-FEEDBACK-ENCRYPTION-REFUSAL input_too_large\n'));
});

test('producer encrypts the fixed-size Linux quick payload under its own untrusted-ref profile', () => {
  const value = fixture('linux_quick');
  assert.equal(value.context.workflow_ref, 'refs/heads/untrusted');
  assert.equal(Buffer.from(value.input.payload_b64, 'base64').length, QUICK_BYTES);
  const ciphertext = encryptFeedbackPayload(value.input);
  assert.equal(ciphertext.subarray(0, 4).toString('ascii'), 'KDLE');
  assert.equal(ciphertext[5], 6);
  assert.equal(ciphertext.length, QUICK_BYTES + 486);
  assert.ok(ciphertext.length <= 4 * 1024 * 1024);
  assert.equal(ciphertext.includes(Buffer.from('KD-LINUX-QUICK-PAYLOAD')), false);

  const withManifest = fixture('linux_quick');
  withManifest.input.expected_manifest = { root: {}, workspaces: [] };
  assert.throws(() => encryptFeedbackPayload(withManifest.input));

  const withPaths = fixture('linux_quick');
  withPaths.input.reviewed_rust_paths = ['src/lib.rs'];
  assert.throws(() => encryptFeedbackPayload(withPaths.input));

  const withSources = fixture('linux_quick');
  withSources.input.original_rust_files_b64 = [];
  assert.throws(() => encryptFeedbackPayload(withSources.input));
});

test('producer refuses a Linux quick payload that is oversized, credential-shaped or on the wrong ref', () => {
  const over = fixture('linux_quick');
  over.input.payload_b64 = Buffer.alloc(QUICK_BYTES + 1, 0x20).toString('base64');
  assert.throws(() => encryptFeedbackPayload(over.input), { code: 'invalid_payload' });

  const credential = fixture('linux_quick');
  credential.input.payload_b64 = quickPayload('{"stderr_tail":"error token=abcdefghijkl"}').toString('base64');
  assert.throws(() => encryptFeedbackPayload(credential.input), { code: 'credential_like_content' });

  const mainRef = fixture('linux_quick');
  mainRef.input.context.workflow_ref = 'refs/heads/main';
  assert.throws(() => encryptFeedbackPayload(mainRef.input), { code: 'invalid_context' });

  const wrongKind = fixture('linux_quick');
  wrongKind.input.kind = 'build_diagnostics';
  assert.throws(() => encryptFeedbackPayload(wrongKind.input), { code: 'invalid_context' });

  const diagnosticOnUntrusted = fixture('build_diagnostics');
  diagnosticOnUntrusted.input.context.workflow_ref = 'refs/heads/untrusted';
  assert.throws(() => encryptFeedbackPayload(diagnosticOnUntrusted.input), { code: 'invalid_context' });

  const oversizedDiagnostic = fixture('build_diagnostics');
  oversizedDiagnostic.input.payload_b64 = quickPayload().toString('base64');
  assert.throws(() => encryptFeedbackPayload(oversizedDiagnostic.input), { code: 'invalid_payload' });
});

test('CLI encrypts the Linux quick payload from bounded stdin and emits only ciphertext', () => {
  const value = fixture('linux_quick');
  const validInput = Buffer.from(JSON.stringify(value.input), 'utf8');
  assert.ok(validInput.length < 6 * 1024 * 1024);
  const positive = spawnSync(process.execPath, [CRYPTO_SCRIPT], {
    input: validInput,
    timeout: 60_000,
    maxBuffer: 4 * 1024 * 1024 + 1024,
    env: { PATH: process.env.PATH ?? '', LANG: 'C', LC_ALL: 'C' },
  });
  assert.equal(positive.error, undefined);
  assert.equal(positive.status, 0);
  assert.equal(positive.stderr.length, 0);
  assert.equal(positive.stdout.subarray(0, 4).toString('ascii'), 'KDLE');
  assert.equal(positive.stdout[5], 6);
  assert.equal(positive.stdout.length, QUICK_BYTES + 486);
});
