import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { before, test } from 'node:test';

import {
  DEVELOPMENT_FEEDBACK_LIMITS,
  DevelopmentFeedbackError,
  decryptDevelopmentFeedback,
  encryptDevelopmentFeedback,
  validateDevelopmentFeedback,
} from './development_feedback.mjs';
import { encryptReturnEnvelope, RETURN_PROFILES } from './node_lock_envelope.mjs';

const NOW = 1_793_160_000;
let recipient;

const lockExpectation = {
  root: {
    name: 'fixture-root',
    version: '1.0.0',
    workspaces: ['packages/*'],
    devDependencies: { typescript: '6.0.3' },
  },
  workspaces: [
    {
      path: 'packages/client-api',
      name: '@fixture/client-api',
      version: '1.0.0',
      dependencies: { '@fixture/shared': 'workspace:*' },
    },
    { path: 'packages/shared', name: '@fixture/shared', version: '1.0.0' },
  ],
};

function fingerprint(key) {
  return createHash('sha256').update(key.export({ format: 'der', type: 'spki' })).digest('hex');
}

function contextFor(profileName) {
  const profile = RETURN_PROFILES[profileName];
  const context = {
    request_id: '1'.repeat(64),
    nonce: '2'.repeat(64),
    recipient_fingerprint: fingerprint(recipient.publicKey),
    concern: profile.concern,
    repository_id: '123456',
    source_sha: 'a'.repeat(40),
    base_sha: 'b'.repeat(40),
    control_sha: 'c'.repeat(40),
    base_branch: 'main',
    reviewed_diff_sha256: 'd'.repeat(64),
    workflow_ref: 'refs/heads/main',
    run_id: '987654321',
    producer_job: profile.producerJob,
    run_attempt: 1,
    expiry: NOW + 3600,
  };
  if (profile.id !== 1) context.kind = profile.kind;
  return context;
}

function lockBytes() {
  const lock = {
    name: 'fixture-root',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': {
        name: 'fixture-root',
        version: '1.0.0',
        workspaces: ['packages/*'],
        devDependencies: { typescript: '6.0.3' },
      },
      'packages/client-api': {
        name: '@fixture/client-api',
        version: '1.0.0',
        dependencies: { '@fixture/shared': 'workspace:*' },
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
  };
  return Buffer.from(`${JSON.stringify(lock)}\n`, 'utf8');
}

function rustPatch(
  path = 'src/lib.rs',
  oldLine = 'pub const VALUE: u32 = 1;',
  newLine = 'pub const VALUE: u32 = 2;',
) {
  return Buffer.from([
    `diff --git a/${path} b/${path}`,
    'index 1111111..2222222 100644',
    `--- a/${path}`,
    `+++ b/${path}`,
    '@@ -1,1 +1,1 @@',
    `-${oldLine}`,
    `+${newLine}`,
    '',
  ].join('\n'), 'utf8');
}

function validate(kind, payloadBytes, extra = {}) {
  const profileName = kind === 'lock' ? 'core-node-lock-return'
    : kind === 'rust_patch' ? 'core-rust-format-return'
      : kind === 'cargo_lock' ? 'core-rust-lock-return' : 'core-build-diagnostic-return';
  return validateDevelopmentFeedback({ payloadBytes, context: contextFor(profileName), now: NOW, ...extra });
}

before(() => {
  recipient = generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 65537 });
});

test('accepts a bounded lock only with the reviewed manifest expectation', () => {
  const bytes = lockBytes();
  assert.deepEqual(validate('lock', bytes, { expectedManifest: lockExpectation }), bytes);
  assert.throws(() => validate('lock', bytes), DevelopmentFeedbackError);
  assert.throws(() => validate('lock', bytes, { expectedManifest: {} }), DevelopmentFeedbackError);
});

test('accepts a one-file patch only for an exact reviewed Rust path', () => {
  const payload = rustPatch();
  assert.deepEqual(validate('rust_patch', payload, { reviewedRustPaths: ['src/lib.rs'] }), payload);
  for (const rejected of [
    rustPatch('../outside.rs'),
    rustPatch('src/main.rs'),
    Buffer.from(rustPatch().toString('utf8').replace(
      'index 1111111..2222222 100644',
      'index 1111111..2222222 100644\nrename from src/lib.rs\nrename to src/renamed.rs',
    ), 'utf8'),
    Buffer.from('diff --git a/src/lib.rs b/src/lib.rs\nGIT binary patch\n', 'utf8'),
    Buffer.from(rustPatch().toString('utf8').replace('@@ -1,1 +1,1 @@', '@@ -1,2 +1,1 @@'), 'utf8'),
    Buffer.from(`${rustPatch().toString('utf8').trimEnd()}\n${rustPatch().toString('utf8')}`, 'utf8'),
    rustPatch('src/lib.rs', 'old source line', '// password=synthetic-fixture-value'),
    rustPatch('src/lib.rs', 'old source line', '// token=synthetic-fixture-value'),
    rustPatch('src/lib.rs', 'old source line', '// -----BEGIN PRIVATE KEY-----'),
    rustPatch('src/lib.rs', '// secret=synthetic-fixture-value', 'new source line'),
  ]) {
    assert.throws(() => validate('rust_patch', rejected, { reviewedRustPaths: ['src/lib.rs'] }), DevelopmentFeedbackError);
  }
  assert.throws(() => validate('rust_patch', payload, { reviewedRustPaths: ['../outside.rs'] }), DevelopmentFeedbackError);
  assert.throws(() => validate('rust_patch', Buffer.alloc(DEVELOPMENT_FEEDBACK_LIMITS.rustPatchBytes + 1), {
    reviewedRustPaths: ['src/lib.rs'],
  }), DevelopmentFeedbackError);
});

test('bounds the reviewed Rust path list at the four crate headroom', () => {
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.reviewedRustPaths, 512);
  const payload = rustPatch();
  const reviewed = (count) => ['src/lib.rs', ...Array.from({ length: count - 1 }, (_, index) => `src/module_${index}.rs`)];
  assert.deepEqual(validate('rust_patch', payload, { reviewedRustPaths: reviewed(512) }), payload);
  assert.throws(() => validate('rust_patch', payload, { reviewedRustPaths: reviewed(513) }), DevelopmentFeedbackError);
  assert.throws(() => validate('rust_patch', payload, { reviewedRustPaths: [] }), DevelopmentFeedbackError);
});

test('accepts bounded diagnostics and rejects malformed or credential-shaped text', () => {
  const payload = Buffer.from('compiler completed with zero warnings\n', 'utf8');
  assert.deepEqual(validate('build_diagnostics', payload), payload);
  for (const rejected of [
    Buffer.from([0xc3, 0x28]),
    Buffer.from('first\0second\n', 'utf8'),
    Buffer.from('password=synthetic-fixture-value\n', 'utf8'),
    Buffer.from('token=synthetic-fixture-value\n', 'utf8'),
    Buffer.from('https://user:placeholder@example.invalid/path\n', 'utf8'),
    Buffer.from('-----BEGIN PRIVATE KEY-----\n', 'utf8'),
    Buffer.alloc(DEVELOPMENT_FEEDBACK_LIMITS.diagnosticBytes + 1),
  ]) {
    assert.throws(() => validate('build_diagnostics', rejected), DevelopmentFeedbackError);
  }
});

test('the development exception requires a trusted in-window clock and bounded expiry', () => {
  const payloadBytes = Buffer.from('compiler completed with zero warnings\n', 'utf8');
  const context = contextFor('core-build-diagnostic-return');
  assert.throws(() => validateDevelopmentFeedback({ payloadBytes, context }), DevelopmentFeedbackError);
  assert.throws(() => validateDevelopmentFeedback({
    payloadBytes,
    context,
    now: DEVELOPMENT_FEEDBACK_LIMITS.exceptionEndUnixSeconds,
  }), DevelopmentFeedbackError);
  assert.throws(() => validateDevelopmentFeedback({ payloadBytes, context, now: NOW + 0.5 }), DevelopmentFeedbackError);
  assert.throws(() => validateDevelopmentFeedback({
    payloadBytes,
    context: { ...context, expiry: NOW },
    now: NOW,
  }), DevelopmentFeedbackError);
  assert.throws(() => validateDevelopmentFeedback({
    payloadBytes,
    context: { ...context, expiry: NOW + DEVELOPMENT_FEEDBACK_LIMITS.contextLifetimeSeconds + 1 },
    now: NOW,
  }), DevelopmentFeedbackError);
  assert.throws(() => validateDevelopmentFeedback({
    payloadBytes,
    context: { ...context, expiry: DEVELOPMENT_FEEDBACK_LIMITS.exceptionEndUnixSeconds + 1 },
    now: NOW,
  }), DevelopmentFeedbackError);
  const edgeNow = DEVELOPMENT_FEEDBACK_LIMITS.exceptionEndUnixSeconds - 3600;
  const edgeContext = { ...context, expiry: DEVELOPMENT_FEEDBACK_LIMITS.exceptionEndUnixSeconds };
  assert.doesNotThrow(() => validateDevelopmentFeedback({ payloadBytes, context: edgeContext, now: edgeNow }));
});

test('encrypted feedback round-trips only validated profile payloads', () => {
  const payload = rustPatch();
  const context = contextFor('core-rust-format-return');
  const envelope = encryptDevelopmentFeedback({
    payloadBytes: payload,
    context,
    recipientPublicKey: recipient.publicKey,
    now: NOW,
    reviewedRustPaths: ['src/lib.rs'],
  });
  assert.equal(envelope[5], RETURN_PROFILES['core-rust-format-return'].id);
  assert.deepEqual(decryptDevelopmentFeedback({
    envelope,
    context,
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
    reviewedRustPaths: ['src/lib.rs'],
  }), payload);
  assert.throws(() => encryptDevelopmentFeedback({
    payloadBytes: Buffer.from('unbound text\n'),
    context,
    recipientPublicKey: recipient.publicKey,
    now: NOW,
    reviewedRustPaths: ['src/lib.rs'],
  }), DevelopmentFeedbackError);
  const invalidEnvelope = encryptReturnEnvelope({
    payloadBytes: Buffer.from('not a unified patch\n'),
    recipientPublicKey: recipient.publicKey,
    context,
    now: NOW,
  });
  assert.throws(() => decryptDevelopmentFeedback({
    envelope: invalidEnvelope,
    context,
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
    reviewedRustPaths: ['src/lib.rs'],
  }), DevelopmentFeedbackError);
  const lockContext = contextFor('core-node-lock-return');
  assert.throws(() => decryptDevelopmentFeedback({
    envelope,
    context: lockContext,
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
    expectedManifest: lockExpectation,
  }), DevelopmentFeedbackError);
});

test('lock and diagnostics profiles validate on both encryption and decryption', () => {
  const lockPayload = lockBytes();
  const lockContext = contextFor('core-node-lock-return');
  const lockEnvelope = encryptDevelopmentFeedback({
    payloadBytes: lockPayload,
    context: lockContext,
    recipientPublicKey: recipient.publicKey,
    now: NOW,
    expectedManifest: lockExpectation,
  });
  assert.equal(lockEnvelope[5], RETURN_PROFILES['core-node-lock-return'].id);
  assert.deepEqual(decryptDevelopmentFeedback({
    envelope: lockEnvelope,
    context: lockContext,
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
    expectedManifest: lockExpectation,
  }), lockPayload);

  const diagnosticPayload = Buffer.from('compiler completed with zero warnings\n', 'utf8');
  const diagnosticContext = contextFor('core-build-diagnostic-return');
  const diagnosticEnvelope = encryptDevelopmentFeedback({
    payloadBytes: diagnosticPayload,
    context: diagnosticContext,
    recipientPublicKey: recipient.publicKey,
    now: NOW,
  });
  assert.equal(diagnosticEnvelope[5], RETURN_PROFILES['core-build-diagnostic-return'].id);
  assert.deepEqual(decryptDevelopmentFeedback({
    envelope: diagnosticEnvelope,
    context: diagnosticContext,
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
  }), diagnosticPayload);
});

function cargoLockBundle(overrides = {}) {
  return Buffer.from(JSON.stringify({
    evidence_b64: Buffer.from('{"schema_version":1}', 'ascii').toString('base64'),
    lock_b64: Buffer.from('version = 4\n', 'ascii').toString('base64'),
    receipt_b64: Buffer.from('{"schema_version":1}', 'ascii').toString('base64'),
    schema_version: 1,
    ...overrides,
  }), 'utf8');
}

test('accepts one bounded canonical cargo lock bundle and refuses everything else', () => {
  const payload = cargoLockBundle();
  assert.deepEqual(validate('cargo_lock', payload), payload);
  for (const rejected of [
    Buffer.from('{}', 'utf8'),
    Buffer.from(`${payload.toString('utf8')}\n`, 'utf8'),
    cargoLockBundle({ extra: 'AAAA' }),
    cargoLockBundle({ schema_version: 2 }),
    cargoLockBundle({ lock_b64: Buffer.from('version = 4', 'ascii').toString('base64') }),
    cargoLockBundle({ lock_b64: Buffer.from(`version = 4\n${String.fromCharCode(233)}`, 'utf8').toString('base64') }),
    cargoLockBundle({ receipt_b64: Buffer.from('{"a":1}\n', 'ascii').toString('base64') }),
    cargoLockBundle({ evidence_b64: '' }),
    cargoLockBundle({ evidence_b64: 'AAA' }),
    cargoLockBundle({
      lock_b64: Buffer.alloc(DEVELOPMENT_FEEDBACK_LIMITS.cargoLockLockBytes + 1, 0x61).toString('base64'),
    }),
    Buffer.alloc(DEVELOPMENT_FEEDBACK_LIMITS.cargoLockBytes + 1, 0x20),
  ]) {
    assert.throws(() => validate('cargo_lock', rejected), DevelopmentFeedbackError);
  }
  assert.throws(() => validate('cargo_lock', payload, { expectedManifest: lockExpectation }),
    DevelopmentFeedbackError);
  assert.throws(() => validate('cargo_lock', payload, { reviewedRustPaths: ['src/lib.rs'] }),
    DevelopmentFeedbackError);
});

test('cargo lock bundles stay under their own limit and never reuse the node lock limit', () => {
  assert.ok(DEVELOPMENT_FEEDBACK_LIMITS.cargoLockBytes <= 1024 * 1024);
  assert.ok(DEVELOPMENT_FEEDBACK_LIMITS.cargoLockBytes < 4 * 1024 * 1024 - 64 * 1024);
});

test('cargo lock bundles encrypt and decrypt only under their own profile', () => {
  const payload = cargoLockBundle();
  const context = contextFor('core-rust-lock-return');
  const envelope = encryptDevelopmentFeedback({
    payloadBytes: payload,
    context,
    recipientPublicKey: recipient.publicKey,
    now: NOW,
  });
  assert.equal(envelope[5], RETURN_PROFILES['core-rust-lock-return'].id);
  assert.deepEqual(decryptDevelopmentFeedback({
    envelope,
    context,
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
  }), payload);
  assert.throws(() => decryptDevelopmentFeedback({
    envelope,
    context: contextFor('core-build-diagnostic-return'),
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
  }), DevelopmentFeedbackError);
});
