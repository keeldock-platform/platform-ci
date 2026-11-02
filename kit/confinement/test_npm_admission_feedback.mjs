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
import { RETURN_PROFILES } from './node_lock_envelope.mjs';

const NOW = 1_793_160_000;
const PROFILE = 'core-npm-admission-return';
let recipient;

function fingerprint(key) {
  return createHash('sha256').update(key.export({ format: 'der', type: 'spki' })).digest('hex');
}

function contextFor(profileName) {
  const profile = RETURN_PROFILES[profileName];
  return {
    request_id: '1'.repeat(64),
    nonce: '2'.repeat(64),
    recipient_fingerprint: fingerprint(recipient.publicKey),
    concern: profile.concern,
    kind: profile.kind,
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
}

function bundle(overrides = {}) {
  return Buffer.from(JSON.stringify({
    evidence_b64: Buffer.from('{"schema_version":1}', 'ascii').toString('base64'),
    lock_b64: Buffer.from('{"lockfileVersion":3}\n', 'ascii').toString('base64'),
    receipt_b64: Buffer.from('{"schema_version":1}', 'ascii').toString('base64'),
    schema_version: 1,
    ...overrides,
  }), 'utf8');
}

function validate(payloadBytes, extra = {}) {
  return validateDevelopmentFeedback({ payloadBytes, context: contextFor(PROFILE), now: NOW, ...extra });
}

before(() => {
  recipient = generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 65537 });
});

test('the npm admission profile is the fifth closed profile with its own kind and member', () => {
  const profile = RETURN_PROFILES[PROFILE];
  assert.equal(profile.id, 5);
  assert.equal(profile.kind, 'npm_admission');
  assert.equal(profile.producerJob, 'core-npm-admission-return');
  assert.equal(profile.artifactMember, 'npm-admission-return-v1.enc');
  const members = Object.values(RETURN_PROFILES).map((item) => item.artifactMember);
  assert.equal(new Set(members).size, members.length);
  const ids = Object.values(RETURN_PROFILES).map((item) => item.id);
  assert.equal(new Set(ids).size, ids.length);
});

test('accepts one bounded canonical npm admission bundle and refuses everything else', () => {
  const payload = bundle();
  assert.deepEqual(validate(payload), payload);
  for (const rejected of [
    Buffer.from('{}', 'utf8'),
    Buffer.from(`${payload.toString('utf8')}\n`, 'utf8'),
    bundle({ extra: 'AAAA' }),
    bundle({ schema_version: 2 }),
    bundle({ lock_b64: Buffer.from('{"lockfileVersion":3}', 'ascii').toString('base64') }),
    bundle({ lock_b64: Buffer.from(`{"a":"${String.fromCharCode(233)}"}\n`, 'utf8').toString('base64') }),
    bundle({ receipt_b64: Buffer.from('{"a":1}\n', 'ascii').toString('base64') }),
    bundle({ evidence_b64: '' }),
    bundle({ evidence_b64: 'AAA' }),
    bundle({
      lock_b64: Buffer.alloc(DEVELOPMENT_FEEDBACK_LIMITS.npmAdmissionLockBytes + 1, 0x61).toString('base64'),
    }),
    bundle({
      receipt_b64: Buffer.alloc(DEVELOPMENT_FEEDBACK_LIMITS.npmAdmissionReceiptBytes + 1, 0x61).toString('base64'),
    }),
    bundle({
      evidence_b64: Buffer.alloc(DEVELOPMENT_FEEDBACK_LIMITS.npmAdmissionEvidenceBytes + 1, 0x61).toString('base64'),
    }),
    Buffer.alloc(DEVELOPMENT_FEEDBACK_LIMITS.npmAdmissionBytes + 1, 0x20),
  ]) {
    assert.throws(() => validate(rejected), DevelopmentFeedbackError);
  }
  assert.throws(() => validate(payload, { expectedManifest: {} }), DevelopmentFeedbackError);
  assert.throws(() => validate(payload, { reviewedRustPaths: ['src/lib.rs'] }), DevelopmentFeedbackError);
});

test('a bundle that is larger than the cargo bound but inside the npm bound is accepted only here', () => {
  const large = Buffer.alloc(DEVELOPMENT_FEEDBACK_LIMITS.cargoLockLockBytes + 1024, 0x61);
  large[large.length - 1] = 0x0a;
  const payload = bundle({ lock_b64: large.toString('base64') });
  assert.ok(payload.byteLength > DEVELOPMENT_FEEDBACK_LIMITS.cargoLockBytes / 4);
  assert.deepEqual(validate(payload), payload);
  assert.throws(() => validateDevelopmentFeedback({
    payloadBytes: payload,
    context: { ...contextFor('core-rust-lock-return') },
    now: NOW,
  }), DevelopmentFeedbackError);
});

test('npm admission limits stay inside the envelope plaintext bound and below the node lock limit semantics', () => {
  assert.ok(DEVELOPMENT_FEEDBACK_LIMITS.npmAdmissionBytes <= 4 * 1024 * 1024 - 64 * 1024);
  const encoded = (size) => 4 * Math.ceil(size / 3);
  const total = encoded(DEVELOPMENT_FEEDBACK_LIMITS.npmAdmissionLockBytes)
    + encoded(DEVELOPMENT_FEEDBACK_LIMITS.npmAdmissionReceiptBytes)
    + encoded(DEVELOPMENT_FEEDBACK_LIMITS.npmAdmissionEvidenceBytes) + 256;
  assert.ok(total <= DEVELOPMENT_FEEDBACK_LIMITS.npmAdmissionBytes);
});

test('npm admission bundles encrypt and decrypt only under their own profile', () => {
  const payload = bundle();
  const context = contextFor(PROFILE);
  const envelope = encryptDevelopmentFeedback({
    payloadBytes: payload,
    context,
    recipientPublicKey: recipient.publicKey,
    now: NOW,
  });
  assert.equal(envelope[5], RETURN_PROFILES[PROFILE].id);
  assert.deepEqual(decryptDevelopmentFeedback({
    envelope,
    context,
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
  }), payload);
  assert.throws(() => decryptDevelopmentFeedback({
    envelope,
    context: contextFor('core-rust-lock-return'),
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
  }));
  assert.throws(() => decryptDevelopmentFeedback({
    envelope,
    context: { ...context, kind: 'cargo_lock' },
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
  }));
});

const DIAGNOSTIC_HEADER = 'KD-NPM-DIAGNOSTICS schema=1 step=npm_resolve reason=eresolve';

function diagnostics({
  header = DIAGNOSTIC_HEADER,
  stderr = ['  npm error code ERESOLVE', '  npm error While resolving: x@1.0.0'],
  report = ['  Found: y@2.0.0'],
} = {}) {
  const text = `${header}\nstderr:\n${stderr.map((line) => `${line}\n`).join('')}report:\n`
    + `${report.map((line) => `${line}\n`).join('')}`;
  return Buffer.from(text, 'utf8');
}

function refusalCode(error) {
  return error instanceof DevelopmentFeedbackError ? error.code : 'other';
}

test('the npm diagnostic payload is a closed variant of the npm admission kind only', () => {
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.npmDiagnosticBytes, 64 * 1024);
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.npmDiagnosticLines, 401);
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.npmDiagnosticLineCodeUnits, 2048);
  const payload = diagnostics();
  assert.deepEqual(validate(payload), payload);
  for (const step of ['npm_resolve', 'npm_lock', 'npm_bundle']) {
    const header = `KD-NPM-DIAGNOSTICS schema=1 step=${step} reason=npm_peer_refused`;
    assert.deepEqual(validate(diagnostics({ header })), diagnostics({ header }));
  }
  assert.deepEqual(validate(diagnostics({ stderr: [], report: [] })), diagnostics({ stderr: [], report: [] }));
  for (const profile of ['core-rust-lock-return', 'core-rust-format-return']) {
    assert.throws(() => validateDevelopmentFeedback({
      payloadBytes: payload,
      context: contextFor(profile),
      now: NOW,
    }), DevelopmentFeedbackError);
  }
  assert.throws(() => validate(payload, { expectedManifest: {} }), DevelopmentFeedbackError);
  assert.throws(() => validate(payload, { reviewedRustPaths: ['src/lib.rs'] }), DevelopmentFeedbackError);
});

test('a diagnostic payload is never accepted as a bundle and a bundle never as a diagnostic', () => {
  const bundleBytes = bundle();
  assert.notEqual(bundleBytes.subarray(0, 19).toString('latin1'), 'KD-NPM-DIAGNOSTICS ');
  assert.deepEqual(validate(bundleBytes), bundleBytes);
  for (const bad of [
    Buffer.from(`${DIAGNOSTIC_HEADER}\n${bundleBytes.toString('utf8')}`, 'utf8'),
    Buffer.from(`${DIAGNOSTIC_HEADER} ${bundleBytes.toString('utf8')}`, 'utf8'),
    Buffer.from('KD-NPM-DIAGNOSTICS ', 'utf8'),
  ]) {
    assert.throws(() => validate(bad), DevelopmentFeedbackError);
  }
});

test('the npm diagnostic payload refuses every malformed shape', () => {
  const wrongHeaders = [
    'KD-NPM-DIAGNOSTICS schema=2 step=npm_resolve reason=eresolve',
    'KD-NPM-DIAGNOSTICS schema=1 step=npm_inputs reason=eresolve',
    'KD-NPM-DIAGNOSTICS schema=1 step=npm_resolve reason=ERESOLVE',
    'KD-NPM-DIAGNOSTICS schema=1 step=npm_resolve reason=',
    `KD-NPM-DIAGNOSTICS schema=1 step=npm_resolve reason=${'a'.repeat(41)}`,
    `${DIAGNOSTIC_HEADER} extra=1`,
    `${DIAGNOSTIC_HEADER} `,
    'KD-NPM-DIAGNOSTICS  schema=1 step=npm_resolve reason=eresolve',
  ];
  for (const header of wrongHeaders) {
    assert.throws(() => validate(diagnostics({ header })), DevelopmentFeedbackError, header);
  }
  const good = diagnostics().toString('utf8');
  for (const bad of [
    good.replace('stderr:\n', ''),
    good.replace('report:\n', ''),
    good.replace('stderr:\n', 'stderr: \n'),
    `${good}report:\n`,
    good.replace('  npm error code ERESOLVE', 'npm error code ERESOLVE'),
    good.slice(0, -1),
    `${good}\n`,
    good.replace('\n', '\r\n'),
    good.replace('ERESOLVE', 'ER\u0000ESOLVE'),
    good.replace('ERESOLVE', `ER${String.fromCharCode(0x85)}ESOLVE`),
    good.replace('ERESOLVE', 'ER\u001bESOLVE'),
    `${String.fromCharCode(0xfeff)}${good}`,
  ]) {
    assert.throws(() => validate(Buffer.from(bad, 'utf8')), DevelopmentFeedbackError);
  }
  assert.throws(() => validate(Buffer.concat([diagnostics(), Buffer.from([0xff, 0x0a])])), DevelopmentFeedbackError);
});

test('the npm diagnostic payload keeps its byte, line and line-length bounds', () => {
  const line = `  ${'a'.repeat(2046)}`;
  assert.deepEqual(validate(diagnostics({ stderr: [line], report: [line] })), diagnostics({ stderr: [line], report: [line] }));
  assert.throws(() => validate(diagnostics({ stderr: [`${line}a`] })), (error) => refusalCode(error) === 'limit_exceeded');
  const lines = (count) => Array.from({ length: count }, () => '  npm error x');
  assert.deepEqual(validate(diagnostics({ stderr: lines(397), report: [] })), diagnostics({ stderr: lines(397), report: [] }));
  assert.throws(
    () => validate(diagnostics({ stderr: lines(398), report: [] })),
    (error) => refusalCode(error) === 'limit_exceeded',
  );
  const wide = Array.from({ length: 30 }, () => line);
  assert.deepEqual(validate(diagnostics({ stderr: wide, report: [] })), diagnostics({ stderr: wide, report: [] }));
  const heavy = Array.from({ length: 40 }, () => line);
  assert.throws(
    () => validate(diagnostics({ stderr: heavy, report: heavy })),
    (error) => refusalCode(error) === 'payload_too_large',
  );
});

test('the npm diagnostic payload is credential screened', () => {
  for (const secret of [
    `  npm error token: ${'a'.repeat(12)}`,
    `  npm error ghp_${'A'.repeat(24)} leaked`,
    '  npm error Authorization: Bearer abcdefghijklmnopqrstuvwxyz',
    '  npm error fetch https://user:pass@registry.example/pkg',
    '  npm error -----BEGIN PRIVATE KEY-----',
  ]) {
    assert.throws(
      () => validate(diagnostics({ stderr: [secret] })),
      (error) => refusalCode(error) === 'credential_like_content',
      secret,
    );
    assert.throws(
      () => validate(diagnostics({ report: [secret] })),
      (error) => refusalCode(error) === 'credential_like_content',
      secret,
    );
  }
});

test('the npm diagnostic payload encrypts and decrypts only under the npm admission profile', () => {
  const payload = diagnostics();
  const context = contextFor(PROFILE);
  const envelope = encryptDevelopmentFeedback({
    payloadBytes: payload,
    context,
    recipientPublicKey: recipient.publicKey,
    now: NOW,
  });
  assert.equal(envelope[5], RETURN_PROFILES[PROFILE].id);
  assert.deepEqual(decryptDevelopmentFeedback({
    envelope,
    context,
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
  }), payload);
  assert.throws(() => decryptDevelopmentFeedback({
    envelope,
    context: contextFor('core-rust-lock-return'),
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
  }));
  assert.throws(() => encryptDevelopmentFeedback({
    payloadBytes: diagnostics({ stderr: ['  npm error password: hunter22222'] }),
    context,
    recipientPublicKey: recipient.publicKey,
    now: NOW,
  }), DevelopmentFeedbackError);
});
