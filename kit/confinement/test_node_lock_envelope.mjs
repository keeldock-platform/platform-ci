import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
} from 'node:crypto';
import { before, test } from 'node:test';

import {
  canonicalContext,
  decryptLock,
  encryptLock,
  LOCK_ENVELOPE_LIMITS,
  LockEnvelopeError,
  parseCanonicalContext,
} from './node_lock_envelope.mjs';

const NOW = 1_999_999_000;
const PAYLOAD = Buffer.from('{"name":"fixture-lock","lockfileVersion":3}\n', 'utf8');
let recipient;
let otherRecipient;
let nonstandardExponentRecipient;
let context;
let frame;

function fingerprint(key) {
  return createHash('sha256').update(key.export({ format: 'der', type: 'spki' })).digest('hex');
}

function sampleContext(recipientKey = recipient?.publicKey) {
  return {
    request_id: '1'.repeat(64),
    nonce: '2'.repeat(64),
    recipient_fingerprint: fingerprint(recipientKey),
    concern: 'core-node-lock-return',
    repository_id: '123456',
    source_sha: 'a'.repeat(40),
    base_sha: 'b'.repeat(40),
    control_sha: 'c'.repeat(40),
    base_branch: 'main',
    reviewed_diff_sha256: 'd'.repeat(64),
    workflow_ref: 'refs/heads/main',
    run_id: '987654321',
    producer_job: 'node-lock-return',
    run_attempt: 1,
    expiry: NOW + 3600,
  };
}

function encrypted(contextValue = context, bytes = PAYLOAD) {
  return encryptLock({
    lockBytes: bytes,
    recipientPublicKey: recipient.publicKey,
    context: contextValue,
    now: NOW,
  });
}

function decrypt(ciphertext = frame, contextValue = context, key = recipient.privateKey, now = NOW) {
  return decryptLock({
    envelope: ciphertext,
    recipientPrivateKey: key,
    expectedContext: contextValue,
    now,
  });
}

before(() => {
  recipient = generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 65537 });
  otherRecipient = generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 65537 });
  nonstandardExponentRecipient = generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 3 });
  context = sampleContext();
  frame = encrypted();
});

test('round-trips only the caller-bound lock bytes', () => {
  assert.deepEqual(decrypt(), PAYLOAD);
  assert.ok(frame.byteLength <= LOCK_ENVELOPE_LIMITS.frameBytes);
});

test('canonical context has the fixed field order and rejects duplicates', () => {
  const bytes = canonicalContext(context);
  assert.ok(bytes.toString('ascii').startsWith('node-lock-return-context-v1\n'));
  const parsed = parseCanonicalContext(bytes);
  assert.deepEqual(parsed, context);
  const lines = bytes.toString('ascii').split('\n');
  const duplicate = [...lines.slice(0, 2), lines[2], lines[2], ...lines.slice(3)].join('\n');
  assert.throws(() => parseCanonicalContext(Buffer.from(
    duplicate, 'ascii',
  )), LockEnvelopeError);
  assert.throws(() => parseCanonicalContext(Buffer.from(
    bytes.toString('ascii').replace('request_id=', 'unknown=1\nrequest_id='), 'ascii',
  )), LockEnvelopeError);
  const reorderedLines = [...lines];
  [reorderedLines[2], reorderedLines[3]] = [reorderedLines[3], reorderedLines[2]];
  assert.throws(() => parseCanonicalContext(Buffer.from(
    reorderedLines.join('\n'), 'ascii',
  )), LockEnvelopeError);
});

test('context is closed, canonical, bounded, and fixed to the producer concern', () => {
  assert.throws(() => canonicalContext({ ...context, unreviewed: 'x' }), LockEnvelopeError);
  assert.throws(() => canonicalContext({ ...context, concern: 'format-diff' }), LockEnvelopeError);
  assert.throws(() => canonicalContext({ ...context, producer_job: 'different-job' }), LockEnvelopeError);
  assert.throws(() => canonicalContext({ ...context, workflow_ref: 'refs/heads/feature' }), LockEnvelopeError);
  assert.throws(() => canonicalContext({ ...context, run_attempt: 2 }), LockEnvelopeError);
  assert.throws(() => canonicalContext({ ...context, base_branch: 'main\nrun_id=4' }), LockEnvelopeError);
  assert.throws(() => canonicalContext({ ...context, base_branch: 'feature/new' }), LockEnvelopeError);
  assert.throws(() => canonicalContext({ ...context, source_sha: 'a'.repeat(64) }), LockEnvelopeError);
  for (const field of ['repository_id', 'run_id']) {
    assert.doesNotThrow(() => canonicalContext({ ...context, [field]: '9007199254740991' }));
    assert.throws(() => canonicalContext({ ...context, [field]: '9007199254740992' }), LockEnvelopeError);
    assert.throws(() => canonicalContext({ ...context, [field]: '18446744073709551615' }), LockEnvelopeError);
  }
  for (const baseBranch of ['main', 'develop', 'uat']) {
    assert.doesNotThrow(() => canonicalContext({ ...context, base_branch: baseBranch }));
  }
  const polluted = Object.create(null);
  Object.assign(polluted, context);
  Object.defineProperty(polluted, '__proto__', { value: 'blocked', enumerable: true });
  assert.throws(() => canonicalContext(polluted), LockEnvelopeError);
});

test('expiry must be current and no more than one day ahead', () => {
  assert.throws(() => encrypted({ ...context, expiry: NOW }), LockEnvelopeError);
  assert.throws(() => encrypted({ ...context, expiry: NOW + 86_401 }), LockEnvelopeError);
  assert.throws(() => decrypt(frame, { ...context, expiry: NOW }, recipient.privateKey, NOW), LockEnvelopeError);
  assert.throws(() => decrypt(frame, { ...context, expiry: NOW + 10 }, recipient.privateKey, NOW + 10), LockEnvelopeError);
});

test('wrong key, fingerprint, or expected source context fails closed', () => {
  assert.throws(() => decrypt(frame, context, otherRecipient.privateKey), LockEnvelopeError);
  assert.throws(() => decrypt(frame, { ...context, recipient_fingerprint: fingerprint(otherRecipient.publicKey) }), LockEnvelopeError);
  assert.throws(() => decrypt(frame, { ...context, source_sha: 'e'.repeat(40) }), LockEnvelopeError);
  assert.throws(() => decrypt(frame, { ...context, base_sha: 'e'.repeat(40) }), LockEnvelopeError);
  assert.throws(() => decrypt(frame, { ...context, control_sha: 'e'.repeat(40) }), LockEnvelopeError);
  assert.throws(() => decrypt(frame, { ...context, nonce: 'e'.repeat(64) }), LockEnvelopeError);
  assert.throws(() => decrypt(frame, { ...context, request_id: 'e'.repeat(64) }), LockEnvelopeError);
  assert.throws(() => decrypt(frame, { ...context, run_id: '987654322' }), LockEnvelopeError);
});

test('key input must be a genuine RSA-3072 KeyObject with exponent 65537', () => {
  let getterTouched = false;
  const fakeKey = {
    get type() { getterTouched = true; throw new Error('fixture-canary'); },
    export() { getterTouched = true; throw new Error('fixture-canary'); },
  };
  assert.throws(() => encryptLock({
    lockBytes: PAYLOAD,
    recipientPublicKey: fakeKey,
    context,
    now: NOW,
  }), (error) => error instanceof LockEnvelopeError && error.message === 'Lock envelope rejected');
  assert.equal(getterTouched, false);
  assert.throws(() => encryptLock({
    lockBytes: PAYLOAD,
    recipientPublicKey: nonstandardExponentRecipient.publicKey,
    context,
    now: NOW,
  }), LockEnvelopeError);
});

test('rejects frame tampering, truncation, unsupported profiles, and trailing bytes', () => {
  const offsets = [0, 4, 5, 6, 38, 70, 454, 466, 470, frame.byteLength - 1];
  for (const offset of offsets) {
    const changed = Buffer.from(frame);
    changed[offset] ^= 1;
    assert.throws(() => decrypt(changed), LockEnvelopeError, `offset ${offset}`);
  }
  for (const length of [0, 5, 70, 454, frame.byteLength - 1]) {
    assert.throws(() => decrypt(frame.subarray(0, length)), LockEnvelopeError, `length ${length}`);
  }
  assert.throws(() => decrypt(Buffer.concat([frame, Buffer.from([0])])), LockEnvelopeError);
  const badLength = Buffer.from(frame);
  badLength.writeUInt32BE(0xffff_ffff, 466);
  assert.throws(() => decrypt(badLength), LockEnvelopeError);
});

test('rejects oversized plaintext and frame input before cryptographic processing', () => {
  const tooLarge = Buffer.alloc(LOCK_ENVELOPE_LIMITS.plaintextBytes + 1);
  assert.throws(() => encrypted(context, tooLarge), LockEnvelopeError);
  assert.throws(() => decrypt(Buffer.alloc(LOCK_ENVELOPE_LIMITS.frameBytes + 1)), LockEnvelopeError);
});
