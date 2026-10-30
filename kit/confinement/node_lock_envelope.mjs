import {
  constants,
  KeyObject,
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

// Inactive primitives only: callers validate the trusted receipt, replay history, and one-use state.
export const LOCK_ENVELOPE_LIMITS = Object.freeze({
  frameBytes: 4 * 1024 * 1024,
  plaintextBytes: (4 * 1024 * 1024) - (64 * 1024),
  contextBytes: 4096,
  keyBytes: 32,
  ivBytes: 12,
  tagBytes: 16,
  wrappedKeyBytes: 384,
  expirySeconds: 24 * 60 * 60,
});

const MAGIC = Buffer.from('KDLE', 'ascii');
const VERSION = 1;
const OAEP_PADDING = constants.RSA_PKCS1_OAEP_PADDING;
const HEADER_BYTES = 4 + 1 + 1 + 32 + 32 + LOCK_ENVELOPE_LIMITS.wrappedKeyBytes
  + LOCK_ENVELOPE_LIMITS.ivBytes + 4;
const FRAME_OVERHEAD = HEADER_BYTES + LOCK_ENVELOPE_LIMITS.tagBytes;
const LOCK_CONTEXT_FIELDS = Object.freeze([
  'request_id',
  'nonce',
  'recipient_fingerprint',
  'concern',
  'repository_id',
  'source_sha',
  'base_sha',
  'control_sha',
  'base_branch',
  'reviewed_diff_sha256',
  'workflow_ref',
  'run_id',
  'producer_job',
  'run_attempt',
  'expiry',
]);
const FEEDBACK_CONTEXT_FIELDS = Object.freeze([
  ...LOCK_CONTEXT_FIELDS.slice(0, 4),
  'kind',
  ...LOCK_CONTEXT_FIELDS.slice(4),
]);
export const RETURN_PROFILES = Object.freeze({
  'core-node-lock-return': Object.freeze({
    id: 1,
    concern: 'core-node-lock-return',
    kind: 'lock',
    producerJob: 'node-lock-return',
    artifactMember: 'lock-return-v1.enc',
    contextDomain: 'node-lock-return-context-v1',
    contextFields: LOCK_CONTEXT_FIELDS,
  }),
  'core-rust-format-return': Object.freeze({
    id: 2,
    concern: 'core-rust-format-return',
    kind: 'rust_patch',
    producerJob: 'core-rust-format-return',
    artifactMember: 'rust-format-return-v1.enc',
    contextDomain: 'node-feedback-return-context-v1',
    contextFields: FEEDBACK_CONTEXT_FIELDS,
  }),
  'core-build-diagnostic-return': Object.freeze({
    id: 3,
    concern: 'core-build-diagnostic-return',
    kind: 'build_diagnostics',
    producerJob: 'core-build-diagnostic-return',
    artifactMember: 'build-diagnostic-return-v1.enc',
    contextDomain: 'node-feedback-return-context-v1',
    contextFields: FEEDBACK_CONTEXT_FIELDS,
  }),
  'core-rust-lock-return': Object.freeze({
    id: 4,
    concern: 'core-rust-lock-return',
    kind: 'cargo_lock',
    producerJob: 'core-rust-lock-return',
    artifactMember: 'rust-lock-return-v1.enc',
    contextDomain: 'node-feedback-return-context-v1',
    contextFields: FEEDBACK_CONTEXT_FIELDS,
  }),
  'core-npm-admission-return': Object.freeze({
    id: 5,
    concern: 'core-npm-admission-return',
    kind: 'npm_admission',
    producerJob: 'core-npm-admission-return',
    artifactMember: 'npm-admission-return-v1.enc',
    contextDomain: 'node-feedback-return-context-v1',
    contextFields: FEEDBACK_CONTEXT_FIELDS,
  }),
});
const HEX_256 = /^[a-f0-9]{64}$/u;
const GIT_SHA = /^[a-f0-9]{40}$/u;
const BASE_BRANCHES = new Set(['main', 'develop', 'uat']);
const MAX_API_ID = BigInt(Number.MAX_SAFE_INTEGER);

export class LockEnvelopeError extends Error {
  constructor(code = 'invalid_input') {
    super('Lock envelope rejected');
    this.name = 'LockEnvelopeError';
    this.code = code;
  }
}

function reject(code = 'invalid_input') {
  throw new LockEnvelopeError(code);
}

function plainDataObject(value, keys, code = 'invalid_context') {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) reject(code);
  let prototype;
  let descriptors;
  let ownKeys;
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
    ownKeys = Reflect.ownKeys(value);
  } catch {
    reject(code);
  }
  if (prototype !== Object.prototype && prototype !== null) reject(code);
  if (ownKeys.length !== keys.length || ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key))) {
    reject(code);
  }
  const copy = Object.create(null);
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) reject(code);
    copy[key] = descriptor.value;
  }
  return copy;
}

function isPositiveApiId(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,15}$/u.test(value)) return false;
  try {
    return BigInt(value) <= MAX_API_ID;
  } catch {
    return false;
  }
}

function contextProfile(input) {
  let concern;
  try {
    if (input === null || typeof input !== 'object' || Array.isArray(input)) reject('invalid_context');
    const descriptor = Object.getOwnPropertyDescriptor(input, 'concern');
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) reject('invalid_context');
    concern = descriptor.value;
  } catch (error) {
    if (error instanceof LockEnvelopeError) throw error;
    reject('invalid_context');
  }
  if (typeof concern !== 'string' || !Object.hasOwn(RETURN_PROFILES, concern)) reject('invalid_context');
  const profile = RETURN_PROFILES[concern];
  return profile;
}

export function returnProfileForContext(input) {
  try {
    const profile = contextProfile(input);
    normalizeContext(input, profile);
    return profile;
  } catch (error) {
    if (error instanceof LockEnvelopeError) throw error;
    reject('invalid_context');
  }
}

function normalizeContext(input, profile = contextProfile(input)) {
  const context = plainDataObject(input, profile.contextFields);
  if (typeof context.request_id !== 'string' || !HEX_256.test(context.request_id)) reject('invalid_context');
  if (typeof context.nonce !== 'string' || !HEX_256.test(context.nonce)) reject('invalid_context');
  if (typeof context.recipient_fingerprint !== 'string' || !HEX_256.test(context.recipient_fingerprint)) {
    reject('invalid_context');
  }
  if (context.concern !== profile.concern) reject('invalid_context');
  if (profile.id !== 1 && context.kind !== profile.kind) reject('invalid_context');
  if (!isPositiveApiId(context.repository_id)) reject('invalid_context');
  if (typeof context.source_sha !== 'string' || !GIT_SHA.test(context.source_sha)) reject('invalid_context');
  if (typeof context.base_sha !== 'string' || !GIT_SHA.test(context.base_sha)) reject('invalid_context');
  if (typeof context.control_sha !== 'string' || !GIT_SHA.test(context.control_sha)) reject('invalid_context');
  if (!BASE_BRANCHES.has(context.base_branch)) reject('invalid_context');
  if (typeof context.reviewed_diff_sha256 !== 'string' || !HEX_256.test(context.reviewed_diff_sha256)) {
    reject('invalid_context');
  }
  if (context.workflow_ref !== 'refs/heads/main') reject('invalid_context');
  if (!isPositiveApiId(context.run_id)) reject('invalid_context');
  if (context.producer_job !== profile.producerJob) reject('invalid_context');
  if (context.run_attempt !== 1) reject('invalid_context');
  if (!Number.isSafeInteger(context.expiry) || context.expiry < 1) reject('invalid_context');
  return context;
}

function validateTime(context, now) {
  if (!Number.isSafeInteger(now) || now < 0) reject('invalid_time');
  if (context.expiry <= now || context.expiry - now > LOCK_ENVELOPE_LIMITS.expirySeconds) {
    reject('expired_or_unbounded');
  }
}

/** Return the canonical ASCII AAD record for one validated return profile. */
export function canonicalContext(input) {
  const profile = contextProfile(input);
  const context = normalizeContext(input, profile);
  const lines = [profile.contextDomain];
  for (const field of profile.contextFields) lines.push(`${field}=${context[field]}`);
  const bytes = Buffer.from(`${lines.join('\n')}\n`, 'ascii');
  if (bytes.byteLength > LOCK_ENVELOPE_LIMITS.contextBytes) reject('context_too_large');
  return bytes;
}

/** Parse canonical bytes and reject duplicate, reordered, unknown, or non-ASCII fields. */
function parseCanonicalContextUnchecked(input) {
  if (!(input instanceof Uint8Array) || input.byteLength > LOCK_ENVELOPE_LIMITS.contextBytes) {
    reject('invalid_context');
  }
  const bytes = Buffer.from(input);
  if (bytes.some((byte) => byte > 0x7f)) reject('invalid_context');
  const text = bytes.toString('ascii');
  if (!text.endsWith('\n') || text.includes('\r')) reject('invalid_context');
  const lines = text.slice(0, -1).split('\n');
  const domain = lines[0];
  const domainFields = domain === 'node-lock-return-context-v1'
    ? LOCK_CONTEXT_FIELDS
    : domain === 'node-feedback-return-context-v1' ? FEEDBACK_CONTEXT_FIELDS : null;
  if (!domainFields || lines.length !== domainFields.length + 1) reject('invalid_context');
  const context = Object.create(null);
  for (let index = 0; index < domainFields.length; index += 1) {
    const field = domainFields[index];
    const prefix = `${field}=`;
    const line = lines[index + 1];
    if (!line.startsWith(prefix)) reject('invalid_context');
    context[field] = line.slice(prefix.length);
  }
  if (!/^[1-9][0-9]{0,15}$/u.test(context.run_attempt)) reject('invalid_context');
  if (!/^[1-9][0-9]{0,15}$/u.test(context.expiry)) reject('invalid_context');
  context.run_attempt = Number(context.run_attempt);
  context.expiry = Number(context.expiry);
  const profile = contextProfile(context);
  if (profile.contextDomain !== domain) reject('invalid_context');
  const canonical = canonicalContext(context);
  if (!canonical.equals(bytes)) reject('invalid_context');
  return Object.freeze({ ...context });
}

export function parseCanonicalContext(input) {
  try {
    return parseCanonicalContextUnchecked(input);
  } catch (error) {
    if (error instanceof LockEnvelopeError) throw error;
    reject('invalid_context');
  }
}

function asBytes(value, maxBytes, code) {
  if (!(value instanceof Uint8Array) || value.byteLength > maxBytes) reject(code);
  return Buffer.from(value);
}

function checkedRsaKey(input, kind) {
  try {
    // RSA-3072 with exponent 65537 is the only accepted recipient-key profile.
    if (!(input instanceof KeyObject) || input.type !== kind || input.asymmetricKeyType !== 'rsa'
        || input.asymmetricKeyDetails?.modulusLength !== 3072
        || input.asymmetricKeyDetails?.publicExponent !== 65537n) reject('invalid_key');
    return input;
  } catch (error) {
    if (error instanceof LockEnvelopeError) throw error;
    reject('invalid_key');
  }
}

function publicFingerprint(publicKey) {
  try {
    const der = publicKey.export({ format: 'der', type: 'spki' });
    return createHash('sha256').update(der).digest('hex');
  } catch {
    reject('invalid_key');
  }
}

function contextMaterial(contextInput, now) {
  const profile = contextProfile(contextInput);
  const context = normalizeContext(contextInput, profile);
  validateTime(context, now);
  const aad = canonicalContext(context);
  const digest = createHash('sha256').update(aad).digest();
  const requestId = Buffer.from(context.request_id, 'hex');
  return { context, profile, aad, digest, requestId };
}

function encryptReturnEnvelopeUnchecked({ payloadBytes, recipientPublicKey, context, now }) {
  const material = contextMaterial(context, now);
  const plaintext = asBytes(payloadBytes, LOCK_ENVELOPE_LIMITS.plaintextBytes, 'plaintext_too_large');
  const publicKey = checkedRsaKey(recipientPublicKey, 'public');
  if (publicFingerprint(publicKey) !== material.context.recipient_fingerprint) reject('recipient_mismatch');

  const contentKey = randomBytes(LOCK_ENVELOPE_LIMITS.keyBytes);
  try {
    const wrappedKey = publicEncrypt({
      key: publicKey,
      padding: OAEP_PADDING,
      oaepHash: 'sha256',
      oaepLabel: material.digest,
    }, contentKey);
    if (wrappedKey.byteLength !== LOCK_ENVELOPE_LIMITS.wrappedKeyBytes) reject('invalid_key');

    const iv = randomBytes(LOCK_ENVELOPE_LIMITS.ivBytes);
    const cipher = createCipheriv('aes-256-gcm', contentKey, iv, {
      authTagLength: LOCK_ENVELOPE_LIMITS.tagBytes,
    });
    cipher.setAAD(material.aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const frame = Buffer.alloc(FRAME_OVERHEAD + ciphertext.byteLength);
    let offset = 0;
    MAGIC.copy(frame, offset); offset += MAGIC.byteLength;
    frame[offset++] = VERSION;
    frame[offset++] = material.profile.id;
    material.requestId.copy(frame, offset); offset += 32;
    material.digest.copy(frame, offset); offset += 32;
    wrappedKey.copy(frame, offset); offset += wrappedKey.byteLength;
    iv.copy(frame, offset); offset += iv.byteLength;
    frame.writeUInt32BE(ciphertext.byteLength, offset); offset += 4;
    ciphertext.copy(frame, offset); offset += ciphertext.byteLength;
    tag.copy(frame, offset);
    if (frame.byteLength > LOCK_ENVELOPE_LIMITS.frameBytes) reject('frame_too_large');
    return frame;
  } catch (error) {
    if (error instanceof LockEnvelopeError) throw error;
    reject('encryption_failed');
  } finally {
    contentKey.fill(0);
  }
}

export function encryptReturnEnvelope(options) {
  try {
    return encryptReturnEnvelopeUnchecked(options);
  } catch (error) {
    if (error instanceof LockEnvelopeError) throw error;
    reject('invalid_input');
  }
}

export function encryptLock(options) {
  try {
    if (contextProfile(options?.context).id !== 1) reject('invalid_context');
    return encryptReturnEnvelopeUnchecked({
      payloadBytes: options.lockBytes,
      recipientPublicKey: options.recipientPublicKey,
      context: options.context,
      now: options.now,
    });
  } catch (error) {
    if (error instanceof LockEnvelopeError) throw error;
    reject('invalid_input');
  }
}

function decryptReturnEnvelopeUnchecked({ envelope, recipientPrivateKey, expectedContext, now }) {
  const material = contextMaterial(expectedContext, now);
  const frame = asBytes(envelope, LOCK_ENVELOPE_LIMITS.frameBytes, 'frame_too_large');
  if (frame.byteLength < FRAME_OVERHEAD) reject('invalid_frame');
  if (!frame.subarray(0, MAGIC.byteLength).equals(MAGIC)) reject('invalid_frame');
  if (frame[4] !== VERSION) reject('unsupported_profile');
  if (!Object.values(RETURN_PROFILES).some((profile) => profile.id === frame[5])) reject('unsupported_profile');
  if (frame[5] !== material.profile.id) reject('context_mismatch');

  let offset = 6;
  const requestId = frame.subarray(offset, offset + 32); offset += 32;
  const contextDigest = frame.subarray(offset, offset + 32); offset += 32;
  if (!timingSafeEqual(requestId, material.requestId)
      || !timingSafeEqual(contextDigest, material.digest)) reject('context_mismatch');
  const wrappedKey = frame.subarray(offset, offset + LOCK_ENVELOPE_LIMITS.wrappedKeyBytes);
  offset += LOCK_ENVELOPE_LIMITS.wrappedKeyBytes;
  const iv = frame.subarray(offset, offset + LOCK_ENVELOPE_LIMITS.ivBytes);
  offset += LOCK_ENVELOPE_LIMITS.ivBytes;
  const ciphertextLength = frame.readUInt32BE(offset); offset += 4;
  if (ciphertextLength > LOCK_ENVELOPE_LIMITS.plaintextBytes
      || frame.byteLength !== offset + ciphertextLength + LOCK_ENVELOPE_LIMITS.tagBytes) {
    reject('invalid_frame');
  }
  const ciphertext = frame.subarray(offset, offset + ciphertextLength);
  const tag = frame.subarray(offset + ciphertextLength);
  const privateKey = checkedRsaKey(recipientPrivateKey, 'private');
  let contentKey;
  try {
    const publicKey = createPublicKey(privateKey);
    if (publicFingerprint(publicKey) !== material.context.recipient_fingerprint) reject('recipient_mismatch');
    contentKey = privateDecrypt({
      key: privateKey,
      padding: OAEP_PADDING,
      oaepHash: 'sha256',
      oaepLabel: material.digest,
    }, wrappedKey);
    if (contentKey.byteLength !== LOCK_ENVELOPE_LIMITS.keyBytes) reject('invalid_key');
    const decipher = createDecipheriv('aes-256-gcm', contentKey, iv, {
      authTagLength: LOCK_ENVELOPE_LIMITS.tagBytes,
    });
    decipher.setAAD(material.aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (error) {
    if (error instanceof LockEnvelopeError) throw error;
    reject('authentication_failed');
  } finally {
    if (contentKey instanceof Uint8Array) contentKey.fill(0);
  }
}

export function decryptReturnEnvelope(options) {
  try {
    return decryptReturnEnvelopeUnchecked(options);
  } catch (error) {
    if (error instanceof LockEnvelopeError) throw error;
    reject('invalid_input');
  }
}

export function decryptLock(options) {
  try {
    if (contextProfile(options?.expectedContext).id !== 1) reject('invalid_context');
    return decryptReturnEnvelopeUnchecked(options);
  } catch (error) {
    if (error instanceof LockEnvelopeError) throw error;
    reject('invalid_input');
  }
}
