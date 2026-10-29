import { createHash, createPublicKey } from 'node:crypto';
import { TextDecoder } from 'node:util';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  encryptDevelopmentFeedback,
  encryptDevelopmentFeedbackWithRustSources,
} from './development_feedback.mjs';
import { returnProfileForContext } from './node_lock_envelope.mjs';

const MAX_INPUT_BYTES = 6 * 1024 * 1024;
const REFUSAL_CODES = new Set([
  'credential_like_content', 'envelope_rejected', 'exception_expired', 'invalid_cargo_lock',
  'invalid_context', 'invalid_expectation', 'invalid_input', 'invalid_lock_manifest',
  'invalid_payload', 'invalid_recipient', 'invalid_rust_patch', 'limit_exceeded',
  'payload_too_large', 'unreviewed_rust_path', 'unsupported_kind', 'input_too_large',
  'encryption_failed',
]);
const BASE64_SHAPE = /^[A-Za-z0-9+/]*={0,2}$/u;
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const MAX_RUST_SOURCE_BYTES = 1024 * 1024;

export class FeedbackCryptoError extends Error {
  constructor(code = 'invalid_input') {
    super('Feedback encryption refused');
    this.name = 'FeedbackCryptoError';
    this.code = code;
  }
}

function reject(code = 'invalid_input') {
  throw new FeedbackCryptoError(code);
}

function innerRefusalCode(error) {
  const code = error !== null && typeof error === 'object' && error.name === 'DevelopmentFeedbackError'
    ? error.code : undefined;
  return typeof code === 'string' && REFUSAL_CODES.has(code) ? code : 'encryption_failed';
}

function refusalLine(error) {
  const code = error instanceof FeedbackCryptoError ? error.code : undefined;
  return typeof code === 'string' && REFUSAL_CODES.has(code)
    ? `KD-FEEDBACK-ENCRYPTION-REFUSAL ${code}\n`
    : 'KD-FEEDBACK-ENCRYPTION-REFUSAL\n';
}

function exactObject(value, allowed, required) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  let ownKeys;
  let descriptors;
  let prototype;
  try {
    prototype = Object.getPrototypeOf(value);
    ownKeys = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return false;
  }
  return (prototype === Object.prototype || prototype === null)
    && ownKeys.every((key) => typeof key === 'string' && allowed.includes(key)
      && Object.hasOwn(descriptors[key], 'value') && descriptors[key].enumerable)
    && required.every((key) => Object.hasOwn(descriptors, key));
}

function strictBytes(encoded, limit) {
  if (typeof encoded !== 'string' || encoded.length > Math.ceil(limit / 3) * 4 + 4
      || encoded.length % 4 !== 0 || !BASE64_SHAPE.test(encoded)) {
    reject('invalid_payload');
  }
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.length > limit || bytes.toString('base64') !== encoded) reject('invalid_payload');
  return bytes;
}

function publicKeyFromSpki(encoded, context) {
  const der = strictBytes(encoded, 4096);
  let key;
  try {
    key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    reject('invalid_recipient');
  }
  const details = key.asymmetricKeyDetails;
  const fingerprint = createHash('sha256').update(key.export({ format: 'der', type: 'spki' })).digest('hex');
  if (key.asymmetricKeyType !== 'rsa' || details?.modulusLength !== 3072
      || details.publicExponent !== 65537n || fingerprint !== context.recipient_fingerprint) {
    reject('invalid_recipient');
  }
  return key;
}

function originalRustFiles(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 512) reject('invalid_expectation');
  const files = new Map();
  for (const entry of value) {
    if (!exactObject(entry, ['path', 'content_b64'], ['path', 'content_b64'])
        || typeof entry.path !== 'string' || files.has(entry.path)) reject('invalid_expectation');
    const bytes = strictBytes(entry.content_b64, MAX_RUST_SOURCE_BYTES);
    try {
      UTF8.decode(bytes);
    } catch {
      reject('invalid_payload');
    }
    files.set(entry.path, bytes);
  }
  return files;
}

function validateInput(input) {
  const keys = [
    'schema_version', 'kind', 'payload_b64', 'context', 'recipient_spki_b64', 'now',
    'expected_manifest', 'reviewed_rust_paths', 'original_rust_files_b64',
  ];
  if (!exactObject(input, keys,
    ['schema_version', 'kind', 'payload_b64', 'context', 'recipient_spki_b64', 'now'])
      || input.schema_version !== 1
      || !Number.isSafeInteger(input.now) || input.now < 1
      || !['lock', 'rust_patch', 'build_diagnostics', 'cargo_lock'].includes(input.kind)) {
    reject('invalid_input');
  }
  let profile;
  try {
    profile = returnProfileForContext(input.context);
  } catch {
    reject('invalid_context');
  }
  if (profile.kind !== input.kind) reject('invalid_context');
  const limit = input.kind === 'lock' ? 4 * 1024 * 1024 - 64 * 1024
    : input.kind === 'rust_patch' ? 4 * 1024 * 1024 - 64 * 1024
      : input.kind === 'cargo_lock' ? 1024 * 1024 : 512 * 1024;
  const payloadBytes = strictBytes(input.payload_b64, limit);
  const publicKey = publicKeyFromSpki(input.recipient_spki_b64, input.context);
  const options = {
    payloadBytes,
    context: input.context,
    recipientPublicKey: publicKey,
    now: input.now,
  };
  let trustedOriginalRustFiles;
  if (input.kind === 'lock') {
    if (!Object.hasOwn(input, 'expected_manifest') || Object.hasOwn(input, 'reviewed_rust_paths')
        || Object.hasOwn(input, 'original_rust_files_b64')) {
      reject('invalid_expectation');
    }
    options.expectedManifest = input.expected_manifest;
  } else if (input.kind === 'rust_patch') {
    if (!Object.hasOwn(input, 'reviewed_rust_paths') || Object.hasOwn(input, 'expected_manifest')) {
      reject('invalid_expectation');
    }
    options.reviewedRustPaths = input.reviewed_rust_paths;
    if (Object.hasOwn(input, 'original_rust_files_b64')) {
      trustedOriginalRustFiles = originalRustFiles(input.original_rust_files_b64);
    }
  } else if (Object.hasOwn(input, 'expected_manifest') || Object.hasOwn(input, 'reviewed_rust_paths')) {
    reject('invalid_expectation');
  } else if (Object.hasOwn(input, 'original_rust_files_b64')) {
    reject('invalid_expectation');
  }
  return { options, payloadBytes, trustedOriginalRustFiles };
}

export function encryptFeedbackPayload(input) {
  try {
    const { options, trustedOriginalRustFiles } = validateInput(input);
    const ciphertext = trustedOriginalRustFiles === undefined
      ? encryptDevelopmentFeedback(options)
      : encryptDevelopmentFeedbackWithRustSources(options, trustedOriginalRustFiles);
    return Buffer.from(ciphertext);
  } catch (error) {
    if (error instanceof FeedbackCryptoError) throw error;
    reject(innerRefusalCode(error));
  }
}

async function readInput() {
  const chunks = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    if (!(Buffer.isBuffer(chunk) || chunk instanceof Uint8Array)
        || chunk.length > MAX_INPUT_BYTES - total) reject('input_too_large');
    total += chunk.length;
    chunks.push(chunk);
  }
  try {
    return JSON.parse(UTF8.decode(Buffer.concat(chunks, total)));
  } catch {
    reject('invalid_input');
  }
}

async function main() {
  const ciphertext = encryptFeedbackPayload(await readInput());
  process.stdout.write(ciphertext);
}

if (process.argv.length === 2) {
  if (typeof process.argv[1] === 'string'
      && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
    try {
      void main().catch((error) => {
        process.stderr.write(refusalLine(error));
        process.exitCode = 1;
      });
    } catch {
      process.stderr.write('KD-FEEDBACK-ENCRYPTION-REFUSAL\n');
      process.exitCode = 1;
    }
  }
}
