import { TextDecoder } from 'node:util';

import {
  canonicalContext,
  decryptReturnEnvelope,
  encryptReturnEnvelope,
  LockEnvelopeError,
  parseCanonicalContext,
  returnProfileForContext,
} from './node_lock_envelope.mjs';
import { LOCK_MANIFEST_LIMITS, validateLockManifest } from './node_lock_manifest.mjs';

// Callers must validate the trusted receipt, API evidence, and replay state.
export const DEVELOPMENT_FEEDBACK_LIMITS = Object.freeze({
  exceptionEndUnixSeconds: 1_800_835_200,
  contextLifetimeSeconds: 24 * 60 * 60,
  rustPatchBytes: 1024 * 1024,
  diagnosticBytes: 512 * 1024,
  diagnosticLines: 8192,
  diagnosticLineCodeUnits: 8192,
  rustPatchLines: 32_768,
  rustPatchLineCodeUnits: 16_384,
  rustPatchFiles: 128,
  reviewedRustPaths: 512,
  hunkLines: 16_384,
  hunkCount: 1_000_000,
  cargoLockBytes: 1024 * 1024,
  cargoLockLockBytes: 256 * 1024,
  cargoLockReceiptBytes: 128 * 1024,
  cargoLockEvidenceBytes: 192 * 1024,
});

const PROFILE_KINDS = new Set(['lock', 'rust_patch', 'build_diagnostics', 'cargo_lock']);
const CARGO_LOCK_FIELDS = Object.freeze(['evidence_b64', 'lock_b64', 'receipt_b64', 'schema_version']);
const BASE64_TEXT = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const RUST_PATH = /^(?:[A-Za-z0-9_-][A-Za-z0-9._-]*\/)*[A-Za-z0-9_-][A-Za-z0-9._-]*\.rs$/u;
const TOKEN_SHAPE = /(?:^|[^A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{16,}|npm_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16})(?:$|[^A-Za-z0-9])/u;
const PRIVATE_KEY_HEADER = /-----BEGIN [A-Z0-9 ]{0,64}PRIVATE KEY-----/u;
const CREDENTIAL_ASSIGNMENT = /\b(?:authorization|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|api[_-]?key|private[_-]?key|secret|token|credential)\b\s*[:=]\s*(?:Bearer\s+)?[^\s,;]{8,}/iu;
const BEARER_TOKEN = /\bBearer\s+[A-Za-z0-9._~+/-]{24,}={0,2}/u;
const CREDENTIAL_URL = /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/iu;
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const TYPED_ARRAY_PROTO = Object.getPrototypeOf(Uint8Array.prototype);
const VIEW_BUFFER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'buffer').get;
const VIEW_BYTE_OFFSET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'byteOffset').get;
const VIEW_BYTE_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'byteLength').get;

export class DevelopmentFeedbackError extends Error {
  constructor(code = 'invalid_input') {
    super('Development feedback rejected');
    this.name = 'DevelopmentFeedbackError';
    this.code = code;
  }
}

function reject(code = 'invalid_payload') {
  throw new DevelopmentFeedbackError(code);
}

function dataOptions(input, required = ['payloadBytes', 'context', 'now']) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) reject('invalid_input');
  let prototype;
  let descriptors;
  let keys;
  try {
    prototype = Object.getPrototypeOf(input);
    descriptors = Object.getOwnPropertyDescriptors(input);
    keys = Reflect.ownKeys(input);
  } catch {
    reject('invalid_input');
  }
  const allowed = [
    'payloadBytes', 'context', 'expectedManifest', 'reviewedRustPaths', 'recipientPublicKey',
    'recipientPrivateKey', 'envelope', 'now',
  ];
  if ((prototype !== Object.prototype && prototype !== null)
      || keys.some((key) => typeof key !== 'string' || !allowed.includes(key))) reject('invalid_input');
  const result = Object.create(null);
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) reject('invalid_input');
    result[key] = descriptor.value;
  }
  if (required.some((key) => !Object.hasOwn(result, key))) reject('invalid_input');
  return result;
}

function copyPayload(value, limit) {
  if (!(value instanceof Uint8Array) || !ArrayBuffer.isView(value)) reject('invalid_payload');
  let buffer;
  let offset;
  let length;
  try {
    buffer = Reflect.apply(VIEW_BUFFER, value, []);
    offset = Reflect.apply(VIEW_BYTE_OFFSET, value, []);
    length = Reflect.apply(VIEW_BYTE_LENGTH, value, []);
  } catch {
    reject('invalid_payload');
  }
  if (!(buffer instanceof ArrayBuffer)) reject('invalid_payload');
  if (length > limit) reject('payload_too_large');
  try {
    const copy = Buffer.alloc(length);
    copy.set(new Uint8Array(buffer, offset, length));
    return copy;
  } catch {
    reject('invalid_payload');
  }
}

function rustPaths(input) {
  if (!Array.isArray(input)) {
    reject('invalid_expectation');
  }
  let descriptors;
  let keys;
  try {
    descriptors = Object.getOwnPropertyDescriptors(input);
    keys = Reflect.ownKeys(input);
  } catch {
    reject('invalid_expectation');
  }
  const lengthDescriptor = descriptors.length;
  const length = lengthDescriptor?.value;
  if (!Number.isSafeInteger(length) || length < 1 || length > DEVELOPMENT_FEEDBACK_LIMITS.reviewedRustPaths
      || keys.length !== length + 1 || keys.some((key) => key !== 'length'
        && (typeof key !== 'string' || !/^(?:0|[1-9][0-9]*)$/u.test(key) || Number(key) >= length))) {
    reject('invalid_expectation');
  }
  const paths = new Set();
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) reject('invalid_expectation');
    const path = descriptor.value;
    if (typeof path !== 'string' || path.length > 256 || !RUST_PATH.test(path)
        || path.split('/').some((part) => part === '.' || part === '..') || paths.has(path)) {
      reject('invalid_expectation');
    }
    paths.add(path);
  }
  return paths;
}

function decodeText(bytes, maxLines, maxLineCodeUnits) {
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) reject('invalid_payload');
  let text;
  try {
    text = UTF8.decode(bytes);
  } catch {
    reject('invalid_payload');
  }
  if (text.includes('\0') || text.includes('\r')) reject('invalid_payload');
  let lineCount = 1;
  let lineLength = 0;
  for (const character of text) {
    if (character === '\n') {
      lineCount += 1;
      lineLength = 0;
      if (lineCount > maxLines) reject('limit_exceeded');
    } else {
      lineLength += character.length;
      if (lineLength > maxLineCodeUnits) reject('limit_exceeded');
      const code = character.codePointAt(0);
      if (code < 0x20 && code !== 0x09) reject('invalid_payload');
      if (code >= 0x7f && code <= 0x9f) reject('invalid_payload');
    }
  }
  return text;
}

function readHunkHeader(line) {
  const match = /^@@ -(0|[1-9][0-9]*)(?:,(0|[1-9][0-9]*))? \+(0|[1-9][0-9]*)(?:,(0|[1-9][0-9]*))? @@(?: .*)?$/u.exec(line);
  if (!match) reject('invalid_rust_patch');
  const oldStart = Number(match[1]);
  const oldCount = match[2] === undefined ? 1 : Number(match[2]);
  const newStart = Number(match[3]);
  const newCount = match[4] === undefined ? 1 : Number(match[4]);
  if (![oldStart, oldCount, newStart, newCount].every(Number.isSafeInteger)
      || oldStart > DEVELOPMENT_FEEDBACK_LIMITS.hunkCount
      || oldCount > DEVELOPMENT_FEEDBACK_LIMITS.hunkCount
      || newStart > DEVELOPMENT_FEEDBACK_LIMITS.hunkCount
      || newCount > DEVELOPMENT_FEEDBACK_LIMITS.hunkCount) reject('invalid_rust_patch');
  return { oldStart, oldCount, newStart, newCount };
}

function parseRustPatch(text, reviewedPaths) {
  if (!text.endsWith('\n')) reject('invalid_rust_patch');
  const lines = text.slice(0, -1).split('\n');
  if (lines.length > DEVELOPMENT_FEEDBACK_LIMITS.rustPatchLines) reject('limit_exceeded');
  const changedPaths = new Set();
  let index = 0;
  while (index < lines.length) {
    const fileHeader = /^diff --git a\/([^ ]+) b\/([^ ]+)$/u.exec(lines[index]);
    if (!fileHeader) reject('invalid_rust_patch');
    const oldPath = fileHeader[1];
    const newPath = fileHeader[2];
    if (oldPath !== newPath || !RUST_PATH.test(oldPath) || !reviewedPaths.has(oldPath)
        || changedPaths.has(oldPath)) reject('unreviewed_rust_path');
    changedPaths.add(oldPath);
    index += 1;
    if (index < lines.length && lines[index].startsWith('index ')) {
      if (!/^index [a-f0-9]{7,64}\.{2}[a-f0-9]{7,64}(?: 100644)?$/u.test(lines[index])) {
        reject('invalid_rust_patch');
      }
      index += 1;
    }
    if (lines[index] !== `--- a/${oldPath}` || lines[index + 1] !== `+++ b/${newPath}`) {
      reject('invalid_rust_patch');
    }
    index += 2;
    let hunkCount = 0;
    let hasEdit = false;
    let previousOldEnd = 0;
    let previousNewEnd = 0;
    while (index < lines.length && lines[index].startsWith('@@ ')) {
      const hunk = readHunkHeader(lines[index]);
      if ((hunkCount > 0 && (hunk.oldStart < previousOldEnd || hunk.newStart < previousNewEnd))) {
        reject('invalid_rust_patch');
      }
      previousOldEnd = hunk.oldStart + hunk.oldCount;
      previousNewEnd = hunk.newStart + hunk.newCount;
      index += 1;
      let oldSeen = 0;
      let newSeen = 0;
      let bodyLines = 0;
      let canMarkNoNewline = false;
      while (index < lines.length && !lines[index].startsWith('@@ ')
          && !lines[index].startsWith('diff --git ')) {
        const line = lines[index];
        if (line === '\\ No newline at end of file') {
          if (!canMarkNoNewline) reject('invalid_rust_patch');
          canMarkNoNewline = false;
          index += 1;
          continue;
        }
        if (![' ', '+', '-'].includes(line[0])) reject('invalid_rust_patch');
        if (line[0] !== ' ') hasEdit = true;
        if (line[0] !== '+') oldSeen += 1;
        if (line[0] !== '-') newSeen += 1;
        bodyLines += 1;
        if (oldSeen > hunk.oldCount || newSeen > hunk.newCount
            || bodyLines > DEVELOPMENT_FEEDBACK_LIMITS.hunkLines) reject('invalid_rust_patch');
        canMarkNoNewline = true;
        index += 1;
      }
      if (oldSeen !== hunk.oldCount || newSeen !== hunk.newCount || bodyLines === 0) {
        reject('invalid_rust_patch');
      }
      hunkCount += 1;
    }
    if (hunkCount === 0 || !hasEdit) reject('invalid_rust_patch');
    if (changedPaths.size > DEVELOPMENT_FEEDBACK_LIMITS.rustPatchFiles) reject('limit_exceeded');
  }
  if (changedPaths.size === 0) reject('invalid_rust_patch');
}

function validateDiagnosticText(text) {
  // These checks cover common credential shapes, not every possible secret.
  if (TOKEN_SHAPE.test(text) || PRIVATE_KEY_HEADER.test(text) || CREDENTIAL_ASSIGNMENT.test(text)
      || BEARER_TOKEN.test(text) || CREDENTIAL_URL.test(text)) reject('credential_like_content');
}

function validatedContext(contextInput) {
  try {
    const context = parseCanonicalContext(canonicalContext(contextInput));
    const profile = returnProfileForContext(context);
    return { profile, context };
  } catch {
    reject('invalid_context');
  }
}

function validateExceptionWindow(context, now) {
  const end = DEVELOPMENT_FEEDBACK_LIMITS.exceptionEndUnixSeconds;
  if (!Number.isSafeInteger(now) || now < 0 || now >= end
      || !Number.isSafeInteger(context.expiry) || context.expiry <= now || context.expiry > end
      || context.expiry - now > DEVELOPMENT_FEEDBACK_LIMITS.contextLifetimeSeconds) {
    reject('exception_expired');
  }
}

function cargoLockMember(value, limit, multiline) {
  if (typeof value !== 'string' || value.length === 0) reject('invalid_cargo_lock');
  if (value.length > Math.ceil(limit / 3) * 4) reject('payload_too_large');
  if (!BASE64_TEXT.test(value)) reject('invalid_cargo_lock');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.byteLength === 0 || bytes.toString('base64') !== value) reject('invalid_cargo_lock');
  if (bytes.byteLength > limit) reject('payload_too_large');
  for (const byte of bytes) {
    if (byte > 0x7e || (byte < 0x20 && !(multiline && byte === 0x0a))) reject('invalid_cargo_lock');
  }
  if (multiline && bytes[bytes.byteLength - 1] !== 0x0a) reject('invalid_cargo_lock');
  return bytes;
}

function validateCargoLockBundle(bytes) {
  if (bytes.byteLength > DEVELOPMENT_FEEDBACK_LIMITS.cargoLockBytes) reject('payload_too_large');
  if (bytes.byteLength === 0) reject('invalid_cargo_lock');
  let text;
  let parsed;
  try {
    text = UTF8.decode(bytes);
    parsed = JSON.parse(text);
  } catch {
    reject('invalid_cargo_lock');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) reject('invalid_cargo_lock');
  const keys = Object.keys(parsed).sort();
  if (keys.length !== CARGO_LOCK_FIELDS.length
      || keys.some((key, index) => key !== CARGO_LOCK_FIELDS[index])
      || parsed.schema_version !== 1) reject('invalid_cargo_lock');
  cargoLockMember(parsed.lock_b64, DEVELOPMENT_FEEDBACK_LIMITS.cargoLockLockBytes, true);
  cargoLockMember(parsed.receipt_b64, DEVELOPMENT_FEEDBACK_LIMITS.cargoLockReceiptBytes, false);
  cargoLockMember(parsed.evidence_b64, DEVELOPMENT_FEEDBACK_LIMITS.cargoLockEvidenceBytes, false);
  const canonical = JSON.stringify({
    evidence_b64: parsed.evidence_b64,
    lock_b64: parsed.lock_b64,
    receipt_b64: parsed.receipt_b64,
    schema_version: 1,
  });
  if (canonical !== text) reject('invalid_cargo_lock');
}

function validatePayload(bytes, profile, options) {
  if (!PROFILE_KINDS.has(profile.kind)) reject('unsupported_kind');
  if (profile.kind === 'cargo_lock') {
    if (Object.hasOwn(options, 'expectedManifest') || Object.hasOwn(options, 'reviewedRustPaths')) {
      reject('invalid_expectation');
    }
    validateCargoLockBundle(bytes);
    return;
  }
  if (profile.kind === 'lock') {
    if (!Object.hasOwn(options, 'expectedManifest')) reject('invalid_expectation');
    try {
      validateLockManifest(bytes, options.expectedManifest);
    } catch {
      reject('invalid_lock_manifest');
    }
    return;
  }
  if (profile.kind === 'rust_patch') {
    const reviewedPaths = rustPaths(options.reviewedRustPaths);
    if (bytes.byteLength > DEVELOPMENT_FEEDBACK_LIMITS.rustPatchBytes) reject('payload_too_large');
    const text = decodeText(bytes, DEVELOPMENT_FEEDBACK_LIMITS.rustPatchLines,
      DEVELOPMENT_FEEDBACK_LIMITS.rustPatchLineCodeUnits);
    validateDiagnosticText(text);
    parseRustPatch(text, reviewedPaths);
    return;
  }
  if (bytes.byteLength > DEVELOPMENT_FEEDBACK_LIMITS.diagnosticBytes) reject('payload_too_large');
  const text = decodeText(bytes, DEVELOPMENT_FEEDBACK_LIMITS.diagnosticLines,
    DEVELOPMENT_FEEDBACK_LIMITS.diagnosticLineCodeUnits);
  validateDiagnosticText(text);
}

function payloadLimit(kind) {
  if (kind === 'rust_patch') return DEVELOPMENT_FEEDBACK_LIMITS.rustPatchBytes;
  if (kind === 'build_diagnostics') return DEVELOPMENT_FEEDBACK_LIMITS.diagnosticBytes;
  if (kind === 'cargo_lock') return DEVELOPMENT_FEEDBACK_LIMITS.cargoLockBytes;
  return LOCK_MANIFEST_LIMITS.inputBytes;
}

function prepare(options) {
  const input = dataOptions(options);
  const { profile, context } = validatedContext(input.context);
  validateExceptionWindow(context, input.now);
  input.context = context;
  const payloadBytes = copyPayload(input.payloadBytes, payloadLimit(profile.kind));
  validatePayload(payloadBytes, profile, input);
  return { input, profile, payloadBytes };
}

/** Validate one bounded payload against its closed return profile. */
export function validateDevelopmentFeedback(options) {
  try {
    return Buffer.from(prepare(options).payloadBytes);
  } catch (error) {
    if (error instanceof DevelopmentFeedbackError) throw error;
    reject('invalid_payload');
  }
}

/** Validate a payload before encrypting it for the supplied return context. */
export function encryptDevelopmentFeedback(options) {
  try {
    const prepared = prepare(options);
    return encryptReturnEnvelope({
      payloadBytes: prepared.payloadBytes,
      recipientPublicKey: prepared.input.recipientPublicKey,
      context: prepared.input.context,
      now: prepared.input.now,
    });
  } catch (error) {
    if (error instanceof DevelopmentFeedbackError) throw error;
    if (error instanceof LockEnvelopeError) reject('envelope_rejected');
    reject('invalid_input');
  }
}

/** Authenticate and validate one bounded return payload before exposing its bytes. */
export function decryptDevelopmentFeedback(options) {
  try {
    const input = dataOptions(options, ['context', 'envelope', 'recipientPrivateKey', 'now']);
    const { profile, context } = validatedContext(input.context);
    validateExceptionWindow(context, input.now);
    const payloadBytes = decryptReturnEnvelope({
      envelope: input.envelope,
      recipientPrivateKey: input.recipientPrivateKey,
      expectedContext: context,
      now: input.now,
    });
    validatePayload(copyPayload(payloadBytes, payloadLimit(profile.kind)), profile, input);
    return Buffer.from(payloadBytes);
  } catch (error) {
    if (error instanceof DevelopmentFeedbackError) throw error;
    if (error instanceof LockEnvelopeError) reject('envelope_rejected');
    reject('invalid_input');
  }
}
