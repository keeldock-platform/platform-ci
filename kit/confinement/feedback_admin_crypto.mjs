import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
} from 'node:crypto';
import {
  constants as fsConstants,
  closeSync,
  fstatSync,
  fchmodSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { dirname, isAbsolute, basename, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const MAX_KEY_BYTES = 16 * 1024;
const MAX_ENVELOPE_BYTES = 4 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES = 4 * 1024 * 1024 - 64 * 1024;
const BASE64_SHAPE = /^[A-Za-z0-9+/]*={0,2}$/u;
const HEX_64 = /^[a-f0-9]{64}$/u;

function refuse() {
  throw new Error('operation refused');
}

function requirePosixOwnerFs() {
  if (typeof process.getuid !== 'function' || process.platform === 'win32') refuse();
}

function exactObject(value, required, optional = []) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) refuse();
  const allowed = new Set([...required, ...optional]);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string' || !allowed.has(key))) refuse();
  for (const key of required) if (!Object.hasOwn(value, key)) refuse();
  const copy = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) refuse();
    copy[key] = descriptor.value;
  }
  return copy;
}

function secureDirectory(directoryPath) {
  if (typeof directoryPath !== 'string' || !isAbsolute(directoryPath)
      || directoryPath.split(sep).some((part) => part === '.' || part === '..')) refuse();
  let current = sep;
  let info;
  for (const part of directoryPath.split(sep).filter(Boolean)) {
    current = current === sep ? current + part : current + sep + part;
    info = lstatSync(current);
    if (info.isSymbolicLink() || !info.isDirectory() || ![0, process.getuid()].includes(info.uid)
        || ((info.mode & 0o022) !== 0 && (info.mode & 0o1000) === 0)) refuse();
  }
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid()
      || (info.mode & 0o777) !== 0o700) refuse();
}

function privateKeyPath(value) {
  if (typeof value !== 'string' || !isAbsolute(value)
      || !/^key-[a-f0-9]{64}\.der$/u.test(basename(value))) refuse();
  secureDirectory(dirname(value));
  return value;
}

function writeAll(fd, bytes) {
  let offset = 0;
  while (offset < bytes.byteLength) offset += writeSync(fd, bytes, offset, bytes.byteLength - offset);
}

function syncParentDirectory(path) {
  const flags = fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW;
  const fd = openSync(dirname(path), flags);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function createRecipientKey(pathInput) {
  const keyPath = privateKeyPath(pathInput);
  const pair = generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 65537 });
  let privateDer;
  let fd;
  let created = false;
  try {
    privateDer = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
    if (!(privateDer instanceof Uint8Array) || privateDer.byteLength === 0 || privateDer.byteLength > MAX_KEY_BYTES) {
      refuse();
    }
    const flags = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW;
    fd = openSync(keyPath, flags, 0o600);
    created = true;
    writeAll(fd, privateDer);
    fsyncSync(fd);
    fchmodSync(fd, 0o400);
    const info = fstatSync(fd);
    if (!info.isFile() || info.uid !== process.getuid() || info.nlink !== 1
        || (info.mode & 0o777) !== 0o400 || info.size !== privateDer.byteLength) refuse();
    syncParentDirectory(keyPath);
    const publicSpki = pair.publicKey.export({ format: 'der', type: 'spki' });
    const fingerprint = createHash('sha256').update(publicSpki).digest('hex');
    return Object.freeze({
      schema_version: 1,
      public_spki_base64: publicSpki.toString('base64'),
      recipient_fingerprint: fingerprint,
      modulus_length: pair.publicKey.asymmetricKeyDetails?.modulusLength,
      public_exponent: pair.publicKey.asymmetricKeyDetails?.publicExponent?.toString(),
    });
  } catch {
    if (created) {
      try {
        unlinkSync(keyPath);
        syncParentDirectory(keyPath);
      } catch { /* Cleanup is best effort. */ }
    }
    refuse();
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* Close is best effort. */ }
    }
    if (privateDer instanceof Uint8Array) privateDer.fill(0);
  }
}

function readPrivateKey(keyPathInput) {
  const keyPath = privateKeyPath(keyPathInput);
  const flags = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW;
  const fd = openSync(keyPath, flags);
  let bytes;
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.uid !== process.getuid() || info.nlink !== 1
        || (info.mode & 0o777) !== 0o400 || info.size <= 0 || info.size > MAX_KEY_BYTES) refuse();
    bytes = readFileSync(fd);
    if (bytes.byteLength !== info.size) refuse();
    return createPrivateKey({ key: bytes, format: 'der', type: 'pkcs8' });
  } catch {
    refuse();
  } finally {
    if (bytes instanceof Uint8Array) bytes.fill(0);
    closeSync(fd);
  }
}

function strictEnvelope(value) {
  if (typeof value !== 'string' || value.length === 0
      || value.length > Math.ceil(MAX_ENVELOPE_BYTES / 3) * 4 + 4
      || value.length % 4 !== 0 || !BASE64_SHAPE.test(value)) refuse();
  const bytes = Buffer.from(value, 'base64');
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_ENVELOPE_BYTES || bytes.toString('base64') !== value) refuse();
  return bytes;
}

function decryptToDescriptor(input) {
  const values = exactObject(input, [
    'operation', 'private_key_path', 'context', 'now', 'envelope_base64', 'plaintext_fd',
  ], ['expected_manifest', 'reviewed_rust_paths']);
  if (values.operation !== 'decrypt' || !Number.isSafeInteger(values.now) || values.now < 0
      || !Number.isSafeInteger(values.plaintext_fd) || values.plaintext_fd < 3) refuse();
  const envelope = strictEnvelope(values.envelope_base64);
  const privateKey = readPrivateKey(values.private_key_path);
  let plaintext;
  try {
    const developmentFeedbackPath = new URL('./development_feedback.mjs', import.meta.url);
    return import(developmentFeedbackPath.href).then(({ decryptDevelopmentFeedback }) => {
      const options = {
        envelope,
        recipientPrivateKey: privateKey,
        context: values.context,
        now: values.now,
      };
      if (Object.hasOwn(values, 'expected_manifest')) options.expectedManifest = values.expected_manifest;
      if (Object.hasOwn(values, 'reviewed_rust_paths')) options.reviewedRustPaths = values.reviewed_rust_paths;
      plaintext = decryptDevelopmentFeedback(options);
      if (!(plaintext instanceof Uint8Array) || plaintext.byteLength > MAX_PLAINTEXT_BYTES) refuse();
      writeAll(values.plaintext_fd, plaintext);
      return Object.freeze({ schema_version: 1, ok: true });
    }).finally(() => {
      if (plaintext instanceof Uint8Array) plaintext.fill(0);
      envelope.fill(0);
    });
  } catch {
    if (plaintext instanceof Uint8Array) plaintext.fill(0);
    envelope.fill(0);
    refuse();
  }
}

async function readRequest() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.byteLength;
    if (size > MAX_INPUT_BYTES) refuse();
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks, size);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  return JSON.parse(text);
}

export async function handleRequest(input) {
  try {
    requirePosixOwnerFs();
    const operation = input?.operation;
    if (operation === 'keygen') {
      const values = exactObject(input, ['operation', 'private_key_path']);
      return createRecipientKey(values.private_key_path);
    }
    if (operation === 'decrypt') return await decryptToDescriptor(input);
    refuse();
  } catch {
    refuse();
  }
}

async function main() {
  try {
    const result = await handleRequest(await readRequest());
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch {
    process.stderr.write('operation refused\n');
    process.exitCode = 1;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
