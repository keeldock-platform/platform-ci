import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { closeSync, mkdirSync, openSync, rmSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { decryptDevelopmentFeedback, encryptDevelopmentFeedback } from './development_feedback.mjs';

const MEMBER_NAME = 'lock-return-v1.enc';
const MAX_FRAME_BYTES = 4 * 1024 * 1024;
const MAX_EXPIRY = 1_800_835_200;
const CANARY = 'feedback-smoke-canary-7c49b2';

const EXPECTED_MANIFEST = Object.freeze({
  root: Object.freeze({
    name: CANARY,
    version: '1.0.0',
    workspaces: Object.freeze(['packages/*']),
    devDependencies: Object.freeze({ typescript: '6.0.3' }),
  }),
  workspaces: Object.freeze([
    Object.freeze({
      path: 'packages/client-api',
      name: '@fixture/client-api',
      version: '1.0.0',
      dependencies: Object.freeze({ '@fixture/shared': 'workspace:*' }),
    }),
    Object.freeze({ path: 'packages/shared', name: '@fixture/shared', version: '1.0.0' }),
  ]),
});

function lockBytes() {
  const lock = {
    name: CANARY,
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': {
        name: CANARY,
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

function validEnvironment(env) {
  return env !== null && typeof env === 'object'
    && typeof env.CI_SHA === 'string' && /^[a-f0-9]{40}$/u.test(env.CI_SHA)
    && typeof env.GITHUB_RUN_ID === 'string'
    && /^[1-9][0-9]{0,18}$/u.test(env.GITHUB_RUN_ID)
    && Number(env.GITHUB_RUN_ID) <= Number.MAX_SAFE_INTEGER
    && typeof env.GITHUB_REPOSITORY_ID === 'string'
    && /^[1-9][0-9]{0,18}$/u.test(env.GITHUB_REPOSITORY_ID)
    && Number(env.GITHUB_REPOSITORY_ID) <= Number.MAX_SAFE_INTEGER
    && env.GITHUB_RUN_ATTEMPT === '1'
    && typeof env.RUNNER_TEMP === 'string' && isAbsolute(env.RUNNER_TEMP);
}

function buildContext(publicKey, env, now) {
  const fingerprint = createHash('sha256')
    .update(publicKey.export({ format: 'der', type: 'spki' }))
    .digest('hex');
  return {
    request_id: randomBytes(32).toString('hex'),
    nonce: randomBytes(32).toString('hex'),
    recipient_fingerprint: fingerprint,
    concern: 'core-node-lock-return',
    repository_id: env.GITHUB_REPOSITORY_ID,
    source_sha: 'a'.repeat(40),
    base_sha: 'b'.repeat(40),
    control_sha: env.CI_SHA,
    base_branch: 'main',
    reviewed_diff_sha256: 'c'.repeat(64),
    workflow_ref: 'refs/heads/main',
    run_id: env.GITHUB_RUN_ID,
    producer_job: 'node-lock-return',
    run_attempt: 1,
    expiry: now + 3600,
  };
}

function writeOutput(path, digest, size) {
  if (path === undefined) return;
  if (typeof path !== 'string' || !isAbsolute(path)) throw new Error('invalid-input');
  writeFileSync(path, `ciphertext_sha256=${digest}\nciphertext_size=${size}\n`, {
    encoding: 'utf8',
    flag: 'a',
    mode: 0o600,
  });
}

export function createSmokeCiphertext({ env, outputRoot, outputFile, now = Math.floor(Date.now() / 1000) }) {
  if (!validEnvironment(env) || !Number.isSafeInteger(now) || now < 1
      || now + 3600 > MAX_EXPIRY) {
    throw new Error('invalid-input');
  }
  const runnerTemp = resolve(outputRoot ?? env.RUNNER_TEMP);
  if (!isAbsolute(runnerTemp)) throw new Error('invalid-input');
  const outputDirectory = join(runnerTemp, 'feedback-smoke');
  const ciphertextPath = join(outputDirectory, MEMBER_NAME);
  if (outputFile !== undefined && outputFile !== ciphertextPath) throw new Error('invalid-input');

  let directoryCreated = false;
  let fileCreated = false;
  try {
    mkdirSync(outputDirectory, { mode: 0o700 });
    directoryCreated = true;
    const pair = generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 65537 });
    const payload = lockBytes();
    if (!payload.includes(Buffer.from(CANARY, 'utf8'))) throw new Error('fixture-invalid');
    const context = buildContext(pair.publicKey, env, now);
    const envelope = encryptDevelopmentFeedback({
      payloadBytes: payload,
      context,
      recipientPublicKey: pair.publicKey,
      expectedManifest: EXPECTED_MANIFEST,
      now,
    });
    if (!(envelope instanceof Uint8Array) || envelope.byteLength > MAX_FRAME_BYTES) {
      throw new Error('envelope-invalid');
    }
    if (Buffer.from(envelope).includes(Buffer.from(CANARY, 'utf8'))) {
      throw new Error('plaintext-leaked');
    }
    const plaintext = decryptDevelopmentFeedback({
      envelope,
      context,
      recipientPrivateKey: pair.privateKey,
      expectedManifest: EXPECTED_MANIFEST,
      now,
    });
    if (!Buffer.from(plaintext).equals(payload)) throw new Error('roundtrip-failed');
    const digest = createHash('sha256').update(envelope).digest('hex');
    const descriptor = openSync(ciphertextPath, 'wx', 0o600);
    fileCreated = true;
    try {
      writeFileSync(descriptor, envelope);
    } finally {
      closeSync(descriptor);
    }
    writeOutput(env.GITHUB_OUTPUT, digest, envelope.byteLength);
    return Object.freeze({
      ciphertextPath,
      ciphertextSha256: digest,
      ciphertextSize: envelope.byteLength,
      memberName: MEMBER_NAME,
      roundTrip: true,
    });
  } catch (error) {
    if (fileCreated) {
      try { rmSync(ciphertextPath, { force: true }); } catch { /* Cleanup is best effort. */ }
    }
    if (directoryCreated) {
      try { rmSync(outputDirectory, { recursive: true, force: true }); } catch { /* Cleanup is best effort. */ }
    }
    if (error?.message === 'invalid-input' || error?.message === 'roundtrip-failed'
        || error?.message === 'envelope-invalid' || error?.message === 'fixture-invalid'
        || error?.message === 'plaintext-leaked') {
      throw error;
    }
    throw new Error('smoke-failed');
  }
}

function main() {
  if (process.argv.length !== 2) throw new Error('invalid-input');
  const result = createSmokeCiphertext({ env: process.env });
  process.stdout.write(
    `KD-FEEDBACK-CIPHERTEXT schema=1 control-sha=${process.env.CI_SHA}`
    + ` run-id=${process.env.GITHUB_RUN_ID} run-attempt=1 member=${result.memberName}`
    + ` ciphertext-sha256=${result.ciphertextSha256} ciphertext-size=${result.ciphertextSize}`
    + ` roundtrip=passed source=synthetic\n`,
  );
}

if (typeof process.argv[1] === 'string'
    && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`KD-FEEDBACK-REFUSAL reason=${error?.message === 'invalid-input' ? 'invalid_input' : 'smoke_failed'}\n`);
    process.exitCode = 1;
  }
}
