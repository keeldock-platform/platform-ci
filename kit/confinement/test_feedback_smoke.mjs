import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { after, test } from 'node:test';

import { createSmokeCiphertext } from './feedback_smoke.mjs';

const directories = [];
const CONTROL_SHA = 'f'.repeat(40);

function environment(root, overrides = {}) {
  return {
    CI_SHA: CONTROL_SHA,
    GITHUB_RUN_ID: '24680',
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_REPOSITORY_ID: '123456789',
    RUNNER_TEMP: root,
    ...overrides,
  };
}

function temporaryRoot() {
  const path = resolve(mkdtempSync(join(tmpdir(), 'feedback-smoke-')));
  directories.push(path);
  return path;
}

after(() => {
  for (const directory of directories) rmSync(directory, { recursive: true, force: true });
});

test('creates one bounded encrypted fixture and reports only ciphertext metadata', () => {
  const root = temporaryRoot();
  const output = join(root, 'runner-output');
  mkdirSync(output);
  const result = createSmokeCiphertext({
    env: environment(output, { GITHUB_OUTPUT: join(root, 'step-output') }),
    now: 1_793_160_000,
  });
  const bytes = readFileSync(result.ciphertextPath);
  assert.deepEqual(Object.keys(result).sort(), [
    'ciphertextPath', 'ciphertextSha256', 'ciphertextSize', 'memberName', 'roundTrip',
  ]);
  assert.equal(result.memberName, 'lock-return-v1.enc');
  assert.equal(result.roundTrip, true);
  assert.equal(bytes.subarray(0, 4).toString('ascii'), 'KDLE');
  assert.equal(bytes[5], 1);
  assert.equal(bytes.includes(Buffer.from('feedback-smoke-canary-7c49b2')), false);
  assert.equal(bytes.length, result.ciphertextSize);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), result.ciphertextSha256);
  assert.equal(statSync(result.ciphertextPath).isFile(), true);
  assert.match(readFileSync(join(root, 'step-output'), 'utf8'),
    new RegExp(`^ciphertext_sha256=${result.ciphertextSha256}\\nciphertext_size=${bytes.length}\\n$`));
});

test('refuses nonfirst attempts and malformed control identity before creating output', () => {
  for (const overrides of [
    { GITHUB_RUN_ATTEMPT: '2' },
    { CI_SHA: 'not-a-control-sha' },
    { GITHUB_RUN_ID: '0' },
  ]) {
    const root = temporaryRoot();
    const env = environment(join(root, 'runner-output'), overrides);
    assert.throws(() => createSmokeCiphertext({ env, now: 1_793_160_000 }), /invalid-input/u);
    assert.equal(statSync(join(env.RUNNER_TEMP, 'feedback-smoke'), { throwIfNoEntry: false }), undefined);
  }
});

test('refuses output collisions without replacing existing content', () => {
  const root = temporaryRoot();
  const env = environment(join(root, 'runner-output'));
  mkdirSync(env.RUNNER_TEMP);
  const first = createSmokeCiphertext({ env, now: 1_793_160_000 });
  const before = readFileSync(first.ciphertextPath);
  assert.throws(() => createSmokeCiphertext({ env, now: 1_793_160_000 }), /smoke-failed/u);
  assert.deepEqual(readFileSync(first.ciphertextPath), before);
});

test('rejects caller-selected output locations', () => {
  const root = temporaryRoot();
  const env = environment(join(root, 'runner-output'));
  assert.throws(() => createSmokeCiphertext({
    env,
    outputFile: join(root, 'elsewhere.enc'),
    now: 1_793_160_000,
  }), /invalid-input/u);
});

test('refuses synthetic context expiry beyond the approved feedback window', () => {
  const root = temporaryRoot();
  const env = environment(join(root, 'runner-output'));
  assert.throws(() => createSmokeCiphertext({ env, now: 1_800_832_000 }), /invalid-input/u);
  assert.equal(statSync(join(env.RUNNER_TEMP, 'feedback-smoke'), { throwIfNoEntry: false }), undefined);
});

test('CLI entrypoint emits a bounded marker on every native path shape', () => {
  const root = temporaryRoot();
  const runnerTemp = join(root, 'runner-output');
  mkdirSync(runnerTemp);
  const entrypoint = fileURLToPath(new URL('./feedback_smoke.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [entrypoint], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...process.env,
      CI_SHA: CONTROL_SHA,
      GITHUB_RUN_ID: '24680',
      GITHUB_RUN_ATTEMPT: '1',
      GITHUB_REPOSITORY_ID: '123456789',
      RUNNER_TEMP: runnerTemp,
    },
  });
  assert.equal(result.status, 0);
  assert.equal(result.stderr, '');
  assert.match(result.stdout, /^KD-FEEDBACK-CIPHERTEXT schema=1 control-sha=[a-f0-9]{40} run-id=24680 run-attempt=1 member=lock-return-v1\.enc ciphertext-sha256=[a-f0-9]{64} ciphertext-size=[1-9][0-9]* roundtrip=passed source=synthetic\n$/u);
});
