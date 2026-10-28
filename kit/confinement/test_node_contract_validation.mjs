import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import {
  closeSync, chmodSync, fsyncSync, mkdirSync, mkdtempSync, openSync,
  readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';

import {
  NODE_CONTRACT_POLICY,
  NodeContractError,
  main,
  validateNodeDependencyLock,
} from './node_contract_validation.mjs';

function hostedTest(name, callback) {
  test(name, callback);
}

function posixHostedTest(name, callback) {
  test(name, { skip: process.platform === 'win32' ? 'requires POSIX private-file ownership and tool paths' : false }, callback);
}

const identity = Object.freeze({
  source_sha: '1'.repeat(40),
  base_sha: '2'.repeat(40),
  control_sha: '3'.repeat(40),
  reviewed_diff_sha256: '4'.repeat(64),
});

const expectedManifest = Object.freeze({
  root: Object.freeze({
    name: 'fixture-root',
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

function lockFixture(extraPackageCount = 0, nestedEntries = false) {
  const packages = {
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
  };
  for (let index = 0; index < extraPackageCount; index += 1) {
    const name = `fixture-transitive-${String(index).padStart(4, '0')}`;
    packages[`node_modules/${name}`] = {
      version: '1.0.0',
      resolved: `https://registry.npmjs.org/${name}/-/${name}-1.0.0.tgz`,
      integrity: `sha512-${'A'.repeat(86)}==`,
    };
  }
  if (nestedEntries) {
    packages['node_modules/fixture-parent'] = {
      version: '1.0.0',
      resolved: 'https://registry.npmjs.org/fixture-parent/-/fixture-parent-1.0.0.tgz',
      integrity: `sha512-${'A'.repeat(86)}==`,
    };
    packages['node_modules/fixture-parent/node_modules/fixture-nested'] = {
      version: '3.0.0',
      resolved: 'https://registry.npmjs.org/fixture-nested/-/fixture-nested-3.0.0.tgz',
      integrity: `sha512-${'A'.repeat(86)}==`,
    };
    packages['packages/client-api/node_modules/@fixture/nested'] = {
      version: '2.0.0',
      resolved: 'https://registry.npmjs.org/@fixture/nested/-/nested-2.0.0.tgz',
      integrity: `sha512-${'A'.repeat(86)}==`,
    };
  }
  return Buffer.from(`${JSON.stringify({
    name: 'fixture-root',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages,
  })}\n`, 'utf8');
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function npmCliPath() {
  const runtimeRoot = process.platform === 'win32'
    ? dirname(process.execPath)
    : dirname(dirname(process.execPath));
  const npmSuffix = process.platform === 'win32'
    ? 'node_modules/npm/bin/npm-cli.js'
    : 'lib/node_modules/npm/bin/npm-cli.js';
  return resolve(runtimeRoot, npmSuffix);
}

function spawnBounded(executable, args, options, timeoutMs = 30_000) {
  return new Promise((accept) => {
    const child = spawn(executable, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] });
    const output = { stdout: [], stderr: [], stdoutBytes: 0, stderrBytes: 0, oversized: false };
    let timedOut = false;
    let finished = false;
    const finish = (status, signal) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      accept({
        status: timedOut || output.oversized ? null : status,
        signal,
        stdout: Buffer.concat(output.stdout).toString('utf8'),
        stderr: Buffer.concat(output.stderr).toString('utf8'),
        timedOut,
        oversized: output.oversized,
      });
    };
    const collect = (stream, field) => stream.on('data', (chunk) => {
      const sizeKey = `${field}Bytes`;
      const remaining = Math.max(0, (64 * 1024) - output[sizeKey]);
      if (chunk.byteLength > remaining) {
        if (remaining > 0) output[field].push(chunk.subarray(0, remaining));
        output[sizeKey] += remaining;
        output.oversized = true;
        child.kill('SIGKILL');
        return;
      }
      output[field].push(chunk);
      output[sizeKey] += chunk.byteLength;
    });
    collect(child.stdout, 'stdout');
    collect(child.stderr, 'stderr');
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);
    child.once('error', () => finish(null, null));
    child.once('close', finish);
  });
}

function proof(lockBytes, policyEpochMs, manifest = expectedManifest, source = identity) {
  return {
    schema_version: 1,
    status: 'generated',
    generation_identity: source,
    lock_sha256: sha256(lockBytes),
    manifest_sha256: sha256(Buffer.from(canonicalJson(manifest), 'ascii')),
    node_version: NODE_CONTRACT_POLICY.nodeVersion,
    npm_version: NODE_CONTRACT_POLICY.npmVersion,
    release_age_days: NODE_CONTRACT_POLICY.releaseAgeDays,
    policy_epoch_ms: policyEpochMs,
    cutoff_epoch_ms: policyEpochMs - (7 * 24 * 60 * 60 * 1000),
    age_status: 'passed',
    generation_attempts: 1,
  };
}

function acceptedProvenance(lockBytes, policyEpochMs, source = identity, generation = {
  source_sha: 'a'.repeat(40),
  base_sha: 'b'.repeat(40),
  control_sha: 'c'.repeat(40),
  reviewed_diff_sha256: 'd'.repeat(64),
}) {
  return {
    schema_version: 1,
    status: 'accepted',
    generation_identity: generation,
    accepted_source_identity: source,
    lock_sha256: sha256(lockBytes),
    manifest_sha256: sha256(Buffer.from(canonicalJson(expectedManifest), 'ascii')),
    node_version: NODE_CONTRACT_POLICY.nodeVersion,
    npm_version: NODE_CONTRACT_POLICY.npmVersion,
    release_age_days: NODE_CONTRACT_POLICY.releaseAgeDays,
    policy_epoch_ms: policyEpochMs,
    cutoff_epoch_ms: policyEpochMs - (7 * 24 * 60 * 60 * 1000),
    age_status: 'passed',
    generation_attempts: 1,
    audit_endpoint: NODE_CONTRACT_POLICY.auditEndpoint,
    audit_status: 'passed',
    accepted_at_ms: policyEpochMs + 1000,
  };
}

async function validate({
  mode = 'bootstrap',
  lockBytes = lockFixture(),
  manifest = expectedManifest,
  source = identity,
  policyEpochMs = Date.now() - 10_000,
  accepted = undefined,
  responseBody = '{}',
  fetchImpl,
} = {}) {
  const nowMs = Date.now();
  const calls = [];
  const fetcher = fetchImpl ?? (async (url, options) => {
    calls.push({ url, options });
    return new Response(responseBody, {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  });
  const result = await validateNodeDependencyLock({
    mode,
    lockBytes,
    expectedManifest: manifest,
    sourceIdentity: source,
    npmCliPath: npmCliPath(),
    generationProof: mode === 'bootstrap' ? proof(lockBytes, policyEpochMs, manifest, source) : undefined,
    acceptedProvenance: mode === 'verify'
      ? accepted ?? acceptedProvenance(lockBytes, policyEpochMs, source)
      : undefined,
    policyEpochMs: mode === 'bootstrap' ? policyEpochMs : undefined,
    nowMs,
    deadlineMs: nowMs + 60_000,
    fetchImpl: fetcher,
  });
  return { result, calls, nowMs, lockBytes, policyEpochMs };
}

hostedTest('bulk audit sends only public remote package versions to the fixed endpoint', async () => {
  const { result, calls } = await validate();
  assert.equal(result.status, 'passed');
  assert.equal(result.audit_status, 'passed');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk');
  assert.equal(calls[0].options.method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].options.body), { typescript: ['6.0.3'] });
  assert.equal(Object.hasOwn(calls[0].options.headers, 'authorization'), false);
  assert.equal(calls[0].options.redirect, 'error');
});

hostedTest('bulk inventory includes nested root and workspace package versions without local names', async () => {
  const { calls, result } = await validate({ lockBytes: lockFixture(0, true) });
  assert.equal(result.remote_package_count, 4);
  assert.deepEqual(JSON.parse(calls[0].options.body), {
    '@fixture/nested': ['2.0.0'],
    'fixture-nested': ['3.0.0'],
    'fixture-parent': ['1.0.0'],
    typescript: ['6.0.3'],
  });
});

hostedTest('audit refuses vulnerable and unrequested package responses without a quick-audit fallback', async () => {
  const benign = await validate({ responseBody: JSON.stringify({
    typescript: [{ name: 'typescript', vulnerable_versions: '<6.0.0', cvss: 7.5 }],
  }) });
  assert.equal(benign.result.advisory_count, 1);
  await assert.rejects(
    validate({ responseBody: JSON.stringify({
      typescript: [{ name: 'typescript', vulnerable_versions: '<6.0.4' }],
    }) }),
    (error) => error instanceof NodeContractError && error.code === 'vulnerable_dependency',
  );
  const benignNoName = await validate({ responseBody: JSON.stringify({
    typescript: [{ vulnerable_versions: '<6.0.0', cvss: 7.5 }],
  }) });
  assert.equal(benignNoName.result.advisory_count, 1);
  await assert.rejects(
    validate({ responseBody: JSON.stringify({
      typescript: [{ vulnerable_versions: '<6.0.4' }],
    }) }),
    (error) => error instanceof NodeContractError && error.code === 'vulnerable_dependency',
  );
  await assert.rejects(
    validate({ responseBody: JSON.stringify({
      typescript: [{ name: 'other-package', vulnerable_versions: '<6.0.0' }],
    }) }),
    (error) => error instanceof NodeContractError && error.code === 'audit_response_invalid',
  );
  let calls = 0;
  await assert.rejects(
    validate({ responseBody: JSON.stringify({ unknown: [] }), fetchImpl: async () => {
      calls += 1;
      return new Response('{"unknown":[]}', { headers: { 'content-type': 'application/json' } });
    } }),
    (error) => error instanceof NodeContractError && error.code === 'audit_response_invalid',
  );
  assert.equal(calls, 1);
  let unavailableCalls = 0;
  await assert.rejects(
    validate({ fetchImpl: async () => {
      unavailableCalls += 1;
      return new Response('unavailable', { status: 503, headers: { 'content-type': 'text/plain' } });
    } }),
    (error) => error instanceof NodeContractError && error.code === 'audit_unavailable',
  );
  assert.equal(unavailableCalls, 1);
  await assert.rejects(
    validate({ responseBody: '{"typescript":[],"typescript":[]}' }),
    (error) => error instanceof NodeContractError && error.code === 'audit_response_invalid',
  );
});

hostedTest('provenance binds lock, manifest, and current source while allowing the bootstrap commit to differ', async () => {
  const lockBytes = lockFixture();
  const policyEpochMs = Date.now() - (30 * 24 * 60 * 60 * 1000);
  const output = await validate({
    mode: 'verify', lockBytes, policyEpochMs,
    accepted: acceptedProvenance(lockBytes, policyEpochMs),
  });
  assert.equal(output.result.policy_epoch_ms, policyEpochMs);
  assert.equal(output.calls.length, 1);

  const badLock = Buffer.concat([lockBytes, Buffer.from(' ', 'ascii')]);
  await assert.rejects(validate({
    mode: 'verify', lockBytes: badLock, policyEpochMs,
    accepted: acceptedProvenance(lockBytes, policyEpochMs),
  }), (error) => error instanceof NodeContractError && error.code === 'accepted_provenance_invalid');

  const changedManifest = JSON.parse(JSON.stringify(expectedManifest));
  changedManifest.root.version = '1.0.1';
  await assert.rejects(validate({
    mode: 'verify', lockBytes, manifest: changedManifest, policyEpochMs,
    accepted: acceptedProvenance(lockBytes, policyEpochMs),
  }), (error) => error instanceof NodeContractError && error.code === 'manifest_invalid');
});

hostedTest('bootstrap rejects a policy epoch outside the request window before contacting npm registry', async () => {
  let calls = 0;
  const nowMs = Date.now();
  await assert.rejects(validate({
    policyEpochMs: nowMs - (24 * 60 * 60 * 1000) - 1,
    fetchImpl: async () => {
      calls += 1;
      return new Response('{}', { headers: { 'content-type': 'application/json' } });
    },
  }), (error) => error instanceof NodeContractError && error.code === 'accepted_provenance_invalid');
  assert.equal(calls, 0);
});

posixHostedTest('private RPC accepts a bounded lock larger than the ordinary audit string limit', async (context) => {
  const lockBytes = lockFixture(400);
  assert.ok(lockBytes.byteLength > 48 * 1024);
  const nowMs = Date.now();
  const policyEpochMs = nowMs - 10_000;
  const record = {
    schema_version: 1,
    mode: 'bootstrap',
    lock_base64: lockBytes.toString('base64'),
    expected_manifest: expectedManifest,
    source_identity: identity,
    npm_cli_path: npmCliPath(),
    generation_proof: proof(lockBytes, policyEpochMs),
    accepted_provenance: null,
    now_ms: nowMs,
    deadline_ms: nowMs + 60_000,
    policy_epoch_ms: policyEpochMs,
  };
  const root = mkdtempSync(resolve(tmpdir(), 'fixture-node-contract-'));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const requestPath = resolve(root, 'request.json');
  const descriptor = openSync(requestPath, 'wx', 0o600);
  try {
    writeFileSync(descriptor, JSON.stringify(record), 'utf8');
    fsyncSync(descriptor);
    chmodSync(requestPath, 0o600);
  } finally {
    closeSync(descriptor);
  }
  const calls = [];
  const originalWrite = process.stdout.write;
  const outputChunks = [];
  process.stdout.write = (chunk) => {
    outputChunks.push(Buffer.from(chunk));
    return true;
  };
  let code;
  try {
    code = await main(['--request', requestPath], {
      fetchImpl: async (url, options) => {
        calls.push({ url, options });
        return new Response('{}', { headers: { 'content-type': 'application/json' } });
      },
    });
  } finally {
    process.stdout.write = originalWrite;
  }
  assert.equal(code, 0);
  const response = JSON.parse(Buffer.concat(outputChunks).toString('utf8'));
  assert.equal(response.status, 'passed');
  assert.equal(response.result.lock_sha256, sha256(lockBytes));
  assert.equal(response.result.remote_package_count, 401);
  assert.equal(calls.length, 1);
});

posixHostedTest('the pinned npm honors one immutable cutoff against a synthetic local registry', async (context) => {
  assert.equal(process.version, `v${NODE_CONTRACT_POLICY.nodeVersion}`);
  const cli = npmCliPath();
  const npmVersion = await spawnBounded(process.execPath, [cli, '--version'], {}, 10_000);
  assert.equal(npmVersion.status, 0, npmVersion.stderr.slice(0, 1024));
  assert.equal(npmVersion.stdout.trim(), NODE_CONTRACT_POLICY.npmVersion);

  const now = Date.now();
  const policyEpochMs = now - 10_000;
  const cutoff = new Date(policyEpochMs - (7 * 24 * 60 * 60 * 1000)).toISOString();
  const oldTime = new Date(now - (10 * 24 * 60 * 60 * 1000)).toISOString();
  const youngTime = new Date(now - (24 * 60 * 60 * 1000)).toISOString();
  const packageName = 'fixture-age-package';
  const integrity = `sha512-${'B'.repeat(86)}==`;
  const packument = JSON.stringify({
    _id: packageName,
    name: packageName,
    'dist-tags': { latest: '1.1.0' },
    versions: {
      '1.0.0': {
        name: packageName,
        version: '1.0.0',
        dist: { tarball: `http://127.0.0.1/${packageName}/-/${packageName}-1.0.0.tgz`, integrity },
      },
      '1.1.0': {
        name: packageName,
        version: '1.1.0',
        dist: { tarball: `http://127.0.0.1/${packageName}/-/${packageName}-1.1.0.tgz`, integrity },
      },
    },
    time: { created: oldTime, modified: youngTime, '1.0.0': oldTime, '1.1.0': youngTime },
  });
  const requests = [];
  const server = createServer((request, response) => {
    requests.push(request.url);
    response.writeHead(200, { 'content-type': 'application/vnd.npm.install-v1+json' });
    response.end(packument);
  });
  await new Promise((accept, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', accept);
  });
  context.after(() => new Promise((accept) => server.close(accept)));

  const root = mkdtempSync(resolve(tmpdir(), 'fixture-npm-age-'));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const registry = `http://127.0.0.1:${server.address().port}/`;
  const configRoot = resolve(root, 'npm-config');
  mkdirSync(configRoot, { mode: 0o700 });
  const userConfig = resolve(configRoot, 'npm-user-empty.npmrc');
  const globalConfig = resolve(configRoot, 'npm-global-empty.npmrc');
  for (const configPath of [userConfig, globalConfig]) {
    const descriptor = openSync(configPath, 'wx', 0o600);
    try {
      writeFileSync(descriptor, '\n', 'utf8');
      fsyncSync(descriptor);
      chmodSync(configPath, 0o600);
    } finally {
      closeSync(descriptor);
    }
  }
  assert.notEqual(userConfig, globalConfig);
  assert.equal(readFileSync(userConfig, 'utf8'), '\n');
  assert.equal(readFileSync(globalConfig, 'utf8'), '\n');
  const environmentFor = (directory) => ({
    HOME: root,
    PATH: `${dirname(process.execPath)}:/usr/bin:/bin:/usr/sbin:/sbin`,
    npm_config_cache: resolve(directory, 'npm-cache'),
    npm_config_update_notifier: 'false',
    npm_config_registry: registry,
    npm_config_userconfig: userConfig,
    npm_config_globalconfig: globalConfig,
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    npm_config_fetch_retries: '0',
    npm_config_fetch_timeout: '10000',
  });
  const commonArgs = [
    cli, `--registry=${registry}`, `--userconfig=${userConfig}`, `--globalconfig=${globalConfig}`,
    'install', '--package-lock-only', '--ignore-scripts', '--audit=false', '--fund=false',
    '--min-release-age=7', `--before=${cutoff}`,
    '--fetch-retries=0', '--fetch-timeout=10000',
  ];
  const cutoffArgs = commonArgs.filter((argument) => argument.startsWith('--before='));
  assert.deepEqual(cutoffArgs, [`--before=${cutoff}`]);
  const eligible = resolve(root, 'eligible');
  const tooYoung = resolve(root, 'too-young');
  for (const directory of [eligible, tooYoung]) {
    mkdirSync(directory, { mode: 0o700 });
  }
  writeFileSync(resolve(eligible, 'package.json'), JSON.stringify({
    name: 'fixture-root', version: '1.0.0', private: true,
    dependencies: { [packageName]: '^1.0.0' },
  }));
  writeFileSync(resolve(tooYoung, 'package.json'), JSON.stringify({
    name: 'fixture-root', version: '1.0.0', private: true,
    dependencies: { [packageName]: '1.1.0' },
  }));

  const accepted = await spawnBounded(process.execPath, commonArgs, {
    cwd: eligible, env: environmentFor(eligible),
  });
  assert.equal(accepted.status, 0, accepted.stderr.slice(0, 1024));
  const lock = JSON.parse(readFileSync(resolve(eligible, 'package-lock.json'), 'utf8'));
  assert.equal(lock.packages[`node_modules/${packageName}`].version, '1.0.0');

  const refused = await spawnBounded(process.execPath, commonArgs, {
    cwd: tooYoung, env: environmentFor(tooYoung),
  });
  assert.ok(typeof refused.status === 'number' && refused.status !== 0,
            refused.stderr.slice(0, 1024));
  assert.ok(requests.length >= 2);
  assert.ok(requests.every((path) => new URL(path, registry).pathname === `/${packageName}`));
});
