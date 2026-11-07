import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  LOCK_MANIFEST_LIMITS,
  LockManifestError,
  captureDependencyCheck,
  deriveNpmLockExpectation,
  formatDependencyCheckSummary,
  validateNoNpmShrinkwrap,
  validateLockManifest,
  validateLockManifestInventory,
  validateNpmProjectLock,
} from './node_lock_manifest.mjs';

const expected = {
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
    {
      path: 'packages/shared',
      name: '@fixture/shared',
      version: '1.0.0',
    },
  ],
};

function lockFixture() {
  return {
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
}

function bytes(lock = lockFixture()) {
  return Buffer.from(`${JSON.stringify(lock)}\n`, 'utf8');
}

function rejected(lock = lockFixture(), expectation = expected) {
  assert.throws(() => validateLockManifest(bytes(lock), expectation), LockManifestError);
}

function codeOf(lock, expectation = expected) {
  try {
    validateLockManifest(bytes(lock), expectation);
    return 'accepted';
  } catch (error) {
    assert.ok(error instanceof LockManifestError);
    return error.code;
  }
}

function workspaceTypescriptFixture(version) {
  const expectation = JSON.parse(JSON.stringify(expected));
  expectation.workspaces[0].dependencies.typescript = '6.0.3';
  const lock = lockFixture();
  lock.packages['packages/client-api'].dependencies.typescript = '6.0.3';
  lock.packages['packages/client-api/node_modules/typescript'] = {
    version,
    resolved: `https://registry.npmjs.org/typescript/-/typescript-${version}.tgz`,
    integrity: `sha512-${'A'.repeat(86)}==`,
  };
  return { lock, expectation };
}

test('accepts only the reviewed root, workspace, exact pins, and public registry package entries', () => {
  assert.deepEqual(validateLockManifest(bytes(), expected), { packageCount: 6, lockfileVersion: 3 });
});

test('projects the validated lock into exact package identities and dependency edges', () => {
  const inventory = validateLockManifestInventory(bytes(), expected);
  assert.equal(inventory.inventoryVersion, 1);
  assert.equal(inventory.lockfileVersion, 3);
  assert.match(inventory.lockSha256, /^[a-f0-9]{64}$/u);
  assert.equal(inventory.packages.length, 4);
  const byName = new Map(inventory.packages.map((item) => [item.name, item]));
  assert.deepEqual(byName.get('fixture-root').dependencies, [
    { name: 'typescript', version: '6.0.3' },
  ]);
  assert.deepEqual(byName.get('@fixture/client-api').dependencies, [
    { name: '@fixture/shared', version: '1.0.0' },
  ]);
  assert.equal(byName.get('typescript').integrity, `sha512-${'A'.repeat(86)}==`);
});

test('the established validator keeps inventory-only restrictions out of existing callers', () => {
  const absentDevelopmentDependency = lockFixture();
  absentDevelopmentDependency.packages['node_modules/typescript'].devDependencies = {
    uninstalled: '1.0.0',
  };
  assert.deepEqual(validateLockManifest(bytes(absentDevelopmentDependency), expected), {
    packageCount: 6, lockfileVersion: 3,
  });
  assert.throws(
    () => validateLockManifestInventory(bytes(absentDevelopmentDependency), expected),
    LockManifestError,
  );

  const nonStringLicense = lockFixture();
  nonStringLicense.packages['node_modules/typescript'].license = { id: 'MIT' };
  assert.deepEqual(validateLockManifest(bytes(nonStringLicense), expected), {
    packageCount: 6, lockfileVersion: 3,
  });
  assert.throws(
    () => validateLockManifestInventory(bytes(nonStringLicense), expected),
    LockManifestError,
  );
});

test('fails closed on root/workspace metadata and direct pin drift', () => {
  const wrongRoot = lockFixture();
  wrongRoot.name = 'other-root';
  rejected(wrongRoot);

  const wrongWorkspace = lockFixture();
  wrongWorkspace.packages['packages/client-api'].version = '1.0.1';
  rejected(wrongWorkspace);

  const wrongPin = lockFixture();
  wrongPin.packages[''].devDependencies.typescript = '6.0.4';
  rejected(wrongPin);

  const extraPin = lockFixture();
  extraPin.packages[''].devDependencies.extra = '1.2.3';
  rejected(extraPin);

  const missingDirectPackage = lockFixture();
  delete missingDirectPackage.packages['node_modules/typescript'];
  rejected(missingDirectPackage);

  const wrongResolvedDirectPackage = lockFixture();
  wrongResolvedDirectPackage.packages['node_modules/typescript'].version = '6.0.4';
  wrongResolvedDirectPackage.packages['node_modules/typescript'].resolved =
    'https://registry.npmjs.org/typescript/-/typescript-6.0.4.tgz';
  rejected(wrongResolvedDirectPackage);
});

test('workspace dependency resolution chooses the nearest reviewed package entry', () => {
  const validLocal = workspaceTypescriptFixture('6.0.3');
  assert.deepEqual(validateLockManifest(bytes(validLocal.lock), validLocal.expectation), {
    packageCount: 7,
    lockfileVersion: 3,
  });

  const shadowed = workspaceTypescriptFixture('6.0.4');
  assert.throws(() => validateLockManifest(bytes(shadowed.lock), shadowed.expectation), LockManifestError);
});

test('accepts apps workspaces and ranged peer dependencies without treating ranges as installed pins', () => {
  const workspacePath = 'apps/test-shell-desktop/web';
  const peerRange = '>=19.2.0 <20';
  const expectedWithPeer = {
    root: {
      name: 'fixture-root',
      version: '1.0.0',
      workspaces: [workspacePath],
    },
    workspaces: [{
      path: workspacePath,
      name: '@fixture/app',
      version: '1.0.0',
      peerDependencies: { react: peerRange },
    }],
  };
  const lock = {
    name: 'fixture-root',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': { name: 'fixture-root', version: '1.0.0', workspaces: [workspacePath] },
      [workspacePath]: {
        name: '@fixture/app', version: '1.0.0', peerDependencies: { react: peerRange },
      },
      'node_modules/react': {
        version: '19.3.1',
        resolved: 'https://registry.npmjs.org/react/-/react-19.3.1.tgz',
        integrity: `sha512-${'A'.repeat(86)}==`,
      },
    },
  };

  assert.deepEqual(validateLockManifest(bytes(lock), expectedWithPeer), { packageCount: 3, lockfileVersion: 3 });
  const inventory = validateLockManifestInventory(bytes(lock), expectedWithPeer);
  const app = inventory.packages.find((item) => item.name === '@fixture/app');
  assert.deepEqual(app.dependencies, [{ name: 'react', version: '19.3.1' }]);
});

test('accepts bounded source-local file dependencies through reviewed package links', () => {
  const workspacePath = 'packages/client-api';
  const localPath = '../packages/shared';
  const fileSpec = 'file:../../../packages/shared';
  const expectedWithLocal = {
    root: { name: 'fixture-root', version: '1.0.0', workspaces: [workspacePath] },
    workspaces: [{
      path: workspacePath,
      name: '@fixture/client-api',
      version: '1.0.0',
      dependencies: { '@fixture/shared': fileSpec },
    }],
    localPackages: [{ path: localPath, name: '@fixture/shared', version: '1.0.0' }],
  };
  const lock = {
    name: 'fixture-root', version: '1.0.0', lockfileVersion: 3, requires: true,
    packages: {
      '': { name: 'fixture-root', version: '1.0.0', workspaces: [workspacePath] },
      [workspacePath]: {
        name: '@fixture/client-api', version: '1.0.0', dependencies: { '@fixture/shared': fileSpec },
      },
      [localPath]: { name: '@fixture/shared', version: '1.0.0' },
      'node_modules/@fixture/shared': { resolved: localPath, link: true },
    },
  };

  assert.deepEqual(validateLockManifest(bytes(lock), expectedWithLocal), { packageCount: 4, lockfileVersion: 3 });
  const inventory = validateLockManifestInventory(bytes(lock), expectedWithLocal);
  assert.ok(inventory.packages.some((item) => item.name === '@fixture/shared' && item.kind === 'workspace'));
});

test('rejects unknown package sources, credentials, and nonpublic registries', () => {
  for (const resolved of [
    'file:../../outside.tgz',
    'git+https://registry.npmjs.org/typescript.git',
    'https://user:pass@registry.npmjs.org/typescript.tgz',
    'https://registry.npmjs.org.evil.invalid/typescript.tgz',
    'http://registry.npmjs.org/typescript.tgz',
    'https://registry.npmjs.org/other-package/-/other-package-6.0.3.tgz',
  ]) {
    const lock = lockFixture();
    lock.packages['node_modules/typescript'].resolved = resolved;
    assert.throws(() => validateLockManifest(bytes(lock), expected), LockManifestError, resolved);
  }
  const noIntegrity = lockFixture();
  delete noIntegrity.packages['node_modules/typescript'].integrity;
  assert.deepEqual(validateLockManifest(bytes(noIntegrity), expected), { packageCount: 6, lockfileVersion: 3 });
  assert.throws(() => validateLockManifestInventory(bytes(noIntegrity), expected), LockManifestError);
  const noResolved = lockFixture();
  delete noResolved.packages['node_modules/typescript'].resolved;
  delete noResolved.packages['node_modules/typescript'].integrity;
  assert.deepEqual(validateLockManifest(bytes(noResolved), expected), { packageCount: 6, lockfileVersion: 3 });
  assert.throws(() => validateLockManifestInventory(bytes(noResolved), expected), LockManifestError);
  const badIntegrity = lockFixture();
  badIntegrity.packages['node_modules/typescript'].integrity = 'sha1-not-accepted';
  rejected(badIntegrity);

  const externalTarball = lockFixture();
  externalTarball.packages['node_modules/typescript'].tarball = 'https://packages.example.invalid/typescript.tgz';
  rejected(externalTarball);

  const scopedRegistryPackage = lockFixture();
  scopedRegistryPackage.packages['node_modules/@fixture/other'] = {
    version: '1.0.0',
    resolved: 'https://registry.npmjs.org/@fixture%2fother/-/other-1.0.0.tgz',
    integrity: `sha512-${'A'.repeat(86)}==`,
  };
  assert.deepEqual(validateLockManifest(bytes(scopedRegistryPackage), expected), {
    packageCount: 7,
    lockfileVersion: 3,
  });

  const officialTarball = lockFixture();
  officialTarball.packages['node_modules/typescript'].tarball =
    'https://registry.npmjs.org/typescript/-/typescript-6.0.3.tgz';
  assert.deepEqual(validateLockManifest(bytes(officialTarball), expected), {
    packageCount: 6, lockfileVersion: 3,
  });
});

test('dependency tool output is private and summaries contain only allowlisted fields', async () => {
  const temporary = mkdtempSync(join(tmpdir(), 'kd-dependency-output-test-'));
  const privateMarker = 'private-source-diagnostic-marker';
  try {
    const result = await captureDependencyCheck({
      check: 'cargo-audit-root',
      command: process.execPath,
      args: ['-e', `process.stdout.write(${JSON.stringify(`${privateMarker} RUSTSEC-2026-1234`)});`
        + `process.stderr.write(${JSON.stringify('GHSA-ABCD-2345-XY67')});process.exitCode=7;`],
      timeoutMs: 5_000,
      tempRoot: temporary,
    });
    const summary = formatDependencyCheckSummary(result);
    assert.equal(result.status, 'failed');
    assert.equal(result.advisoryCount, 2);
    assert.deepEqual(result.advisoryIds, ['GHSA-ABCD-2345-XY67', 'RUSTSEC-2026-1234']);
    assert.equal(summary,
      'KD-DEPENDENCY-RESULT check=cargo-audit-root status=failed advisory-count=2 advisory-ids=GHSA-ABCD-2345-XY67,RUSTSEC-2026-1234');
    assert.equal(summary.includes(privateMarker), false);
    assert.deepEqual(readdirSync(temporary), []);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test('Rust and npm workflow checks use only private capture summaries and publish no artifacts', () => {
  const workflowPath = fileURLToPath(new URL('../../.github/workflows/core-dependency-checks.yml', import.meta.url));
  const workflow = readFileSync(workflowPath, 'utf8');

  for (const check of [
    'cargo-deny-${name}', 'cargo-audit-${name}',
    'cargo-vet-root', 'cargo-vet-fuzz', 'cargo-vet-runtime',
    'npm12-toolchain-install', 'npm12-bootstrap',
    'npm-root-ci', 'npm-root-audit', 'npm-root-signatures',
    'npm-runtime-ci', 'npm-runtime-audit', 'npm-runtime-signatures',
  ]) {
    assert.ok(workflow.includes(check), `${check} is present`);
  }
  assert.equal((workflow.match(/captureDependencyCheck\(\{/gu) ?? []).length, 7);
  assert.equal((workflow.match(/formatDependencyCheckSummary\(result\)/gu) ?? []).length, 7);
  assert.equal(workflow.includes('actions/upload-artifact'), false);
  for (const check of ['npm12-toolchain-install', 'npm12-bootstrap']) {
    const start = workflow.indexOf("check: '" + check + "'");
    const end = workflow.indexOf('formatDependencyCheckSummary(result)', start);
    assert.ok(start >= 0 && end > start, check + ' is captured');
    const blockStart = workflow.lastIndexOf('captureDependencyCheck, formatDependencyCheckSummary', start);
    assert.ok(blockStart >= 0, check + ' uses the private capture wrapper');
    const command = workflow.slice(blockStart, end);
    assert.ok(command.includes('--registry=https://registry.npmjs.org/'), check + ' pins the registry');
    assert.ok(command.includes("npm_config_userconfig: '/dev/null'"), check + ' ignores user npm config');
    assert.ok(command.includes("npm_config_replace_registry_host: 'never'"), check + ' keeps the registry host fixed');
  }
});

test('npm CI validates both locks before install and fixes every registry request', () => {
  const workflowPath = fileURLToPath(new URL('../../.github/workflows/core-dependency-checks.yml', import.meta.url));
  const workflow = readFileSync(workflowPath, 'utf8');
  const npmJob = workflow.slice(workflow.indexOf('\n  npm:\n'));
  const validation = npmJob.indexOf('validateNpmProjectLock(source, project);');
  const rootInstall = npmJob.indexOf("['npm-root-ci', ['ci'");
  const runtimeInstall = npmJob.indexOf("['npm-runtime-ci', ['ci'");

  assert.ok(validation >= 0);
  assert.ok(rootInstall > validation);
  assert.ok(runtimeInstall > validation);
  assert.ok(npmJob.includes("for (const project of [source, path.join(source, 'runtime')])"));
  assert.ok(npmJob.includes('--replace-registry-host=never'));
  assert.ok(npmJob.includes("npm_config_userconfig: '/dev/null'"));
  assert.ok(npmJob.includes("npm_config_globalconfig: '/dev/null'"));
  assert.equal((workflow.match(/validateNpmProjectLock\(source, project\);/gu) ?? []).length, 2);
  for (const check of [
    'npm-root-ci', 'npm-root-audit', 'npm-root-signatures',
    'npm-runtime-ci', 'npm-runtime-audit', 'npm-runtime-signatures',
  ]) {
    const start = npmJob.indexOf("['" + check + "',");
    const end = npmJob.indexOf(']],', start);
    assert.ok(start >= 0 && end > start, check + ' is present');
    const command = npmJob.slice(start, end);
    assert.ok(command.includes('--registry=https://registry.npmjs.org/'), check + ' sets the official registry');
  }
});

test('rejects npm-shrinkwrap.json at either npm root, including a dangling symlink', () => {
  const temporary = mkdtempSync(join(tmpdir(), 'kd-npm-shrinkwrap-test-'));
  const root = join(temporary, 'root');
  const runtime = join(root, 'runtime');
  mkdirSync(runtime, { recursive: true });
  try {
    for (const project of [root, runtime]) {
      assert.equal(validateNoNpmShrinkwrap(project), true);
      const shrinkwrap = join(project, 'npm-shrinkwrap.json');
      writeFileSync(shrinkwrap, '{"name":"private-canary"}\n');
      assert.throws(() => validateNoNpmShrinkwrap(project), LockManifestError);
      rmSync(shrinkwrap);
      symlinkSync('missing-shrinkwrap-target', shrinkwrap);
      assert.throws(() => validateNoNpmShrinkwrap(project), LockManifestError);
      rmSync(shrinkwrap);
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test('derives npm lock metadata from real manifests and validates source-contained file links', () => {
  const temporary = mkdtempSync(join(tmpdir(), 'kd-npm-project-lock-test-'));
  const source = join(temporary, 'source');
  const runtime = join(source, 'runtime');
  const workspace = join(runtime, 'packages/host-ui');
  const localPackage = join(source, 'packages/shared');
  mkdirSync(workspace, { recursive: true });
  mkdirSync(localPackage, { recursive: true });
  const runtimeManifest = { name: 'fixture-runtime', version: '1.0.0', workspaces: ['packages/host-ui'] };
  const workspaceManifest = {
    name: '@fixture/host-ui', version: '1.0.0', dependencies: { '@fixture/shared': 'file:../../../packages/shared' },
  };
  const localManifest = { name: '@fixture/shared', version: '1.0.0' };
  writeFileSync(join(runtime, 'package.json'), `${JSON.stringify(runtimeManifest)}\n`);
  writeFileSync(join(workspace, 'package.json'), `${JSON.stringify(workspaceManifest)}\n`);
  writeFileSync(join(localPackage, 'package.json'), `${JSON.stringify(localManifest)}\n`);
  const lock = {
    name: 'fixture-runtime', version: '1.0.0', lockfileVersion: 3, requires: true,
    packages: {
      '': { name: 'fixture-runtime', version: '1.0.0', workspaces: ['packages/host-ui'] },
      'packages/host-ui': {
        name: '@fixture/host-ui', version: '1.0.0', dependencies: { '@fixture/shared': 'file:../../../packages/shared' },
      },
      '../packages/shared': { name: '@fixture/shared', version: '1.0.0' },
      'node_modules/@fixture/shared': { resolved: '../packages/shared', link: true },
    },
  };
  writeFileSync(join(runtime, 'package-lock.json'), bytes(lock));
  try {
    const expectation = deriveNpmLockExpectation(source, runtime);
    assert.deepEqual(expectation.localPackages.map((item) => item.path), ['../packages/shared']);
    assert.deepEqual(validateNpmProjectLock(source, runtime), { packageCount: 4, lockfileVersion: 3 });
    writeFileSync(join(workspace, 'package.json'), `${JSON.stringify({
      ...workspaceManifest,
      dependencies: { '@fixture/shared': 'file:../../../../outside' },
    })}\n`);
    assert.throws(() => deriveNpmLockExpectation(source, runtime), LockManifestError);
    writeFileSync(join(runtime, 'npm-shrinkwrap.json'), '{}\n');
    assert.throws(() => validateNpmProjectLock(source, runtime), LockManifestError);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test('workspace links must resolve to one reviewed in-workspace path', () => {
  const outside = lockFixture();
  outside.packages['node_modules/@fixture/client-api'].resolved = '../../outside';
  rejected(outside);

  const unexpectedLink = lockFixture();
  unexpectedLink.packages['node_modules/unknown'] = { link: true, resolved: 'packages/client-api' };
  rejected(unexpectedLink);

  const pathEntry = lockFixture();
  pathEntry.packages['packages/../../outside'] = { name: 'outside', version: '1.0.0' };
  rejected(pathEntry);

  const validLocalWorkspaceLink = lockFixture();
  validLocalWorkspaceLink.packages['packages/client-api/node_modules/@fixture/shared'] = {
    link: true,
    resolved: 'packages/shared',
  };
  assert.doesNotThrow(() => validateLockManifest(bytes(validLocalWorkspaceLink), expected));

  const wrongLocalWorkspaceLink = lockFixture();
  wrongLocalWorkspaceLink.packages['packages/client-api/node_modules/@fixture/shared'] = {
    link: true,
    resolved: 'packages/client-api',
  };
  rejected(wrongLocalWorkspaceLink);

  const localRegistryShadow = lockFixture();
  localRegistryShadow.packages['packages/client-api/node_modules/@fixture/shared'] = {
    version: '9.0.0',
    resolved: 'https://registry.npmjs.org/@fixture/shared/-/shared-9.0.0.tgz',
    integrity: `sha512-${'A'.repeat(86)}==`,
  };
  rejected(localRegistryShadow);
});

test('expected metadata rejects path dependencies and workspace paths outside the fixed graph', () => {
  const badExpectation = JSON.parse(JSON.stringify(expected));
  badExpectation.root.devDependencies.typescript = 'file:../outside';
  assert.throws(() => validateLockManifest(bytes(), badExpectation), LockManifestError);

  const outsideWorkspace = JSON.parse(JSON.stringify(expected));
  outsideWorkspace.workspaces[0].path = '../outside';
  assert.throws(() => validateLockManifest(bytes(), outsideWorkspace), LockManifestError);

  for (const invalidVersion of ['1.0.0-01', '1.0.0-..', '1.0.0+.', `1.0.0-${'a'.repeat(123)}`]) {
    const badVersion = JSON.parse(JSON.stringify(expected));
    badVersion.root.version = invalidVersion;
    assert.throws(() => validateLockManifest(bytes(), badVersion), LockManifestError);
  }
  const longRegistryVersion = `1.0.0-${'a'.repeat(123)}`;
  const overlongPackage = lockFixture();
  overlongPackage.packages['node_modules/overflow'] = {
    version: longRegistryVersion,
    resolved: `https://registry.npmjs.org/overflow/-/overflow-${longRegistryVersion}.tgz`,
    integrity: `sha512-${'A'.repeat(86)}==`,
  };
  rejected(overlongPackage);
});

test('strict bounded JSON parser rejects duplicates, prototype keys, invalid UTF-8, and deep input', () => {
  const duplicate = Buffer.from('{"name":"fixture-root","name":"other"}', 'utf8');
  assert.throws(() => validateLockManifest(duplicate, expected), LockManifestError);
  const prototype = Buffer.from('{"__proto__":{"polluted":true}}', 'utf8');
  assert.throws(() => validateLockManifest(prototype, expected), LockManifestError);
  assert.throws(() => validateLockManifest(Buffer.from([0xc3, 0x28]), expected), LockManifestError);
  const tooDeep = Buffer.from(`${'['.repeat(LOCK_MANIFEST_LIMITS.jsonDepth + 2)}0${']'.repeat(LOCK_MANIFEST_LIMITS.jsonDepth + 2)}`);
  assert.throws(() => validateLockManifest(tooDeep, expected), LockManifestError);
  assert.throws(() => validateLockManifest(Buffer.alloc(LOCK_MANIFEST_LIMITS.inputBytes + 1), expected), LockManifestError);
});

test('package count is bounded independently of byte size', () => {
  const manyPackages = Array.from({ length: LOCK_MANIFEST_LIMITS.packageCount + 1 }, (_, index) =>
    `"node_modules/x${index}":{}`).join(',');
  const raw = `{"name":"fixture-root","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{},${manyPackages}}}`;
  assert.ok(Buffer.byteLength(raw, 'utf8') < LOCK_MANIFEST_LIMITS.inputBytes);
  assert.throws(() => validateLockManifest(Buffer.from(raw), expected), LockManifestError);
});

test('lock parser errors never include attacker-controlled manifest text', () => {
  const marker = 'fixture-canary-never-echo';
  const input = Buffer.from(`{"${marker}":`, 'utf8');
  assert.throws(() => validateLockManifest(input, expected), (error) => {
    assert.ok(error instanceof LockManifestError);
    assert.equal(error.message.includes(marker), false);
    return true;
  });
});

test('rejects extra top-level fields and malformed lock package paths', () => {
  const extra = lockFixture();
  extra.other = 'unexpected';
  rejected(extra);
  const malformedPath = lockFixture();
  malformedPath.packages['node_modules/../typescript'] = {
    version: '6.0.3',
    resolved: 'https://registry.npmjs.org/typescript/-/typescript-6.0.3.tgz',
    integrity: `sha512-${'A'.repeat(86)}==`,
  };
  rejected(malformedPath);

  const unknownMetadata = lockFixture();
  unknownMetadata.packages['node_modules/typescript'].authToken = 'fixture-value';
  rejected(unknownMetadata);

  const unsafeFunding = lockFixture();
  unsafeFunding.packages['node_modules/typescript'].funding = 'https://user:pass@example.invalid/support';
  rejected(unsafeFunding);

  for (const fragment of ['.top', '-top', 'top/next', 'top:next', 'top%20next', 'top?next', 'a'.repeat(129)]) {
    const fragmentFunding = lockFixture();
    fragmentFunding.packages['node_modules/typescript'].funding = `https://example.invalid/support${String.fromCharCode(35)}${fragment}`;
    rejected(fragmentFunding);
  }

  for (const bare of [
    'https://example.invalid?', 'https://example.invalid?sponsor=1', 'https://EXAMPLE.invalid',
    `https://example.invalid${String.fromCharCode(35)}top`, 'https://user@example.invalid',
  ]) {
    const bareFunding = lockFixture();
    bareFunding.packages['node_modules/typescript'].funding = { url: bare };
    rejected(bareFunding);
  }

  const credentialQueryFunding = lockFixture();
  credentialQueryFunding.packages['node_modules/typescript'].funding = [
    { type: 'github', url: 'https://user:pass@example.invalid/owner/project?sponsor=1' },
  ];
  rejected(credentialQueryFunding);

  const plainHttpFunding = lockFixture();
  plainHttpFunding.packages['node_modules/typescript'].funding = 'http://example.invalid/owner/project?sponsor=1';
  rejected(plainHttpFunding);
});

test('accepts funding URLs that carry a query string', () => {
  const stringForm = lockFixture();
  stringForm.packages['node_modules/typescript'].funding = 'https://example.invalid/owner/project?sponsor=1';
  assert.doesNotThrow(() => validateLockManifest(bytes(stringForm), expected));

  const objectForm = lockFixture();
  objectForm.packages['node_modules/typescript'].funding = {
    type: 'github', url: 'https://example.invalid/owner/project?sponsor=1',
  };
  assert.doesNotThrow(() => validateLockManifest(bytes(objectForm), expected));
});

test('accepts a bare origin funding URL and one plain fragment as npm copies them', () => {
  const bareOrigin = lockFixture();
  bareOrigin.packages['node_modules/typescript'].funding = { url: 'https://example.invalid' };
  assert.equal(codeOf(bareOrigin, expected), 'accepted');

  const listForm = lockFixture();
  listForm.packages['node_modules/typescript'].funding = [
    { type: 'individual', url: 'https://www.example.invalid/owner' },
    { type: 'individual', url: `https://www.example.invalid/how-to/faq${String.fromCharCode(35)}owner-is-here.-how-to-help` },
    { type: 'individual', url: 'https://www.example.invalid' },
  ];
  assert.equal(codeOf(listForm, expected), 'accepted');

  const stringForm = lockFixture();
  stringForm.packages['node_modules/typescript'].funding = `https://example.invalid/support${String.fromCharCode(35)}top`;
  assert.equal(codeOf(stringForm, expected), 'accepted');
});
