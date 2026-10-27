import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  LOCK_MANIFEST_LIMITS,
  LockManifestError,
  validateLockManifest,
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

test('rejects unknown package sources, missing integrity, credentials, and nonpublic registries', () => {
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
  rejected(noIntegrity);
  const badIntegrity = lockFixture();
  badIntegrity.packages['node_modules/typescript'].integrity = 'sha1-not-accepted';
  rejected(badIntegrity);
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
});
