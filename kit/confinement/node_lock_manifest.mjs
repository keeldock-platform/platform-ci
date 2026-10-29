import { TextDecoder } from 'node:util';
import { createHash } from 'node:crypto';

export const LOCK_MANIFEST_LIMITS = Object.freeze({
  inputBytes: (4 * 1024 * 1024) - (64 * 1024),
  jsonDepth: 48,
  jsonNodes: 100_000,
  stringCodeUnits: 32_768,
  packageCount: 50_000,
});

const DEPENDENCY_GROUPS = Object.freeze([
  'dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies',
]);
const PERMITTED_OVERRIDES = Object.freeze({ lightningcss: '1.33.0' });
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/u;
const NUMERIC_IDENTIFIER = '(?:0|[1-9][0-9]*)';
const PRE_RELEASE_IDENTIFIER = '(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)';
const EXACT_VERSION = new RegExp(`^${NUMERIC_IDENTIFIER}\\.${NUMERIC_IDENTIFIER}\\.${NUMERIC_IDENTIFIER}`
  + `(?:-${PRE_RELEASE_IDENTIFIER}(?:\\.${PRE_RELEASE_IDENTIFIER})*)?`
  + '(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$', 'u');
const VERSION_SPEC = /^[0-9A-Za-z.*^~<>=|+ -]{1,128}$/u;
const WORKSPACE_PATH = /^packages\/(?:[A-Za-z0-9_-][A-Za-z0-9._-]*\/)*[A-Za-z0-9_-][A-Za-z0-9._-]*$/u;
const LOCK_ENTRY_FIELDS = new Set([
  'name', 'version', 'workspaces', 'resolved', 'integrity', 'link', 'inBundle', 'hasInstallScript',
  'hasShrinkwrap', 'funding',
  'dev', 'devOptional', 'optional', 'peer', 'dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies',
  'peerDependenciesMeta', 'bin', 'license', 'engines', 'os', 'cpu', 'libc', 'deprecated',
  'bundledDependencies', 'bundleDependencies',
]);

export class LockManifestError extends Error {
  constructor(code = 'invalid_manifest') {
    super('Lock manifest rejected');
    this.name = 'LockManifestError';
    this.code = code;
  }
}

function reject(code = 'invalid_manifest') {
  throw new LockManifestError(code);
}

function failJson() {
  reject('invalid_json');
}

function dataObject(value, allowed, required = [], code = 'invalid_expectation') {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) reject(code);
  let prototype;
  let descriptors;
  let keys;
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
    keys = Reflect.ownKeys(value);
  } catch {
    reject(code);
  }
  if ((prototype !== Object.prototype && prototype !== null)
      || keys.some((key) => typeof key !== 'string' || !allowed.includes(key))) reject(code);
  for (const key of required) if (!Object.hasOwn(descriptors, key)) reject(code);
  const result = Object.create(null);
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) reject(code);
    result[key] = descriptor.value;
  }
  return result;
}

function safeDependencySpec(value, exact) {
  if (typeof value !== 'string' || value.length > 128 || !VERSION_SPEC.test(value)) return false;
  if (/^(?:file:|link:|workspace:|git\+|git:|https?:|ssh:|github:|npm:)/iu.test(value)) return false;
  return !exact || exactVersion(value);
}

function exactVersion(value) {
  return typeof value === 'string' && value.length <= 128 && EXACT_VERSION.test(value);
}

function packageName(value) {
  return typeof value === 'string' && value.length <= 214 && PACKAGE_NAME.test(value)
    && !value.includes('..') && !['__proto__', 'constructor', 'prototype'].includes(value);
}

function normalizeOverrides(value) {
  const overrides = dataObject(value, Object.keys(PERMITTED_OVERRIDES), Object.keys(PERMITTED_OVERRIDES));
  for (const [name, spec] of Object.entries(PERMITTED_OVERRIDES)) {
    if (overrides[name] !== spec) reject('invalid_expectation');
  }
  return overrides;
}

function normalizeExpectation(input) {
  const expected = dataObject(input, ['root', 'workspaces'], ['root', 'workspaces']);
  if (!Array.isArray(expected.workspaces) || expected.workspaces.length > 256) reject('invalid_expectation');
  const root = dataObject(expected.root,
    ['name', 'version', 'workspaces', 'overrides', ...DEPENDENCY_GROUPS], ['name', 'version', 'workspaces']);
  const workspaces = expected.workspaces.map((value) => dataObject(value,
    ['path', 'name', 'version', ...DEPENDENCY_GROUPS], ['path', 'name', 'version']));
  if (!packageName(root.name) || !exactVersion(root.version)
      || !Array.isArray(root.workspaces) || root.workspaces.length === 0 || root.workspaces.length > 16
      || new Set(root.workspaces).size !== root.workspaces.length
      || root.workspaces.some((path) => typeof path !== 'string'
        || !(path === 'packages/*' || validWorkspacePath(path)))) reject('invalid_expectation');
  if (Object.hasOwn(root, 'overrides')) root.overrides = normalizeOverrides(root.overrides);
  const names = new Set();
  const paths = new Set();
  for (const item of workspaces) {
    if (!validWorkspacePath(item.path) || !packageName(item.name) || !exactVersion(item.version)
        || names.has(item.name) || paths.has(item.path)) {
      reject('invalid_expectation');
    }
    const included = root.workspaces.some((pattern) => pattern === item.path
      || (pattern === 'packages/*' && item.path.startsWith('packages/')));
    if (!included) reject('invalid_expectation');
    names.add(item.name);
    paths.add(item.path);
  }
  for (const item of [root, ...workspaces]) {
    for (const group of DEPENDENCY_GROUPS) {
      const map = item[group] === undefined ? Object.create(null) : item[group];
      const pins = dataObject(map, Object.keys(map), [], 'invalid_expectation');
      if (Object.keys(pins).length > 512) reject('limit_exceeded');
      item[group] = pins;
      for (const [name, spec] of Object.entries(pins)) {
        const workspaceSpec = names.has(name) && typeof spec === 'string'
          && /^workspace:(?:\*|\^|~|[0-9][0-9A-Za-z.+-]*)$/u.test(spec);
        if (!packageName(name) || (!workspaceSpec && !safeDependencySpec(spec, !names.has(name)))
            || (!names.has(name) && typeof spec === 'string' && spec.startsWith('workspace:'))) {
          reject('invalid_expectation');
        }
      }
    }
  }
  if (root.overrides !== undefined) {
    for (const item of [root, ...workspaces]) {
      for (const group of DEPENDENCY_GROUPS) {
        for (const [name, spec] of Object.entries(PERMITTED_OVERRIDES)) {
          if (Object.hasOwn(item[group], name) && item[group][name] !== spec) reject('invalid_expectation');
        }
      }
    }
  }
  return { root, workspaces };
}

function parseJsonStrict(text) {
  let offset = 0;
  let nodes = 0;
  const whitespace = () => {
    while (text.charCodeAt(offset) === 0x20 || text.charCodeAt(offset) === 0x09
      || text.charCodeAt(offset) === 0x0a || text.charCodeAt(offset) === 0x0d) offset += 1;
  };
  const string = () => {
    if (text[offset] !== '"') failJson();
    const start = offset++;
    while (offset < text.length) {
      const code = text.charCodeAt(offset);
      if (code === 0x22) {
        offset += 1;
        let value;
        try { value = JSON.parse(text.slice(start, offset)); } catch { failJson(); }
        if (value.length > LOCK_MANIFEST_LIMITS.stringCodeUnits) reject('limit_exceeded');
        return value;
      }
      if (code < 0x20) failJson();
      if (code === 0x5c) offset += 1;
      offset += 1;
    }
    failJson();
  };
  const value = (depth) => {
    whitespace();
    nodes += 1;
    if (nodes > LOCK_MANIFEST_LIMITS.jsonNodes || depth > LOCK_MANIFEST_LIMITS.jsonDepth) {
      reject('limit_exceeded');
    }
    const char = text[offset];
    if (char === '"') return string();
    if (char === '{') {
      offset += 1; whitespace();
      const result = Object.create(null);
      const seen = new Set();
      if (text[offset] === '}') { offset += 1; return result; }
      while (true) {
        whitespace();
        const key = string();
        if (seen.has(key) || key === '__proto__' || key === 'constructor' || key === 'prototype') failJson();
        seen.add(key);
        whitespace();
        if (text[offset++] !== ':') failJson();
        result[key] = value(depth + 1);
        whitespace();
        if (text[offset] === '}') { offset += 1; return result; }
        if (text[offset++] !== ',') failJson();
      }
    }
    if (char === '[') {
      offset += 1; whitespace();
      const result = [];
      if (text[offset] === ']') { offset += 1; return result; }
      while (true) {
        result.push(value(depth + 1));
        whitespace();
        if (text[offset] === ']') { offset += 1; return result; }
        if (text[offset++] !== ',') failJson();
      }
    }
    if (text.startsWith('true', offset)) { offset += 4; return true; }
    if (text.startsWith('false', offset)) { offset += 5; return false; }
    if (text.startsWith('null', offset)) { offset += 4; return null; }
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(text.slice(offset));
    if (!match) failJson();
    offset += match[0].length;
    const number = Number(match[0]);
    if (!Number.isSafeInteger(number)) failJson();
    return number;
  };
  const parsed = value(0);
  whitespace();
  if (offset !== text.length) failJson();
  return parsed;
}

function decodeLock(input) {
  if (!(input instanceof Uint8Array) || input.byteLength > LOCK_MANIFEST_LIMITS.inputBytes) {
    reject('limit_exceeded');
  }
  if (input.byteLength >= 3 && input[0] === 0xef && input[1] === 0xbb && input[2] === 0xbf) failJson();
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(input); } catch { failJson(); }
  if (text.startsWith('\uFEFF')) failJson();
  return parseJsonStrict(text);
}

function exactMap(actual, expected) {
  if (actual === undefined) actual = Object.create(null);
  if (expected === undefined) expected = Object.create(null);
  if (actual === null || typeof actual !== 'object' || Array.isArray(actual)) return false;
  const keys = Object.keys(actual);
  const expectedKeys = Object.keys(expected);
  return keys.length === expectedKeys.length && expectedKeys.every((key) => actual[key] === expected[key]);
}

function validateDependencyMap(map, workspaceNames) {
  if (map === undefined) return;
  if (map === null || typeof map !== 'object' || Array.isArray(map) || Object.keys(map).length > 512) {
    reject('invalid_package');
  }
  for (const [name, spec] of Object.entries(map)) {
    const workspaceSpec = workspaceNames.has(name) && typeof spec === 'string'
      && /^workspace:(?:\*|\^|~|[0-9][0-9A-Za-z.+-]*)$/u.test(spec);
    if (!packageName(name) || (!workspaceSpec && !safeDependencySpec(spec, false))) reject('invalid_package');
  }
}

function validateEntryMetadata(entry, isRoot = false) {
  const keys = Object.keys(entry);
  if (keys.some((key) => !LOCK_ENTRY_FIELDS.has(key) && !(isRoot && key === 'overrides'))) reject('invalid_package');
  if (entry.link === true && keys.some((key) => key !== 'link' && key !== 'resolved')) reject('workspace_link_invalid');
  for (const flag of ['link', 'inBundle', 'hasInstallScript', 'hasShrinkwrap', 'dev', 'devOptional', 'optional', 'peer']) {
    if (entry[flag] !== undefined && typeof entry[flag] !== 'boolean') reject('invalid_package');
  }
  if (entry.peerDependenciesMeta !== undefined) {
    const metadata = entry.peerDependenciesMeta;
    if (metadata === null || typeof metadata !== 'object' || Array.isArray(metadata) || Object.keys(metadata).length > 512) {
      reject('invalid_package');
    }
    for (const [name, options] of Object.entries(metadata)) {
      if (!packageName(name) || options === null || typeof options !== 'object' || Array.isArray(options)
          || Object.keys(options).some((key) => key !== 'optional')
          || (options.optional !== undefined && typeof options.optional !== 'boolean')) reject('invalid_package');
    }
  }
  if (entry.bin !== undefined) {
    const bins = typeof entry.bin === 'string' ? { package: entry.bin } : entry.bin;
    if (bins === null || typeof bins !== 'object' || Array.isArray(bins) || Object.keys(bins).length > 64) {
      reject('invalid_package');
    }
    for (const [name, path] of Object.entries(bins)) {
      const relative = typeof path === 'string' && path.startsWith('./') ? path.slice(2) : path;
      if (!/^[A-Za-z0-9._-]{1,128}$/u.test(name) || typeof path !== 'string' || path.length > 256
          || path.startsWith('/') || path.includes('\\')
          || relative.split('/').some((part) => !part || part === '.' || part === '..')) reject('invalid_package');
    }
  }
  if (entry.funding !== undefined) {
    const items = Array.isArray(entry.funding) ? entry.funding : [entry.funding];
    if (items.length > 16) reject('invalid_package');
    for (const item of items) {
      const funding = typeof item === 'string'
        ? { url: item }
        : dataObject(item, ['type', 'url'], ['url'], 'invalid_package');
      if (typeof funding.url !== 'string' || funding.url.length > 2048) reject('invalid_package');
      let url;
      try { url = new URL(funding.url); } catch { reject('invalid_package'); }
      if (url.protocol !== 'https:' || url.username || url.password || url.hash
          || url.href !== funding.url) reject('invalid_package');
      if (funding.type !== undefined && (typeof funding.type !== 'string'
          || !/^[A-Za-z0-9._-]{1,64}$/u.test(funding.type))) reject('invalid_package');
    }
  }
}

function validWorkspacePath(path) {
  return typeof path === 'string' && path.length <= 512 && WORKSPACE_PATH.test(path)
    && !path.split('/').some((part) => part === '.' || part === '..');
}

function moduleNameFromTail(tail) {
  const parts = tail.split('/');
  let index = 0;
  let name = null;
  while (index < parts.length) {
    if (index >= parts.length) return null;
    const first = parts[index++];
    if (!first || first === '.' || first === '..' || first.includes('\\')) return null;
    if (first.startsWith('@')) {
      if (!PACKAGE_NAME.test(`${first}/x`) || index >= parts.length) return null;
      const second = parts[index++];
      name = `${first}/${second}`;
    } else {
      name = first;
    }
    if (!packageName(name)) return null;
    if (index === parts.length) return name;
    if (parts[index++] !== 'node_modules') return null;
  }
  return null;
}

function nodeModulesPackageName(path, workspaceDirectories) {
  if (typeof path !== 'string' || path.length > 4096) return null;
  if (path.startsWith('node_modules/')) return moduleNameFromTail(path.slice('node_modules/'.length));
  for (const directory of workspaceDirectories) {
    const prefix = `${directory}/node_modules/`;
    if (path.startsWith(prefix)) return moduleNameFromTail(path.slice(prefix.length));
  }
  return null;
}

function workspaceDirectorySet(workspaces) {
  const directories = new Set(['packages']);
  for (const workspace of workspaces) {
    const parts = workspace.path.split('/');
    for (let index = 1; index <= parts.length; index += 1) {
      directories.add(parts.slice(0, index).join('/'));
    }
  }
  return directories;
}

function validRegistryUrl(value, name, version) {
  if (typeof value !== 'string' || value.length > 4096 || value.includes('%')) return false;
  let url;
  try { url = new URL(value); } catch { return false; }
  if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.port
      || url.username || url.password || url.search || url.hash || !url.pathname.startsWith('/')) return false;
  if (url.pathname.includes('//') || url.pathname.split('/').some((part) => part === '.' || part === '..')) return false;
  const packagePath = `/${name}/-/${name.split('/').at(-1)}-${version}.tgz`;
  return url.href === value && url.pathname === packagePath;
}

function validSha512Integrity(value) {
  if (typeof value !== 'string' || !value.startsWith('sha512-') || value.length > 128) return false;
  const encoded = value.slice(7);
  if (!/^[A-Za-z0-9+/]{86}==$/u.test(encoded)) return false;
  const decoded = Buffer.from(encoded, 'base64');
  return decoded.byteLength === 64 && decoded.toString('base64') === encoded;
}

function compareDirectPins(actual, expected) {
  for (const group of DEPENDENCY_GROUPS) {
    if (!exactMap(actual[group], expected[group])) reject('direct_pin_mismatch');
  }
}

function validateDirectPin(packages, name, spec, parentPath, workspaceByName) {
  const candidates = parentPath ? workspaceResolutionCandidates(parentPath, name) : [`node_modules/${name}`];
  const key = candidates.find((candidate) => Object.hasOwn(packages, candidate));
  if (!key) reject('direct_pin_mismatch');
  const entry = packages[key];
  const workspacePath = workspaceByName.get(name);
  if (workspacePath) {
    if (!entry || entry.link !== true || entry.resolved !== workspacePath) reject('direct_pin_mismatch');
    return;
  }
  if (!entry || entry.link === true || entry.version !== spec
      || !validRegistryUrl(entry.resolved, name, spec) || !validSha512Integrity(entry.integrity)) {
    reject('direct_pin_mismatch');
  }
}

function workspaceResolutionCandidates(workspacePath, name) {
  const parts = workspacePath.split('/');
  const candidates = [];
  for (let index = parts.length; index > 0; index -= 1) {
    candidates.push(`${parts.slice(0, index).join('/')}/node_modules/${name}`);
  }
  candidates.push(`node_modules/${name}`);
  return candidates;
}

function packageResolutionCandidates(packagePath, name) {
  let parent = packagePath;
  const candidates = [];
  while (parent) {
    candidates.push(`${parent}/node_modules/${name}`);
    const separator = parent.lastIndexOf('/');
    parent = separator < 0 ? '' : parent.slice(0, separator);
  }
  candidates.push(`node_modules/${name}`);
  return candidates;
}

function validateExpectedDirectPins(packages, expected, workspaceByName) {
  for (const group of DEPENDENCY_GROUPS) {
    for (const [name, spec] of Object.entries(expected.root[group] ?? {})) {
      validateDirectPin(packages, name, spec, null, workspaceByName);
    }
    for (const workspace of expected.workspaces) {
      for (const [name, spec] of Object.entries(workspace[group] ?? {})) {
        validateDirectPin(packages, name, spec, workspace.path, workspaceByName);
      }
    }
  }
}

function buildLockInventory(packages, expected, workspaceByPath, workspaceDirectories) {
  const records = Object.create(null);
  const packageKeys = Object.keys(packages);
  for (const key of packageKeys) {
    const entry = packages[key];
    if (key !== '' && entry.link === true) continue;
    let name;
    let version;
    let kind;
    if (key === '') {
      name = expected.root.name;
      version = expected.root.version;
      kind = 'root';
    } else if (workspaceByPath.has(key)) {
      const workspace = workspaceByPath.get(key);
      name = workspace.name;
      version = workspace.version;
      kind = 'workspace';
    } else {
      name = nodeModulesPackageName(key, workspaceDirectories);
      version = entry.version;
      kind = 'registry';
    }
    if (typeof name !== 'string' || typeof version !== 'string') reject('invalid_package');
    if (entry.license !== undefined
        && (typeof entry.license !== 'string' || entry.license.length > 4096)) {
      reject('invalid_package');
    }
    records[key] = {
      name,
      version,
      kind,
      integrity: kind === 'registry' ? entry.integrity : null,
      license: typeof entry.license === 'string' ? entry.license : null,
      dependencies: [],
    };
  }

  for (const key of Object.keys(records)) {
    const entry = packages[key];
    const names = new Set();
    for (const group of DEPENDENCY_GROUPS) {
      const map = entry[group];
      if (map && typeof map === 'object' && !Array.isArray(map)) {
        for (const name of Object.keys(map)) names.add(name);
      }
    }
    const dependencies = [];
    for (const name of [...names].sort()) {
      const candidates = key === ''
        ? [`node_modules/${name}`]
        : (workspaceByPath.has(key)
          ? workspaceResolutionCandidates(key, name)
          : packageResolutionCandidates(key, name));
      let targetPath = candidates.find((candidate) => Object.hasOwn(packages, candidate));
      if (targetPath && packages[targetPath].link === true) {
        targetPath = packages[targetPath].resolved;
      }
      const target = targetPath === undefined ? undefined : records[targetPath];
      if (!target) {
        const optionalPeer = entry.peerDependenciesMeta
          && entry.peerDependenciesMeta[name]
          && entry.peerDependenciesMeta[name].optional === true;
        if (entry.optionalDependencies && Object.hasOwn(entry.optionalDependencies, name)
            || optionalPeer) continue;
        reject('invalid_package');
      }
      dependencies.push({ name: target.name, version: target.version });
    }
    dependencies.sort((left, right) => {
      const leftKey = `${left.name}@${left.version}`;
      const rightKey = `${right.name}@${right.version}`;
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    });
    records[key].dependencies = dependencies;
  }

  const result = Object.keys(records).map((key) => records[key]);
  result.sort((left, right) => {
    const leftKey = `${left.name}@${left.version}:${left.kind}`;
    const rightKey = `${right.name}@${right.version}:${right.kind}`;
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
  return result;
}

/** Validate an npm v3 lock against caller-supplied, pre-reviewed manifest metadata. */
function validateLockManifestUnchecked(lockBytes, expectedInput, includeInventory) {
  const expected = normalizeExpectation(expectedInput);
  const lock = decodeLock(lockBytes);
  if (lock === null || typeof lock !== 'object' || Array.isArray(lock)) reject('invalid_lock');
  if (lock.lockfileVersion !== 3 || lock.requires !== true || !lock.packages
      || typeof lock.packages !== 'object' || Array.isArray(lock.packages)) reject('invalid_lock');
  const topKeys = Object.keys(lock).sort();
  if (topKeys.join(',') !== 'lockfileVersion,name,packages,requires,version') reject('invalid_lock');
  if (lock.name !== expected.root.name || lock.version !== expected.root.version) reject('root_mismatch');
  const packages = lock.packages;
  const packageKeys = Object.keys(packages);
  if (packageKeys.length > LOCK_MANIFEST_LIMITS.packageCount || !Object.hasOwn(packages, '')) {
    reject('limit_exceeded');
  }
  const rootEntry = packages[''];
  if (!rootEntry || rootEntry.name !== expected.root.name || rootEntry.version !== expected.root.version
      || !Array.isArray(rootEntry.workspaces)
      || rootEntry.workspaces.length !== expected.root.workspaces.length
      || rootEntry.workspaces.some((path, index) => path !== expected.root.workspaces[index])) {
    reject('root_mismatch');
  }
  if (Object.hasOwn(rootEntry, 'overrides')
      && (expected.root.overrides === undefined || !exactMap(rootEntry.overrides, expected.root.overrides))) {
    reject('root_mismatch');
  }
  compareDirectPins(rootEntry, expected.root);

  const workspaceByPath = new Map();
  const workspaceByName = new Map();
  for (const workspace of expected.workspaces) {
    if (!validWorkspacePath(workspace.path) || workspaceByPath.has(workspace.path)
        || workspaceByName.has(workspace.name)) reject('invalid_expectation');
    workspaceByPath.set(workspace.path, workspace);
    workspaceByName.set(workspace.name, workspace.path);
    const actual = packages[workspace.path];
    if (!actual || actual.link === true || actual.name !== workspace.name || actual.version !== workspace.version) {
      reject('workspace_mismatch');
    }
    compareDirectPins(actual, workspace);
  }
  const workspaceDirectories = [...workspaceDirectorySet(expected.workspaces)]
    .sort((left, right) => right.length - left.length);
  validateExpectedDirectPins(packages, expected, workspaceByName);
  for (const key of packageKeys) {
    const entry = packages[key];
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) reject('invalid_package');
    validateEntryMetadata(entry, key === '');
    for (const group of DEPENDENCY_GROUPS) validateDependencyMap(entry[group], workspaceByName);
    if (key === '' || workspaceByPath.has(key)) {
      if (entry.resolved !== undefined || entry.integrity !== undefined || entry.link === true) {
        reject('workspace_mismatch');
      }
      continue;
    }
    const moduleName = nodeModulesPackageName(key, workspaceDirectories);
    if (!moduleName) reject('invalid_package_path');
    if (entry.link === true) {
      const target = workspaceByName.get(moduleName);
      if (!target || entry.resolved !== target || entry.integrity !== undefined) reject('workspace_link_invalid');
      continue;
    }
    if ((entry.link !== undefined && entry.link !== false)
        || !exactVersion(entry.version)
        || !validRegistryUrl(entry.resolved, moduleName, entry.version)
        || !validSha512Integrity(entry.integrity)) {
      reject('package_source_invalid');
    }
    if (entry.name !== undefined && entry.name !== moduleName) reject('invalid_package');
    if (expected.root.overrides !== undefined) {
      for (const [name, pinned] of Object.entries(expected.root.overrides)) {
        if ((moduleName === name || moduleName.startsWith(`${name}-`)) && entry.version !== pinned) {
          reject('override_mismatch');
        }
      }
    }
  }

  const result = {
    packageCount: packageKeys.length,
    lockfileVersion: 3,
  };
  if (includeInventory) {
    result.packages = buildLockInventory(packages, expected, workspaceByPath, workspaceDirectories);
  }
  return Object.freeze(result);
}

function checkedLockManifest(lockBytes, expectedInput, includeInventory) {
  try {
    return validateLockManifestUnchecked(lockBytes, expectedInput, includeInventory);
  } catch (error) {
    if (error instanceof LockManifestError) throw error;
    reject('invalid_manifest');
  }
}

export function validateLockManifest(lockBytes, expectedInput) {
  const result = checkedLockManifest(lockBytes, expectedInput, false);
  return Object.freeze({ packageCount: result.packageCount, lockfileVersion: result.lockfileVersion });
}

export function validateLockManifestInventory(lockBytes, expectedInput) {
  const result = checkedLockManifest(lockBytes, expectedInput, true);
  if (!(lockBytes instanceof Uint8Array)) reject('invalid_manifest');
  return Object.freeze({
    inventoryVersion: 1,
    packageCount: result.packageCount,
    lockfileVersion: result.lockfileVersion,
    lockSha256: createHash('sha256').update(lockBytes).digest('hex'),
    packages: result.packages,
  });
}
