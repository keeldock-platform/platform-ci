import { spawn } from 'node:child_process';
import { TextDecoder } from 'node:util';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

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
const OVERRIDE_PLATFORM_BINARIES = Object.freeze({
  lightningcss: new Set([
    'darwin-arm64', 'darwin-x64', 'freebsd-x64', 'linux-arm-gnueabihf', 'linux-arm64-gnu', 'linux-arm64-musl',
    'linux-x64-gnu', 'linux-x64-musl', 'win32-arm64-msvc', 'win32-x64-msvc', 'android-arm64',
  ].map((suffix) => `lightningcss-${suffix}`)),
});
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/u;
const LOCAL_PACKAGE_PATH = /^(?:\.\.\/)?packages\/(?:[A-Za-z0-9_-][A-Za-z0-9._-]*\/)*[A-Za-z0-9_-][A-Za-z0-9._-]*$/u;
const NUMERIC_IDENTIFIER = '(?:0|[1-9][0-9]*)';
const PRE_RELEASE_IDENTIFIER = '(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)';
const EXACT_VERSION = new RegExp(`^${NUMERIC_IDENTIFIER}\\.${NUMERIC_IDENTIFIER}\\.${NUMERIC_IDENTIFIER}`
  + `(?:-${PRE_RELEASE_IDENTIFIER}(?:\\.${PRE_RELEASE_IDENTIFIER})*)?`
  + '(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$', 'u');
const VERSION_SPEC = /^[0-9A-Za-z.*^~<>=|+ -]{1,128}$/u;
const FUNDING_FRAGMENT = /^\x23[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const WORKSPACE_PATH = /^(?:packages|apps)\/(?:[A-Za-z0-9_-][A-Za-z0-9._-]*\/)*[A-Za-z0-9_-][A-Za-z0-9._-]*$/u;
const LOCK_ENTRY_FIELDS = new Set([
  'name', 'version', 'workspaces', 'resolved', 'tarball', 'integrity', 'link', 'inBundle', 'hasInstallScript',
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

const ADVISORY_ID = /(?<![A-Za-z0-9-])(?:RUSTSEC-[0-9]{4}-[0-9]{4}|GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}|CVE-[0-9]{4}-[0-9]{4,19})(?![A-Za-z0-9-])/gu;
const MAX_REPORTED_ADVISORY_IDS = 25;
const MAX_PRIVATE_OUTPUT_SCAN_BYTES = 64 * 1024 * 1024;

function collectAdvisoryIds(file) {
  const descriptor = fs.openSync(file, 'r');
  const buffer = Buffer.alloc(64 * 1024);
  const ids = new Set();
  let position = 0;
  let tail = '';
  let scanned = 0;
  try {
    while (scanned < MAX_PRIVATE_OUTPUT_SCAN_BYTES) {
      const length = fs.readSync(descriptor, buffer, 0,
        Math.min(buffer.length, MAX_PRIVATE_OUTPUT_SCAN_BYTES - scanned), position);
      if (length === 0) break;
      position += length;
      scanned += length;
      const text = tail + buffer.toString('utf8', 0, length);
      for (const match of text.matchAll(ADVISORY_ID)) ids.add(match[0]);
      tail = text.slice(-64);
    }
  } finally {
    fs.closeSync(descriptor);
  }
  return [...ids].sort();
}

function safeCheckName(value) {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9-]{0,63}$/u.test(value);
}

function terminateProcess(child) {
  try {
    if (process.platform === 'win32') child.kill('SIGKILL');
    else process.kill(-child.pid, 'SIGKILL');
  } catch {
    try { child.kill('SIGKILL'); } catch { /* already exited */ }
  }
}

/** Run a dependency check with private output files and return an allowlisted summary. */
export async function captureDependencyCheck({
  check,
  command,
  args = [],
  cwd,
  env = process.env,
  timeoutMs = 60_000,
  tempRoot = os.tmpdir(),
}) {
  if (!safeCheckName(check) || typeof command !== 'string' || command.length === 0
      || !Array.isArray(args) || args.some((item) => typeof item !== 'string')
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 3_600_000
      || env === null || typeof env !== 'object' || Array.isArray(env)) {
    return Object.freeze({ check: safeCheckName(check) ? check : 'invalid-check', status: 'failed',
      exitCode: 2, advisoryCount: 0, advisoryIds: [] });
  }

  let privateDirectory;
  let stdoutPath;
  let stderrPath;
  let stdoutFd = -1;
  let stderrFd = -1;
  try {
    privateDirectory = fs.mkdtempSync(path.join(tempRoot, 'kd-private-dependency-check-'));
    fs.chmodSync(privateDirectory, 0o700);
    stdoutPath = path.join(privateDirectory, 'stdout');
    stderrPath = path.join(privateDirectory, 'stderr');
    stdoutFd = fs.openSync(stdoutPath, 'wx', 0o600);
    stderrFd = fs.openSync(stderrPath, 'wx', 0o600);
    const result = await new Promise((resolve) => {
      let child;
      let timedOut = false;
      let settled = false;
      let timer;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      };
      try {
        child = spawn(command, args, {
          cwd,
          env: { ...env },
          stdio: ['ignore', stdoutFd, stderrFd],
          detached: process.platform !== 'win32',
          windowsHide: true,
        });
      } catch {
        finish({ exitCode: 127, timedOut: false });
        return;
      }
      child.once('error', () => finish({ exitCode: 127, timedOut: false }));
      child.once('close', (code) => finish({
        exitCode: timedOut ? 124 : (Number.isInteger(code) ? code : 127),
        timedOut,
      }));
      timer = setTimeout(() => {
        timedOut = true;
        terminateProcess(child);
      }, timeoutMs);
    });
    fs.closeSync(stdoutFd);
    stdoutFd = -1;
    fs.closeSync(stderrFd);
    stderrFd = -1;
    const advisoryIds = [...new Set([
      ...collectAdvisoryIds(stdoutPath),
      ...collectAdvisoryIds(stderrPath),
    ])].sort();
    const status = result.exitCode === 0 && !result.timedOut ? 'passed' : 'failed';
    return Object.freeze({ check, status, exitCode: result.exitCode,
      advisoryCount: advisoryIds.length, advisoryIds: advisoryIds.slice(0, MAX_REPORTED_ADVISORY_IDS) });
  } catch {
    return Object.freeze({ check, status: 'failed', exitCode: 127, advisoryCount: 0, advisoryIds: [] });
  } finally {
    if (stdoutFd >= 0) { try { fs.closeSync(stdoutFd); } catch { /* already closed */ } }
    if (stderrFd >= 0) { try { fs.closeSync(stderrFd); } catch { /* already closed */ } }
    if (privateDirectory) { try { fs.rmSync(privateDirectory, { recursive: true, force: true }); } catch { /* private temp cleanup */ } }
  }
}

export function formatDependencyCheckSummary(result) {
  const check = safeCheckName(result?.check) ? result.check : 'invalid-check';
  const status = result?.status === 'passed' ? 'passed' : 'failed';
  const advisoryCount = Number.isSafeInteger(result?.advisoryCount) && result.advisoryCount >= 0
    ? result.advisoryCount : 0;
  const advisoryIds = Array.isArray(result?.advisoryIds)
    ? result.advisoryIds.filter((item) => typeof item === 'string'
      && /^(?:RUSTSEC-[0-9]{4}-[0-9]{4}|GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}|CVE-[0-9]{4}-[0-9]{4,19})$/u.test(item))
      .slice(0, MAX_REPORTED_ADVISORY_IDS)
    : [];
  const uniqueIds = [...new Set(advisoryIds)].sort();
  return `KD-DEPENDENCY-RESULT check=${check} status=${status} advisory-count=${advisoryCount} advisory-ids=${uniqueIds.join(',') || 'none'}`;
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

function validLocalPackagePath(value) {
  return typeof value === 'string' && value.length <= 512 && LOCAL_PACKAGE_PATH.test(value)
    && !value.slice(value.startsWith('../') ? 3 : 0).split('/').some((part) => part === '.' || part === '..');
}

function localTargetForSpec(ownerPath, spec) {
  if (typeof ownerPath !== 'string' || typeof spec !== 'string' || !spec.startsWith('file:')) return null;
  const relative = spec.slice('file:'.length);
  if (!relative || relative.includes('\\') || path.posix.isAbsolute(relative)) return null;
  const target = path.posix.normalize(path.posix.join(ownerPath || '.', relative));
  return validLocalPackagePath(target) ? target : null;
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
  const expected = dataObject(input, ['root', 'workspaces', 'localPackages'], ['root', 'workspaces']);
  if (!Array.isArray(expected.workspaces) || expected.workspaces.length > 256) reject('invalid_expectation');
  if (expected.localPackages !== undefined
      && (!Array.isArray(expected.localPackages) || expected.localPackages.length > 256)) reject('invalid_expectation');
  const root = dataObject(expected.root,
    ['name', 'version', 'workspaces', 'overrides', ...DEPENDENCY_GROUPS], ['name', 'version', 'workspaces']);
  const workspaces = expected.workspaces.map((value) => dataObject(value,
    ['path', 'name', 'version', ...DEPENDENCY_GROUPS], ['path', 'name', 'version']));
  const localPackages = (expected.localPackages ?? []).map((value) => dataObject(value,
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
  const versionByName = new Map(workspaces.map((item) => [item.name, item.version]));
  const localByPath = new Map();
  const localByName = new Map();
  for (const item of localPackages) {
    if (!validLocalPackagePath(item.path) || !packageName(item.name) || !exactVersion(item.version)
        || paths.has(item.path) || names.has(item.name) || localByPath.has(item.path) || localByName.has(item.name)) {
      reject('invalid_expectation');
    }
    localByPath.set(item.path, item);
    localByName.set(item.name, item.path);
  }
  for (const item of [root, ...workspaces, ...localPackages]) {
    const ownerPath = item === root ? '' : item.path;
    for (const group of DEPENDENCY_GROUPS) {
      const map = item[group] === undefined ? Object.create(null) : item[group];
      const pins = dataObject(map, Object.keys(map), [], 'invalid_expectation');
      if (Object.keys(pins).length > 512) reject('limit_exceeded');
      item[group] = pins;
      for (const [name, spec] of Object.entries(pins)) {
        const workspaceSpec = names.has(name) && typeof spec === 'string'
          && /^workspace:(?:\*|\^|~|[0-9][0-9A-Za-z.+-]*)$/u.test(spec);
        const localPath = localTargetForSpec(ownerPath, spec);
        const localFileSpec = localPath !== null && localByPath.has(localPath)
          && localByPath.get(localPath).name === name;
        if (!packageName(name) || (!workspaceSpec && !localFileSpec
            && !safeDependencySpec(spec, !names.has(name) && group !== 'peerDependencies'))
            || (!names.has(name) && typeof spec === 'string' && spec.startsWith('workspace:'))) {
          reject('invalid_expectation');
        }
        if (names.has(name) && !workspaceSpec && group !== 'peerDependencies'
            && (item === root || item.name === name || spec !== versionByName.get(name))) {
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
  return { root, workspaces, localPackages };
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

function validateDependencyMap(map, workspaceNames, localByPath, ownerPath) {
  if (map === undefined) return;
  if (map === null || typeof map !== 'object' || Array.isArray(map) || Object.keys(map).length > 512) {
    reject('invalid_package');
  }
  for (const [name, spec] of Object.entries(map)) {
    const workspaceSpec = workspaceNames.has(name) && typeof spec === 'string'
      && /^workspace:(?:\*|\^|~|[0-9][0-9A-Za-z.+-]*)$/u.test(spec);
    const localPath = localTargetForSpec(ownerPath, spec);
    const localFileSpec = localPath !== null && localByPath.has(localPath)
      && localByPath.get(localPath).name === name;
    if (!packageName(name) || (!workspaceSpec && !localFileSpec && !safeDependencySpec(spec, false))) {
      reject('invalid_package');
    }
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
      if (url.protocol !== 'https:' || url.username || url.password
          || (url.hash && !FUNDING_FRAGMENT.test(url.hash))) reject('invalid_package');
      const bareOrigin = url.pathname === '/' && !url.search && !url.hash && url.href === `${funding.url}/`;
      if (url.href !== funding.url && !bareOrigin) reject('invalid_package');
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

function workspaceDirectorySet(workspaces, localPackages = []) {
  const directories = new Set(['packages']);
  for (const workspace of [...workspaces, ...localPackages]) {
    const parts = workspace.path.split('/');
    for (let index = 1; index <= parts.length; index += 1) {
      directories.add(parts.slice(0, index).join('/'));
    }
  }
  return directories;
}

function validRegistryUrl(value, name, version) {
  if (typeof value !== 'string' || value.length > 4096) return false;
  let url;
  try { url = new URL(value); } catch { return false; }
  if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.port
      || url.username || url.password || url.search || url.hash || !url.pathname.startsWith('/')) return false;
  if (url.pathname.includes('//') || url.pathname.split('/').some((part) => part === '.' || part === '..')) return false;
  const packageTail = `/-/${name.split('/').at(-1)}-${version}.tgz`;
  const packagePaths = [`/${name}${packageTail}`];
  if (name.startsWith('@')) {
    const [scope, packageName] = name.split('/');
    packagePaths.push(`/${scope}%2f${packageName}${packageTail}`, `/${scope}%2F${packageName}${packageTail}`);
  }
  return url.href === value && packagePaths.includes(url.pathname);
}

function validSha512Integrity(value) {
  if (typeof value !== 'string' || !value.startsWith('sha512-') || value.length > 128) return false;
  const encoded = value.slice(7);
  if (!/^[A-Za-z0-9+/]{86}==$/u.test(encoded)) return false;
  const decoded = Buffer.from(encoded, 'base64');
  return decoded.byteLength === 64 && decoded.toString('base64') === encoded;
}

const INERT_CPU_TOKENS = new Set([
  'wasm32', 'loong64', 'mips', 'mipsel', 'ppc', 'ppc64', 'riscv64', 's390', 's390x',
]);
const BUNDLED_FIELDS = Object.freeze(['bundledDependencies', 'bundleDependencies']);
const MAX_BUNDLED_NAMES = 64;

function inertBundledNames(entry) {
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) return null;
  const names = [];
  for (const key of BUNDLED_FIELDS) {
    const values = entry[key];
    if (values === undefined) continue;
    if (!Array.isArray(values)) return null;
    names.push(...values);
  }
  if (names.length === 0 || names.length > MAX_BUNDLED_NAMES || entry.optional !== true) return null;
  const cpu = entry.cpu;
  if (!Array.isArray(cpu) || cpu.length === 0 || cpu.length > 16
      || cpu.some((token) => typeof token !== 'string' || !INERT_CPU_TOKENS.has(token))) return null;
  if (names.some((name) => !packageName(name))) return null;
  return new Set(names);
}

function bundledChildAllowed(packages, key, entry, workspaceDirectories) {
  if (entry.inBundle !== true || entry.optional !== true || typeof key !== 'string') return false;
  const marker = key.lastIndexOf('/node_modules/');
  if (marker <= 0) return false;
  const parentPath = key.slice(0, marker);
  const name = key.slice(marker + '/node_modules/'.length);
  if (!parentPath.startsWith('node_modules/') || !Object.hasOwn(packages, parentPath)
      || !nodeModulesPackageName(parentPath, workspaceDirectories)) return false;
  const parent = packages[parentPath];
  if (parent === null || typeof parent !== 'object' || Array.isArray(parent)
      || parent.inBundle === true || Object.hasOwn(parent, 'link')) return false;
  const names = inertBundledNames(parent);
  if (names === null || !names.has(name)) return false;
  if (['resolved', 'tarball', 'integrity', 'link', 'hasInstallScript', ...BUNDLED_FIELDS]
    .some((field) => Object.hasOwn(entry, field))) return false;
  return exactVersion(entry.version) && (entry.name === undefined || entry.name === name);
}

function compareDirectPins(actual, expected) {
  for (const group of DEPENDENCY_GROUPS) {
    if (!exactMap(actual[group], expected[group])) reject('direct_pin_mismatch');
  }
}

function validateDirectPin(packages, name, spec, parentPath, workspaceByName, localByName, includeInventory) {
  const candidates = parentPath ? workspaceResolutionCandidates(parentPath, name) : [`node_modules/${name}`];
  const key = candidates.find((candidate) => Object.hasOwn(packages, candidate));
  if (!key) reject('direct_pin_mismatch');
  const entry = packages[key];
  const workspacePath = workspaceByName.get(name);
  if (workspacePath) {
    if (!entry || entry.link !== true || entry.resolved !== workspacePath) reject('direct_pin_mismatch');
    if (!spec.startsWith('workspace:') && (!parentPath || key !== `node_modules/${name}`)) {
      reject('direct_pin_mismatch');
    }
    return;
  }
  if (typeof spec === 'string' && spec.startsWith('file:')) {
    const localPath = localByName.get(name);
    if (!localPath || !entry || entry.link !== true || entry.resolved !== localPath
        || entry.integrity !== undefined) reject('direct_pin_mismatch');
    return;
  }
  if (!entry || entry.link === true || entry.version !== spec
      || (entry.resolved !== undefined && !validRegistryUrl(entry.resolved, name, spec))
      || (entry.tarball !== undefined && !validRegistryUrl(entry.tarball, name, spec))
      || (entry.integrity !== undefined && !validSha512Integrity(entry.integrity))
      || (includeInventory && (entry.resolved === undefined || !validSha512Integrity(entry.integrity)))) {
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

function validateExpectedDirectPins(packages, expected, workspaceByName, localByName, includeInventory) {
  for (const group of DEPENDENCY_GROUPS) {
    if (group === 'peerDependencies') continue;
    for (const [name, spec] of Object.entries(expected.root[group] ?? {})) {
      validateDirectPin(packages, name, spec, null, workspaceByName, localByName, includeInventory);
    }
    for (const workspace of expected.workspaces) {
      for (const [name, spec] of Object.entries(workspace[group] ?? {})) {
        validateDirectPin(packages, name, spec, workspace.path, workspaceByName, localByName, includeInventory);
      }
    }
  }
}

function buildLockInventory(packages, expected, workspaceByPath, localByPath, workspaceDirectories) {
  const records = Object.create(null);
  const packageKeys = Object.keys(packages);
  for (const key of packageKeys) {
    const entry = packages[key];
    if (key !== '' && entry.link === true) continue;
    if (key !== '' && bundledChildAllowed(packages, key, entry, workspaceDirectories)) continue;
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
    } else if (localByPath.has(key)) {
      const localPackage = localByPath.get(key);
      name = localPackage.name;
      version = localPackage.version;
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
    const bundledNames = inertBundledNames(entry);
    for (const name of [...names].sort()) {
      if (bundledNames !== null && bundledNames.has(name)) continue;
      const candidates = key === ''
        ? [`node_modules/${name}`]
        : (workspaceByPath.has(key) || localByPath.has(key)
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
        if (localByPath.has(key)) continue;
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
  const localByPath = new Map();
  const localByName = new Map();
  for (const localPackage of expected.localPackages) {
    if (!validLocalPackagePath(localPackage.path) || workspaceByPath.has(localPackage.path)
        || localByPath.has(localPackage.path) || workspaceByName.has(localPackage.name)
        || localByName.has(localPackage.name)) reject('invalid_expectation');
    const actual = packages[localPackage.path];
    if (!actual || actual.link === true || actual.name !== localPackage.name
        || actual.version !== localPackage.version) reject('workspace_mismatch');
    localByPath.set(localPackage.path, localPackage);
    localByName.set(localPackage.name, localPackage.path);
    compareDirectPins(actual, localPackage);
  }
  const workspaceDirectories = [...workspaceDirectorySet(expected.workspaces, expected.localPackages)]
    .sort((left, right) => right.length - left.length);
  validateExpectedDirectPins(packages, expected, workspaceByName, localByName, includeInventory);
  for (const key of packageKeys) {
    const entry = packages[key];
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) reject('invalid_package');
    validateEntryMetadata(entry, key === '');
    const ownerPath = key === '' ? '' : (workspaceByPath.has(key) || localByPath.has(key) ? key : null);
    for (const group of DEPENDENCY_GROUPS) {
      validateDependencyMap(entry[group], workspaceByName, localByPath, ownerPath);
    }
    if (key === '' || workspaceByPath.has(key) || localByPath.has(key)) {
      if (entry.resolved !== undefined || entry.tarball !== undefined || entry.integrity !== undefined || entry.link === true) {
        reject('workspace_mismatch');
      }
      continue;
    }
    const moduleName = nodeModulesPackageName(key, workspaceDirectories);
    if (!moduleName) reject('invalid_package_path');
    if (entry.link === true) {
      const target = workspaceByName.get(moduleName) ?? localByName.get(moduleName);
      if (!target || entry.resolved !== target || entry.integrity !== undefined) reject('workspace_link_invalid');
      continue;
    }
    const bundledChild = bundledChildAllowed(packages, key, entry, workspaceDirectories);
    const registrySourceValid = entry.resolved === undefined
      ? !includeInventory
      : validRegistryUrl(entry.resolved, moduleName, entry.version);
    const registryTarballValid = entry.tarball === undefined
      || validRegistryUrl(entry.tarball, moduleName, entry.version);
    const registryIntegrityValid = entry.integrity === undefined
      ? !includeInventory
      : validSha512Integrity(entry.integrity);
    if ((entry.link !== undefined && entry.link !== false)
        || !exactVersion(entry.version)
        || (!bundledChild && (!registrySourceValid || !registryTarballValid || !registryIntegrityValid))) {
      reject('package_source_invalid');
    }
    if (entry.name !== undefined && entry.name !== moduleName) reject('invalid_package');
    if (expected.root.overrides !== undefined) {
      for (const [name, pinned] of Object.entries(expected.root.overrides)) {
        if ((moduleName === name || OVERRIDE_PLATFORM_BINARIES[name]?.has(moduleName)) && entry.version !== pinned) {
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
    result.packages = buildLockInventory(packages, expected, workspaceByPath, localByPath, workspaceDirectories);
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

/** Reject npm-shrinkwrap.json because npm gives it precedence over package-lock.json. */
export function validateNoNpmShrinkwrap(projectDirectory) {
  if (typeof projectDirectory !== 'string' || projectDirectory.length === 0) reject('invalid_project');
  let directory;
  try { directory = fs.lstatSync(projectDirectory); } catch { reject('invalid_project'); }
  if (!directory.isDirectory() || directory.isSymbolicLink()) reject('invalid_project');
  try {
    fs.lstatSync(path.join(projectDirectory, 'npm-shrinkwrap.json'));
  } catch (error) {
    if (error && error.code === 'ENOENT') return true;
    reject('invalid_project');
  }
  reject('npm_shrinkwrap_present');
}

function regularFileBytes(file) {
  let info;
  try { info = fs.lstatSync(file); } catch { reject('invalid_project'); }
  if (!info.isFile() || info.isSymbolicLink() || info.size > LOCK_MANIFEST_LIMITS.inputBytes) {
    reject('invalid_project');
  }
  try { return fs.readFileSync(file); } catch { reject('invalid_project'); }
}

function regularJson(file) {
  const bytes = regularFileBytes(file);
  let value;
  try { value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { reject('invalid_project'); }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) reject('invalid_project');
  return value;
}

function realDirectory(directory) {
  let info;
  try { info = fs.lstatSync(directory); } catch { reject('invalid_project'); }
  if (!info.isDirectory() || info.isSymbolicLink()) reject('invalid_project');
}

function realDirectoryBelow(root, target) {
  realDirectory(root);
  const relative = path.relative(root, target);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    reject('invalid_project');
  }
  let cursor = root;
  for (const component of relative.split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, component);
    realDirectory(cursor);
  }
}

function expectedWorkspacePaths(project, patterns) {
  if (!Array.isArray(patterns) || patterns.length < 1 || patterns.length > 16) reject('invalid_project');
  const found = [];
  for (const pattern of patterns) {
    if (pattern === 'packages/*') {
      const directory = path.join(project, 'packages');
      realDirectory(directory);
      let entries;
      try { entries = fs.readdirSync(directory, { withFileTypes: true }); } catch { reject('invalid_project'); }
      for (const item of entries) {
        if (item.isSymbolicLink()) reject('invalid_project');
        if (!item.isDirectory()) continue;
        const relative = `packages/${item.name}`;
        if (!validWorkspacePath(relative)) reject('invalid_project');
        const workspaceDirectory = path.join(project, relative);
        realDirectory(workspaceDirectory);
        try {
          fs.lstatSync(path.join(workspaceDirectory, 'package.json'));
          found.push(relative);
        } catch (error) {
          if (!error || error.code !== 'ENOENT') reject('invalid_project');
        }
      }
      continue;
    }
    if (typeof pattern !== 'string' || pattern.length > 512 || pattern.includes('*')
        || pattern.includes('\\') || path.isAbsolute(pattern)
        || pattern.split('/').some((part) => !part || part === '.' || part === '..')
        || !validWorkspacePath(pattern)) reject('invalid_project');
    found.push(pattern);
  }
  const unique = [...new Set(found)].sort();
  if (unique.length > 256) reject('limit_exceeded');
  return unique;
}

function dependencyPins(manifest) {
  const pins = {};
  for (const group of DEPENDENCY_GROUPS) {
    if (Object.hasOwn(manifest, group)) pins[group] = manifest[group];
  }
  return pins;
}

function localPackageFromFileSpec(sourceRoot, project, ownerDirectory, dependencyName, spec) {
  if (typeof spec !== 'string' || !spec.startsWith('file:')) return null;
  const relative = spec.slice('file:'.length);
  if (!relative || relative.includes('\\') || path.isAbsolute(relative)) reject('invalid_expectation');
  const target = path.resolve(ownerDirectory, relative);
  const sourceRelative = path.relative(sourceRoot, target).split(path.sep).join('/');
  if (!/^packages\/[A-Za-z0-9_-][A-Za-z0-9._-]*(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$/u.test(sourceRelative)) {
    reject('invalid_expectation');
  }
  realDirectoryBelow(sourceRoot, target);
  const lockPath = path.relative(project, target).split(path.sep).join('/');
  if (!validLocalPackagePath(lockPath)) reject('invalid_expectation');
  const manifest = regularJson(path.join(target, 'package.json'));
  if (manifest.name !== dependencyName) reject('invalid_expectation');
  return { path: lockPath, directory: target, manifest };
}

/** Build the exact npm lock expectation from a checked-out root or runtime project. */
export function deriveNpmLockExpectation(sourceRoot, projectDirectory) {
  if (typeof sourceRoot !== 'string' || typeof projectDirectory !== 'string') reject('invalid_project');
  const source = path.resolve(sourceRoot);
  const project = path.resolve(projectDirectory);
  const projectRelative = path.relative(source, project);
  if (projectRelative !== '' && projectRelative !== 'runtime') reject('invalid_project');
  realDirectoryBelow(source, project);
  validateNoNpmShrinkwrap(project);

  const rootManifest = regularJson(path.join(project, 'package.json'));
  const workspacePaths = expectedWorkspacePaths(project, rootManifest.workspaces);
  const workspaces = workspacePaths.map((workspace) => {
    const directory = path.join(project, workspace);
    realDirectoryBelow(project, directory);
    const manifest = regularJson(path.join(directory, 'package.json'));
    return { path: workspace, name: manifest.name, version: manifest.version, ...dependencyPins(manifest) };
  });
  const localPackagesByPath = new Map();
  const pending = [
    { path: '', directory: project, manifest: rootManifest },
    ...workspaces.map((workspace) => ({
      path: workspace.path,
      directory: path.join(project, workspace.path),
      manifest: regularJson(path.join(project, workspace.path, 'package.json')),
    })),
  ];
  while (pending.length > 0) {
    const owner = pending.shift();
    for (const group of DEPENDENCY_GROUPS) {
      const dependencies = owner.manifest[group];
      if (dependencies === undefined) continue;
      if (dependencies === null || typeof dependencies !== 'object' || Array.isArray(dependencies)) {
        reject('invalid_expectation');
      }
      for (const [name, spec] of Object.entries(dependencies)) {
        if (typeof spec !== 'string' || !spec.startsWith('file:')) continue;
        const localPackage = localPackageFromFileSpec(source, project, owner.directory, name, spec);
        const prior = localPackagesByPath.get(localPackage.path);
        if (prior) {
          if (prior.name !== localPackage.manifest.name || prior.version !== localPackage.manifest.version) {
            reject('invalid_expectation');
          }
          continue;
        }
        if (localPackagesByPath.size >= 256) reject('limit_exceeded');
        const expected = {
          path: localPackage.path,
          name: localPackage.manifest.name,
          version: localPackage.manifest.version,
          ...dependencyPins(localPackage.manifest),
        };
        localPackagesByPath.set(localPackage.path, expected);
        pending.push({ path: localPackage.path, directory: localPackage.directory, manifest: localPackage.manifest });
      }
    }
  }

  const expected = {
    root: {
      name: rootManifest.name,
      version: rootManifest.version,
      workspaces: rootManifest.workspaces,
      ...dependencyPins(rootManifest),
    },
    workspaces,
    localPackages: [...localPackagesByPath.values()].sort((left, right) => (
      left.path < right.path ? -1 : (left.path > right.path ? 1 : 0)
    )),
  };
  if (Object.hasOwn(rootManifest, 'overrides')) expected.root.overrides = rootManifest.overrides;
  return expected;
}

/** Validate a package-lock after rejecting npm-shrinkwrap precedence and unsafe local package links. */
export function validateNpmProjectLock(sourceRoot, projectDirectory) {
  const expected = deriveNpmLockExpectation(sourceRoot, projectDirectory);
  const lockBytes = regularFileBytes(path.join(path.resolve(projectDirectory), 'package-lock.json'));
  return validateLockManifest(lockBytes, expected);
}
