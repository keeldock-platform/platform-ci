import { createHash } from 'node:crypto';
import { readFileSync, lstatSync } from 'node:fs';
import { createRequire } from 'node:module';
import { isAbsolute, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { TextDecoder } from 'node:util';

import { validateLockManifest } from './node_lock_manifest.mjs';

export const NODE_CONTRACT_LIMITS = Object.freeze({
  requestBytes: 6 * 1024 * 1024,
  jsonDepth: 32,
  jsonNodes: 200_000,
  jsonStringCodeUnits: 65_536,
  packageVersions: 20_000,
  packageNames: 4_096,
  auditRequestBytes: 1024 * 1024,
  auditResponseBytes: 4 * 1024 * 1024,
  auditSeconds: 90,
  perRequestSeconds: 15,
  advisoryCount: 100_000,
});

export const NODE_CONTRACT_POLICY = Object.freeze({
  nodeVersion: '24.22.1',
  npmVersion: '11.19.1',
  releaseAgeDays: 7,
  auditEndpoint: 'npm-bulk-advisory-v1',
  registryUrl: 'https://registry.npmjs.org/',
});

const BULK_ADVISORY_URL = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk';
const DAY_MS = 24 * 60 * 60 * 1000;
const HASH40 = /^[a-f0-9]{40}$/u;
const HASH64 = /^[a-f0-9]{64}$/u;
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/u;
const IDENTITY_KEYS = Object.freeze(['source_sha', 'base_sha', 'control_sha', 'reviewed_diff_sha256']);
const PROVENANCE_KEYS = Object.freeze([
  'schema_version', 'status', 'generation_identity', 'accepted_source_identity', 'lock_sha256',
  'manifest_sha256', 'node_version', 'npm_version', 'release_age_days', 'policy_epoch_ms',
  'cutoff_epoch_ms', 'age_status', 'generation_attempts', 'audit_endpoint', 'audit_status',
  'accepted_at_ms',
]);
const PROVENANCE_KEYS_WITH_ALLOWS = Object.freeze([...PROVENANCE_KEYS, 'allowed_findings']);
const FINDING_KEYS = Object.freeze([
  'name', 'version', 'severity', 'advisory_id', 'range', 'allow_justification_sha256',
  'allow_expires_at_ms', 'allow_removal_condition',
]);
const MAX_ALLOW_TTL_MS = 90 * DAY_MS;
const MAX_ALLOWED_FINDINGS = 16;
const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, moderate: 2, high: 3, critical: 4 });
const ALLOWABLE_SEVERITY_RANK = Object.freeze({ info: 0, low: 1, moderate: 2 });
const IDENTIFIER = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/u;
const LOCKED_VERSION = /^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}(?:[-+][0-9A-Za-z.+-]{1,64})?$/u;
const PRODUCTION_EDGE_GROUPS = Object.freeze(['dependencies', 'optionalDependencies', 'peerDependencies']);
const ERROR_CODES = new Set([
  'invalid_input', 'limit_exceeded', 'manifest_invalid', 'lock_missing', 'toolchain_mismatch',
  'accepted_provenance_invalid', 'audit_unavailable', 'audit_response_invalid',
  'vulnerable_dependency', 'deadline_exceeded',
]);

export class NodeContractError extends Error {
  constructor(code = 'invalid_input') {
    super('Node contract rejected');
    this.name = 'NodeContractError';
    this.code = ERROR_CODES.has(code) ? code : 'invalid_input';
  }
}

function reject(code = 'invalid_input') {
  throw new NodeContractError(code);
}

function exactKeys(value, keys, code = 'invalid_input') {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) reject(code);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) reject(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key))
      || keys.some((key) => !Object.hasOwn(descriptors, key))) reject(code);
  const result = Object.create(null);
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) reject(code);
    result[key] = descriptor.value;
  }
  return result;
}

function parseStrictJson(text, limits = NODE_CONTRACT_LIMITS) {
  let offset = 0;
  let nodes = 0;
  const whitespace = () => {
    while (text.charCodeAt(offset) === 0x20 || text.charCodeAt(offset) === 0x09
      || text.charCodeAt(offset) === 0x0a || text.charCodeAt(offset) === 0x0d) offset += 1;
  };
  const string = () => {
    if (text[offset] !== '"') reject('audit_response_invalid');
    const start = offset++;
    while (offset < text.length) {
      const code = text.charCodeAt(offset);
      if (code === 0x22) {
        offset += 1;
        let value;
        try { value = JSON.parse(text.slice(start, offset)); } catch { reject('audit_response_invalid'); }
        if (value.length > limits.jsonStringCodeUnits) reject('limit_exceeded');
        return value;
      }
      if (code < 0x20) reject('audit_response_invalid');
      if (code === 0x5c) offset += 1;
      offset += 1;
    }
    reject('audit_response_invalid');
  };
  const value = (depth) => {
    whitespace();
    nodes += 1;
    if (nodes > limits.jsonNodes || depth > limits.jsonDepth) reject('limit_exceeded');
    const char = text[offset];
    if (char === '"') return string();
    if (char === '{') {
      offset += 1;
      whitespace();
      const result = Object.create(null);
      const seen = new Set();
      if (text[offset] === '}') { offset += 1; return result; }
      while (true) {
        whitespace();
        const key = string();
        if (seen.has(key) || key === '__proto__' || key === 'constructor' || key === 'prototype') {
          reject('audit_response_invalid');
        }
        seen.add(key);
        whitespace();
        if (text[offset++] !== ':') reject('audit_response_invalid');
        result[key] = value(depth + 1);
        whitespace();
        if (text[offset] === '}') { offset += 1; return result; }
        if (text[offset++] !== ',') reject('audit_response_invalid');
      }
    }
    if (char === '[') {
      offset += 1;
      whitespace();
      const result = [];
      if (text[offset] === ']') { offset += 1; return result; }
      while (true) {
        result.push(value(depth + 1));
        whitespace();
        if (text[offset] === ']') { offset += 1; return result; }
        if (text[offset++] !== ',') reject('audit_response_invalid');
      }
    }
    if (text.startsWith('true', offset)) { offset += 4; return true; }
    if (text.startsWith('false', offset)) { offset += 5; return false; }
    if (text.startsWith('null', offset)) { offset += 4; return null; }
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(text.slice(offset));
    if (!match) reject('audit_response_invalid');
    offset += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number)) reject('audit_response_invalid');
    return number;
  };
  const parsed = value(0);
  whitespace();
  if (offset !== text.length) reject('audit_response_invalid');
  return parsed;
}

function parseStrictBytes(bytes, maximum, code = 'audit_response_invalid', limits = NODE_CONTRACT_LIMITS) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > maximum) reject('limit_exceeded');
  if (bytes.byteLength >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) reject(code);
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { reject(code); }
  return parseStrictJson(text, limits);
}

function safeInteger(value, minimum = 0) {
  return Number.isSafeInteger(value) && value >= minimum;
}

function validIdentity(input) {
  const identity = exactKeys(input, IDENTITY_KEYS, 'accepted_provenance_invalid');
  if (!HASH40.test(identity.source_sha) || !HASH40.test(identity.base_sha)
      || !HASH40.test(identity.control_sha) || !HASH64.test(identity.reviewed_diff_sha256)) {
    reject('accepted_provenance_invalid');
  }
  return identity;
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) reject('manifest_invalid');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    let descriptors;
    let keys;
    try {
      descriptors = Object.getOwnPropertyDescriptors(value);
      keys = Reflect.ownKeys(value);
    } catch { reject('manifest_invalid'); }
    let prototype;
    try { prototype = Object.getPrototypeOf(value); } catch { reject('manifest_invalid'); }
    if (prototype !== Array.prototype || keys.length !== value.length + 1
        || keys.some((key) => typeof key !== 'string' || (key !== 'length'
          && (!/^(?:0|[1-9][0-9]*)$/u.test(key) || Number(key) >= value.length)))) {
      reject('manifest_invalid');
    }
    const items = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
        reject('manifest_invalid');
      }
      items.push(canonicalJson(descriptor.value));
    }
    return `[${items.join(',')}]`;
  }
  if (typeof value !== 'object') reject('manifest_invalid');
  let prototype;
  let descriptors;
  let keys;
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
    keys = Reflect.ownKeys(value);
  } catch { reject('manifest_invalid'); }
  if (prototype !== null && prototype !== Object.prototype
      || keys.some((key) => typeof key !== 'string' || key === '__proto__')) reject('manifest_invalid');
  const sorted = keys.sort();
  return `{${sorted.map((key) => {
    const descriptor = descriptors[key];
    if (!Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) reject('manifest_invalid');
    return `${JSON.stringify(key)}:${canonicalJson(descriptor.value)}`;
  }).join(',')}}`;
}

function manifestDigest(expectedManifest) {
  const encoded = canonicalJson(expectedManifest);
  if (Buffer.byteLength(encoded, 'ascii') > 256 * 1024 || /[^\x00-\x7f]/u.test(encoded)) {
    reject('manifest_invalid');
  }
  return sha256(Buffer.from(encoded, 'ascii'));
}

function validateGenerationProof(input, sourceIdentity, lockSha256, expectedManifestSha256, nowMs, policyEpochMs) {
  const proof = exactKeys(input, [
    'schema_version', 'status', 'generation_identity', 'lock_sha256', 'manifest_sha256',
    'node_version', 'npm_version', 'release_age_days', 'policy_epoch_ms', 'cutoff_epoch_ms',
    'age_status', 'generation_attempts',
  ], 'accepted_provenance_invalid');
  const proofIdentity = validIdentity(proof.generation_identity);
  if (proof.schema_version !== 1 || proof.status !== 'generated'
      || proof.lock_sha256 !== lockSha256 || proof.node_version !== NODE_CONTRACT_POLICY.nodeVersion
      || proof.manifest_sha256 !== expectedManifestSha256
      || proof.npm_version !== NODE_CONTRACT_POLICY.npmVersion
      || proof.release_age_days !== NODE_CONTRACT_POLICY.releaseAgeDays || proof.age_status !== 'passed'
      || proof.generation_attempts !== 1 || !safeInteger(proof.policy_epoch_ms, 1)
      || !safeInteger(proof.cutoff_epoch_ms)
      || proof.cutoff_epoch_ms !== proof.policy_epoch_ms - 7 * DAY_MS
      || proof.policy_epoch_ms !== policyEpochMs
      || proof.policy_epoch_ms > nowMs || nowMs - proof.policy_epoch_ms > DAY_MS
      || proofIdentity.source_sha !== sourceIdentity.source_sha
      || proofIdentity.base_sha !== sourceIdentity.base_sha
      || proofIdentity.control_sha !== sourceIdentity.control_sha
      || proofIdentity.reviewed_diff_sha256 !== sourceIdentity.reviewed_diff_sha256) {
    reject('accepted_provenance_invalid');
  }
  return proof;
}

function validateAllowedFindings(input, policyEpochMs) {
  if (!Array.isArray(input) || input.length < 1 || input.length > MAX_ALLOWED_FINDINGS) {
    reject('accepted_provenance_invalid');
  }
  const seen = new Set();
  const findings = [];
  for (const item of input) {
    const finding = exactKeys(item, FINDING_KEYS, 'accepted_provenance_invalid');
    const expires = finding.allow_expires_at_ms;
    if (typeof finding.name !== 'string' || finding.name.length > 214 || !PACKAGE_NAME.test(finding.name)
        || typeof finding.version !== 'string' || !LOCKED_VERSION.test(finding.version)
        || typeof finding.severity !== 'string' || !Object.hasOwn(ALLOWABLE_SEVERITY_RANK, finding.severity)
        || typeof finding.advisory_id !== 'string' || !IDENTIFIER.test(finding.advisory_id)
        || typeof finding.range !== 'string' || finding.range.length < 1 || finding.range.length > 1024
        || typeof finding.allow_removal_condition !== 'string'
        || !IDENTIFIER.test(finding.allow_removal_condition)
        || typeof finding.allow_justification_sha256 !== 'string'
        || !HASH64.test(finding.allow_justification_sha256)
        || !safeInteger(expires, 1) || expires <= policyEpochMs || expires > policyEpochMs + MAX_ALLOW_TTL_MS) {
      reject('accepted_provenance_invalid');
    }
    const key = JSON.stringify([finding.name, finding.version, finding.advisory_id]);
    if (seen.has(key)) reject('accepted_provenance_invalid');
    seen.add(key);
    findings.push(Object.freeze({
      name: finding.name,
      version: finding.version,
      severity: finding.severity,
      advisoryId: finding.advisory_id,
      expiresAtMs: expires,
    }));
  }
  return Object.freeze(findings);
}

function validateAcceptedProvenance(input, sourceIdentity, lockSha256, expectedManifestSha256, nowMs) {
  const withAllows = input !== null && typeof input === 'object' && !Array.isArray(input)
    && Object.hasOwn(input, 'allowed_findings');
  const provenance = exactKeys(
    input, withAllows ? PROVENANCE_KEYS_WITH_ALLOWS : PROVENANCE_KEYS, 'accepted_provenance_invalid',
  );
  validIdentity(provenance.generation_identity);
  const acceptedIdentity = validIdentity(provenance.accepted_source_identity);
  if (provenance.schema_version !== (withAllows ? 2 : 1)
      || provenance.audit_status !== (withAllows ? 'allowed_findings' : 'passed')) {
    reject('accepted_provenance_invalid');
  }
  if (provenance.status !== 'accepted'
      || provenance.lock_sha256 !== lockSha256 || provenance.node_version !== NODE_CONTRACT_POLICY.nodeVersion
      || provenance.manifest_sha256 !== expectedManifestSha256
      || provenance.npm_version !== NODE_CONTRACT_POLICY.npmVersion
      || provenance.release_age_days !== NODE_CONTRACT_POLICY.releaseAgeDays
      || provenance.age_status !== 'passed' || provenance.generation_attempts !== 1
      || provenance.audit_endpoint !== NODE_CONTRACT_POLICY.auditEndpoint
      || !safeInteger(provenance.policy_epoch_ms, 1) || !safeInteger(provenance.cutoff_epoch_ms)
      || provenance.cutoff_epoch_ms !== provenance.policy_epoch_ms - 7 * DAY_MS
      || !safeInteger(provenance.accepted_at_ms) || provenance.accepted_at_ms < provenance.policy_epoch_ms
      || provenance.accepted_at_ms > nowMs
      || acceptedIdentity.source_sha !== sourceIdentity.source_sha
      || acceptedIdentity.base_sha !== sourceIdentity.base_sha
      || acceptedIdentity.control_sha !== sourceIdentity.control_sha
      || acceptedIdentity.reviewed_diff_sha256 !== sourceIdentity.reviewed_diff_sha256) {
    reject('accepted_provenance_invalid');
  }
  const allows = withAllows
    ? validateAllowedFindings(provenance.allowed_findings, provenance.policy_epoch_ms)
    : Object.freeze([]);
  return { provenance, allows };
}

function packageNameFromLocation(location) {
  if (typeof location !== 'string' || location.length > 4096) return null;
  let tail;
  const marker = location.lastIndexOf('/node_modules/');
  if (marker >= 0) {
    tail = location.slice(marker + '/node_modules/'.length);
  } else if (location.startsWith('node_modules/')) {
    tail = location.slice('node_modules/'.length);
  } else {
    return null;
  }
  const parts = tail.split('/');
  const name = parts[0]?.startsWith('@') && parts.length === 2
    ? `${parts[0]}/${parts[1]}`
    : parts.length === 1 ? parts[0] : null;
  return typeof name === 'string' && PACKAGE_NAME.test(name)
    && !name.includes('..') && !['__proto__', 'constructor', 'prototype'].includes(name) ? name : null;
}

function publicRemoteInventory(lock, expectedManifest) {
  const rootName = expectedManifest.root.name;
  const privateNames = new Set([rootName, ...expectedManifest.workspaces.map((item) => item.name)]);
  const packageEntries = lock.packages;
  const versions = new Map();
  let totalVersions = 0;
  for (const [location, entry] of Object.entries(packageEntries)) {
    if (location === '' || expectedManifest.workspaces.some((item) => item.path === location)
        || entry.link === true) continue;
    const name = packageNameFromLocation(location);
    if (!name || privateNames.has(name) || typeof entry.version !== 'string') reject('manifest_invalid');
    let selected = versions.get(name);
    if (!selected) {
      selected = new Set();
      versions.set(name, selected);
    }
    selected.add(entry.version);
    totalVersions += 1;
    if (versions.size > NODE_CONTRACT_LIMITS.packageNames
        || totalVersions > NODE_CONTRACT_LIMITS.packageVersions) reject('limit_exceeded');
  }
  const body = Object.create(null);
  let distinctVersions = 0;
  for (const name of [...versions.keys()].sort()) {
    const items = [...versions.get(name)].sort();
    distinctVersions += items.length;
    body[name] = items;
  }
  const encoded = Buffer.from(JSON.stringify(body), 'utf8');
  if (encoded.byteLength > NODE_CONTRACT_LIMITS.auditRequestBytes) reject('limit_exceeded');
  return Object.freeze({
    body,
    packageCount: Object.keys(packageEntries).length,
    remotePackageCount: versions.size,
    remoteVersionCount: distinctVersions,
  });
}

function loadSemver(npmCliPath) {
  const npmSuffix = process.platform === 'win32'
    ? `${sep}node_modules${sep}npm${sep}bin${sep}npm-cli.js`
    : `${sep}lib${sep}node_modules${sep}npm${sep}bin${sep}npm-cli.js`;
  if (typeof npmCliPath !== 'string' || npmCliPath.length > 4096 || !isAbsolute(npmCliPath)
      || resolve(npmCliPath) !== npmCliPath || !npmCliPath.endsWith(npmSuffix)) {
    reject('toolchain_mismatch');
  }
  try {
    const npmRoot = resolve(npmCliPath, '..', '..');
    const npmPackage = createRequire(resolve(npmRoot, 'package.json'))(resolve(npmRoot, 'package.json'));
    const semver = createRequire(resolve(npmRoot, 'package.json'))('semver');
    if (npmPackage.name !== 'npm' || npmPackage.version !== NODE_CONTRACT_POLICY.npmVersion
        || typeof semver.satisfies !== 'function' || typeof semver.validRange !== 'function') {
      reject('toolchain_mismatch');
    }
    return semver;
  } catch (error) {
    if (error instanceof NodeContractError) throw error;
    reject('toolchain_mismatch');
  }
}

function responseHeader(response, name) {
  try { return response.headers.get(name); } catch { return null; }
}

async function readResponseBounded(response, maximum) {
  const declared = responseHeader(response, 'content-length');
  if (declared !== null && (!/^(?:0|[1-9][0-9]*)$/u.test(declared) || Number(declared) > maximum)) {
    reject('limit_exceeded');
  }
  const stream = response.body;
  if (!stream || typeof stream.getReader !== 'function') reject('audit_response_invalid');
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      if (!(part.value instanceof Uint8Array)) reject('audit_response_invalid');
      total += part.value.byteLength;
      if (total > maximum) {
        await reader.cancel().catch(() => {});
        reject('limit_exceeded');
      }
      chunks.push(part.value);
    }
  } catch (error) {
    if (error instanceof NodeContractError) throw error;
    reject('audit_response_invalid');
  } finally {
    try { reader.releaseLock(); } catch { /* no external state is retained */ }
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

async function fetchBounded(fetchImpl, url, options, maximum, deadlineMs, nowMs, allowMissingContentType = false) {
  const remaining = deadlineMs - nowMs();
  if (!safeInteger(remaining, 1)) reject('deadline_exceeded');
  const controller = new AbortController();
  const timeout = Math.min(NODE_CONTRACT_LIMITS.perRequestSeconds * 1000, remaining);
  const timer = setTimeout(() => controller.abort(), timeout);
  const externalSignal = options.signal;
  const abort = () => controller.abort();
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort();
    else externalSignal.addEventListener('abort', abort, { once: true });
  }
  try {
    const response = await fetchImpl(url, { ...options, signal: controller.signal, redirect: 'error' });
    if (response.redirected || (response.url && new URL(response.url).origin !== 'https://registry.npmjs.org')) {
      reject('audit_response_invalid');
    }
    if (response.status !== 200 || !response.ok) reject('audit_unavailable');
    const contentType = responseHeader(response, 'content-type');
    const contentTypeAbsent = contentType === null && allowMissingContentType;
    if (!contentTypeAbsent && !/^application\/(?:json|[a-z0-9.+-]+\+json)(?:\s*;|$)/iu.test(contentType ?? '')) {
      reject('audit_response_invalid');
    }
    return await readResponseBounded(response, maximum);
  } catch (error) {
    if (error instanceof NodeContractError) throw error;
    if (controller.signal.aborted) reject('deadline_exceeded');
    reject('audit_unavailable');
  } finally {
    clearTimeout(timer);
    if (externalSignal) externalSignal.removeEventListener('abort', abort);
  }
}

function resolveDependency(packages, from, name) {
  let current = from;
  for (let guard = 0; guard < 4096; guard += 1) {
    const candidate = `${current ? `${current}/` : ''}node_modules/${name}`;
    if (Object.hasOwn(packages, candidate)) return candidate;
    if (!current) return null;
    const index = current.lastIndexOf('/node_modules/');
    if (index >= 0) current = current.slice(0, index);
    else { const slash = current.lastIndexOf('/'); current = slash >= 0 ? current.slice(0, slash) : ''; }
  }
  return null;
}

function productionReach(packages, workspacePaths) {
  const seen = new Set();
  const stack = ['', ...workspacePaths];
  while (stack.length > 0) {
    const path = stack.pop();
    if (seen.has(path)) continue;
    seen.add(path);
    const entry = Object.hasOwn(packages, path) ? packages[path] : null;
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) continue;
    if (entry.link === true && typeof entry.resolved === 'string') stack.push(entry.resolved);
    for (const group of PRODUCTION_EDGE_GROUPS) {
      const edges = entry[group];
      if (edges === null || typeof edges !== 'object' || Array.isArray(edges)) continue;
      for (const dependency of Object.keys(edges)) {
        const target = resolveDependency(packages, path, dependency);
        if (target !== null) stack.push(target);
      }
    }
  }
  return seen;
}

function advisoryIdentifiers(item) {
  const identifiers = new Set();
  if (typeof item.id === 'string' || safeInteger(item.id)) identifiers.add(String(item.id));
  if (typeof item.github_advisory_id === 'string') identifiers.add(item.github_advisory_id);
  return identifiers;
}

function recordedAllow(item, name, version, allowContext) {
  const severity = item.severity;
  if (typeof severity !== 'string' || !Object.hasOwn(ALLOWABLE_SEVERITY_RANK, severity)) return null;
  const identifiers = advisoryIdentifiers(item);
  const allow = allowContext.allows.find((candidate) => candidate.name === name
    && candidate.version === version && identifiers.has(candidate.advisoryId)
    && SEVERITY_RANK[severity] <= SEVERITY_RANK[candidate.severity]
    && candidate.expiresAtMs > allowContext.fetchedMs);
  if (!allow) return null;
  if (allowContext.reach === null) {
    allowContext.reach = productionReach(allowContext.packages, allowContext.workspacePaths);
  }
  let located = false;
  for (const [location, entry] of Object.entries(allowContext.packages)) {
    if (packageNameFromLocation(location) !== name || entry === null || typeof entry !== 'object'
        || entry.version !== version) continue;
    if (entry.dev !== true || allowContext.reach.has(location)) return null;
    located = true;
  }
  return located ? allow : null;
}

function validateAdvisories(advisories, inventory, semver, allowContext) {
  if (advisories === null || typeof advisories !== 'object' || Array.isArray(advisories)
      || Object.getPrototypeOf(advisories) !== null) reject('audit_response_invalid');
  const requested = new Set(Object.keys(inventory.body));
  const keys = Object.keys(advisories);
  if (keys.some((name) => !requested.has(name))) reject('audit_response_invalid');
  let count = 0;
  let findings = 0;
  const used = new Set();
  for (const name of keys) {
    const items = advisories[name];
    if (!Array.isArray(items)) reject('audit_response_invalid');
    count += items.length;
    if (count > NODE_CONTRACT_LIMITS.advisoryCount) reject('limit_exceeded');
    for (const item of items) {
      if (item === null || typeof item !== 'object' || Array.isArray(item)
          || Object.getPrototypeOf(item) !== null
          || (item.name !== undefined && item.name !== name)
          || typeof item.vulnerable_versions !== 'string' || item.vulnerable_versions.length < 1
          || item.vulnerable_versions.length > 1024) reject('audit_response_invalid');
      let range;
      try { range = semver.validRange(item.vulnerable_versions); } catch { reject('audit_response_invalid'); }
      if (typeof range !== 'string' || !range) reject('audit_response_invalid');
      for (const version of inventory.body[name]) {
        let vulnerable;
        try { vulnerable = semver.satisfies(version, range, { includePrerelease: true }); }
        catch { reject('audit_response_invalid'); }
        if (!vulnerable) continue;
        const allow = recordedAllow(item, name, version, allowContext);
        if (allow === null) reject('vulnerable_dependency');
        findings += 1;
        used.add(allow);
      }
    }
  }
  return { advisoryCount: count, findingCount: findings, allowedCount: used.size };
}

async function auditInventory(inventory, {
  fetchImpl, semver, deadlineMs, nowMs, signal, allows, packages, workspacePaths,
}) {
  if (inventory.remoteVersionCount === 0) return { advisoryCount: 0, findingCount: 0, allowedCount: 0 };
  if (typeof fetchImpl !== 'function') reject('audit_unavailable');
  const body = JSON.stringify(inventory.body);
  let responseBytes;
  try {
    responseBytes = await fetchBounded(fetchImpl, BULK_ADVISORY_URL, {
      method: 'POST',
      headers: { accept: 'application/json', 'content-type': 'application/json' },
      body,
      signal,
    }, NODE_CONTRACT_LIMITS.auditResponseBytes, deadlineMs, nowMs, true);
  } catch (error) {
    if (error instanceof NodeContractError) throw error;
    reject('audit_unavailable');
  }
  const fetchedMs = nowMs();
  const parsed = parseStrictBytes(responseBytes, NODE_CONTRACT_LIMITS.auditResponseBytes);
  return validateAdvisories(parsed, inventory, semver, {
    allows, packages, workspacePaths, fetchedMs, reach: null,
  });
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function validateNodeAndNpm(npmCliPath) {
  if (process.version !== `v${NODE_CONTRACT_POLICY.nodeVersion}`) reject('toolchain_mismatch');
  loadSemver(npmCliPath);
}

export async function validateNodeDependencyLock({
  mode,
  lockBytes,
  expectedManifest,
  sourceIdentity: sourceIdentityInput,
  npmCliPath,
  generationProof,
  acceptedProvenance,
  policyEpochMs,
  nowMs = Date.now(),
  deadlineMs = nowMs + NODE_CONTRACT_LIMITS.auditSeconds * 1000,
  fetchImpl = globalThis.fetch,
  signal,
}) {
  if (mode !== 'bootstrap' && mode !== 'verify') reject('invalid_input');
  if (!(lockBytes instanceof Uint8Array) || lockBytes.byteLength === 0) reject('lock_missing');
  if (lockBytes.byteLength > 4 * 1024 * 1024 - 64 * 1024) reject('limit_exceeded');
  if (!safeInteger(nowMs) || !safeInteger(deadlineMs, nowMs + 1)) reject('invalid_input');
  validateNodeAndNpm(npmCliPath);
  const sourceIdentity = validIdentity(sourceIdentityInput);
  const lockSha256 = sha256(lockBytes);
  let manifestResult;
  try { manifestResult = validateLockManifest(lockBytes, expectedManifest); }
  catch { reject('manifest_invalid'); }
  const expectedManifestSha256 = manifestDigest(expectedManifest);
  let provenance;
  let allows = Object.freeze([]);
  if (mode === 'bootstrap') {
    if (acceptedProvenance !== null && acceptedProvenance !== undefined) reject('invalid_input');
    if (!safeInteger(policyEpochMs, 1)) reject('invalid_input');
    provenance = validateGenerationProof(
      generationProof, sourceIdentity, lockSha256, expectedManifestSha256, nowMs, policyEpochMs,
    );
  } else {
    if (generationProof !== null && generationProof !== undefined) reject('invalid_input');
    if (policyEpochMs !== null && policyEpochMs !== undefined) reject('invalid_input');
    ({ provenance, allows } = validateAcceptedProvenance(
      acceptedProvenance, sourceIdentity, lockSha256, expectedManifestSha256, nowMs,
    ));
  }

  const lock = parseStrictBytes(lockBytes, 4 * 1024 * 1024 - 64 * 1024, 'manifest_invalid');
  const inventory = publicRemoteInventory(lock, expectedManifest);
  const semver = loadSemver(npmCliPath);
  const audit = await auditInventory(inventory, {
    fetchImpl, semver, deadlineMs, nowMs: Date.now, signal, allows,
    packages: lock.packages, workspacePaths: expectedManifest.workspaces.map((item) => item.path),
  });
  return Object.freeze({
    schema_version: 1,
    status: 'passed',
    mode,
    lock_sha256: lockSha256,
    manifest_sha256: expectedManifestSha256,
    node_version: NODE_CONTRACT_POLICY.nodeVersion,
    npm_version: NODE_CONTRACT_POLICY.npmVersion,
    release_age_days: NODE_CONTRACT_POLICY.releaseAgeDays,
    policy_epoch_ms: provenance.policy_epoch_ms,
    cutoff_epoch_ms: provenance.cutoff_epoch_ms,
    age_status: 'passed',
    generation_attempts: 1,
    audit_endpoint: NODE_CONTRACT_POLICY.auditEndpoint,
    audit_status: audit.allowedCount > 0 ? 'allowed_findings' : 'passed',
    package_count: manifestResult.packageCount,
    remote_package_count: inventory.remotePackageCount,
    remote_version_count: inventory.remoteVersionCount,
    advisory_count: audit.advisoryCount,
    finding_count: audit.findingCount,
    allowed_count: audit.allowedCount,
  });
}

function decodeRequest(bytes) {
  const request = parseStrictBytes(bytes, NODE_CONTRACT_LIMITS.requestBytes, 'invalid_input', {
    ...NODE_CONTRACT_LIMITS,
    jsonStringCodeUnits: 5_600_000,
  });
  return exactKeys(request, [
    'schema_version', 'mode', 'lock_base64', 'expected_manifest', 'source_identity', 'npm_cli_path',
    'generation_proof', 'accepted_provenance', 'now_ms', 'deadline_ms',
    'policy_epoch_ms',
  ]);
}

function decodeBase64(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 5_600_000
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    reject('lock_missing');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) reject('invalid_input');
  return bytes;
}

function readPrivateRequest(path) {
  if (!isAbsolute(path) || resolve(path) !== path || typeof process.getuid !== 'function') reject('invalid_input');
  let info;
  let bytes;
  try {
    info = lstatSync(path);
    if (!info.isFile() || info.isSymbolicLink() || info.uid !== process.getuid()
        || info.nlink !== 1 || info.size < 1 || info.size > NODE_CONTRACT_LIMITS.requestBytes
        || (info.mode & 0o022) !== 0) reject('invalid_input');
    bytes = readFileSync(path);
    const after = lstatSync(path);
    if (!after.isFile() || after.isSymbolicLink() || after.uid !== process.getuid()
        || after.nlink !== 1 || after.size !== info.size
        || after.dev !== info.dev || after.ino !== info.ino || bytes.byteLength !== info.size) reject('invalid_input');
  } catch (error) {
    if (error instanceof NodeContractError) throw error;
    reject('invalid_input');
  }
  return bytes;
}

export async function main(argumentsList = process.argv.slice(2), { fetchImpl = globalThis.fetch } = {}) {
  let code = 1;
  let output;
  try {
    if (!Array.isArray(argumentsList) || argumentsList.length !== 2 || argumentsList[0] !== '--request') {
      reject('invalid_input');
    }
    const request = decodeRequest(readPrivateRequest(argumentsList[1]));
    if (request.schema_version !== 1 || typeof request.lock_base64 !== 'string') reject('invalid_input');
    const result = await validateNodeDependencyLock({
      mode: request.mode,
      lockBytes: decodeBase64(request.lock_base64),
      expectedManifest: request.expected_manifest,
      sourceIdentity: request.source_identity,
      npmCliPath: request.npm_cli_path,
      generationProof: request.generation_proof,
      acceptedProvenance: request.accepted_provenance,
      policyEpochMs: request.policy_epoch_ms,
      nowMs: request.now_ms,
      deadlineMs: request.deadline_ms,
      fetchImpl,
    });
    output = { schema_version: 1, status: 'passed', result };
    code = 0;
  } catch (error) {
    output = {
      schema_version: 1,
      status: 'refused',
      reason: error instanceof NodeContractError ? error.code : 'invalid_input',
    };
  }
  process.stdout.write(`${JSON.stringify(output)}\n`);
  return code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().then((code) => { process.exitCode = code; }).catch(() => {
    process.stdout.write('{"reason":"invalid_input","schema_version":1,"status":"refused"}\n');
    process.exitCode = 1;
  });
}
