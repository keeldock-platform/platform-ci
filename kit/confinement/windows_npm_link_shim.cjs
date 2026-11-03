'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const MAP_VARIABLE = 'KD_NPM_LINK_MAP';
const HASH_VARIABLE = 'KD_NPM_LINK_MAP_SHA256';
const MAX_MAP_BYTES = 65536;
const MAX_LINKS = 64;
const MAX_PATH_LENGTH = 1000;
const SEGMENT = /^[A-Za-z0-9@._-]{1,100}$/;
const DOTS = /^\.+$/;
const HEX = /^[0-9a-f]{64}$/;
const PRINTABLE = /^[\x20-\x7e]+$/;
const LINK_TAIL = /\\node_modules\\(?:@[a-z0-9][a-z0-9._-]{0,99}\\)?[a-z0-9][a-z0-9._-]{0,99}$/;
const MODULES = '\\node_modules\\';

const refuse = (reason) => {
  throw new Error('npm_link_shim refused ' + reason);
};

const windowsPath = (value) => {
  if (typeof value !== 'string' || value.length < 4 || value.length > MAX_PATH_LENGTH) return false;
  if (!/^[A-Za-z]:\\/.test(value)) return false;
  for (const segment of value.slice(3).split('\\')) {
    if (!SEGMENT.test(segment) || DOTS.test(segment)) return false;
  }
  return path.win32.normalize(value) === value;
};

const plainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype;

const keysAre = (value, expected) => Object.keys(value).sort().join(',') === expected;

const loadMap = () => {
  const mapPath = process.env[MAP_VARIABLE];
  const expected = process.env[HASH_VARIABLE];
  delete process.env[MAP_VARIABLE];
  delete process.env[HASH_VARIABLE];
  if (typeof mapPath !== 'string' || mapPath.length < 4 || mapPath.length > MAX_PATH_LENGTH
      || !PRINTABLE.test(mapPath) || !path.isAbsolute(mapPath)) refuse('map_path');
  if (typeof expected !== 'string' || !HEX.test(expected)) refuse('map_hash');
  const payload = fs.readFileSync(mapPath);
  if (payload.length < 2 || payload.length > MAX_MAP_BYTES) refuse('map_size');
  const actual = crypto.createHash('sha256').update(payload).digest('hex');
  if (actual !== expected) refuse('map_hash');
  const text = payload.toString('latin1');
  if (!PRINTABLE.test(text)) refuse('map_text');
  let map;
  try {
    map = JSON.parse(text);
  } catch (error) {
    refuse('map_json');
  }
  if (!plainObject(map) || !keysAre(map, 'links,schema_version') || map.schema_version !== 1
      || !Array.isArray(map.links)) refuse('map_shape');
  if (map.links.length < 1 || map.links.length > MAX_LINKS) refuse('map_count');
  const links = new Map();
  for (const entry of map.links) {
    if (!plainObject(entry) || !keysAre(entry, 'link,target')) refuse('map_entry');
    if (!windowsPath(entry.link) || !windowsPath(entry.target) || !LINK_TAIL.test(entry.link)) refuse('map_path');
    const key = entry.link.toLowerCase();
    const target = entry.target.toLowerCase();
    const project = key.slice(0, key.indexOf(MODULES));
    if (project.length < 3 || !target.startsWith(project + '\\') || target.includes(MODULES)
        || target.endsWith('\\node_modules') || links.has(key)) refuse('map_entry');
    links.set(key, entry.target);
  }
  return links;
};

const links = loadMap();
const constants = fs.constants;
const promises = fs.promises;
const LINK_MODE = (typeof constants.S_IFLNK === 'number' ? constants.S_IFLNK : 0o120000) | 0o666;
const STATS_PROTOTYPE = typeof fs.Stats === 'function' && fs.Stats.prototype !== null && typeof fs.Stats.prototype === 'object'
  ? fs.Stats.prototype : Object.prototype;
const realLstat = fs.lstat;
const realLstatSync = fs.lstatSync;
const realReadlink = fs.readlink;
const realReadlinkSync = fs.readlinkSync;
const realPromiseLstat = promises.lstat;
const realPromiseReadlink = promises.readlink;
for (const item of [realLstat, realLstatSync, realReadlink, realReadlinkSync, realPromiseLstat, realPromiseReadlink]) {
  if (typeof item !== 'function') refuse('fs_shape');
}

const lookup = (candidate) => {
  if (typeof candidate !== 'string' || candidate.length < 4 || candidate.length > MAX_PATH_LENGTH) return undefined;
  return links.get(path.win32.resolve(candidate).toLowerCase());
};

const bigintRequested = (options) => options !== null && typeof options === 'object' && options.bigint === true;

const linkStats = (target) => {
  const stats = Object.create(STATS_PROTOTYPE);
  const values = {
    dev: 0, mode: LINK_MODE, nlink: 1, uid: 0, gid: 0, rdev: 0, blksize: 4096, ino: 0,
    size: Buffer.byteLength(target, 'utf8'), blocks: 0, atimeMs: 0, mtimeMs: 0, ctimeMs: 0, birthtimeMs: 0,
    atime: new Date(0), mtime: new Date(0), ctime: new Date(0), birthtime: new Date(0),
  };
  for (const name of Object.keys(values)) {
    Object.defineProperty(stats, name, { value: values[name], writable: true, enumerable: true, configurable: true });
  }
  const kinds = [
    ['isSymbolicLink', true], ['isDirectory', false], ['isFile', false], ['isBlockDevice', false],
    ['isCharacterDevice', false], ['isFIFO', false], ['isSocket', false],
  ];
  for (const [name, answer] of kinds) {
    Object.defineProperty(stats, name, { value: () => answer, writable: true, enumerable: false, configurable: true });
  }
  return stats;
};

const linkValue = (target, options) => {
  let encoding;
  if (typeof options === 'string') encoding = options;
  else if (options !== null && typeof options === 'object') encoding = options.encoding;
  if (encoding === undefined || encoding === null || encoding === 'utf8' || encoding === 'utf-8') return target;
  if (encoding === 'buffer') return Buffer.from(target, 'utf8');
  return undefined;
};

fs.lstat = function lstat(candidate, options, callback) {
  const target = lookup(candidate);
  const done = typeof options === 'function' ? options : callback;
  if (target === undefined || typeof done !== 'function' || bigintRequested(options)) {
    return Reflect.apply(realLstat, this, arguments);
  }
  process.nextTick(done, null, linkStats(target));
};

fs.lstatSync = function lstatSync(candidate, options) {
  const target = lookup(candidate);
  if (target === undefined || bigintRequested(options)) return Reflect.apply(realLstatSync, this, arguments);
  return linkStats(target);
};

promises.lstat = async function lstat(candidate, options) {
  const target = lookup(candidate);
  if (target === undefined || bigintRequested(options)) return Reflect.apply(realPromiseLstat, this, arguments);
  return linkStats(target);
};

fs.readlink = function readlink(candidate, options, callback) {
  const target = lookup(candidate);
  const done = typeof options === 'function' ? options : callback;
  const value = target === undefined || typeof options === 'function' ? target : linkValue(target, options);
  if (value === undefined || typeof done !== 'function') return Reflect.apply(realReadlink, this, arguments);
  process.nextTick(done, null, value);
};

fs.readlinkSync = function readlinkSync(candidate, options) {
  const target = lookup(candidate);
  const value = target === undefined ? undefined : linkValue(target, options);
  if (value === undefined) return Reflect.apply(realReadlinkSync, this, arguments);
  return value;
};

promises.readlink = async function readlink(candidate, options) {
  const target = lookup(candidate);
  const value = target === undefined ? undefined : linkValue(target, options);
  if (value === undefined) return Reflect.apply(realPromiseReadlink, this, arguments);
  return value;
};
