import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseStrictJson } from './safe_json.mjs';
import { normalizePlaywright, normalizeVitest } from './test_adapters.mjs';
import { compileForTest } from './typescript_reporter.mjs';

const MAX_REPORT_BYTES = 256 * 1024 * 1024;
const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
const MAX_RECORDS = 100;
const MAX_SUMMARY_BYTES = 16 * 1024;

function readJson(file, maximum) {
  const metadata = fs.lstatSync(file);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > maximum) throw new Error('input-invalid');
  const payload = fs.readFileSync(file);
  if (payload.length > maximum) throw new Error('input-size');
  return parseStrictJson(payload.toString('utf8'), maximum);
}

function writeRecords(file, records) {
  if (!Array.isArray(records) || records.length > MAX_RECORDS) throw new Error('record-count');
  const payload = records.map((record) => `${JSON.stringify(record)}\n`).join('');
  if (Buffer.byteLength(payload, 'ascii') > MAX_SUMMARY_BYTES) throw new Error('record-size');
  const descriptor = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
  try {
    fs.writeFileSync(descriptor, payload, 'ascii');
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

async function main(argv) {
  try {
    if (argv[0] === 'typescript' && argv.length === 5) {
      const manifest = readJson(argv[2], MAX_CONFIG_BYTES);
      const modulePath = pathToFileURL(path.resolve(argv[4])).href;
      const loaded = await import(modulePath);
      const records = compileForTest(loaded.default ?? loaded, path.resolve(argv[1]), manifest,
        path.dirname(path.resolve(argv[4])));
      writeRecords(argv[3], records);
      return 0;
    }
    if (['vitest', 'playwright'].includes(argv[0]) && argv.length === 4) {
      const report = readJson(argv[1], MAX_REPORT_BYTES);
      const config = readJson(argv[2], MAX_CONFIG_BYTES);
      if (!config || typeof config !== 'object') throw new Error('config-invalid');
      const records = argv[0] === 'vitest'
        ? normalizeVitest(report, config.tests)
        : normalizePlaywright(report, config.frames);
      writeRecords(argv[3], records);
      return records.some((record) => record.kind === 'control' && record.status === 'fail') ? 1 : 0;
    }
    return 2;
  } catch {
    return 2;
  }
}

process.exitCode = await main(process.argv.slice(2));
