import fs from 'node:fs';
import { isMainThread } from 'node:worker_threads';
import assert from 'node:assert/strict';
import test from 'node:test';
import os from 'node:os';
import path from 'node:path';
import { parseStrictJson } from './safe_json.mjs';
import { compileForTest, runTypeScriptReporter } from './typescript_reporter.mjs';

const idPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

function fixedFailure(stage) {
  return [{ kind: 'control', stage, status: 'fail', code: 'DEVLANE_FAILURE' }];
}

function parseReport(reportPath) {
  const descriptor = fs.openSync(reportPath, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.size > 256 * 1024 * 1024) throw new Error('report-file-invalid');
    const data = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < data.length) {
      const count = fs.readSync(descriptor, data, offset, data.length - offset, offset);
      if (count === 0) throw new Error('report-file-truncated');
      offset += count;
    }
    return parseStrictJson(data.toString('utf8'), 256 * 1024 * 1024);
  } finally {
    fs.closeSync(descriptor);
  }
}

function safeWriteLines(outputPath, records) {
  if (!Array.isArray(records) || records.length > 100) throw new Error('record-count');
  const payload = records.map((record) => `${JSON.stringify(record)}\n`).join('');
  if (Buffer.byteLength(payload, 'ascii') > 16 * 1024) throw new Error('record-size');
  const descriptor = fs.openSync(outputPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
  try {
    fs.writeFileSync(descriptor, payload);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function normalizeVitest(report, expectedTests) {
  if (!report || !Array.isArray(report.testResults) || !Array.isArray(expectedTests)) return fixedFailure('unit');
  const identity = new Map(expectedTests.map(([name, id]) => [name, id]));
  if (identity.size !== expectedTests.length || [...identity.values()].some((id) => !idPattern.test(id))) return fixedFailure('unit');
  const found = new Map();
  let malformed = false;
  for (const suite of report.testResults) {
    if (!suite || !Array.isArray(suite.assertionResults)) { malformed = true; break; }
    for (const assertion of suite.assertionResults) {
      if (!assertion || typeof assertion.fullName !== 'string' || typeof assertion.status !== 'string') { malformed = true; break; }
      const id = identity.get(assertion.fullName);
      if (!id || found.has(id) || !['passed', 'failed'].includes(assertion.status)) { malformed = true; break; }
      found.set(id, assertion.status);
    }
    if (malformed) break;
  }
  if (malformed || found.size !== identity.size) return fixedFailure('unit');
  return [...found.entries()].filter(([, status]) => status === 'failed')
    .map(([test]) => ({ kind: 'test', stage: 'unit', test }));
}

function normalizePlaywright(report, expectedFrames) {
  if (!report || !Array.isArray(report.suites) || !Array.isArray(expectedFrames)) return fixedFailure('browser');
  const identity = new Map(expectedFrames.map(([name, id]) => [name, id]));
  if (identity.size !== expectedFrames.length || [...identity.values()].some((id) => !/^frame_[0-9]{4,6}$/.test(id))) return fixedFailure('browser');
  const found = new Map();
  let malformed = false;
  function visit(suite) {
    if (!suite || !Array.isArray(suite.specs)) { malformed = true; return; }
    for (const spec of suite.specs) {
      if (!spec || typeof spec.title !== 'string' || !Array.isArray(spec.tests)) { malformed = true; return; }
      const id = identity.get(spec.title);
      if (!id || found.has(id) || spec.tests.length === 0) { malformed = true; return; }
      let status = 'passed';
      for (const test of spec.tests) {
        if (!test || typeof test.projectName !== 'string' || !Array.isArray(test.results) || test.results.length === 0) { malformed = true; return; }
        const finalStatus = test.results[test.results.length - 1]?.status;
        if (!['passed', 'failed', 'timedOut', 'skipped', 'interrupted'].includes(finalStatus)) { malformed = true; return; }
        if (finalStatus !== 'passed') status = 'failed';
      }
      found.set(id, status);
    }
    for (const child of suite.suites || []) visit(child);
  }
  for (const suite of report.suites) visit(suite);
  if (malformed || found.size !== identity.size) return fixedFailure('browser');
  return [...found.entries()].map(([frame, status]) => ({ kind: 'frame', frame, status: status === 'passed' ? 'pass' : 'fail' }));
}

export { normalizePlaywright, normalizeVitest };

async function main(argv) {
  if (argv.length !== 3 || !['vitest', 'playwright'].includes(argv[0])) return 2;
  try {
    const report = parseReport(argv[1]);
    // The manifest remains inside the offline workspace; only opaque public IDs
    // survive this adapter. The first positional config is a trusted file path.
    const config = parseStrictJson(fs.readFileSync('/trusted/adapter-config.json', 'utf8'), 4 * 1024 * 1024);
    const result = argv[0] === 'vitest'
      ? normalizeVitest(report, config.tests)
      : normalizePlaywright(report, config.frames);
    safeWriteLines(argv[2], result);
    return result.some((record) => record.kind === 'control' && record.status === 'fail') ? 1 : 0;
  } catch {
    try { safeWriteLines(argv[2], fixedFailure(argv[0] === 'vitest' ? 'unit' : 'browser')); } catch {}
    return 1;
  }
}

if (process.env.NODE_TEST_CONTEXT) {
  test('Vitest failures expose only reviewed opaque identities', () => {
    const sourceCanary = 'SYNTHETIC_SOURCE_CANARY const value = secret();';
    const secretCanary = 'SYNTHETIC_SECRET_CANARY_81f2';
    const result = normalizeVitest({ testResults: [{ assertionResults: [
      { fullName: 'approved failure', status: 'failed', failureMessages: [sourceCanary, secretCanary] },
    ] }] }, [['approved failure', 'case_0042']]);
    assert.deepEqual(result, [{ kind: 'test', stage: 'unit', test: 'case_0042' }]);
    assert.equal(JSON.stringify(result).includes(sourceCanary), false);
    assert.equal(JSON.stringify(result).includes(secretCanary), false);
  });
  test('unknown or incomplete Vitest identities become fixed failures', () => {
    assert.deepEqual(normalizeVitest({ testResults: [{ assertionResults: [
      { fullName: 'private test input', status: 'failed' },
    ] }] }, [['approved case', 'case_0001']]), fixedFailure('unit'));
  });
  test('a missing prepared TypeScript package becomes a fixed refusal', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'devlane-missing-typescript-'));
    const sourceRoot = path.join(root, 'source');
    const manifestPath = path.join(root, 'manifest.json');
    const outputPath = path.join(root, 'typescript.jsonl');
    fs.mkdirSync(sourceRoot);
    fs.writeFileSync(path.join(sourceRoot, 'tsconfig.json'), '{"compilerOptions":{}}\n');
    fs.writeFileSync(path.join(sourceRoot, 'example.ts'), 'export const value = 1;\n');
    fs.writeFileSync(manifestPath, JSON.stringify({ schema: 1, allowed_files: { 'example.ts': 'file_0001' } }));
    try {
      await assert.rejects(runTypeScriptReporter({
        sourceRoot,
        manifestPath,
        outputPath,
        trustedTypeScriptPath: '/prepared/node_modules/typescript/lib/typescript.js',
      }), (error) => error?.code === 'typescript-unavailable');
      assert.equal(fs.existsSync(outputPath), false);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
  test('Playwright reports only frame IDs and pass/fail', () => {
    const report = {
      config: { workers: 1, reporter: [['json', { outputFile: 'playwright-report.json' }]] },
      suites: [{
        title: 'synthetic browser suite', file: 'tests/example.spec.ts', line: 1, column: 1,
        specs: [{
          title: 'frame sample source canary', ok: false, tags: [],
          tests: [{
            timeout: 30000, annotations: [], expectedStatus: 'passed', projectName: 'chromium',
            results: [{
              workerIndex: 0, parallelIndex: 0, retry: 0, duration: 1, status: 'failed',
              errors: [{ message: 'SYNTHETIC_SECRET_CANARY' }], stdout: [], stderr: [], attachments: [],
            }],
            status: 'unexpected',
          }],
        }],
        suites: [],
      }],
    };
    const result = normalizePlaywright(report, [['frame sample source canary', 'frame_0012']]);
    assert.deepEqual(result, [{ kind: 'frame', frame: 'frame_0012', status: 'fail' }]);
    assert.equal(JSON.stringify(result).includes('SYNTHETIC_SECRET_CANARY'), false);
  });
  test('TypeScript reporter converts tsconfig enum strings and reads only source plus trusted default libraries', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'devlane-ts-'));
    const library = fs.mkdtempSync(path.join(os.tmpdir(), 'devlane-ts-lib-'));
    try {
      fs.writeFileSync(path.join(root, 'tsconfig.json'), JSON.stringify({ compilerOptions: { target: 'ES2020', strict: true } }));
      fs.writeFileSync(path.join(library, 'lib.d.ts'), 'declare var x: number;');
      fs.writeFileSync(path.join(root, 'secret.ts'), 'export const s = 1;');
      let observed = null;
      const fakeTs = {
        DiagnosticCategory: { Error: 1 },
        sys: { readDirectory: () => [path.join(fs.realpathSync(root), 'secret.ts')] },
        convertCompilerOptionsFromJson: (raw) => ({ options: { ...raw, target: 7 }, errors: [] }),
        createCompilerHost: () => ({
          fileExists: (name) => fs.existsSync(name),
          readFile: (name) => (fs.existsSync(name) ? fs.readFileSync(name, 'utf8') : undefined),
        }),
        createProgram: ({ options, host }) => {
          observed = {
            target: options.target,
            library: host.readFile(path.join(fs.realpathSync(library), 'lib.d.ts')),
            outside: host.readFile(path.join(fs.realpathSync(os.tmpdir()), 'devlane-outside-probe')),
            libraryLocation: host.getDefaultLibLocation(),
          };
          return {};
        },
        getPreEmitDiagnostics: () => [],
      };
      fs.writeFileSync(path.join(os.tmpdir(), 'devlane-outside-probe'), 'outside');
      const manifest = { schema: 1, allowed_files: { 'secret.ts': 'file_0001' } };
      compileForTest(fakeTs, fs.realpathSync(root), manifest, fs.realpathSync(library));
      assert.equal(observed.target, 7);
      assert.equal(typeof observed.library, 'string');
      assert.equal(observed.outside, undefined);
      assert.equal(observed.libraryLocation, fs.realpathSync(library));
      assert.throws(() => compileForTest({ ...fakeTs, convertCompilerOptionsFromJson: () => ({ options: {}, errors: [{}] }) },
        fs.realpathSync(root), manifest, fs.realpathSync(library)), /tsconfig-option-invalid/);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(library, { recursive: true, force: true });
      fs.rmSync(path.join(os.tmpdir(), 'devlane-outside-probe'), { force: true });
    }
  });
  test('duplicate JSON keys are refused before report fields are read', () => {
    assert.throws(() => parseStrictJson('{"kind":"diagnostic","kind":"test"}'), /duplicate-json-key/);
    assert.equal(parseStrictJson('{"source":"::error::SYNTHETIC_SECRET_CANARY"}').source,
      '::error::SYNTHETIC_SECRET_CANARY');
  });
}

if (!isMainThread) process.exitCode = 2;
else if (['vitest', 'playwright'].includes(process.argv[2])) process.exitCode = await main(process.argv.slice(2));
