import fs from 'node:fs';
import { isMainThread } from 'node:worker_threads';
import assert from 'node:assert/strict';
import test from 'node:test';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseStrictJson } from './safe_json.mjs';
import { compileForTest, runTypeScriptReporter } from './typescript_reporter.mjs';

const idPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const BROWSER_SMOKE_TIMEOUT_MS = 15000;
const BROWSER_SMOKE_STDERR_BYTES = 8192;
const BROWSER_PROBE_TIMEOUT_MS = 3000;
const BROWSER_SMOKE_VMODULE = '*child_process_launcher*=2,*render_process_host*=2,*utility_process_host*=2';
const BROWSER_SMOKE_BASE_ARGS = [
  '--no-sandbox', '--no-zygote', '--enable-logging=stderr', '--v=1',
  `--vmodule=${BROWSER_SMOKE_VMODULE}`, '--headless', '--dump-dom',
];
const BROWSER_SMOKE_VARIANTS = [
  { name: 'current', args: [] },
  { name: 'single_process', args: ['--single-process'] },
  { name: 'gpu_disabled', args: ['--disable-gpu', '--disable-software-rasterizer', '--disable-dev-shm-usage'] },
  { name: 'network_audio_inproc', args: [
    '--disable-features=NetworkServiceSandbox,AudioServiceOutOfProcess', '--in-process-gpu',
  ] },
  { name: 'font_cache', args: [], fontCache: true },
];
const BROWSER_MOJO_PROBE = [
  'import ctypes, os',
  'PR_GET_DUMPABLE = 3',
  'library = ctypes.CDLL(None, use_errno=True)',
  'prctl = getattr(library, "prctl", None)',
  'ctypes.set_errno(0)',
  'dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) if prctl is not None else -1',
  'prctl_errno = ctypes.get_errno()',
  'print("prctl_dumpable=%s prctl_errno=%s" % (dumpable if dumpable >= 0 else "unavailable", prctl_errno))',
  'name = ("/devlane-mojo-" + str(os.getpid())).encode()',
  'descriptor = os.memfd_create("devlane-mojo", os.MFD_CLOEXEC)',
  'os.write(descriptor, b"x")',
  'os.close(descriptor)',
  'library = ctypes.CDLL(None, use_errno=True)',
  'shm_open = library.shm_open',
  'shm_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_uint]',
  'shm_open.restype = ctypes.c_int',
  'shm_unlink = library.shm_unlink',
  'shm_unlink.argtypes = [ctypes.c_char_p]',
  'shm_unlink.restype = ctypes.c_int',
  'assert os.getuid() == 65534 and os.access("/dev/shm", os.W_OK)',
  'descriptor = shm_open(name, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)',
  'assert descriptor >= 0',
  'os.close(descriptor)',
  'assert shm_unlink(name) == 0',
].join(';');

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

function errnoLabel(error) {
  if (!error) return 'none:0';
  const code = typeof error.code === 'string' && /^[A-Z][A-Z0-9_]{0,31}$/.test(error.code)
    ? error.code : 'unknown';
  const number = Number.isInteger(error.errno) && Math.abs(error.errno) <= 65535
    ? String(Math.abs(error.errno)) : 'unknown';
  return `${code}:${number}`;
}

function metadataSummary(fileSystem, target) {
  try {
    const value = fileSystem.statSync(target);
    const uid = Number.isInteger(value.uid) ? value.uid : 'unknown';
    const gid = Number.isInteger(value.gid) ? value.gid : 'unknown';
    const mode = Number.isInteger(value.mode) ? (value.mode & 0o7777).toString(8).padStart(4, '0') : 'unknown';
    return `ok:${uid}:${gid}:${mode}`;
  } catch (error) {
    return `err:${errnoLabel(error)}`;
  }
}

function accessSummary(fileSystem, target, mode) {
  try {
    fileSystem.accessSync(target, mode);
    return 'ok';
  } catch (error) {
    return `err:${errnoLabel(error)}`;
  }
}

function safeProcTarget(fileSystem) {
  try {
    const target = fileSystem.readlinkSync('/proc/self/exe');
    if (typeof target !== 'string') return 'invalid';
    if (/^\/(?:tools|prepared|usr|bin)\/[A-Za-z0-9._/+:-]{1,240}$/.test(target)) return target;
    if (target.endsWith(' (deleted)')) return 'deleted';
    return target.startsWith('/') ? 'outside-root' : 'invalid';
  } catch (error) {
    return `err:${errnoLabel(error)}`;
  }
}

function statusIdentity(fileSystem) {
  try {
    const text = fileSystem.readFileSync('/proc/self/status', 'utf8');
    const field = (name) => {
      const match = text.match(new RegExp(`^${name}:\\s+([0-9\\s]+)$`, 'm'));
      if (!match) return 'unavailable';
      const values = match[1].trim().split(/\s+/);
      return values.length === 4 && values.every((value) => /^[0-9]{1,10}$/.test(value))
        ? values.join(',') : 'unavailable';
    };
    const dumpable = text.match(/^Dumpable:\s*([0-2])\s*$/m)?.[1] || 'unavailable';
    return { uid: field('Uid'), gid: field('Gid'), dumpable };
  } catch {
    return { uid: 'unavailable', gid: 'unavailable', dumpable: 'unavailable' };
  }
}

function directorySummary(fileSystem, target) {
  if (typeof target !== 'string' || !path.posix.isAbsolute(target)) return 'unavailable';
  const parts = target.split('/').filter(Boolean);
  const rows = [`root:${metadataSummary(fileSystem, '/')}:x${accessSummary(fileSystem, '/', fs.constants.X_OK)}`];
  for (let index = 1; index < parts.length && rows.length < 8; index += 1) {
    const directory = `/${parts.slice(0, index).join('/')}`;
    const name = /^[A-Za-z0-9._-]{1,80}$/.test(parts[index - 1]) ? parts[index - 1] : 'other';
    rows.push(`${name}:${metadataSummary(fileSystem, directory)}:x${accessSummary(fileSystem, directory, fs.constants.X_OK)}`);
  }
  return rows.join(',');
}

function browserRuntimeProbes(spawn = spawnSync, environment = process.env, fileSystem = fs,
  getuid = process.getuid, browserExecutable = '') {
  const output = [];
  let hidepid = 'unavailable';
  let procGid = 'none';
  try {
    const mounts = fileSystem.readFileSync('/proc/mounts', 'utf8');
    const procMount = mounts.split('\n').find((line) => {
      const fields = line.split(' ');
      return fields[1] === '/proc' && fields[2] === 'proc';
    });
    if (procMount) {
      const options = procMount.split(' ')[3]?.split(',') || [];
      hidepid = options.find((option) => /^hidepid=[0-9]+$/.test(option))?.slice(8) || 'default';
      procGid = options.find((option) => /^gid=[0-9]+$/.test(option))?.slice(4) || 'none';
    }
  } catch {}
  const status = statusIdentity(fileSystem);
  const selfStat = metadataSummary(fileSystem, '/proc/self');
  const exeStat = metadataSummary(fileSystem, '/proc/self/exe');
  const exeAccess = accessSummary(fileSystem, '/proc/self/exe', fs.constants.R_OK | fs.constants.X_OK);
  const readlink = safeProcTarget(fileSystem);
  const procProbe = [
    'const fs=require("node:fs");const {spawn}=require("node:child_process");',
    'let finished=false;let child;let deadline;',
    'function errnoLabel(error){const code=typeof error.code==="string"&&/^[A-Z][A-Z0-9_]{0,31}$/.test(error.code)?error.code:"unknown";const number=Number.isInteger(error.errno)&&Math.abs(error.errno)<=65535?String(Math.abs(error.errno)):"unknown";return code+":"+number;}',
    'function finish(childSpawn,childStat,childErrno,code){if(finished)return;finished=true;if(deadline)clearTimeout(deadline);if(child&&child.pid)child.kill("SIGKILL");process.stdout.write(JSON.stringify({child_spawn:childSpawn,child_stat:childStat,child_errno:childErrno}));process.exitCode=code;}',
    'child=spawn("/proc/self/exe",["-e","setTimeout(()=>{},5000)"],{stdio:"ignore"});',
    'child.once("spawn",()=>{try{fs.statSync("/proc/"+child.pid+"/exe");finish("ok","ok","none:0",0);}catch(error){finish("ok","err:"+(typeof error.code==="string"&&/^[A-Z][A-Z0-9_]{0,31}$/.test(error.code)?error.code:"unknown"),errnoLabel(error),4);}});',
    'child.once("error",error=>finish("err:"+(typeof error.code==="string"&&/^[A-Z][A-Z0-9_]{0,31}$/.test(error.code)?error.code:"unknown"),"unavailable",errnoLabel(error),4));',
    'deadline=setTimeout(()=>finish("timeout","unavailable","unknown",4),1500);',
  ].join('');
  let procResult;
  try {
    procResult = spawn('/proc/self/exe', ['-e', procProbe], {
      timeout: BROWSER_PROBE_TIMEOUT_MS,
      maxBuffer: 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
      encoding: 'utf8',
      env: environment,
    });
  } catch {}
  const procRecord = (() => {
    try {
      const value = JSON.parse(procResult?.stdout || 'null');
      if (value && typeof value === 'object'
          && /^(?:ok|err:[A-Z][A-Z0-9_]{0,31}|timeout)$/.test(value.child_spawn)
          && /^(?:ok|err:[A-Z][A-Z0-9_]{0,31}|unavailable)$/.test(value.child_stat)
          && /^(?:none:0|[A-Z][A-Z0-9_]{0,31}:[0-9]{1,5}|unknown)$/.test(value.child_errno)) {
        return value;
      }
    } catch {}
    return { child_spawn: 'unavailable', child_stat: 'unavailable', child_errno: 'unknown' };
  })();
  const procOkay = typeof getuid === 'function' && getuid() === 65534
    && hidepid === '2' && procResult?.status === 0 && !procResult?.error
    && !readlink.startsWith('err:') && selfStat.startsWith('ok:')
    && exeStat.startsWith('ok:') && exeAccess === 'ok'
    && procRecord.child_spawn === 'ok' && procRecord.child_stat === 'ok';
  output.push(`browser_smoke_probe=proc_self_exe result=${procOkay ? 'ok' : 'fail'} launch_errno=${errnoLabel(procResult?.error)}`);
  output.push(`browser_smoke_probe=proc_self_exe_details readlink=${readlink} self_stat=${selfStat} exe_stat=${exeStat} exe_access=${exeAccess} status_Uid=${status.uid} status_Gid=${status.gid} status_Dumpable=${status.dumpable} child_spawn=${procRecord.child_spawn} child_stat=${procRecord.child_stat} child_errno=${procRecord.child_errno} hidepid=${hidepid} gid=${procGid}`);

  const nodeExecutable = typeof process.execPath === 'string' ? process.execPath : '';
  output.push(`browser_smoke_probe=exec_permissions node=${metadataSummary(fileSystem, nodeExecutable)} node_access=${accessSummary(fileSystem, nodeExecutable, fs.constants.R_OK | fs.constants.X_OK)} node_dirs=${directorySummary(fileSystem, nodeExecutable)} browser=${metadataSummary(fileSystem, browserExecutable)} browser_access=${accessSummary(fileSystem, browserExecutable, fs.constants.R_OK | fs.constants.X_OK)} browser_dirs=${directorySummary(fileSystem, browserExecutable)}`);

  let devicesOkay = true;
  for (const [name, access] of [['null', fs.constants.W_OK], ['urandom', fs.constants.R_OK],
    ['zero', fs.constants.R_OK]]) {
    try {
      if (!fileSystem.statSync(`/dev/${name}`).isCharacterDevice()) devicesOkay = false;
      fileSystem.accessSync(`/dev/${name}`, access);
    } catch {
      devicesOkay = false;
    }
  }
  output.push(`browser_smoke_probe=worker_devices result=${devicesOkay ? 'ok' : 'fail'}`);

  let mojoResult;
  try {
    mojoResult = spawn('python3', ['-I', '-c', BROWSER_MOJO_PROBE], {
      timeout: BROWSER_PROBE_TIMEOUT_MS,
      maxBuffer: 2048,
      stdio: ['ignore', 'pipe', 'ignore'],
      env: environment,
    });
  } catch {}
  const mojoStdout = Buffer.isBuffer(mojoResult?.stdout) ? mojoResult.stdout.toString('ascii')
    : typeof mojoResult?.stdout === 'string' ? mojoResult.stdout : '';
  const dumpableMatch = mojoStdout.match(/^prctl_dumpable=(0|1|2|unavailable) prctl_errno=([0-9]{1,5})$/m);
  output.push(dumpableMatch
    ? `browser_smoke_probe=prctl_get_dumpable result=${dumpableMatch[1] === 'unavailable' ? 'unavailable' : 'ok'} value=${dumpableMatch[1]} errno=${dumpableMatch[2]} helper=python3`
    : 'browser_smoke_probe=prctl_get_dumpable result=unavailable');
  const mojoStatus = mojoResult?.status === 0 && !mojoResult?.error ? 'ok'
    : mojoResult?.error?.code === 'ENOENT' ? 'unavailable' : 'fail';
  output.push(`browser_smoke_probe=mojo_shared_memory result=${mojoStatus}`);
  return output;
}

function runBrowserSmoke(executable, spawn = spawnSync, probe = browserRuntimeProbes,
  environment = process.env) {
  if (typeof executable !== 'string' || !path.posix.isAbsolute(executable) || executable.includes('\0')) {
    return { code: 125, output: 'browser_smoke_exit=unavailable\n' };
  }
  let output = '';
  try {
    const probes = probe(spawn, environment, fs, process.getuid, executable);
    if (Array.isArray(probes)) output += probes.slice(0, 8).join('\n') + (probes.length ? '\n' : '');
  } catch {
    output += 'browser_smoke_probe=runtime result=fail\n';
  }
  const baselineEnvironment = { ...environment, HOME: '/devlane-home', XDG_CACHE_HOME: '/scratch/tmp' };
  delete baselineEnvironment.FONTCONFIG_FILE;
  let successful = false;
  for (const variant of BROWSER_SMOKE_VARIANTS) {
    const variantEnvironment = { ...baselineEnvironment };
    if (variant.fontCache) {
      variantEnvironment.HOME = '/scratch/tmp/browser-home';
      variantEnvironment.XDG_CACHE_HOME = '/scratch/tmp/xdg-cache';
      variantEnvironment.FONTCONFIG_FILE = '/etc/fonts/fonts.conf';
    }
    const args = [...BROWSER_SMOKE_BASE_ARGS, ...variant.args, 'about:blank'];
    const started = process.hrtime.bigint();
    let result;
    try {
      result = spawn(executable, args, {
        timeout: BROWSER_SMOKE_TIMEOUT_MS,
        maxBuffer: 524288,
        stdio: ['ignore', 'pipe', 'pipe'],
        encoding: 'buffer',
        env: variantEnvironment,
      });
    } catch {}
    const elapsedMs = Number((process.hrtime.bigint() - started) / 1000000n);
    const timedOut = result?.error?.code === 'ETIMEDOUT';
    const resultLabel = timedOut ? 'timeout'
      : result?.status === 0 && !result?.error ? 'ok'
        : `exit:${Number.isInteger(result?.status) ? result.status : 125}`;
    if (resultLabel === 'ok') successful = true;
    const stderr = Buffer.isBuffer(result?.stderr) ? result.stderr
      : Buffer.from(typeof result?.stderr === 'string' ? result.stderr : '');
    const tail = stderr.subarray(Math.max(0, stderr.length - BROWSER_SMOKE_STDERR_BYTES));
    output += `browser_smoke_variant_stderr_begin=${variant.name} bytes=${tail.length}\n`;
    if (tail.length > 0) output += `${tail.toString('utf8')}\n`;
    output += `browser_smoke_variant_stderr_end=${variant.name}\n`;
    output += `browser_smoke_variant=${variant.name} result=${resultLabel} ms=${elapsedMs}\n`;
  }
  return { code: successful ? 0 : 1, output };
}

async function main(argv) {
  if (argv.length === 2 && argv[0] === 'browser-smoke') {
    const result = runBrowserSmoke(argv[1]);
    process.stdout.write(result.output);
    return result.code;
  }
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
  test('browser smoke runs every bounded Chromium variant and records each result', () => {
    const calls = [];
    const results = [
      { error: { code: 'ETIMEDOUT' }, stderr: Buffer.alloc(BROWSER_SMOKE_STDERR_BYTES + 100, 120) },
      { status: 1, stderr: Buffer.from('single process failed') },
      { status: 0, stderr: Buffer.from('gpu variant started') },
      { status: null, signal: 'SIGKILL', stderr: Buffer.alloc(9000, 120) },
      { status: 2, stderr: Buffer.from('font cache failed') },
    ];
    const result = runBrowserSmoke(
      '/prepared/ms-playwright/chromium_headless_shell-1248/chrome-linux/headless_shell',
      (executable, args, options) => {
        calls.push({ executable, args, options });
        return results.shift();
      },
      () => ['browser_smoke_probe=fixture result=ok'],
      { HOME: '/scratch/tmp/browser-home', XDG_CACHE_HOME: '/scratch/tmp/xdg-cache',
        FONTCONFIG_FILE: '/etc/fonts/fonts.conf' },
    );
    assert.equal(result.code, 0);
    assert.equal(calls.length, 5);
    const commonArgs = [
      '--no-sandbox', '--no-zygote', '--enable-logging=stderr', '--v=1',
      `--vmodule=${BROWSER_SMOKE_VMODULE}`, '--headless', '--dump-dom',
    ];
    assert.equal(calls[0].executable,
      '/prepared/ms-playwright/chromium_headless_shell-1248/chrome-linux/headless_shell');
    assert.deepEqual(calls.map((call) => call.args), [
      [...commonArgs, 'about:blank'],
      [...commonArgs, '--single-process', 'about:blank'],
      [...commonArgs, '--disable-gpu', '--disable-software-rasterizer', '--disable-dev-shm-usage', 'about:blank'],
      [...commonArgs, '--disable-features=NetworkServiceSandbox,AudioServiceOutOfProcess',
        '--in-process-gpu', 'about:blank'],
      [...commonArgs, 'about:blank'],
    ]);
    assert.equal(calls.every((call) => call.options.timeout === BROWSER_SMOKE_TIMEOUT_MS), true);
    assert.equal(calls.every((call) => call.args.some((arg) => arg.startsWith('--vmodule='))), true);
    assert.deepEqual(calls[0].options.env, { HOME: '/devlane-home', XDG_CACHE_HOME: '/scratch/tmp' });
    assert.deepEqual(calls[3].options.env, { HOME: '/devlane-home', XDG_CACHE_HOME: '/scratch/tmp' });
    assert.deepEqual(calls[4].options.env, {
      HOME: '/scratch/tmp/browser-home', XDG_CACHE_HOME: '/scratch/tmp/xdg-cache',
      FONTCONFIG_FILE: '/etc/fonts/fonts.conf',
    });
    assert.match(result.output, /browser_smoke_variant=current result=timeout ms=[0-9]+/);
    assert.match(result.output, /browser_smoke_variant=single_process result=exit:1 ms=[0-9]+/);
    assert.match(result.output, /browser_smoke_variant=gpu_disabled result=ok ms=[0-9]+/);
    assert.match(result.output, /browser_smoke_variant=network_audio_inproc result=exit:125 ms=[0-9]+/);
    assert.match(result.output, /browser_smoke_variant=font_cache result=exit:2 ms=[0-9]+/);
    assert.equal((result.output.match(/bytes=8192/g) || []).length, 2);
    assert.equal(result.output.includes('browser_smoke_stderr_begin'), false);
  });
  test('browser runtime probes verify same-uid proc, worker devices and Mojo shared memory', () => {
    const calls = [];
    const fakeFileSystem = {
      readFileSync: (file) => file === '/proc/mounts'
        ? 'proc /proc proc ro,relatime,hidepid=2,gid=65534 0 0\n'
        : 'Uid:\t65534\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t65534\n',
      readlinkSync: () => '/tools/node/bin/node',
      statSync: () => ({ mode: 0o100555, uid: 0, gid: 0, isCharacterDevice: () => true }),
      accessSync: () => {},
      constants: fs.constants,
    };
    const output = browserRuntimeProbes((executable, args, options) => {
      calls.push({ executable, args, options });
      return executable === 'python3'
        ? { status: 0, stdout: Buffer.from('prctl_dumpable=1 prctl_errno=0\n') }
        : { status: 0, stdout: JSON.stringify({
          child_spawn: 'ok', child_stat: 'ok', child_errno: 'none:0',
        }) };
    }, { PATH: '/usr/bin:/bin' }, fakeFileSystem, () => 65534,
    '/prepared/ms-playwright/chromium_headless_shell-1248/chrome-linux/headless_shell');
    assert.match(output[0], /^browser_smoke_probe=proc_self_exe result=ok launch_errno=none:0$/);
    assert.match(output[1], /readlink=\/tools\/node\/bin\/node .*status_Uid=65534,65534,65534,65534 status_Gid=65534,65534,65534,65534 .*child_spawn=ok child_stat=ok child_errno=none:0 hidepid=2 gid=65534/);
    assert.match(output[2], /browser_smoke_probe=exec_permissions node=ok:0:0:0555 .*browser=ok:0:0:0555 browser_access=ok browser_dirs=root:ok:0:0:0555:xok,prepared:ok:0:0:0555:xok,ms-playwright:ok:0:0:0555:xok,chromium_headless_shell-1248:ok:0:0:0555:xok,chrome-linux:ok:0:0:0555:xok/);
    assert.equal(output[3], 'browser_smoke_probe=worker_devices result=ok');
    assert.equal(output[4], 'browser_smoke_probe=prctl_get_dumpable result=ok value=1 errno=0 helper=python3');
    assert.equal(output[5], 'browser_smoke_probe=mojo_shared_memory result=ok');
    assert.equal(calls[0].executable, '/proc/self/exe');
    assert.equal(calls[0].args[1].includes('/proc/"+child.pid+"/exe'), true);
    assert.doesNotThrow(() => new Function(calls[0].args[2]));
    assert.equal(calls[1].executable, 'python3');
    assert.equal(calls[1].args[2].includes('memfd_create'), true);
    assert.equal(calls[1].args[2].includes('shm_open'), true);
    assert.equal(calls[1].args[2].includes('/dev/shm'), true);
    assert.equal(calls[1].args[2].includes('PR_GET_DUMPABLE'), true);
    const pythonSyntax = spawnSync('python3', [
      '-c', 'import sys; compile(sys.argv[1], "<browser-probe>", "exec")', calls[1].args[2],
    ], { stdio: 'ignore' });
    assert.equal(pythonSyntax.status, 0);
  });
  test('browser proc diagnostics show bounded errno and permission details', () => {
    const denied = Object.assign(new Error('SYNTHETIC_SECRET_CANARY'), { code: 'EACCES', errno: -13 });
    const fakeFileSystem = {
      readFileSync: (file) => file === '/proc/mounts'
        ? 'proc /proc proc ro,relatime,hidepid=2,gid=73 0 0\n'
        : 'Uid:\t65534\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t65534\n',
      readlinkSync: () => '/external/opaque/node',
      statSync: (file) => {
        if (file === '/proc/self/exe') throw denied;
        return { mode: 0o40555, uid: 0, gid: 0 };
      },
      accessSync: (file) => { if (file === '/proc/self/exe') throw denied; },
      constants: fs.constants,
    };
    const output = browserRuntimeProbes((executable) => executable === 'python3'
      ? { status: 0, stdout: Buffer.from('prctl_dumpable=1 prctl_errno=0\n') }
      : { status: null, error: denied }, { PATH: '/usr/bin:/bin' }, fakeFileSystem, () => 65534,
    '/prepared/ms-playwright/chromium_headless_shell-1248/chrome-linux/headless_shell');
    assert.equal(output[0], 'browser_smoke_probe=proc_self_exe result=fail launch_errno=EACCES:13');
    assert.match(output[1], /readlink=outside-root self_stat=ok:0:0:0555 exe_stat=err:EACCES:13 exe_access=err:EACCES:13 .*status_Uid=65534,65534,65534,65534 status_Gid=65534,65534,65534,65534 .*hidepid=2 gid=73/);
    assert.equal(output.join('\n').includes('SYNTHETIC_SECRET_CANARY'), false);
  });
  test('browser proc diagnostics report nested executable errno', () => {
    const fakeFileSystem = {
      readFileSync: (file) => file === '/proc/mounts'
        ? 'proc /proc proc ro,relatime,hidepid=2 0 0\n'
        : 'Uid:\t65534\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t65534\n',
      readlinkSync: () => '/tools/node/bin/node',
      statSync: () => ({ mode: 0o100555, uid: 0, gid: 0, isCharacterDevice: () => true }),
      accessSync: () => {},
      constants: fs.constants,
    };
    const output = browserRuntimeProbes((executable) => executable === '/proc/self/exe'
      ? { status: 4, stdout: JSON.stringify({
        child_spawn: 'err:EACCES', child_stat: 'unavailable', child_errno: 'EACCES:13',
      }) }
      : { status: 0, stdout: Buffer.from('prctl_dumpable=1 prctl_errno=0\n') },
    { PATH: '/usr/bin:/bin' }, fakeFileSystem, () => 65534,
    '/prepared/ms-playwright/chromium_headless_shell-1248/chrome-linux/headless_shell');
    assert.match(output[1], /child_spawn=err:EACCES child_stat=unavailable child_errno=EACCES:13/);
    assert.equal(output[0], 'browser_smoke_probe=proc_self_exe result=fail launch_errno=none:0');
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
else if (process.argv[2] === 'browser-smoke') process.exitCode = await main(process.argv.slice(2));
