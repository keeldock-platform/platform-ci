import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseStrictJson } from './safe_json.mjs';

const allowedCompilerOptions = new Set([
  'allowJs', 'checkJs', 'declaration', 'esModuleInterop', 'forceConsistentCasingInFileNames',
  'jsx', 'lib', 'module', 'moduleResolution', 'noEmit', 'noImplicitAny', 'skipLibCheck',
  'strict', 'target', 'types', 'useDefineForClassFields', 'verbatimModuleSyntax',
]);
const codeCatalog = new Set([1005, 2322, 2339, 2345, 2551, 7006, 2307, 2688]);
const idPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

function fail(code = 'report-invalid') {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function inside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function readBounded(file, maximum) {
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.size > maximum) fail('input-file-invalid');
    const data = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < data.length) {
      const count = fs.readSync(descriptor, data, offset, data.length - offset, offset);
      if (count === 0) fail('input-file-truncated');
      offset += count;
    }
    return data;
  } finally {
    fs.closeSync(descriptor);
  }
}

function safeWrite(file, payload) {
  const descriptor = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
  try {
    fs.writeFileSync(descriptor, payload);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function safeCompilerHost(ts, options, sourceRoot, libraryRoot) {
  const host = ts.createCompilerHost(options, true);
  const originalFileExists = host.fileExists.bind(host);
  const originalReadFile = host.readFile.bind(host);
  const originalDirectoryExists = host.directoryExists?.bind(host);
  const originalGetDirectories = host.getDirectories?.bind(host);
  // Reads stay inside the source tree, plus the trusted compiler's own default
  // libraries (lib.*.d.ts) that sit beside it; nothing else is readable.
  const restricted = (candidate) => {
    const resolved = path.resolve(candidate);
    return inside(sourceRoot, resolved) || (libraryRoot !== undefined && inside(libraryRoot, resolved));
  };
  if (libraryRoot !== undefined) host.getDefaultLibLocation = () => libraryRoot;
  host.fileExists = (candidate) => restricted(candidate) && originalFileExists(candidate);
  host.readFile = (candidate) => restricted(candidate) ? originalReadFile(candidate) : undefined;
  if (originalDirectoryExists) host.directoryExists = (candidate) => restricted(candidate) && originalDirectoryExists(candidate);
  if (originalGetDirectories) host.getDirectories = (candidate) => restricted(candidate) ? originalGetDirectories(candidate).filter((name) => restricted(path.join(candidate, name))) : [];
  host.realpath = (candidate) => restricted(candidate) ? path.resolve(candidate) : candidate;
  return host;
}

function compile(ts, sourceRoot, manifest, libraryRoot) {
  if (!manifest || manifest.schema !== 1 || !manifest.allowed_files || typeof manifest.allowed_files !== 'object') {
    fail('manifest-invalid');
  }
  const mappings = manifest.allowed_files;
  for (const [relative, publicId] of Object.entries(mappings)) {
    if (typeof relative !== 'string' || relative.startsWith('/') || relative.includes('\\') || relative.split('/').includes('..') || !idPattern.test(publicId)) {
      fail('file-map-invalid');
    }
  }
  const configPath = path.join(sourceRoot, 'tsconfig.json');
  const configBytes = readBounded(configPath, 1024 * 1024);
  const configText = configBytes.toString('utf8');
  if (configText.includes('\u0000') || /"(?:extends|plugins|references|tsBuildInfoFile)"\s*:/.test(configText)) {
    fail('tsconfig-feature-unsupported');
  }
  let parsedConfig;
  try { parsedConfig = parseStrictJson(configText, 1024 * 1024); } catch { fail('tsconfig-invalid'); }
  if (!parsedConfig || typeof parsedConfig !== 'object') fail('tsconfig-invalid');
  const sourceOptions = parsedConfig.compilerOptions || {};
  if (!sourceOptions || typeof sourceOptions !== 'object' || Object.keys(sourceOptions).some((key) => !allowedCompilerOptions.has(key))) {
    fail('tsconfig-option-unsupported');
  }
  // tsconfig stores enums as JSON strings ("ES2020", "bundler"); the compiler API needs the
  // converted numeric form, so use the compiler's own converter and refuse on any error.
  const converted = ts.convertCompilerOptionsFromJson(sourceOptions, sourceRoot, configPath);
  if (!converted || !Array.isArray(converted.errors) || converted.errors.length > 0 || !converted.options) {
    fail('tsconfig-option-invalid');
  }
  const options = {
    ...converted.options,
    noEmit: true,
    incremental: false,
    composite: false,
    tsBuildInfoFile: undefined,
    configFilePath: configPath,
  };
  const fileNames = ts.sys.readDirectory(sourceRoot, ['.ts', '.tsx', '.mts', '.cts'], ['node_modules', 'target', 'dist', 'coverage', '.git']);
  if (fileNames.length === 0 || fileNames.length > 10000 || fileNames.some((name) => !inside(sourceRoot, path.resolve(name)))) {
    fail('typescript-files-invalid');
  }
  const program = ts.createProgram({
    rootNames: fileNames,
    options,
    host: safeCompilerHost(ts, options, sourceRoot, libraryRoot),
  });
  const diagnostics = ts.getPreEmitDiagnostics(program);
  const records = [];
  for (const diagnostic of diagnostics) {
    if (diagnostic.category !== ts.DiagnosticCategory.Error) continue;
    const numericCode = Number(diagnostic.code);
    const code = codeCatalog.has(numericCode) ? `TS${String(numericCode).padStart(4, '0')}` : 'DEVLANE_FAILURE';
    const record = { kind: 'diagnostic', stage: 'typecheck', code, level: 'error' };
    if (diagnostic.file && typeof diagnostic.start === 'number') {
      const absolute = path.resolve(diagnostic.file.fileName);
      if (inside(sourceRoot, absolute)) {
        const relative = path.relative(sourceRoot, absolute).split(path.sep).join('/');
        if (Object.hasOwn(mappings, relative)) {
          const line = diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start).line + 1;
          record.file = relative;
          record.line = line;
        }
      }
    }
    records.push(record);
    if (records.length > 100) fail('diagnostic-count');
  }
  return records;
}

export async function runTypeScriptReporter({ sourceRoot, manifestPath, outputPath, trustedTypeScriptPath,
  trustedTypeScriptRoot = '/prepared/node_modules' }) {
  const normalizedRoot = fs.realpathSync(sourceRoot);
  if (!fs.statSync(normalizedRoot).isDirectory()) fail('source-root-invalid');
  const manifest = parseStrictJson(readBounded(manifestPath, 4 * 1024 * 1024).toString('utf8'), 4 * 1024 * 1024);
  const tsPath = requireTypeScriptPath(trustedTypeScriptPath, trustedTypeScriptRoot);
  const ts = await import(pathToFileURL(tsPath).href);
  const records = compile(ts.default ?? ts, normalizedRoot, manifest, path.dirname(tsPath));
  const payload = records.map((record) => `${JSON.stringify(record)}\n`).join('');
  if (Buffer.byteLength(payload, 'ascii') > 16 * 1024) fail('diagnostic-size');
  safeWrite(outputPath, payload);
  return records.length;
}

function requireTypeScriptPath(candidate, trustedTypeScriptRoot = '/prepared/node_modules') {
  const preparedRoot = path.resolve(trustedTypeScriptRoot || '');
  const resolved = path.resolve(candidate || '');
  if (!inside(preparedRoot, resolved) || !resolved.endsWith('/typescript/lib/typescript.js')) {
    fail('typescript-unavailable');
  }
  let stat;
  try {
    stat = fs.lstatSync(resolved);
  } catch {
    fail('typescript-unavailable');
  }
  if (!stat.isFile() || stat.isSymbolicLink()) fail('typescript-unavailable');
  return resolved;
}

export { compile as compileForTest };

async function main(argv) {
  if (argv.length !== 4 && argv.length !== 5) fail('usage');
  try {
    const count = await runTypeScriptReporter({ sourceRoot: argv[0], manifestPath: argv[1], outputPath: argv[2],
      trustedTypeScriptPath: argv[3], trustedTypeScriptRoot: argv[4] });
    process.stdout.write(`typescript_records=${count}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`typescript_reporter_refusal=${error?.code || 'reporter-failed'}\n`);
    return 2;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.exitCode = await main(process.argv.slice(2));
}
