import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';

const packageDir = process.cwd();
const require = createRequire(import.meta.url);
let vitestBin = null;

try {
  const vitestDir = path.dirname(require.resolve('vitest/package.json'));
  vitestBin = path.join(vitestDir, 'vitest.mjs');
} catch {
  vitestBin = null;
}

const viteServerCode = (config) => `
const fail = error => {
  console.error(String(error?.message ?? error).split(/\\r?\\n/, 1)[0]);
  process.exit(3);
};
import('vite').then(async ({ createServer }) => {
  try {
    const server = await createServer(${JSON.stringify(config)});
    console.error('created');
    await server.close();
  } catch (error) {
    fail(error);
  }
}, fail);
`;

const steps = [
  ['cmd-echo', 'cmd.exe', ['/d', '/s', '/c', 'echo hi'], 20000],
  ['net-use', 'cmd.exe', ['/d', '/s', '/c', 'net use'], 20000],
  ['realpath-native', process.execPath, ['-e', "try { require('node:fs').realpathSync.native(process.cwd()); console.error('ok'); } catch (error) { console.error(error.code); process.exit(2); }"], 60000],
  ['vite-resolve-config-exit', process.execPath, ['-e', "(async () => { try { const v = await import('vite'); await v.resolveConfig({ configFile: false }, 'serve'); console.error('resolved'); process.exit(0); } catch (error) { console.error(error?.code ?? 'error'); process.exit(2); } })()"], 60000],
  ['vite-resolve-config-stub', process.execPath, ['--import', './tests/no-net-use.mjs', '-e', "import('vite').then(v => v.resolveConfig({ configFile: false }, 'serve')).catch(error => { console.error(error?.code ?? 'error'); process.exit(2); })"], 60000],
  ['vite-server-stub', process.execPath, ['--import', './tests/no-net-use.mjs', '-e', viteServerCode({ configFile: false, server: { middlewareMode: true, watch: null, hmr: false, ws: false }, optimizeDeps: { noDiscovery: true } })], 60000],
  ['vitest-stub', process.execPath, vitestBin === null ? null : ['--import', './tests/no-net-use.mjs', vitestBin, 'run', '--configLoader', 'runner'], 60000],
  ['vitest-stub-nohmr', process.execPath, vitestBin === null ? null : ['--import', './tests/no-net-use.mjs', vitestBin, 'run', '--configLoader', 'runner', '--config', 'vitest.nohmr.config.ts'], 60000],
  ['vitest-default', process.execPath, vitestBin === null ? null : [vitestBin, 'run', '--configLoader', 'runner'], 60000],
];

const summary = [];

for (const [index, [name, executable, args, timeout]] of steps.entries()) {
  const number = index + 1;
  let code;

  if (args === null) {
    code = 'skip';
  } else {
    const result = spawnSync(executable, args, {
      stdio: ['ignore', 'ignore', 'inherit'],
      timeout,
      windowsHide: true,
      cwd: packageDir,
    });
    const timedOut = result.error?.code === 'ETIMEDOUT' || result.signal === 'SIGTERM';
    code = timedOut ? 'to' : result.status === 0 ? 'ok' : `e${result.status ?? 1}`;
  }

  console.log(`PROBE ${number} ${name} ${code}`);
  summary.push(`${number}=${code}`);
}

console.log(`PROBE summary ${summary.join(' ')}`);
process.exitCode = 1;
