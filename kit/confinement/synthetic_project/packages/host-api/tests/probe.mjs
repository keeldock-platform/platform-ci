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
  ['dns-localhost', ['-e', "require('node:dns').lookup('localhost', (error, address) => { console.error(error ? 'err ' + error.code : 'ok ' + address); })"]],
  ['tcp-listen', ['-e', "const server = require('node:net').createServer(); server.once('error', error => { console.error(error.code); process.exit(2); }); server.listen(0, '127.0.0.1', () => server.close());"]],
  ['vite-resolve-config', ['-e', "import('vite').then(v => v.resolveConfig({ configFile: false }, 'serve'))"]],
  ['vite-server-nohmr', ['-e', viteServerCode({ configFile: false, server: { middlewareMode: true, watch: null, hmr: false }, optimizeDeps: { noDiscovery: true } })]],
  ['vite-server-nows', ['-e', viteServerCode({ configFile: false, server: { middlewareMode: true, watch: null, ws: false }, optimizeDeps: { noDiscovery: true } })]],
  ['vite-server-nohmr-nows', ['-e', viteServerCode({ configFile: false, server: { middlewareMode: true, watch: null, hmr: false, ws: false }, optimizeDeps: { noDiscovery: true } })]],
  ['vite-server-nohmr-nows-nopretransform', ['-e', viteServerCode({ configFile: false, server: { middlewareMode: true, watch: null, hmr: false, ws: false, preTransformRequests: false }, optimizeDeps: { noDiscovery: true }, appType: 'custom' })]],
  ['vitest-default', vitestBin === null ? null : [vitestBin, 'run', '--configLoader', 'runner']],
  ['vitest-nohmr-nows', vitestBin === null ? null : [vitestBin, 'run', '--configLoader', 'runner', '--config', 'vitest.nohmr.config.ts']],
  ['vitest-nohmr-nows-vmthreads', vitestBin === null ? null : [vitestBin, 'run', '--configLoader', 'runner', '--config', 'vitest.nohmr.config.ts', '--pool=vmThreads']],
];

const summary = [];

for (const [index, [name, args]] of steps.entries()) {
  const number = index + 1;
  let code;

  if (args === null) {
    code = 'skip';
  } else {
    const result = spawnSync(process.execPath, args, {
      stdio: ['ignore', 'ignore', 'inherit'],
      timeout: 60000,
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
