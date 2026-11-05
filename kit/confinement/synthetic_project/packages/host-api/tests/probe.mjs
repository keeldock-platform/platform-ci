import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';

const packageDir = process.cwd();
const require = createRequire(import.meta.url);
let vitestBin = null;

try {
  const vitestDir = path.dirname(require.resolve('vitest/package.json'));
  vitestBin = path.join(vitestDir, 'vitest.mjs');
  console.log(`PROBE vitest-bin ${path.relative(packageDir, vitestBin)}`);
} catch {
  console.log('PROBE vitest-bin missing');
}

const steps = [
  ['node-ok', ['-e', "console.log('ok')"]],
  ['rolldown-binding', ['-e', "import('rolldown').then(() => console.log('ok'))"]],
  ['vite-import', ['-e', "import('vite').then(() => console.log('ok'))"]],
  ['vitest-node-import', ['-e', "import('vitest/node').then(() => console.log('ok'))"]],
  ['vite-server', ['-e', "import('vite').then(async ({ createServer }) => { const server = await createServer({ configFile: false, server: { middlewareMode: true, watch: null }, optimizeDeps: { noDiscovery: true } }); await server.close(); console.log('ok'); })"]],
  ['worker-thread', ['-e', "const { Worker } = require('node:worker_threads'); const worker = new Worker(\"const { parentPort } = require('node:worker_threads'); parentPort.postMessage('ok')\", { eval: true }); worker.once('message', message => console.log(message));"]],
];

const vitestSteps = [
  ['vitest-threads-runner', [vitestBin, 'run', '--configLoader', 'runner']],
  ['vitest-vmthreads', [vitestBin, 'run', '--configLoader', 'runner', '--pool=vmThreads']],
  ['vitest-no-parallel', [vitestBin, 'run', '--configLoader', 'runner', '--no-file-parallelism', '--maxWorkers=1']],
  ['vitest-native-loader', [vitestBin, 'run', '--configLoader', 'native']],
  ['vitest-forks-1', [vitestBin, 'run', '--configLoader', 'runner', '--pool=forks', '--maxWorkers=1']],
];
steps.push(...vitestSteps.map(([name, args]) => [name, vitestBin === null ? null : args]));

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
