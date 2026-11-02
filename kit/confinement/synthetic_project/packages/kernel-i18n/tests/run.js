import assert from 'node:assert/strict';
import { Worker, isMainThread, parentPort } from 'node:worker_threads';
import { formatDuration } from '../src/index.js';

if (isMainThread) {
  assert.equal(formatDuration(60000), '1m');
  const worker = new Worker(new URL(import.meta.url));
  const message = await new Promise((resolve, reject) => {
    worker.once('message', resolve);
    worker.once('error', reject);
  });
  assert.equal(message, '2s');
  await worker.terminate();
} else {
  parentPort.postMessage(formatDuration(2000));
}
