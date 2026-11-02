import assert from 'node:assert/strict';
import { Worker, isMainThread, parentPort } from 'node:worker_threads';
import { apiVersion, describe } from '../src/index.js';

if (isMainThread) {
  assert.equal(apiVersion, 1);
  assert.equal(describe('api'), 'api@1');
  const worker = new Worker(new URL(import.meta.url));
  const message = await new Promise((resolve, reject) => {
    worker.once('message', resolve);
    worker.once('error', reject);
  });
  assert.equal(message, 'api@1');
  await worker.terminate();
} else {
  parentPort.postMessage(describe('api'));
}
