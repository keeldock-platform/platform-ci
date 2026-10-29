import { readFileSync } from 'node:fs';

import { LOCK_MANIFEST_LIMITS, validateLockManifestInventory } from './node_lock_manifest.mjs';

const INPUT_LIMIT = (Math.ceil(LOCK_MANIFEST_LIMITS.inputBytes / 3) * 4) + 262_144;

try {
  const input = readFileSync(0);
  if (input.byteLength > INPUT_LIMIT) throw new Error('inventory input limit');
  const envelope = JSON.parse(input.toString('utf8'));
  if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope)
      || Object.keys(envelope).sort().join(',') !== 'expected,lockBase64'
      || typeof envelope.lockBase64 !== 'string') throw new Error('inventory input shape');
  const lockBytes = Buffer.from(envelope.lockBase64, 'base64');
  if (lockBytes.byteLength > LOCK_MANIFEST_LIMITS.inputBytes
      || lockBytes.toString('base64') !== envelope.lockBase64) throw new Error('inventory lock encoding');
  const inventory = validateLockManifestInventory(lockBytes, envelope.expected);
  const output = JSON.stringify(inventory);
  if (Buffer.byteLength(output, 'utf8') > 16 * 1024 * 1024) throw new Error('inventory output limit');
  process.stdout.write(`${output}\n`);
} catch {
  process.exitCode = 1;
}
