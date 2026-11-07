import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { before, test } from 'node:test';

import {
  DEVELOPMENT_FEEDBACK_LIMITS,
  DevelopmentFeedbackError,
  decryptDevelopmentFeedback,
  decryptDevelopmentFeedbackWithRustSources,
  encryptDevelopmentFeedback,
  encryptDevelopmentFeedbackWithRustSources,
  validateDevelopmentFeedback,
} from './development_feedback.mjs';
import { encryptReturnEnvelope, LOCK_ENVELOPE_LIMITS, RETURN_PROFILES } from './node_lock_envelope.mjs';

const NOW = 1_793_160_000;
let recipient;

function fingerprint(key) {
  return createHash('sha256').update(key.export({ format: 'der', type: 'spki' })).digest('hex');
}

function contextFor(profileName) {
  const profile = RETURN_PROFILES[profileName];
  const context = {
    request_id: '1'.repeat(64),
    nonce: '2'.repeat(64),
    recipient_fingerprint: fingerprint(recipient.publicKey),
    concern: profile.concern,
    repository_id: '123456',
    source_sha: 'a'.repeat(40),
    base_sha: 'b'.repeat(40),
    control_sha: 'c'.repeat(40),
    base_branch: 'main',
    reviewed_diff_sha256: 'd'.repeat(64),
    workflow_ref: profile.workflowRef ?? 'refs/heads/main',
    run_id: '987654321',
    producer_job: profile.producerJob,
    run_attempt: 1,
    expiry: NOW + 3600,
  };
  context.kind = profile.kind;
  return context;
}

function rustPatch(
  path = 'src/lib.rs',
  oldLine = 'pub const VALUE: u32 = 1;',
  newLine = 'pub const VALUE: u32 = 2;',
) {
  return Buffer.from([
    `diff --git a/${path} b/${path}`,
    'index 1111111..2222222 100644',
    `--- a/${path}`,
    `+++ b/${path}`,
    '@@ -1,1 +1,1 @@',
    `-${oldLine}`,
    `+${newLine}`,
    '',
  ].join('\n'), 'utf8');
}

function sizedRustPatch(totalBytes) {
  const width = 4000;
  const prefix = [
    'diff --git a/src/lib.rs b/src/lib.rs',
    'index 1111111..2222222 100644',
    '--- a/src/lib.rs',
    '+++ b/src/lib.rs',
    '',
  ].join('\n');
  const pairs = Math.floor((totalBytes - 512) / (2 * (width + 2)));
  const header = `@@ -1,${pairs} +1,${pairs} @@\n`;
  const extra = totalBytes - prefix.length - header.length - pairs * 2 * (width + 2);
  const removed = Array.from({ length: pairs }, () => `-${'x'.repeat(width)}\n`).join('');
  const added = Array.from({ length: pairs },
    (_, index) => `+${'y'.repeat(index === pairs - 1 ? width + extra : width)}\n`).join('');
  const patch = Buffer.from(prefix + header + removed + added, 'ascii');
  assert.equal(patch.length, totalBytes);
  return patch;
}

function linedRustPatch(totalLines) {
  const hunks = Math.floor((totalLines - 4) / 3);
  const spare = totalLines - 4 - hunks * 3;
  const lines = [
    'diff --git a/src/lib.rs b/src/lib.rs',
    'index 1111111..2222222 100644',
    '--- a/src/lib.rs',
    '+++ b/src/lib.rs',
  ];
  for (let index = 0; index < hunks; index += 1) {
    const extra = index === hunks - 1 ? spare : 0;
    lines.push(`@@ -${index * 2 + 1},${1 + extra} +${index * 2 + 1},${1 + extra} @@`, '-a', '+b');
    for (let count = 0; count < extra; count += 1) lines.push(' c');
  }
  lines.push('');
  const patch = Buffer.from(lines.join('\n'), 'ascii');
  assert.equal(lines.length - 1, totalLines);
  return patch;
}

function manyFilePatch(count) {
  const lines = [];
  for (let index = 0; index < count; index += 1) {
    const path = index === 0 ? 'src/lib.rs' : `src/module_${index}.rs`;
    lines.push(`diff --git a/${path} b/${path}`, '--- a/' + path, '+++ b/' + path, '@@ -1,1 +1,1 @@', '-a', '+b');
  }
  lines.push('');
  return Buffer.from(lines.join('\n'), 'ascii');
}

function validate(kind, payloadBytes, extra = {}) {
  const profileName = kind === 'rust_patch' ? 'core-rust-format-return'
    : kind === 'linux_quick' ? 'core-linux-quick-return' : 'core-build-diagnostic-return';
  return validateDevelopmentFeedback({ payloadBytes, context: contextFor(profileName), now: NOW, ...extra });
}

function encryptRustPatchWithSources(payloadBytes, originals, reviewedRustPaths = ['src/lib.rs']) {
  return encryptDevelopmentFeedbackWithRustSources({
    payloadBytes,
    context: contextFor('core-rust-format-return'),
    recipientPublicKey: recipient.publicKey,
    now: NOW,
    reviewedRustPaths,
  }, new Map(Object.entries(originals).map(([path, contents]) => [path, Buffer.from(contents, 'utf8')])));
}

function decryptRustPatchWithSources(envelope, originals) {
  return decryptDevelopmentFeedbackWithRustSources({
    envelope,
    context: contextFor('core-rust-format-return'),
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
    reviewedRustPaths: ['src/lib.rs'],
  }, new Map(Object.entries(originals).map(([path, contents]) => [path, Buffer.from(contents, 'utf8')])));
}

before(() => {
  recipient = generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 65537 });
});

test('accepts a one-file patch only for an exact reviewed Rust path', () => {
  const payload = rustPatch();
  assert.deepEqual(validate('rust_patch', payload, { reviewedRustPaths: ['src/lib.rs'] }), payload);
  for (const rejected of [
    rustPatch('../outside.rs'),
    rustPatch('src/main.rs'),
    Buffer.from(rustPatch().toString('utf8').replace(
      'index 1111111..2222222 100644',
      'index 1111111..2222222 100644\nrename from src/lib.rs\nrename to src/renamed.rs',
    ), 'utf8'),
    Buffer.from('diff --git a/src/lib.rs b/src/lib.rs\nGIT binary patch\n', 'utf8'),
    Buffer.from(rustPatch().toString('utf8').replace('@@ -1,1 +1,1 @@', '@@ -1,2 +1,1 @@'), 'utf8'),
    Buffer.from(`${rustPatch().toString('utf8').trimEnd()}\n${rustPatch().toString('utf8')}`, 'utf8'),
    rustPatch('src/lib.rs', 'old source line', '// password=synthetic-fixture-value'),
    rustPatch('src/lib.rs', 'old source line', '// token=synthetic-fixture-value'),
    rustPatch('src/lib.rs', 'old source line', '// -----BEGIN PRIVATE KEY-----'),
    rustPatch('src/lib.rs', '// secret=synthetic-fixture-value', 'new source line'),
  ]) {
    assert.throws(() => validate('rust_patch', rejected, { reviewedRustPaths: ['src/lib.rs'] }), DevelopmentFeedbackError);
  }
  assert.throws(() => validate('rust_patch', payload, { reviewedRustPaths: ['../outside.rs'] }), DevelopmentFeedbackError);
  assert.throws(() => validate('rust_patch', Buffer.alloc(DEVELOPMENT_FEEDBACK_LIMITS.rustPatchBytes + 1), {
    reviewedRustPaths: ['src/lib.rs'],
  }), DevelopmentFeedbackError);
});

test('accepts whitespace-equivalent rust patches with credential-shaped context', () => {
  const payload = rustPatch('src/lib.rs', 'let token=CancellationToken::new();',
    'let token = CancellationToken::new();');
  const envelope = encryptRustPatchWithSources(payload, {
    'src/lib.rs': 'let token=CancellationToken::new();\n',
  });
  assert.ok(envelope instanceof Uint8Array);
});

test('accepts a subset patch with originals for its changed reviewed file', () => {
  const payload = rustPatch('src/lib.rs', 'let token=CancellationToken::new();',
    'let token = CancellationToken::new();');
  const envelope = encryptRustPatchWithSources(payload, {
    'src/lib.rs': 'let token=CancellationToken::new();\n',
  }, ['src/lib.rs', 'src/unchanged.rs']);
  assert.ok(envelope instanceof Uint8Array);
});

test('rejects consumer originals outside the reviewed Rust path set', () => {
  const payload = rustPatch('src/lib.rs', 'let value = alpha;', 'let value = beta;');
  assert.throws(() => encryptRustPatchWithSources(payload, {
    'src/lib.rs': 'let value = alpha;\n',
    'src/unchanged.rs': 'fn unchanged() {}\n',
  }, ['src/lib.rs']), { code: 'invalid_expectation' });
});

test('rejects rust patches that add a credential-shaped literal', () => {
  const payload = Buffer.from([
    'diff --git a/src/lib.rs b/src/lib.rs',
    '--- a/src/lib.rs',
    '+++ b/src/lib.rs',
    '@@ -1,1 +1,2 @@',
    ' fn run() {}',
    '+let token = "synthetic-secret-value";',
    '',
  ].join('\n'), 'utf8');
  assert.throws(() => encryptRustPatchWithSources(payload, {
    'src/lib.rs': 'fn run() {}\n',
  }), { code: 'credential_like_content' });
});

test('continues scanning credential-shaped text for non-rust payloads', () => {
  const payload = rustPatch('src/lib.rs', 'let token=CancellationToken::new();',
    'let token = CancellationToken::new();');
  assert.throws(() => encryptDevelopmentFeedback({
    payloadBytes: payload,
    context: contextFor('core-build-diagnostic-return'),
    recipientPublicKey: recipient.publicKey,
    now: NOW,
  }), {
    code: 'credential_like_content',
  });
});

test('scans credential-shaped context when a rust patch changes a non-whitespace token', () => {
  const payload = Buffer.from([
    'diff --git a/src/lib.rs b/src/lib.rs',
    '--- a/src/lib.rs',
    '+++ b/src/lib.rs',
    '@@ -1,2 +1,2 @@',
    ' let token = CancellationToken::new();',
    '-let value = alpha;',
    '+let value = beta;',
    '',
  ].join('\n'), 'utf8');
  assert.throws(() => encryptRustPatchWithSources(payload, {
    'src/lib.rs': 'let token = CancellationToken::new();\nlet value = alpha;\n',
  }), { code: 'credential_like_content' });
});

test('decrypts whitespace-equivalent credential-shaped patches with consumer originals', () => {
  const payload = rustPatch('src/lib.rs', 'let token=CancellationToken::new();',
    'let token = CancellationToken::new();');
  const originals = { 'src/lib.rs': 'let token=CancellationToken::new();\n' };
  const envelope = encryptRustPatchWithSources(payload, originals);
  assert.deepEqual(decryptRustPatchWithSources(envelope, originals), payload);
});

test('scans equivalent credential-shaped patches when consumer originals are absent', () => {
  const payload = rustPatch('src/lib.rs', 'let token=CancellationToken::new();',
    'let token = CancellationToken::new();');
  const envelope = encryptRustPatchWithSources(payload, {
    'src/lib.rs': 'let token=CancellationToken::new();\n',
  });
  assert.throws(() => decryptDevelopmentFeedback({
    envelope,
    context: contextFor('core-rust-format-return'),
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
    reviewedRustPaths: ['src/lib.rs'],
  }), { code: 'credential_like_content' });
});

test('scans when consumer originals differ from the producer originals', () => {
  const payload = rustPatch('src/lib.rs', 'let token=CancellationToken::new();',
    'let token = CancellationToken::new();');
  const producerOriginal = 'let token=CancellationToken::new();\nlet value = alpha;\n';
  const envelope = encryptRustPatchWithSources(payload, { 'src/lib.rs': producerOriginal });
  assert.throws(() => decryptRustPatchWithSources(envelope, {
    'src/lib.rs': 'let token=OtherCall::new();\nlet value = beta;\n',
  }), { code: 'credential_like_content' });
});

test('bounds the reviewed Rust path list at the four crate headroom', () => {
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.reviewedRustPaths, 512);
  const payload = rustPatch();
  const reviewed = (count) => ['src/lib.rs', ...Array.from({ length: count - 1 }, (_, index) => `src/module_${index}.rs`)];
  assert.deepEqual(validate('rust_patch', payload, { reviewedRustPaths: reviewed(512) }), payload);
  assert.throws(() => validate('rust_patch', payload, { reviewedRustPaths: reviewed(513) }), DevelopmentFeedbackError);
  assert.throws(() => validate('rust_patch', payload, { reviewedRustPaths: [] }), DevelopmentFeedbackError);
});

test('pins the Rust patch limits to the reviewed path cap and the envelope plaintext bound', () => {
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.rustPatchBytes, 4 * 1024 * 1024 - 64 * 1024);
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.rustPatchBytes, LOCK_ENVELOPE_LIMITS.plaintextBytes);
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.rustPatchFiles, 512);
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.rustPatchFiles, DEVELOPMENT_FEEDBACK_LIMITS.reviewedRustPaths);
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.rustPatchLines, 131_072);
});

test('accepts a Rust patch of exactly the byte limit and rejects one byte more', () => {
  const limit = DEVELOPMENT_FEEDBACK_LIMITS.rustPatchBytes;
  const atLimit = sizedRustPatch(limit);
  assert.deepEqual(validate('rust_patch', atLimit, { reviewedRustPaths: ['src/lib.rs'] }), atLimit);
  assert.throws(() => validate('rust_patch', sizedRustPatch(limit + 1), { reviewedRustPaths: ['src/lib.rs'] }),
    { code: 'payload_too_large' });
});

test('accepts a Rust patch at the file cap and rejects one file more', () => {
  const reviewed = (count) => ['src/lib.rs', ...Array.from({ length: count - 1 }, (_, index) => `src/module_${index + 1}.rs`)];
  const atCap = manyFilePatch(DEVELOPMENT_FEEDBACK_LIMITS.rustPatchFiles);
  assert.deepEqual(validate('rust_patch', atCap, { reviewedRustPaths: reviewed(512) }), atCap);
  assert.throws(() => validate('rust_patch', manyFilePatch(DEVELOPMENT_FEEDBACK_LIMITS.rustPatchFiles + 1), {
    reviewedRustPaths: reviewed(512),
  }), DevelopmentFeedbackError);
});

test('accepts a Rust patch below the line limit and rejects one at the limit', () => {
  const limit = DEVELOPMENT_FEEDBACK_LIMITS.rustPatchLines;
  const below = linedRustPatch(limit - 1);
  assert.deepEqual(validate('rust_patch', below, { reviewedRustPaths: ['src/lib.rs'] }), below);
  assert.throws(() => validate('rust_patch', linedRustPatch(limit), { reviewedRustPaths: ['src/lib.rs'] }),
    { code: 'limit_exceeded' });
});

test('round trips a Rust patch of exactly the byte limit through the envelope', () => {
  const context = contextFor('core-rust-format-return');
  const payload = sizedRustPatch(DEVELOPMENT_FEEDBACK_LIMITS.rustPatchBytes);
  const envelope = encryptDevelopmentFeedback({
    payloadBytes: payload,
    context,
    recipientPublicKey: recipient.publicKey,
    now: NOW,
    reviewedRustPaths: ['src/lib.rs'],
  });
  assert.ok(envelope.byteLength <= LOCK_ENVELOPE_LIMITS.frameBytes);
  assert.deepEqual(decryptDevelopmentFeedback({
    envelope,
    context,
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
    reviewedRustPaths: ['src/lib.rs'],
  }), payload);
});

test('accepts bounded diagnostics and rejects malformed or credential-shaped text', () => {
  const payload = Buffer.from('compiler completed with zero warnings\n', 'utf8');
  assert.deepEqual(validate('build_diagnostics', payload), payload);
  for (const rejected of [
    Buffer.from([0xc3, 0x28]),
    Buffer.from('first\0second\n', 'utf8'),
    Buffer.from('password=synthetic-fixture-value\n', 'utf8'),
    Buffer.from('token=synthetic-fixture-value\n', 'utf8'),
    Buffer.from('https://user:placeholder@example.invalid/path\n', 'utf8'),
    Buffer.from('-----BEGIN PRIVATE KEY-----\n', 'utf8'),
    Buffer.alloc(DEVELOPMENT_FEEDBACK_LIMITS.diagnosticBytes + 1),
  ]) {
    assert.throws(() => validate('build_diagnostics', rejected), DevelopmentFeedbackError);
  }
});

test('diagnostic text refusals name the violated class and still refuse every such byte', () => {
  const cases = [
    [Buffer.from([0xef, 0xbb, 0xbf, 0x61, 0x0a]), 'invalid_payload_bom'],
    [Buffer.from([0xc3, 0x28]), 'invalid_payload_utf8'],
    [Buffer.from([0x61, 0xe2, 0x8e]), 'invalid_payload_utf8'],
    [Buffer.from('first\0second\n', 'utf8'), 'invalid_payload_nul'],
    [Buffer.from('first\rsecond\n', 'utf8'), 'invalid_payload_cr'],
    [Buffer.from('first\u001bsecond\n', 'utf8'), 'invalid_payload_c0'],
    [Buffer.from('first\u0008second\n', 'utf8'), 'invalid_payload_c0'],
    [Buffer.from('first\u007fsecond\n', 'utf8'), 'invalid_payload_c0'],
    [Buffer.from('first\u0080second\n', 'utf8'), 'invalid_payload_c1'],
    [Buffer.from('first\u0085second\n', 'utf8'), 'invalid_payload_c1'],
    [Buffer.from('first\u009fsecond\n', 'utf8'), 'invalid_payload_c1'],
  ];
  for (const [bytes, code] of cases) {
    assert.throws(() => validate('build_diagnostics', bytes), { code }, code);
  }
  // Tab and newline stay allowed, and the visible escape forms the producer emits are plain text.
  const allowed = Buffer.from('a\tb\nstdout \\u{1b} \\u{85} \\x80 end\n', 'utf8');
  assert.deepEqual(validate('build_diagnostics', allowed), allowed);
  // A line over the code-unit limit is still a limit refusal, not a text-class refusal.
  assert.throws(
    () => validate('build_diagnostics', Buffer.from('a'.repeat(DEVELOPMENT_FEEDBACK_LIMITS.diagnosticLineCodeUnits + 1))),
    { code: 'limit_exceeded' },
  );
});

test('the development exception requires a trusted in-window clock and bounded expiry', () => {
  const payloadBytes = Buffer.from('compiler completed with zero warnings\n', 'utf8');
  const context = contextFor('core-build-diagnostic-return');
  assert.throws(() => validateDevelopmentFeedback({ payloadBytes, context }), DevelopmentFeedbackError);
  assert.throws(() => validateDevelopmentFeedback({
    payloadBytes,
    context,
    now: DEVELOPMENT_FEEDBACK_LIMITS.exceptionEndUnixSeconds,
  }), DevelopmentFeedbackError);
  assert.throws(() => validateDevelopmentFeedback({ payloadBytes, context, now: NOW + 0.5 }), DevelopmentFeedbackError);
  assert.throws(() => validateDevelopmentFeedback({
    payloadBytes,
    context: { ...context, expiry: NOW },
    now: NOW,
  }), DevelopmentFeedbackError);
  assert.throws(() => validateDevelopmentFeedback({
    payloadBytes,
    context: { ...context, expiry: NOW + DEVELOPMENT_FEEDBACK_LIMITS.contextLifetimeSeconds + 1 },
    now: NOW,
  }), DevelopmentFeedbackError);
  assert.throws(() => validateDevelopmentFeedback({
    payloadBytes,
    context: { ...context, expiry: DEVELOPMENT_FEEDBACK_LIMITS.exceptionEndUnixSeconds + 1 },
    now: NOW,
  }), DevelopmentFeedbackError);
  const edgeNow = DEVELOPMENT_FEEDBACK_LIMITS.exceptionEndUnixSeconds - 3600;
  const edgeContext = { ...context, expiry: DEVELOPMENT_FEEDBACK_LIMITS.exceptionEndUnixSeconds };
  assert.doesNotThrow(() => validateDevelopmentFeedback({ payloadBytes, context: edgeContext, now: edgeNow }));
});

test('encrypted feedback round-trips only validated profile payloads', () => {
  const payload = rustPatch();
  const context = contextFor('core-rust-format-return');
  const envelope = encryptDevelopmentFeedback({
    payloadBytes: payload,
    context,
    recipientPublicKey: recipient.publicKey,
    now: NOW,
    reviewedRustPaths: ['src/lib.rs'],
  });
  assert.equal(envelope[5], RETURN_PROFILES['core-rust-format-return'].id);
  assert.deepEqual(decryptDevelopmentFeedback({
    envelope,
    context,
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
    reviewedRustPaths: ['src/lib.rs'],
  }), payload);
  assert.throws(() => encryptDevelopmentFeedback({
    payloadBytes: Buffer.from('unbound text\n'),
    context,
    recipientPublicKey: recipient.publicKey,
    now: NOW,
    reviewedRustPaths: ['src/lib.rs'],
  }), DevelopmentFeedbackError);
  const invalidEnvelope = encryptReturnEnvelope({
    payloadBytes: Buffer.from('not a unified patch\n'),
    recipientPublicKey: recipient.publicKey,
    context,
    now: NOW,
  });
  assert.throws(() => decryptDevelopmentFeedback({
    envelope: invalidEnvelope,
    context,
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
    reviewedRustPaths: ['src/lib.rs'],
  }), DevelopmentFeedbackError);
});

test('diagnostic profiles validate on both encryption and decryption', () => {
  const diagnosticPayload = Buffer.from('compiler completed with zero warnings\n', 'utf8');
  const diagnosticContext = contextFor('core-build-diagnostic-return');
  const diagnosticEnvelope = encryptDevelopmentFeedback({
    payloadBytes: diagnosticPayload,
    context: diagnosticContext,
    recipientPublicKey: recipient.publicKey,
    now: NOW,
  });
  assert.equal(diagnosticEnvelope[5], RETURN_PROFILES['core-build-diagnostic-return'].id);
  assert.deepEqual(decryptDevelopmentFeedback({
    envelope: diagnosticEnvelope,
    context: diagnosticContext,
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
  }), diagnosticPayload);
});

function quickPayload(bodyText = '{"gates":[],"tier":"quick"}', total = DEVELOPMENT_FEEDBACK_LIMITS.linuxQuickBytes) {
  const header = `KD-LINUX-QUICK-PAYLOAD 1 ${String(Buffer.byteLength(bodyText, 'ascii')).padStart(8, '0')}\n`;
  const used = header.length + bodyText.length;
  return Buffer.from(header + bodyText + ' '.repeat(total - used), 'ascii');
}

test('the Linux quick limits are the envelope plaintext bound with a two line frame', () => {
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.linuxQuickBytes, 4128768);
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.linuxQuickBytes, LOCK_ENVELOPE_LIMITS.plaintextBytes);
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.linuxQuickLines, 2);
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.linuxQuickLineCodeUnits, DEVELOPMENT_FEEDBACK_LIMITS.linuxQuickBytes);
  assert.ok(DEVELOPMENT_FEEDBACK_LIMITS.linuxQuickBytes > DEVELOPMENT_FEEDBACK_LIMITS.diagnosticBytes);
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.diagnosticBytes, 512 * 1024);
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.diagnosticLines, 8192);
  assert.equal(DEVELOPMENT_FEEDBACK_LIMITS.diagnosticLineCodeUnits, 8192);
});

test('accepts the fixed-size padded Linux quick payload and rejects malformed or credential-shaped text', () => {
  const payload = quickPayload();
  assert.equal(payload.byteLength, DEVELOPMENT_FEEDBACK_LIMITS.linuxQuickBytes);
  assert.deepEqual(validate('linux_quick', payload), payload);
  const body = '{"gates":[{"name":"format","outcome":"passed","duration_ms":10,"stdout_tail":"ok\\n"}]}';
  assert.deepEqual(validate('linux_quick', quickPayload(body)), quickPayload(body));
  const cases = [
    [Buffer.from([0xef, 0xbb, 0xbf, 0x61, 0x0a]), 'invalid_payload_bom'],
    [Buffer.from([0xc3, 0x28]), 'invalid_payload_utf8'],
    [Buffer.from('first\0second\n', 'utf8'), 'invalid_payload_nul'],
    [Buffer.from('first\rsecond\n', 'utf8'), 'invalid_payload_cr'],
    [Buffer.from('first\u001bsecond\n', 'utf8'), 'invalid_payload_c0'],
    [Buffer.from('first\u007fsecond\n', 'utf8'), 'invalid_payload_c0'],
    [Buffer.from('first\u0085second\n', 'utf8'), 'invalid_payload_c1'],
    [Buffer.from('one\ntwo\nthree', 'utf8'), 'limit_exceeded'],
    [quickPayload('{"stderr_tail":"error token=abcdefghijkl"}'), 'credential_like_content'],
    [quickPayload('{"stderr_tail":"password=synthetic-fixture-value"}'), 'credential_like_content'],
    [quickPayload('{"stderr_tail":"https://user:placeholder@example.invalid/path"}'), 'credential_like_content'],
    [quickPayload('{"stderr_tail":"-----BEGIN PRIVATE KEY-----"}'), 'credential_like_content'],
    [Buffer.alloc(DEVELOPMENT_FEEDBACK_LIMITS.linuxQuickBytes + 1, 0x20), 'payload_too_large'],
  ];
  for (const [bytes, code] of cases) {
    assert.throws(() => validate('linux_quick', bytes), { code }, code);
  }
  const tab = Buffer.from('header\n{"a":"b\\tc"} \tend', 'ascii');
  assert.deepEqual(validate('linux_quick', tab), tab);
});

test('the Linux quick payload is limited by its own bound and never by the diagnostic bound', () => {
  const longLine = Buffer.from(`head\n${' '.repeat(DEVELOPMENT_FEEDBACK_LIMITS.diagnosticLineCodeUnits + 1)}`, 'ascii');
  assert.deepEqual(validate('linux_quick', longLine), longLine);
  assert.throws(() => validate('build_diagnostics', longLine), { code: 'limit_exceeded' });
  const bigDiagnostic = Buffer.alloc(DEVELOPMENT_FEEDBACK_LIMITS.diagnosticBytes + 1, 0x20);
  assert.deepEqual(validate('linux_quick', bigDiagnostic), bigDiagnostic);
  assert.throws(() => validate('build_diagnostics', bigDiagnostic), { code: 'payload_too_large' });
});

test('Linux quick payloads encrypt and decrypt only under their own untrusted-ref profile', () => {
  const payload = quickPayload();
  const context = contextFor('core-linux-quick-return');
  assert.equal(context.workflow_ref, 'refs/heads/untrusted');
  assert.equal(context.kind, 'linux_quick');
  const envelope = encryptDevelopmentFeedback({
    payloadBytes: payload,
    context,
    recipientPublicKey: recipient.publicKey,
    now: NOW,
  });
  assert.equal(envelope[5], RETURN_PROFILES['core-linux-quick-return'].id);
  assert.equal(envelope[5], 6);
  assert.deepEqual(decryptDevelopmentFeedback({
    envelope,
    context,
    recipientPrivateKey: recipient.privateKey,
    now: NOW,
  }), payload);
  for (const wrong of [
    contextFor('core-build-diagnostic-return'),
    { ...context, workflow_ref: 'refs/heads/main' },
    { ...context, nonce: '3'.repeat(64) },
  ]) {
    assert.throws(() => decryptDevelopmentFeedback({
      envelope,
      context: wrong,
      recipientPrivateKey: recipient.privateKey,
      now: NOW,
    }), DevelopmentFeedbackError);
  }
  assert.throws(() => encryptDevelopmentFeedback({
    payloadBytes: payload,
    context: { ...context, workflow_ref: 'refs/heads/main' },
    recipientPublicKey: recipient.publicKey,
    now: NOW,
  }), DevelopmentFeedbackError);
  assert.throws(() => encryptDevelopmentFeedback({
    payloadBytes: quickPayload('{"stderr_tail":"error token=abcdefghijkl"}'),
    context,
    recipientPublicKey: recipient.publicKey,
    now: NOW,
  }), { code: 'credential_like_content' });
  assert.throws(() => encryptDevelopmentFeedback({
    payloadBytes: payload,
    context,
    recipientPublicKey: recipient.publicKey,
    now: 1_800_835_200,
  }), { code: 'exception_expired' });
});

test('no other profile accepts the untrusted ref in a development feedback context', () => {
  for (const name of Object.keys(RETURN_PROFILES)) {
    if (name === 'core-linux-quick-return') continue;
    const context = { ...contextFor(name), workflow_ref: 'refs/heads/untrusted' };
    assert.equal(RETURN_PROFILES[name].workflowRef, undefined, name);
    assert.throws(() => validateDevelopmentFeedback({
      payloadBytes: Buffer.from('synthetic\n', 'utf8'),
      context,
      now: NOW,
    }), DevelopmentFeedbackError, name);
  }
});
