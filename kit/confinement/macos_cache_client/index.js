"use strict";

const { execFileSync, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const CACHE_ACTION_SHA = "3edfce9056124e459a23f683a21433670d47daca";
const MAX_CAPTURE_BYTES = 1048576;
const RUN_ID_RE = /^[1-9][0-9]{0,18}$/;
const RUN_ATTEMPT_RE = /^[1-9][0-9]{0,18}$/;
const SHA_RE = /^[a-f0-9]{40}$/;

function refuse(reason) {
  process.stdout.write("macos-cache-client=refused schema=1 reason=" + reason + "\n");
  process.exitCode = 1;
}

function readRevision(directory) {
  return execFileSync("git", ["-C", directory, "rev-parse", "--verify", "HEAD"], {
    encoding: "ascii",
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 5000,
    maxBuffer: 256,
  }).trim();
}

function readRemote(directory) {
  return execFileSync("git", ["-C", directory, "config", "--get", "remote.origin.url"], {
    encoding: "ascii",
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 5000,
    maxBuffer: 512,
  }).trim();
}

function hasEntry(filePath) {
  try {
    fs.lstatSync(filePath);
    return true;
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function main() {
  const mode = process.env.INPUT_MODE || "";
  const runId = process.env.GITHUB_RUN_ID || "";
  const runAttempt = process.env.GITHUB_RUN_ATTEMPT || "";
  const controlSha = process.env.CI_SHA || "";
  const runnerTemp = process.env.RUNNER_TEMP || "";
  const eventName = process.env.GITHUB_EVENT_NAME || "";
  const gitRef = process.env.GITHUB_REF || "";
  const repository = process.env.GITHUB_REPOSITORY || "";
  const serverUrl = process.env.CI_SERVER_URL || "";
  const inputPath = process.env.INPUT_PATH || "";
  const key = process.env.INPUT_KEY || "";

  if (process.version.match(/^v24\.[0-9]+\.[0-9]+$/) === null) {
    refuse("node_version");
    return;
  }
  if (process.env.ACTIONS_CACHE_MODE !== "none" || process.env.GITHUB_TOKEN) {
    refuse("job_binding");
    return;
  }
  if ((mode !== "read" && mode !== "write")
      || eventName !== "workflow_dispatch"
      || gitRef !== "refs/heads/main"
      || repository !== "keeldock-platform/platform-ci"
      || serverUrl !== "https://github.com"
      || !SHA_RE.test(controlSha)
      || !RUN_ID_RE.test(runId)
      || !RUN_ATTEMPT_RE.test(runAttempt)) {
    refuse("identity");
    return;
  }
  if (!path.isAbsolute(runnerTemp)
      || !process.env.ACTIONS_RUNTIME_TOKEN
      || !(process.env.ACTIONS_CACHE_URL || process.env.ACTIONS_RESULTS_URL)) {
    refuse("runtime_unavailable");
    return;
  }

  const expectedKey = mode === "read"
    ? "macos-public-cache-seed-v1-" + runId + "-" + runAttempt
    : "macos-public-cache-none-write-v1-" + runId + "-" + runAttempt;
  const expectedPath = path.resolve(
    runnerTemp,
    mode === "read" ? "macos-public-cache/fixture.txt" : "macos-public-cache-write/fixture.txt"
  );
  if (key !== expectedKey || path.resolve(inputPath) !== expectedPath) {
    refuse("fixture_binding");
    return;
  }
  if (mode === "read") {
    if (hasEntry(expectedPath)) {
      refuse("fixture_present");
      return;
    }
  } else {
    const entry = fs.lstatSync(expectedPath);
    const expectedBytes = Buffer.from("Public macOS cache write probe v1\n", "ascii");
    if (!entry.isFile() || entry.isSymbolicLink()
        || !fs.readFileSync(expectedPath).equals(expectedBytes)) {
      refuse("fixture_invalid");
      return;
    }
  }

  let tempRoot;
  let clientDirectory;
  let cacheBundle;
  try {
    tempRoot = fs.realpathSync(path.resolve(runnerTemp));
    clientDirectory = path.join(tempRoot, "macos-cache-client");
    if (fs.realpathSync(clientDirectory) !== clientDirectory
        || readRevision(clientDirectory) !== CACHE_ACTION_SHA
        || readRemote(clientDirectory) !== serverUrl + "/actions/cache.git") {
      refuse("client_pin");
      return;
    }
    const bundleRelative = mode === "read"
      ? "dist/restore-only/index.js"
      : "dist/save-only/index.js";
    cacheBundle = path.join(clientDirectory, bundleRelative);
    const realBundle = fs.realpathSync(cacheBundle);
    if (!realBundle.startsWith(clientDirectory + path.sep)) {
      refuse("client_path");
      return;
    }
  } catch (error) {
    refuse("client_unavailable");
    return;
  }

  const childEnv = Object.assign({}, process.env, { ACTIONS_CACHE_MODE: mode });
  const result = spawnSync(process.execPath, [cacheBundle], {
    cwd: process.env.GITHUB_WORKSPACE,
    env: childEnv,
    encoding: null,
    timeout: 240000,
    maxBuffer: MAX_CAPTURE_BYTES,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error || result.signal || result.status !== 0
      || !Buffer.isBuffer(result.stdout) || !Buffer.isBuffer(result.stderr)
      || result.stdout.length > MAX_CAPTURE_BYTES || result.stderr.length > MAX_CAPTURE_BYTES) {
    refuse("client_failed");
    return;
  }

  const lines = result.stdout.toString("latin1").split(/\r?\n/);
  const warningPrefix = mode === "read"
    ? "::warning::Failed to restore: Failed to GetCacheEntryDownloadURL: Received non-retryable error: Failed request: (403) Forbidden: cache read denied:"
    : "::warning::Failed to save: Failed to CreateCacheEntry: Received non-retryable error: Failed request: (403) Forbidden: cache write denied:";
  const warnings = lines.filter((line) => line.startsWith("::warning::"));
  const matching = lines.filter((line) => line.startsWith(warningPrefix));
  const commands = lines.filter((line) => line.startsWith("::"));
  if (warnings.length !== 1 || matching.length !== 1
      || commands.length !== 1 || commands[0] !== matching[0]) {
    refuse("service_denial_missing");
    return;
  }
  const suffix = matching[0].slice(warningPrefix.length);
  if (suffix.length === 0 || suffix.length > 1024 || suffix.includes("::")
      || /[^\x20-\x7e]/.test(suffix)) {
    refuse("service_denial_unbounded");
    return;
  }
  const captured = result.stdout.toString("latin1");
  if (captured.includes("Cache restored from key: " + key)
      || captured.includes("Cache saved with key: " + key)) {
    refuse("unexpected_cache_success");
    return;
  }
  if (mode === "read" && hasEntry(expectedPath)) {
    refuse("fixture_restored");
    return;
  }

  const actionMode = mode === "read" ? "read" : "write";
  const nodeVersion = process.version.slice(1);
  process.stdout.write(
    "macos-cache-client=" + actionMode + "-denied schema=1 action-sha=" + CACHE_ACTION_SHA
    + " key=" + key + " control-sha=" + controlSha + " run-id=" + runId + " run-attempt=" + runAttempt
    + " node=" + nodeVersion + "\n"
  );
}

try {
  main();
} catch (error) {
  refuse("internal_error");
}
