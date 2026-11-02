param(
    [ValidateSet('spike', 'compile')]
    [string]$Mode = 'spike'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$phase = 'control_identity'
$script:Redactions = @()
$exitCode = 1
$refusal = $null
$cleanup = 'verified'
$box = $null
$baseDirectory = $null
$componentNameExpected = $null
$componentNameObserved = $null
$script:NullLease = $null
$script:ExpectedTemp = $null
$script:ProfileFolder = $null
$script:OtherBox = $null
$script:OtherFolder = $null
$script:OtherContainerSeconds = 30
$script:Canaries = @()
$script:CanaryRunnerTemp = ''
$script:CanaryWorkspace = ''
$script:CanaryProfile = ''
$script:CanaryControl = ''
$script:CanaryNeedle = ''
$script:CanaryScratchNeedle = ''
$script:Channel = $null
$script:Listener = $null
$script:ChannelRegistry = $false
$script:TrapDirectory = $null
$script:TrapSentinel = $null
$script:PlantedJunctions = 0
$script:PlantedSymlinks = 0

$RustVersion = '1.99.1'
$RustTarget = 'x86_64-pc-windows-msvc'
$RustDate = '2026-10-15'
$NodeVersion = '24.22.1'
$ExpectedRustComponents = @{
    rustc = 'rustc'
    cargo = 'cargo'
    rust_std = ('rust-std-' + $RustTarget)
}
$Downloads = @(
    @{ Name = 'rustc'; File = 'rustc.tar.gz'; Url = ('https://static.rust-lang.org/dist/' + $RustDate + '/rustc-' + $RustVersion + '-' + $RustTarget + '.tar.gz'); Sha256 = '4e211ed2047e7890a8aea79fc8a88922d4c0e87a325349323d56c958d8da5d3a'; Root = ('rustc-' + $RustVersion + '-' + $RustTarget) },
    @{ Name = 'cargo'; File = 'cargo.tar.gz'; Url = ('https://static.rust-lang.org/dist/' + $RustDate + '/cargo-' + $RustVersion + '-' + $RustTarget + '.tar.gz'); Sha256 = 'bbf6e9295b69c9de8f2610e3e5bb90217d23826b7f2adac698262663a58ad899'; Root = ('cargo-' + $RustVersion + '-' + $RustTarget) },
    @{ Name = 'rust_std'; File = 'rust-std.tar.gz'; Url = ('https://static.rust-lang.org/dist/' + $RustDate + '/rust-std-' + $RustVersion + '-' + $RustTarget + '.tar.gz'); Sha256 = 'e856f160e01c31fe35aa7255579eed0774029882692d694736106f5883a96f22'; Root = ('rust-std-' + $RustVersion + '-' + $RustTarget) }
)
$NodeDownload = @{ Name = 'node'; File = 'node.zip'; Url = ('https://nodejs.org/dist/v' + $NodeVersion + '/node-v' + $NodeVersion + '-win-x64.zip'); Sha256 = 'd2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5' }
$NpmDownloads = @(
    @{ Name = 'lightningcss'; File = 'lightningcss.tgz'; Url = 'https://registry.npmjs.org/lightningcss-win32-x64-msvc/-/lightningcss-win32-x64-msvc-1.33.0.tgz'; Sri = 'sha512-OlEICDx/Xl0FqSp4bry8zFnCvGpig3Gl4gCquvYwHuqJKEC1+n9NgDniFvqHGmMv1ZkqDJrDqKKSykTDX+ehuA==' },
    @{ Name = 'rolldown'; File = 'rolldown.tgz'; Url = 'https://registry.npmjs.org/@rolldown/binding-win32-x64-msvc/-/binding-win32-x64-msvc-1.2.14.tgz'; Sri = 'sha512-9mE94bf2GZUaR/fUSXCMpBoWkctu421Mi0ORpm4zqfbkjKep7RxzPFa5etcGs5h+2KApoWBOA/hAJa/7saGgEQ==' }
)
$AllowedHosts = @('static.rust-lang.org', 'nodejs.org', 'registry.npmjs.org')

$CargoManifestText = "[package]`nname = `"kd_spike`"`nversion = `"0.1.0`"`nedition = `"2021`"`n`n[lib]`npath = `"src/lib.rs`"`n"
$RustSourceText = @'
pub fn add(left: u32, right: u32) -> u32 {
    left + right
}

KDHASH[cfg(test)]
mod tests {
    use super::*;

    KDHASH[test]
    fn adds_two_numbers() {
        assert_eq!(add(2, 3), 5);
    }
}
'@
$NodeTestText = @'
import { createRequire } from 'node:module';
import process from 'node:process';

const require = createRequire(import.meta.url);
const registered = [];
let currentSuite = '';

function describe(name, body) {
  currentSuite = name;
  body();
  currentSuite = '';
}

function it(name, body) {
  registered.push({ suite: currentSuite, name, body });
}

function expect(actual) {
  return {
    toBe(expected) {
      if (actual !== expected) {
        throw new Error('expected ' + String(expected) + ' received ' + String(actual));
      }
    },
    toContain(expected) {
      if (String(actual).indexOf(expected) < 0) {
        throw new Error('expected text containing ' + String(expected) + ' received ' + String(actual));
      }
    },
    toBeGreaterThan(expected) {
      if (!(actual > expected)) {
        throw new Error('expected above ' + String(expected) + ' received ' + String(actual));
      }
    },
  };
}

function label(text) {
  return String(text).replace(/[^A-Za-z0-9_.-]+/g, '_');
}

describe('runtime', () => {
  it('reports the pinned node on win32 x64', () => {
    expect(process.platform).toBe('win32');
    expect(process.arch).toBe('x64');
    expect(process.versions.node).toBe('24.22.1');
  });
});

describe('lightningcss win32 binding', () => {
  it('loads the native binding', () => {
    const binding = require(process.env.KD_LIGHTNINGCSS_NODE);
    expect(typeof binding.transform).toBe('function');
  });
  it('minifies a stylesheet', () => {
    const binding = require(process.env.KD_LIGHTNINGCSS_NODE);
    const output = binding.transform({ filename: 'kd.css', code: Buffer.from('a { color: red; }'), minify: true });
    expect(Buffer.from(output.code).toString('utf8')).toContain('color:red');
  });
});

describe('rolldown win32 binding', () => {
  it('loads the native binding', () => {
    const binding = require(process.env.KD_ROLLDOWN_NODE);
    expect(Object.keys(binding).length).toBeGreaterThan(0);
  });
});

let passed = 0;
let failed = 0;
for (const test of registered) {
  let outcome = 'pass';
  let message = '';
  try {
    test.body();
    passed += 1;
  } catch (error) {
    outcome = 'fail';
    failed += 1;
    message = String(error && error.message ? error.message : error).slice(0, 200);
  }
  console.log('kd-node-test suite=' + label(test.suite) + ' name=' + label(test.name) + ' result=' + outcome + (message ? ' message=' + label(message) : ''));
}
console.log('kd-node-summary passed=' + passed + ' failed=' + failed);
process.exitCode = failed === 0 ? 0 : 1;
'@
$NodeChildText = @'
'use strict';

const childProcess = require('node:child_process');
const { Worker } = require('node:worker_threads');

function spawnInherit() {
  const result = childProcess.spawnSync(process.execPath, ['-e', '0'], { stdio: 'inherit', timeout: 20000 });
  return !result.error && result.status === 0;
}

function workerRoundTrip() {
  return new Promise((resolve) => {
    let worker = null;
    try {
      worker = new Worker('require("node:worker_threads").parentPort.postMessage("kd");', { eval: true });
    } catch (error) {
      resolve(false);
      return;
    }
    worker.on('message', (message) => resolve(message === 'kd'));
    worker.on('error', () => resolve(false));
  });
}

async function main() {
  const spawned = spawnInherit();
  const worker = await Promise.race([
    workerRoundTrip(),
    new Promise((resolve) => setTimeout(() => resolve(false), 20000)),
  ]);
  console.log('kd-node-child spawn=' + (spawned ? 'ok' : 'fail') + ' worker=' + (worker ? 'ok' : 'fail'));
  process.exit(spawned && worker ? 0 : 1);
}

main();
'@
$FixtureRustText = @'
use std::env;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::Duration;

fn code(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        Some(value) => format!("err{}", value),
        None => String::from("errnone"),
    }
}

fn variable(name: &str) -> String {
    env::var(name).unwrap_or_default()
}

fn report(name: &str, text: &str) {
    println!("KDATT {} {}", name, text);
}

fn connect(target: &str) -> String {
    let addresses: Vec<SocketAddr> = match target.to_socket_addrs() {
        Ok(list) => list.collect(),
        Err(error) => return format!("resolve={}", code(&error)),
    };
    if addresses.is_empty() {
        return String::from("resolve=empty");
    }
    match TcpStream::connect_timeout(&addresses[0], Duration::from_secs(8)) {
        Ok(_) => String::from("resolve=ok connect=open"),
        Err(error) => format!("resolve=ok connect={}", code(&error)),
    }
}

fn lookup(host: &str) -> String {
    match (host, 443u16).to_socket_addrs() {
        Ok(list) => format!("resolve=ok count={}", list.count()),
        Err(error) => format!("resolve={}", code(&error)),
    }
}

fn read_file(path: &str) -> String {
    match OpenOptions::new().read(true).open(path) {
        Ok(mut file) => {
            let mut buffer = [0u8; 16];
            match file.read(&mut buffer) {
                Ok(count) => format!("open=ok read=ok bytes={}", count),
                Err(error) => format!("open=ok read={}", code(&error)),
            }
        }
        Err(error) => format!("open={}", code(&error)),
    }
}

fn write_file(path: &str) -> String {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => match file.write_all(b"kd") {
            Ok(_) => String::from("create=ok write=ok"),
            Err(error) => format!("create=ok write={}", code(&error)),
        },
        Err(error) => format!("create={}", code(&error)),
    }
}

fn open_pipe(path: &str) -> String {
    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(_) => String::from("open=ok"),
        Err(error) => format!("open={}", code(&error)),
    }
}

fn hunt() -> String {
    let mut found: u32 = 0;
    for (key, _) in env::vars_os() {
        let name = key.to_string_lossy().to_ascii_uppercase();
        if name.starts_with("ACTIONS_") || name.starts_with("GITHUB_") || name.starts_with("RUNNER_") {
            found += 1;
        }
    }
    format!("found={}", found)
}

fn child(arguments: &[&str]) -> String {
    let probe = variable("KD_PROBE");
    let prefix = format!("kd-probe {} ", arguments[0]);
    match Command::new(&probe).args(arguments).output() {
        Ok(done) => {
            let text = String::from_utf8_lossy(&done.stdout).to_string();
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with(&prefix) {
                    return trimmed[prefix.len()..].to_string();
                }
            }
            String::from("child=noline")
        }
        Err(error) => format!("child={}", code(&error)),
    }
}

fn child_cmd() -> String {
    let shell = variable("ComSpec");
    match Command::new(&shell).args(["/d", "/c", "exit", "7"]).output() {
        Ok(done) => match done.status.code() {
            Some(value) => format!("exit={}", value),
            None => String::from("exit=none"),
        },
        Err(error) => format!("child={}", code(&error)),
    }
}

fn run_attempts() {
    println!();
    let nonce = variable("KD_FX_NONCE");
    let temp = variable("KD_FX_TEMP");
    let loopback = format!("127.0.0.1:{}", variable("KD_FX_PORT"));
    let pipe = format!("\\\\.\\pipe\\{}", variable("KD_FX_PIPE"));
    let direct = format!("{}\\kd-att-fx{}.tmp", temp, nonce);
    let spawned = format!("{}\\kd-att-fy{}.tmp", temp, nonce);
    report("net-external", &connect("1.1.1.1:443"));
    report("net-loopback", &connect(&loopback));
    report("dns-lookup", &lookup("github.com"));
    report("read-canary", &read_file(&variable("KD_FX_CANARY")));
    report("write-escape", &write_file(&direct));
    report("env-hunt", &hunt());
    report("pipe-open", &open_pipe(&pipe));
    report("child-network", &child(&["connect", "1.1.1.1:443"]));
    report("child-write", &child(&["write", spawned.as_str()]));
    report("child-cmd", &child_cmd());
    println!("::debug::kd-fx-marker");
    eprintln!("::debug::kd-fx-marker");
    report("output-exfil", "text=ok");
}
'@
$FixtureNodeText = @'
'use strict';

const net = require('node:net');
const dns = require('node:dns');
const fs = require('node:fs');
const childProcess = require('node:child_process');

const mode = process.argv[2] || 'main';
const nonce = process.env.KD_FX_NONCE || '';
const temp = process.env.KD_FX_TEMP || '';
const canary = process.env.KD_FX_CANARY || '';
const port = Number(process.env.KD_FX_PORT || '0');
const pipePath = '\\\\.\\pipe\\' + (process.env.KD_FX_PIPE || '');

function report(name, text) {
  console.log('KDATT ' + name + ' ' + text);
}

function code(error) {
  return error && error.code ? String(error.code) : 'none';
}

function connectState(options) {
  return new Promise(function (resolve) {
    let settled = false;
    const finish = function (text) {
      if (!settled) {
        settled = true;
        resolve(text);
      }
    };
    const timer = setTimeout(function () {
      finish('connect=timeout');
    }, 8000);
    const socket = net.connect(options);
    socket.on('connect', function () {
      clearTimeout(timer);
      socket.destroy();
      finish('connect=open');
    });
    socket.on('error', function (error) {
      clearTimeout(timer);
      finish('connect=' + code(error));
    });
  });
}

function readState(path) {
  let handle = -1;
  try {
    handle = fs.openSync(path, 'r');
  } catch (error) {
    return 'open=' + code(error);
  }
  try {
    const buffer = Buffer.alloc(16);
    const count = fs.readSync(handle, buffer, 0, 16, null);
    return 'open=ok read=ok bytes=' + count;
  } catch (error) {
    return 'open=ok read=' + code(error);
  } finally {
    fs.closeSync(handle);
  }
}

function writeState(path) {
  let handle = -1;
  try {
    handle = fs.openSync(path, 'wx');
  } catch (error) {
    return 'create=' + code(error);
  }
  try {
    fs.writeSync(handle, 'kd');
    return 'create=ok write=ok';
  } catch (error) {
    return 'create=ok write=' + code(error);
  } finally {
    fs.closeSync(handle);
  }
}

function pipeState(path) {
  try {
    fs.closeSync(fs.openSync(path, 'r+'));
    return 'open=ok';
  } catch (error) {
    return 'open=' + code(error);
  }
}

function envState() {
  let found = 0;
  for (const key of Object.keys(process.env)) {
    const name = key.toUpperCase();
    if (name.startsWith('ACTIONS_') || name.startsWith('GITHUB_') || name.startsWith('RUNNER_')) {
      found += 1;
    }
  }
  return 'found=' + found;
}

function lookupState() {
  return new Promise(function (resolve) {
    const timer = setTimeout(function () {
      resolve('resolve=timeout');
    }, 8000);
    dns.lookup('github.com', function (error) {
      clearTimeout(timer);
      resolve(error ? 'resolve=' + code(error) : 'resolve=ok');
    });
  });
}

function spawnState() {
  const result = childProcess.spawnSync(process.execPath, ['-e', '0'], { stdio: 'pipe', timeout: 15000 });
  if (result.error) {
    return 'spawn=' + code(result.error);
  }
  return result.status === 0 ? 'spawn=ok' : 'spawn=fail';
}

async function main() {
  if (mode === 'spawn-pipe') {
    report('spawn-pipe', spawnState());
    process.exit(0);
  }
  report('net-external', await connectState({ host: '1.1.1.1', port: 443 }));
  report('net-loopback', await connectState({ host: '127.0.0.1', port: port }));
  report('dns-lookup', await lookupState());
  report('read-canary', readState(canary));
  report('write-escape', writeState(temp + '\\kd-att-fx' + nonce + '.tmp'));
  report('env-hunt', envState());
  report('pipe-open', pipeState(pipePath));
  console.log('::debug::kd-fx-marker');
  console.error('::debug::kd-fx-marker');
  report('output-exfil', 'text=ok');
  process.exit(0);
}

main();
'@
$FixtureNodePackage = '{"name":"hostile-fixture","version":"0.0.0","private":true,"scripts":{"postinstall":"node install.js"}}'
$FixtureForms = @('build_rs', 'test', 'binary', 'node_install')
$FixtureCargoSeconds = 240
$FixtureNodeSeconds = 60
$FixtureSpawnSeconds = 30
$FixtureSentinelEnvironment = [string[]]@('ACTIONS_RUNTIME_TOKEN=kd-sentinel', 'GITHUB_TOKEN=kd-sentinel', 'RUNNER_TOOL_CACHE=kd-sentinel')

function Write-Line([string]$text) {
    [Console]::Out.WriteLine($text)
}

function Get-CleanText([string]$text, [int]$limit) {
    $value = [string]$text
    foreach ($item in $script:Redactions) {
        if (-not [string]::IsNullOrEmpty($item) -and $item.Length -gt 3) {
            $value = [regex]::Replace($value, [regex]::Escape($item), 'ROOT', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }
    $value = $value.Replace("`r", '')
    $value = [regex]::Replace($value, '[^A-Za-z0-9 ._=/,\n-]', '?')
    if ($value.Length -gt $limit) { $value = $value.Substring(0, $limit) }
    return $value
}

function Get-SafeComponentName([string]$text) {
    $value = [regex]::Replace([string]$text, '[^A-Za-z0-9._-]', '_')
    if ($value.Length -gt 64) { $value = $value.Substring(0, 64) }
    if ($value.Length -eq 0) { return 'empty' }
    return $value
}

function Get-Token([string]$text, [string]$pattern) {
    $value = [string]$text
    if ($value -match $pattern) { return $value }
    return 'unknown'
}

function Write-DiagLines([string]$stage, [string]$stream, [string]$text) {
    $clean = Get-CleanText $text 2500
    foreach ($line in ($clean -split "`n")) {
        $trimmed = $line.TrimEnd()
        if ($trimmed.Length -gt 0) {
            Write-Line ('kd-diag stage=' + $stage + ' stream=' + $stream + ' line=' + $trimmed)
        }
    }
}

function Get-StatusName([uint32]$code) {
    switch ($code) {
        3221225781 { return 'dll_not_found' }
        3221225794 { return 'dll_init_failed' }
        3221225477 { return 'access_violation' }
        3221225506 { return 'access_denied_status' }
        3221226356 { return 'heap_corruption' }
        3221225485 { return 'status_invalid_parameter' }
        3221225595 { return 'bad_image_format' }
        3221225785 { return 'entrypoint_not_found' }
        3221226505 { return 'stack_buffer_overrun' }
        1262769995 { return 'job_terminated_by_harness' }
        default { return 'none' }
    }
}

function Invoke-Download($item) {
    $uri = [Uri]$item.Url
    if ($uri.Scheme -ne 'https' -or $AllowedHosts -notcontains $uri.Host) { throw 'download_host' }
    $target = Join-Path $script:Layout.Downloads $item.File
    $attempt = 0
    while ($true) {
        $attempt += 1
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.MaxAutomaticRedirections = 5
        $client = New-Object System.Net.Http.HttpClient($handler)
        $cancel = New-Object System.Threading.CancellationTokenSource
        $cancel.CancelAfter([TimeSpan]::FromSeconds(120))
        $stream = $null
        $file = $null
        try {
            $response = $client.GetAsync($item.Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancel.Token).GetAwaiter().GetResult()
            [void]$response.EnsureSuccessStatusCode()
            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $file = [IO.File]::Create($target)
            [void]$stream.CopyToAsync($file, 81920, $cancel.Token).GetAwaiter().GetResult()
            break
        } catch {
            if ($attempt -ge 2) { throw 'download_failed' }
            Start-Sleep -Seconds (5 * $attempt)
        } finally {
            if ($file) { $file.Dispose() }
            if ($stream) { $stream.Dispose() }
            $client.Dispose()
            $cancel.Dispose()
        }
    }
    return [string]$target
}

function Assert-Sha256([string]$path, [string]$expected, [string]$name) {
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        $script:phase = 'fetch_hash_mismatch_' + $name
        throw 'hash_mismatch'
    }
}

function Assert-Sri([string]$path, [string]$sri, [string]$name) {
    if ($sri -notmatch '^sha512-([A-Za-z0-9+/]{86}==)$') { throw 'sri_shape' }
    $actual = [Convert]::ToBase64String([Convert]::FromHexString((Get-FileHash -Algorithm SHA512 -LiteralPath $path).Hash))
    if ($actual -ne $Matches[1]) {
        $script:phase = 'fetch_hash_mismatch_' + $name
        throw 'hash_mismatch'
    }
}

function Invoke-Tar([string]$archive, [string]$destination) {
    New-Item -ItemType Directory -Path $destination | Out-Null
    $tar = Join-Path $env:SystemRoot 'System32\tar.exe'
    & $tar -xzf $archive -C $destination | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'tar_failed' }
}

function Copy-Tree([string]$source, [string]$destination) {
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    & robocopy $source $destination /E /COPY:DAT /R:1 /W:1 /MT:16 /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw 'robocopy_failed' }
    $global:LASTEXITCODE = 0
}

function Grant-Access([string]$path, [string]$sid, [string]$rights, [bool]$inherit) {
    $info = New-Object System.IO.DirectoryInfo($path)
    $security = [System.IO.FileSystemAclExtensions]::GetAccessControl($info, [System.Security.AccessControl.AccessControlSections]::Access)
    $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $flags = [System.Security.AccessControl.InheritanceFlags]::None
    if ($inherit) {
        $flags = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    }
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, [System.Security.AccessControl.FileSystemRights]$rights, $flags, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
    $security.AddAccessRule($rule)
    [System.IO.FileSystemAclExtensions]::SetAccessControl($info, $security)
}

function Set-LowIntegrityLabel([string]$path) {
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $path '/setintegritylevel' '(OI)(CI)L' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'integrity_set' }
    $global:LASTEXITCODE = 0
}

function Test-LowIntegrityLabel([string]$path) {
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    $output = & $icacls $path 2>$null
    $code = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    if ($code -ne 0) { return $false }
    return [bool]($output -match 'Mandatory Label\\Low Mandatory Level:(?:\(I\))?\(OI\)\(CI\)\(NW\)')
}

function Grant-NonPropagating([string]$path, [string]$sid) {
    $bytes = [KeelDock.Platform.WindowsConfinement.NonPropagatingDacl]::Read($path)
    $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($bytes, 0)
    if ($null -eq $descriptor.DiscretionaryAcl) { throw 'dacl_missing' }
    $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $ace = New-Object System.Security.AccessControl.CommonAce([System.Security.AccessControl.AceFlags]::None, [System.Security.AccessControl.AceQualifier]::AccessAllowed, 1048704, $identity, $false, $null)
    $index = 0
    while ($index -lt $descriptor.DiscretionaryAcl.Count) {
        $existing = $descriptor.DiscretionaryAcl[$index]
        $explicitDeny = ($existing -is [System.Security.AccessControl.CommonAce]) -and ($existing.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessDenied) -and (([int]$existing.AceFlags -band 16) -eq 0)
        if (-not $explicitDeny) { break }
        $index += 1
    }
    $descriptor.DiscretionaryAcl.InsertAce($index, $ace)
    $updated = New-Object byte[] $descriptor.BinaryLength
    $descriptor.GetBinaryForm($updated, 0)
    [KeelDock.Platform.WindowsConfinement.NonPropagatingDacl]::Write($path, $updated)
}

function Get-SidRules([string]$path, [string]$sid) {
    $security = Get-Acl -LiteralPath $path
    $rules = $security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    return @($rules | Where-Object { $_.IdentityReference.Value -eq $sid })
}

function New-ScratchSet([string]$root) {
    return @{
        Root = $root
        Tmp = (Join-Path $root 'tmp')
        Profile = (Join-Path $root 'profile')
        CargoHome = (Join-Path $root 'cargo-home')
        Crate = (Join-Path $root 'crate')
    }
}

function Test-Acl {
    $sid = $script:Sid
    $writeMask = [System.Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteAttributes, WriteExtendedAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $readMask = [System.Security.AccessControl.FileSystemRights]'ReadAndExecute'
    $ro = @(Get-SidRules $script:Layout.ReadOnly $sid)
    if ($ro.Count -ne 1 -or ($ro[0].FileSystemRights -band $writeMask) -ne 0 -or ($ro[0].FileSystemRights -band $readMask) -ne $readMask -or $ro[0].AccessControlType -ne 'Allow') { return 'ro_rule' }
    $scratch = @(Get-SidRules $script:Lpac.Root $sid)
    $modifyMask = [System.Security.AccessControl.FileSystemRights]'Modify'
    if ($scratch.Count -ne 1 -or ($scratch[0].FileSystemRights -band $modifyMask) -ne $modifyMask -or $scratch[0].AccessControlType -ne 'Allow') { return 'scratch_rule' }
    foreach ($path in @($script:Layout.Downloads, $script:Control.Root, $script:Control.Tmp, $script:Control.Crate)) {
        if (@(Get-SidRules $path $sid).Count -ne 0) { return 'unexpected_rule' }
    }
    $attributeMask = [System.Security.AccessControl.FileSystemRights]'ReadAttributes, Synchronize'
    foreach ($path in $script:AncestorPaths) {
        $entries = @(Get-SidRules $path $sid)
        if ($entries.Count -ne 1) { return 'ancestor_rule' }
        if ($entries[0].FileSystemRights -ne $attributeMask -or $entries[0].AccessControlType -ne 'Allow' -or $entries[0].IsInherited) { return 'ancestor_rule' }
        if ($entries[0].InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None -or $entries[0].PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) { return 'ancestor_rule' }
    }
    foreach ($path in @(($script:Layout.RustBin + '\rustc.exe'), ($script:Layout.MsvcBin + '\link.exe'), ($script:Layout.NodeDir + '\node.exe'), $script:Layout.LightningcssBinding, $script:Layout.RolldownBinding, $script:Layout.NodeTest, $script:Layout.NodeChild, $script:Layout.ProbeExe)) {
        if (@(Get-SidRules $path $sid).Count -lt 1) { return 'not_inherited' }
    }
    foreach ($path in @($script:Lpac.Tmp, $script:Lpac.Profile, $script:Lpac.CargoHome, $script:Lpac.Crate, (Join-Path $script:Lpac.Crate 'src'))) {
        $entries = @(Get-SidRules $path $sid)
        if ($entries.Count -ne 1 -or -not $entries[0].IsInherited -or $entries[0].AccessControlType -ne 'Allow' -or ($entries[0].FileSystemRights -band $modifyMask) -ne $modifyMask) { return 'scratch_not_inherited' }
        if (-not (Test-LowIntegrityLabel $path)) { return 'scratch_integrity' }
    }
    if (-not (Test-LowIntegrityLabel $script:Lpac.Root)) { return 'scratch_integrity' }
    return 'verified'
}

function New-StageEnvironment([hashtable]$scratch, [string]$targetName) {
    $layout = $script:Layout
    $searchPath = @($layout.RustBin, $layout.NodeDir, $layout.MsvcBin, (Join-Path $env:SystemRoot 'System32'), $env:SystemRoot) -join ';'
    return [string[]]@(
        ('SystemRoot=' + $env:SystemRoot),
        ('windir=' + $env:SystemRoot),
        ('SystemDrive=' + $env:SystemDrive),
        ('ComSpec=' + (Join-Path $env:SystemRoot 'System32\cmd.exe')),
        ('PATH=' + $searchPath),
        ('TEMP=' + $scratch.Tmp),
        ('TMP=' + $scratch.Tmp),
        ('USERPROFILE=' + $scratch.Profile),
        ('APPDATA=' + $scratch.Profile),
        ('LOCALAPPDATA=' + $scratch.Profile),
        ('CARGO_HOME=' + $scratch.CargoHome),
        ('CARGO_TARGET_DIR=' + (Join-Path $scratch.Root $targetName)),
        ('CARGO_INCREMENTAL=0'),
        ('CARGO_NET_OFFLINE=true'),
        ('CARGO_BUILD_JOBS=2'),
        ('CARGO_TERM_COLOR=never'),
        ('NO_COLOR=1'),
        ('RUSTC=' + $layout.RustBin + '\rustc.exe'),
        ('LIB=' + $layout.MsvcLib + ';' + $layout.SdkUcrt + ';' + $layout.SdkUm),
        ('RUSTFLAGS=-C linker=' + $layout.MsvcBin + '\link.exe -C debuginfo=0 -C link-arg=/DEBUG:NONE'),
        ('KD_LIGHTNINGCSS_NODE=' + $layout.LightningcssBinding),
        ('KD_ROLLDOWN_NODE=' + $layout.RolldownBinding)
    )
}

function Get-NormalPath([string]$path) {
    $text = ([string]$path).Replace('/', '\')
    if ($text.StartsWith('\\?\', [StringComparison]::Ordinal)) { $text = $text.Substring(4) }
    while ($text.EndsWith('\') -and $text.Length -gt 3) { $text = $text.Substring(0, $text.Length - 1) }
    return $text.ToLowerInvariant()
}

function Test-PathUnder([string]$path, [string]$root) {
    if ([string]::IsNullOrEmpty($root)) { return $false }
    $prefix = (Get-NormalPath $root) + '\'
    return (((Get-NormalPath $path) + '\').StartsWith($prefix, [StringComparison]::Ordinal))
}

function Get-Mib([uint64]$value) {
    return [string][math]::Floor($value / 1048576)
}

function Get-ProbeText([string]$stdout, [string]$name) {
    $prefix = 'kd-probe ' + $name + ' '
    foreach ($line in ([string]$stdout -split "`n")) {
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith($prefix, [StringComparison]::Ordinal)) { return $trimmed.Substring($prefix.Length) }
    }
    return ''
}

function Get-ProbeValue([string]$text, [string]$key) {
    $match = [regex]::Match($text, '(?:^| )' + [regex]::Escape($key) + '=([A-Za-z0-9_.-]+)')
    if ($match.Success) { return $match.Groups[1].Value }
    return 'none'
}

$NetworkDeniedConnect = @('err10013')
$NetworkDeniedResolve = @('err10013', 'err11001')
$NetworkDeniedUdp = @('err10013')
$NetworkDeniedHostResolve = @('err11003')
$NetworkDeniedBind = @('err10013')
$NetworkUnroutableConnect = @('err10047', 'err10051')
$ChannelNames = @('https', 'dns', 'redirect', 'proxy', 'runner_ipc', 'raw_logs', 'artifact_upload', 'cache_upload', 'runner_files', 'process_memory', 'boundary_disablement')
$ChannelSentinelEnvironment = [string[]]@('ACTIONS_RUNTIME_TOKEN=kd-sentinel', 'ACTIONS_RESULTS_URL=kd-sentinel', 'ACTIONS_CACHE_URL=kd-sentinel', 'GITHUB_TOKEN=kd-sentinel', 'RUNNER_TOOL_CACHE=kd-sentinel', 'HTTPS_PROXY=kd-sentinel')

function Get-NetworkState([string]$stdout, [string]$name) {
    $text = Get-ProbeText $stdout $name
    if ($text.Length -eq 0) { return 'no_output' }
    if ($text -ceq 'wsa=failed') { return 'wsa_failed' }
    if ($name -ceq 'connect') {
        if ($text -ceq 'resolve=ok connect=open') { return 'open' }
        $connectFound = [regex]::Match($text, '^resolve=ok connect=(err[0-9]{1,5})$')
        if ($connectFound.Success -and ($NetworkDeniedConnect -ccontains $connectFound.Groups[1].Value)) { return 'blocked' }
        $found = [regex]::Match($text, '^resolve=(err[0-9]{1,5})$')
        if ($found.Success -and ($NetworkDeniedResolve -ccontains $found.Groups[1].Value)) { return 'blocked' }
        if ($found.Success -and ($NetworkDeniedHostResolve -ccontains $found.Groups[1].Value)) { return 'blocked_resolve' }
        if ($text -ceq 'resolve=empty') { return 'unroutable' }
        if ($connectFound.Success -and ($NetworkUnroutableConnect -ccontains $connectFound.Groups[1].Value)) { return 'unroutable' }
        return 'unexpected'
    }
    if ($name -ceq 'dns') {
        if ($text -cmatch '^resolve=ok count=[1-9][0-9]*$') { return 'open' }
        $found = [regex]::Match($text, '^resolve=(err[0-9]{1,5})$')
        if ($found.Success -and ($NetworkDeniedResolve -ccontains $found.Groups[1].Value)) { return 'blocked' }
        if ($found.Success -and ($NetworkDeniedHostResolve -ccontains $found.Groups[1].Value)) { return 'blocked_resolve' }
        return 'unexpected'
    }
    if ($name -ceq 'udp') {
        if ($text -ceq 'send=ok recv=data') { return 'open' }
        $found = [regex]::Match($text, '^send=(err[0-9]{1,5})$')
        if ($found.Success -and ($NetworkDeniedUdp -ccontains $found.Groups[1].Value)) { return 'blocked' }
        $found = [regex]::Match($text, '^bind=(err[0-9]{1,5})$')
        if ($found.Success -and ($NetworkDeniedBind -ccontains $found.Groups[1].Value)) { return 'blocked_bind' }
        return 'unexpected'
    }
    return 'unexpected'
}

function Test-CanaryHidden([string]$stdout) {
    $code = Get-ProbeValue (Get-ProbeText $stdout 'read') 'open'
    return ($code -ceq 'err5' -or $code -ceq 'err2' -or $code -ceq 'err3')
}

function Test-ContainerTempReport([string]$stdout) {
    $text = Get-ProbeText $stdout 'tempdir'
    $found = [regex]::Match($text, '^exists=yes writable=yes path=(.+)$')
    if (-not $found.Success) { return $false }
    if ([string]::IsNullOrEmpty($script:ExpectedTemp)) { return $false }
    return ((Get-NormalPath $found.Groups[1].Value) -ceq (Get-NormalPath $script:ExpectedTemp))
}

function Test-Passed($outcomes, [string[]]$names) {
    foreach ($name in $names) {
        if (-not $outcomes.Contains($name)) { return $false }
        if (-not $outcomes[$name].Passed) { return $false }
    }
    return $true
}

function Invoke-ConfinedProbe($sandbox, [string]$arguments, [int]$timeoutSeconds) {
    $exe = $script:Layout.ProbeExe
    $environment = New-StageEnvironment $script:Lpac 'target-probe'
    return $sandbox.Run($true, $exe, ('"' + $exe + '" ' + $arguments), $script:Lpac.Root, $environment, ($timeoutSeconds * 1000), [uint32]32)
}

function Initialize-ContainerTemp($sandbox) {
    $profileName = [string]$sandbox.ProfileName
    $profileRoot = [string]$script:Lpac.Profile
    $expected = Join-Path (Join-Path (Join-Path (Join-Path $profileRoot 'Packages') $profileName) 'AC') 'Temp'
    $shape = '^' + [regex]::Escape($profileRoot) + '\\Packages\\KDW[0-9a-f]{32}\\AC\\Temp$'
    if ($expected -notmatch $shape) { throw 'shape' }
    if (-not (Test-PathUnder $expected $script:Lpac.Root)) { throw 'shape' }
    New-Item -ItemType Directory -Force -Path $expected | Out-Null
    $script:ExpectedTemp = $expected
    $modifyMask = [System.Security.AccessControl.FileSystemRights]'Modify'
    $rules = @(Get-SidRules $expected $script:Sid)
    $inherited = ($rules.Count -ge 1)
    foreach ($rule in $rules) {
        if (-not $rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or ($rule.FileSystemRights -band $modifyMask) -ne $modifyMask) { $inherited = $false }
    }
    if (-not $inherited) { throw 'acl' }
    if (-not (Test-LowIntegrityLabel $expected)) { throw 'label' }
    $run = Invoke-ConfinedProbe $sandbox 'tempdir' 30
    if ($run.Failure -ne '' -or -not $run.Exited -or $run.TimedOut -or $run.ExitCode -ne 0) {
        $probeReason = 'probe_exit'
        if ($run.Failure -ne '') { $probeReason = 'probe_launch' }
        elseif (-not $run.Exited) { $probeReason = 'probe_not_exited' }
        elseif ($run.TimedOut) { $probeReason = 'probe_timeout' }
        $probeFailure = Get-Token ([string]$run.Failure) '^[a-z_]{0,24}$'
        $probeCode = '0x' + ([uint32]$run.ExitCode).ToString('x8')
        Write-Line ('windows-confinement-temp=failed reason=' + $probeReason + ' failure=' + $probeFailure + ' create_error=' + $run.CreateError + ' exit=' + $probeCode)
        throw $probeReason
    }
    if (-not (Test-ContainerTempReport ([string]$run.Stdout))) { throw 'identity' }
    Write-Line 'windows-confinement-temp=verified location=scratch_profile inherited_acl=verified label=low'
}

function Test-OtherContainerNul($first) {
    $other = [KeelDock.Platform.WindowsConfinement.Sandbox]::Create()
    $script:OtherBox = $other
    $script:OtherFolder = Join-Path (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) 'Packages') $other.ProfileName
    Register-RemovalRoot $script:OtherFolder
    if (([string]$other.SidText -ceq [string]$script:Sid) -or ([string]$other.ProfileName -ceq [string]$first.ProfileName)) { throw 'nul_other_not_distinct' }
    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $commandLine = '"' + $cmd + '" /d /c echo x>NUL'
    $environment = New-StageEnvironment $script:Lpac 'target-nul-other'
    $seconds = $script:OtherContainerSeconds
    $granted = $first.Run($true, $cmd, $commandLine, $script:Lpac.Root, $environment, ($seconds * 1000), [uint32]32)
    if ($granted.Failure -ne '' -or -not $granted.Exited -or $granted.TimedOut -or $granted.ExitCode -ne 0) { throw 'nul_other_control' }
    $denied = $other.Run($true, $cmd, $commandLine, (Join-Path $env:SystemRoot 'System32'), $environment, ($seconds * 1000), [uint32]32)
    if ($denied.Failure -ne '' -or -not $denied.Exited -or $denied.TimedOut) { throw 'nul_other_launch' }
    if ($denied.ExitCode -eq 0 -or (($denied.Stdout + $denied.Stderr) -cnotmatch 'Access is denied')) { throw 'nul_other_not_denied' }
    Write-Line 'windows-confinement-nul-other=denied container=distinct error=5 control=granted'
}

function Remove-TreeNoFollow([string]$path) {
    [KeelDock.Platform.WindowsConfinement.HandleRemover]::Remove($path)
}

function Remove-ReparsePoints([string]$path) {
    [KeelDock.Platform.WindowsConfinement.HandleRemover]::RemoveLinks($path)
}

function Register-RemovalRoot([string]$path) {
    [KeelDock.Platform.WindowsConfinement.HandleRemover]::AllowRoot($path)
}

function Test-NotFoundAttributable([string]$text, [string]$path) {
    if ($text -cnotmatch '^open=(err2|err3|ENOENT)$') { return $true }
    if ([string]::IsNullOrEmpty($path)) { return $false }
    return [bool](Test-Path -LiteralPath $path -PathType Leaf)
}

function Get-JobLiveness($sandboxes, [int]$waitSeconds) {
    $state = 'none'
    foreach ($sandbox in @($sandboxes)) {
        if ($null -eq $sandbox) { continue }
        $item = [string]$sandbox.JobState($waitSeconds * 1000)
        if ($item -ceq 'unreadable') { return 'unknown' }
        if ($item -ceq 'alive') { $state = 'alive' }
    }
    return $state
}

function Write-CleanupDetail([string]$stage, $failure) {
    $message = [string]$failure.Exception.Message
    Write-Line ('kd-diag stage=cleanup_' + $stage + ' stream=detail line=' + (Get-CleanText $message 160))
}

function Test-PipeListed([string]$leaf) {
    try {
        foreach ($pipePath in [System.IO.Directory]::GetFiles('\\.\pipe\')) {
            if ([System.IO.Path]::GetFileName($pipePath) -ceq $leaf) { return $true }
        }
    } catch {
        return $true
    }
    return $false
}

function Remove-Canaries {
    foreach ($item in @($script:Canaries)) {
        if ($item -and (Test-Path -LiteralPath $item)) {
            Remove-TreeNoFollow $item
        }
    }
}

function New-LinkFixture([string]$kind, [string]$path, [string]$target) {
    try {
        New-Item -ItemType $kind -Path $path -Value $target | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Initialize-LinkFixtures {
    $suffix = [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $trap = Join-Path $env:RUNNER_TEMP ('kd-trap-' + $suffix)
    $inner = Join-Path $trap 'inner'
    New-Item -ItemType Directory -Path $inner | Out-Null
    $sentinel = Join-Path $inner 'sentinel.txt'
    [IO.File]::WriteAllText($sentinel, 'kd-sentinel')
    $script:TrapDirectory = $trap
    Register-RemovalRoot $trap
    $script:TrapSentinel = $sentinel
    $nested = Join-Path (Join-Path $script:Lpac.Tmp 'nested') 'deeper'
    New-Item -ItemType Directory -Force -Path $nested | Out-Null
    $packageAc = Join-Path $script:ProfileFolder 'AC'
    if (-not (Test-Path -LiteralPath $packageAc -PathType Container)) { $packageAc = $script:ProfileFolder }
    $junctions = @((Join-Path $script:Lpac.Tmp 'kd_junction'), (Join-Path $nested 'kd_junction'), (Join-Path $packageAc 'kd_junction'))
    foreach ($junction in $junctions) {
        if (-not (New-LinkFixture 'Junction' $junction $trap)) { throw 'link_fixture' }
        $script:PlantedJunctions += 1
    }
    if (New-LinkFixture 'SymbolicLink' (Join-Path $script:Lpac.Tmp 'kd_symlink_dir') $trap) { $script:PlantedSymlinks += 1 }
    if (New-LinkFixture 'SymbolicLink' (Join-Path $nested 'kd_symlink_file') $sentinel) { $script:PlantedSymlinks += 1 }
    Write-Line ('windows-confinement-links=planted junctions=' + $script:PlantedJunctions + ' symlinks=' + $script:PlantedSymlinks)
}

function Test-PathShape([string]$path) {
    return [bool]($path -match '^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$')
}

function Get-HostAddress([string]$name) {
    try {
        foreach ($address in [System.Net.Dns]::GetHostAddresses($name)) {
            if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { return [string]$address.IPAddressToString }
        }
    } catch {
        return ''
    }
    return ''
}

function Get-ChannelHost([string]$variable, [string]$fallback) {
    $value = [string][Environment]::GetEnvironmentVariable($variable)
    if ($value.Length -gt 0) {
        $uri = $null
        if ([Uri]::TryCreate($value, [UriKind]::Absolute, [ref]$uri) -and $uri.Scheme -eq 'https' -and $uri.Host -match '^[A-Za-z0-9.-]{1,100}$') { return [string]$uri.Host }
    }
    return $fallback
}

function Get-FirstExistingDirectory([string[]]$candidates) {
    foreach ($candidate in $candidates) {
        if ((Test-PathShape $candidate) -and (Test-Path -LiteralPath $candidate -PathType Container)) { return [string]$candidate }
    }
    return ''
}

function Get-RunnerDiagnosticFile([int]$workerPid) {
    if ($workerPid -le 0) { return '' }
    try {
        $workerPath = [string](Get-Process -Id $workerPid -ErrorAction Stop).Path
        $diagnosticDirectory = Join-Path (Split-Path -Parent (Split-Path -Parent $workerPath)) '_diag'
        if (-not (Test-Path -LiteralPath $diagnosticDirectory -PathType Container)) { return '' }
        $first = @(Get-ChildItem -LiteralPath $diagnosticDirectory -File -ErrorAction Stop | Select-Object -First 1)
        if ($first.Count -gt 0 -and (Test-PathShape $first[0].FullName)) { return [string]$first[0].FullName }
    } catch {
        return ''
    }
    return ''
}

function New-RegistryCanary($hive, [string]$value) {
    $path = 'Software\KeelDock\Canary'
    $parent = $hive.CreateSubKey('Software\KeelDock')
    if ($null -eq $parent) { throw 'channel_registry' }
    $parent.Dispose()
    $created = $hive.CreateSubKey($path)
    if ($null -eq $created) { throw 'channel_registry' }
    $created.Dispose()
    $permission = [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
    $rights = [System.Security.AccessControl.RegistryRights]'ChangePermissions, ReadKey, SetValue'
    $key = $hive.OpenSubKey($path, $permission, $rights)
    if ($null -eq $key) { throw 'channel_registry' }
    $allowed = @('S-1-5-18', 'S-1-5-32-544', [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    $security = New-Object System.Security.AccessControl.RegistrySecurity
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in $allowed) {
        $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule($identity, [System.Security.AccessControl.RegistryRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    $key.SetAccessControl($security)
    $key.SetValue('canary', $value)
    $key.Dispose()
    $reader = $hive.OpenSubKey($path)
    if ($null -eq $reader) { throw 'channel_registry' }
    $readback = $reader.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
    $reader.Dispose()
    if (-not $readback.AreAccessRulesProtected) { throw 'channel_registry' }
    $rules = @($readback.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne $allowed.Count) { throw 'channel_registry' }
    foreach ($rule in $rules) {
        $sidText = [string]$rule.IdentityReference.Value
        if ($rule.IsInherited -or $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { throw 'channel_registry' }
        if ($allowed -cnotcontains $sidText) { throw 'channel_registry' }
        if ($sidText.StartsWith('S-1-15-2-', [StringComparison]::Ordinal) -or $sidText.StartsWith('S-1-15-3-', [StringComparison]::Ordinal)) { throw 'channel_registry' }
        if ($rule.RegistryRights -ne [System.Security.AccessControl.RegistryRights]::FullControl) { throw 'channel_registry' }
    }
}

function Initialize-ChannelContext {
    $values = @{}
    foreach ($name in @('RUNNER_TEMP', 'RUNNER_TOOL_CACHE', 'GITHUB_ENV', 'GITHUB_OUTPUT', 'GITHUB_PATH', 'GITHUB_STEP_SUMMARY')) {
        $value = [string][Environment]::GetEnvironmentVariable($name)
        if (-not (Test-PathShape $value)) { throw 'channel_env' }
        $values[$name] = $value
    }
    foreach ($name in @('GITHUB_ENV', 'GITHUB_OUTPUT', 'GITHUB_PATH', 'GITHUB_STEP_SUMMARY')) {
        if (-not (Test-Path -LiteralPath $values[$name] -PathType Leaf)) { throw 'channel_file' }
    }
    foreach ($name in @('RUNNER_TEMP', 'RUNNER_TOOL_CACHE')) {
        if (-not (Test-Path -LiteralPath $values[$name] -PathType Container)) { throw 'channel_file' }
    }
    if ([string]::IsNullOrEmpty($script:CanaryNeedle) -or [string]::IsNullOrEmpty($script:CanaryScratchNeedle) -or $script:CanaryNeedle -ceq $script:CanaryScratchNeedle) { throw 'channel_needle' }
    $harnessPid = [int]$PID
    $parentPid = 0
    $self = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = ' + $harnessPid) -ErrorAction SilentlyContinue
    if ($self) { $parentPid = [int]$self.ParentProcessId }
    $workerPid = 0
    $workers = @(Get-Process -Name 'Runner.Worker' -ErrorAction SilentlyContinue)
    if ($workers.Count -gt 0) { $workerPid = [int]$workers[0].Id }
    $pids = @()
    foreach ($candidate in @($harnessPid, $parentPid, $workerPid)) {
        if ($candidate -gt 0 -and $pids -notcontains $candidate) { $pids += $candidate }
    }
    $runnerPipes = @()
    try {
        foreach ($pipePath in [System.IO.Directory]::GetFiles('\\.\pipe\')) {
            $leaf = [System.IO.Path]::GetFileName($pipePath)
            if ($runnerPipes.Count -lt 6 -and $leaf -match '^[A-Za-z0-9._{}-]{1,120}$' -and $leaf -match '(?i)runner|actions|github|hosted') { $runnerPipes += $leaf }
        }
    } catch {
        $runnerPipes = @()
    }
    $drives = @()
    foreach ($drive in @('C:\', 'D:\')) {
        if (Test-Path -LiteralPath $drive -PathType Container) { $drives += $drive }
    }
    $cryptoDirectory = Get-FirstExistingDirectory @((Join-Path $env:APPDATA 'Microsoft\Crypto\Keys'), (Join-Path $env:APPDATA 'Microsoft\Crypto'), (Join-Path $env:APPDATA 'Microsoft\Protect'), $env:APPDATA)
    if ($cryptoDirectory.Length -eq 0 -or $drives.Count -eq 0) { throw 'channel_file' }
    $resultsHost = 'results-receiver.actions.githubusercontent.com'
    $hostSource = 'default'
    $resultsFromEnv = Get-ChannelHost 'ACTIONS_RESULTS_URL' ''
    if ($resultsFromEnv.Length -gt 0) {
        $resultsHost = $resultsFromEnv
        $hostSource = 'env'
    }
    $cacheHost = $resultsHost
    $cacheSource = 'results'
    $cacheFromEnv = Get-ChannelHost 'ACTIONS_CACHE_URL' ''
    if ($cacheFromEnv.Length -gt 0) {
        $cacheHost = $cacheFromEnv
        $cacheSource = 'env'
    }
    $resultsIp = Get-HostAddress $resultsHost
    $cacheIp = Get-HostAddress $cacheHost
    $script:ChannelRegistry = $true
    foreach ($hive in @([Microsoft.Win32.Registry]::CurrentUser, [Microsoft.Win32.Registry]::LocalMachine)) {
        New-RegistryCanary $hive $script:CanaryNeedle
    }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText((Join-Path $script:Control.Root 'kd_walk_control.txt'), $script:CanaryNeedle, $encoding)
    $script:Listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $script:Listener.Start()
    $port = [int]([System.Net.IPEndPoint]$script:Listener.LocalEndpoint).Port
    $scalars = @{
        runner_temp = $values['RUNNER_TEMP']
        tool_cache = $values['RUNNER_TOOL_CACHE']
        github_env = $values['GITHUB_ENV']
        github_output = $values['GITHUB_OUTPUT']
        github_path = $values['GITHUB_PATH']
        github_summary = $values['GITHUB_STEP_SUMMARY']
        diag_file = (Get-RunnerDiagnosticFile $workerPid)
        crypto_dir = $cryptoDirectory
        base = [string]$script:Layout.Base
        canary_runner_temp = [string]$script:CanaryRunnerTemp
        canary_workspace = [string]$script:CanaryWorkspace
        canary_profile = [string]$script:CanaryProfile
        scratch_tmp = [string]$script:Lpac.Tmp
        control_tmp = [string]$script:Control.Tmp
        control_root = [string]$script:Control.Root
        ro_file = [string]$script:Layout.NodeTest
        needle = [string]$script:CanaryNeedle
        scratch_needle = [string]$script:CanaryScratchNeedle
        harness_pid = [string]$harnessPid
        port = [string]$port
        results_ip = $resultsIp
        cache_ip = $cacheIp
    }
    $script:Channel = @{ Pids = $pids; RunnerPipes = $runnerPipes; Drives = $drives; Scalars = $scalars }
    $diagState = 'absent'
    if (([string]$scalars['diag_file']).Length -gt 0) { $diagState = 'present' }
    Write-Line ('windows-confinement-channel-fixtures=ready targets=' + $pids.Count + ' runner_pipes=' + $runnerPipes.Count + ' drives=' + $drives.Count + ' diag=' + $diagState + ' results_host=' + $hostSource + ' cache_host=' + $cacheSource + ' results_ip=' + [string]($resultsIp.Length -gt 0) + ' cache_ip=' + [string]($cacheIp.Length -gt 0))
}

function Remove-ChannelFixtures {
    $failed = 0
    try {
        if ($script:Listener) { $script:Listener.Stop() }
    } catch {
        $failed += 1
    }
    if ($script:ChannelRegistry) {
        foreach ($hive in @([Microsoft.Win32.Registry]::CurrentUser, [Microsoft.Win32.Registry]::LocalMachine)) {
            try {
                $hive.DeleteSubKeyTree('Software\KeelDock', $false)
                $left = $hive.OpenSubKey('Software\KeelDock')
                if ($null -ne $left) {
                    $left.Dispose()
                    $failed += 1
                }
            } catch {
                $failed += 1
            }
        }
    }
    if ($script:Channel) {
        foreach ($name in @('runner_temp', 'tool_cache')) {
            try {
                foreach ($file in [System.IO.Directory]::GetFiles([string]$script:Channel.Scalars[$name], 'kd-att-*.tmp')) {
                    [System.IO.File]::Delete($file)
                    if (Test-Path -LiteralPath $file) { $failed += 1 }
                }
            } catch {
                $failed += 1
            }
        }
    }
    if ($failed -gt 0) { throw 'channel_cleanup' }
}

function New-TrustedPipe([string]$name) {
    Add-Type -AssemblyName System.IO.Pipes.AccessControl
    $security = New-Object System.IO.Pipes.PipeSecurity
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = New-Object System.IO.Pipes.PipeAccessRule($user, [System.IO.Pipes.PipeAccessRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)
    $security.AddAccessRule($rule)
    return [System.IO.Pipes.NamedPipeServerStreamAcl]::Create($name, [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::None, 0, 0, $security)
}

function Test-LpacTokenText([string]$tokenText) {
    return (($tokenText -like 'appcontainer=1,*') -and ($tokenText -like '*,capabilities=1,*') -and ($tokenText -like '*,integrity=0x1000,*') -and ($tokenText -like '*,lpac=attr,*') -and ($tokenText -like '*,cap=registryRead,*') -and ($tokenText -like '*,sid=match,*') -and ($tokenText -like '*,aap=absent'))
}

function Test-ChannelRunValid($run, [bool]$confined) {
    if ($run.Failure -ne '' -or -not $run.Exited -or $run.TimedOut -or $run.ExitCode -ne 0) { return $false }
    if ([uint32]$run.HandleCount -ne 3) { return $false }
    if ($confined) {
        $tokenText = Get-Token (([string]$run.Token) -replace ' ', ',') '^[A-Za-z0-9=,_.-]{1,160}$'
        $jobText = Get-Token (([string]$run.Job) -replace ' ', ',') '^[A-Za-z0-9=,_.-]{1,120}$'
        if (-not (Test-LpacTokenText $tokenText)) { return $false }
        if (-not ($jobText -like 'assigned,*')) { return $false }
    }
    return $true
}

function Expand-ChannelRun([string]$template) {
    $items = @($template)
    $multiple = [ordered]@{ '{pid}' = $script:Channel.Pids; '{runner_pipe}' = $script:Channel.RunnerPipes; '{drive}' = $script:Channel.Drives }
    foreach ($token in $multiple.Keys) {
        $values = @($multiple[$token])
        $next = @()
        foreach ($item in $items) {
            if ($item.Contains($token)) {
                foreach ($value in $values) { $next += $item.Replace($token, [string]$value) }
            } else {
                $next += $item
            }
        }
        $items = $next
    }
    $final = @()
    foreach ($item in $items) {
        $text = $item.Replace('{rand}', [Guid]::NewGuid().ToString('N').Substring(0, 12))
        $skip = $false
        foreach ($key in $script:Channel.Scalars.Keys) {
            $marker = '{' + $key + '}'
            if ($text.Contains($marker)) {
                $value = [string]$script:Channel.Scalars[$key]
                if ($value.Length -eq 0) { $skip = $true } else { $text = $text.Replace($marker, $value) }
            }
        }
        if ($text.Replace('{pipe}', '').Contains('{')) { $skip = $true }
        if (-not $skip) { $final += $text }
    }
    return $final
}

function Invoke-ChannelRun($sandbox, [bool]$confined, [string]$arguments, [int]$timeoutSeconds, [string[]]$extraEnvironment) {
    $exe = $script:Layout.ProbeExe
    $scratch = $script:Control
    $targetName = 'target-channel-control'
    if ($confined) {
        $scratch = $script:Lpac
        $targetName = 'target-probe'
    }
    $environment = New-StageEnvironment $scratch $targetName
    if ($extraEnvironment -and $extraEnvironment.Count -gt 0) { $environment = [string[]]($environment + $extraEnvironment) }
    $pipe = $null
    $text = $arguments
    if ($text.Contains('{pipe}')) {
        $pipeName = 'kd-trusted-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
        $pipe = New-TrustedPipe $pipeName
        $text = $text.Replace('{pipe}', $pipeName)
    }
    try {
        return $sandbox.Run($confined, $exe, ('"' + $exe + '" ' + $text), $scratch.Root, $environment, ($timeoutSeconds * 1000), [uint32]32)
    } finally {
        if ($pipe) { $pipe.Dispose() }
    }
}

function Get-TextClass([string]$text, $attempt) {
    if ($text.Length -eq 0) { return 'other' }
    $allow = [string]$attempt.Allow
    if ($attempt.ContainsKey('ConfinedAllow')) { $allow = [string]$attempt.ConfinedAllow }
    if ($text -cmatch $allow) { return 'allowed' }
    if ($text -cmatch $attempt.Deny) {
        if ($attempt.Expect -ceq 'contained') { return 'contained' }
        return 'denied'
    }
    if ($attempt.ContainsKey('NaPattern') -and ($text -cmatch $attempt.NaPattern)) { return 'not_applicable' }
    return 'other'
}

function Get-AttemptResult($run, [string]$command, $attempt) {
    $stdout = [string]$run.Stdout
    $text = Get-ProbeText $stdout $command
    if ($attempt.ContainsKey('Marker')) {
        if (($text -ceq 'text=ok') -and ($stdout -match '(?m)^::debug::kd-marker\s*$') -and ((Get-CleanText $stdout 500) -cnotmatch ':')) { return 'contained' }
        return 'other'
    }
    return (Get-TextClass $text $attempt)
}

function Get-ChannelAttempts {
    $attempts = @()
    $attempts += @{ Channel = 'https'; Name = 'tls-ipv4'; Runs = @('connect 1.1.1.1:443'); ControlRuns = @('connect 1.1.1.1:443'); Allow = '^resolve=ok connect=open$'; Deny = '^resolve=ok connect=err10013$'; Expect = 'denied'; Timeout = 30 }
    $attempts += @{ Channel = 'https'; Name = 'tls-ipv6'; Runs = @('connect [2606:4700:4700::1111]:443'); ControlRuns = @('connect [2606:4700:4700::1111]:443'); ControlNa = '^resolve=ok connect=err(10047|10051)$|^resolve=empty$'; Allow = '^resolve=ok connect=open$'; Deny = '^resolve=ok connect=err10013$'; Expect = 'denied'; Timeout = 30 }
    $attempts += @{ Channel = 'https'; Name = 'tls-hostname'; Runs = @('connect registry.npmjs.org:443'); ControlRuns = @('connect registry.npmjs.org:443'); Allow = '^resolve=ok connect=open$'; Deny = '^resolve=(err11003|err10013)$|^resolve=ok connect=err10013$'; Expect = 'denied'; Timeout = 30 }
    $attempts += @{ Channel = 'dns'; Name = 'getaddrinfo'; Runs = @('dns github.com'); ControlRuns = @('dns github.com'); Allow = '^resolve=ok count=[1-9][0-9]*$'; Deny = '^resolve=(err11003|err10013)$'; Expect = 'denied'; Timeout = 30 }
    $attempts += @{ Channel = 'dns'; Name = 'unique-name'; Runs = @('dns kd-{rand}.example.com'); ControlRuns = @('dns kd-{rand}.example.com'); ControlAllow = '^resolve=err(11001|11004)$'; Allow = '^resolve=ok count=[1-9][0-9]*$'; Deny = '^resolve=(err11003|err10013)$'; Expect = 'denied'; Timeout = 30 }
    $attempts += @{ Channel = 'dns'; Name = 'udp-query'; Runs = @('udp 1.1.1.1:53'); ControlRuns = @('udp 1.1.1.1:53'); Allow = '^send=ok recv=data$'; Deny = '^bind=err10013$|^send=err10013$'; Expect = 'denied'; Timeout = 30 }
    $attempts += @{ Channel = 'dns'; Name = 'tcp-query'; Runs = @('connect 1.1.1.1:53'); ControlRuns = @('connect 1.1.1.1:53'); Allow = '^resolve=ok connect=open$'; Deny = '^resolve=ok connect=err10013$'; Expect = 'denied'; Timeout = 30 }
    $attempts += @{ Channel = 'redirect'; Name = 'http-redirect'; Runs = @('connect github.com:80'); ControlRuns = @('connect github.com:80'); Allow = '^resolve=ok connect=open$'; Deny = '^resolve=(err11003|err10013)$|^resolve=ok connect=err10013$'; Expect = 'denied'; Timeout = 30 }
    $attempts += @{ Channel = 'proxy'; Name = 'proxy-env-http'; Basis = 'harness'; Runs = @('envhunt proxy'); ControlRuns = @('envhunt proxy'); ControlEnvironment = $true; Allow = '^found=[1-9][0-9]*$'; Deny = '^found=0$'; Expect = 'contained'; Timeout = 10 }
    $attempts += @{ Channel = 'proxy'; Name = 'proxy-connect'; Runs = @('connect 127.0.0.1:{port}'); ControlRuns = @('connect 127.0.0.1:{port}'); Allow = '^resolve=ok connect=open$'; Deny = '^resolve=ok connect=err10013$'; Expect = 'denied'; Timeout = 30 }
    $attempts += @{ Channel = 'runner_ipc'; Name = 'pipe-root-create'; Runs = @('pipemake root {rand}'); ControlRuns = @('pipemake root {rand}'); Allow = '^create=ok$'; Deny = '^create=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'runner_ipc'; Name = 'pipe-existing-open'; Runs = @('pipeopen {pipe}'); ControlRuns = @('pipeopen {pipe}'); Allow = '^open=ok$'; Deny = '^open=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'runner_ipc'; Name = 'pipe-runner-open'; Optional = $true; NaPattern = '^open=err2$'; NaRecheck = 'pipe'; Runs = @('pipeopen {runner_pipe}'); ControlRuns = @(); Allow = '^open=ok$'; Deny = '^open=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'runner_ipc'; Name = 'process-open-runner'; Runs = @('procopen {pid} dup'); ControlRuns = @('procopen {harness_pid} dup'); Allow = '^open=ok$'; Deny = '^open=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'runner_ipc'; Name = 'handle-inventory'; Runs = @('echo'); ControlRuns = @(); Allow = '^result=fail$'; Deny = '^result=ok$'; Expect = 'contained'; Timeout = 10 }
    $attempts += @{ Channel = 'runner_ipc'; Name = 'named-pipe-local'; Informational = $true; Runs = @('pipemake local {rand}'); ControlRuns = @(); Allow = '^create=ok$'; Deny = '^create=err5$'; Expect = 'allowed'; Timeout = 10 }
    $attempts += @{ Channel = 'raw_logs'; Name = 'stdout-markers'; Basis = 'harness'; Marker = $true; Runs = @('marker'); ControlRuns = @('marker'); ControlAllow = '^text=ok$'; Allow = '^text=never$'; Deny = '^text=never$'; Expect = 'contained'; Timeout = 10 }
    $attempts += @{ Channel = 'raw_logs'; Name = 'conout-open'; Informational = $true; Runs = @('conout'); ControlRuns = @('conout'); ControlInformational = $true; Allow = '^open=ok$'; Deny = '^open=err(2|5|6)$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'raw_logs'; Name = 'eventlog'; Runs = @('eventlog'); ControlRuns = @('eventlog'); Allow = '^open=ok$'; Deny = '^open=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'artifact_upload'; Name = 'env-hunt'; Basis = 'harness'; Runs = @('envhunt actions'); ControlRuns = @('envhunt actions'); ControlEnvironment = $true; Allow = '^found=[1-9][0-9]*$'; Deny = '^found=0$'; Expect = 'contained'; Timeout = 10 }
    $attempts += @{ Channel = 'artifact_upload'; Name = 'endpoint-post'; Runs = @('connect {results_ip}:443'); ControlRuns = @('connect {results_ip}:443'); Allow = '^resolve=ok connect=open$'; Deny = '^resolve=ok connect=err10013$'; Expect = 'denied'; Timeout = 30 }
    $attempts += @{ Channel = 'artifact_upload'; Name = 'staging-write'; Runs = @('write {runner_temp}\kd-att-{rand}.tmp'); ControlRuns = @('write {runner_temp}\kd-att-{rand}.tmp'); Allow = '^create=ok write=ok$'; Deny = '^create=err5$'; Expect = 'contained'; Timeout = 10 }
    $attempts += @{ Channel = 'cache_upload'; Name = 'env-hunt'; Basis = 'harness'; Runs = @('envhunt actions'); ControlRuns = @('envhunt actions'); ControlEnvironment = $true; Allow = '^found=[1-9][0-9]*$'; Deny = '^found=0$'; Expect = 'contained'; Timeout = 10 }
    $attempts += @{ Channel = 'cache_upload'; Name = 'endpoint-post'; Optional = $true; Runs = @('connect {cache_ip}:443'); ControlRuns = @('connect {cache_ip}:443'); Allow = '^resolve=ok connect=open$'; Deny = '^resolve=ok connect=err10013$'; Expect = 'denied'; Timeout = 30 }
    $attempts += @{ Channel = 'cache_upload'; Name = 'cache-write'; Runs = @('write {tool_cache}\kd-att-{rand}.tmp'); ControlRuns = @('write {tool_cache}\kd-att-{rand}.tmp'); Allow = '^create=ok write=ok$'; Deny = '^create=err5$'; Expect = 'contained'; Timeout = 10 }
    $attempts += @{ Channel = 'runner_files'; Name = 'canary-reads'; Runs = @('read {canary_runner_temp}', 'read {canary_workspace}', 'read {canary_profile}'); ControlRuns = @('read {canary_runner_temp}', 'read {canary_workspace}', 'read {canary_profile}'); Allow = '^open=ok read=ok bytes=[0-9]+$'; Deny = '^open=err(2|3|5)$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'runner_files'; Name = 'diag-read'; Optional = $true; Runs = @('read {diag_file}'); ControlRuns = @('read {diag_file}'); Allow = '^open=ok read=ok bytes=[0-9]+$'; Deny = '^open=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'runner_files'; Name = 'command-files'; Runs = @('read {github_env}', 'read {github_output}', 'read {github_path}', 'read {github_summary}', 'append {github_env}', 'append {github_output}', 'append {github_path}', 'append {github_summary}'); ControlRuns = @('read {github_env}', 'read {github_output}', 'read {github_path}', 'read {github_summary}', 'append {github_env}', 'append {github_output}', 'append {github_path}', 'append {github_summary}'); Allow = '^open=ok( read=ok bytes=[0-9]+)?$'; Deny = '^open=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'runner_files'; Name = 'cng-keys'; Runs = @('list {crypto_dir}'); ControlRuns = @('list {crypto_dir}'); Allow = '^list=ok count=[0-9]+$'; Deny = '^list=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'runner_files'; Name = 'registry-canary'; Runs = @('regread hkcu', 'regread hklm'); ControlRuns = @('regread hkcu', 'regread hklm'); Allow = '^open=ok$'; Deny = '^open=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'runner_files'; Name = 'bounded-walk'; Runs = @('walk {drive} 150 {needle}'); ControlRuns = @('walk {control_root} 30 {needle}'); Allow = '^scanned=[0-9]+ found=1$'; Deny = '^scanned=[0-9]+ found=0$'; Expect = 'contained'; Timeout = 200; ControlTimeout = 60 }
    $attempts += @{ Channel = 'runner_files'; Name = 'walk-control-scratch'; Runs = @('walk {scratch_tmp} 30 {scratch_needle}'); ControlRuns = @(); Allow = '^scanned=[0-9]+ found=1$'; Deny = '^scanned=[0-9]+ found=0$'; Expect = 'allowed'; Timeout = 60 }
    $attempts += @{ Channel = 'process_memory'; Name = 'mem-read'; Runs = @('procopen {pid} vmread'); ControlRuns = @('procopen {harness_pid} vmread'); Allow = '^open=ok$'; Deny = '^open=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'process_memory'; Name = 'environ-read'; Runs = @('procopen {pid} environ'); ControlRuns = @('procopen {harness_pid} environ'); Allow = '^open=ok$'; Deny = '^open=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'process_memory'; Name = 'debug-attach'; Runs = @('procopen {pid} debug'); ControlRuns = @('procopen {harness_pid} debug'); Allow = '^open=ok$'; Deny = '^open=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'process_memory'; Name = 'control-self-memory'; Runs = @('procopen self vmread'); ControlRuns = @(); Allow = '^open=ok$'; Deny = '^open=err5$'; Expect = 'allowed'; Timeout = 10 }
    $attempts += @{ Channel = 'process_memory'; Name = 'control-peer-memory'; Runs = @('procpeer'); ControlRuns = @('procpeer'); Allow = '^open=ok$'; Deny = '^open=never$'; NaPattern = '^open=err5$'; Expect = 'allowed'; Timeout = 20 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'job-breakaway'; Runs = @('jobbreak'); ControlRuns = @(); Allow = '^spawn=ok$'; Deny = '^spawn=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'job-membership'; Basis = 'harness'; Runs = @('jobmember'); ControlRuns = @('jobmember'); ControlAllow = '^injob=yes$'; Allow = '^injob=no$'; Deny = '^injob=yes$'; Expect = 'contained'; Timeout = 10 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'profile-create'; Runs = @('profile'); ControlRuns = @('profile'); Allow = '^create=ok$'; ConfinedAllow = '^create=ok( delete=(err[0-9]+|hr[0-9a-f]{8}))?$'; Deny = '^create=hr80070005$|^create=hr800706d9$'; Expect = 'denied'; Timeout = 20 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'scm-open'; Runs = @('scm'); ControlRuns = @('scm'); Allow = '^open=ok$'; Deny = '^open=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'nul-write-dac'; Runs = @('nuldac'); ControlRuns = @(); Allow = '^result=ok$'; Deny = '^result=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'ancestor-write-dac'; Runs = @('dacopen {base}'); ControlRuns = @('dacopen {base}'); Allow = '^open=ok$'; Deny = '^open=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'hklm-write'; Runs = @('regcreate hklm'); ControlRuns = @('regcreate hklm'); Allow = '^create=ok$'; ConfinedAllow = '^create=ok( delete=(err[0-9]+|hr[0-9a-f]{8}))?$'; Deny = '^create=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'hkcu-write'; Runs = @('regcreate hkcu'); ControlRuns = @('regcreate hkcu'); Allow = '^create=ok$'; ConfinedAllow = '^create=ok( delete=(err[0-9]+|hr[0-9a-f]{8}))?$'; Deny = '^create=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'symlink'; Runs = @('symlink {scratch_tmp}\kd_att_{rand}.lnk {ro_file}'); ControlRuns = @('symlink {control_tmp}\kd_att_{rand}.lnk {ro_file}'); Allow = '^create=ok$'; Deny = '^create=err(5|1314)$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'hardlink-ro'; Runs = @('hardlink {scratch_tmp}\kd_att_{rand}.lnk {ro_file}'); ControlRuns = @('hardlink {control_tmp}\kd_att_{rand}.lnk {ro_file}'); Allow = '^create=ok$'; Deny = '^create=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'integrity-raise'; Runs = @('tokenraise'); ControlRuns = @('tokenraise'); Allow = '^open=ok set=ok$'; Deny = '^open=ok set=err(5|1314)$|^open=err5 set=na$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'privilege-enable'; Runs = @('tokenpriv'); ControlRuns = @('tokenpriv'); Allow = '^adjust=ok$'; Deny = '^adjust=err1300$|^open=err5$'; Expect = 'denied'; Timeout = 10 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'task-register'; Informational = $true; LeakGuard = $true; Runs = @('taskreg'); ControlRuns = @('taskreg'); Allow = '^create=ok connect=ok$'; Deny = '^create=ok connect=hr80070005$'; Expect = 'denied'; Timeout = 30 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'wmi'; Informational = $true; LeakGuard = $true; Runs = @('wmi'); ControlRuns = @('wmi'); Allow = '^create=ok connect=ok$'; Deny = '^create=ok connect=hr80070005$|^create=ok connect=hr80041003$'; Expect = 'denied'; Timeout = 30 }
    $attempts += @{ Channel = 'boundary_disablement'; Name = 'wfp'; Informational = $true; LeakGuard = $true; Runs = @('wfp'); ControlRuns = @('wfp'); Allow = '^open=ok$'; Deny = '^open=err5$'; Expect = 'denied'; Timeout = 20 }
    return $attempts
}

function Invoke-ChannelAttempt($sandbox, $attempt, [string]$phase, [bool]$withControls) {
    $outcome = @{ Result = 'other'; Reason = 'none'; Runs = 0; Control = 'none' }
    $label = [string]$attempt.Channel + '_' + [string]$attempt.Name
    $optional = $attempt.ContainsKey('Optional')
    $informationalControl = $attempt.ContainsKey('ControlInformational')
    $expanded = @()
    foreach ($template in $attempt.Runs) {
        foreach ($item in @(Expand-ChannelRun $template)) { $expanded += $item }
    }
    if ($withControls -and $attempt.ControlRuns.Count -gt 0) {
        $controlAllow = [string]$attempt.Allow
        if ($attempt.ContainsKey('ControlAllow')) { $controlAllow = [string]$attempt.ControlAllow }
        $controlTimeout = [int]$attempt.Timeout
        if ($attempt.ContainsKey('ControlTimeout')) { $controlTimeout = [int]$attempt.ControlTimeout }
        $controlEnvironment = @()
        if ($attempt.ContainsKey('ControlEnvironment')) { $controlEnvironment = $ChannelSentinelEnvironment }
        $controlRuns = 0
        $controlFailed = $false
        $controlNa = $false
        foreach ($template in $attempt.ControlRuns) {
            foreach ($arguments in @(Expand-ChannelRun $template)) {
                $controlRuns += 1
                $run = Invoke-ChannelRun $sandbox $false $arguments $controlTimeout $controlEnvironment
                $command = ($arguments -split ' ')[0]
                $text = Get-ProbeText ([string]$run.Stdout) $command
                $fired = (Test-ChannelRunValid $run $false) -and ($text -cmatch $controlAllow)
                if (-not $fired -and (Test-ChannelRunValid $run $false) -and $attempt.ContainsKey('ControlNa') -and ($text -cmatch [string]$attempt.ControlNa)) {
                    $controlNa = $true
                } elseif (-not $fired) {
                    $controlFailed = $true
                    Write-DiagLines ($label + '_control') 'stdout' ([string]$run.Stdout)
                }
            }
        }
        if ($controlRuns -eq 0) {
            if ($optional) {
                $outcome.Result = 'not_applicable'
                return $outcome
            }
            $controlFailed = $true
        }
        if ($controlNa -and -not $controlFailed) {
            $outcome.Control = 'na'
            $outcome.Result = 'not_applicable'
            return $outcome
        }
        if ($controlFailed -and -not $informationalControl) {
            $outcome.Control = 'not_fired'
            if (-not $attempt.ContainsKey('LeakGuard')) {
                $outcome.Reason = 'control_not_fired'
                return $outcome
            }
        } else {
            $outcome.Control = 'fired'
            if ($controlFailed) { $outcome.Control = 'informational' }
        }
    }
    if ($expanded.Count -eq 0) {
        if ($optional) {
            $outcome.Result = 'not_applicable'
            return $outcome
        }
        $outcome.Reason = 'fixture_incomplete'
        return $outcome
    }
    $results = @()
    foreach ($arguments in $expanded) {
        $run = Invoke-ChannelRun $sandbox $true $arguments ([int]$attempt.Timeout) @()
        $outcome.Runs += 1
        $command = ($arguments -split ' ')[0]
        $result = 'invalid'
        $runValid = Test-ChannelRunValid $run $true
        if ($runValid -or $attempt.ContainsKey('LeakGuard')) { $result = Get-AttemptResult $run $command $attempt }
        if (-not $runValid -and $result -cne 'allowed') { $result = 'invalid' }
        if ($result -ceq 'not_applicable' -and $attempt.ContainsKey('NaRecheck') -and (Test-PipeListed (($arguments -split ' ')[1]))) { $result = 'other' }
        if ($result -ceq 'denied' -and [string]$attempt.Name -ceq 'canary-reads' -and -not (Test-NotFoundAttributable (Get-ProbeText ([string]$run.Stdout) $command) (($arguments -split ' ', 2)[1]))) { $result = 'other' }
        $results += $result
        if ($result -cne [string]$attempt.Expect) { Write-DiagLines $label 'stdout' ([string]$run.Stdout) }
    }
    $outcome.Result = [string]$attempt.Expect
    $applicable = 0
    foreach ($result in $results) {
        if ($result -cne 'not_applicable') { $applicable += 1 }
    }
    if ($applicable -eq 0) {
        if ($attempt.ContainsKey('NaPattern') -or $optional) {
            $outcome.Result = 'not_applicable'
            return $outcome
        }
    }
    foreach ($result in $results) {
        if ($result -ceq [string]$attempt.Expect) { continue }
        if ($result -ceq 'not_applicable' -and $attempt.ContainsKey('NaPattern')) { continue }
        if ($outcome.Reason -cne 'none') { continue }
        $outcome.Result = $result
        if ($result -ceq 'allowed') { $outcome.Reason = 'channel_leak' }
        elseif ($result -ceq 'invalid') { $outcome.Reason = 'attempt_incomplete' }
        else { $outcome.Reason = 'attempt_unexpected' }
    }
    return $outcome
}

function Invoke-ChannelPhase($sandbox, [string]$phase, [bool]$withControls) {
    $report = [ordered]@{}
    foreach ($channel in $ChannelNames) {
        $report[$channel] = @{ Status = 'blocked'; Reason = 'none'; Attempts = 0; NotApplicable = 0; Boundary = 0; Informational = 0; ControlsFired = 0; ControlsMissed = 0 }
    }
    foreach ($attempt in (Get-ChannelAttempts)) {
        $entry = $report[[string]$attempt.Channel]
        $outcome = Invoke-ChannelAttempt $sandbox $attempt $phase $withControls
        $informational = $attempt.ContainsKey('Informational')
        $basis = 'boundary'
        if ($attempt.ContainsKey('Basis')) { $basis = [string]$attempt.Basis }
        Write-Line ('windows-confinement-attempt=' + $attempt.Channel + '/' + $attempt.Name + ' phase=' + $phase + ' result=' + $outcome.Result + ' expect=' + $attempt.Expect + ' runs=' + $outcome.Runs + ' control=' + $outcome.Control + ' reason=' + $outcome.Reason + ' informational=' + $informational.ToString().ToLowerInvariant() + ' basis=' + $basis)
        if ($informational) {
            $entry.Informational += 1
            if ($attempt.ContainsKey('LeakGuard') -and $outcome.Reason -ceq 'channel_leak' -and $entry.Status -ceq 'blocked') {
                $entry.Status = 'observed-leak'
                $entry.Reason = 'channel_leak'
            }
            continue
        }
        $entry.Attempts += 1
        if ($outcome.Result -ceq 'not_applicable') {
            $entry.NotApplicable += 1
        } elseif ($basis -ceq 'boundary' -and $attempt.Expect -cne 'allowed' -and $outcome.Reason -ceq 'none') {
            $entry.Boundary += 1
        }
        if ($outcome.Control -ceq 'not_fired') { $entry.ControlsMissed += 1 }
        if (@('fired', 'na') -ccontains $outcome.Control) { $entry.ControlsFired += 1 }
        if ($outcome.Reason -cne 'none' -and $entry.Status -ceq 'blocked') {
            $entry.Status = 'refused'
            if ($outcome.Reason -ceq 'channel_leak') { $entry.Status = 'observed-leak' }
            $entry.Reason = $outcome.Reason
        }
    }
    foreach ($channel in $ChannelNames) {
        $entry = $report[$channel]
        if ($entry.Boundary -eq 0 -and $entry.Status -ceq 'blocked') {
            $entry.Status = 'refused'
            $entry.Reason = 'fixture_incomplete'
        }
        Write-Line ('windows-confinement-channel=' + $channel + ' phase=' + $phase + ' status=' + $entry.Status + ' reason=' + $entry.Reason + ' attempts=' + $entry.Attempts + ' not_applicable=' + $entry.NotApplicable + ' boundary=' + $entry.Boundary + ' informational=' + $entry.Informational + ' controls_fired=' + $entry.ControlsFired + ' controls_missed=' + $entry.ControlsMissed)
    }
    return $report
}

function Get-ChannelBlockedCount($report) {
    $count = 0
    foreach ($channel in $ChannelNames) {
        if ($report[$channel].Status -ceq 'blocked') { $count += 1 }
    }
    return $count
}

function Get-ChannelControlState($report) {
    foreach ($channel in $ChannelNames) {
        if ($report[$channel].ControlsMissed -gt 0 -or $report[$channel].ControlsFired -eq 0) { return 'not_fired' }
    }
    return 'fired'
}

function Initialize-FixtureSources {
    $hash = [string][char]35
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $manifest = "[package]`nname = `"kd_fx`"`nversion = `"0.1.0`"`nedition = `"2021`"`n"
    $body = $FixtureRustText.Replace("`r`n", "`n")
    $mainText = $body + "`nfn main() {`n    run_attempts();`n}`n"
    $libText = ($body + "`nKDHASH[test]`nfn hostile_attempts() {`n    run_attempts();`n}`n").Replace('KDHASH', $hash)
    $nodeText = $FixtureNodeText.Replace("`r`n", "`n")
    foreach ($set in @($script:Lpac, $script:Control)) {
        $root = Join-Path $set.Root 'fx'
        $sources = [ordered]@{}
        $sources['build_rs\Cargo.toml'] = $manifest
        $sources['build_rs\build.rs'] = $mainText
        $sources['build_rs\src\main.rs'] = "fn main() {}`n"
        $sources['test\Cargo.toml'] = $manifest + "`n[lib]`npath = `"src/lib.rs`"`n"
        $sources['test\src\lib.rs'] = $libText
        $sources['binary\Cargo.toml'] = $manifest
        $sources['binary\src\main.rs'] = $mainText
        $sources['node_install\package.json'] = $FixtureNodePackage
        $sources['node_install\install.js'] = $nodeText
        foreach ($name in $sources.Keys) {
            $path = Join-Path $root $name
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
            [IO.File]::WriteAllText($path, [string]$sources[$name], $encoding)
        }
    }
}

function Get-FixtureAttempts([string]$form) {
    $attempts = @()
    if ($form -ceq 'node_install') {
        $attempts += @{ Name = 'net-external'; Allow = '^connect=open$'; Deny = '^connect=EACCES$'; Expect = 'denied' }
        $attempts += @{ Name = 'net-loopback'; Allow = '^connect=open$'; Deny = '^connect=EACCES$'; Expect = 'denied' }
        $attempts += @{ Name = 'dns-lookup'; Informational = $true; LeakGuard = $true; Allow = '^resolve=ok$'; Deny = '^resolve=(EAI_FAIL|EACCES)$'; Expect = 'denied' }
        $attempts += @{ Name = 'read-canary'; Allow = '^open=ok read=ok bytes=[0-9]+$'; Deny = '^open=(EPERM|ENOENT)$'; Expect = 'denied' }
        $attempts += @{ Name = 'write-escape'; Allow = '^create=ok write=ok$'; Deny = '^create=EPERM$'; Expect = 'contained' }
        $attempts += @{ Name = 'env-hunt'; Basis = 'harness'; Allow = '^found=[1-9][0-9]*$'; Deny = '^found=0$'; Expect = 'contained' }
        $attempts += @{ Name = 'pipe-open'; Allow = '^open=ok$'; Deny = '^open=EPERM$'; Expect = 'denied' }
        $attempts += @{ Name = 'output-exfil'; Basis = 'harness'; Marker = $true; Allow = '^text=never$'; Deny = '^text=never$'; Expect = 'contained' }
        $attempts += @{ Name = 'spawn-pipe'; Separate = $true; RequireHang = 'busy'; Informational = $true; LeakGuard = $true; Allow = '^spawn=ok$'; Deny = '^spawn=never$'; Expect = 'denied' }
    } else {
        $attempts += @{ Name = 'net-external'; Allow = '^resolve=ok connect=open$'; Deny = '^resolve=ok connect=err10013$'; Expect = 'denied' }
        $attempts += @{ Name = 'net-loopback'; Allow = '^resolve=ok connect=open$'; Deny = '^resolve=ok connect=err10013$'; Expect = 'denied' }
        $attempts += @{ Name = 'dns-lookup'; Allow = '^resolve=ok count=[1-9][0-9]*$'; Deny = '^resolve=(err11003|err10013)$'; Expect = 'denied' }
        $attempts += @{ Name = 'read-canary'; Allow = '^open=ok read=ok bytes=[0-9]+$'; Deny = '^open=err(2|3|5)$'; Expect = 'denied' }
        $attempts += @{ Name = 'write-escape'; Allow = '^create=ok write=ok$'; Deny = '^create=err5$'; Expect = 'contained' }
        $attempts += @{ Name = 'env-hunt'; Basis = 'harness'; Allow = '^found=[1-9][0-9]*$'; Deny = '^found=0$'; Expect = 'contained' }
        $attempts += @{ Name = 'pipe-open'; Allow = '^open=ok$'; Deny = '^open=err5$'; Expect = 'denied' }
        $attempts += @{ Name = 'child-network'; Allow = '^resolve=ok connect=open$'; Deny = '^resolve=ok connect=err10013$'; Expect = 'denied' }
        $attempts += @{ Name = 'child-write'; Allow = '^create=ok write=ok$'; Deny = '^create=err5$'; Expect = 'contained' }
        $attempts += @{ Name = 'child-cmd'; Allow = '^exit=7$'; Deny = '^exit=never$'; Expect = 'allowed' }
        $attempts += @{ Name = 'output-exfil'; Basis = 'harness'; Marker = $true; Allow = '^text=never$'; Deny = '^text=never$'; Expect = 'contained' }
    }
    return $attempts
}

function Get-FixtureLines([string]$text) {
    $items = @{}
    $valid = $true
    $pattern = '^(?:\[[A-Za-z0-9_.+-]{1,40} [0-9][A-Za-z0-9_.+-]{0,20}\] )?KDATT ([a-z0-9-]{1,40}) ([A-Za-z0-9_=. -]{1,100})$'
    foreach ($line in ($text -split "`n")) {
        $trimmed = $line.Trim()
        if (-not $trimmed.Contains('KDATT ')) { continue }
        $match = [regex]::Match($trimmed, $pattern)
        if (-not $match.Success) {
            $valid = $false
            continue
        }
        $name = $match.Groups[1].Value
        if ($items.ContainsKey($name)) {
            $valid = $false
            continue
        }
        $items[$name] = $match.Groups[2].Value
    }
    return @{ Valid = $valid; Items = $items }
}

function Invoke-FixtureRun($sandbox, [string]$form, [bool]$confined, [string]$mode) {
    $layout = $script:Layout
    $scratch = $script:Control
    if ($confined) { $scratch = $script:Lpac }
    $directory = Join-Path (Join-Path $scratch.Root 'fx') $form
    $environment = New-StageEnvironment $scratch ('target-fx-' + $form)
    $pipeName = 'kd-trusted-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
    $extra = [string[]]@(
        ('KD_PROBE=' + $layout.ProbeExe),
        ('KD_FX_NONCE=' + [Guid]::NewGuid().ToString('N').Substring(0, 12)),
        ('KD_FX_PORT=' + [string]$script:Channel.Scalars['port']),
        ('KD_FX_TEMP=' + [string]$script:Channel.Scalars['runner_temp']),
        ('KD_FX_CANARY=' + [string]$script:CanaryRunnerTemp),
        ('KD_FX_PIPE=' + $pipeName)
    )
    $environment = [string[]]($environment + $extra)
    if (-not $confined) { $environment = [string[]]($environment + $FixtureSentinelEnvironment) }
    $exe = $layout.RustBin + '\cargo.exe'
    $manifest = Join-Path $directory 'Cargo.toml'
    $arguments = ''
    $seconds = $FixtureCargoSeconds
    if ($form -ceq 'build_rs') {
        $arguments = 'build -vv --offline --manifest-path ' + $manifest
    } elseif ($form -ceq 'test') {
        $arguments = 'test --offline --manifest-path ' + $manifest + ' -- --nocapture'
    } elseif ($form -ceq 'binary') {
        $arguments = 'run --offline --manifest-path ' + $manifest
    } elseif ($form -ceq 'node_install') {
        $exe = $layout.NodeDir + '\node.exe'
        $arguments = Join-Path $directory 'install.js'
        $seconds = $FixtureNodeSeconds
        if ($mode.Length -gt 0) {
            $arguments = $arguments + ' ' + $mode
            $seconds = $FixtureSpawnSeconds
        }
        $environment = [string[]]($environment + @('npm_lifecycle_event=postinstall', 'npm_package_name=hostile-fixture', ('INIT_CWD=' + $scratch.Root)))
    } else {
        throw 'fixture_form'
    }
    $pipe = New-TrustedPipe $pipeName
    try {
        return $sandbox.Run($confined, $exe, ('"' + $exe + '" ' + $arguments), $scratch.Root, $environment, ($seconds * 1000), [uint32]32)
    } finally {
        $pipe.Dispose()
    }
}

function Write-FixtureDiag([string]$label, $run) {
    $text = [string]$run.Stdout + "`n" + [string]$run.Stderr
    if ($text.Length -gt 2400) { $text = $text.Substring($text.Length - 2400) }
    $state = 'exit=0x' + ([uint32]$run.ExitCode).ToString('x8') + ' timed_out=' + $run.TimedOut.ToString().ToLowerInvariant() + ' failure=' + (Get-Token ([string]$run.Failure) '^[a-z_]{0,24}$') + ' handles=' + $run.HandleCount
    Write-Line ('kd-diag stage=' + $label + ' stream=state line=' + $state)
    if ($run.Detail) { Write-DiagLines $label 'detail' ([string]$run.Detail) }
    Write-DiagLines $label 'tail' $text
}

function Set-FixtureRefusal($report, [string]$status, [string]$reason) {
    $upgrade = ($status -ceq 'observed-leak') -and ($report.Status -cne 'observed-leak')
    if ($report.Reason -cne 'none' -and -not $upgrade) { return }
    $report.Status = $status
    $report.Reason = $reason
}

function Invoke-FixtureSeparate($sandbox, [string]$form, $attempt, $report) {
    $label = 'fixture_' + $form + '_' + $attempt.Name
    $controlRun = Invoke-FixtureRun $sandbox $form $false $attempt.Name
    $controlLines = Get-FixtureLines ([string]$controlRun.Stdout + "`n" + [string]$controlRun.Stderr)
    $controlText = ''
    if ($controlLines.Items.ContainsKey($attempt.Name)) { $controlText = [string]$controlLines.Items[$attempt.Name] }
    $control = 'not_fired'
    if ((Test-ChannelRunValid $controlRun $false) -and $controlLines.Valid -and ($controlText -cmatch $attempt.Allow)) { $control = 'fired' }
    $run = Invoke-FixtureRun $sandbox $form $true $attempt.Name
    $result = 'other'
    $hang = 'none'
    $lines = Get-FixtureLines ([string]$run.Stdout + "`n" + [string]$run.Stderr)
    $text = ''
    if ($lines.Items.ContainsKey($attempt.Name)) { $text = [string]$lines.Items[$attempt.Name] }
    if ($text -cmatch $attempt.Allow) {
        $result = 'allowed'
    } elseif ($run.TimedOut) {
        $result = 'timeout'
        $hang = 'slow'
        if (([uint64]$run.CpuMs * 10) -ge ([uint64]$run.ElapsedMs * 8)) { $hang = 'busy' }
    }
    Write-Line ('windows-confinement-fixture-attempt=' + $form + '/' + $attempt.Name + ' result=' + $result + ' expect=' + $attempt.Expect + ' control=' + $control + ' hang=' + $hang + ' informational=true basis=boundary')
    $report.Informational += 1
    if ($result -cne 'allowed' -and $result -cne 'timeout') { Write-FixtureDiag $label $run }
    if ($result -ceq 'allowed') { Set-FixtureRefusal $report 'observed-leak' 'fixture_allowed' }
    elseif ($attempt.ContainsKey('RequireHang') -and ($result -cne 'timeout' -or $hang -cne [string]$attempt.RequireHang)) { Set-FixtureRefusal $report 'refused' 'attempt_unexpected' }
}

function Invoke-FixtureForm($sandbox, [string]$form) {
    $report = @{ Status = 'contained'; Reason = 'none'; Attempts = 0; Informational = 0; ControlsFired = 0 }
    $attempts = @(Get-FixtureAttempts $form)
    $main = @($attempts | Where-Object { -not $_.ContainsKey('Separate') })
    $separate = @($attempts | Where-Object { $_.ContainsKey('Separate') })
    $label = 'fixture_' + $form
    $control = Invoke-FixtureRun $sandbox $form $false ''
    $controlLines = Get-FixtureLines ([string]$control.Stdout + "`n" + [string]$control.Stderr)
    $controlFired = (Test-ChannelRunValid $control $false) -and $controlLines.Valid
    if ($controlFired) {
        foreach ($attempt in $main) {
            if ($attempt.ContainsKey('Informational')) { continue }
            $expected = [string]$attempt.Allow
            if ($attempt.ContainsKey('Marker')) { $expected = '^text=ok$' }
            if (-not $controlLines.Items.ContainsKey($attempt.Name)) {
                $controlFired = $false
            } elseif ([string]$controlLines.Items[$attempt.Name] -cnotmatch $expected) {
                $controlFired = $false
            }
        }
    }
    if (-not $controlFired) {
        Write-FixtureDiag ($label + '_control') $control
        Set-FixtureRefusal $report 'refused' 'control_not_fired'
        return $report
    }
    $run = Invoke-FixtureRun $sandbox $form $true ''
    if (-not (Test-ChannelRunValid $run $true)) {
        Write-FixtureDiag $label $run
        Set-FixtureRefusal $report 'refused' 'fixture_incomplete'
        return $report
    }
    $lines = Get-FixtureLines ([string]$run.Stdout + "`n" + [string]$run.Stderr)
    if (-not $lines.Valid) { Set-FixtureRefusal $report 'refused' 'attempt_unexpected' }
    $names = @($main | ForEach-Object { [string]$_.Name })
    foreach ($seen in @($lines.Items.Keys)) {
        if ($names -cnotcontains [string]$seen) { Set-FixtureRefusal $report 'refused' 'attempt_unexpected' }
    }
    foreach ($attempt in $main) {
        $informational = $attempt.ContainsKey('Informational')
        $basis = 'boundary'
        if ($attempt.ContainsKey('Basis')) { $basis = [string]$attempt.Basis }
        $result = 'missing'
        if ($lines.Items.ContainsKey($attempt.Name)) {
            $text = [string]$lines.Items[$attempt.Name]
            if ($attempt.ContainsKey('Marker')) {
                $result = 'other'
                if (($text -ceq 'text=ok') -and (([string]$run.Stdout + "`n" + [string]$run.Stderr) -match '(?m)^(?:\[[A-Za-z0-9_.+-]{1,40} [0-9][A-Za-z0-9_.+-]{0,20}\] )?::debug::kd-fx-marker\s*$')) { $result = 'contained' }
            } else {
                $result = Get-TextClass $text $attempt
                if ($result -ceq 'denied' -and [string]$attempt.Name -ceq 'read-canary' -and -not (Test-NotFoundAttributable $text $script:CanaryRunnerTemp)) { $result = 'other' }
            }
        }
        Write-Line ('windows-confinement-fixture-attempt=' + $form + '/' + $attempt.Name + ' result=' + $result + ' expect=' + $attempt.Expect + ' control=fired hang=none informational=' + $informational.ToString().ToLowerInvariant() + ' basis=' + $basis)
        if ($informational) {
            $report.Informational += 1
            if ($result -cne [string]$attempt.Expect) {
                $diagLine = 'result=' + $result
                if ($lines.Items.ContainsKey($attempt.Name)) { $diagLine = [string]$lines.Items[$attempt.Name] }
                Write-DiagLines ($label + '_' + $attempt.Name) 'observed' $diagLine
            }
            if ($attempt.ContainsKey('LeakGuard') -and $result -ceq 'allowed') { Set-FixtureRefusal $report 'observed-leak' 'fixture_allowed' }
            continue
        }
        $report.Attempts += 1
        $report.ControlsFired += 1
        if ($result -ceq [string]$attempt.Expect) { continue }
        if ($result -ceq 'allowed') { Set-FixtureRefusal $report 'observed-leak' 'fixture_allowed' }
        elseif ($result -ceq 'missing') { Set-FixtureRefusal $report 'refused' 'fixture_incomplete' }
        else { Set-FixtureRefusal $report 'refused' 'attempt_unexpected' }
    }
    if ($report.Status -cne 'contained') { Write-FixtureDiag $label $run }
    foreach ($attempt in $separate) {
        Invoke-FixtureSeparate $sandbox $form $attempt $report
    }
    return $report
}

function Invoke-FixturePhase($sandbox) {
    $reports = [ordered]@{}
    $contained = 0
    $controlled = 0
    foreach ($form in $FixtureForms) {
        $report = Invoke-FixtureForm $sandbox $form
        $reports[$form] = $report
        Write-Line ('windows-confinement-fixture=' + $form + ' status=' + $report.Status + ' reason=' + $report.Reason + ' attempts=' + $report.Attempts + ' informational=' + $report.Informational + ' controls_fired=' + $report.ControlsFired)
        if ($report.Status -ceq 'contained') { $contained += 1 }
        $controlled += $report.ControlsFired
    }
    $state = 'contained'
    foreach ($form in $FixtureForms) {
        if ($reports[$form].Status -ceq 'observed-leak') { $state = 'observed-leak' }
    }
    if ($state -cne 'observed-leak' -and $contained -ne $FixtureForms.Count) { $state = 'refused' }
    Write-Line ('windows-confinement-fixtures=' + $state + ' forms=' + $contained + '/' + $FixtureForms.Count + ' controlled=' + $controlled + ' uncontrolled=0')
    return $state
}

function Get-StageSpecs([bool]$confined, [hashtable]$scratch) {
    $layout = $script:Layout
    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $probe = $layout.ProbeExe
    $cargoManifest = Join-Path $scratch.Crate 'Cargo.toml'
    $specs = @()
    if ($confined) {
        $specs += @{ Name = 'cmd_exec'; Exe = $cmd; Arguments = '/d /c echo kd-lpac-cmd'; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'kd-lpac-cmd' } }
        $specs += @{ Name = 'acl_ro_read'; Exe = $cmd; Arguments = ('/d /c dir /b ' + $layout.RustBin); Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'rustc\.exe' } }
        $specs += @{ Name = 'acl_scratch_write'; Exe = $probe; Arguments = ('write ' + $scratch.Tmp + '\kd_write.txt'); Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match '(?m)^kd-probe write create=ok write=ok\s*$' -and (Test-Path -LiteralPath ($script:Lpac.Tmp + '\kd_write.txt')) } }
        $specs += @{ Name = 'acl_ro_write_denied'; Exe = $probe; Arguments = ('write ' + $layout.ReadOnly + '\kd_write_probe.txt'); Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match '(?m)^kd-probe write create=err5\s*$' -and -not (Test-Path -LiteralPath ($script:Layout.ReadOnly + '\kd_write_probe.txt')) } }
        $specs += @{ Name = 'acl_downloads_denied'; Exe = $cmd; Arguments = ('/d /c type "' + $layout.Downloads + '\acl_probe.txt"'); Timeout = 30; Check = { param($r) $r.ExitCode -ne 0 -and (($r.Stdout + $r.Stderr) -match 'Access is denied') } }
        $specs += @{ Name = 'nul_open'; Exe = $probe; Arguments = 'nul'; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match '(?m)^kd-probe nul read=ok write=ok readwrite=ok device=ok\s*$' } }
        $specs += @{ Name = 'nul_write_dac'; Exe = $probe; Arguments = 'nuldac'; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match '(?m)^kd-probe nuldac result=err5\s*$' } }
        $specs += @{ Name = 'stdin_eof'; Exe = $probe; Arguments = 'stdin'; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.HandleCount -eq 3 -and $r.Stdout -match '(?m)^kd-probe stdin result=eof\s*$' } }
        $specs += @{ Name = 'temp_dir'; Exe = $probe; Arguments = 'tempdir'; Timeout = 30; Quiet = $true; Check = { param($r) $r.ExitCode -eq 0 -and (Test-ContainerTempReport $r.Stdout) } }
        $specs += @{ Name = 'network_tcp_ipv4'; Exe = $probe; Arguments = 'connect 1.1.1.1:443'; Timeout = 60; Check = { param($r) (Get-NetworkState $r.Stdout 'connect') -ceq 'blocked' } }
        $specs += @{ Name = 'network_tcp_ipv6'; Exe = $probe; Arguments = 'connect [2606:4700:4700::1111]:443'; Timeout = 60; Check = { param($r) (Get-NetworkState $r.Stdout 'connect') -cin @('blocked', 'unroutable') } }
        $specs += @{ Name = 'network_tcp_host'; Exe = $probe; Arguments = 'connect github.com:443'; Timeout = 60; Check = { param($r) (Get-NetworkState $r.Stdout 'connect') -cin @('blocked', 'blocked_resolve') } }
        $specs += @{ Name = 'network_dns'; Exe = $probe; Arguments = 'dns github.com'; Timeout = 60; Check = { param($r) (Get-NetworkState $r.Stdout 'dns') -cin @('blocked', 'blocked_resolve') } }
        $specs += @{ Name = 'network_udp'; Exe = $probe; Arguments = 'udp 1.1.1.1:53'; Timeout = 60; Check = { param($r) (Get-NetworkState $r.Stdout 'udp') -cin @('blocked', 'blocked_bind') } }
        $specs += @{ Name = 'canary_runner_temp'; Exe = $probe; Arguments = ('read ' + $script:CanaryRunnerTemp); Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and (Test-CanaryHidden $r.Stdout) } }
        $specs += @{ Name = 'canary_workspace'; Exe = $probe; Arguments = ('read ' + $script:CanaryWorkspace); Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and (Test-CanaryHidden $r.Stdout) } }
        $specs += @{ Name = 'canary_profile'; Exe = $probe; Arguments = ('read ' + $script:CanaryProfile); Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and (Test-CanaryHidden $r.Stdout) } }
        $specs += @{ Name = 'canary_scratch_control'; Exe = $probe; Arguments = ('read ' + $script:CanaryControl); Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and (Get-ProbeValue (Get-ProbeText $r.Stdout 'read') 'open') -ceq 'ok' } }
        $specs += @{ Name = 'spawn_piped'; Exe = $probe; Arguments = 'spawn piped_no_null'; Timeout = 60; Check = { param($r) $r.ExitCode -eq 0 -and (Get-ProbeValue (Get-ProbeText $r.Stdout 'spawn') 'result') -ceq 'ok' } }
        $specs += @{ Name = 'spawn_output'; Exe = $probe; Arguments = 'spawn output'; Timeout = 60; Check = { param($r) $r.ExitCode -eq 0 -and (Get-ProbeValue (Get-ProbeText $r.Stdout 'spawn') 'result') -ceq 'ok' } }
    } else {
        $specs += @{ Name = 'acl_downloads_listable'; Exe = $cmd; Arguments = ('/d /c dir /b ' + $layout.Downloads); Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'rustc\.tar\.gz' } }
        $specs += @{ Name = 'network_control'; Exe = $probe; Arguments = 'connect 1.1.1.1:443'; Timeout = 40; Check = { param($r) (Get-NetworkState $r.Stdout 'connect') -ceq 'open' } }
        $specs += @{ Name = 'network_control_ipv6'; Exe = $probe; Arguments = 'connect [2606:4700:4700::1111]:443'; Timeout = 40; Check = { param($r) (Get-NetworkState $r.Stdout 'connect') -cin @('open', 'unroutable') } }
        $specs += @{ Name = 'network_control_dns'; Exe = $probe; Arguments = 'dns github.com'; Timeout = 30; Check = { param($r) (Get-NetworkState $r.Stdout 'dns') -ceq 'open' } }
        $specs += @{ Name = 'network_control_udp'; Exe = $probe; Arguments = 'udp 1.1.1.1:53'; Timeout = 30; Check = { param($r) (Get-NetworkState $r.Stdout 'udp') -ceq 'open' } }
    }
    $specs += @{ Name = 'rustc_version'; Exe = ($layout.RustBin + '\rustc.exe'); Arguments = '--version --verbose'; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match '(?m)^rustc 1\.99\.1 ' -and $r.Stdout -match '(?m)^host: x86_64-pc-windows-msvc' } }
    $specs += @{ Name = 'cargo_version'; Exe = ($layout.RustBin + '\cargo.exe'); Arguments = '--version'; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match '(?m)^cargo (0\.100\.0|1\.99\.[01]) ' } }
    $specs += @{ Name = 'link_banner'; Exe = ($layout.MsvcBin + '\link.exe'); Arguments = '/?'; Timeout = 30; Check = { param($r) $r.Stdout -match 'Incremental Linker' } }
    $specs += @{ Name = 'rust_build'; Exe = ($layout.RustBin + '\cargo.exe'); Arguments = ('build --offline --manifest-path ' + $cargoManifest); Timeout = 240; Check = { param($r) $r.ExitCode -eq 0 } }
    $specs += @{ Name = 'rust_test'; Exe = ($layout.RustBin + '\cargo.exe'); Arguments = ('test --offline --manifest-path ' + $cargoManifest); Timeout = 240; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'test result: ok\. 1 passed; 0 failed' } }
    $specs += @{ Name = 'node_version'; Exe = ($layout.NodeDir + '\node.exe'); Arguments = '--version'; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout.Trim() -eq 'v24.22.1' } }
    $specs += @{ Name = 'node_bindings'; Exe = ($layout.NodeDir + '\node.exe'); Arguments = $layout.NodeTest; Timeout = 60; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'kd-node-summary passed=4 failed=0' } }
    $specs += @{ Name = 'node_child'; Exe = ($layout.NodeDir + '\node.exe'); Arguments = $layout.NodeChild; Timeout = 60; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'kd-node-child spawn=ok worker=ok' } }
    return $specs
}

function Invoke-Ladder($sandbox, [bool]$confined, [hashtable]$scratch, [string[]]$only = @(), [string]$suffix = '') {
    $outcomes = [ordered]@{}
    $targetName = 'target-control'
    if ($confined) { $targetName = 'target-lpac' }
    $environment = New-StageEnvironment $scratch $targetName
    foreach ($spec in (Get-StageSpecs $confined $scratch)) {
        if ($only.Count -gt 0 -and ($only -cnotcontains $spec.Name)) { continue }
        $commandLine = '"' + $spec.Exe + '" ' + $spec.Arguments
        $result = $sandbox.Run($confined, $spec.Exe, $commandLine, $scratch.Root, $environment, ([int]$spec.Timeout * 1000), [uint32]32)
        $ran = ($result.Failure -eq '' -and $result.Exited -and -not $result.TimedOut)
        $passed = $false
        if ($ran) {
            $passed = [bool](& $spec.Check $result)
        }
        $quiet = $spec.ContainsKey('Quiet')
        $exitText = '0x' + ([uint32]$result.ExitCode).ToString('x8')
        $jobText = Get-Token ($result.Job -replace ' ', ',') '^[A-Za-z0-9=,_.-]{1,120}$'
        $tokenText = Get-Token ($result.Token -replace ' ', ',') '^[A-Za-z0-9=,_.-]{1,160}$'
        $failureText = Get-Token $result.Failure '^[a-z_]{0,24}$'
        $class46Text = Get-Token ([string]$result.Class46) '^[a-z0-9]{1,16}$'
        $hang = 'none'
        if ($result.TimedOut) {
            $hang = 'slow'
            if (([uint64]$result.CpuMs * 10) -ge ([uint64]$result.ElapsedMs * 8)) { $hang = 'busy' }
        }
        $verdict = 'failed'
        if ($passed) { $verdict = 'ok' }
        Write-Line ('windows-confinement-stage=' + $spec.Name + $suffix + ' confined=' + $confined.ToString().ToLowerInvariant() + ' result=' + $verdict + ' exit=' + $exitText + ' status=' + (Get-StatusName ([uint32]$result.ExitCode)) + ' ms=' + $result.ElapsedMs + ' timed_out=' + $result.TimedOut.ToString().ToLowerInvariant() + ' hang=' + $hang + ' failure=' + $failureText + ' create_error=' + $result.CreateError + ' job=' + $jobText + ' token=' + $tokenText + ' handles=' + $result.HandleCount + ' handles_method=list_attr_readback cpu_ms=' + $result.CpuMs + ' peak_process_mib=' + (Get-Mib $result.PeakProcessMemory) + ' peak_job_mib=' + (Get-Mib $result.PeakJobMemory) + ' class46=' + $class46Text)
        if (-not $passed) {
            if ($result.Detail) { Write-DiagLines $spec.Name 'detail' $result.Detail }
            if (-not $quiet) {
                Write-DiagLines $spec.Name 'stdout' $result.Stdout
                Write-DiagLines $spec.Name 'stderr' $result.Stderr
            }
        } elseif (-not $quiet) {
            $firstLine = ($result.Stdout -split "`n" | Where-Object { $_.Trim().Length -gt 0 } | Select-Object -First 1)
            if ($firstLine) { Write-Line ('kd-diag stage=' + $spec.Name + ' stream=first line=' + (Get-CleanText $firstLine.Trim() 160)) }
        }
        $lpacProven = ($tokenText -like 'appcontainer=1,*') -and ($tokenText -like '*,capabilities=1,*') -and ($tokenText -like '*,integrity=0x1000,*') -and ($tokenText -like '*,lpac=attr,*') -and ($tokenText -like '*,cap=registryRead,*') -and ($tokenText -like '*,sid=match,*') -and ($tokenText -like '*,aap=absent')
        $outcomes[$spec.Name] = @{ Passed = $passed; Job = ($jobText -like 'assigned,*'); Token = $lpacProven; Handles = ([uint32]$result.HandleCount -eq 3); Stdout = [string]$result.Stdout; Ran = $ran }
    }
    return $outcomes
}


try {
    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) { throw 'platform' }
    $phase = 'runtime'
    [void](Add-Type -Path (Join-Path $PSScriptRoot 'windows_confinement.cs') -ErrorAction Stop)
    if ($Mode -eq 'compile') {
        Write-Line 'windows-confinement-compile=observed result=compiled'
        $exitCode = 0
    } else {
        $phase = 'control_identity'
        if ($env:CI_EVENT_NAME -ne 'workflow_dispatch' -or $env:CI_REF -ne 'refs/heads/main') { throw 'control' }
        if ($env:CI_REPOSITORY -ne 'keeldock-platform/platform-ci' -or $env:CI_SERVER_URL -ne 'https://github.com') { throw 'control' }
        if ($env:CI_SHA -notmatch '^[a-f0-9]{40}$') { throw 'control' }
        $root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
        $workspace = [IO.Path]::GetFullPath($env:CI_WORKSPACE)
        if (-not [string]::Equals($root, $workspace, [StringComparison]::OrdinalIgnoreCase)) { throw 'control' }
        $actualSha = git -C $root rev-parse --verify HEAD 2>$null
        if ($LASTEXITCODE -ne 0 -or $actualSha.Trim() -ne $env:CI_SHA) { throw 'control' }

        $phase = 'image_record'
        $imageOs = Get-Token $env:ImageOS '^[A-Za-z0-9._-]{1,32}$'
        $imageVersion = Get-Token $env:ImageVersion '^[A-Za-z0-9._-]{1,32}$'
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        $vsPath = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
        $vsVersion = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationVersion | Select-Object -First 1)
        if (-not $vsPath -or -not (Test-Path -LiteralPath $vsPath)) { throw 'msvc_missing' }
        $msvcVersion = (Get-Content -LiteralPath (Join-Path $vsPath 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt') | Select-Object -First 1).Trim()
        $msvcRoot = Join-Path $vsPath ('VC\Tools\MSVC\' + $msvcVersion)
        $sdkLibRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Lib'
        $sdkVersion = (Get-ChildItem -LiteralPath $sdkLibRoot -Directory | Where-Object { $_.Name -match '^10\.0\.[0-9]+\.[0-9]+$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'ucrt\x64\ucrt.lib')) -and (Test-Path -LiteralPath (Join-Path $_.FullName 'um\x64\kernel32.lib')) } | Sort-Object { [Version]$_.Name } -Descending | Select-Object -First 1).Name
        if (-not $sdkVersion) { throw 'sdk_missing' }
        $msvcBinSource = Join-Path $msvcRoot 'bin\Hostx64\x64'
        $msvcLibSource = Join-Path $msvcRoot 'lib\x64'
        $sdkUcrtSource = Join-Path $sdkLibRoot ($sdkVersion + '\ucrt\x64')
        $sdkUmSource = Join-Path $sdkLibRoot ($sdkVersion + '\um\x64')
        foreach ($source in @($msvcBinSource, $msvcLibSource, $sdkUcrtSource, $sdkUmSource)) {
            if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw 'msvc_layout' }
        }
        if (-not (Test-Path -LiteralPath (Join-Path $msvcBinSource 'link.exe'))) { throw 'msvc_layout' }
        Write-Line ('windows-confinement-image=recorded image_os=' + $imageOs + ' image_version=' + $imageVersion + ' vs_version=' + (Get-Token ([string]$vsVersion) '^[0-9.]{1,32}$') + ' msvc_version=' + (Get-Token $msvcVersion '^[0-9.]{1,32}$') + ' sdk_version=' + (Get-Token $sdkVersion '^[0-9.]{1,32}$') + ' os_build=' + (Get-Token ([Environment]::OSVersion.Version.ToString()) '^[0-9.]{1,32}$') + ' powershell=' + (Get-Token $PSVersionTable.PSVersion.ToString() '^[0-9A-Za-z.-]{1,32}$'))

        $phase = 'workspace_prepare'
        $baseDirectory = Join-Path $env:RUNNER_TEMP ('kd-confinement-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        if ($baseDirectory -notmatch '^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$') { throw 'workspace_path' }
        $script:Redactions = @($baseDirectory, $env:RUNNER_TEMP, $env:CI_WORKSPACE)
        Register-RemovalRoot $baseDirectory
        $script:Layout = @{
            Base = $baseDirectory
            Downloads = (Join-Path $baseDirectory 'dl')
            ReadOnly = (Join-Path $baseDirectory 'ro')
        }
        $script:Lpac = New-ScratchSet (Join-Path $baseDirectory 'scratch')
        $script:Control = New-ScratchSet (Join-Path $baseDirectory 'control')
        $layout = $script:Layout
        $layout.RustPrefix = Join-Path $layout.ReadOnly 'rust'
        $layout.RustBin = Join-Path $layout.RustPrefix 'bin'
        $layout.NodeDir = Join-Path $layout.ReadOnly 'node'
        $layout.MsvcBin = Join-Path $layout.ReadOnly 'msvc\bin'
        $layout.MsvcLib = Join-Path $layout.ReadOnly 'msvc\lib'
        $layout.SdkUcrt = Join-Path $layout.ReadOnly 'sdk\ucrt'
        $layout.SdkUm = Join-Path $layout.ReadOnly 'sdk\um'
        $layout.ProbeDir = Join-Path $layout.ReadOnly 'probe'
        $layout.ProbeExe = Join-Path $layout.ProbeDir 'kd_probe.exe'
        $layout.NpmDir = Join-Path $layout.ReadOnly 'npm'
        $layout.TestDir = Join-Path $layout.ReadOnly 'tests'
        $layout.NodeTest = Join-Path $layout.TestDir 'kd_bindings.test.mjs'
        $layout.NodeChild = Join-Path $layout.TestDir 'kd_child.js'
        $layout.LightningcssBinding = Join-Path $layout.NpmDir 'lightningcss.node'
        $layout.RolldownBinding = Join-Path $layout.NpmDir 'rolldown.node'
        foreach ($directory in @($layout.Base, $layout.Downloads, $layout.ReadOnly, $script:Lpac.Root, $script:Control.Root)) {
            New-Item -ItemType Directory -Path $directory | Out-Null
        }
        New-Item -ItemType File -Path (Join-Path $layout.Downloads 'acl_probe.txt') | Out-Null

        $phase = 'lpac_profile'
        $box = [KeelDock.Platform.WindowsConfinement.Sandbox]::Create()
        $script:Sid = $box.SidText
        $script:ProfileFolder = Join-Path (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) 'Packages') $box.ProfileName
        Register-RemovalRoot $script:ProfileFolder

        $phase = 'acl_grant'
        Grant-Access $layout.ReadOnly $script:Sid 'ReadAndExecute, Synchronize' $true
        Grant-Access $script:Lpac.Root $script:Sid 'Modify, Synchronize' $true
        Set-LowIntegrityLabel $script:Lpac.Root
        $phase = 'acl_ancestors'
        $script:AncestorPaths = @()
        $ancestorPath = $layout.Base
        while ($ancestorPath) {
            $script:AncestorPaths += $ancestorPath
            $ancestorPath = Split-Path -Parent $ancestorPath
        }
        foreach ($ancestorPath in $script:AncestorPaths) {
            Grant-NonPropagating $ancestorPath $script:Sid
        }
        $ancestorCount = $script:AncestorPaths.Count
        $ancestorFailures = 0
        $phase = 'acl_grant'
        foreach ($set in @($script:Lpac, $script:Control)) {
            foreach ($directory in @($set.Tmp, $set.Profile, $set.CargoHome, $set.Crate, (Join-Path $set.Crate 'src'))) {
                New-Item -ItemType Directory -Force -Path $directory | Out-Null
            }
        }
        foreach ($directory in @($layout.RustPrefix, $layout.NodeDir, $layout.ProbeDir, $layout.NpmDir, $layout.TestDir)) {
            New-Item -ItemType Directory -Force -Path $directory | Out-Null
        }
        Write-Line ('windows-confinement-acl=granted ro=read_execute scratch=modify ancestors_read_attributes=' + $ancestorCount + ' ancestors_failed=' + $ancestorFailures)

        $phase = 'fetch'
        foreach ($item in ($Downloads + @($NodeDownload))) {
            $path = Invoke-Download $item
            Assert-Sha256 $path $item.Sha256 $item.Name
        }
        foreach ($item in $NpmDownloads) {
            $path = Invoke-Download $item
            Assert-Sri $path $item.Sri $item.Name
        }
        Write-Line 'windows-confinement-fetch=verified rust_components=3 node=1 npm_bindings=2'

        $phase = 'stage_rust'
        foreach ($item in $Downloads) {
            $extract = Join-Path $layout.Downloads ('x-' + $item.Name)
            Invoke-Tar (Join-Path $layout.Downloads $item.File) $extract
            $componentRoot = Join-Path $extract $item.Root
            $expectedComponent = $ExpectedRustComponents[$item.Name]
            foreach ($component in (Get-Content -LiteralPath (Join-Path $componentRoot 'components'))) {
                $name = $component.Trim()
                if ($name.Length -eq 0) { continue }
                if (-not [string]::Equals($name, $expectedComponent, [StringComparison]::Ordinal)) {
                    $componentNameExpected = $expectedComponent
                    $componentNameObserved = $name
                    throw 'component_name'
                }
                $componentSource = Join-Path $componentRoot $name
                if (-not (Test-Path -LiteralPath $componentSource -PathType Container)) { throw 'component_missing' }
                Copy-Item -Path (Join-Path $componentSource '*') -Destination $layout.RustPrefix -Recurse -Force
            }
        }
        foreach ($required in @((Join-Path $layout.RustBin 'rustc.exe'), (Join-Path $layout.RustBin 'cargo.exe'), (Join-Path $layout.RustPrefix ('lib\rustlib\' + $RustTarget + '\lib')))) {
            if (-not (Test-Path -LiteralPath $required)) { throw 'rust_layout' }
        }

        $phase = 'stage_node'
        $nodeExtract = Join-Path $layout.Downloads 'x-node'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $layout.Downloads $NodeDownload.File), $nodeExtract)
        Copy-Item -LiteralPath (Join-Path $nodeExtract ('node-v' + $NodeVersion + '-win-x64\node.exe')) -Destination (Join-Path $layout.NodeDir 'node.exe')

        $phase = 'stage_npm'
        foreach ($item in $NpmDownloads) {
            $extract = Join-Path $layout.Downloads ('x-' + $item.Name)
            Invoke-Tar (Join-Path $layout.Downloads $item.File) $extract
            $binaries = @(Get-ChildItem -LiteralPath $extract -Recurse -File -Filter '*.node')
            if ($binaries.Count -ne 1) { throw 'npm_binding_missing' }
            Copy-Item -LiteralPath $binaries[0].FullName -Destination (Join-Path $layout.NpmDir ($item.Name + '.node'))
        }

        $phase = 'stage_msvc'
        Copy-Tree $msvcBinSource $layout.MsvcBin
        Copy-Tree $msvcLibSource $layout.MsvcLib
        Copy-Tree $sdkUcrtSource $layout.SdkUcrt
        Copy-Tree $sdkUmSource $layout.SdkUm

        $phase = 'stage_sources'
        $hash = [string][char]35
        $encoding = New-Object System.Text.UTF8Encoding($false)
        foreach ($set in @($script:Lpac, $script:Control)) {
            [IO.File]::WriteAllText((Join-Path $set.Crate 'Cargo.toml'), $CargoManifestText, $encoding)
            [IO.File]::WriteAllText((Join-Path $set.Crate 'src\lib.rs'), $RustSourceText.Replace('KDHASH', $hash).Replace("`r`n", "`n"), $encoding)
        }
        [IO.File]::WriteAllText($layout.NodeTest, $NodeTestText.Replace("`r`n", "`n"), $encoding)
        [IO.File]::WriteAllText($layout.NodeChild, $NodeChildText.Replace("`r`n", "`n"), $encoding)
        Initialize-FixtureSources

        $phase = 'canaries'
        $canarySuffix = [Guid]::NewGuid().ToString('N').Substring(0, 8)
        $canaryDirectory = Join-Path $env:RUNNER_TEMP ('kd-canary-' + $canarySuffix)
        $script:CanaryRunnerTemp = Join-Path $canaryDirectory 'canary.txt'
        $script:CanaryWorkspace = Join-Path $env:CI_WORKSPACE ('kd-canary-' + $canarySuffix + '.txt')
        $script:CanaryProfile = Join-Path $env:USERPROFILE ('kd-canary-' + $canarySuffix + '.txt')
        $script:CanaryControl = Join-Path $script:Lpac.Tmp 'kd_canary_control.txt'
        $script:Canaries += $canaryDirectory
        $script:Canaries += $script:CanaryWorkspace
        $script:Canaries += $script:CanaryProfile
        foreach ($rootItem in $script:Canaries) { Register-RemovalRoot $rootItem }
        $canaryFiles = @($script:CanaryRunnerTemp, $script:CanaryWorkspace, $script:CanaryProfile, $script:CanaryControl)
        foreach ($canaryFile in $canaryFiles) {
            if ($canaryFile -notmatch '^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$') { throw 'canary_path' }
        }
        New-Item -ItemType Directory -Path $canaryDirectory | Out-Null
        $script:CanaryNeedle = [Guid]::NewGuid().ToString('N')
        $script:CanaryScratchNeedle = [Guid]::NewGuid().ToString('N')
        foreach ($canaryFile in $canaryFiles) {
            $canaryValue = $script:CanaryNeedle
            if ($canaryFile -ceq $script:CanaryControl) { $canaryValue = $script:CanaryScratchNeedle }
            [IO.File]::WriteAllText($canaryFile, $canaryValue, $encoding)
        }

        $phase = 'channel_fixtures'
        Initialize-ChannelContext

        $phase = 'build_probe'
        $probeBuilt = Join-Path $script:Control.Root 'kd_probe_build.exe'
        $probeSource = Join-Path $PSScriptRoot 'windows_probe.rs'
        $probeRustc = Join-Path $layout.RustBin 'rustc.exe'
        $probeArguments = '--edition 2021 -C opt-level=1 -C debuginfo=0 -C link-arg=/DEBUG:NONE -C linker=' + $layout.MsvcBin + '\link.exe -l kernel32 -l ws2_32 -l advapi32 -l userenv -l ole32 -l oleaut32 -o ' + $probeBuilt + ' ' + $probeSource
        $probeEnvironment = New-StageEnvironment $script:Control 'target-probe-build'
        $probeBuild = $box.Run($false, $probeRustc, ('"' + $probeRustc + '" ' + $probeArguments), $script:Control.Root, $probeEnvironment, 240000, [uint32]32)
        if ($probeBuild.Failure -ne '' -or -not $probeBuild.Exited -or $probeBuild.TimedOut -or $probeBuild.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $probeBuilt)) {
            Write-DiagLines 'probe_build' 'stdout' $probeBuild.Stdout
            Write-DiagLines 'probe_build' 'stderr' $probeBuild.Stderr
            throw 'probe_build'
        }
        Copy-Item -LiteralPath $probeBuilt -Destination $layout.ProbeExe
        Write-Line ('windows-confinement-probe=built ms=' + $probeBuild.ElapsedMs)

        $phase = 'acl_readback'
        $aclState = Test-Acl
        Write-Line ('windows-confinement-acl=' + $aclState)
        if ($aclState -ne 'verified') { throw 'acl_readback' }

        $phase = 'ladder'
        $controlOutcomes = Invoke-Ladder $box $false $script:Control

        $phase = 'null_lease'
        $script:NullLease = [KeelDock.Platform.WindowsConfinement.NullDeviceLease]::Open($script:Sid)
        $nullState = [string]$script:NullLease.Apply()
        $nullReadback = 'mismatch'
        if ($nullState -eq 'applied') { $nullReadback = [string]$script:NullLease.Readback() }
        Write-Line ('windows-confinement-null=' + $nullState + ' mask=0x0012019f trustee=package readback=' + $nullReadback)
        if ($nullState -ne 'applied' -or $nullReadback -ne 'match') { throw 'null_lease' }

        $phase = 'container_temp'
        Initialize-ContainerTemp $box

        $phase = 'nul_other_container'
        Test-OtherContainerNul $box

        $phase = 'channels_before'
        $channelsBefore = Invoke-ChannelPhase $box 'selftest' $true

        $phase = 'fixtures'
        $fixtureState = Invoke-FixturePhase $box

        $phase = 'ladder'
        $confinedOutcomes = Invoke-Ladder $box $true $script:Lpac

        $phase = 'channels_after'
        $channelsAfter = Invoke-ChannelPhase $box 'recheck' $false

        $phase = 'ladder'
        $dnsAfterOutcomes = Invoke-Ladder $box $false $script:Control @('network_control_dns') '_after'

        $phase = 'cleanup_links'
        Initialize-LinkFixtures

        $firstFailure = 'none'
        foreach ($key in $confinedOutcomes.Keys) {
            if (-not $confinedOutcomes[$key].Passed) { $firstFailure = $key; break }
        }
        $allProven = $true
        $allJobs = $true
        $allHandles = $true
        foreach ($key in $confinedOutcomes.Keys) {
            if (-not $confinedOutcomes[$key].Token) { $allProven = $false }
            if (-not $confinedOutcomes[$key].Job) { $allJobs = $false }
            if (-not $confinedOutcomes[$key].Handles) { $allHandles = $false }
        }
        $observed = [ordered]@{}
        $observed['rust'] = 'failed'
        if (Test-Passed $confinedOutcomes @('rust_build', 'rust_test')) { $observed['rust'] = 'compiled' }
        $observed['node'] = 'failed'
        if (Test-Passed $confinedOutcomes @('node_version', 'node_bindings')) { $observed['node'] = 'ran' }
        $observed['node_child'] = 'failed'
        if (Test-Passed $confinedOutcomes @('node_child')) { $observed['node_child'] = 'ran' }
        $observed['first_failure'] = $firstFailure
        $observed['lpac'] = 'unverified'
        $observed['lpac_basis'] = 'none'
        $observed['capabilities'] = 'unverified'
        if ($allProven) {
            $observed['lpac'] = 'verified'
            $observed['lpac_basis'] = 'attr'
            $observed['capabilities'] = 'registryRead'
        }
        $observed['job'] = 'unverified'
        if ($allJobs) { $observed['job'] = 'verified' }
        $observed['acl'] = $aclState
        $observed['scratch_write'] = 'failed'
        if (Test-Passed $confinedOutcomes @('acl_scratch_write')) { $observed['scratch_write'] = 'ok' }
        $observed['ro_write'] = 'failed'
        if (Test-Passed $confinedOutcomes @('acl_ro_write_denied')) { $observed['ro_write'] = 'denied' }
        $observed['downloads'] = 'failed'
        if ((Test-Passed $confinedOutcomes @('acl_downloads_denied')) -and (Test-Passed $controlOutcomes @('acl_downloads_listable'))) { $observed['downloads'] = 'denied' }
        $observed['nul_open'] = 'failed'
        if (Test-Passed $confinedOutcomes @('nul_open')) { $observed['nul_open'] = 'ok' }
        $observed['nul_write_dac'] = 'failed'
        if (Test-Passed $confinedOutcomes @('nul_write_dac')) { $observed['nul_write_dac'] = 'denied' }
        $observed['stdin'] = 'failed'
        if ((Test-Passed $confinedOutcomes @('stdin_eof')) -and $allHandles) { $observed['stdin'] = 'eof_pipe' }
        $observed['temp_dir'] = 'failed'
        if (Test-Passed $confinedOutcomes @('temp_dir')) { $observed['temp_dir'] = 'verified' }
        $observed['spawn_piped'] = 'failed'
        if (Test-Passed $confinedOutcomes @('spawn_piped', 'spawn_output')) { $observed['spawn_piped'] = 'ok' }
        $observed['network'] = 'failed'
        $ipv6Control = 'failed'
        if ((Test-Passed $controlOutcomes @('network_control_ipv6'))) { $ipv6Control = Get-NetworkState $controlOutcomes['network_control_ipv6'].Stdout 'connect' }
        $ipv6Confined = 'failed'
        if ((Test-Passed $confinedOutcomes @('network_tcp_ipv6'))) { $ipv6Confined = Get-NetworkState $confinedOutcomes['network_tcp_ipv6'].Stdout 'connect' }
        $observed['ipv6'] = 'failed'
        $observed['ipv6_control'] = 'failed'
        if ($ipv6Control -ceq 'open') { $observed['ipv6_control'] = 'open' }
        if ($ipv6Control -ceq 'unroutable') { $observed['ipv6_control'] = 'unroutable' }
        if (($ipv6Control -ceq 'open') -and ($ipv6Confined -ceq 'blocked')) { $observed['ipv6'] = 'blocked' }
        if (($ipv6Control -ceq 'unroutable') -and ($ipv6Confined -cin @('blocked', 'unroutable'))) { $observed['ipv6'] = 'not_applicable' }
        $networkDenied = (Test-Passed $confinedOutcomes @('network_tcp_ipv4', 'network_tcp_ipv6', 'network_tcp_host', 'network_dns', 'network_udp')) -and -not (($ipv6Control -ceq 'open') -and ($ipv6Confined -ceq 'unroutable'))
        $networkControls = Test-Passed $controlOutcomes @('network_control', 'network_control_ipv6', 'network_control_dns', 'network_control_udp')
        $dnsAfter = 'failed'
        if (Test-Passed $dnsAfterOutcomes @('network_control_dns')) { $dnsAfter = 'open' }
        if ($dnsAfter -cne 'open') { $networkControls = $false }
        if ($networkDenied -and $networkControls) { $observed['network'] = 'blocked' }
        if ($networkDenied -and -not $networkControls) { $observed['network'] = 'inconclusive' }
        $observed['canary'] = 'failed'
        if (Test-Passed $confinedOutcomes @('canary_runner_temp', 'canary_workspace', 'canary_profile', 'canary_scratch_control')) { $observed['canary'] = 'absent' }
        $observed['control_rust'] = 'failed'
        if (Test-Passed $controlOutcomes @('rust_build', 'rust_test')) { $observed['control_rust'] = 'compiled' }
        $observed['control_node'] = 'failed'
        if (Test-Passed $controlOutcomes @('node_version', 'node_bindings')) { $observed['control_node'] = 'ran' }
        $observed['css_transform'] = 'failed'
        if ($confinedOutcomes['node_bindings'].Stdout -match 'name=minifies_a_stylesheet result=pass') { $observed['css_transform'] = 'ok' }
        $observed['channels_before'] = 'failed'
        if ((Get-ChannelBlockedCount $channelsBefore) -eq $ChannelNames.Count) { $observed['channels_before'] = 'blocked' }
        $observed['channels_after'] = 'failed'
        if ((Get-ChannelBlockedCount $channelsAfter) -eq $ChannelNames.Count) { $observed['channels_after'] = 'blocked' }
        $observed['channel_controls'] = Get-ChannelControlState $channelsBefore
        $observed['dns_after'] = $dnsAfter
        $observed['fixtures'] = $fixtureState
        $expectedTokens = [ordered]@{ rust = 'compiled'; node = 'ran'; node_child = 'ran'; first_failure = 'none'; lpac = 'verified'; lpac_basis = 'attr'; capabilities = 'registryRead'; job = 'verified'; acl = 'verified'; scratch_write = 'ok'; ro_write = 'denied'; downloads = 'denied'; nul_open = 'ok'; nul_write_dac = 'denied'; stdin = 'eof_pipe'; temp_dir = 'verified'; spawn_piped = 'ok'; network = 'blocked'; ipv6 = 'blocked'; ipv6_control = 'open'; canary = 'absent'; control_rust = 'compiled'; control_node = 'ran'; css_transform = 'ok'; channels_before = 'blocked'; channels_after = 'blocked'; channel_controls = 'fired'; dns_after = 'open'; fixtures = 'contained' }
        if ($observed['ipv6'] -ceq 'not_applicable') { $expectedTokens['ipv6'] = 'not_applicable'; $expectedTokens['ipv6_control'] = 'unroutable' }
        $summary = 'windows-confinement-spike=observed'
        $allExpected = $true
        foreach ($key in $expectedTokens.Keys) {
            $summary += ' ' + $key + '=' + $observed[$key]
            if ($observed[$key] -cne $expectedTokens[$key]) { $allExpected = $false }
        }
        Write-Line ($summary + ' rolldown=load_only vitest=not_run rolldown_call=not_run')
        if ($allExpected) { $exitCode = 0 }
    }
} catch {
    $reason = [string]$_.Exception.Message
    $reason = Get-CleanText $reason 120
    $reason = [regex]::Replace($reason, '[^A-Za-z0-9._ -]', '_').Trim().Replace(' ', '_')
    if ($reason.Length -eq 0) { $reason = 'unspecified' }
    $safePhase = [regex]::Replace([string]$phase, '[^A-Za-z0-9_]', '_')
    $componentDiagnostic = ''
    if ($null -ne $componentNameExpected) {
        $componentDiagnostic = ' expected_component=' + (Get-SafeComponentName $componentNameExpected) + ' observed_component=' + (Get-SafeComponentName $componentNameObserved)
    }
    $refusal = 'windows-confinement-spike=refused phase=' + $safePhase + ' reason=' + $reason + $componentDiagnostic
}

$nullRestore = 'not_applied'
try {
    if ($script:NullLease -ne $null) { $nullRestore = [string]$script:NullLease.Restore() }
} catch {
    $nullRestore = 'failed'
}
if ($nullRestore -eq 'failed') { $cleanup = 'incomplete' }

$processState = 'none'
try {
    $processState = Get-JobLiveness @($box, $script:OtherBox) 10
} catch {
    $processState = 'unknown'
}
if ($processState -ne 'none') { $cleanup = 'incomplete' }

try {
    Remove-Canaries
} catch {
    $cleanup = 'incomplete'
    Write-CleanupDetail 'canaries' $_
}

try {
    Remove-ChannelFixtures
} catch {
    $cleanup = 'incomplete'
}

try {
    if ($processState -eq 'none' -and $script:ProfileFolder -and (Test-Path -LiteralPath $script:ProfileFolder)) { Remove-ReparsePoints $script:ProfileFolder }
    if ($processState -eq 'none' -and $script:OtherFolder -and (Test-Path -LiteralPath $script:OtherFolder)) { Remove-ReparsePoints $script:OtherFolder }
} catch {
    $cleanup = 'incomplete'
    Write-CleanupDetail 'links' $_
}

$profileState = 'not_created'
try {
    if ($box -ne $null) {
        $box.Dispose()
        if (-not $box.CleanupComplete) { $cleanup = 'incomplete' }
        $profileState = 'deleted_by_api'
        if ($processState -eq 'none' -and $script:ProfileFolder -and (Test-Path -LiteralPath $script:ProfileFolder)) {
            Remove-TreeNoFollow $script:ProfileFolder
            $profileState = 'removed_manually'
        }
        if ($script:ProfileFolder -and (Test-Path -LiteralPath $script:ProfileFolder)) { $profileState = 'failed' }
    }
} catch {
    $profileState = 'failed'
    Write-CleanupDetail 'profile' $_
}
if ($profileState -eq 'failed') { $cleanup = 'incomplete' }

try {
    if ($script:OtherBox -ne $null) {
        $script:OtherBox.Dispose()
        if (-not $script:OtherBox.CleanupComplete) { $cleanup = 'incomplete' }
        if ($processState -eq 'none' -and $script:OtherFolder -and (Test-Path -LiteralPath $script:OtherFolder)) {
            Remove-TreeNoFollow $script:OtherFolder
        }
        if ($script:OtherFolder -and (Test-Path -LiteralPath $script:OtherFolder)) { $cleanup = 'incomplete' }
    }
} catch {
    $cleanup = 'incomplete'
    Write-CleanupDetail 'other' $_
}

$tempState = 'removed'
try {
    if ($processState -eq 'none' -and $baseDirectory -and (Test-Path -LiteralPath $baseDirectory)) {
        Remove-TreeNoFollow $baseDirectory
    }
    if ($baseDirectory -and (Test-Path -LiteralPath $baseDirectory)) { $tempState = 'failed' }
    if ($script:ExpectedTemp -and (Test-Path -LiteralPath $script:ExpectedTemp)) { $tempState = 'failed' }
} catch {
    $tempState = 'failed'
    Write-CleanupDetail 'base' $_
}
if ($tempState -eq 'failed') { $cleanup = 'incomplete' }

$linksState = 'not_planted'
try {
    if ($script:TrapDirectory) {
        $linksState = 'verified'
        if ($script:PlantedJunctions -lt 3) { $linksState = 'incomplete' }
        if (-not (Test-Path -LiteralPath $script:TrapSentinel -PathType Leaf)) { $linksState = 'followed' }
        elseif ([IO.File]::ReadAllText($script:TrapSentinel) -cne 'kd-sentinel') { $linksState = 'followed' }
        Remove-TreeNoFollow $script:TrapDirectory
        if (Test-Path -LiteralPath $script:TrapDirectory) { $linksState = 'failed' }
    }
} catch {
    $linksState = 'failed'
    Write-CleanupDetail 'trap' $_
}
if (@('verified', 'not_planted') -cnotcontains $linksState) { $cleanup = 'incomplete' }

if ($refusal) {
    Write-Line ($refusal + ' cleanup=' + $cleanup + ' null_restore=' + $nullRestore)
    exit 1
}
if ($Mode -eq 'spike') {
    $profileText = 'deleted'
    if (@('deleted_by_api', 'removed_manually') -cnotcontains $profileState) { $profileText = $profileState }
    Write-Line ('windows-confinement-profile-folder=' + $profileState)
    Write-Line ('windows-confinement-cleanup=' + $cleanup + ' null_restore=' + $nullRestore + ' profile=' + $profileText + ' temp_dir=' + $tempState + ' links=' + $linksState + ' symlinks=' + $script:PlantedSymlinks + ' processes=' + $processState + ' liveness=job')
    if ($cleanup -ne 'verified' -or $nullRestore -ne 'verified' -or $profileText -ne 'deleted' -or $tempState -ne 'removed' -or $linksState -ne 'verified' -or $processState -ne 'none') { $exitCode = 1 }
}
exit $exitCode
