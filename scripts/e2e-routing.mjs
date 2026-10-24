// Checks that routing really sends new connections where the rules say, with
// the real engine: the main line by default, an app's own line once it is
// pinned there, and every line while combining. Runs on a disposable hosted
// Windows runner with a local TLS fixture. The server uses test mode
// (a local proxy instead of the network adapter), with both lines on one adapter:
// lines are told apart by the engine's outbound, not by the adapter.
//
//   node scripts/e2e-routing.mjs [--engine-dir path\to\engine]
//
// The engine must be in engine\ (scripts\fetch-engine.ps1 puts it there) or
// in the folder --engine-dir names. This script's own connections go through
// the proxy, so this script is the app being routed.
import { spawn, execFile } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { connect as tlsConnect } from 'node:tls';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { killTree, runFile, runPowerShellJson } from '../lib/ps.mjs';
import { describePowerShellFailure } from '../tests/windows/clixml.mjs';
import { launchServer, recordServerAndEngine, isNodeServer, launchSpec } from './server-under-test.mjs';
import { verifyEngineProcess } from '../tests/windows/launch.mjs';
import { localHttps } from './tun-test-https.mjs';
import { hostedOnly } from '../tests/windows/testisp/harness.mjs';

hostedOnly();
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
// Windows names a program by its real path; Node may run through a link (nvm).
const SELF = realpathSync.native(process.execPath);
const publicTarget = { host: '1.1.1.1', port: 443, path: '/cdn-cgi/trace', servername: 'one.one.one.one', publicTrace: true };
let httpsResponder, localTarget;

const dataDir = await mkdtemp(path.join(tmpdir(), 'net-switch-e2e-'));
await recordServerAndEngine();
// A cold Windows PowerShell 5.1 writes its "Preparing modules for first use"
// progress record to stderr. That is not a failure, but it fills the captured
// stderr and buries the real error, so every call silences progress.
const QUIET = `$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
`;

async function powershellJson(script) {
  try {
    return await runPowerShellJson(`${QUIET}${script}`);
  } catch (error) {
    throw new Error(describePowerShellFailure(error), { cause: error });
  }
}
// The stale-PID proof needs a process the app must never stop: killable, not
// critical, and alive for the whole run. A temporary scheduled task running as
// SYSTEM starts a PowerShell that records its own PID and sleeps. An arbitrary
// svchost can exit on its own (jobs 120949316352 and 120614380814), and a
// critical process such as winlogon would bugcheck the runner if a regression
// ever stopped it.
const CANARY_TASK = `net-switch-canary-${process.pid}`;
let canary = null;

async function systemProcessIdentity(pid) {
  // Get-Process reads the running token's owner directly. A CIM service scan
  // can spend the whole deadline loading WMI on a cold ARM64 runner.
  return powershellJson(`$system = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-18').Translate([Security.Principal.NTAccount]).Value
$process = Get-Process -Id ${Number(pid)} -IncludeUserName -ErrorAction Stop
if ($process.UserName -ne $system) { throw "PID ${Number(pid)} runs as $($process.UserName), not $system" }
[pscustomobject]@{ Id = [int]$process.Id; Name = $process.ProcessName; Start = [string]$process.StartTime.ToFileTimeUtc() } | ConvertTo-Json -Compress`);
}

async function stopSystemCanary(task, process) {
  await runFile('schtasks.exe', ['/End', '/TN', task], { timeoutMs: 30_000 }).catch(() => {});
  await runFile('schtasks.exe', ['/Delete', '/TN', task, '/F'], { timeoutMs: 30_000 }).catch(() => {});
  if (!process) return;
  // End already stops the task's process; this covers a task that lost track of it.
  await powershellJson(`$process = Get-Process -Id ${Number(process.pid)} -ErrorAction SilentlyContinue
if ($process -and $process.ProcessName -eq '${process.name.replaceAll("'", "''")}' -and [string]$process.StartTime.ToFileTimeUtc() -eq '${process.start}') { Stop-Process -Id $process.Id -Force }`).catch(() => {});
}

async function startSystemCanary() {
  const script = path.join(dataDir, 'system-canary.ps1');
  const pidFile = path.join(dataDir, 'system-canary.pid');
  await writeFile(script, `$PID | Set-Content -LiteralPath '${pidFile.replaceAll("'", "''")}' -Encoding ASCII
Start-Sleep -Seconds 3600
`);
  const command = `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "${script}"`;
  try {
    await runFile('schtasks.exe', ['/Create', '/TN', CANARY_TASK, '/TR', command, '/SC', 'ONCE', '/ST', '00:00', '/RU', 'SYSTEM', '/RL', 'HIGHEST', '/F'], { timeoutMs: 30_000 });
    await runFile('schtasks.exe', ['/Run', '/TN', CANARY_TASK], { timeoutMs: 30_000 });
    const pid = await until('the SYSTEM canary starting', async () => {
      const text = await readFile(pidFile, 'utf8').catch(() => '');
      const value = Number(text.trim());
      return Number.isInteger(value) && value > 0 ? value : null;
    }, 60);
    const identity = await systemProcessIdentity(pid);
    if (identity.Name !== 'powershell') throw new Error(`the SYSTEM canary is ${identity.Name}, not powershell`);
    console.log(`SYSTEM canary PID for stale-PID proof: ${pid} (${identity.Name}, started ${identity.Start})`);
    return { pid, name: identity.Name, start: identity.Start, task: CANARY_TASK };
  } catch (error) {
    await stopSystemCanary(CANARY_TASK, null).catch(() => {});
    throw error;
  }
}

const hosted = process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted';
let server = null;
let serverOutput = '';

let session = null;
const open = [];

async function api(route, body) {
  const response = await fetch(`http://127.0.0.1:${session.port}/api/${route}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'X-Token': session.token, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });
  const answer = await response.json();
  if (!response.ok) throw new Error(`${route}: ${answer.error ?? response.status}`);
  return answer;
}

async function until(what, check, seconds = 60) {
  const deadline = Date.now() + seconds * 1000;
  let last;
  while (Date.now() < deadline) {
    try {
      last = await check();
      if (last) return last;
    } catch (error) {
      last = error.message;
    }
    await delay(250);
  }
  throw new Error(`${what} did not happen within ${seconds} s${last ? ` (last: ${JSON.stringify(last)})` : ''}`);
}

// Starting checks the engine's files against their checksums first, which
// takes a while on a busy PC.
async function routingOn() {
  let routing = null;
  try {
    return await until('routing turning on', async () => {
      const state = await api('state');
      routing = state.routing;
      if (state.routing.status === 'on') return state;
      if (state.routing.status === 'error' && /missing|doesn’t match/.test(state.routing.error ?? '')) {
        throw new Error(`the engine can't start: ${state.routing.error}`);
      }
      return null;
    }, 120);
  } catch (error) {
    throw new Error(`${error.message}; routing was ${JSON.stringify(routing)}`);
  }
}

// One HTTPS request through the test-mode proxy, left open so the server's
// next poll sees it. Resolves once the answer has arrived.
// One deadline covers the proxy, TLS and the answer; any other answer, or the
// connection closing first, fails the request instead of hanging the test.
const REQUEST_TIMEOUT_MS = 20_000;
function connectThroughProxy(proxyPort, target = localTarget) {
  const nonce = randomBytes(16).toString('hex');
  return new Promise((resolve, reject) => {
    let settled = false;
    const sockets = [];
    const fail = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      for (const socket of sockets) socket.destroy();
      reject(error.code === 'ECONNRESET'
        ? new Error(`transport reset (origin unproven): ${target.host}:${target.port} (${error.message})`, { cause: error }) : error);
    };
    const timer = setTimeout(() => fail(new Error('the request through the proxy took too long')), REQUEST_TIMEOUT_MS);
    const tunnel = request({ host: '127.0.0.1', port: proxyPort, method: 'CONNECT', path: `${target.host}:${target.port}` });
    tunnel.on('error', fail);
    tunnel.on('connect', (response, socket) => {
      sockets.push(socket);
      if (response.statusCode !== 200) {
        fail(new Error(`local proxy CONNECT failed: HTTP ${response.statusCode}`));
        return;
      }
      const secure = tlsConnect({ socket, servername: target.servername, ca: target.ca }, () => {
        if (!secure.authorized) { fail(new Error(`TLS verification failed: ${secure.authorizationError}`)); return; }
        secure.write(`GET ${target.path ?? `/?nonce=${nonce}`} HTTP/1.1\r\nHost: ${target.servername}\r\nConnection: keep-alive\r\n\r\n`);
      });
      sockets.push(secure);
      let text = '';
      secure.on('data', (chunk) => {
        if (settled) return;
        text += chunk;
        if (!text.includes('\r\n\r\n')) return;
        const status = /^HTTP\/1\.[01] (\d{3})/.exec(text)?.[1];
        if (status !== '200') {
          const label = target.publicTrace && secure.authorized && /^5\d\d$/.test(status) ? 'public target unavailable: ' : '';
          fail(new Error(`${label}the site answered ${status ?? 'something unreadable'}`));
          return;
        }
        const body = text.slice(text.indexOf('\r\n\r\n') + 4);
        if (target.publicTrace) {
          if (!/(?:^|\n)ip=[^\r\n]+\r?\n/.test(body)) return;
        } else {
          const length = Number(/\r\ncontent-length:\s*(\d+)/i.exec(text)?.[1]);
          if (!length) { fail(new Error('Local HTTPS response has no content length')); return; }
          if (Buffer.byteLength(body) < length) return;
          try { check(JSON.parse(body).nonce === nonce, 'local HTTPS response echoes this request'); }
          catch (error) { fail(error); return; }
        }
        settled = true;
        clearTimeout(timer);
        open.push(secure);
        resolve(secure);
      });
      secure.on('end', () => fail(new Error('early close (origin unproven): connection ended before the HTTPS answer')));
      secure.on('close', () => fail(new Error('early close (origin unproven): connection closed before the HTTPS answer')));
      secure.on('error', fail);
    });
    tunnel.end();
  });
}

// Closes this script's connections and waits until the server no longer
// counts any, so the next check only sees new ones.
async function closeAll() {
  for (const socket of open.splice(0)) socket.destroy();
  if (!session || server.exitCode !== null) return;
  const self = SELF.toLowerCase();
  await until('closed connections leaving the count', async () => {
    const state = await api('state');
    const row = state.apps.find((app) => app.path.toLowerCase() === self);
    return Object.values(row?.connections ?? {}).every((count) => count === 0);
  }, 20);
}

// This script's connections per line, as the server counts them after a poll.
async function connectionsPerLine(expected) {
  const self = SELF.toLowerCase();
  let apps = [];
  try {
    return await until(`${expected} connections showing in the window`, async () => {
      const state = await api('state');
      apps = state.apps.map((app) => ({ path: app.path, connections: app.connections }));
      const row = state.apps.find((app) => app.path.toLowerCase() === self);
      const counts = row?.connections ?? {};
      return Object.values(counts).reduce((sum, count) => sum + count, 0) >= expected ? counts : null;
    }, 20);
  } catch (error) {
    throw new Error(`${error.message}; the window shows ${JSON.stringify(apps)}`);
  }
}

async function openMany(count, proxyPort) {
  // One after another, as an app opening connections would: Windows hands
  // out the proxy's client ports in order, which is what combining splits.
  for (let i = 0; i < count; i += 1) await connectThroughProxy(proxyPort);
}

function check(condition, message) {
  if (!condition) throw new Error(message);
  console.log(`ok - ${message}`);
}

let failed = false;
try {
  if (hosted) {
    canary = await startSystemCanary();
    await writeFile(path.join(dataDir, 'engine.pid'), String(canary.pid));
  }
  server = launchServer(dataDir);
  server.stdout.on('data', (chunk) => (serverOutput += chunk));
  server.stderr.on('data', (chunk) => (serverOutput += chunk));
  session = await until('the server starting', async () => JSON.parse(await readFile(path.join(dataDir, 'server.json'), 'utf8')), 60);
  let state = await routingOn();
  await verifyEngineProcess(launchSpec, dataDir);
  if (canary) check(Number(await readFile(path.join(dataDir, 'engine.pid'), 'utf8')) !== canary.pid, 'start replaced a stale SYSTEM process PID');
  if (canary && !isNodeServer) {
    const { stdout, stderr } = await promisify(execFile)('go', ['test', '-v', '-count=1', '-timeout=90s', '-run=^TestReadWorkerCannotWriteControlHKLMOrTCP$', './internal/platform/worker'], {
      cwd: ROOT, windowsHide: true, timeout: 120_000, maxBuffer: 2 * 1024 * 1024,
      env: { ...process.env, NETSWITCH_CONTROL_PID: String(server.pid), GOMAXPROCS: '2' },
    }).catch((error) => {
      // execFile's message omits stdout, where Go prints failed assertions.
      // Keep the live-Control proof visible even when the test exits nonzero.
      if (error.stdout) console.error(error.stdout);
      if (error.stderr) console.error(error.stderr);
      throw error;
    });
    console.log(stdout); if (stderr) console.error(stderr);
    check(true, 'read workers cannot modify the running Control process, HKLM or TCP rows');
  }
  check(state.lines.length === 1, `the first line is the adapter Windows uses (${state.lines[0]?.alias})`);
  const main = state.lines[0];

  // A second line on the same adapter, so this works on a PC with one.
  await api('lines/add', { alias: main.alias });
  state = await routingOn();
  check(state.lines.length === 2, 'a second line was added and routing restarted');
  const second = state.lines[1];
  const proxyPort = state.routing.proxyPort;

  const address = await powershellJson(`(Get-NetIPAddress -InterfaceAlias '${main.alias.replaceAll("'", "''")}' -AddressFamily IPv4 | Where-Object AddressState -eq 'Preferred' | Select-Object -First 1).IPAddress | ConvertTo-Json -Compress`);
  httpsResponder = await localHttps(address);
  localTarget = { ...httpsResponder.target, host: address, port: httpsResponder.port };
  // Exactly one public request: a local peer cannot prove real internet egress.
  // No held-socket/count assertion relies on this independently owned server.
  if (!process.argv.includes('--public-via-tun')) {
    await connectThroughProxy(proxyPort, publicTarget);
    check(true, 'one public HTTPS trace proves real internet egress through the selected Control proxy');
    await closeAll();
  }

  await openMany(3, proxyPort);
  let counts = await connectionsPerLine(3);
  check(counts[main.id] === 3 && !counts[second.id], `without a choice, connections use the main line (${JSON.stringify(counts)})`);
  await closeAll();

  await api('app-line', { path: SELF, line: second.id });
  await openMany(3, proxyPort);
  counts = await until('the pinned connections showing', async () => {
    const now = await connectionsPerLine(3);
    return now[second.id] === 3 ? now : null;
  }, 20);
  check(counts[second.id] === 3 && !counts[main.id], `a pinned app's new connections use its line (${JSON.stringify(counts)})`);
  await closeAll();

  // Pinned to the main line: kept there even while combining.
  await api('app-line', { path: SELF, line: null });
  await api('combine', { on: true, mode: 'manual', weights: { [main.id]: 1, [second.id]: 1 } });
  state = await api('state');
  check(state.lines.every((line) => line.share === 0.5), 'combining by hand gives each line half');
  await openMany(12, proxyPort);
  counts = await connectionsPerLine(12);
  check(counts[main.id] >= 3 && counts[second.id] >= 3, `while combining, new connections use both lines (${JSON.stringify(counts)})`);
  await closeAll();

  await api('app-line', { path: SELF, line: main.id });
  await openMany(6, proxyPort);
  counts = await until('the kept connections showing', async () => {
    const now = await connectionsPerLine(6);
    return now[main.id] === 6 ? now : null;
  }, 20);
  check(counts[main.id] === 6, `an app pinned to the main line stays on it while combining (${JSON.stringify(counts)})`);
  await closeAll();

  if (canary) {
    await api('routing', { on: false });
    await writeFile(path.join(dataDir, 'engine.pid'), String(canary.pid));
    await api('routing', { on: false });
    check(await readFile(path.join(dataDir, 'engine.pid')).then(() => false, (error) => error.code === 'ENOENT'), 'Turn off removed a stale SYSTEM process PID');
    await writeFile(path.join(dataDir, 'engine.pid'), String(canary.pid));
  }
  await api('quit', {});
  await until('the server ending', async () => server.exitCode !== null, 30);
  check(server.exitCode === 0, 'quitting stops routing and ends the server');
  if (canary) {
    check(await readFile(path.join(dataDir, 'engine.pid')).then(() => false, (error) => error.code === 'ENOENT'), 'Quit removed a stale SYSTEM process PID');
    const still = await systemProcessIdentity(canary.pid).catch(() => null);
    check(still?.Name === canary.name && still?.Start === canary.start, 'the SYSTEM canary was never stopped');
  }
  console.log('routing end-to-end test passed');
} catch (error) {
  failed = true;
  console.error(`not ok - ${error.message}`);
  console.error('--- server output ---');
  console.error(serverOutput);
  const log = await readFile(path.join(dataDir, 'server.log'), 'utf8').catch(() => '');
  console.error('--- server.log ---');
  console.error(log.split('\n').slice(-40).join('\n'));
} finally {
  for (const socket of open.splice(0)) socket.destroy();
  if (canary) await stopSystemCanary(canary.task, canary).catch(() => {});
  if (httpsResponder) await httpsResponder.close();
  // Quit the normal way, so the engine stops too; else end the whole tree.
  if (server && server.exitCode === null && session) await api('quit', {}).catch(() => {});
  await delay(1000);
  if (server && server.exitCode === null) await killTree(server.pid);
  await rm(dataDir, { recursive: true, force: true }).catch(() => {});
}
process.exit(failed ? 1 : 0);
