import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { createWriteStream, existsSync } from 'node:fs';
import { copyFile, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { engineFirewall } from './firewall.mjs';
import { hostedOnly, run, until } from './testisp/harness.mjs';

if (process.argv.includes('--worker-mode')) {
  await runWorker(process.argv.slice(process.argv.indexOf('--worker-mode') + 1));
  process.exit(0);
}

async function runWorker([mode, targetArg, extraArg]) {
  if (mode === 'http') {
    const body = await new Promise((resolve, reject) => {
      const req = http.get(targetArg, { timeout: 5000, headers: { Connection: 'close' } }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          if (res.statusCode !== 200) reject(new Error(`HTTP ${res.statusCode}`));
          else resolve(Buffer.concat(chunks).toString('utf8'));
        });
      });
      req.on('timeout', () => req.destroy(new Error('HTTP timeout')));
      req.on('error', reject);
    });
    process.stdout.write(body);
    return;
  }
  if (mode === 'trace') {
    const body = await new Promise((resolve, reject) => {
      const req = https.get({
        host: '1.0.0.1',
        port: 443,
        path: '/cdn-cgi/trace',
        servername: 'one.one.one.one',
        timeout: 6000,
        headers: { Connection: 'close' },
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode !== 200 || !/(?:^|\n)ip=/m.test(text)) {
            reject(new Error(`Unexpected trace response HTTP ${res.statusCode}: ${text.slice(0, 120)}`));
          } else {
            resolve(text);
          }
        });
      });
      req.on('timeout', () => req.destroy(new Error('HTTPS trace timeout')));
      req.on('error', reject);
    });
    process.stdout.write(JSON.stringify({ ok: true, sample: body.split('\n').slice(0, 3).join(' ') }));
    return;
  }
  if (mode === 'udp') {
    const [host, portStr] = targetArg.split(':');
    const port = Number(portStr);
    const payload = extraArg || 'hello-wg-udp';
    const sock = dgram.createSocket('udp4');
    try {
      const reply = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('UDP timeout')), 5000);
        sock.once('error', (err) => { clearTimeout(timer); reject(err); });
        sock.once('message', (msg) => { clearTimeout(timer); resolve(msg.toString('utf8')); });
        sock.send(Buffer.from(payload, 'utf8'), port, host, (err) => {
          if (err) { clearTimeout(timer); reject(err); }
        });
      });
      process.stdout.write(JSON.stringify({ reply }));
    } finally {
      sock.close();
    }
    return;
  }
  throw new Error(`Unknown worker mode: ${mode}`);
}

hostedOnly();

const nativeArm64 = (process.env.PROCESSOR_ARCHITEW6432 || process.env.PROCESSOR_ARCHITECTURE || '').toUpperCase() === 'ARM64' || process.arch === 'arm64';
const WIRE_MSI = nativeArm64
  ? {
      name: 'wireguard-arm64-1.1.1.msi',
      sha256: '8336335c738d4aff040fa9d11b752da65a80b6f41d3262d6ba5e82f97ebd1bd4',
    }
  : {
      name: 'wireguard-amd64-1.1.1.msi',
      sha256: '7bfed60ad61b785c914b38b61555a975488e1d3ec472dbfb2fcdf498fca75242',
    };

const dir = path.resolve('dist/windows-wireguard');
const msiPath = path.resolve('dist/cache', WIRE_MSI.name);
const engineExe = path.resolve('dist/windows-test/netswitch-engine.exe');
const wgpeerExe = path.resolve('dist/windows-test/wgpeer.exe');
const wgExe = 'C:\\Program Files\\WireGuard\\wireguard.exe';
const wgCli = 'C:\\Program Files\\WireGuard\\wg.exe';
const pipeName = String.raw`\\.\pipe\ProtectedPrefix\Administrators\NetSwitch\engine`;
const firewallRules = ['NetSwitch-wgpeer-loopback', 'NetSwitch-wg-engine-udp'];
const tunnelNames = ['wgsplit', 'wgclient', 'wgkill'];

const appKey = (p) => p.toLowerCase().replaceAll('/', '\\').split('\\').map((s, i, a) =>
  i < a.length - 1 && /^(?:app-|v)?[0-9]+(?:\.[0-9]+)+$/i.test(s) ? s.replace(/[0-9]+(?:\.[0-9]+)+/, '*') : s).join('\\');
const sorted = (o) => Object.fromEntries(Object.entries(o).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));

async function pwshJSON(script, env = {}) {
  const res = await run('pwsh.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], { env });
  return res.stdout ? JSON.parse(res.stdout.replace(/^\uFEFF/, '')) : null;
}

async function discoverAdapters() {
  const res = await run(engineExe, ['interfaces'], { timeout: 15_000 });
  return JSON.parse(res.stdout);
}

class EngineSession {
  constructor(stateDir, logStream) {
    this.stateDir = stateDir;
    this.logStream = logStream;
    this.proc = null;
    this.pipe = null;
    this.instance = '';
    this.epoch = 0;
    this.serial = 0;
    this.revision = 0;
    this.pending = new Map();
    this.events = [];
    this.renewTimer = null;
  }

  async launch() {
    await mkdir(this.stateDir, { recursive: true });
    const env = { ...process.env };
    delete env.GOMAXPROCS;
    this.proc = spawn(engineExe, ['run', '--standalone-admin', '--state-dir', this.stateDir], {
      detached: true,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env,
    });
    this.proc.stdout.on('data', (c) => this.logStream.write(c));
    this.proc.stderr.on('data', (c) => this.logStream.write(c));

    const deadline = Date.now() + 25_000;
    for (;;) {
      try {
        this.pipe = await new Promise((resolve, reject) => {
          const s = net.connect(pipeName);
          s.once('error', reject);
          s.once('connect', () => { s.removeListener('error', reject); resolve(s); });
        });
        break;
      } catch (err) {
        if (this.proc.exitCode !== null) {
          throw new Error(`Engine exited ${this.proc.exitCode} before pipe connect`);
        }
        if (Date.now() >= deadline) throw err;
        await delay(25);
      }
    }

    let buffer = '';
    this.pipe.on('data', (chunk) => {
      buffer += chunk;
      for (;;) {
        const idx = buffer.indexOf('\n');
        if (idx < 0) break;
        const msg = JSON.parse(buffer.slice(0, idx));
        buffer = buffer.slice(idx + 1);
        if (msg.event) {
          this.events.push(msg);
          continue;
        }
        const waiter = this.pending.get(msg.id);
        if (!waiter) continue;
        this.pending.delete(msg.id);
        clearTimeout(waiter.timer);
        if (msg.error) waiter.reject(new Error(msg.error));
        else waiter.resolve(msg.result);
      }
    });
    this.pipe.on('close', () => {
      for (const w of this.pending.values()) {
        clearTimeout(w.timer);
        w.reject(new Error('Engine pipe closed'));
      }
      this.pending.clear();
    });

    const hello = await this.call('hello');
    this.instance = hello.engineInstanceId;
    const attached = await this.call('attach');
    this.epoch = attached.epoch;
    this.renewTimer = setInterval(() => {
      if (this.pipe && !this.pipe.destroyed) {
        this.call('renew').catch(() => {});
      }
    }, 4000);
    this.renewTimer.unref();
  }

  call(method, fields = {}, timeout = 25_000) {
    assert(this.pipe && !this.pipe.destroyed, `Engine pipe unavailable for ${method}`);
    const id = String(++this.serial);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method}: engine command timeout`));
      }, timeout);
      this.pending.set(id, { resolve, reject, timer });
      this.pipe.write(JSON.stringify({
        id,
        method,
        engineInstanceId: this.instance,
        epoch: this.epoch,
        ...fields,
      }) + '\n');
    });
  }

  async applyConfig(method, config) {
    const normalized = {
      lines: config.lines,
      appLines: sorted(config.appLines ?? {}),
      combine: Boolean(config.combine),
      shares: sorted(config.shares ?? {}),
      lanes: sorted(config.lanes ?? {}),
      blocked: config.blocked ?? [],
      ipv6: config.ipv6 ?? true,
    };
    const hash = createHash('sha256').update(JSON.stringify(normalized)).digest('hex');
    this.revision += 1;
    return this.call(method, { revision: { n: this.revision, hash, config: normalized } });
  }

  async allFlows() {
    const flows = [];
    let cursor = '';
    do {
      const page = await this.call('flows', { cursor });
      flows.push(...(page.flows ?? []));
      cursor = page.cursor ?? '';
    } while (cursor);
    return flows;
  }

  async stop() {
    if (this.renewTimer) {
      clearInterval(this.renewTimer);
      this.renewTimer = null;
    }
    try {
      if (this.pipe && !this.pipe.destroyed) {
        await this.call('stop').catch(() => {});
      }
    } finally {
      this.pipe?.destroy();
      this.pipe = null;
    }
    if (this.proc) {
      if (this.proc.exitCode === null && this.proc.signalCode === null) {
        await once(this.proc, 'exit', { signal: AbortSignal.timeout(20_000) });
      }
      assert.equal(this.proc.exitCode, 0, `netswitch-engine exited ${this.proc.exitCode}`);
      this.proc = null;
    }
  }
}

async function uninstallTunnel(name) {
  if (!existsSync(wgExe)) return;
  await run(wgExe, ['/uninstalltunnelservice', name], { failure: true, timeout: 20_000 });
  await until(async () => {
    const adapters = await discoverAdapters();
    return !adapters.some((a) => a.alias === name);
  }, `tunnel ${name} adapter removed`, 15_000);
}

async function installTunnel(confDir, name, configText) {
  const confFile = path.join(confDir, `${name}.conf`);
  await writeFile(confFile, configText, { encoding: 'utf8', mode: 0o600 });
  await run(wgExe, ['/installtunnelservice', confFile], { timeout: 25_000 });
  return until(async () => {
    const adapters = await discoverAdapters();
    const found = adapters.find((a) => a.alias === name && a.up && a.addresses?.length > 0);
    return found || null;
  }, `tunnel ${name} up with address`, 20_000);
}

async function wgTransfer(name) {
  const res = await run(wgCli, ['show', name, 'transfer'], { timeout: 10_000 });
  let rx = 0, tx = 0;
  for (const line of res.stdout.split(/\r?\n/).filter(Boolean)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 3) {
      rx += Number(parts[1]) || 0;
      tx += Number(parts[2]) || 0;
    }
  }
  return { rx, tx, raw: res.stdout };
}

async function routeMetricsOn(ifIndex, prefix = '0.0.0.0/0') {
  const rows = await pwshJSON(
    `@(Get-NetRoute -InterfaceIndex ([int]$env:WG_IFINDEX) -DestinationPrefix $env:WG_PREFIX -ErrorAction SilentlyContinue | Select-Object RouteMetric,InterfaceMetric,NextHop) | ConvertTo-Json -Compress`,
    { WG_IFINDEX: String(ifIndex), WG_PREFIX: prefix },
  );
  return Array.isArray(rows) ? rows : (rows ? [rows] : []);
}

async function netSwitchCaptureRoutes() {
  const rows = await pwshJSON(
    `@(Get-NetRoute -DestinationPrefix @('0.0.0.0/1','128.0.0.0/1') -ErrorAction SilentlyContinue | Where-Object InterfaceAlias -eq 'NetSwitch' | Select-Object DestinationPrefix,RouteMetric) | ConvertTo-Json -Compress`,
  );
  return Array.isArray(rows) ? rows : (rows ? [rows] : []);
}

await rm(dir, { recursive: true, force: true });
await mkdir(dir, { recursive: true });
const confDir = path.join(dir, 'configs');
await mkdir(confDir, { recursive: true });
const engineLog = createWriteStream(path.join(dir, 'engine.log'));
const peerLog = createWriteStream(path.join(dir, 'wgpeer.log'));

const pinnedExe = path.join(dir, 'wg-pinned-app.exe');
const generalExe = path.join(dir, 'wg-general-app.exe');
await copyFile(process.execPath, pinnedExe);
await copyFile(process.execPath, generalExe);

function runAsApp(exe, mode, target, extra = '', options = {}) {
  return run(exe, [path.resolve('tests/windows/wireguard.mjs'), '--worker-mode', mode, target, extra], {
    timeout: 15_000,
    ...options,
  });
}

const results = [];
async function step(name, fn) {
  const started = performance.now();
  console.log(`WIREGUARD STEP START: ${name}`);
  const detail = await fn();
  const ms = Math.round(performance.now() - started);
  results.push({ name, status: 'passed', ms, detail });
  console.log(`WIREGUARD STEP PASS (${ms} ms): ${name}`);
  return detail;
}

let peerProc = null;
let peerState = null;
let activeEngine = null;
let msiInstalled = false;

try {
  await step('verify and install official WireGuard 1.1.1 MSI', async () => {
    const msiBytes = await readFile(msiPath);
    const actualHash = createHash('sha256').update(msiBytes).digest('hex');
    assert.equal(actualHash, WIRE_MSI.sha256, `SHA-256 mismatch for ${WIRE_MSI.name}`);

    const msiLog = path.join(dir, 'msi-install.log');
    await run('msiexec.exe', ['/i', msiPath, 'DO_NOT_LAUNCH=1', '/qn', '/norestart', '/l*v', msiLog], { timeout: 120_000 });
    msiInstalled = true;
    await until(() => existsSync(wgExe) && existsSync(wgCli), 'wireguard.exe and wg.exe installed', 20_000);
    const ver = await run(wgCli, ['--version'], { timeout: 10_000 });
    return { msi: WIRE_MSI.name, sha256: actualHash, wgVersion: ver.stdout };
  });

  await step('start userspace WireGuard peer and scoped UDP firewall rules', async () => {
    await pwshJSON(`
      foreach ($n in @('NetSwitch-wgpeer-loopback', 'NetSwitch-wg-engine-udp')) {
        Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue | Remove-NetFirewallRule
      }
      New-NetFirewallRule -Name 'NetSwitch-wgpeer-loopback' -DisplayName 'NetSwitch-wgpeer-loopback' -Direction Inbound -Action Allow -Program $env:WG_PEER_EXE -Protocol UDP -LocalAddress '127.0.0.1' | Out-Null
      New-NetFirewallRule -Name 'NetSwitch-wg-engine-udp' -DisplayName 'NetSwitch-wg-engine-udp' -Direction Inbound -Action Allow -Program $env:WG_ENGINE_EXE -Protocol UDP -RemoteAddress @('198.51.100.10', '198.51.101.10') | Out-Null
      '{}'
    `, { WG_PEER_EXE: wgpeerExe, WG_ENGINE_EXE: engineExe });

    const readyFile = path.join(dir, 'wgpeer-ready.json');
    peerProc = spawn(wgpeerExe, ['--state', readyFile], {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    peerProc.stdout.on('data', (c) => peerLog.write(c));
    peerProc.stderr.on('data', (c) => peerLog.write(c));

    peerState = await until(async () => {
      if (peerProc.exitCode !== null) throw new Error(`wgpeer exited ${peerProc.exitCode}`);
      return JSON.parse(await readFile(readyFile, 'utf8'));
    }, 'wgpeer ready state', 15_000);
    return { listenPort: peerState.listenPort, control: peerState.control };
  });

  const peerStats = async () => {
    const res = await fetch(`${peerState.control}/stats`, { signal: AbortSignal.timeout(5000) });
    assert(res.ok, `wgpeer /stats HTTP ${res.status}`);
    return res.json();
  };

  const initialAdapters = await discoverAdapters();
  const mainAdapter = initialAdapters.find((a) => a.up && a.default4 && !a.tunnel);
  assert(mainAdapter, `Missing physical default IPv4 adapter in ${JSON.stringify(initialAdapters)}`);
  const mainLine = { id: mainAdapter.id, interface: mainAdapter.alias, addresses: mainAdapter.addresses };

  await step('vpn.start-orders-exclude-and-split (WireGuard->NetSwitch and NetSwitch->WireGuard)', async () => {
    const splitConf = [
      '[Interface]',
      `PrivateKey = ${peerState.splitPrivateKeyBase64}`,
      'Address = 10.88.1.2/24',
      '',
      '[Peer]',
      `PublicKey = ${peerState.serverPublicKeyBase64}`,
      `Endpoint = 127.0.0.1:${peerState.listenPort}`,
      'AllowedIPs = 10.88.1.0/24, 198.51.101.0/24',
      '',
    ].join('\r\n');

    // Start order A: WireGuard split tunnel is up BEFORE Net Switch starts.
    const wgsplitA = await installTunnel(confDir, 'wgsplit', splitConf);
    assert.equal(wgsplitA.tunnel, true, `Expected wgsplit tunnel=true: ${JSON.stringify(wgsplitA)}`);
    assert.equal(wgsplitA.default4, false, `Split tunnel must not claim default4: ${JSON.stringify(wgsplitA)}`);

    activeEngine = new EngineSession(path.join(dir, 'state-order-a'), engineLog);
    await activeEngine.launch();
    await activeEngine.applyConfig('start', {
      lines: [mainLine],
      lanes: { [mainLine.id]: mainLine.id },
      ipv6: true,
    });

    // General traffic uses main physical line via Net Switch TUN.
    const traceA = JSON.parse((await runAsApp(generalExe, 'trace', '')).stdout);
    assert.equal(traceA.ok, true);

    // Split-VPN subnet 198.51.101.0/24 (/24 > /1) bypasses Net Switch TUN directly into wgsplit.
    const beforeSplitA = await peerStats();
    const splitRespA = JSON.parse((await runAsApp(generalExe, 'http', `${peerState.splitHTTP}/?nonce=orderA`)).stdout);
    assert.equal(splitRespA.via, 'wgpeer-split');
    assert(splitRespA.source.startsWith('10.88.1.2:'), `Unexpected split source: ${splitRespA.source}`);
    const afterSplitA = await peerStats();
    assert.equal(afterSplitA.tcpSplitHits, beforeSplitA.tcpSplitHits + 1);
    const xferA = await wgTransfer('wgsplit');
    assert(xferA.rx > 0 && xferA.tx > 0, `Expected real WireGuardNT encrypted transfer on wgsplit: ${JSON.stringify(xferA)}`);

    const flowsA = await activeEngine.allFlows();
    assert(!flowsA.some((f) => String(f.destination ?? '').startsWith('198.51.101.10:')),
      `Split-VPN destination should bypass Net Switch TUN via LPM: ${JSON.stringify(flowsA)}`);

    // Start order B: Net Switch is already running when WireGuard tunnel appears.
    await uninstallTunnel('wgsplit');
    const traceMid = JSON.parse((await runAsApp(generalExe, 'trace', '')).stdout);
    assert.equal(traceMid.ok, true);

    const wgsplitB = await installTunnel(confDir, 'wgsplit', splitConf);
    assert.equal(wgsplitB.tunnel, true);
    const splitRespB = JSON.parse((await runAsApp(generalExe, 'http', `${peerState.splitHTTP}/?nonce=orderB`)).stdout);
    assert.equal(splitRespB.via, 'wgpeer-split');
    assert(splitRespB.source.startsWith('10.88.1.2:'));

    await uninstallTunnel('wgsplit');
    return { orderASource: splitRespA.source, orderBSource: splitRespB.source, transferA: xferA };
  });

  await step('vpn.table-off-include-tcp-and-udp andvpn.fail-closed-and-failover', async () => {
    const clientConf = [
      '[Interface]',
      `PrivateKey = ${peerState.clientPrivateKeyBase64}`,
      'Address = 10.88.0.2/24',
      'Table = off',
      '',
      '[Peer]',
      `PublicKey = ${peerState.serverPublicKeyBase64}`,
      `Endpoint = 127.0.0.1:${peerState.listenPort}`,
      'AllowedIPs = 0.0.0.0/0',
      '',
    ].join('\r\n');

    const wgclient = await installTunnel(confDir, 'wgclient', clientConf);
    assert.equal(wgclient.tunnel, true);
    assert.equal(wgclient.default4, false, 'Table = off must not install a native default4 route');
    const preRoutes = await routeMetricsOn(wgclient.index4);
    assert.equal(preRoutes.length, 0, `Table = off should have no 0.0.0.0/0 route before Include: ${JSON.stringify(preRoutes)}`);

    const vpnLine = {
      id: wgclient.id,
      interface: wgclient.alias,
      addresses: wgclient.addresses.filter((ip) => !ip.includes(':')),
      vpn: true,
    };
    const pinnedKey = appKey(pinnedExe);

    await activeEngine.applyConfig('apply', {
      lines: [mainLine, vpnLine],
      appLines: { [pinnedKey]: vpnLine.id },
      lanes: { [mainLine.id]: mainLine.id, [vpnLine.id]: vpnLine.id },
      blocked: [],
      combine: false,
      shares: {},
      ipv6: true,
    });

    // Engine must synthesize metric-4096 fallback route on Table=off VPN interface.
    const synthRoutes = await until(async () => {
      const rows = await routeMetricsOn(wgclient.index4);
      return rows.some((r) => r.RouteMetric === 4096) ? rows : null;
    }, 'synthesized metric-4096 route on wgclient', 10_000);

    // Pinned app TCP + UDP must traverse Net Switch TUN -> wgclient (WireGuardNT) -> wgpeer.
    const beforePeer = await peerStats();
    const tcpNonce = randomBytes(8).toString('hex');
    const tcpResp = JSON.parse((await runAsApp(pinnedExe, 'http', `${peerState.includeHTTP}/?nonce=${tcpNonce}`)).stdout);
    assert.equal(tcpResp.via, 'wgpeer-include');
    assert.equal(tcpResp.nonce, tcpNonce);
    assert(tcpResp.source.startsWith('10.88.0.2:'), `Expected wgclient source 10.88.0.2, got ${tcpResp.source}`);

    const udpNonce = `udp-${randomBytes(6).toString('hex')}`;
    const udpResp = JSON.parse((await runAsApp(pinnedExe, 'udp', peerState.includeUDP, udpNonce)).stdout);
    assert.equal(udpResp.reply, `wgpeer-udp:${udpNonce}`);

    const afterPeer = await peerStats();
    assert.equal(afterPeer.tcpMainHits, beforePeer.tcpMainHits + 1);
    assert.equal(afterPeer.udpHits, beforePeer.udpHits + 1);
    const xfer = await wgTransfer('wgclient');
    assert(xfer.rx > 0 && xfer.tx > 0, `Expected real WireGuardNT encrypted transfer on wgclient: ${JSON.stringify(xfer)}`);

    // Unpinned general app continues using main physical line, never wgclient.
    const generalTrace = JSON.parse((await runAsApp(generalExe, 'trace', '')).stdout);
    assert.equal(generalTrace.ok, true);
    const afterGeneralPeer = await peerStats();
    assert.equal(afterGeneralPeer.tcpMainHits, afterPeer.tcpMainHits);

    // Fail-closed (Fallback: false): marking VPN line blocked rejects pinned app without leaking to main.
    await activeEngine.applyConfig('apply', {
      lines: [mainLine, vpnLine],
      appLines: { [pinnedKey]: vpnLine.id },
      lanes: { [mainLine.id]: mainLine.id, [vpnLine.id]: vpnLine.id },
      blocked: [vpnLine.id],
      combine: false,
      shares: {},
      ipv6: true,
    });
    const blockedAttempt = await runAsApp(pinnedExe, 'trace', '', '', { failure: true, timeout: 10_000 });
    assert.notEqual(blockedAttempt.code, 0, 'Fail-closed pinned app must not reach public trace via main');
    const blockedFlows = await activeEngine.allFlows();
    assert(!blockedFlows.some((f) => f.app?.id === pinnedKey && f.line === mainLine.id && !f.closing),
      `Fail-closed leaked pinned flow onto main: ${JSON.stringify(blockedFlows)}`);

    // Failover (Fallback: true): lanes maps vpnLine.id -> mainLine.id so pinned app fails over to main.
    await activeEngine.applyConfig('apply', {
      lines: [mainLine, vpnLine],
      appLines: { [pinnedKey]: vpnLine.id },
      lanes: { [mainLine.id]: mainLine.id, [vpnLine.id]: mainLine.id },
      blocked: [],
      combine: false,
      shares: {},
      ipv6: true,
    });
    const failoverTrace = JSON.parse((await runAsApp(pinnedExe, 'trace', '')).stdout);
    assert.equal(failoverTrace.ok, true);

    // Switching back to Exclude removes the synthesized metric-4096 route.
    await activeEngine.applyConfig('apply', {
      lines: [mainLine],
      lanes: { [mainLine.id]: mainLine.id },
      ipv6: true,
    });
    await until(async () => (await routeMetricsOn(wgclient.index4)).length === 0,
      'synthesized metric-4096 route removed when VPN excluded', 10_000);
    await uninstallTunnel('wgclient');

    return { synthRoutes, tcpSource: tcpResp.source, udpReply: udpResp.reply, transfer: xfer };
  });

  await step('vpn.real-wireguard-killswitch-step-aside (live and startup)', async () => {
    // Confirm Net Switch currently owns 0.0.0.0/1 + 128.0.0.0/1 capture routes.
    const beforeCapture = await netSwitchCaptureRoutes();
    assert.equal(beforeCapture.length, 2, `Expected active NetSwitch /1 capture routes: ${JSON.stringify(beforeCapture)}`);

    // AllowedIPs = ::/0 without Table=off activates WireGuard's real dynamic WFP
    // kill switch ("WireGuard filters" + "Block all outbound (IPv4)/(IPv6)")
    // without replacing the hosted runner's IPv4 0.0.0.0/0 default route.
    const killConf = [
      '[Interface]',
      `PrivateKey = ${peerState.clientPrivateKeyBase64}`,
      'Address = fd00:88::2/64',
      '',
      '[Peer]',
      `PublicKey = ${peerState.serverPublicKeyBase64}`,
      `Endpoint = 127.0.0.1:${peerState.listenPort}`,
      'AllowedIPs = ::/0',
      '',
    ].join('\r\n');
    const killConfFile = path.join(confDir, 'wgkill.conf');
    await writeFile(killConfFile, killConf, { encoding: 'utf8', mode: 0o600 });

    // Detached 20-second failsafe so even an unexpected test crash restores runner networking.
    const failsafe = spawn('pwsh.exe', [
      '-NoProfile', '-NonInteractive', '-Command',
      `Start-Sleep -Seconds 20; & '${wgExe}' /uninstalltunnelservice wgkill 2>$null`,
    ], { detached: true, windowsHide: true, stdio: 'ignore' });
    failsafe.unref();

    let liveStatus, startupError, startupStatus;
    try {
      await run(wgExe, ['/installtunnelservice', killConfFile], { timeout: 20_000 });

      // 1. Live step-aside on the already-running engine.
      liveStatus = await until(async () => {
        const st = await activeEngine.call('status');
        return st.vpnFirewall?.blocked && st.vpnFirewall?.steppedOut ? st : null;
      }, 'live WireGuard WFP kill-switch step-aside', 10_000);
      assert.equal(liveStatus.vpnFirewall.blocker, 'WireGuard', JSON.stringify(liveStatus));

      await until(async () => (await netSwitchCaptureRoutes()).length === 0,
        'NetSwitch /1 capture routes released on live step-aside', 8_000);
      await activeEngine.stop();
      activeEngine = null;

      // 2. Pre-capture startup step-aside on a fresh engine while wgkill is active.
      const startupEngine = new EngineSession(path.join(dir, 'state-killswitch-startup'), engineLog);
      await startupEngine.launch();
      try {
        await assert.rejects(
          startupEngine.applyConfig('start', {
            lines: [mainLine],
            lanes: { [mainLine.id]: mainLine.id },
            ipv6: true,
          }),
          (err) => {
            startupError = err.message;
            return /WireGuard's kill switch blocks Net Switch/i.test(err.message);
          },
        );
        startupStatus = await startupEngine.call('status');
        assert.equal(startupStatus.vpnFirewall?.blocked, true, JSON.stringify(startupStatus));
        assert.equal(startupStatus.vpnFirewall?.steppedOut, true, JSON.stringify(startupStatus));
        assert.equal(startupStatus.vpnFirewall?.blocker, 'WireGuard', JSON.stringify(startupStatus));
        assert.equal((await netSwitchCaptureRoutes()).length, 0, 'Startup step-aside must never leave /1 capture routes');
      } finally {
        await startupEngine.stop();
      }
    } finally {
      try { failsafe.kill(); } catch {}
      await uninstallTunnel('wgkill');
    }

    // 3. Once wgkill is uninstalled, Net Switch starts and stops cleanly again.
    const recoveryEngine = new EngineSession(path.join(dir, 'state-post-killswitch'), engineLog);
    await recoveryEngine.launch();
    try {
      await recoveryEngine.applyConfig('start', {
        lines: [mainLine],
        lanes: { [mainLine.id]: mainLine.id },
        ipv6: true,
      });
      const recovered = await recoveryEngine.call('status');
      assert.equal(recovered.status, 'on');
      assert.equal(recovered.vpnFirewall ?? null, null);
      assert.equal((await netSwitchCaptureRoutes()).length, 2);
    } finally {
      await recoveryEngine.stop();
    }

    return {
      liveFirewall: liveStatus.vpnFirewall,
      startupError,
      startupFirewall: startupStatus.vpnFirewall,
    };
  });
} finally {
  const cleanupErrors = [];
  if (activeEngine) {
    await activeEngine.stop().catch((e) => cleanupErrors.push(e));
    activeEngine = null;
  }
  for (const t of tunnelNames) {
    await uninstallTunnel(t).catch((e) => cleanupErrors.push(e));
  }
  if (peerState?.control) {
    await fetch(`${peerState.control}/stop`, { method: 'POST', signal: AbortSignal.timeout(3000) }).catch(() => {});
  }
  if (peerProc && peerProc.exitCode === null) {
    peerProc.kill();
    await once(peerProc, 'exit', { signal: AbortSignal.timeout(5000) }).catch(() => {});
  }
  await pwshJSON(`
    foreach ($n in @('NetSwitch-wgpeer-loopback', 'NetSwitch-wg-engine-udp')) {
      Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
    '{}'
  `).catch((e) => cleanupErrors.push(e));
  if (msiInstalled) {
    const msiUninstallLog = path.join(dir, 'msi-uninstall.log');
    await run('msiexec.exe', ['/x', msiPath, '/qn', '/norestart', '/l*v', msiUninstallLog], { timeout: 120_000 })
      .catch((e) => cleanupErrors.push(e));
  }
  await engineFirewall(engineExe, false).catch((e) => cleanupErrors.push(e));
  const remainingCapture = await netSwitchCaptureRoutes().catch(() => []);
  if (remainingCapture.length) {
    cleanupErrors.push(new Error(`Leftover NetSwitch capture routes: ${JSON.stringify(remainingCapture)}`));
  }
  engineLog.end();
  peerLog.end();
  await writeFile(path.join(dir, 'report.json'), JSON.stringify({
    arch: process.arch,
    msi: WIRE_MSI,
    results,
    cleanupErrors: cleanupErrors.map((e) => e.stack ?? String(e)),
  }, null, 2));
  if (cleanupErrors.length) {
    throw new AggregateError(cleanupErrors, 'WireGuard CI cleanup failed');
  }
}
