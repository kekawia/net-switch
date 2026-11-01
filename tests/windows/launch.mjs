import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startEngineDriver } from './launch-engine.mjs';
import { identity, run } from './testisp/harness.mjs';

function argument(name, fallback) {
  let value;
  for (const flag of Array.isArray(name) ? name : [name]) {
    const index = process.argv.indexOf(flag);
    if (index === -1) continue;
    assert(process.argv[index + 1] && !process.argv[index + 1].startsWith('--'), `${flag} needs a value`);
    assert(value === undefined || value === process.argv[index + 1], `Conflicting values for ${name}`);
    value = process.argv[index + 1];
  }
  return value ?? fallback;
}

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

export function launchOptions() {
  const profile = argument('--profile', 'v1');
  assert.equal(profile, 'v1', 'Only --profile v1 is supported');
  assert(!process.argv.includes('--engine-dir'), '--engine-dir is retired');
  const server = path.resolve(argument(['--server-exe', '--server-executable'], process.execPath));
  const nodeServer = server.toLowerCase() === process.execPath.toLowerCase() || /^(node|nodejs)(\.exe)?$/i.test(path.basename(server));
  const entry = argument('--server-entry', nodeServer ? path.join(repoRoot, 'tests/windows/engine-driver.mjs') : null);
  const engine = path.resolve(argument(['--engine-exe', '--engine-executable'], path.join(repoRoot, 'dist/windows-test/netswitch-engine.exe')));
  return {
    server, entry: entry ? path.resolve(entry) : null,
    engine,
    profile,
    serverVersionArgs: JSON.parse(argument('--server-version-args', '["--version"]')),
    engineVersionArgs: JSON.parse(argument('--engine-version-args', '["version"]')),
  };
}

export async function recordLaunch(options, file) {
  const binaries = { server: await identity(options.server, options.serverVersionArgs), engine: await identity(options.engine, options.engineVersionArgs) };
  if (options.entry) {
    const packageJSON = JSON.parse(await readFile(path.join(repoRoot, 'package.json'), 'utf8'));
    binaries.server.entry = { path: options.entry, version: packageJSON.version,
      sha256: createHash('sha256').update(await readFile(options.entry)).digest('hex') };
  }
  console.log(`Executables under test: ${JSON.stringify(binaries)}`);
  if (file) await writeFile(file, JSON.stringify(binaries, null, 2));
  return binaries;
}

export function serverCommand(options, dataDir, { proxy = false } = {}) {
  return [options.server, [
    ...(options.entry ? [options.entry] : ['--root', repoRoot]), ...(proxy ? ['--dev-proxy'] : []),
    '--user-data', dataDir, '--machine-data', dataDir,
    '--engine-executable', options.engine,
  ]];
}

export async function startServer(options, dataDir, output) {
  assert.equal(options.profile, 'v1', 'Only --profile v1 is supported');
  return startEngineDriver(options, dataDir, output);
}

export async function verifyEngineProcess(options, dataDir) {
  const pid = Number((await readFile(path.join(dataDir, 'engine.pid'), 'utf8')).trim());
  assert(Number.isSafeInteger(pid) && pid > 0, 'Missing engine PID');
  const result = await run('powershell.exe', ['-NoProfile', '-Command',
    '$p = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $env:TEST_ENGINE_PID); if (-not $p) { throw "Engine PID is gone" }; $p.ExecutablePath'],
  { env: { TEST_ENGINE_PID: String(pid) } });
  const observed = await realpath(result.stdout);
  assert.equal(observed.toLowerCase(), (await realpath(options.engine)).toLowerCase(), 'The running engine is not the requested executable');
  return { pid, path: observed };
}
