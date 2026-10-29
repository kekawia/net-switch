// Original proof objects; no host headers, libbpf headers or running-kernel
// generated vmlinux.h. Run only on the reviewed hosted Linux amd64 builder.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = resolve(root, 'dist/ownerbpf');
const toolchain = join(output, 'toolchain');
// Ubuntu noble release pocket, exact package bytes and compiler libraries.
// Codegen is clang 18.1.3-1. No moving apt package is used for compilation.
const packages = [
  ['pool/universe/l/llvm-toolchain-18/clang-18_18.1.3-1_amd64.deb', '3d028a3b4c0b3dc942e043db94e153baedf5c384283181d274a5e915da1b5135'],
  ['pool/main/l/llvm-toolchain-18/libclang-cpp18_18.1.3-1_amd64.deb', '899e354d4719c31eb7829517a3ed8d6b64173590fb5c7fe7371ede469fbbe05d'],
  ['pool/main/l/llvm-toolchain-18/libllvm18_18.1.3-1_amd64.deb', '826621c8e678dd27b4f5c3a9b26d10aae50d5de2d95575695a17c91014f5eaa5'],
];
const hash = b => createHash('sha256').update(b).digest('hex');
function run(command, args, env = {}) {
  const r = spawnSync(command, args, { cwd: root, env: { ...process.env, GOMAXPROCS: '2', GOTOOLCHAIN: 'local', ...env }, encoding: 'utf8', timeout: 180_000 });
  if (r.error || r.status !== 0) throw new Error(`${command}: ${r.error ?? r.status}\n${r.stdout}\n${r.stderr}`);
  process.stdout.write(r.stdout);
  process.stderr.write(r.stderr);
  return r.stdout;
}

if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('requires hosted Linux amd64 builder; never downloads a local Windows toolchain');
if (!run('go', ['version']).includes('go1.27.3 linux/amd64')) throw new Error('requires pinned Go 1.27.3 linux/amd64');
const mod = await readFile(join(root, 'go.mod'), 'utf8');
if (!mod.includes('github.com/cilium/ebpf v0.22.0') || !mod.includes('tool github.com/cilium/ebpf/cmd/bpf2go')) throw new Error('loader and bpf2go must both be pinned to v0.22.0');
await mkdir(toolchain, { recursive: true });
for (const [path, digest] of packages) {
  const target = join(output, path.split('/').at(-1));
  let bytes;
  try { bytes = await readFile(target); } catch { /* first build */ }
  if (!bytes || hash(bytes) !== digest) {
    const response = await fetch(`https://archive.ubuntu.com/ubuntu/${path}`, { signal: AbortSignal.timeout(120_000) });
    if (!response.ok) throw new Error(`pinned compiler download ${response.status}: ${path}`);
    bytes = Buffer.from(await response.arrayBuffer());
    if (hash(bytes) !== digest) throw new Error(`compiler checksum mismatch: ${path}`);
    await writeFile(target, bytes); // generated toolchain artifact
  }
  run('dpkg-deb', ['-x', target, toolchain]);
}
const env = { LD_LIBRARY_PATH: join(toolchain, 'usr/lib/x86_64-linux-gnu'), SOURCE_DATE_EPOCH: '0', LC_ALL: 'C', TZ: 'UTC' };
const compiler = join(toolchain, 'usr/lib/llvm-18/bin/clang');
if (!run(compiler, ['--version'], env).includes('18.1.3')) throw new Error('wrong clang');
const source = join(root, 'internal/engine/linux/ownerbpf/bpf/attribution.c');
for (const pass of ['first', 'second']) {
  const dir = join(output, pass);
  await mkdir(dir, { recursive: true });
  for (const [prefix, input, defines] of [
    ['proof', source, []],
    ['bridge', join(dirname(source), 'bridge.c'), []],
    ['fault', join(dirname(source), 'bridge.c'), ['-DNS_OWNER_PROOF_FAULTS=1']],
  ]) {
  run('go', ['run', '-p=2', '-mod=vendor', 'github.com/cilium/ebpf/cmd/bpf2go',
    '-cc', compiler, '-no-strip', '-target', 'amd64,arm64', '-go-package', 'ownerbpf',
    '-output-dir', dir, prefix, input, '--', ...defines, '-O2', '-g', '-mcpu=v1', '-nostdinc',
    '-Werror', '-Wall', `-fdebug-prefix-map=${root}=/ns-owner`, `-ffile-prefix-map=${root}=/ns-owner`,
    '-fdebug-compilation-dir=/ns-owner'], env);
  }
}
const files = (await readdir(join(output, 'first'))).sort();
const manifest = { schema: 1, loader: 'github.com/cilium/ebpf@v0.22.0', compiler: packages, source: {}, files: {} };
for (const name of ['abi.h', 'attribution.c', 'provenance.h', 'bridge.c']) manifest.source[name] = hash(await readFile(join(dirname(source), name)));
for (const name of files) {
  const first = await readFile(join(output, 'first', name));
  const second = await readFile(join(output, 'second', name));
  if (!first.equals(second)) throw new Error(`non-reproducible generated artifact: ${name}`);
  manifest.files[name] = hash(first);
}
await writeFile(join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest, null, 2));
