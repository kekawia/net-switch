// Build and boot the pinned upstream Linux v5.8 floor guests (amd64 KVM and
// arm64 TCG) using the digest-pinned Debian Bookworm compiler container and
// pinned .deb packages recorded in tests/linux/ownerproof/guest.lock.json.
import { createHash } from 'node:crypto';
import { spawnSync, spawn } from 'node:child_process';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const lockPath = join(root, 'tests/linux/ownerproof/guest.lock.json');
const distRoot = resolve(root, 'dist/ownerproof-guest');

const sha256 = buf => createHash('sha256').update(buf).digest('hex');

function run(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, {
    cwd: opts.cwd ?? root,
    env: { ...process.env, GOMAXPROCS: '2', GOTOOLCHAIN: 'local', ...opts.env },
    encoding: 'utf8',
    timeout: opts.timeout ?? 1_800_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (res.stdout) process.stdout.write(res.stdout);
  if (res.stderr) process.stderr.write(res.stderr);
  if (res.error || res.status !== 0) {
    throw new Error(`${cmd} ${args.join(' ')} failed: ${res.error ?? `exit ${res.status}`}`);
  }
  return res.stdout;
}

// Original deterministic SVR4 newc cpio archive writer (magic "070701").
// Zero timestamps, uid=0, gid=0, deterministic inode numbers and sorted entries.
function pad4(n) {
  const rem = n % 4;
  return rem === 0 ? 0 : 4 - rem;
}

function cpioHeader({ ino, mode, filesize, namesize }) {
  const hex8 = v => (v >>> 0).toString(16).padStart(8, '0');
  const fields = [
    hex8(ino),      // c_ino
    hex8(mode),     // c_mode
    hex8(0),        // c_uid
    hex8(0),        // c_gid
    hex8(mode & 0o040000 ? 2 : 1), // c_nlink
    hex8(0),        // c_mtime
    hex8(filesize), // c_filesize
    hex8(0),        // c_devmajor
    hex8(0),        // c_devminor
    hex8(0),        // c_rdevmajor
    hex8(0),        // c_rdevminor
    hex8(namesize), // c_namesize
    hex8(0),        // c_check
  ];
  return Buffer.from('070701' + fields.join(''), 'ascii');
}

export function buildDeterministicInitramfs(entries) {
  const sorted = [...entries].sort((a, b) => a.name.localeCompare(b.name));
  const chunks = [];
  let ino = 1;
  for (const item of sorted) {
    const nameBuf = Buffer.from(item.name + '\0', 'utf8');
    const dataBuf = item.data ?? Buffer.alloc(0);
    const hdr = cpioHeader({
      ino: ino++,
      mode: item.mode,
      filesize: dataBuf.length,
      namesize: nameBuf.length,
    });
    chunks.push(hdr, nameBuf);
    const namePad = pad4(hdr.length + nameBuf.length);
    if (namePad) chunks.push(Buffer.alloc(namePad));
    if (dataBuf.length) {
      chunks.push(dataBuf);
      const dataPad = pad4(dataBuf.length);
      if (dataPad) chunks.push(Buffer.alloc(dataPad));
    }
  }
  const trailerName = Buffer.from('TRAILER!!!\0', 'ascii');
  const trailerHdr = cpioHeader({
    ino: 0,
    mode: 0,
    filesize: 0,
    namesize: trailerName.length,
  });
  chunks.push(trailerHdr, trailerName);
  const trailerPad = pad4(trailerHdr.length + trailerName.length);
  if (trailerPad) chunks.push(Buffer.alloc(trailerPad));
  const cpio = Buffer.concat(chunks);
  const rem512 = cpio.length % 512;
  const aligned = rem512 === 0 ? cpio : Buffer.concat([cpio, Buffer.alloc(512 - rem512)]);
  const gz = gzipSync(aligned, { level: 9 });
  // Set gzip header mtime (bytes 4..7) and OS byte (byte 9 = 3 Unix) deterministically.
  gz.writeUInt32LE(0, 4);
  gz[9] = 3;
  return gz;
}

async function fetchPinned(url, expectedSha256, destPath) {
  try {
    const existing = await readFile(destPath);
    if (sha256(existing) === expectedSha256) return destPath;
  } catch {
    // Download fresh copy.
  }
  const res = await fetch(url, { signal: AbortSignal.timeout(300_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  const bytes = Buffer.from(await res.arrayBuffer());
  const actual = sha256(bytes);
  if (actual !== expectedSha256) {
    throw new Error(`SHA-256 mismatch for ${url}: got ${actual}, expected ${expectedSha256}`);
  }
  await writeFile(destPath, bytes);
  return destPath;
}

async function buildArchInitramfs(lock, arch, outDir) {
  const target = arch === 'amd64' ? 'x86' : 'arm64';
  const bpfDir = resolve(root, 'dist/ownerbpf');
  const bpfObjects = lock.initramfs.bpfObjects[arch];
  if (!bpfObjects) throw new Error(`Missing BPF object map for ${arch}`);

  const initBin = join(outDir, `nsownerinit-${arch}`);
  const testBin = join(outDir, `ownerbpf-proof-${arch}.test`);
  const initBin2 = join(outDir, `nsownerinit-${arch}.second`);
  const testBin2 = join(outDir, `ownerbpf-proof-${arch}.second.test`);
  const goEnv = {
    CGO_ENABLED: '0',
    GOOS: 'linux',
    GOARCH: arch,
    GOFLAGS: '-mod=vendor -p=2 -trimpath -buildvcs=false',
  };
  run('go', ['build', '-ldflags=-s -w -buildid=', '-o', initBin, lock.initramfs.pid1Package], { env: goEnv });
  run('go', ['test', '-c', `-tags=${lock.initramfs.proofTestTag}`, '-ldflags=-s -w -buildid=', '-o', testBin, lock.initramfs.proofTestPackage], { env: goEnv });
  run('go', ['build', '-ldflags=-s -w -buildid=', '-o', initBin2, lock.initramfs.pid1Package], { env: goEnv });
  run('go', ['test', '-c', `-tags=${lock.initramfs.proofTestTag}`, '-ldflags=-s -w -buildid=', '-o', testBin2, lock.initramfs.proofTestPackage], { env: goEnv });

  const initBytes = await readFile(initBin);
  const testBytes = await readFile(testBin);
  const initBytes2 = await readFile(initBin2);
  const testBytes2 = await readFile(testBin2);
  if (!initBytes.equals(initBytes2)) {
    throw new Error(`PID 1 binary nsownerinit is not byte-for-byte reproducible across two builds on ${arch}`);
  }
  if (!testBytes.equals(testBytes2)) {
    throw new Error(`Test binary ownerbpf-proof.test is not byte-for-byte reproducible across two builds on ${arch}`);
  }

  const entries = [
    { name: 'bin', mode: 0o040755 },
    { name: 'boot', mode: 0o040755 },
    { name: 'dev', mode: 0o040755 },
    { name: 'ownerbpf', mode: 0o040755 },
    { name: 'proc', mode: 0o040755 },
    { name: 'sys', mode: 0o040755 },
    { name: 'tmp', mode: 0o041777 },
    { name: 'init', mode: 0o100755, data: initBytes },
    { name: 'bin/ownerbpf-proof.test', mode: 0o100755, data: testBytes },
  ];

  for (const [objName, expectedHash] of Object.entries(bpfObjects)) {
    let objPath = join(bpfDir, objName);
    try {
      await stat(objPath);
    } catch {
      objPath = join(bpfDir, 'first', objName);
    }
    const objBytes = await readFile(objPath);
    const actualHash = sha256(objBytes);
    console.log(`FLOOR_GUEST_BPF_OBJECT arch=${arch} name=${objName} bytes=${objBytes.length} sha256=${actualHash}`);
    if (actualHash !== expectedHash) {
      throw new Error(`BPF object ${objName} SHA-256 mismatch: got ${actualHash}, expected ${expectedHash}`);
    }
    entries.push({ name: `ownerbpf/${objName}`, mode: 0o100644, data: objBytes });
  }

  const initramfs = buildDeterministicInitramfs(entries);
  const secondPass = buildDeterministicInitramfs(entries);
  if (!initramfs.equals(secondPass)) {
    throw new Error(`Initramfs builder is not byte-for-byte deterministic on ${arch}`);
  }
  const initramfsPath = join(outDir, `initramfs-5.8-${arch}.cpio.gz`);
  await writeFile(initramfsPath, initramfs);
  const digest = sha256(initramfs);
  const expectedInitramfsSha = lock.outputs?.[arch]?.initramfsSha256;
  const lockMatch = expectedInitramfsSha === digest;
  console.log(`FLOOR_GUEST_INITRAMFS arch=${arch} target=${target} bytes=${initramfs.length} sha256=${digest} init_sha256=${sha256(initBytes)} test_sha256=${sha256(testBytes)} double_build_verified=true lock_match=${lockMatch}`);
  if (!expectedInitramfsSha || !lockMatch) {
    throw new Error(`Initramfs SHA-256 mismatch on ${arch}: got ${digest}, expected ${expectedInitramfsSha}`);
  }
  return { initramfsPath, digest };
}

async function buildArchKernel(lock, arch, outDir) {
  const cfgProfile = lock.kernel.configs[arch];
  if (!cfgProfile) throw new Error(`Unsupported kernel arch ${arch}`);
  const configFile = join(root, cfgProfile.path);
  const configBytes = await readFile(configFile);
  if (sha256(configBytes) !== cfgProfile.sha256) {
    throw new Error(`Kernel config hash mismatch for ${cfgProfile.path}`);
  }

  const cacheDir = join(distRoot, 'cache');
  await mkdir(cacheDir, { recursive: true });
  const tarballPath = await fetchPinned(
    lock.kernel.tarballUrl,
    lock.kernel.tarballSha256,
    join(cacheDir, 'linux-5.8.tar.xz'),
  );

  const debDir = join(cacheDir, `debs-${arch}`);
  await mkdir(debDir, { recursive: true });
  const pkgList = arch === 'amd64' ? lock.debianPackages.amd64 : lock.debianPackages.arm64;
  for (const pkg of pkgList) {
    const fileName = pkg.path.split('/').at(-1);
    await fetchPinned(
      `${lock.debianPackages.mirror}/${pkg.path}`,
      pkg.sha256,
      join(debDir, fileName),
    );
  }

  const imageRef = `${lock.compilerImage.repository}:${lock.compilerImage.tag}@${lock.compilerImage.indexDigest}`;
  const containerScript = [
    'set -euo pipefail',
    'export DEBIAN_FRONTEND=noninteractive LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0',
    'export KBUILD_BUILD_TIMESTAMP="Thu Jan  1 00:00:00 UTC 1970" KBUILD_BUILD_USER=builder KBUILD_BUILD_HOST=netswitch KBUILD_BUILD_VERSION=1',
    'dpkg -i /work/debs/*.deb',
    'echo "=== FLOOR_COMPILER_INVENTORY arch=' + arch + ' ==="',
    'dpkg-query -W -f=\'${Package}=${Version}\\n\' gcc-12 gcc binutils make bc bison cpio dwarves pahole libbpf1 libdw1 libelf1 libelf-dev flex kmod libkmod2 libpopt0 m4 rsync',
    'gcc --version | head -n 1',
    'ld --version | head -n 1',
    'pahole --version',
    'rm -rf /tmp/kbuild && mkdir -p /tmp/kbuild',
    'tar -xf /work/linux-5.8.tar.xz -C /tmp/kbuild',
    'cd /tmp/kbuild/linux-5.8',
    // Upstream v5.8 tools/objtool/elf.h, tools/lib/subcmd, and scripts/dtc can fail on GCC 12 defaults if -Werror is active;
    // also pahole >= 1.24 enables 64-bit BTF enum encoding (kind_flag=1 on BTF_KIND_ENUM) by default, which Linux 5.8's
    // in-kernel BTF verifier rejects ("Invalid btf_info kind_flag") unless --skip_encoding_btf_enum64 is passed.
    'sed -i "s/-Werror//g" tools/lib/subcmd/Makefile tools/objtool/Makefile',
    'sed -i "s/-J /--skip_encoding_btf_enum64 -J /g" scripts/link-vmlinux.sh',
    `make ${cfgProfile.baseDefconfig}`,
    './scripts/kconfig/merge_config.sh -m .config /work/kernel.config',
    'make olddefconfig',
    'grep -qx "CONFIG_KPROBES=y" .config',
    'grep -qx "CONFIG_KPROBE_EVENTS=y" .config',
    'grep -qx "CONFIG_DEBUG_INFO_BTF=y" .config',
    'cp .config /work/out/resolved-kernel.config',
    // Ensure pahole emits only BTF kinds supported by Linux 5.8 using DWARF-4 debug info.
    `make -j"$(nproc)" KCFLAGS="-gdwarf-4 -Wno-error -fcommon" HOSTCFLAGS="-Wno-error -fcommon" ${cfgProfile.imageTarget}`,
    'test -s vmlinux',
    `cp ${cfgProfile.imageRelativePath} /work/out/kernel-image`,
  ].join('\n');

  await mkdir(outDir, { recursive: true });
  run('docker', [
    'run', '--rm',
    '-v', `${tarballPath}:/work/linux-5.8.tar.xz:ro`,
    '-v', `${debDir}:/work/debs:ro`,
    '-v', `${configFile}:/work/kernel.config:ro`,
    '-v', `${outDir}:/work/out`,
    imageRef,
    'bash', '-c', containerScript,
  ], { timeout: 2_400_000 });

  const imagePath = join(outDir, 'kernel-image');
  const resolvedConfigPath = join(outDir, 'resolved-kernel.config');
  const imageBytes = await readFile(imagePath);
  const resolvedBytes = await readFile(resolvedConfigPath);
  const imageHash = sha256(imageBytes);
  const resolvedHash = sha256(resolvedBytes);
  const expectedKernelSha = lock.outputs?.[arch]?.kernelImageSha256;
  if (!expectedKernelSha || expectedKernelSha !== imageHash) {
    throw new Error(`Kernel image SHA-256 mismatch on ${arch}: got ${imageHash}, expected ${expectedKernelSha}`);
  }
  if (!cfgProfile.resolvedConfigSha256 || cfgProfile.resolvedConfigSha256 !== resolvedHash) {
    throw new Error(`Resolved kernel config SHA-256 mismatch on ${arch}: got ${resolvedHash}, expected ${cfgProfile.resolvedConfigSha256}`);
  }
  console.log(`FLOOR_GUEST_KERNEL_IMAGE arch=${arch} target=${cfgProfile.imageTarget} bytes=${imageBytes.length} sha256=${imageHash} resolved_config_sha256=${resolvedHash} lock_verified=true`);
  return { imagePath, imageHash, resolvedConfigPath, resolvedHash };
}

async function bootFloorGuest(lock, arch, kernelImagePath, initramfsPath) {
  const cfgProfile = lock.kernel.configs[arch];
  const imageBytes = await readFile(kernelImagePath);
  const initramfsBytes = await readFile(initramfsPath);
  const imageHash = sha256(imageBytes);
  const initramfsHash = sha256(initramfsBytes);
  const expectedKernelSha = lock.outputs?.[arch]?.kernelImageSha256;
  const expectedInitramfsSha = lock.outputs?.[arch]?.initramfsSha256;
  if (!expectedKernelSha || imageHash !== expectedKernelSha) {
    throw new Error(`Boot kernel image SHA-256 mismatch on ${arch}: got ${imageHash}, expected ${expectedKernelSha}`);
  }
  if (!expectedInitramfsSha || initramfsHash !== expectedInitramfsSha) {
    throw new Error(`Boot initramfs SHA-256 mismatch on ${arch}: got ${initramfsHash}, expected ${expectedInitramfsSha}`);
  }
  console.log(`FLOOR_GUEST_BOOT_INPUTS arch=${arch} kernel_sha256=${imageHash} initramfs_sha256=${initramfsHash} lock_verified=true`);

  if (arch === 'amd64') {
    const kvmStat = await stat('/dev/kvm').catch(err => {
      throw new Error(`Required /dev/kvm missing on amd64 floor guest runner: ${err.message}`);
    });
    if (!kvmStat.isCharacterDevice()) {
      throw new Error('/dev/kvm is not a character device');
    }
  }

  const qemuBin = cfgProfile.qemuBinary;
  let qemuVersionOut;
  try {
    qemuVersionOut = run(qemuBin, ['--version']);
  } catch {
    run('sudo', ['apt-get', 'update'], { timeout: 300_000 });
    run('sudo', ['apt-get', 'install', '-y', '--no-install-recommends', 'qemu-system-x86', 'qemu-system-arm'], { timeout: 300_000 });
    qemuVersionOut = run(qemuBin, ['--version']);
  }
  const firstLine = (qemuVersionOut ?? '').split('\n')[0]?.trim() ?? 'unknown';
  console.log(`FLOOR_GUEST_QEMU_HOST_INPUT arch=${arch} binary=${qemuBin} verified=false version="${firstLine}"`);

  const qemuArgs = arch === 'amd64'
    ? [
        '-machine', 'q35,accel=kvm',
        '-cpu', 'host',
        '-smp', String(cfgProfile.cpus),
        '-m', String(cfgProfile.memoryMiB),
        '-nographic',
        '-no-reboot',
        '-kernel', kernelImagePath,
        '-initrd', initramfsPath,
        '-append', `console=${cfgProfile.console},115200 earlyprintk=serial,ttyS0,115200 panic=-1 oops=panic rdinit=/init`,
      ]
    : [
        '-machine', 'virt,accel=tcg',
        '-cpu', 'cortex-a57',
        '-smp', String(cfgProfile.cpus),
        '-m', String(cfgProfile.memoryMiB),
        '-nographic',
        '-no-reboot',
        '-kernel', kernelImagePath,
        '-initrd', initramfsPath,
        '-append', `console=${cfgProfile.console} panic=-1 oops=panic rdinit=/init`,
      ];

  const timeoutMs = arch === 'amd64' ? 10 * 60 * 1000 : 35 * 60 * 1000;
  console.log(`FLOOR_GUEST_LAUNCH arch=${arch} accel=${cfgProfile.accelerator} cmd="${qemuBin} ${qemuArgs.join(' ')}"`);

  return await new Promise((resolvePromise, rejectPromise) => {
    const useSudo = arch === 'amd64';
    const cmd = useSudo ? 'sudo' : qemuBin;
    const args = useSudo ? [qemuBin, ...qemuArgs] : qemuArgs;
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let combined = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      rejectPromise(new Error(`Floor guest ${arch} timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    child.stdout.on('data', chunk => {
      const text = chunk.toString('utf8');
      process.stdout.write(text);
      combined += text;
    });
    child.stderr.on('data', chunk => {
      const text = chunk.toString('utf8');
      process.stderr.write(text);
      combined += text;
    });
    child.on('error', err => {
      clearTimeout(timer);
      rejectPromise(err);
    });
    child.on('close', code => {
      clearTimeout(timer);
      if (!combined.includes('FLOOR_GUEST_RESULT status=pass')) {
        rejectPromise(new Error(`Floor guest ${arch} did not report FLOOR_GUEST_RESULT status=pass (qemu exit=${code})`));
        return;
      }
      if (combined.includes('--- FAIL:') || combined.includes('--- SKIP:')) {
        rejectPromise(new Error(`Floor guest ${arch} had failed or skipped tests`));
        return;
      }
      console.log(`FLOOR_GUEST_VERIFIED arch=${arch} accel=${cfgProfile.accelerator} qemu_exit=${code} status=pass`);
      resolvePromise();
    });
  });
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const mode = process.argv[2] ?? 'all';
  const arch = process.argv[3] ?? 'amd64';
  const lock = JSON.parse(await readFile(lockPath, 'utf8'));
  const outDir = join(distRoot, arch);
  await mkdir(outDir, { recursive: true });

  if (mode === 'initramfs') {
    const { initramfsPath, digest } = await buildArchInitramfs(lock, arch, outDir);
    console.log(`FLOOR_GUEST_INITRAMFS_COMPLETE arch=${arch} initramfs=${initramfsPath} sha256=${digest}`);
  } else if (mode === 'build') {
    const { initramfsPath } = await buildArchInitramfs(lock, arch, outDir);
    const { imagePath } = await buildArchKernel(lock, arch, outDir);
    console.log(`FLOOR_GUEST_BUILD_COMPLETE arch=${arch} kernel=${imagePath} initramfs=${initramfsPath}`);
  } else if (mode === 'boot') {
    const kernelImagePath = join(outDir, 'kernel-image');
    const initramfsPath = join(outDir, `initramfs-5.8-${arch}.cpio.gz`);
    await bootFloorGuest(lock, arch, kernelImagePath, initramfsPath);
  } else if (mode === 'all') {
    const { initramfsPath } = await buildArchInitramfs(lock, arch, outDir);
    const { imagePath } = await buildArchKernel(lock, arch, outDir);
    await bootFloorGuest(lock, arch, imagePath, initramfsPath);
  } else {
    throw new Error(`Unknown mode ${mode} (expected initramfs, build, boot, or all)`);
  }
}
