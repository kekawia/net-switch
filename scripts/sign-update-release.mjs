// The offline root key is never present in this workflow. Only its public,
// signed release-key statement is copied into the release assets.
import { spawnSync } from 'node:child_process';
import { lstatSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';

const { values } = parseArgs({ options: {
  ctl: { type: 'string' }, artifacts: { type: 'string' }, version: { type: 'string' },
  'key-statement': { type: 'string', default: 'packaging/updates/netswitch-release-key.json' },
} });
if (!values.ctl || !values.artifacts || !/^\d+\.\d+\.\d+$/.test(values.version ?? '')) {
  throw new Error('Require --ctl, --artifacts and a stable --version.');
}
const ctl = path.resolve(values.ctl);
const artifacts = path.resolve(values.artifacts);
const statement = path.resolve(values['key-statement']);
const signingVariable = 'NETSWITCH_RELEASE_SIGNING_KEY';
const invoke = (args, signing = false) => {
  const env = { ...process.env };
  if (!signing) delete env[signingVariable];
  const result = spawnSync(ctl, args, { env, encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 120000 });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${args[0]} failed: ${result.stderr.trim()}`);
};
const regularFile = (file, maximum) => {
  const info = lstatSync(file);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size <= 0 || info.size > maximum) {
    throw new Error(`Expected a bounded, plain single-link file: ${path.basename(file)}`);
  }
};

invoke(['update-check-root']);
if (!process.env[signingVariable]) throw new Error('The production release signing secret is not configured.');
regularFile(statement, 65536);
regularFile(statement + '.minisig', 65536);
const key = JSON.parse(readFileSync(statement, 'utf8'));
if (typeof key.expiresAt !== 'string' || !(Date.parse(key.expiresAt) > Date.now())) {
  throw new Error('The root-signed release key needs a future expiry.');
}
for (const arch of ['x64', 'arm64']) {
  const installer = path.join(artifacts, `NetSwitch-Setup-${values.version}-${arch}.exe`);
  const manifest = path.join(artifacts, `update-manifest-${arch}.json`);
  regularFile(installer, 512 * 1024 * 1024);
  invoke(['update-sign-manifest', '--key-env', signingVariable, '--key-statement', statement,
    '--installer', installer, '--version', values.version, '--arch', arch,
    '--expires', key.expiresAt, '--out', manifest], true);
  // Verify the exact files about to be published with the compiled root. No
  // alternate public-key argument or signing secret reaches this verification.
  invoke(['update-verify-manifest', '--key-statement', statement, '--manifest', manifest,
    '--installer', installer, '--current', '0.0.0', '--arch', arch]);
}
for (const suffix of ['', '.minisig']) {
  writeFileSync(path.join(artifacts, 'netswitch-release-key.json' + suffix), readFileSync(statement + suffix), { flag: 'wx' });
}
console.log('Verified both signed Windows installers and their complete root-key chain.');
