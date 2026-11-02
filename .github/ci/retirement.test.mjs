import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const exceptionsUrl = new URL('./singbox-exceptions.json', import.meta.url);
const versionsUrl = new URL('../../packaging/versions.json', import.meta.url);
const issUrl = new URL('../../packaging/NetSwitch.iss', import.meta.url);
const packageJsonUrl = new URL('../../package.json', import.meta.url);
const noticesUrl = new URL('../../THIRD_PARTY_NOTICES.md', import.meta.url);
const licenseUrl = new URL('../../LICENSE', import.meta.url);
const userGuideUrl = new URL('../../docs/user-guide.md', import.meta.url);
const iconUrl = new URL('../../assets/net-switch.ico', import.meta.url);
const lucideLicenseUrl = new URL('../../licenses/lucide-ISC.txt', import.meta.url);

const retiredPaths = [
  'tests/linux/engine/singbox',
  'tests/linux/sing-box-linux.json',
  'engine/SHA256SUMS.txt',
  'engine/SHA256SUMS-arm64.txt',
  'engine/LICENSE',
  'licenses/GPL-3.0.txt',
  'scripts/fetch-engine.ps1',
  'scripts/check-engine-config.mjs',
  'scripts/write-source-manifest.mjs',
  'scripts/build-release.ps1',
  'scripts/smoke-test-installer.ps1',
  'scripts/server-under-test-node.mjs',
  'scripts/tun-test-udp.mjs',
  'scripts/e2e-routing.mjs',
  'scripts/e2e-tun.mjs',
  'scripts/tun-control-adapter.mjs',
  'scripts/tun-test-client.mjs',
  'scripts/tun-test-diagnostics.mjs',
  'scripts/tun-test-diagnostics.ps1',
  'scripts/control-test-https.mjs',
];

const allowedCategories = new Set([
  'frozen-0.3.x',
  'oracle-fixture',
  'stand-in-refusal',
  'historical-doc',
]);

const forbiddenExceptionPrefixes = [
  '.github/workflows/',
  'packaging/',
  'scripts/',
  'tests/linux/',
  'cmd/',
  'internal/dataplane/',
  'internal/engine/',
  'internal/platform/',
  'internal/service/',
];

function gitTrackedFiles() {
  return execFileSync('git', ['ls-files'], { cwd: repoRoot, encoding: 'utf8' })
    .trim()
    .split(/\r?\n/)
    .filter(Boolean);
}

describe('sing-box retirement and packaging invariants', () => {
  it('removes retired sing-box files, pins, scripts, and GPL-3.0 bundle artifacts', () => {
    const tracked = new Set(gitTrackedFiles());
    for (const rel of retiredPaths) {
      assert.equal(tracked.has(rel), false, `${rel} must not be git-tracked`);
      for (const file of tracked) {
        assert.equal(
          file.startsWith(`${rel}/`),
          false,
          `${file} under retired directory ${rel} must not be git-tracked`,
        );
      }
      assert.equal(
        fs.existsSync(path.join(repoRoot, rel)),
        false,
        `${rel} must not exist in workspace`,
      );
    }

    const versions = JSON.parse(fs.readFileSync(versionsUrl, 'utf8'));
    for (const key of ['singBox', 'cronetGo', 'cronetNative', 'naiveproxy', 'singTun', 'gpl3']) {
      assert.equal(key in versions, false, `packaging/versions.json must not contain ${key}`);
      assert.equal(
        key in (versions.licenses ?? {}),
        false,
        `packaging/versions.json licenses must not contain ${key}`,
      );
    }

    const pkg = JSON.parse(fs.readFileSync(packageJsonUrl, 'utf8'));
    for (const scriptName of ['fetch:engine', 'build', 'test:routing']) {
      assert.equal(
        scriptName in (pkg.scripts ?? {}),
        false,
        `package.json scripts must not contain ${scriptName}`,
      );
    }

    const notices = fs.readFileSync(noticesUrl, 'utf8');
    assert.doesNotMatch(notices, /sing[-_]?box/i);
    assert.doesNotMatch(notices, /libcronet/i);
    assert.doesNotMatch(notices, /GPL-3\.0/i);

    const license = fs.readFileSync(licenseUrl, 'utf8');
    assert.match(license, /MIT License/);

    const userGuide = fs.readFileSync(userGuideUrl, 'utf8');
    assert.ok(userGuide.length > 0, 'docs/user-guide.md must be non-empty');

    const iss = fs.readFileSync(issUrl, 'utf8');
    assert.ok(iss.includes('AppName'), 'packaging/NetSwitch.iss must be readable');

    const iconStat = fs.statSync(iconUrl);
    assert.ok(iconStat.size > 0, 'assets/net-switch.ico must be non-empty');

    const lucideLicense = fs.readFileSync(lucideLicenseUrl, 'utf8');
    assert.match(lucideLicense, /ISC License/);
  });

  it('enforces exact-path and SHA-256 exception manifest for every remaining sing-box mention', () => {
    const manifest = JSON.parse(fs.readFileSync(exceptionsUrl, 'utf8'));
    assert.equal(manifest.schemaVersion, 1);
    assert.ok(Array.isArray(manifest.exceptions), 'exceptions must be an array');

    const byPath = new Map();
    for (const entry of manifest.exceptions) {
      assert.equal(typeof entry.path, 'string');
      assert.ok(entry.path.length > 0, 'exception path must be non-empty');
      assert.doesNotMatch(
        entry.path,
        /[*?[\]]/,
        `wildcard patterns are forbidden in exception manifest: ${entry.path}`,
      );
      assert.equal(
        byPath.has(entry.path),
        false,
        `duplicate exception path in manifest: ${entry.path}`,
      );
      for (const prefix of forbiddenExceptionPrefixes) {
        assert.equal(
          entry.path.startsWith(prefix),
          false,
          `exception path ${entry.path} is in forbidden active prefix ${prefix}`,
        );
      }
      assert.match(entry.sha256, /^[0-9a-f]{64}$/, `invalid sha256 for ${entry.path}`);
      assert.equal(typeof entry.matches, 'number');
      assert.ok(entry.matches >= 1, `matches must be >= 1 for ${entry.path}`);
      assert.equal(
        allowedCategories.has(entry.category),
        true,
        `invalid category ${entry.category} for ${entry.path}`,
      );
      assert.equal(typeof entry.reason, 'string');
      assert.ok(entry.reason.length > 0, `reason must be non-empty for ${entry.path}`);
      byPath.set(entry.path, entry);
    }

    const selfPaths = new Set([
      '.github/ci/singbox-exceptions.json',
      '.github/ci/retirement.test.mjs',
    ]);
    const tracked = gitTrackedFiles();
    const pattern = /sing[-_]?box/gi;
    const seen = new Set();

    for (const rel of tracked) {
      if (selfPaths.has(rel)) continue;
      const abs = path.join(repoRoot, rel);
      const buf = fs.readFileSync(abs);
      const text = buf.toString('utf8');
      const matches = text.match(pattern);
      if (!matches || matches.length === 0) continue;

      seen.add(rel);
      const expected = byPath.get(rel);
      assert.ok(
        expected,
        `unapproved sing-box mention in ${rel} (${matches.length} matches); remove it or register an exact SHA-256 exception`,
      );
      const actualSha = crypto.createHash('sha256').update(buf).digest('hex');
      assert.equal(
        actualSha,
        expected.sha256,
        `SHA-256 mismatch for ${rel}: expected ${expected.sha256}, got ${actualSha}`,
      );
      assert.equal(
        matches.length,
        expected.matches,
        `match count mismatch for ${rel}: expected ${expected.matches}, got ${matches.length}`,
      );
    }

    for (const rel of byPath.keys()) {
      assert.equal(
        seen.has(rel),
        true,
        `stale exception in .github/ci/singbox-exceptions.json: ${rel} no longer matches or is untracked`,
      );
    }
  });
});
