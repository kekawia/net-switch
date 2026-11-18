import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

test('a trailing stderr redirection terminates with or without a final newline', () => {
  for (const ending of ['', '\n']) {
    const input = `node scripts/check.mjs 2>&1${ending}`;
    const code = `import { commands } from ${JSON.stringify(new URL('./drift.mjs', import.meta.url).href)}; console.log(JSON.stringify(commands(${JSON.stringify(input)})));`;
    // A regression must fail the case, not spin forever inside the test worker.
    const result = spawnSync(process.execPath, ['--max-old-space-size=2048', '--input-type=module', '-e', code], {
      encoding: 'utf8', timeout: 10000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.length, 1);
    assert.deepEqual(parsed[0].slice(0, 2), [{ text: 'node', dynamic: false }, { text: 'scripts/check.mjs', dynamic: false }]);
  }
});
