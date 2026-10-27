import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { declared } from './drift.mjs';

const mapping = JSON.parse(readFileSync(new URL('../../internal/replayledger/mapping.json', import.meta.url), 'utf8'));
function missingDeclarations(mapping) {
  const entry = declared.find(item => item.from === 'internal/replayledger/ledger_test.go' && item.call === 'filepath.Join("../..", path)');
  return mapping.supportingEvidence.flatMap(e => e.tests).map(ref => ref.split('#')[0]).filter(file => !entry?.reads.includes(file));
}
test('ledger supporting test files stay inside the declared dependency reads', () => {
  assert.deepEqual(missingDeclarations(mapping), []);
  const changed = structuredClone(mapping);
  changed.supportingEvidence[0].tests.push('internal/new/replay_test.go#TestNew');
  assert.deepEqual(missingDeclarations(changed), ['internal/new/replay_test.go']);
});
