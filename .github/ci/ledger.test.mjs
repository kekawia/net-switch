import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { declared } from './drift.mjs';
import { readWorkflow } from './workflows.mjs';

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

test('replay CI preserves the native shell, full test selection and both exit codes', () => {
  const workflow = readWorkflow(readFileSync(new URL('../workflows/ci.yml', import.meta.url), 'utf8'));
  for (const jobName of ['go1-windows', 'go1-linux']) {
    const step = workflow.jobs.get(jobName).steps.find(step => step.keys.name?.inline === 'Internal packages and native replay coverage');
    assert.equal(step.keys.shell.inline, 'pwsh');
    assert.match(step.run, /go test -json -count=1 -timeout=10m \.\/internal\/\.\.\. \.\/cmd\/\.\.\. \.\/tests\/\.\.\./);
    assert.match(step.run, /\$script:replayTestExit = \$LASTEXITCODE\s*\} \| & \.\/bin\/replay-report\.exe/);
    assert.match(step.run, /\$replayReportExit = \$LASTEXITCODE/);
    assert.match(step.run, /if \(\$script:replayTestExit -ne 0\) \{ exit \$script:replayTestExit \}/);
    assert.match(step.run, /if \(\$replayReportExit -ne 0\) \{ exit \$replayReportExit \}/);
    assert.doesNotMatch(step.run, /Tee-Object|Out-File|RedirectStandardOutput/);
  }
});
