// Run the pure ABI contract on hosted Linux. Missing tests and skips fail.
import { spawnSync } from 'node:child_process';
const expected = new Set([
  'TestProvenanceReadDecision',
  'TestProvenanceRejectsUnboundEvidence',
  'TestProvenanceTerminalAndHealth',
  'TestProvenanceSizing',
  'TestProvenanceGoLayout',
  'TestProvenanceCInterchange',
]);
const run = spawnSync('go', ['test', '-json', '-count=1', '-p=2', './internal/engine/linux/ownerbpf'], {
  encoding: 'utf8', timeout: 180_000, maxBuffer: 8 * 1024 * 1024,
});
process.stderr.write(run.stderr ?? '');
const passed = new Set();
let skips = 0;
let failures = 0;
for (const line of (run.stdout ?? '').split('\n').filter(Boolean)) {
  const event = JSON.parse(line);
  if (event.Output) process.stdout.write(event.Output);
  if (event.Action === 'pass' && expected.has(event.Test)) passed.add(event.Test);
  if (event.Action === 'skip') skips++;
  if (event.Action === 'fail') failures++;
}
if (run.error || run.status !== 0 || skips || failures || passed.size !== expected.size) {
  throw new Error(`contract failed: exit=${run.status} error=${run.error ?? 'none'} expected=${expected.size} passed=${passed.size} skips=${skips} failures=${failures}`);
}
console.log(`PROVENANCE_CONTRACT arch=${process.arch} expected=${expected.size} passed=${passed.size} skips=${skips} kernel_proof=false`);
