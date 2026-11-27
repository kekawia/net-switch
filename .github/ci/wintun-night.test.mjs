import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';
import {night, engineClean, expectedJobs, releaseNights} from '../../scripts/wintun-night.mjs';

// The boundary each shard measures (scripts/test-wintun-integrity.ps1, rotate).
const boundary = index => ['receive', 'ingress', 'echo', 'output', 'send', 'host'][(index >> 2) % 6];
const ratios = (index, ours, inprocess = [.93, .96, .91]) => index % 4 < 2 ? {[`${boundary(index)}/ours`]: ours} : {[`${boundary(index)}/ours`]: ours, [`${boundary(index)}/inprocess`]: inprocess};
const job = (index, change = {}) => ({
  arch: index % 2 ? 'ARM64' : 'X64', scenario: index % 4 < 2 ? 'isolated' : 'full', shard: String(1 + (index >> 2)),
  verdict: 'no_corruption_observed', passed: true, own_rejections: 0, recovery_failures: 0, own_payload_mismatches: 0,
  guard: {ignored_heads: 1, shifted_entries: 20, head_probes: 0}, reference_evidence: {payload_mismatch_incidents: 0, ring_rejection_incidents: 0, missing_transfers: 0},
  clean_exposure_connections: 240, overhead_ratios: ratios(index, [.92, .95, .9]), ...change,
});
const jobs = (change = () => ({})) => Array.from({length: expectedJobs}, (_, index) => job(index, change(index)));
const earlier = (rejections, {mismatches = 0, recoveryFailures = 0, clean = 17000} = {}) =>
  ({totals: {own_rejections: rejections, own_payload_mismatches: mismatches, recovery_failures: recoveryFailures, clean_exposure_connections: clean}});

test('the matrix this file counts is the one the workflow runs', () => {
  const workflow = readFileSync(new URL('../workflows/wintun-nightly.yml', import.meta.url), 'utf8');
  const shards = JSON.parse(/shard: .*'\[1,2\]' \|\| '(\[[\d,]+\])'/.exec(workflow)[1]).length;
  const scenarios = JSON.parse(/scenario: .*\|\| '(\[[^']+\])'/.exec(workflow)[1]).length;
  const runners = JSON.parse(/runner: .*\|\| '(\[[^']+\])'/.exec(workflow)[1]).length;
  assert.equal(shards * scenarios * runners, expectedJobs);
  assert.equal(releaseNights, 14);
});

test('a night with nothing found in our own engine passes, and recovered rejections are counted', () => {
  const r = night(jobs(index => index % 9 === 1 ? {verdict: 'recovered_rejections', own_rejections: 2} : {}));
  assert.equal(r.passed, true);
  assert.deepEqual([r.findings, r.warnings], [[], []]);
  assert.equal(r.totals.own_rejections, 16);
  assert.equal(r.totals.ignored_heads, 72);
  assert.equal(r.totals.clean_exposure_connections, 72 * 240);
  assert.equal(r.clean_nights, 1);
  assert.equal(r.regression, null, 'no rule before seven earlier nights have a record');
});

test('what the signed DLL did never changes the night', () => {
  const r = night(jobs(() => ({reference_evidence: {payload_mismatch_incidents: 1, ring_rejection_incidents: 3, missing_transfers: 12}})));
  assert.equal(r.passed, true);
  assert.deepEqual([r.totals.reference_payload_mismatches, r.totals.reference_ring_rejections, r.totals.reference_missing_transfers], [72, 216, 864]);
});

test('wrong bytes or an unrecovered rejection in our own session fail the night and name the shards', () => {
  const wrong = night(jobs(index => index === 5 ? {verdict: 'integrity_failure', passed: false, own_payload_mismatches: 1, detail: ['--- FAIL: TestWintunPerformance']} : {}));
  assert.equal(wrong.passed, false);
  assert.deepEqual(wrong.findings, ['1 job: our own session delivered bytes that differ from what was sent (ARM64/isolated/2)']);
  assert.deepEqual(wrong.warnings, []);
  assert.deepEqual(wrong.failed_jobs, [{job: 'ARM64/isolated/2', verdict: 'integrity_failure', detail: ['--- FAIL: TestWintunPerformance']}]);
  assert.equal(wrong.clean_nights, 0);
  // A count is a finding even when the job's verdict was something else.
  const counted = night(jobs(index => index === 9 ? {verdict: 'diagnostic_incomplete', passed: false, recovery_failures: 1} : {}));
  assert.deepEqual(counted.findings, ['1 job: a ring rejection in our own session did not recover (ARM64/isolated/3)']);
  assert.deepEqual(counted.warnings, [], 'a job is named once, under its finding');
});

// 2026-11-27: the owner dropped "14 passing nights in a row". Nights 11-11 to
// 11-27 failed 9 times, every time on the tests themselves, never on our engine.
test('what a night could not show is a warning and never fails it', () => {
  // Shards are ordered by arch, scenario and number, whatever the input order.
  const several = night(jobs(index => index < 3 ? {verdict: 'diagnostic_incomplete', passed: false} : index === 9 ? {verdict: 'test_failed', passed: false} : {}).reverse());
  assert.equal(several.passed, true);
  assert.deepEqual(several.findings, []);
  assert.deepEqual(several.warnings, [
    '3 jobs: diagnostic_incomplete (ARM64/isolated/1, X64/full/1, X64/isolated/1)',
    '1 job: test_failed (ARM64/isolated/3)',
  ]);
  assert.deepEqual(several.failed_jobs.map(j => `${j.job}:${j.verdict}`), [
    'ARM64/isolated/1:diagnostic_incomplete',
    'ARM64/isolated/3:test_failed',
    'X64/full/1:diagnostic_incomplete',
    'X64/isolated/1:diagnostic_incomplete',
  ]);
  const missing = night(jobs().slice(1));
  assert.deepEqual(missing.warnings, ['71 of 72 jobs reported a verdict']);
  assert.equal(missing.passed, true);
  const repeated = night([...jobs().slice(1), job(1)]);
  assert.deepEqual(repeated.warnings, ['two records name the same job']);
  // Without one clean transfer the night showed nothing, and does not pass.
  const empty = night([]);
  assert.equal(empty.passed, false);
  assert.deepEqual(empty.findings, []);
  assert.deepEqual(empty.warnings, ['0 of 72 jobs reported a verdict', 'no clean transfers: this night shows nothing about our own engine']);
});

test('slow instrumentation is reported pooled per boundary, and is only a warning', () => {
  // Index 53 is ARM64/isolated/14, an ingress shard, as on 2026-11-23 and 11-26.
  const r = night(jobs(index => index % 4 === 1 && boundary(index) === 'ingress' ? {verdict: 'diagnostic_invalid', passed: false, clean_exposure_connections: 0, overhead_ratios: ratios(index, [.78, .79, .81])} : {}));
  assert.equal(r.passed, true);
  assert.deepEqual(r.warnings, ['3 jobs: diagnostic_invalid (ARM64/isolated/2, ARM64/isolated/8, ARM64/isolated/14)']);
  assert.equal(r.overhead['ARM64/isolated/ingress/ours'].median, .79);
  assert.equal(r.overhead['ARM64/isolated/receive/ours'].median, .92, 'boundaries are never pooled together');
  assert.equal(r.totals.clean_exposure_connections, 69 * 240, 'an invalid job earns no clean transfers');
});

test('rejections more than ten times the trailing median fail the night, once seven nights exist', () => {
  const tonight = rejections => jobs(index => index === 0 ? {verdict: 'recovered_rejections', own_rejections: rejections} : {});
  const six = Array.from({length: 6}, () => earlier(4));
  assert.equal(night(tonight(500), six).passed, true, 'six nights are too few for the rule');
  const seven = [...six, earlier(6)];
  const within = night(tonight(40), seven);
  assert.deepEqual(within.regression, {nights: 7, median: 4, limit: 40});
  assert.equal(within.passed, true);
  const over = night(tonight(41), seven);
  assert.equal(over.passed, false);
  assert.match(over.findings[0], /41 ring rejections in our own session, more than ten times the median of 4 over the last 7 nights/);
  assert.equal(engineClean(over), false);
  // A quiet history does not make one rejection a regression.
  const quiet = Array.from({length: 9}, () => earlier(0));
  assert.equal(night(tonight(10), quiet).passed, true);
  assert.equal(night(tonight(11), quiet).passed, false);
  // Only the last fourteen recorded nights count, and a night without a record is skipped.
  const long = [...Array.from({length: 14}, () => earlier(2)), {missing: true}, ...Array.from({length: 10}, () => earlier(900))];
  assert.deepEqual(night(tonight(1), long).regression, {nights: 14, median: 2, limit: 20});
});

test('the night counts what the release would read: the last fourteen nights without a finding', () => {
  assert.equal(night(jobs(), Array.from({length: 20}, () => earlier(0))).clean_nights, 14);
  // A finding, a night that left no record and a night without clean transfers each cost one.
  const history = [earlier(0), earlier(0, {mismatches: 3}), {missing: true}, earlier(0, {clean: 0}), ...Array.from({length: 12}, () => earlier(0))];
  assert.equal(night(jobs(), history).clean_nights, 11);
  // Records written before 2026-11-27 are judged by their totals, not their old pass flag.
  assert.equal(engineClean({passed: false, reasons: ['1 job: diagnostic_invalid (ARM64/isolated/14)'], ...earlier(24)}), true);
  assert.equal(engineClean({passed: false, reasons: ['2 jobs: integrity_failure (ARM64/full/6, X64/full/7)'], ...earlier(41, {mismatches: 3})}), false);
});
