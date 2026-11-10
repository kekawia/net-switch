import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';
import {night, expectedJobs, requiredNights} from '../../scripts/wintun-night.mjs';

const job = (index, change = {}) => ({
  arch: index % 2 ? 'ARM64' : 'X64', scenario: index % 4 < 2 ? 'isolated' : 'full', shard: String(1 + (index >> 2)),
  verdict: 'no_corruption_observed', passed: true, own_rejections: 0, recovery_failures: 0, own_payload_mismatches: 0,
  guard: {ignored_heads: 1, shifted_entries: 20, head_probes: 0}, reference_evidence: {payload_mismatch_incidents: 0, ring_rejection_incidents: 0, missing_transfers: 0},
  clean_exposure_connections: 240, ...change,
});
const jobs = (change = () => ({})) => Array.from({length: expectedJobs}, (_, index) => job(index, change(index)));
const earlier = (rejections, passed = true) => ({passed, totals: {own_rejections: rejections}});

test('the matrix this file counts is the one the workflow runs', () => {
  const workflow = readFileSync(new URL('../workflows/wintun-nightly.yml', import.meta.url), 'utf8');
  const shards = JSON.parse(/shard: .*'\[1,2\]' \|\| '(\[[\d,]+\])'/.exec(workflow)[1]).length;
  const scenarios = JSON.parse(/scenario: .*\|\| '(\[[^']+\])'/.exec(workflow)[1]).length;
  const runners = JSON.parse(/runner: .*\|\| '(\[[^']+\])'/.exec(workflow)[1]).length;
  assert.equal(shards * scenarios * runners, expectedJobs);
  assert.equal(requiredNights, 14);
});

test('a night passes when every job reported and passed, and recovered rejections are counted', () => {
  const r = night(jobs(index => index % 9 === 1 ? {verdict: 'recovered_rejections', own_rejections: 2} : {}));
  assert.equal(r.passed, true);
  assert.deepEqual(r.reasons, []);
  assert.equal(r.totals.own_rejections, 16);
  assert.equal(r.totals.ignored_heads, 72);
  assert.equal(r.totals.clean_exposure_connections, 72 * 240);
  assert.equal(r.consecutive_passing_nights, 1);
  assert.equal(r.regression, null, 'no rule before seven earlier nights have a record');
});

test('what the signed DLL did never changes the night', () => {
  const r = night(jobs(() => ({reference_evidence: {payload_mismatch_incidents: 1, ring_rejection_incidents: 3, missing_transfers: 12}})));
  assert.equal(r.passed, true);
  assert.deepEqual([r.totals.reference_payload_mismatches, r.totals.reference_ring_rejections, r.totals.reference_missing_transfers], [72, 216, 864]);
});

test('one failed, missing or repeated job fails the night and says why', () => {
  const wrong = night(jobs(index => index === 5 ? {verdict: 'integrity_failure', passed: false, own_payload_mismatches: 1} : {}));
  assert.equal(wrong.passed, false);
  assert.deepEqual(wrong.reasons, ['1 job: integrity_failure']);
  assert.equal(wrong.consecutive_passing_nights, 0);
  const several = night(jobs(index => index < 3 ? {verdict: 'diagnostic_incomplete', passed: false} : index === 9 ? {verdict: 'recovery_failure', passed: false} : {}));
  assert.deepEqual(several.reasons, ['3 jobs: diagnostic_incomplete', '1 job: recovery_failure']);
  const missing = night(jobs().slice(1));
  assert.deepEqual(missing.reasons, ['71 of 72 jobs reported a verdict']);
  const repeated = night([...jobs().slice(1), job(1)]);
  assert.deepEqual(repeated.reasons, ['two records name the same job']);
  assert.equal(night([]).passed, false);
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
  assert.match(over.reasons[0], /41 ring rejections in our own session, more than ten times the median of 4 over the last 7 nights/);
  // A quiet history does not make one rejection a regression.
  const quiet = Array.from({length: 9}, () => earlier(0));
  assert.equal(night(tonight(10), quiet).passed, true);
  assert.equal(night(tonight(11), quiet).passed, false);
  // Only the last fourteen recorded nights count, and a night without a record is skipped.
  const long = [...Array.from({length: 14}, () => earlier(2)), {passed: false, missing: true}, ...Array.from({length: 10}, () => earlier(900))];
  assert.deepEqual(night(tonight(1), long).regression, {nights: 14, median: 2, limit: 20});
});

test('the run of passing nights ends at the first night that failed or left no record', () => {
  assert.equal(night(jobs(), [earlier(0), earlier(0), earlier(0, false), earlier(0)]).consecutive_passing_nights, 3);
  assert.equal(night(jobs(), [{passed: false, missing: true}, earlier(0)]).consecutive_passing_nights, 1);
  assert.equal(night(jobs(), Array.from({length: 13}, () => earlier(0))).consecutive_passing_nights, 14);
  assert.equal(night(jobs().slice(1), Array.from({length: 13}, () => earlier(0))).consecutive_passing_nights, 0);
});
