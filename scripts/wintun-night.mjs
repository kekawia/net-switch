// The night's verdict over every TCP integrity job: the release gate approved
// on 2026-11-10 (internal/wintun/README.md, "Release gate").
//
// A night passes when every job of the matrix reported, and passed, in our own
// session mode on x64 and ARM64: no delivered byte wrong, every ring rejection
// recovered, every transfer finished. Recovered rejections are counted, and a
// count more than ten times the trailing median fails the night as a
// regression. The signed DLL is a reference: its totals are printed and never
// change the verdict. The release needs 14 passing nights in a row.
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

export const expectedJobs = 72; // 18 shards, 2 scenarios, 2 runners
export const requiredNights = 14;
const trailingNights = 14, nightsBeforeTheRegressionRule = 7;

const median = values => {
  const sorted = [...values].sort((a, b) => a - b), middle = sorted.length >> 1;
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
};

// night judges tonight's job records (nightRecord in
// wintun-integrity-summary.mjs) against earlier nights, newest first. An
// earlier night without a record is {passed:false, missing:true}: it ends the
// run of passing nights and stays out of the median.
export function night(records, history = [], expected = expectedJobs) {
  const reasons = [];
  if (new Set(records.map(r => `${r.arch}/${r.scenario}/${r.shard}`)).size !== records.length) reasons.push('two records name the same job');
  if (records.length !== expected) reasons.push(`${records.length} of ${expected} jobs reported a verdict`);
  const failed = new Map();
  for (const r of records) if (!r.passed) failed.set(r.verdict, (failed.get(r.verdict) ?? 0) + 1);
  for (const [verdict, count] of failed) reasons.push(`${count} ${count === 1 ? 'job' : 'jobs'}: ${verdict}`);
  const sum = pick => records.reduce((n, r) => n + (Number(pick(r)) || 0), 0);
  const totals = {
    own_rejections: sum(r => r.own_rejections), recovery_failures: sum(r => r.recovery_failures), own_payload_mismatches: sum(r => r.own_payload_mismatches),
    ignored_heads: sum(r => r.guard?.ignored_heads), shifted_entries: sum(r => r.guard?.shifted_entries), head_probes: sum(r => r.guard?.head_probes),
    reference_payload_mismatches: sum(r => r.reference_evidence?.payload_mismatch_incidents), reference_ring_rejections: sum(r => r.reference_evidence?.ring_rejection_incidents),
    reference_missing_transfers: sum(r => r.reference_evidence?.missing_transfers), clean_exposure_connections: sum(r => r.clean_exposure_connections),
  };
  const earlier = history.filter(h => Number.isFinite(h.totals?.own_rejections)).slice(0, trailingNights).map(h => h.totals.own_rejections);
  let regression = null;
  if (earlier.length >= nightsBeforeTheRegressionRule) {
    // A median of zero would make any rejection a regression; one is the floor.
    regression = {nights: earlier.length, median: median(earlier), limit: 10 * Math.max(median(earlier), 1)};
    if (totals.own_rejections > regression.limit) reasons.push(`${totals.own_rejections} ring rejections in our own session, more than ten times the median of ${regression.median} over the last ${earlier.length} nights`);
  }
  const passed = reasons.length === 0;
  let streak = 0;
  if (passed) for (streak = 1; streak <= history.length && history[streak - 1].passed; streak++);
  return {passed, reasons, jobs: records.length, expected_jobs: expected, totals, regression, consecutive_passing_nights: streak, required_nights: requiredNights};
}

// Earlier scheduled nights, newest first, read from their own night records.
function earlierNights(directory) {
  const runs = JSON.parse(execFileSync('gh', ['run', 'list', '--workflow', 'wintun-nightly.yml', '--event', 'schedule', '--status', 'completed', '--limit', '40', '--json', 'databaseId'], {encoding: 'utf8'}))
    .map(run => String(run.databaseId)).filter(id => id !== process.env.GITHUB_RUN_ID).slice(0, trailingNights + requiredNights);
  return runs.map(id => {
    const target = join(directory, id);
    try {
      execFileSync('gh', ['run', 'download', id, '--name', 'wintun-night', '--dir', target], {stdio: 'ignore'});
      return JSON.parse(readFileSync(join(target, 'wintun-night.json'), 'utf8'));
    } catch {
      return {run: id, passed: false, missing: true};
    }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted') throw Error('Hosted CI only');
  const [results, output] = process.argv.slice(2);
  const records = existsSync(results) ? readdirSync(results, {recursive: true}).filter(name => String(name).endsWith('.json')).map(name => JSON.parse(readFileSync(join(results, String(name)), 'utf8'))) : [];
  const scheduled = process.env.GITHUB_EVENT_NAME === 'schedule';
  const result = {run: process.env.GITHUB_RUN_ID, sha: process.env.GITHUB_SHA, event: process.env.GITHUB_EVENT_NAME, ...night(records, earlierNights(join(process.env.RUNNER_TEMP, 'earlier-nights')))};
  writeFileSync(output, JSON.stringify(result));
  console.log(`NIGHT_SUMMARY ${JSON.stringify(result)}`);
  const t = result.totals;
  const lines = [
    `### Wintun night: ${result.passed ? 'passed' : 'not passed'}`,
    '',
    result.passed ? `Passing nights in a row: **${result.consecutive_passing_nights}** of ${result.required_nights}.` : `Reasons:\n${result.reasons.map(reason => `- ${reason}`).join('\n')}`,
    scheduled ? '' : '\nThis run was started by hand. Only scheduled nights count towards the 14.',
    '',
    `Our own session, ${result.jobs} of ${result.expected_jobs} jobs: ${t.own_payload_mismatches} delivered mismatches, ${t.own_rejections} ring rejections, ${t.recovery_failures} recovery failures, ${t.clean_exposure_connections} clean transfers.`,
    `Writer guard: ${t.ignored_heads} Heads refused, ${t.shifted_entries} entries shifted, ${t.head_probes} stall probes.`,
    result.regression ? `Rejections against earlier nights: median ${result.regression.median} over ${result.regression.nights} nights, limit ${result.regression.limit}.` : 'The regression rule starts once seven earlier nights have a record.',
    '',
    `Signed DLL, reference only: ${t.reference_payload_mismatches} delivered mismatches, ${t.reference_ring_rejections} ring rejections, ${t.reference_missing_transfers} transfers not finished.`,
    '',
  ];
  if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n'));
  process.exitCode = result.passed ? 0 : 1;
}
