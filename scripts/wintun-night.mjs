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
import { minimumOverheadRatio } from './wintun-integrity-summary.mjs';

export const expectedJobs = 72; // 18 shards, 2 scenarios, 2 runners
export const requiredNights = 14;
const trailingNights = 14, nightsBeforeTheRegressionRule = 7;

const median = values => {
  const sorted = [...values].sort((a, b) => a - b), middle = sorted.length >> 1;
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
};

const jobName = r => `${r.arch}/${r.scenario}/${r.shard}`;
const jobOrder = (a, b) => String(a.arch).localeCompare(String(b.arch)) || String(a.scenario).localeCompare(String(b.scenario))
  || (Number(a.shard) - Number(b.shard)) || String(a.shard).localeCompare(String(b.shard));

// night judges tonight's job records (nightRecord in
// wintun-integrity-summary.mjs) against earlier nights, newest first. An
// earlier night without a record is {passed:false, missing:true}: it ends the
// run of passing nights and stays out of the median.
export function night(tonight, history = [], expected = expectedJobs) {
  const reasons = [];
  if (new Set(tonight.map(jobName)).size !== tonight.length) reasons.push('two records name the same job');
  if (tonight.length !== expected) reasons.push(`${tonight.length} of ${expected} jobs reported a verdict`);
  // A job's own overhead median rests on three pairs. One whose only
  // shortfall is that median is judged by the night's pooled pairs for its
  // runner, scenario, boundary and mode (three jobs, nine pairs), against the
  // same bound; anything else it found stands (wintun-integrity-summary.mjs,
  // overhead_pending). Boundaries are never pooled together: ingress costs
  // more than the others, and a slowdown at one boundary must show.
  const pooled = new Map();
  for (const r of tonight) for (const [boundaryMode, ratios] of Object.entries(r.overhead_ratios ?? {})) {
    const key = `${r.arch}/${r.scenario}/${boundaryMode}`;
    pooled.set(key, [...(pooled.get(key) ?? []), ...ratios]);
  }
  const overhead = Object.fromEntries([...pooled].sort(([a], [b]) => a.localeCompare(b)).map(([key, ratios]) => [key, {pairs: ratios.length, median: ratios.length ? median(ratios) : null}]));
  const pooledPasses = (r, mode) => {
    const keys = Object.keys(r.overhead_ratios ?? {}).filter(key => key.endsWith(`/${mode}`));
    return keys.length > 0 && keys.every(key => overhead[`${r.arch}/${r.scenario}/${key}`]?.median >= minimumOverheadRatio);
  };
  const judgedByNight = [];
  const records = tonight.map(r => {
    if (r.passed || !r.overhead_pending) return r;
    if (!r.overhead_pending.invalid_modes.every(mode => pooledPasses(r, mode))) return r;
    judgedByNight.push(jobName(r));
    return {...r, verdict: r.overhead_pending.verdict, passed: ['no_corruption_observed', 'recovered_rejections'].includes(r.overhead_pending.verdict)};
  });
  const failed = new Map();
  const failedRecords = [...records.filter(r => !r.passed)].sort(jobOrder);
  for (const r of failedRecords) {
    const names = failed.get(r.verdict) ?? [];
    names.push(jobName(r));
    failed.set(r.verdict, names);
  }
  for (const [verdict, names] of failed) reasons.push(`${names.length} ${names.length === 1 ? 'job' : 'jobs'}: ${verdict} (${names.join(', ')})`);
  const failedJobs = failedRecords.map(r => ({job: jobName(r), verdict: r.verdict, ...(r.detail?.length ? {detail: r.detail} : {})}));
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
  return {passed, reasons, failed_jobs: failedJobs, jobs: records.length, expected_jobs: expected, totals, regression, consecutive_passing_nights: streak, required_nights: requiredNights,
    overhead, overhead_judged_by_night: judgedByNight.sort()};
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
  const details = result.failed_jobs.filter(j => j.detail?.length).map(j =>
    `\nFailed job \`${j.job}\` (${j.verdict}):\n${j.detail.map(line => `- ${String(line).replaceAll('<', '&lt;')}`).join('\n')}`).join('\n');
  const lines = [
    `### Wintun night: ${result.passed ? 'passed' : 'not passed'}`,
    '',
    result.passed ? `Passing nights in a row: **${result.consecutive_passing_nights}** of ${result.required_nights}.` : `Reasons:\n${result.reasons.map(reason => `- ${reason}`).join('\n')}${details}`,
    scheduled ? '' : '\nThis run was started by hand. Only scheduled nights count towards the 14.',
    '',
    `Our own session, ${result.jobs} of ${result.expected_jobs} jobs: ${t.own_payload_mismatches} delivered mismatches, ${t.own_rejections} ring rejections, ${t.recovery_failures} recovery failures, ${t.clean_exposure_connections} clean transfers.`,
    `Writer guard: ${t.ignored_heads} Heads refused, ${t.shifted_entries} entries shifted, ${t.head_probes} stall probes.`,
    result.regression ? `Rejections against earlier nights: median ${result.regression.median} over ${result.regression.nights} nights, limit ${result.regression.limit}.` : 'The regression rule starts once seven earlier nights have a record.',
    `Instrumentation overhead, pooled median per runner, scenario, boundary and mode (bound ${minimumOverheadRatio}):${Object.entries(result.overhead).map(([key, o]) => `${key} ${o.median?.toFixed(3) ?? 'none'} over ${o.pairs} pairs`).join('; ')}.`,
    result.overhead_judged_by_night.length ? `Judged by the pooled overhead instead of their own three pairs: ${result.overhead_judged_by_night.join(', ')}.` : '',
    '',
    `Signed DLL, reference only: ${t.reference_payload_mismatches} delivered mismatches, ${t.reference_ring_rejections} ring rejections, ${t.reference_missing_transfers} transfers not finished.`,
    '',
  ];
  if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n'));
  process.exitCode = result.passed ? 0 : 1;
}
