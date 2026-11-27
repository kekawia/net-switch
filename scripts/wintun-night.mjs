// The night's verdict over every TCP integrity job (internal/wintun/README.md,
// "Release gate", as the owner changed it on 2026-11-27).
//
// A night fails only on a finding in our own engine, on x64 or ARM64: a
// delivered byte that differs from what was sent, a ring rejection that did
// not recover, or more rejections than ten times the trailing median. What a
// night could not show (a job missing or repeated, a test that failed or did
// not finish, instrumentation too slow to qualify) is a warning: printed, never
// the verdict. The signed DLL is a reference: its totals are printed and never
// change the verdict. The release reads the last releaseNights scheduled
// nights and needs each to have left a record without a finding.
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { minimumOverheadRatio } from './wintun-integrity-summary.mjs';

export const expectedJobs = 72; // 18 shards, 2 scenarios, 2 runners
export const releaseNights = 14;
const trailingNights = 14, nightsBeforeTheRegressionRule = 7;

// engineClean says whether a night record, of any version, found nothing in
// our own engine and carried evidence: some clean transfers. A night that
// left no record is never clean.
export function engineClean(record) {
  const t = record?.totals;
  if (!t || record.missing) return false;
  const regressed = Boolean(record.regression) && Number(t.own_rejections) > record.regression.limit;
  return Number(t.own_payload_mismatches) === 0 && Number(t.recovery_failures) === 0 && !regressed && Number(t.clean_exposure_connections) > 0;
}

const median = values => {
  const sorted = [...values].sort((a, b) => a - b), middle = sorted.length >> 1;
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
};

const jobName = r => `${r.arch}/${r.scenario}/${r.shard}`;
const jobOrder = (a, b) => String(a.arch).localeCompare(String(b.arch)) || String(a.scenario).localeCompare(String(b.scenario))
  || (Number(a.shard) - Number(b.shard)) || String(a.shard).localeCompare(String(b.shard));

// night judges tonight's job records (nightRecord in
// wintun-integrity-summary.mjs) against earlier nights, newest first. An
// earlier night without a record is {missing:true}: it stays out of the
// median and is never counted as clean.
export function night(tonight, history = [], expected = expectedJobs) {
  const findings = [], warnings = [];
  const jobs = (records, what) => `${records.length} ${records.length === 1 ? 'job' : 'jobs'}: ${what} (${records.map(jobName).join(', ')})`;
  const records = [...tonight].sort(jobOrder);
  const wrong = records.filter(r => r.verdict === 'integrity_failure' || Number(r.own_payload_mismatches) > 0);
  if (wrong.length) findings.push(jobs(wrong, 'our own session delivered bytes that differ from what was sent'));
  const unrecovered = records.filter(r => r.verdict === 'recovery_failure' || Number(r.recovery_failures) > 0);
  if (unrecovered.length) findings.push(jobs(unrecovered, 'a ring rejection in our own session did not recover'));
  if (new Set(tonight.map(jobName)).size !== tonight.length) warnings.push('two records name the same job');
  if (tonight.length !== expected) warnings.push(`${tonight.length} of ${expected} jobs reported a verdict`);
  const failed = new Map();
  const failedRecords = records.filter(r => !r.passed && !wrong.includes(r) && !unrecovered.includes(r));
  for (const r of failedRecords) failed.set(r.verdict, [...(failed.get(r.verdict) ?? []), r]);
  for (const [verdict, list] of failed) warnings.push(jobs(list, verdict));
  const failedJobs = records.filter(r => !r.passed).map(r => ({job: jobName(r), verdict: r.verdict, ...(r.detail?.length ? {detail: r.detail} : {})}));
  // Overhead is reported, not judged: pooled per runner, scenario, boundary
  // and mode. A job under the bound already earned no clean credit.
  const pooled = new Map();
  for (const r of records) for (const [boundaryMode, ratios] of Object.entries(r.overhead_ratios ?? {})) {
    const key = `${r.arch}/${r.scenario}/${boundaryMode}`;
    pooled.set(key, [...(pooled.get(key) ?? []), ...ratios]);
  }
  const overhead = Object.fromEntries([...pooled].sort(([a], [b]) => a.localeCompare(b)).map(([key, ratios]) => [key, {pairs: ratios.length, median: ratios.length ? median(ratios) : null}]));
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
    if (totals.own_rejections > regression.limit) findings.push(`${totals.own_rejections} ring rejections in our own session, more than ten times the median of ${regression.median} over the last ${earlier.length} nights`);
  }
  // A night without one clean transfer showed nothing about our engine, so
  // it cannot pass either; the release would not count it.
  if (!findings.length && !totals.clean_exposure_connections) warnings.push('no clean transfers: this night shows nothing about our own engine');
  const result = {passed: findings.length === 0 && totals.clean_exposure_connections > 0, findings, warnings, failed_jobs: failedJobs, jobs: records.length, expected_jobs: expected, totals, regression, overhead};
  // What the release would read today: this night and the ones before it.
  result.clean_nights = [result, ...history].slice(0, releaseNights).filter(engineClean).length;
  result.release_nights = releaseNights;
  return result;
}

// Earlier scheduled nights, newest first, read from their own night records.
function earlierNights(directory) {
  const runs = JSON.parse(execFileSync('gh', ['run', 'list', '--workflow', 'wintun-nightly.yml', '--event', 'schedule', '--status', 'completed', '--limit', '40', '--json', 'databaseId'], {encoding: 'utf8'}))
    .map(run => String(run.databaseId)).filter(id => id !== process.env.GITHUB_RUN_ID).slice(0, Math.max(trailingNights, releaseNights));
  return runs.map(id => {
    const target = join(directory, id);
    try {
      execFileSync('gh', ['run', 'download', id, '--name', 'wintun-night', '--dir', target], {stdio: 'ignore'});
      return JSON.parse(readFileSync(join(target, 'wintun-night.json'), 'utf8'));
    } catch {
      return {run: id, missing: true};
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
    `\nJob \`${j.job}\` (${j.verdict}):\n${j.detail.map(line => `- ${String(line).replaceAll('<', '&lt;')}`).join('\n')}`).join('\n');
  const list = items => items.map(item => `- ${item}`).join('\n');
  const lines = [
    `### Wintun night: ${result.findings.length ? 'a finding in our own engine' : result.passed ? 'nothing found in our own engine' : 'no evidence'}`,
    '',
    result.findings.length ? `Findings (they block a release for ${result.release_nights} nights):\n${list(result.findings)}` : '',
    result.warnings.length ? `Warnings (the night could not show these; they never block a release):\n${list(result.warnings)}` : '',
    details,
    '',
    `Nights without a finding, of the last ${result.release_nights} recorded: **${result.clean_nights}**.${scheduled ? '' : ' This run was started by hand; the release reads only scheduled nights.'}`,
    '',
    `Our own session, ${result.jobs} of ${result.expected_jobs} jobs: ${t.own_payload_mismatches} delivered mismatches, ${t.own_rejections} ring rejections, ${t.recovery_failures} recovery failures, ${t.clean_exposure_connections} clean transfers.`,
    `Writer guard: ${t.ignored_heads} Heads refused, ${t.shifted_entries} entries shifted, ${t.head_probes} stall probes.`,
    result.regression ? `Rejections against earlier nights: median ${result.regression.median} over ${result.regression.nights} nights, limit ${result.regression.limit}.` : 'The regression rule starts once seven earlier nights have a record.',
    `Instrumentation overhead, pooled median per runner, scenario, boundary and mode (a job under ${minimumOverheadRatio} earns no clean transfers):${Object.entries(result.overhead).map(([key, o]) => `${key} ${o.median?.toFixed(3) ?? 'none'} over ${o.pairs} pairs`).join('; ')}.`,
    '',
    `Signed DLL, reference only: ${t.reference_payload_mismatches} delivered mismatches, ${t.reference_ring_rejections} ring rejections, ${t.reference_missing_transfers} transfers not finished.`,
    '',
  ];
  if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n'));
  process.exitCode = result.passed ? 0 : 1;
}
