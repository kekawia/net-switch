import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { engineClean, releaseNights } from '../../scripts/wintun-night.mjs';

// The release reads the last releaseNights scheduled nights on main. Each must
// have left a record that found nothing in our own engine: no wrong byte, no
// unrecovered rejection, no rejection regression, and some clean transfers.
// A night's warnings (a test that failed or did not finish, a job missing,
// slow instrumentation) never block it (owner decision, 2026-11-27).
export function validateNight(run, record) {
  assert.equal(run.event, 'schedule');
  assert.equal(run.head_branch, 'main');
  assert.equal(run.status, 'completed');
  assert.equal(record.run, String(run.id));
  assert.equal(record.sha, run.head_sha);
  assert.equal(record.event, 'schedule');
  assert(engineClean(record), `scheduled night ${run.id} found something in our own engine: ${JSON.stringify(record.findings ?? record.reasons ?? record.totals)}`);
}

export function checkNights(repo, nights) {
  const gh = args=>execFileSync('gh',args,{encoding:'utf8',timeout:45000,windowsHide:true});
  const endpoint='repos/'+repo+'/actions/workflows/wintun-nightly.yml/runs?event=schedule&branch=main&status=completed&per_page='+nights;
  const runs=JSON.parse(gh(['api',endpoint])).workflow_runs;
  assert.equal(runs.length,nights,'too few recorded scheduled nights');
  assert.equal(new Set(runs.map(r=>r.id)).size,nights);
  assert.equal(new Set(runs.map(r=>r.created_at.slice(0,10))).size,nights,'two runs occurred on the same night');
  const temp=mkdtempSync(join(tmpdir(),'netswitch-release-nights-'));
  try {
    for(const run of runs){
      const dir=join(temp,String(run.id));
      try { gh(['run','download',String(run.id),'--repo',repo,'--name','wintun-night','--dir',dir]); }
      catch { assert.fail('scheduled night '+run.id+' left no record'); }
      validateNight(run,JSON.parse(readFileSync(join(dir,'wintun-night.json'),'utf8')));
    }
  } finally { rmSync(temp,{recursive:true,force:true}); }
  console.log('Verified '+nights+' scheduled Wintun nights without a finding in our own engine.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  assert.equal(process.env.GITHUB_REPOSITORY_ID, '1418987447');
  checkNights(process.env.GITHUB_REPOSITORY, releaseNights);
}
