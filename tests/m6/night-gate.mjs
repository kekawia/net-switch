import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { expectedJobs, requiredNights } from '../../scripts/wintun-night.mjs';

export function validateNight(run, record, jobs) {
  assert.equal(run.event, 'schedule');
  assert.equal(run.head_branch, 'main');
  assert.equal(run.status, 'completed');
  assert.equal(run.conclusion, 'success');
  assert.equal(record.run, String(run.id));
  assert.equal(record.sha, run.head_sha);
  assert.equal(record.event, 'schedule');
  assert.equal(record.passed, true);
  assert.equal(record.jobs, jobs);
  assert.equal(record.expected_jobs, jobs);
  assert.deepEqual(record.reasons, []);
  assert.deepEqual(record.failed_jobs, []);
  assert.equal(record.totals.own_payload_mismatches,0);
  assert.equal(record.totals.recovery_failures,0);
  assert(record.totals.clean_exposure_connections > 0);
}

export function checkNights(repo, required, jobs) {
  const gh = args=>execFileSync('gh',args,{encoding:'utf8',timeout:45000,windowsHide:true});
  const endpoint='repos/'+repo+'/actions/workflows/wintun-nightly.yml/runs?event=schedule&branch=main&per_page='+required;
  const runs=JSON.parse(gh(['api',endpoint])).workflow_runs;
  assert.equal(runs.length,required,'too few recorded scheduled nights');
  assert.equal(new Set(runs.map(r=>r.id)).size,required);
  assert.equal(new Set(runs.map(r=>r.created_at.slice(0,10))).size,required,'two runs occurred on the same night');
  const temp=mkdtempSync(join(tmpdir(),'netswitch-release-nights-'));
  try {
    for(let i=0;i<runs.length;i++){
      const run=runs[i];
      const dir=join(temp,String(run.id));
      assert.equal(run.conclusion,'success','scheduled night '+run.id+' has not passed');
      gh(['run','download',String(run.id),'--repo',repo,'--name','wintun-night','--dir',dir]);
      const record=JSON.parse(readFileSync(join(dir,'wintun-night.json'),'utf8'));
      validateNight(run,record,jobs);
      if(i===0) assert(record.consecutive_passing_nights>=required,'latest nightly verdict has not reached the release streak');
    }
  } finally { rmSync(temp,{recursive:true,force:true}); }
  console.log('Verified '+required+' scheduled Wintun night records.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  assert.equal(process.env.GITHUB_REPOSITORY_ID, '1418987447');
  checkNights(process.env.GITHUB_REPOSITORY, requiredNights, expectedJobs);
}
