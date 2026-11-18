import assert from 'node:assert/strict';
import test from 'node:test';
import { compare } from '../../tests/m6/compare.mjs';
import { validateNight } from '../../tests/m6/night-gate.mjs';

function report(baseline) {
  const samples = [], windows = [], memory = [];
  for(const streams of [1,8]) for(const pass of [0,1,2]) {
    const epoch=Date.UTC(2026,0,1,0,streams,pass*10);
    const at=offset=>new Date(epoch+offset).toISOString();
    samples.push({streams,pass,bytes:1e9,mbps:100,startUtc:at(0),endUtc:at(4000)});
    windows.push({Streams:streams,Pass:pass,Bytes:1e9,cpuSeconds:1});
    for(const offset of [500,2000]) memory.push({utc:at(offset),workingSetBytes:1024});
  }
  return {runner:'same',commit:'candidate',arch:'x64',release:baseline?'0.3.2':'1.0.0',
    installerHash:baseline?'0193582d10fcede15f3119b3ec72a20dfad7ad94b87f8465b5e90e835865791b':'f'.repeat(64),
    images:[{hash:'a'.repeat(64)},{hash:'b'.repeat(64)}],gatewayConnections:1000,
    traffic:{connectCount:400,connections:1000,p95ms:2,p99ms:3,samples},accounting:{windows},memory};
}
test('M6 compares measured rates in the right direction and requires matched coverage',()=>{
  const old=report(true),fresh=report(false);
  assert.equal(compare(old,fresh).results.length,8);
  assert.deepEqual(compare(old,fresh).failures,[]);
  fresh.traffic.samples.filter(s=>s.streams===8).forEach(s=>{s.mbps=89});
  fresh.accounting.windows.filter(s=>s.Streams===1).forEach(s=>{s.cpuSeconds=1.2});
  assert.deepEqual(compare(old,fresh).failures.map(r=>r.metric).sort(),['cpuSecondsPerGB1','mbps8']);
  for(const change of [r=>r.memory=[],r=>r.runner='other',r=>r.gatewayConnections--,r=>r.traffic.samples.pop(),r=>r.accounting.windows.pop()]){
    const broken=report(false); change(broken);
    assert.throws(()=>compare(old,broken));
  }
});
test('a nightly release record must match the scheduled run and show complete exposure',()=>{
  const run={id:1,head_sha:'abc',head_branch:'main',status:'completed',conclusion:'success',event:'schedule'};
  const good={sha:'abc',run:'1',event:'schedule',passed:true,jobs:72,expected_jobs:72,reasons:[],failed_jobs:[],
    totals:{own_payload_mismatches:0,recovery_failures:0,clean_exposure_connections:40}};
  validateNight(run,good,72);
  for(const patch of [{sha:'old'},{event:'workflow_dispatch'},{jobs:71},{passed:false},{totals:{...good.totals,recovery_failures:1}}]){
    assert.throws(()=>validateNight(run,{...good,...patch},72));
  }
});
