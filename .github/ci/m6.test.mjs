import assert from 'node:assert/strict';
import test from 'node:test';
import { compare } from '../../tests/m6/compare.mjs';
import { validateNight } from '../../tests/m6/night-gate.mjs';
import { latencySummary } from '../../tests/m6/latency.mjs';

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

test('the first 400 and all 2400 connection times are independently verified', () => {
  function extended(baseline) {
    const r = report(baseline);
    r.traffic.connectBlocks = Array.from({length:6}, () => Array(400).fill(2));
    for (const sample of r.traffic.samples) sample.connections = sample.streams;
    r.traffic.connections = 1 + 2400 + r.traffic.samples.reduce((n,s) => n+s.connections, 0);
    r.gatewayConnections = r.traffic.connections;
    r.traffic.connectCount = 2400;
    r.traffic.p95ms = r.traffic.p99ms = 2;
    return r;
  }
  const old = extended(true), current = extended(false);
  assert.deepEqual(compare(old,current).failures, []);
  for (const r of [old,current]) {
    r.accounting.inventoryReceipts=1;
    r.accounting.observedMembers=r.accounting.members=2;
    r.accounting.processCpu=[1,2].map(pid=>({pid,observed:true,seconds:r.accounting.windows.map(w=>w.cpuSeconds/2)}));
    for (const s of r.memory) s.processes=[{pid:1,workingSet:s.workingSetBytes/2},{pid:2,workingSet:s.workingSetBytes/2}];
  }
  assert.deepEqual(compare(old,current).failures, []);
  current.accounting.processCpu.pop();
  assert.throws(()=>compare(old,current));
  current.accounting.processCpu=structuredClone(old.accounting.processCpu);
  const row={Utc:'2026-01-01T00:00:00Z',TotalRows:20,AllTimeWait:8,TargetRows:0,TargetTimeWait:0};
  for (const r of [old,current]) {
    r.gatewayHash='b'.repeat(64);
    r.precondition={verifiedConnections:64,before:{...row,TargetRows:4,TargetTimeWait:4},after:{...row}};
    r.traffic.tableAtBlocks=Array.from({length:6},()=>({...row}));
  }
  assert.deepEqual(compare(old,current).failures, []);
  current.precondition.after.TargetRows=1;
  assert.throws(()=>compare(old,current));
  current.precondition.after.TargetRows=0;
  current.gatewayHash='c'.repeat(64);
  assert.throws(()=>compare(old,current));
  current.gatewayHash=old.gatewayHash;
  current.traffic.connectBlocks[0].fill(3,395);
  assert.equal(latencySummary(current.traffic.connectBlocks).p99ms,2);
  assert.deepEqual(compare(old,current).failures.map(r => r.metric), ['p99msFirst400']);
  current.traffic.p99ms = 0.1;
  assert.throws(() => compare(old,current));
  current.traffic.p99ms = 2;
  current.traffic.connectBlocks[1].pop();
  assert.throws(() => compare(old,current));
  assert.throws(() => compare(report(true),extended(false)));
});
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
test('a nightly release record must match the scheduled run and find nothing in our own engine',()=>{
  const run={id:1,head_sha:'abc',head_branch:'main',status:'completed',conclusion:'failure',event:'schedule'};
  const good={sha:'abc',run:'1',event:'schedule',passed:true,jobs:72,expected_jobs:72,findings:[],failed_jobs:[],
    totals:{own_rejections:3,own_payload_mismatches:0,recovery_failures:0,clean_exposure_connections:40},regression:{nights:14,median:2,limit:20}};
  validateNight(run,good);
  // Warnings never block: a failed or missing job, an overhead shortfall, or a
  // red run whose only problems were the tests' own.
  validateNight(run,{...good,jobs:71,warnings:['71 of 72 jobs reported a verdict','1 job: diagnostic_invalid (ARM64/isolated/14)']});
  // Records written before 2026-11-27 are read by their totals, not their old pass flag.
  validateNight(run,{...good,passed:false,reasons:['1 job: test_failed (X64/full/9)'],findings:undefined});
  for(const patch of [{sha:'old'},{event:'workflow_dispatch'},{missing:true},{totals:undefined},
    {totals:{...good.totals,recovery_failures:1}},{totals:{...good.totals,own_payload_mismatches:3}},
    {totals:{...good.totals,own_rejections:21}},{totals:{...good.totals,clean_exposure_connections:0}}]){
    assert.throws(()=>validateNight(run,{...good,...patch}),JSON.stringify(patch));
  }
});
