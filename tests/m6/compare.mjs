// Compare whole-product measurements taken sequentially on the same runner.
// All medians retain the three underlying rounds in the saved artifact.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { blockSize, latencySummary } from './latency.mjs';

const read = p => JSON.parse(fs.readFileSync(p,'utf8').replace(/^\uFEFF/,''));
const median = xs => [...xs].sort((a,b)=>a-b)[Math.floor(xs.length/2)];
function metrics(x) {
  if (x.traffic.connectBlocks) {
    const latency = latencySummary(x.traffic.connectBlocks);
    assert.equal(x.traffic.connectCount, latency.count);
    assert.equal(x.traffic.p95ms, latency.p95ms);
    assert.equal(x.traffic.p99ms, latency.p99ms);
    const bulk = x.traffic.samples.reduce((n, sample) => n + sample.connections, 0);
    assert.equal(x.traffic.connections, 1 + bulk + latency.count);
  } else {
    assert.equal(x.traffic.connectCount, blockSize);
  }
  assert.equal(x.gatewayConnections,x.traffic.connections);
  assert(x.images.length>=2 && x.images.every(p=>/^[0-9a-f]{64}$/i.test(p.hash)));
  assert.equal(x.accounting.windows.length,6);
  assert.equal(x.traffic.samples.length,6);
  const out = {p95ms:x.traffic.p95ms,p99ms:x.traffic.p99ms};
  for (const streams of [1,8]) {
    const rows=x.traffic.samples.filter(s=>s.streams===streams);
    assert.deepEqual(rows.map(s=>s.pass).sort(),[0,1,2]);
    const cpu=[], memory=[];
    for (const s of rows) {
      const matches=x.accounting.windows.filter(w=>w.Streams===streams && w.Pass===s.pass && w.Bytes===s.bytes);
      assert.equal(matches.length,1);
      cpu.push(matches[0].cpuSeconds/(s.bytes/1e9));
      const samples=x.memory.filter(m=>Date.parse(m.utc)>=Date.parse(s.startUtc) && Date.parse(m.utc)<=Date.parse(s.endUtc));
      assert(samples.length>=2,'insufficient product memory observations');
      memory.push(Math.max(...samples.map(m=>m.workingSetBytes)));
    }
    out['mbps'+streams]=median(rows.map(s=>s.mbps));
    out['cpuSecondsPerGB'+streams]=median(cpu);
    out['peakSampledWorkingSet'+streams]=median(memory);
  }
  assert(Object.values(out).every(n=>Number.isFinite(n) && n>0));
  return out;
}
export function compare(old,candidate) {
  assert(old.runner && old.commit && candidate.commit === old.commit);
  assert.equal(old.runner,candidate.runner);
  assert.equal(old.arch,candidate.arch);
  assert.equal(Boolean(old.traffic.connectBlocks), Boolean(candidate.traffic.connectBlocks));
  assert.equal(old.release,'0.3.2');
  const pinned = {x64:'0193582d10fcede15f3119b3ec72a20dfad7ad94b87f8465b5e90e835865791b',arm64:'32ee2fb156e76392cca550a9078684f1b2ee1440c15487a41967c96da92d7b11'}[old.arch];
  assert(pinned && old.installerHash === pinned);
  assert(/^[0-9a-f]{64}$/i.test(candidate.installerHash) && candidate.installerHash !== pinned);
  const baseline=metrics(old), current=metrics(candidate);
  const results=Object.entries(baseline).map(([name,b])=>{
    const c=current[name];
    return {metric:name,baseline:b,candidate:c,regressionPercent:100*(name.startsWith('mbps')?(b-c)/b:(c-b)/b)};
  });
  const failures = results.filter(r => r.regressionPercent > 10);
  let latency;
  if (old.traffic.connectBlocks) {
    const baseline = latencySummary(old.traffic.connectBlocks);
    const current = latencySummary(candidate.traffic.connectBlocks);
    const first400 = ['p95ms','p99ms'].map(metric => {
      const b = baseline.blocks[0][metric], c = current.blocks[0][metric];
      return {metric:metric+'First400', baseline:b, candidate:c, regressionPercent:100*(c-b)/b};
    });
    // The existing first-400 gate stays binding alongside the larger sample.
    failures.push(...first400.filter(r => r.regressionPercent > 10));
    latency = {count:current.count, baselineBlocks:baseline.blocks, candidateBlocks:current.blocks, first400};
  }
  return {arch:old.arch,runner:old.runner,commit:candidate.commit,results,failures,latency};
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [oldFile,newFile,output]=process.argv.slice(2);
  const result=compare(read(oldFile),read(newFile));
  fs.writeFileSync(output,JSON.stringify(result,null,2));
  console.table(result.results);
  if (result.latency) console.table(result.latency.first400);
  if (result.failures.length) throw Error('Whole-product performance exceeded the 10% regression limit');
}
