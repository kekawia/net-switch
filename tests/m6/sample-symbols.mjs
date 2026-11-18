// Resolve sampled RVAs against the exact, optimized Go executable under test.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
const [go,binary,report]=process.argv.slice(2);
const pe=fs.readFileSync(binary);
const optional=pe.readUInt32LE(0x3c)+24;
assert.equal(pe.readUInt16LE(optional),0x20b);
const base=Number(pe.readBigUInt64LE(optional+24));
const syms=execFileSync(go,['tool','nm','-size','-sort','address',binary],{encoding:'utf8',maxBuffer:64<<20})
  .split(/\r?\n/).map(l=>/^\s*([0-9a-f]+)\s+(\d+)\s+[tT]\s+(.+)$/.exec(l)).filter(Boolean)
  .map(m=>({rva:parseInt(m[1],16)-base,size:Number(m[2]),name:m[3]}));
assert(syms.length>1000);
function resolve(token){
  const m=/^netswitch-engine\.exe\+(.+)$/i.exec(token); if(!m)return token;
  const n=Number(m[1]);if(!Number.isFinite(n))throw Error('Bad engine RVA: '+m[1]);
  let lo=0,hi=syms.length;while(lo<hi){const mid=(lo+hi)>>>1;if(syms[mid].rva<=n)lo=mid+1;else hi=mid}
  const sym=syms[lo-1];return sym && n<sym.rva+sym.size ? sym.name : 'unresolved engine RVA';
}
const all=JSON.parse(fs.readFileSync(report,'utf8')).samplesByStack;
const counts={flat:new Map(),inclusive:new Map(),paths:new Map()};
const add=(m,k,n)=>m.set(k,(m.get(k)??0)+n);let n=0,identified=0;
for(const [key,freq] of Object.entries(all)){
  const [proc,leaf,stack]=key.split('|'); if(proc.toLowerCase()!=='netswitch-engine.exe')continue;
  const fn=resolve(leaf);const frames=stack.split(';').filter(Boolean).map(resolve);n+=freq;
  if([fn,...frames].some(f=>f.includes('github.com/kekawia/net-switch/')))identified+=freq;
  add(counts.flat,fn,freq);
  for(const name of new Set([fn,...frames]))add(counts.inclusive,name,freq);
  add(counts.paths,[fn,...frames.filter(f=>f.includes('github.com/kekawia/net-switch/')).slice(0,4)].join(' <- '),freq);
}
console.log('ENGINE_SAMPLES',n,'attributed_to_product_stacks',identified);
for(const [type,map] of Object.entries(counts)){
  for(const [name,count] of [...map].sort((a,b)=>b[1]-a[1]).slice(0,35))
    console.log(type,(100*count/n).toFixed(2)+'%',count,name);
}
assert(n>100 && identified>0,'No resolved on-CPU engine samples');
