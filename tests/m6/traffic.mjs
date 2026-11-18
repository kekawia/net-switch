// Common benchmark client/server for the two installed products.
// The controlled server runs on the real uplink, behind the existing TestISP target.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createServer, createConnection } from 'node:net';
import { once } from 'node:events';
import { performance } from 'node:perf_hooks';
import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { blockCount, blockSize, latencySummary } from './latency.mjs';

const block = Buffer.alloc(64 * 1024);
for (let offset = 0; offset < block.length; offset++) block[offset] = (offset * 29 + (offset >>> 7)) & 255;
const bytesPerStream = 32 * 1024 * 1024;
const digest = createHash('sha256');
for (let n = 0; n < bytesPerStream; n += block.length) digest.update(block);
const expected = digest.digest('hex');

export function responder(host) {
  const server = createServer(socket => {
    socket.setTimeout(30000, () => socket.destroy());
    socket.on('error', () => {});
    let header = '';
    socket.on('data', function read(chunk) {
      header += chunk.toString('ascii');
      if (header.length > 80) return socket.destroy();
      if (!header.endsWith('\n')) return;
      socket.removeListener('data', read);
      const match = /^(ping|bulk) ([a-f0-9]{32})\n$/.exec(header);
      if (!match) return socket.destroy();
      socket.write(match[2] + '\n');
      if (match[1] === 'ping') return socket.end();
      let sent = 0;
      const pump = () => {
        while (sent < bytesPerStream) {
          sent += block.length;
          if (!socket.write(block)) { socket.once('drain', pump); return; }
        }
        socket.end();
      };
      pump();
    });
  });
  server.listen(0, host);
  return server;
}

async function transfer(host, port, kind) {
  const marker = randomBytes(16).toString('hex') + '\n';
  const hash = createHash('sha256');
  const start = performance.now();
  const socket = createConnection({host,port});
  const timer = setTimeout(() => socket.destroy(Error('traffic deadline exceeded')), 30000);
  try {
    await once(socket, 'connect');
    const connectMs = performance.now() - start;
    socket.write(kind + ' ' + marker);
    let seen = 0, bytes = 0;
    for await (let chunk of socket) {
      if (seen < marker.length) {
        const count = Math.min(chunk.length, marker.length - seen);
        assert.equal(chunk.subarray(0,count).toString('ascii'), marker.slice(seen,seen+count));
        seen += count;
        chunk = chunk.subarray(count);
      }
      hash.update(chunk);
      bytes += chunk.length;
    }
    assert.equal(seen,marker.length);
    assert.equal(bytes,kind === 'bulk' ? bytesPerStream : 0);
    if (bytes) assert.equal(hash.digest('hex'), expected);
    return {connectMs, bytes};
  } finally { clearTimeout(timer); socket.destroy(); }
}

export async function measure(host, port) {
  await transfer(host,port,'bulk');
  const samples = [];
  for (let pass = 0; pass < 3; pass++) {
    for (const streams of pass % 2 ? [8,1] : [1,8]) {
      const startUtc = new Date().toISOString();
      const start = performance.now();
      let bytes = 0, connections = 0;
      do {
        const results = await Promise.all(Array.from({length:streams}, () => transfer(host,port,'bulk')));
        bytes += results.reduce((n,r) => n+r.bytes,0);
        connections += streams;
      } while (performance.now()-start < 4000);
      const seconds = (performance.now()-start)/1000;
      samples.push({streams,pass,bytes,connections,seconds,startUtc,endUtc:new Date().toISOString(),mbps:bytes*8/seconds/1e6});
    }
  }
  const connectBlocks = [];
  const tableAtBlocks = [];
  for (let block = 0; block < blockCount; block++) {
    const table = execFileSync(process.env.M6_TCP_READER, ['table', String(port), process.env.M6_TCP_UPLINK],
      {encoding:'utf8', windowsHide:true, timeout:10000});
    tableAtBlocks.push(JSON.parse(table));
    const measurements = [];
    for (let i = 0; i < blockSize; i++) {
      measurements.push((await transfer(host, port, 'ping')).connectMs);
    }
    connectBlocks.push(measurements);
  }
  const latency = latencySummary(connectBlocks);
  return {samples, connectBlocks, tableAtBlocks, connectCount:latency.count, p95ms:latency.p95ms, p99ms:latency.p99ms,
    connections:1+latency.count+samples.reduce((n,r)=>n+r.connections,0)};
}

export async function soak(host, port, checkpoint) {
  const start = performance.now(), began = new Date().toISOString();
  let successes = 0, previous = start;
  try {
    do {
      if (performance.now()-previous > 10000) throw Error('unobserved traffic interval exceeds 10 seconds');
      previous = performance.now();
      await transfer(host,port,successes % 60 === 0 ? 'bulk':'ping');
      successes++;
      if (successes % 30 === 0) checkpoint({began,seconds:(performance.now()-start)/1000,successes,complete:false});
      await new Promise(resolve=>setTimeout(resolve,1000));
    } while (performance.now()-start < 7200000);
    await transfer(host,port,'ping');
    checkpoint({began,seconds:(performance.now()-start)/1000,successes:successes+1,complete:true});
  } catch (error) {
    checkpoint({began,seconds:(performance.now()-start)/1000,successes,complete:false,error:error.message}); throw error;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [mode,host,arg,out] = process.argv.slice(2);
  if (mode === 'serve') {
    const server = responder(host);
    await once(server,'listening');
    writeFileSync(arg,String(server.address().port),{flag:'wx'});
  } else {
    assert(process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted');
    if (mode === 'prime') {
      const timings = [];
      for (let i=0; i<64; i++) timings.push((await transfer(host,Number(arg),'ping')).connectMs);
      writeFileSync(out,JSON.stringify({connections:timings.length,timings}),{flag:'wx'});
    } else if (mode === 'measure') writeFileSync(out, JSON.stringify(await measure(host,Number(arg))), {flag:'wx'});
    else if (mode === 'soak') await soak(host,Number(arg), result=>writeFileSync(out,JSON.stringify(result)));
    else throw Error('unknown traffic mode');
  }
}
