import assert from 'node:assert/strict';

export const blockSize = 400;
export const blockCount = 6;

function percentiles(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  return {
    p95ms: sorted[Math.ceil(sorted.length * 0.95) - 1],
    p99ms: sorted[Math.ceil(sorted.length * 0.99) - 1],
  };
}

export function latencySummary(blocks) {
  assert.equal(blocks.length, blockCount);
  for (const block of blocks) {
    assert.equal(block.length, blockSize);
    assert(block.every(ms => Number.isFinite(ms) && ms > 0));
  }
  const samples = blocks.flat();
  return { count: samples.length, ...percentiles(samples), blocks: blocks.map(percentiles) };
}
