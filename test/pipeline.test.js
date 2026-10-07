import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../server/analyzer.js';
import { analyzeInBatches, planBatches, runIsolatedBatch } from '../server/pipeline.js';
const file = (path, text) => ({ path, text, type: path.split('.').pop(), size: Buffer.byteLength(text) });
const inline = async (files, name, custom, options) => analyze(files, name, custom, options);

test('batch planning keeps connected local modules together within the byte budget', () => {
  const files = [file('app.js',"import { read } from './input.js'; document.body.innerHTML = read();"),file('input.js','export function read(){ return location.hash; }'),file('vendor.js','//'+ 'x'.repeat(300))];
  const plan = planBatches(files,200);
  assert.equal(plan.batches.length,2); assert.ok(plan.batches.some(b=>b.length===2)); assert.equal(plan.crossBatchImports.length,0);
});
test('batched analysis retains cross-file taint, inventory, graphs and globally unique finding IDs', async () => {
  const files = [file('app.js',"import { read } from './input.js'; document.body.innerHTML = read();"),file('input.js','export function read(){ return location.hash; }'),file('other.js','document.body.innerHTML=location.search; //'+ 'x'.repeat(250)),file('styles.css','body{}')];
  const r = await analyzeInBatches(files,'fixture.zip',{}, {batchBytes:200,runBatch:inline});
  assert.equal(r.application.counts.files,4); assert.equal(r.application.counts.parsed,3); assert.equal(r.application.coverage.batchCount,2);
  assert.equal(r.findings.filter(f=>f.category==='XSS').length,2); assert.equal(new Set(r.findings.map(f=>f.id)).size,r.findings.length);
  assert.ok(r.graph.edges.some(e=>e.type==='imports')); assert.deepEqual(r.files.map(f=>f.path),files.map(f=>f.path));
  for(const f of r.flows) for(let i=1;i<f.trace.length;i++) assert.ok(r.graph.edges.some(e=>e.source===f.trace[i-1]&&e.target===f.trace[i]));
});
test('one failed batch retains inventory and lets subsequent batches produce results', async () => {
  const files = [file('large.js','const n=1;//'+ 'x'.repeat(150)),file('app.js','document.body.innerHTML=location.hash;')];
  let calls=0;
  const runBatch=async(...args)=>{if(!calls++)throw new Error('batch-memory-limit');return inline(...args);};
  const r=await analyzeInBatches(files,'test.zip',{}, {batchBytes:100,runBatch});
  assert.equal(r.files.length,2); assert.equal(r.application.counts.parsed,1); assert.ok(r.findings.some(f=>f.file==='app.js'));
  assert.equal(r.application.coverage.status,'partial'); assert.deepEqual(r.application.coverage.inventoryOnlyFiles,['large.js']);
  assert.equal(r.files[0].analysisStatus,'inventory-only'); assert.ok(r.files[0].content); assert.ok(r.warnings.some(w=>w.includes('batch-memory-limit')));
});
test('cross-batch import limits are explicit and import edges are retained', async () => {
  const files=[file('app.js',"import { read } from './input.js'; document.body.innerHTML=read();"),file('input.js','export function read(){return location.hash;}')];
  const r=await analyzeInBatches(files,'test.zip',{}, {batchBytes:50,runBatch:inline});
  assert.equal(r.application.coverage.crossBatchImports.length,1); assert.equal(r.application.coverage.status,'partial'); assert.ok(r.graph.edges.some(e=>e.type==='imports'));
  assert.ok(r.warnings.some(w=>w.includes('taint propagation across those boundaries was not performed')));
});
test('embedded source maps are recovered once and included in the batching plan', async () => {
  const files=[file('bundle.js.map',JSON.stringify({version:3,sources:['original.js'],sourcesContent:['document.body.innerHTML=location.hash;']}))];
  const r=await analyzeInBatches(files,'test.zip',{}, {runBatch:inline});
  assert.equal(r.files.length,2);assert.equal(r.application.counts.parsed,1);assert.equal(r.application.coverage.recoveredSources,1);assert.ok(r.findings.some(f=>f.category==='XSS'));
});
test('evaluation exhaustion retains symbols and explicitly marks incomplete data-flow coverage', () => {
  const r=analyze([file('app.js','function read(){return location.hash;} document.body.innerHTML=read();')],'test.zip',{}, {evaluationBudget:1});
  assert.equal(r.application.counts.functions,1); assert.equal(r.application.counts.parsed,1); assert.equal(r.application.coverage.evaluationLimited,true); assert.equal(r.application.coverage.converged,false); assert.ok(r.warnings.some(w=>w.includes('budget reached')));
});
test('isolated batches return real AST results and terminate cleanly', async () => {
  const r=await runIsolatedBatch([file('app.js','document.body.innerHTML=location.hash;')],'test.zip',{}, {},5000);
  assert.equal(r.application.counts.parsed,1);assert.ok(r.findings.some(f=>f.category==='XSS'));
});
test('overall scheduling timeout returns explicit inventory-only coverage', async () => {
  const r=await analyzeInBatches([file('app.js','document.body.innerHTML=location.hash;')],'test.zip',{}, {totalTimeMs:0,runBatch:inline});
  assert.equal(r.application.counts.files,1);assert.equal(r.application.counts.parsed,0);assert.equal(r.application.coverage.status,'partial');assert.equal(r.application.coverage.batches[0].reason,'overall-time-budget');
});
test('oversized source retains redacted content while clearly skipping AST analysis', async () => {
  const r=await analyzeInBatches([file('large.js','/*'+ 'x'.repeat(1024*1024)+'*/')],'test.zip',{}, {runBatch:inline});
  assert.equal(r.application.counts.files,1);assert.equal(r.application.counts.parsed,0);assert.ok(r.files[0].content);assert.deepEqual(r.application.coverage.inventoryOnlyFiles,['large.js']);assert.equal(r.application.coverage.status,'partial');
});
test('isolated batch timeout rejects and terminates its worker', async () => {
  await assert.rejects(runIsolatedBatch([file('app.js','document.body.innerHTML=location.hash;')],'test.zip',{}, {},0),/batch-time-limit/);
});
