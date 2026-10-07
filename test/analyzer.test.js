import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze, redact } from '../server/analyzer.js';
import { readArchive, LIMITS } from '../server/archive.js';
import { readFile } from 'node:fs/promises';
const sourceFile = (path, text) => ({ path, text, type: path.split('.').pop(), size: Buffer.byteLength(text), hash: null });
const scan = (code, others = [], custom = {}) => analyze([sourceFile('app.js', code), ...others], 'test.zip', custom);

function crc32(buffer) { let crc = 0xffffffff; for (const byte of buffer) { crc ^= byte; for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0); } return (crc ^ 0xffffffff) >>> 0; }
function zip(name, text, options = {}) {
  const bytes = Buffer.from(text), filename = Buffer.from(name); const local = Buffer.alloc(30), central = Buffer.alloc(46), end = Buffer.alloc(22);
  local.writeUInt32LE(0x04034b50); local.writeUInt16LE(20, 4); local.writeUInt16LE(options.flags || 0, 6); local.writeUInt32LE(crc32(bytes), 14); local.writeUInt32LE(bytes.length, 18); local.writeUInt32LE(options.size ?? bytes.length, 22); local.writeUInt16LE(filename.length, 26);
  central.writeUInt32LE(0x02014b50); central.writeUInt16LE(0x314, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(options.flags || 0, 8); central.writeUInt32LE(crc32(bytes), 16); central.writeUInt32LE(bytes.length, 20); central.writeUInt32LE(options.size ?? bytes.length, 24); central.writeUInt16LE(filename.length, 28); central.writeUInt32LE(options.attributes || 0, 38);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10); end.writeUInt32LE(central.length + filename.length, 12); end.writeUInt32LE(local.length + filename.length + bytes.length, 16);
  return Buffer.concat([local, filename, bytes, central, filename, end]);
}
test('traces a query through a call argument to an HTML sink', () => {
  const r = scan(`function draw(x) { document.body.innerHTML = x; } const q = new URLSearchParams(location.search).get('q'); draw(decodeURIComponent(q));`);
  const f = r.findings.find(f => f.category === 'XSS'); assert.ok(f); assert.equal(f.confidence, 'high'); assert.ok(f.source.includes('location.search')); assert.ok(r.flows.some(f => f.trace.includes(r.functions[0].id))); assert.ok(r.call_graph.length === 0); // top-level call isn't misrepresented as a function caller
});
test('resolves imported calls and return summaries across files', () => {
  const r = scan(`import { read } from './input.js'; function draw(){ document.body.innerHTML = read(); } draw();`, [sourceFile('input.js', `export function read(){ return location.hash; }`)]);
  assert.ok(r.findings.some(f => f.title === 'Potential DOM XSS')); assert.ok(r.call_graph.some(e => e.confidence === 'high')); assert.ok(r.graph.edges.some(e => e.type === 'imports'));
});
test('does not treat a dangerous API with a constant as a vulnerability', () => {
  const r = scan(`document.body.innerHTML = '<b>Hello</b>'; setTimeout(() => console.log('hello'), 10);`);
  assert.equal(r.findings.length, 0); assert.equal(r.sinks.length, 1);
});
test('recognizes imported HTML sanitizer and does not trust a same-name local function', () => {
  const r = scan(`import DOMPurify from 'dompurify'; document.body.innerHTML = DOMPurify.sanitize(location.hash);`);
  assert.equal(r.findings.filter(f => f.category === 'XSS').length, 0); assert.ok(r.flows.some(f => f.sanitized));
  const local = scan(`const DOMPurify = { sanitize(x) { return x; } }; document.body.innerHTML = DOMPurify.sanitize(location.hash);`);
  assert.ok(local.findings.some(f => f.category === 'XSS'));
});
test('decoding after HTML sanitization invalidates the recognized control', () => {
  const r = scan(`import DOMPurify from 'dompurify'; document.body.innerHTML = decodeURIComponent(DOMPurify.sanitize(location.hash));`);
  assert.ok(r.findings.some(f => f.category === 'XSS'));
});
test('unresolved transformations are explicitly lower confidence', () => {
  const r = scan(`document.body.innerHTML = customTransform(location.hash);`);
  assert.equal(r.findings[0].confidence, 'medium'); assert.equal(r.findings[0].status, 'Potential');
});
test('recognizes postMessage inputs without declaring origin bypass', () => {
  const r = scan(`window.addEventListener('message', e => { document.body.innerHTML = e.data; });`);
  assert.ok(r.sources.some(s => s.label.includes('message.data'))); assert.ok(r.findings.some(f => f.category === 'XSS')); assert.ok(r.anomalies.some(a => a.title === 'Message trust boundary'));
});
test('inventory API authentication and routes without server-side SSRF claim', () => {
  const r = scan(`fetch('/api/users', {method:'POST', headers:{Authorization:'Bearer placeholder'}}); fetch(location.hash); const routes=[{path:'/admin'}];`);
  assert.equal(r.apis[0].method, 'POST'); assert.equal(r.apis[0].authentication, 'Authorization header present'); assert.equal(r.routes[0].path, '/admin'); assert.ok(r.findings.some(f => f.explanation.includes('not evidence of server-side SSRF')));
});
test('redacts credentials from source, formatted text and findings', () => {
  const credential = 'ghp_' + 'z'.repeat(36); const r = scan(`const token = '${credential}'; const password = 'actual-credential-value';`);
  const encoded = JSON.stringify(r); assert.ok(!encoded.includes(credential)); assert.ok(!encoded.includes('actual-credential-value')); assert.ok(r.secrets.length >= 2); assert.ok(r.findings.every(f => f.id));
  assert.ok(!redact('API_SECRET_TOKEN=super-secret-value').includes('super-secret-value'));
});
test('recovers embedded source maps and accounts for unparsed code', () => {
  const r = scan('function { invalid', [sourceFile('bundle.js.map', JSON.stringify({version:3,sources:['original.ts'],sourcesContent:['const q: string = location.hash; document.body.innerHTML = q;']}))]);
  assert.equal(r.application.coverage.recoveredSources, 1); assert.ok(r.warnings.some(w => w.includes('Could not parse'))); assert.ok(r.findings.some(f => f.file.startsWith('sourcemap/')));
});
test('custom rules connect configured source to configured sink', () => {
  const r = scan(`unsafeRender(window.customInput);`, [], {sources:[{match:'window.customInput'}], sinks:[{match:'unsafeRender',kind:'call',argument:0,context:'html'}]}); assert.ok(r.findings.some(f => f.category === 'Custom'));
});
test('extracts all function kinds and simple object methods', () => {
  const r = scan(`const obj={draw(value){document.body.innerHTML=value;}}; const run=()=>obj.draw(location.hash); class Widget { constructor(){} async load(){} } run();`);
  assert.equal(r.functions.length, 4); assert.ok(r.findings.some(f => f.category === 'XSS')); assert.ok(r.call_graph.some(e => e.confidence === 'high'));
});
test('reads bounded ZIP data with hashes and never executes uploaded code', async () => {
  const files = await readArchive(zip('app.js', 'globalThis.__ZIP_EXECUTED = true;')); assert.equal(files.length, 1); assert.equal(files[0].hash.length, 64); assert.equal(globalThis.__ZIP_EXECUTED, undefined);
});
test('rejects traversal, absolute paths, symlinks and encrypted entries', async () => {
  for (const name of ['../app.js', '/app.js', 'C:/app.js']) await assert.rejects(readArchive(zip(name, 'text')));
  await assert.rejects(readArchive(zip('link.js','target',{attributes: (0xa1ff << 16) >>> 0})), /Symbolic/);
  await assert.rejects(readArchive(zip('app.js','text',{flags:1}))); // encrypted stored entry is rejected before it can be read
});
test('rejects oversized entries and malformed archives', async () => {
  await assert.rejects(readArchive(zip('app.js','text',{size:LIMITS.file+1})));
  await assert.rejects(readArchive(Buffer.from('not a ZIP')), /not a readable ZIP/);
});
test('the included example produces real flows, functions and endpoints', async () => {
  const r = analyze(await readArchive(await readFile(new URL('../public/example.zip', import.meta.url))), 'example.zip');
  assert.equal(r.application.counts.files, 5); assert.ok(r.functions.length >= 6); assert.ok(r.apis.length >= 3); assert.ok(r.findings.filter(f => f.category === 'XSS').length >= 2); assert.ok(r.findings.some(f => f.category === 'Navigation')); assert.ok(r.graph.edges.length > 10);
});
test('tracks object property assignments and avoids invented API response sources', () => {
  const r = scan(`const state={}; state.payload=location.hash; document.body.innerHTML=state.payload;`); assert.ok(r.findings.some(f => f.category === 'XSS'));
  const safe = scan(`const obj={json(){return '<p>constant</p>';}}; document.body.innerHTML=obj.json();`); assert.equal(safe.findings.length, 0);
});
test('inventories endpoint strings and OpenAPI declarations without probing them', () => {
  const r = scan(`const hidden='/api/internal/audit'; const vendor='https://example.test/config';`, [sourceFile('openapi.json',JSON.stringify({openapi:'3.0.0',paths:{'/api/users':{get:{parameters:[{name:'id'}]}}}}))]);
  assert.equal(r.endpointCandidates.length,2); assert.equal(r.apis[0].endpoint,'/api/users'); assert.equal(r.apis[0].origin,'OpenAPI declaration; usage not established');
});
test('public client identifiers do not become embedded-secret findings', () => {
  const r = scan(`const apiKey = 'AIza${'x'.repeat(35)}';`); assert.equal(r.secrets[0].classification,'Public configuration'); assert.equal(r.findings.length,0);
});
test('does not mistake shadowed browser sources and eval functions for platform APIs', () => {
  const r = scan(`const location={hash:'safe'}; document.body.innerHTML=location.hash;`); assert.equal(r.findings.length,0);
  const local = scan(`const eval = x => x; eval(location.hash);`); assert.equal(local.findings.length,0);
  const params = scan(`class URLSearchParams {get(){return 'safe';}} document.body.innerHTML=new URLSearchParams().get();`); assert.equal(params.findings.length,0);
});
test('plain object HTML-named properties are not reported as DOM vulnerabilities', () => {
  const plain = scan(`const config={}; config.innerHTML=location.hash;`); assert.equal(plain.findings.length,0);
  const unknown = scan(`unknownElement.innerHTML=location.hash;`); assert.equal(unknown.findings[0].confidence,'medium'); assert.equal(unknown.findings[0].title,'Input reaches an HTML-like API');
});
test('every exported data-flow trace has corresponding graph edges', async () => {
  const r=analyze(await readArchive(await readFile(new URL('../public/example.zip',import.meta.url))),'example.zip');
  for (const f of r.flows) for(let i=1;i<f.trace.length;i++) assert.ok(r.graph.edges.some(e=>e.source===f.trace[i-1] && e.target===f.trace[i]), `${f.id}: missing graph edge`);
});
test('URLSearchParams with constant or empty input is not an attacker-controlled source', () => {
  const r=scan(`document.body.innerHTML=new URLSearchParams('q=constant').get('q'); document.body.outerHTML=new URLSearchParams().get('q');`); assert.equal(r.findings.length,0);
});
