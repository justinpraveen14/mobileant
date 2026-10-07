import test from 'node:test';
import assert from 'node:assert/strict';
import { OmniRouterProvider, buildEvidence, validateAIResponse } from '../src/ai.js';
import { analyze } from '../server/analyzer.js';
import { reportMarkdown } from '../src/reports.js';
const report = analyze([{path:'app.js',type:'js',text:'document.body.innerHTML = location.hash;',size:40}], 'test.zip');
const evidence = buildEvidence(report);
test('AI evidence omits raw file contents unless explicitly selected', () => {
  assert.ok(!('content' in evidence.files[0])); assert.ok(!('formatted' in evidence.files[0])); assert.ok(!('selectedCode' in evidence));
  const selected = buildEvidence(report, report.files[0]); assert.equal(selected.selectedCode.file, 'app.js');
});
test('AI provider sends key only in header and requires grounded response IDs', async () => {
  const original = globalThis.fetch; let request;
  globalThis.fetch = async (url, options) => { request = {url,options}; return {ok:true,json:async()=>({choices:[{message:{content:JSON.stringify({claims:[{topic:'XSS',text:'Review the observed input path.',evidenceIds:[report.findings[0].id]}],limitations:['Reachability not proven.']})}}]})}; };
  try {
    const settings = {baseUrl:'http://localhost:9090/v1',apiKey:'test-only-key',model:'test-model',temperature:.1,maxTokens:2000};
    const answer = await new OmniRouterProvider().analyze({settings,evidence,mode:'XSS Analyst'});
    assert.equal(request.url,'http://localhost:9090/v1/chat/completions'); assert.equal(request.options.headers.Authorization,'Bearer test-only-key'); assert.ok(!request.options.body.includes('test-only-key')); assert.ok(answer.includes(report.findings[0].id));
  } finally { globalThis.fetch = original; }
});
test('AI rejects uncited and unknown evidence claims', () => {
  assert.throws(()=>validateAIResponse('made up plain text',evidence), /unstructured/);
  assert.throws(()=>validateAIResponse(JSON.stringify({claims:[{topic:'XSS',text:'Invented',evidenceIds:['unknown']}]}),evidence), /unknown evidence/);
  assert.throws(()=>validateAIResponse(JSON.stringify({claims:[{topic:'XSS',text:'Invented',evidenceIds:[]}]}),evidence), /missing/);
});
test('AI endpoint validation rejects remote plaintext and URL-embedded credentials', async () => {
  const provider = new OmniRouterProvider();
  await assert.rejects(provider.analyze({settings:{baseUrl:'http://remote.example/v1',model:'x'},evidence}), /HTTPS/);
  await assert.rejects(provider.analyze({settings:{baseUrl:'https://user:password@example.test/v1',model:'x'},evidence}), /without credentials/);
});
test('Markdown export includes evidence, flows and limitations', () => {
  const output=reportMarkdown(report); assert.ok(output.includes('## Function Inventory')); assert.ok(output.includes('Potential DOM XSS')); assert.ok(output.includes('location.hash')); assert.ok(output.includes('## Limitations')); assert.ok(output.includes('not CVSS'));
});
