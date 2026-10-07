import { Worker } from 'node:worker_threads';
import path from 'node:path';
import { parse } from '@babel/parser';
import { analyze, recoverSourceMaps } from './analyzer.js';

export const ANALYSIS_LIMITS = { batchBytes: 256 * 1024, sourceBytes: 1024 * 1024, workerHeapMb: 384, batchTimeMs: 15000, totalTimeMs: 105000 };
const javascript = file => /^(?:[cm]?[jt]sx?)$/.test(file.type);
const bytes = file => Buffer.byteLength(file.text || '');

// Keep connected local source modules together when they fit the AST budget.
// The planning parse has no Babel scopes/NodePaths and is discarded per file.
export function planBatches(files, limit = ANALYSIS_LIMITS.batchBytes) {
  const scripts = files.filter(javascript), byPath = new Map(scripts.map(file => [file.path, file]));
  const parents = new Map(scripts.map(file => [file.path, file.path]));
  const root = name => { while (parents.get(name) !== name) name = parents.get(name); return name; };
  const imports = [];
  for (const file of scripts) {
    if (bytes(file) > ANALYSIS_LIMITS.sourceBytes) continue;
    try {
      const ast = parse(file.text, { sourceType: 'unambiguous', errorRecovery: true, attachComment: false, plugins: ['jsx', 'typescript', 'decorators-legacy'] });
      for (const statement of ast.program.body) {
        const specifier = statement.source?.value;
        if (typeof specifier !== 'string' || !specifier.startsWith('.')) continue;
        const base = path.posix.normalize(path.posix.join(path.posix.dirname(file.path), specifier));
        const target = [base, ...['.js', '.jsx', '.ts', '.tsx', '.mjs', '/index.js', '/index.ts', '/index.tsx'].map(ext => base + ext)].find(candidate => byPath.has(candidate));
        if (target) { imports.push({ source: file.path, target, specifier }); parents.set(root(file.path), root(target)); }
      }
    } catch { /* The analysis stage reports actual parse errors with file locations. */ }
  }
  const components = new Map();
  for (const file of scripts) { const key = root(file.path); if (!components.has(key)) components.set(key, []); components.get(key).push(file); }
  const batches = []; let current = [], size = 0;
  const flush = () => { if (current.length) batches.push(current); current = []; size = 0; };
  for (const component of components.values()) {
    const componentSize = component.reduce((sum, file) => sum + bytes(file), 0);
    if (componentSize <= limit) {
      if (size + componentSize > limit) flush();
      current.push(...component); size += componentSize;
    } else {
      flush();
      for (const file of component) { const length = bytes(file); if (size + length > limit) flush(); current.push(file); size += length; if (size >= limit) flush(); }
      flush();
    }
  }
  flush();
  const batchFor = new Map(batches.flatMap((batch, index) => batch.map(file => [file.path, index])));
  return { batches, imports, crossBatchImports: imports.filter(item => batchFor.get(item.source) !== batchFor.get(item.target)) };
}

export function runIsolatedBatch(files, name, custom, options, timeoutMs) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./batch-worker.js', import.meta.url), { workerData: { files, name, custom, options }, resourceLimits: { maxOldGenerationSizeMb: ANALYSIS_LIMITS.workerHeapMb } });
    let settled = false;
    const finish = (error, result) => {
      if (settled) return; settled = true; clearTimeout(timer);
      // Await termination so no previous batch's trees survive into the next batch.
      worker.terminate().then(() => error ? reject(error) : resolve(result), reject);
    };
    const timer = setTimeout(() => finish(new Error('batch-time-limit')), timeoutMs);
    worker.once('message', message => finish(message.error ? new Error('batch-analysis-failed') : null, message.result));
    worker.once('error', error => finish(new Error(error.code === 'ERR_WORKER_OUT_OF_MEMORY' ? 'batch-memory-limit' : 'batch-worker-failed')));
    worker.once('exit', code => { if (!settled) finish(new Error(`batch-worker-exit-${code}`)); });
  });
}

export async function analyzeInBatches(inputFiles, name, custom = {}, options = {}) {
  const started = Date.now(), deadline = started + (options.totalTimeMs ?? ANALYSIS_LIMITS.totalTimeMs);
  const files = inputFiles.map(file => ({ ...file })), mapWarnings = [], mapAnomalies = [];
  recoverSourceMaps(files, mapWarnings, mapAnomalies);
  const plan = planBatches(files, options.batchBytes ?? ANALYSIS_LIMITS.batchBytes);
  const report = analyze(files.filter(file => !javascript(file)), name, custom, { recoverSources: false });
  report.warnings.push(...mapWarnings); report.anomalies.push(...mapAnomalies);
  const arrays = ['files', 'modules', 'functions', 'routes', 'apis', 'endpointCandidates', 'dependencies', 'secrets', 'sources', 'sinks', 'flows', 'findings', 'anomalies', 'warnings'];
  const compactNode = ({ id, type, label, file, line, column, risk, category, context }) => ({ id, type, label, file, line, column, risk, ...(category ? { category } : {}), ...(context ? { context } : {}) });
  const nodes = new Map(report.graph.nodes.map(node => [node.id, compactNode(node)])), edges = new Map();
  const addEdge = edge => edges.set(`${edge.source}|${edge.target}|${edge.type}`, edge);
  report.graph.edges.forEach(addEdge);
  const technologies = new Set(report.application.technologies);
  const batches = [], incomplete = [];
  let passes = 0, evaluations = 0, converged = true, evaluationLimited = false;
  const runner = options.runBatch || runIsolatedBatch;
  for (let index = 0; index < plan.batches.length; index++) {
    const batch = plan.batches[index]; let part; let reason;
    options.onProgress?.({ stage: 'analysis', batch: index + 1, totalBatches: plan.batches.length, files: batch.map(file => file.path) });
    const remaining = deadline - Date.now();
    if (remaining <= 1000) reason = 'overall-time-budget';
    else {
      try { part = await runner(batch, name, custom, { recoverSources: false, maxSourceBytes: ANALYSIS_LIMITS.sourceBytes }, Math.min(options.batchTimeMs ?? ANALYSIS_LIMITS.batchTimeMs, remaining)); }
      catch (error) { reason = error.message; }
    }
    if (!part) {
      part = analyze(batch, name, custom, { recoverSources: false, inventoryOnly: true, skipReason: `AST analysis unavailable for this batch (${reason}); file and credential inventory retained.` });
      incomplete.push(...batch.map(file => file.path));
    }
    for (const key of arrays) report[key].push(...part[key]);
    part.graph.nodes.forEach(node => { if (!nodes.has(node.id)) nodes.set(node.id, compactNode(node)); }); part.graph.edges.forEach(addEdge);
    part.application.technologies.forEach(tech => technologies.add(tech));
    const coverage = part.application.coverage;
    passes = Math.max(passes, coverage.fixedPointPasses); evaluations += coverage.evaluationCount || 0;
    converged &&= coverage.converged; evaluationLimited ||= coverage.evaluationLimited;
    batches.push({ batch: index + 1, files: batch.map(file => file.path), parsed: part.application.counts.parsed, status: reason ? 'inventory-only' : coverage.evaluationLimited ? 'partial-data-flow' : coverage.converged ? 'analyzed' : 'partial-data-flow', ...(reason ? { reason } : {}) });
  }
  // Preserve the archive's order and source-map provenance rather than batch order.
  const analyzedFiles = new Map(report.files.map(file => [file.path, file]));
  report.files = files.map(file => analyzedFiles.get(file.path));
  const fileNodes = new Map([...nodes.values()].filter(node => node.type === 'file').map(node => [node.file, node.id]));
  for (const item of plan.imports) {
    const source = fileNodes.get(item.source);
    const target = fileNodes.get(item.target);
    if (source && target) addEdge({ source, target, type: 'imports', confidence: 'high' });
  }
  if (plan.crossBatchImports.length) report.warnings.push(`${plan.crossBatchImports.length} local imports cross AST batches. Their import relationships are retained, but taint propagation across those boundaries was not performed.`);
  report.findings = report.findings.map((finding, index) => ({ ...finding, id: `WT-${String(index + 1).padStart(3, '0')}` }));
  report.graph = { nodes: [...nodes.values()], edges: [...edges.values()] }; report.call_graph = report.graph.edges.filter(edge => edge.type === 'calls');
  const weights = { critical: 30, high: 18, medium: 7, low: 2, info: 0 };
  const app = report.application;
  app.technologies = [...technologies]; app.durationMs = Date.now() - started;
  app.exposure = Math.min(100, Math.round(report.findings.reduce((sum, finding) => sum + weights[finding.severity] * (finding.confidence === 'high' ? 1 : .65), 0)));
  app.breakdown = app.breakdown.map(({ category }) => ({ category, score: Math.min(10, report.findings.filter(finding => finding.category === category).reduce((sum, finding) => sum + weights[finding.severity] / 3, 0)) }));
  app.counts = { files: report.files.length, javascript: report.files.filter(javascript).length, parsed: report.files.filter(file => file.parsed).length, functions: report.functions.length, endpoints: report.apis.length, secrets: report.secrets.length, findings: report.findings.length, high: report.findings.filter(finding => ['high', 'critical'].includes(finding.severity)).length, routes: report.routes.length };
  app.coverage = { fixedPointPasses: passes, converged: converged && !incomplete.length && !plan.crossBatchImports.length, evaluationCount: evaluations, evaluationLimited, dataFlowLimitedFiles: report.files.filter(file => file.dataFlowStatus === 'partial').map(file => file.path), compiledFiles: report.files.filter(file => file.minified).length, recoveredSources: report.files.filter(file => file.recoveredFrom).length, batchCount: batches.length, batches, inventoryOnlyFiles: report.files.filter(file => file.analysisStatus === 'inventory-only').map(file => file.path), crossBatchImports: plan.crossBatchImports, status: incomplete.length || evaluationLimited || !converged || plan.crossBatchImports.length || report.files.some(file => file.parsed === false) ? 'partial' : 'completed' };
  report.warnings = [...new Set(report.warnings)];
  report.limitations.push('ASTs are processed in isolated, bounded batches. Small connected local modules are grouped together. Cross-batch import relationships are inventoried but cross-batch taint paths are not proven. Any skipped, failed or budget-limited analysis is explicitly listed in coverage.');
  return report;
}
