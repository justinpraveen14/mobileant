import { parse } from '@babel/parser';
import traverseModule from '@babel/traverse';
import generatorModule from '@babel/generator';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { SINK_RULES, SOURCE_NAMES, LIMITATIONS } from './rules.js';
const traverse = traverseModule.default || traverseModule;
const generate = generatorModule.default || generatorModule;
const hash = value => createHash('sha256').update(value).digest('hex');
const id = (type, file, offset = 0) => `${type}:${hash(`${file}:${offset}`).slice(0, 14)}`;
const member = n => !n ? '' : n.type === 'Identifier' ? n.name : n.type === 'ThisExpression' ? 'this' : n.type === 'Import' ? 'import' : /MemberExpression$/.test(n.type) ? `${member(n.object)}.${n.computed ? (n.property.value ?? '*') : member(n.property)}` : '';
const str = n => n?.type === 'StringLiteral' ? n.value : n?.type === 'TemplateLiteral' ? n.quasis.map((q, i) => q.value.cooked + (i < n.expressions.length ? '{dynamic}' : '')).join('') : null;
const prop = (n, key) => n?.properties?.find(p => (p.key?.name || p.key?.value) === key)?.value;
const basename = value => value.split('/').pop();
const categoryFor = url => /auth|login|logout|password|otp|register/i.test(url) ? 'Authentication' : /admin|internal|debug/i.test(url) ? 'Admin' : /payment|stripe|billing/i.test(url) ? 'Payment' : /upload|file/i.test(url) ? 'File Upload' : /search/i.test(url) ? 'Search' : /user|profile/i.test(url) ? 'User' : /message|chat|socket/i.test(url) ? 'Messaging' : /analytics|telemetry/i.test(url) ? 'Analytics' : /^https?:/.test(url) ? 'Third-party' : 'Unknown';
const secretPatterns = [
  ['Private key', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, 'high'],
  ['GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, 'high'],
  ['Stripe secret key', /\bsk_(?:live|test)_[A-Za-z0-9]{12,}\b/g, 'high'],
  ['AWS access key identifier', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, 'medium'],
  ['Slack token', /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/g, 'high'],
  ['JWT candidate', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, 'medium'],
  ['Database credential URL', /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+/g, 'high'],
  ['Possible embedded credential', /(?:["']?(?:api[_-]?key|client[_-]?secret|password|access[_-]?token|refresh[_-]?token|secret)["']?\s*[:=]\s*["'])([^"'\r\n]{8,})(?:["'])/gi, 'medium'],
  ['Possible environment credential', /^(?:[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*)\s*=\s*([^\r\n]{8,})/gm, 'medium'],
];
export function redact(text) {
  let out = text || '';
  for (const [, pattern] of secretPatterns) { pattern.lastIndex = 0; out = out.replace(pattern, (whole, capture) => typeof capture === 'string' ? whole.replace(capture, capture.replace(/[^\r\n]/g, '*')) : whole.replace(/[^\r\n]/g, '*')); }
  return out;
}
export function analyze(inputFiles, name = 'application.zip', custom = {}) {
  const began = Date.now();
  const files = inputFiles.map(f => ({ ...f }));
  const warnings = [], modules = [], functions = [], apis = [], endpointCandidates = [], routes = [], dependencies = [], secrets = [], findings = [], anomalies = [];
  const nodes = new Map(), edges = new Map(), sourceMap = new Map(), sinkMap = new Map(), fnByNode = new Map(), parameterBindings = new Map(), parsed = new Map(), fnStates = new Map(), propertyWrites = new Map();
  const sourceNames = [...SOURCE_NAMES, ...(custom.sources || []).slice(0, 30).map(s => s.match).filter(Boolean)];
  const rules = [...SINK_RULES, ...(custom.sinks || []).slice(0, 30).map(s => ({ name: s.match, match: s.match, kind: s.kind || 'call', argument: Number.isInteger(s.argument) ? s.argument : 0, category: 'Custom', severity: 'medium', context: s.context || 'code', cwe: 'CWE-20' }))];
  const putNode = n => { if (!nodes.has(n.id)) nodes.set(n.id, { risk: 'info', line: 0, ...n }); return n.id; };
  const edge = (source, target, type, confidence = 'high') => { const key = `${source}|${target}|${type}`; edges.set(key, { source, target, type, confidence }); };
  const loc = (p, file) => ({ file, line: p.node.loc?.start.line || 1, column: p.node.loc?.start.column || 0, offset: p.node.start || 0 });
  const functionAt = p => { for (let cursor = p; cursor; cursor = cursor.parentPath) { if (fnByNode.has(cursor.node)) return fnByNode.get(cursor.node); } return null; };
  const finding = f => { findings.push({ id: `WT-${String(findings.length + 1).padStart(3, '0')}`, severity: 'info', confidence: 'medium', status: 'Observed', exploitability: 'Not established', impact: 'Requires contextual validation', reachability: 'Static candidate; runtime reachability unknown', references: ['https://owasp.org/www-community/attacks/DOM_Based_XSS', 'https://book.hacktricks.wiki/en/pentesting-web/index.html'], ...f }); };
  // Maps are read as data. Recovered virtual files never become filesystem paths.
  let recoveredBytes = 0;
  for (const file of [...files]) {
    if (file.type !== 'map' || !file.text) continue;
    try {
      const map = JSON.parse(file.text); let recovered = 0;
      for (let i = 0; i < (map.sourcesContent?.length || 0); i++) {
        const text = map.sourcesContent[i]; if (typeof text !== 'string') continue;
        recoveredBytes += Buffer.byteLength(text);
        if (recoveredBytes > 24 * 1024 * 1024 || files.length >= 2500) { warnings.push('Embedded source-map recovery limit reached.'); break; }
        const virtual = `sourcemap/${file.path}/${String(map.sources?.[i] || `source-${i}.js`).replace(/^[\/]+/, '')}`;
        files.push({ path: virtual, type: path.extname(virtual).slice(1) || 'js', size: Buffer.byteLength(text), hash: hash(text), text, role: 'recovered source', risk: 'info', recoveredFrom: file.path }); recovered++;
      }
      file.sourceMap = { embeddedSources: recovered, declaredSources: map.sources?.length || 0, confidence: recovered ? 'high' : 'low' };
      anomalies.push({ id: id('anomaly', file.path), title: 'Source map present', file: file.path, line: 1, classification: 'Observed', description: `${recovered} embedded original sources recovered. Public availability cannot be established.` });
    } catch { warnings.push(`Unreadable source map: ${file.path}`); }
  }
  const technologies = new Set();
  const addApi = (p, file, method, endpoint, extra = {}) => {
    const info = loc(p, file), fn = functionAt(p);
    const api = { id: id('api', file, p.node.start), ...info, method, endpoint: redact(endpoint || '{dynamic}'), category: categoryFor(endpoint || ''), function: fn?.name || '(module)', functionId: fn?.id || null, authentication: 'Not inferred', parameters: [], headers: [], ...extra };
    try { const u = new URL(api.endpoint, 'https://relative.invalid'); api.hostname = u.hostname === 'relative.invalid' ? null : u.hostname; api.pathname = u.pathname; api.parameters = [...u.searchParams.keys()]; } catch {}
    apis.push(api); putNode({ ...api, type: 'api', label: `${method} ${api.endpoint}` }); if (fn) { edge(fn.id, api.id, 'requests'); fn.networkRequests.push(api.id); }
    if (/https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?=[:/]|$)/i.test(api.endpoint)) anomalies.push({ id: id('local', file, p.node.start), ...info, title: 'Browser-to-localhost communication', classification: 'Potential', description: `A request targets ${api.endpoint}. Verify intent, local service authentication and browser restrictions.` });
    if (/^ws:\/\//.test(api.endpoint)) finding({ ...info, title: 'Unencrypted WebSocket endpoint', category: 'WebSocket', severity: 'medium', confidence: 'high', status: 'Confirmed by static evidence', explanation: 'A literal ws:// endpoint is configured. Deployment reachability and sensitive message content are not proven.', evidence: redact(fileSlice(file, p.node)), recommendation: 'Use wss:// and validate authentication and message schemas.', validation: 'Confirm the deployed transport and whether sensitive messages are exchanged.', cwe: 'CWE-319' });
  };
  const fileSlice = (file, node) => files.find(f => f.path === file)?.text?.slice(node.start, Math.min(node.end, node.start + 700)) || '';
  for (const file of files) {
    putNode({ id: id('file', file.path), type: 'file', label: file.path, file: file.path });
    if (!file.text) continue;
    const text = file.text;
    file.minified = /[cm]?js/.test(file.type) && text.split('\n').some(line => line.length > 1000);
    for (const [tech, pattern] of [['React', /react(?:-dom)?|__REACT__/], ['Vue', /createApp\(|__VUE__|vue\.runtime/], ['Angular', /@angular\/|ng-version/], ['Next.js', /__NEXT_DATA__|next\/dist|_next\//], ['Webpack', /webpackChunk|__webpack_require__/], ['Vite', /vite\/|vite:|__vite__|vite\.config/], ['Rollup', /rollup/], ['esbuild', /esbuild/], ['Parcel', /parcelRequire/]]) if (pattern.test(text) || pattern.test(file.path)) technologies.add(tech);
    if (/(?:^|\/)package(?:-lock)?\.json$|npm-shrinkwrap\.json$/.test(file.path)) {
      try {
        const pkg = JSON.parse(text);
        if (pkg.packages) {
          for (const [location, dep] of Object.entries(pkg.packages)) { if (!location) continue; dependencies.push({ package: dep.name || location.split('node_modules/').pop(), version: dep.version || 'unknown', type: dep.dev ? 'development' : 'runtime', direct: location.split('node_modules/').length === 2, file: file.path, vulnerability: 'Not checked' }); }
        } else { for (const type of ['dependencies', 'devDependencies', 'peerDependencies']) for (const [packageName, version] of Object.entries(pkg[type] || {})) dependencies.push({ package: packageName, version: String(version), type, direct: true, file: file.path, vulnerability: 'Not checked' }); }
      } catch { warnings.push(`Invalid package metadata: ${file.path}`); }
    }
    if (/\.(?:ya?ml|lock)$/.test(file.path)) {
      // These are declared version indicators, not a substitute for full lockfile semantic resolution.
      for (const match of text.matchAll(/(?:^|\n)\s*["']?(@?[\w.-]+(?:\/[\w.-]+)?)@(?:npm:)?([\d][^\s:"']*)[^\n]*\n\s+(?:version[: ]+)['"]?([^\s'"]+)/g)) dependencies.push({ package: match[1], version: match[3], type: 'lockfile indicator', direct: null, file: file.path, vulnerability: 'Not checked' });
    }
    for (const [type, pattern, confidence] of secretPatterns) {
      pattern.lastIndex = 0;
      for (const match of text.matchAll(pattern)) {
        const candidate = match[1] || match[0]; if (/example|placeholder|your[_-]|changeme|\$\{|process\.env|import\.meta/i.test(candidate)) continue;
        const line = text.slice(0, match.index).split('\n').length;
        const publicIdentifier = /^(?:AIza[\w-]{30,}|pk_(?:live|test)_[A-Za-z0-9]+)$/.test(candidate);
        const secret = { id: id('secret', file.path, match.index), type, file: file.path, line, confidence, classification: publicIdentifier ? 'Public configuration' : type.includes('identifier') ? 'Possible secret' : confidence === 'high' ? 'Secret candidate' : 'Possible secret', maskedValue: '[REDACTED]', reason: 'Format or credential-bearing assignment matched; validity was not tested.' };
        secrets.push(secret); if (!publicIdentifier) finding({ ...secret, id: undefined, title: `Embedded ${type.toLowerCase()}`, category: 'Secrets', severity: confidence === 'high' ? 'high' : 'medium', status: 'Potential', explanation: secret.reason, evidence: '[REDACTED] — sensitive value omitted.', recommendation: 'Determine whether this is a live credential. Revoke or rotate live secrets and remove them from browser-delivered artifacts.', validation: 'Validate type and ownership securely; do not test credentials against live services without authorization.', cwe: 'CWE-798' });
      }
    }
    if (file.type === 'json') {
      try {
        const spec = JSON.parse(text);
        if ((spec.openapi || spec.swagger) && spec.paths) for (const [endpoint, operations] of Object.entries(spec.paths)) for (const [method, operation] of Object.entries(operations)) {
          if (!['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(method)) continue;
          const start = Math.max(0, text.indexOf(JSON.stringify(endpoint)));
          addApi({ node: { start, end: start + endpoint.length + 2, loc: { start: { line: text.slice(0, start).split('\n').length, column: 0 } } }, parentPath: null }, file.path, method.toUpperCase(), endpoint, { authentication: operation.security || spec.security ? 'Security scheme declared in API specification' : 'Not inferred', parameters: (operation.parameters || []).map(p => p.name).filter(Boolean), origin: 'OpenAPI declaration; usage not established' });
        }
      } catch {}
    }
    if (/\.(?:html?|svg)$/i.test(file.path)) {
      for (const match of text.matchAll(/<(?:script|iframe)\b[^>]*(?:src\s*=\s*["']([^"']+)["'])[^>]*>/gi)) {
        const line = text.slice(0, match.index).split('\n').length;
        const isScript = /^<script/i.test(match[0]);
        if (/^https?:\/\//.test(match[1]) && isScript && !/\bintegrity\s*=/.test(match[0])) anomalies.push({ id: id('html', file.path, match.index), file: file.path, line, title: 'Third-party script without visible SRI', classification: 'Observed', description: `External script ${redact(match[1])} has no integrity attribute. Assess vendor trust and resource immutability; this alone is not a vulnerability.` });
      }
    }
    if (!/^(?:[cm]?[jt]sx?)$/.test(file.type)) continue;
    try {
      const ast = parse(text, { sourceType: 'unambiguous', errorRecovery: true, plugins: ['jsx', 'typescript', 'decorators-legacy'], attachComment: true });
      const module = { id: id('module', file.path), file: file.path, imports: [], exports: [], dynamicImports: [], parseErrors: ast.errors.map(e => ({ line: e.loc?.line || 0, message: e.reasonCode || 'Parse error' })) };
      if (ast.errors.length) warnings.push(`${file.path}: ${ast.errors.length} recoverable parse errors.`);
      file.parsed = true; modules.push(module); parsed.set(file.path, { ast, module });
      traverse(ast, {
        ImportDeclaration(p) { module.imports.push({ source: p.node.source.value, names: p.node.specifiers.map(s => ({ local: s.local.name, imported: s.imported?.name || (s.type === 'ImportDefaultSpecifier' ? 'default' : '*') })), line: p.node.loc.start.line }); },
        ExportNamedDeclaration(p) { if (p.node.declaration?.id) module.exports.push({ exported: p.node.declaration.id.name, local: p.node.declaration.id.name }); if (p.node.declaration?.declarations) for (const d of p.node.declaration.declarations) if (d.id.name) module.exports.push({ exported: d.id.name, local: d.id.name }); for (const s of p.node.specifiers) module.exports.push({ exported: s.exported?.name, local: s.local?.name }); },
        ExportDefaultDeclaration(p) { module.exports.push({ exported: 'default', local: p.node.declaration.id?.name || p.node.declaration.name, node: p.node.declaration }); },
        Function(p) {
          const node = p.node;
          const originalName = node.id?.name || node.key?.name || node.key?.value || (p.parentPath.isVariableDeclarator() ? p.parent.id.name : p.parentPath.isObjectProperty() ? p.parent.key.name : null);
          const name = originalName != null ? String(originalName) : `anonymous@${basename(file.path)}:${node.loc.start.line}:${node.loc.start.column}`;
          const fn = { id: id('function', file.path, node.start), name, originalName, ...loc(p, file.path), parameters: node.params.map(n => redact(text.slice(n.start, n.end))), async: node.async, generator: node.generator, calls: [], calledBy: [], sources: [], sinks: [], networkRequests: [], returns: [], kind: node.type, exported: false };
          functions.push(fn); fnByNode.set(node, fn); fnStates.set(fn.id, { path: p, parameters: node.params.map(() => []), returns: [], event: null }); putNode({ ...fn, type: 'function', label: name }); edge(id('file', file.path), fn.id, 'contains');
          node.params.forEach((param, index) => { for (const n of Object.keys(p.get('params')[index].getBindingIdentifiers())) { const binding = p.scope.getBinding(n); if (binding) parameterBindings.set(binding, { fn, index }); } });
        },
      });
      file.formatted = redact(generate(ast, { comments: true, compact: false }).code);
    } catch (error) { file.parsed = false; file.parseError = error.reasonCode || 'Parser rejected file'; warnings.push(`Could not parse ${file.path}: ${file.parseError}`); }
  }
  const resolveImport = (from, specifier) => {
    if (!specifier.startsWith('.')) return null;
    const base = path.posix.normalize(path.posix.join(path.posix.dirname(from), specifier));
    return [base, ...['.js', '.jsx', '.ts', '.tsx', '.mjs', '/index.js', '/index.ts', '/index.tsx'].map(ext => base + ext)].find(f => parsed.has(f));
  };
  const resolve = (p, from, depth = 0) => {
    if (!p?.node || depth > 8) return null;
    if (fnByNode.has(p.node)) return fnByNode.get(p.node);
    if (p.isIdentifier()) {
      const binding = p.scope.getBinding(p.node.name); if (!binding) return null;
      if (fnByNode.has(binding.path.node)) return fnByNode.get(binding.path.node);
      if (binding.path.isVariableDeclarator()) return resolve(binding.path.get('init'), from, depth + 1);
      if (binding.path.isImportSpecifier() || binding.path.isImportDefaultSpecifier()) {
        const target = resolveImport(from, binding.path.parent.source.value); if (!target) return null;
        const exported = binding.path.node.imported?.name || 'default'; const item = parsed.get(target).module.exports.find(e => e.exported === exported);
        return item ? functions.find(f => f.file === target && (f.name === item.local || fnByNode.get(item.node)?.id === f.id)) : null;
      }
    }
    if (p.isMemberExpression() && !p.node.computed) {
      const methodName = p.node.property.name;
      if (p.node.object.type === 'Identifier') {
        const binding = p.scope.getBinding(p.node.object.name);
        const object = binding?.path.isVariableDeclarator() ? binding.path.get('init') : null;
        if (object?.isObjectExpression()) { const target = object.get('properties').find(item => item.node.key?.name === methodName); if (target) return resolve(target.isObjectProperty() ? target.get('value') : target, from, depth + 1); }
      }
      if (p.node.object.type === 'ThisExpression') {
        const cls = p.findParent(v => v.isClass());
        const method = cls?.get('body.body').find(v => v.node.key?.name === methodName); if (method) return fnByNode.get(method.node);
      }
    }
    return null;
  };
  const source = (p, file, label) => {
    const key = id('source', file, p.node.start);
    if (!sourceMap.has(key)) { const s = { id: key, type: 'source', label, ...loc(p, file), risk: 'info' }; sourceMap.set(key, s); putNode(s); if (label.startsWith('API response')) { const api = apis.find(a => a.file === file && a.offset === p.node.start); if (api) edge(api.id, key, 'responds_with'); } const fn = functionAt(p); if (fn) { fn.sources.push(key); edge(key, fn.id, 'flows_to'); } }
    return [{ source: key, trace: [key], controls: [], uncertain: false }];
  };
  const combine = (...values) => {
    const out = new Map(); for (const v of values.flat()) { const k = v.source + '|' + v.controls.join(',') + '|' + v.uncertain; if (!out.has(k) || out.get(k).trace.length > v.trace.length) out.set(k, v); } return [...out.values()].slice(0, 32);
  };
  let changed = false;
  const mergeState = (old, incoming) => { const merged = combine(old, incoming); if (merged.length !== old.length) changed = true; return merged; };
  const step = (values, p, file, label, uncertain = false) => {
    if (!values.length) return values;
    const key = id('transform', file, p.node.start); putNode({ id: key, type: 'transformation', label, ...loc(p, file) });
    return values.map(v => { const prev = v.trace.at(-1); edge(prev, key, 'flows_to', uncertain || v.uncertain ? 'medium' : 'high'); return { ...v, controls: uncertain || /decodeURI|atob|\.replace|template interpolation/.test(label) ? [] : v.controls, uncertain: uncertain || v.uncertain, trace: [...v.trace.filter(x => x !== key), key].slice(-40) }; });
  };
  const evaluate = (p, file, seen = new Set(), depth = 0) => {
    if (!p?.node || depth > 36 || seen.has(p.node)) return [];
    const next = new Set(seen).add(p.node), n = p.node; const ev = child => evaluate(child, file, next, depth + 1);
    const browserRoot = member(n).split('.')[0]; const shadowed = ['window', 'document', 'location', 'localStorage', 'sessionStorage', 'URLSearchParams', 'FormData'].includes(browserRoot) && !!p.scope.getBinding(browserRoot);
    const label = member(n).replace(/^window\.(?=location|localStorage|sessionStorage)/, '');
    if (!shadowed && !['URLSearchParams', 'FormData'].includes(label) && sourceNames.includes(label) && (p.isMemberExpression() || p.isIdentifier() && !p.scope.getBinding(n.name))) return source(p, file, label);
    if (p.isIdentifier()) {
      const binding = p.scope.getBinding(n.name); if (!binding) return [];
      const param = parameterBindings.get(binding); if (param) return fnStates.get(param.fn.id).parameters[param.index];
      const values = [];
      if (binding.path.isVariableDeclarator()) { values.push(...ev(binding.path.get('init'))); if (binding.path.node.id.type !== 'Identifier') return step(values, p, file, `destructure ${n.name}`); }
      for (const violation of binding.constantViolations) if (violation.isAssignmentExpression()) values.push(...ev(violation.get('right')));
      return combine(values);
    }
    if (p.isMemberExpression() || p.isOptionalMemberExpression()) {
      if (['value', 'innerText', 'textContent'].includes(n.property.name) && /input|textarea|target|currentTarget|field|form/i.test(member(n.object))) return source(p, file, `${member(n.object)}.${n.property.name}`);
      const binding = n.object.type === 'Identifier' ? p.scope.getBinding(n.object.name) : null;
      const param = binding && parameterBindings.get(binding);
      if (n.property.name === 'data' && param && fnStates.get(param.fn.id).event) return source(p, file, `${fnStates.get(param.fn.id).event} message.data`);
      const init = binding?.path.isVariableDeclarator() ? binding.path.get('init') : null;
      const writes = binding && propertyWrites.get(binding)?.get(n.computed ? n.property.value : n.property.name);
      if (writes?.length) return combine(...writes.map(write => ev(write)));
      if (init?.isObjectExpression() && !n.computed) { const field = init.get('properties').find(v => (v.node.key?.name || v.node.key?.value) === n.property.name); if (field?.isObjectProperty()) return ev(field.get('value')); }
      return combine(ev(p.get('object')), n.computed ? ev(p.get('property')) : []);
    }
    if (p.isCallExpression() || p.isNewExpression() || p.isOptionalCallExpression()) {
      const callee = member(n.callee), args = p.get('arguments'), values = args.map(ev);
      if (callee === 'URLSearchParams' && !p.scope.getBinding(callee)) return step(combine(...values), p, file, 'URLSearchParams');
      if (callee === 'FormData' && !p.scope.getBinding(callee)) return args.length && !args[0].isStringLiteral() ? source(p, file, 'FormData(form input)').map(value => ({ ...value, uncertain: true })) : [];
      if (sourceNames.includes(callee.replace(/^window\./, '')) && !p.scope.getBinding(callee.split('.')[0])) return source(p, file, callee);
      if (/\.(?:json|text|blob|arrayBuffer)$/.test(callee)) { const response = p.get('callee').isMemberExpression() ? ev(p.get('callee.object')) : []; if (response.some(v => sourceMap.get(v.source)?.label.startsWith('API response'))) return step(response, p, file, `response ${callee.split('.').at(-1)}()`); }
      const target = resolve(p.get('callee'), file);
      if (target) {
        const state = fnStates.get(target.id);
        values.forEach((v, i) => { if (i < state.parameters.length) state.parameters[i] = mergeState(state.parameters[i], v.map(x => { edge(x.trace.at(-1), target.id, 'flows_to', x.uncertain ? 'medium' : 'high'); return { ...x, trace: [...x.trace.filter(k => k !== target.id), target.id] }; })); });
        return step(state.returns.map(value => { edge(value.trace.at(-1), target.id, 'flows_to', value.uncertain ? 'medium' : 'high'); return { ...value, trace: [...value.trace.filter(k => k !== target.id), target.id] }; }), p, file, `return ${target.name}`);
      }
      // Only recognize DOMPurify when a binding actually imports the package.
      if (/\.sanitize$/.test(callee)) {
        const binding = p.scope.getBinding(callee.split('.')[0]);
        if (binding?.path.parent?.source?.value === 'dompurify') return step(combine(...values), p, file, 'DOMPurify.sanitize').map(v => ({ ...v, controls: [...v.controls, 'html-sanitizer'] }));
      }
      if (!p.scope.getBinding(callee) && /^(?:fetch|axios\.(?:get|post|put|patch|delete)|ky\.(?:get|post)|WebSocket|EventSource)$/.test(callee)) return source(p, file, `API response: ${callee}`);
      const knownTransform = /^(?:decodeURIComponent|encodeURIComponent|decodeURI|encodeURI|atob|btoa|String|JSON\.parse|JSON\.stringify)$/.test(callee) || /\.(?:get|trim|replace|split|slice|join|toString)$/.test(callee);
      return step(combine(...values, p.get('callee').isMemberExpression() ? ev(p.get('callee.object')) : []), p, file, callee || 'unresolved call', !knownTransform);
    }
    if (p.isAwaitExpression() || p.isUnaryExpression() || p.isTSAsExpression() || p.isTSNonNullExpression() || p.isParenthesizedExpression()) return ev(p.get(p.isAwaitExpression() || p.isUnaryExpression() ? 'argument' : 'expression'));
    if (p.isBinaryExpression() || p.isLogicalExpression()) return combine(ev(p.get('left')), ev(p.get('right')));
    if (p.isConditionalExpression()) return combine(ev(p.get('consequent')), ev(p.get('alternate')));
    if (p.isTemplateLiteral()) return step(combine(...p.get('expressions').map(ev)), p, file, 'template interpolation');
    if (p.isArrayExpression()) return combine(...p.get('elements').map(ev));
    if (p.isObjectExpression()) return combine(...p.get('properties').map(item => ev(item.get(item.isSpreadElement() ? 'argument' : 'value'))));
    if (p.isAssignmentExpression()) return ev(p.get('right'));
    if (p.isSequenceExpression()) return ev(p.get('expressions').at(-1));
    return [];
  };
  // Structural pass: calls, imports, callback trust boundaries and network requests.
  for (const [file, { ast, module }] of parsed) {
    for (const imp of module.imports) { const target = resolveImport(file, imp.source); if (target) edge(id('file', file), id('file', target), 'imports'); }
    for (const exp of module.exports) { const fn = functions.find(f => f.file === file && (f.name === exp.local || fnByNode.get(exp.node)?.id === f.id)); if (fn) fn.exported = true; }
    traverse(ast, {
      'CallExpression|NewExpression'(p) {
        const callee = member(p.node.callee), fn = functionAt(p), target = resolve(p.get('callee'), file);
        if (fn) {
          const targetId = target?.id || id('external', callee || 'unresolved', 0);
          if (!target) putNode({ id: targetId, type: 'external', label: callee || '(dynamic call)', file, line: p.node.loc.start.line });
          edge(fn.id, targetId, 'calls', target ? 'high' : 'low'); if (!fn.calls.includes(targetId)) fn.calls.push(targetId); if (target && !target.calledBy.includes(fn.id)) target.calledBy.push(fn.id);
        }
        const args = p.get('arguments');
        if (/\.addEventListener$/.test(callee) && ['message', 'messageerror'].includes(str(p.node.arguments[0]))) {
          const handler = resolve(args[1], file); if (handler) { fnStates.get(handler.id).event = 'postMessage'; anomalies.push({ id: id('message', file, p.node.start), ...loc(p, file), title: 'Message trust boundary', classification: 'Potential', description: 'Message handler discovered. Presence of origin references does not prove a dominating origin/source check. Inspect this handler before privileged actions.', functionId: handler.id }); }
        }
        if (/\.then$/.test(callee)) { const callback = resolve(args[0], file); const object = p.get('callee.object'); if (callback && /fetch|axios|\.json\(|\.text\(/.test(fileSlice(file, object.node))) { const state = fnStates.get(callback.id); if (state.parameters.length) state.parameters[0] = combine(state.parameters[0], source(args[0], file, 'API response callback')); } }
        if (/\.postMessage$/.test(callee) && str(p.node.arguments[1]) === '*') anomalies.push({ id: id('wildcard', file, p.node.start), ...loc(p, file), title: 'Wildcard message destination', classification: 'Observed', description: 'postMessage uses targetOrigin "*". Validate receiver identity and avoid transmitting sensitive payloads.' });
        if (callee === 'import') module.dynamicImports.push({ specifier: str(p.node.arguments[0]) || '{dynamic}', line: p.node.loc.start.line });
        if ((callee === 'fetch' || /^(?:window\.)?fetch$/.test(callee)) && !p.scope.getBinding(callee.split('.')[0])) {
          const opts = p.node.arguments[1]; const headers = prop(opts, 'headers');
          const headerNames = headers?.properties?.map(h => h.key?.name || h.key?.value).filter(Boolean) || [];
          addApi(p, file, (str(prop(opts, 'method')) || 'GET').toUpperCase(), str(p.node.arguments[0]), { headers: headerNames, authentication: headerNames.some(h => /authorization/i.test(h)) ? 'Authorization header present' : str(prop(opts, 'credentials')) === 'include' ? 'Cookies included' : 'Not inferred', bodyFields: prop(opts, 'body')?.properties?.map(p => p.key.name || p.key.value) || [] });
        } else if (/^(?:axios|ky|superagent)\.(get|post|put|patch|delete|head)$/.test(callee)) addApi(p, file, callee.split('.').at(-1).toUpperCase(), str(p.node.arguments[0]));
        else if (['WebSocket', 'EventSource'].includes(callee)) addApi(p, file, callee === 'WebSocket' ? 'WS' : 'SSE', str(p.node.arguments[0]));
        else if (callee === 'navigator.sendBeacon') addApi(p, file, 'POST', str(p.node.arguments[0]));
        else if (/\.open$/.test(callee) && /xhr|request/i.test(callee)) addApi(p, file, str(p.node.arguments[0]) || 'UNKNOWN', str(p.node.arguments[1]));
        if (/\.register$/.test(callee) && /serviceWorker/.test(callee)) anomalies.push({ id: id('sw', file, p.node.start), ...loc(p, file), title: 'Service worker registration', classification: 'Observed', description: `Registration path: ${redact(str(p.node.arguments[0]) || '{dynamic}')}. Scope, cache policy and message trust require manual review.` });
        if (/\b(?:merge|extend|set|defaultsDeep)$/.test(callee) && /merge|extend|defaultsDeep/.test(callee)) anomalies.push({ id: id('merge', file, p.node.start), ...loc(p, file), title: 'Deep-object operation', classification: 'Suspicious', description: 'Inspect key filtering and input provenance. Neither prototype mutation nor an exploitable gadget is established.' });
      },
      AssignmentExpression(p) {
        if (p.get('left').isMemberExpression() && p.node.left.object.type === 'Identifier') {
          const binding = p.scope.getBinding(p.node.left.object.name); const key = p.node.left.computed ? p.node.left.property.value : p.node.left.property.name;
          if (binding && key != null) { if (!propertyWrites.has(binding)) propertyWrites.set(binding, new Map()); const fields = propertyWrites.get(binding); if (!fields.has(key)) fields.set(key, []); fields.get(key).push(p.get('right')); }
        }
        if (/\.onmessage$/.test(member(p.node.left))) { const fn = resolve(p.get('right'), file); if (fn) fnStates.get(fn.id).event = /socket|ws/i.test(member(p.node.left)) ? 'WebSocket' : 'message'; }
      },
      JSXOpeningElement(p) { if (member(p.node.name) === 'Route') { const attr = p.node.attributes.find(a => a.name?.name === 'path'); const routePath = str(attr?.value) || str(attr?.value?.expression); if (routePath) routes.push({ id: id('route', file, p.node.start), path: routePath, ...loc(p, file), classification: 'Discovered route', access: 'Not tested' }); } },
      ObjectProperty(p) { if (['path', 'route'].includes(p.node.key.name || p.node.key.value) && str(p.node.value)?.startsWith('/')) routes.push({ id: id('route', file, p.node.start), path: str(p.node.value), ...loc(p, file), classification: 'Route candidate', access: 'Not tested' }); },
      MemberExpression(p) { const value = member(p.node); if (/^(?:chrome|browser)\.(?:runtime|storage)/.test(value) || /(?:process\.env|import\.meta\.env)/.test(value)) anomalies.push({ id: id('indicator', file, p.node.start), ...loc(p, file), title: value.startsWith('chrome') || value.startsWith('browser') ? 'Browser extension interaction' : 'Environment configuration reference', classification: 'Observed', description: `${value} is referenced. Review the trust boundary and deployment values.` }); },
      StringLiteral(p) {
        const value = p.node.value;
        if (/^(?:https?:\/\/|wss?:\/\/|\/(?:api|admin|internal|debug|graphql|swagger|actuator|config|\.env)(?:[/?#]|$))/.test(value)) endpointCandidates.push({ id: id('endpoint-string', file, p.node.start), ...loc(p, file), endpoint: redact(value), classification: 'Discovered endpoint string', access: 'Not tested', category: categoryFor(value) });
      },
      BinaryExpression(p) { if (['===', '=='].includes(p.node.operator) && ['admin', 'superadmin', 'staff', 'moderator'].includes(str(p.node.right))) anomalies.push({ id: id('role', file, p.node.start), ...loc(p, file), title: 'Client-side authorization indicator', classification: 'Observed', description: 'A privileged role comparison is present. Server-side enforcement cannot be verified from frontend code.' }); },
    });
  }
  let iterations = 0;
  for (; iterations < 12; iterations++) {
    changed = false;
    for (const [file, { ast }] of parsed) traverse(ast, {
      'CallExpression|NewExpression'(p) { evaluate(p, file); },
      ReturnStatement(p) { const fn = functionAt(p); if (fn) { const state = fnStates.get(fn.id); state.returns = mergeState(state.returns, evaluate(p.get('argument'), file)); } },
      ArrowFunctionExpression(p) { if (p.node.body.type !== 'BlockStatement') { const fn = fnByNode.get(p.node), state = fnStates.get(fn.id); state.returns = mergeState(state.returns, evaluate(p.get('body'), file)); } },
    });
    if (!changed) { iterations++; break; }
  }
  if (changed) warnings.push('Data-flow fixed point did not converge within 12 passes; some paths may be missing.');
  const flows = [];
  const inspectSink = (p, value, rule, file) => {
    const key = id('sink', file, p.node.start) + ':' + rule.name;
    const info = { id: key, type: 'sink', label: rule.name, ...loc(p, file), category: rule.category, context: rule.context, risk: 'info' };
    sinkMap.set(key, info); putNode(info); const fn = functionAt(p); if (fn) { fn.sinks.push(key); edge(fn.id, key, 'uses'); }
    const taints = evaluate(value, file);
    const active = taints.filter(t => !(rule.context === 'html' && t.controls.includes('html-sanitizer')));
    for (const t of taints) {
      const intermediate = fn && t.trace.at(-1) !== fn.id ? [...t.trace, fn.id] : t.trace; if (fn && t.trace.at(-1) !== fn.id) edge(t.trace.at(-1), fn.id, 'flows_to', t.uncertain ? 'medium' : 'high'); const trace = [...intermediate, key]; edge(intermediate.at(-1), key, 'flows_to', t.uncertain ? 'medium' : 'high');
      flows.push({ id: id('flow', key + t.source), source: t.source, sink: key, trace, controls: t.controls, confidence: t.uncertain ? 'medium' : 'high', sanitized: !active.includes(t) });
    }
    if (!active.length) return;
    const receiver = p.isAssignmentExpression() && p.get('left').isMemberExpression() ? p.get('left.object') : p.isCallExpression() && p.get('callee').isMemberExpression() ? p.get('callee.object') : null;
    const receiverBinding = receiver?.isIdentifier() ? receiver.scope.getBinding(receiver.node.name) : null;
    const receiverInit = receiverBinding?.path.isVariableDeclarator() ? receiverBinding.path.get('init') : null;
    const plainObject = receiverInit?.isObjectExpression() && receiverBinding.constant && receiverInit.node.properties.every(item => item.type === 'ObjectProperty');
    if (rule.context === 'html' && plainObject) return; // A plain data object's HTML-named field is not a DOM API.
    const receiverText = receiver ? fileSlice(file, receiver.node) : '';
    const receiverInitialText = receiverInit?.node ? fileSlice(file, receiverInit.node) : '';
    const htmlReceiverKnown = rule.kind === 'jsx' || /^document\./.test(receiverText) && !p.scope.getBinding('document') || /(?:getElementById|querySelector|createElement)\(/.test(receiverText + receiverInitialText);
    const high = active.every(t => !t.uncertain) && (rule.context === 'code' || rule.context === 'html' && htmlReceiverKnown);
    const title = rule.context === 'html' ? htmlReceiverKnown ? 'Potential DOM XSS' : 'Input reaches an HTML-like API' : rule.context === 'code' ? 'Input influences dynamic execution' : rule.context === 'url' ? 'Input influences browser navigation' : rule.context === 'network' ? 'Input influences network destination' : 'Input reaches browser storage';
    finding({ ...loc(p, file), title, category: rule.category, severity: rule.context === 'html' && !htmlReceiverKnown ? 'medium' : rule.severity, confidence: high ? 'high' : 'medium', status: high ? 'High-confidence' : 'Potential', cwe: rule.cwe, source: active.map(t => sourceMap.get(t.source)?.label).join(', '), sink: rule.name, function: fn?.name || '(module)', flowIds: flows.filter(f => f.sink === key && !f.sanitized).map(f => f.id), path: active[0].trace.map(k => ({ id: k, label: nodes.get(k)?.label, file: nodes.get(k)?.file, line: nodes.get(k)?.line })), evidence: redact(fileSlice(file, p.node)), explanation: 'A bounded static data-flow path connects an input source to this sink. Branch feasibility, deployment protections and runtime reachability are not established.' + (rule.context === 'network' ? ' This is browser destination influence, not evidence of server-side SSRF.' : ''), recommendation: rule.remediation || (rule.context === 'url' || rule.context === 'network' ? 'Parse the destination with URL and enforce an explicit protocol and origin allowlist. Validate again at the sink.' : rule.context === 'storage' ? 'Assess whether sensitive values belong in script-readable storage. Minimize retention and protect against XSS.' : 'Use explicit validated operations and a context-appropriate security control.'), validation: 'In an isolated local copy, use an inert marker to verify source control, the executed call path and the exact sink value. Check existing validation and deployment policies before concluding exploitability.' });
    nodes.get(key).risk = rule.severity; info.risk = rule.severity;
  };
  for (const [file, { ast }] of parsed) traverse(ast, {
    'CallExpression|NewExpression'(p) { const callee = member(p.node.callee).replace(/^window\.(?=location)/, ''); for (const rule of rules) if (rule.kind === 'call' && (callee === rule.match || !rule.match.includes('.') && callee.endsWith('.' + rule.match))) { if (!rule.category || rule.category !== 'Custom') { if (p.node.callee.type === 'Identifier' && p.scope.getBinding(callee)) continue; if (resolve(p.get('callee'), file) && rule.category !== 'Custom') continue; } const args = p.get('arguments'); const value = args[rule.argument === -1 ? args.length - 1 : rule.argument]; if (value) inspectSink(p, value, rule, file); } if (['setTimeout', 'setInterval'].includes(callee) && !p.get('arguments')[0]?.isFunction()) inspectSink(p, p.get('arguments')[0], { name: callee, category: 'Code execution', context: 'code', severity: 'high', cwe: 'CWE-95' }, file); },
    AssignmentExpression(p) { const left = member(p.node.left).replace(/^window\.(?=location)/, ''); for (const rule of rules) if (rule.kind === 'assignment' && (left === rule.match || left.endsWith('.' + rule.match))) inspectSink(p, p.get('right'), rule, file); if (/\.(?:src|srcdoc)$/.test(left) && /script|iframe/i.test(left)) inspectSink(p, p.get('right'), { name: left, category: 'Dynamic loading', context: left.endsWith('srcdoc') ? 'html' : 'url', severity: 'high', cwe: 'CWE-829' }, file); },
    JSXAttribute(p) { if (p.node.name.name === 'dangerouslySetInnerHTML' && p.get('value').isJSXExpressionContainer()) inspectSink(p, p.get('value.expression'), rules.find(r => r.kind === 'jsx'), file); },
  });
  const seenFindings = new Set(); const uniqueFindings = findings.filter(f => { const key = `${f.file}:${f.line}:${f.title}`; if (seenFindings.has(key)) return false; seenFindings.add(key); return true; }).map((f, i) => ({ ...f, id: `WT-${String(i + 1).padStart(3, '0')}` }));
  const weights = { critical: 30, high: 18, medium: 7, low: 2, info: 0 };
  const exposure = Math.min(100, Math.round(uniqueFindings.reduce((n, f) => n + weights[f.severity] * (f.confidence === 'high' ? 1 : .65), 0)));
  const breakdown = ['Secrets', 'XSS', 'API', 'Navigation', 'Code execution', 'Storage'].map(category => ({ category, score: Math.min(10, uniqueFindings.filter(f => f.category === category).reduce((s, f) => s + weights[f.severity] / 3, 0)) }));
  for (const route of routes) { putNode({ ...route, type: 'route', label: route.path }); edge(id('file', route.file), route.id, 'defines'); }
  for (const fn of functions) fn.returns = fnStates.get(fn.id).returns.map(value => ({ sourceId: value.source, controls: value.controls, confidence: value.uncertain ? 'medium' : 'high' }));
  const cleanFiles = files.map(({ text, formatted, ...file }) => ({ ...file, content: text ? redact(text) : null, formatted: formatted || null }));
  const report = {
    application: { name: name.replace(/\.zip$/i, ''), analyzedAt: new Date().toISOString(), durationMs: Date.now() - began, technologies: [...technologies], exposure, scoreLabel: 'Static Analysis Exposure Score', scoring: 'Heuristic sum: critical 30, high 18, medium 7, low 2, info 0; medium-confidence findings weighted 0.65; capped at 100. Not CVSS and not a safety certificate.', breakdown, counts: { files: files.length, javascript: files.filter(f => /^(?:[cm]?[jt]sx?)$/.test(f.type)).length, parsed: cleanFiles.filter(f => f.parsed).length, functions: functions.length, endpoints: apis.length, secrets: secrets.length, findings: uniqueFindings.length, high: uniqueFindings.filter(f => ['high', 'critical'].includes(f.severity)).length, routes: routes.length }, coverage: { fixedPointPasses: iterations, converged: !changed, compiledFiles: files.filter(f => f.minified).length, recoveredSources: files.filter(f => f.recoveredFrom).length } },
    files: cleanFiles, endpointCandidates, modules: modules.map(m => ({ ...m, exports: m.exports.map(({ node, ...e }) => e) })), functions, routes, apis, dependencies, secrets, sources: [...sourceMap.values()], sinks: [...sinkMap.values()], flows, call_graph: [...edges.values()].filter(e => e.type === 'calls'), graph: { nodes: [...nodes.values()], edges: [...edges.values()] }, findings: uniqueFindings, anomalies: [...new Map(anomalies.map(a => [a.id, a])).values()], warnings, limitations: LIMITATIONS, rules: { sinks: rules, sources: sourceNames }, recommendations: ['Manually validate high-confidence paths in an isolated authorized environment.', 'Confirm server-side authorization independently of frontend UI checks.', 'Verify whether exposed credential candidates are live and rotate confirmed secrets.'],
  };
  // Redaction also covers strings, labels and endpoints that may embed credentials.
  const clean = value => typeof value === 'string' ? redact(value) : Array.isArray(value) ? value.map(clean) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([k, v]) => [k, clean(v)])) : value;
  return clean(report);
}
