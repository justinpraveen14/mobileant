// Matching names are extended through Settings; severities describe tainted use, not API presence.
export const SINK_RULES = [
  { name: 'innerHTML', match: 'innerHTML', kind: 'assignment', category: 'XSS', severity: 'high', context: 'html', cwe: 'CWE-79', remediation: 'Use textContent for text. For intentional HTML, sanitize with an audited HTML sanitizer immediately before rendering.' },
  { name: 'outerHTML', match: 'outerHTML', kind: 'assignment', category: 'XSS', severity: 'high', context: 'html', cwe: 'CWE-79' },
  { name: 'dangerouslySetInnerHTML', match: 'dangerouslySetInnerHTML', kind: 'jsx', category: 'XSS', severity: 'high', context: 'html', cwe: 'CWE-79' },
  { name: 'insertAdjacentHTML', match: 'insertAdjacentHTML', kind: 'call', argument: 1, category: 'XSS', severity: 'high', context: 'html', cwe: 'CWE-79' },
  { name: 'document.write', match: 'document.write', kind: 'call', argument: 0, category: 'XSS', severity: 'high', context: 'html', cwe: 'CWE-79' },
  { name: 'eval', match: 'eval', kind: 'call', argument: 0, category: 'Code execution', severity: 'high', context: 'code', cwe: 'CWE-95', remediation: 'Replace runtime code evaluation with explicit, validated data handling.' },
  { name: 'Function', match: 'Function', kind: 'call', argument: -1, category: 'Code execution', severity: 'high', context: 'code', cwe: 'CWE-95' },
  { name: 'location', match: 'location', kind: 'assignment', category: 'Navigation', severity: 'medium', context: 'url', cwe: 'CWE-601' },
  { name: 'location.href', match: 'location.href', kind: 'assignment', category: 'Navigation', severity: 'medium', context: 'url', cwe: 'CWE-601' },
  { name: 'location.assign', match: 'location.assign', kind: 'call', argument: 0, category: 'Navigation', severity: 'medium', context: 'url', cwe: 'CWE-601' },
  { name: 'location.replace', match: 'location.replace', kind: 'call', argument: 0, category: 'Navigation', severity: 'medium', context: 'url', cwe: 'CWE-601' },
  { name: 'window.open', match: 'window.open', kind: 'call', argument: 0, category: 'Navigation', severity: 'medium', context: 'url', cwe: 'CWE-601' },
  { name: 'fetch', match: 'fetch', kind: 'call', argument: 0, category: 'API', severity: 'medium', context: 'network', cwe: 'CWE-20' },
  { name: 'WebSocket', match: 'WebSocket', kind: 'call', argument: 0, category: 'WebSocket', severity: 'medium', context: 'network', cwe: 'CWE-20' },
  { name: 'localStorage.setItem', match: 'localStorage.setItem', kind: 'call', argument: 1, category: 'Storage', severity: 'info', context: 'storage', cwe: 'CWE-922' },
  { name: 'sessionStorage.setItem', match: 'sessionStorage.setItem', kind: 'call', argument: 1, category: 'Storage', severity: 'info', context: 'storage', cwe: 'CWE-922' },
  { name: 'document.cookie', match: 'document.cookie', kind: 'assignment', category: 'Storage', severity: 'low', context: 'storage', cwe: 'CWE-922' },
  { name: 'import', match: 'import', kind: 'call', argument: 0, category: 'Dynamic loading', severity: 'high', context: 'code', cwe: 'CWE-829' },
];
export const SOURCE_NAMES = ['location', 'location.search', 'location.hash', 'location.href', 'location.pathname', 'document.URL', 'document.referrer', 'document.cookie', 'window.name', 'URLSearchParams', 'FormData', 'localStorage.getItem', 'sessionStorage.getItem'];
export const LIMITATIONS = [
  'Static evidence is not proof of exploitability. No uploaded code or discovered endpoint is executed.',
  'Flow analysis is bounded (12 fixed-point passes), flow-insensitive and context-insensitive. Branch feasibility, runtime sanitizers, framework state and event sequencing are not proven.',
  'Direct lexical calls, named/default local imports, simple object methods and same-class this methods are resolved. Dynamic dispatch, re-exports, external libraries and complex aliases may remain unresolved.',
  'Unresolved call outputs conservatively inherit input taint; such paths require runtime validation. Recognized DOMPurify sanitization is only an HTML-context control, not a general safety guarantee.',
  'Source maps recover embedded sourcesContent only. External sources are never fetched. Original and recovered sources can overlap; coverage is reported explicitly.',
  'HTML, SVG, CSS and configuration receive inventory and targeted structural/indicator checks; they do not receive full browser-semantic taint analysis. WebAssembly is inventoried, not decompiled.',
  'No CVE database is bundled. Dependency inventory does not establish vulnerability or vulnerable-function reachability.',
  'Server-side authorization, CSP/CORS headers, endpoint accessibility, prototype-pollution gadgets and exploit impact cannot be confirmed from frontend artifacts alone.',
];
