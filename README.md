# WebTrace Security Analyzer

A local-first React application for investigating static web application ZIPs. It reads archives in memory, parses JavaScript/TypeScript with Babel, builds approximate call/data-flow graphs and correlates evidence into reviewable findings. It never executes uploaded code or probes discovered endpoints.

## Run

Requires Node.js 22.12+ (validated with Node 24).

```sh
npm ci --cache /workspace/.npm-cache
npm run dev
```

The app listens on port 3000, bound to `127.0.0.1` by default. For a cloud development server, explicitly set `HOST=0.0.0.0`. Set `PORT` to change the port.

```sh
npm test
npm run build
npm start
```

Production serves the built React app and analysis API from the same server. This is a single-user investigation tool, not an authenticated multi-tenant service. Bind to localhost or put it behind an authenticated, TLS-enabled gateway before exposing it to others. Uploads and results are held in memory; the server does not persist archives. Browser results disappear on refresh. Export reports to retain them.

## Workflow

1. Upload a ZIP, or choose **Explore example** to scan the bundled, intentionally unsafe sample.
2. Review inventory and coverage. Explore original/formatted code, functions, imports, dependencies, calls and input-to-sink paths.
3. Investigate findings and anomalies. Each correlated finding includes status, confidence, source/sink evidence, validation and remediation.
4. Export redacted JSON, Markdown or inert HTML. JSON includes full node/edge graph data and redacted source text.
5. Optionally configure an OmniRouter/OpenAI-compatible endpoint and model in Settings. Review outgoing evidence and explicitly choose **Send redacted evidence**. The archive is never sent wholesale.

## AI privacy and configuration

AI requests originate directly in the browser. A localhost endpoint refers to the machine running your browser. The endpoint must support `POST /chat/completions` below your configured base URL and allow this application's origin via CORS. Use HTTPS for remote endpoints; HTTP is restricted to loopback. No endpoint or key is hard-coded. Keys live only in React memory and are never stored in localStorage, exported or logged. Only non-secret connection settings can be saved in the browser. Structured evidence includes redacted finding snippets; optional selected code is limited to 16,000 characters. AI output is unverified, cited assistance and must be checked against the underlying source.

## Analysis and coverage

- Babel ASTs for JS, JSX, TS and TSX, including minified files; parser-backed formatting.
- Embedded `sourcesContent` recovery from JSON source maps, with virtual file provenance.
- Functions, methods, classes, imports, exports and dynamic-import inventory.
- Lexical calls, named/default local imports, simple object methods and same-class `this` methods; unresolved calls are explicitly lower confidence.
- Bounded, flow-insensitive and context-insensitive taint propagation through assignments, parameters, returns, selected callbacks, objects, arrays and common transformations. Twelve fixed-point passes; recursive expression evaluation is bounded.
- Structured source/sink database, exact-expression custom rules and HTML-context recognition of imported DOMPurify. Decoding after sanitization invalidates that recognized control.
- Fetch, axios/ky/superagent method calls, basic XHR naming patterns, WebSocket, EventSource and sendBeacon request inventory; route candidates from React Route elements and path properties.
- Format/assignment-based credential candidate detection with redacted content and explicit confidence. No credential validity checks.
- Package metadata and partial lockfile indicators; no CVE database or vulnerability claims based on names alone.
- Indicators for postMessage, localhost requests, service workers, browser extensions, role comparisons, deep-object operations and external scripts.
- Interactive React Flow graphs with search, node-type filtering, zoom/pan and source navigation. Views are capped at 180 nodes; complete graph data remains exportable.

Read the engine's `limitations` in every report. Dynamic dispatch, framework state, branch feasibility, network reachability, backend authorization and prototype-pollution gadgets are not proven. WebAssembly is inventoried but not decompiled. HTML/CSS/SVG/config receive inventory and targeted checks, not complete browser-semantic analysis. External source-map URLs and dependencies are never fetched during analysis. Public client identifiers are not automatically proof of secret exposure. Detection and redaction cannot guarantee every secret format is recognized; review evidence before enabling optional AI.

Exposure scoring is a documented heuristic, not CVSS or a security certification. API presence alone does not produce an exploitability claim. Browser-controlled request destinations are not called server-side SSRF.

## ZIP safety

20 MB upload; 64 MB total expanded size; 8 MB per entry; 2,000 entries; high compression-ratio rejection; no symlinks, encrypted entries or traversal/absolute paths. Embedded source-map recovery is separately capped at 24 MB and 2,500 total files. Archives are read lazily without filesystem extraction. Nested archives are inventoried, never recursively expanded. Parsing runs in a worker with a 384 MB heap and 45-second timeout. At most two analysis/upload operations are accepted simultaneously. Cross-site browser API requests are rejected. The API key never goes through the app server.

## Custom rules

Settings accepts exact source expressions and call/assignment sinks:

```json
{
  "sources": [{ "match": "window.customInput" }],
  "sinks": [{ "match": "unsafeRender", "kind": "call", "argument": 0, "context": "html" }]
}
```

Rules apply to the next scan. Built-in rules are in `server/rules.js`. Custom rules are not executable plugins.

## Validation

`npm test` exercises interprocedural flows, local imports, constant sinks, sanitizer identity/order, messages, endpoint inventory, credential redaction, source maps, custom rules, symbol extraction and ZIP safety. The example is analyzed through the same API as user uploads. No uploaded JavaScript is executed.
