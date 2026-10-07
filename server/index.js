import express from 'express';
import { createServer as createHttpServer } from 'node:http';
import multer from 'multer';
import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { LIMITS } from './archive.js';
const app = express();
const httpServer = createHttpServer(app);
app.disable('x-powered-by');
app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'no-referrer'); next(); });
app.get('/api/health', (req, res) => res.json({ status: 'ok', engine: 'static-ast-v1' }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: LIMITS.upload, files: 1, fields: 1, fieldSize: 16384 } });
let active = 0;
app.use('/api', (req, res, next) => {
  if (req.get('sec-fetch-site') === 'cross-site') return res.status(403).json({ error: 'Cross-site API requests are rejected.' });
  const origin = req.get('origin');
  if (origin) { try { if (new URL(origin).host !== req.get('host')) return res.status(403).json({ error: 'Origin mismatch.' }); } catch { return res.status(403).json({ error: 'Invalid origin.' }); } }
  next();
});
app.post('/api/analyze', (req, res, next) => {
  if (active >= 2) return res.status(429).json({ error: 'The analyzer is busy. Please try again shortly.' });
  active++;
  let released = false;
  const release = () => { if (!released) { active--; released = true; } };
  res.on('close', release);
  upload.single('archive')(req, res, error => {
    if (error) { release(); return next(error); }
    if (!req.file) { release(); return res.status(400).json({ error: 'Attach a ZIP file in the archive field.' }); }
    let custom; try { custom = JSON.parse(req.body?.rules || '{\"sources\":[],\"sinks\":[]}'); if (!custom || !Array.isArray(custom.sources) || !Array.isArray(custom.sinks) || custom.sources.length > 30 || custom.sinks.length > 30 || [...custom.sources, ...custom.sinks].some(rule => !rule || typeof rule.match !== 'string' || rule.match.length > 120)) throw new Error(); } catch { release(); return res.status(400).json({ error: 'Invalid custom rules. Use sources and sinks arrays with up to 30 exact-expression rules each.' }); }
    const worker = new Worker(new URL('./worker.js', import.meta.url), { workerData: { buffer: req.file.buffer, name: req.file.originalname, custom }, resourceLimits: { maxOldGenerationSizeMb: 384 } });
    res.on('close', () => { if (!res.writableFinished) worker.terminate(); });
    const timer = setTimeout(() => { worker.terminate(); release(); if (!res.headersSent && !res.destroyed) res.status(422).json({ error: 'Analysis exceeded the 120-second safety limit. Try a smaller archive.' }); }, 120000);
    worker.on('message', message => { if (message.progress) return; clearTimeout(timer); release(); if (!res.headersSent && !res.destroyed) res.status(message.error ? 422 : 200).json(message.error ? { error: message.error } : message.result); worker.terminate(); });
    worker.on('error', error => { clearTimeout(timer); release(); if (!res.headersSent && !res.destroyed) res.status(422).json({ error: error.code === 'ERR_WORKER_OUT_OF_MEMORY' ? 'The report exceeded the worker memory budget. Try a smaller archive; completed batch results could not be returned.' : 'The analysis worker failed unexpectedly. Try again or review the archive format.' }); });
    worker.on('exit', () => { clearTimeout(timer); release(); if (!res.headersSent && !res.destroyed) res.status(422).json({ error: 'Analysis worker exited before producing a report.' }); });
    req.on('aborted', () => { clearTimeout(timer); worker.terminate(); release(); });
  });
});
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(root, 'dist')));
  app.get('/{*path}', (req, res) => res.sendFile(path.join(root, 'dist/index.html')));
} else {
  const { createServer } = await import('vite');
  const vite = await createServer({ root, server: { middlewareMode: true, hmr: { server: httpServer } }, appType: 'spa' });
  app.use(vite.middlewares);
}
app.use((error, req, res, next) => { if (!res.headersSent) res.status(400).json({ error: error.code === 'LIMIT_FILE_SIZE' ? 'ZIP files must be under 20 MB.' : error instanceof multer.MulterError ? 'Invalid upload. Send one ZIP archive only.' : 'The request could not be processed.' }); });
const port = Number(process.env.PORT || 3000);
httpServer.listen(port, process.env.HOST || '127.0.0.1', () => console.log(`WebTrace listening on port ${port}`));
