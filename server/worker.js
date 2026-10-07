import { parentPort, workerData } from 'node:worker_threads';
import { readArchive } from './archive.js';
import { analyze, redact } from './analyzer.js';
try { parentPort.postMessage({ result: analyze(await readArchive(Buffer.from(workerData.buffer)), workerData.name, workerData.custom) }); }
catch (error) { parentPort.postMessage({ error: redact(error.message) }); }
