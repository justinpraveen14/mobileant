import { parentPort, workerData } from 'node:worker_threads';
import { analyze, redact } from './analyzer.js';
try { parentPort.postMessage({ result: analyze(workerData.files, workerData.name, workerData.custom, workerData.options) }); }
catch (error) { parentPort.postMessage({ error: redact(error.message) }); }
