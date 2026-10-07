import { parentPort, workerData } from 'node:worker_threads';
import { readArchive } from './archive.js';
import { redact } from './analyzer.js';
import { analyzeInBatches } from './pipeline.js';
try { parentPort.postMessage({ result: await analyzeInBatches(await readArchive(Buffer.from(workerData.buffer)), workerData.name, workerData.custom, { onProgress: progress => parentPort.postMessage({ progress }) }) }); }
catch (error) { parentPort.postMessage({ error: redact(error.message) }); }
