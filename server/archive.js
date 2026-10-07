import yauzl from 'yauzl';
import path from 'node:path';
import { createHash } from 'node:crypto';

export const LIMITS = { upload: 20 * 1024 * 1024, total: 64 * 1024 * 1024, file: 8 * 1024 * 1024, entries: 2000 };
const readable = /\.(?:[cm]?[jt]sx?|html?|css|json|map|ya?ml|toml|txt|env|md)$|(?:^|\/)(?:\.env(?:\.[^/]*)?|Dockerfile|yarn\.lock|package-lock\.json|pnpm-lock\.yaml)$/i;
export function readArchive(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true, validateEntrySizes: true, strictFileNames: true }, (error, zip) => {
      if (error) return reject(new Error('This file is not a readable ZIP archive.'));
      const files = []; let total = 0; let count = 0; let settled = false;
      const fail = error => { if (!settled) { settled = true; zip.close(); reject(error); } };
      zip.on('error', fail);
      zip.on('end', () => { if (!settled) { settled = true; resolve(files); } });
      zip.on('entry', entry => {
        const name = entry.fileName;
        if (++count > LIMITS.entries) return fail(new Error('Archive exceeds the 2,000-entry limit.'));
        if (name.includes('\0') || name.startsWith('/') || /^[A-Za-z]:/.test(name) || name.split('/').includes('..') || path.posix.normalize(name) !== name.replace(/\/$/, '') && !name.endsWith('/')) return fail(new Error('Unsafe archive path rejected.'));
        if (entry.generalPurposeBitFlag & 1) return fail(new Error('Encrypted ZIP files are not supported.'));
        if (((entry.externalFileAttributes >>> 16) & 0xf000) === 0xa000) return fail(new Error('Symbolic links are not supported.'));
        if (name.endsWith('/')) { zip.readEntry(); return; }
        total += entry.uncompressedSize;
        if (total > LIMITS.total || entry.uncompressedSize > LIMITS.file) return fail(new Error('Archive exceeds the 64 MB expanded / 8 MB per-file limit.'));
        if (entry.uncompressedSize > 1024 * 1024 && entry.uncompressedSize / Math.max(1, entry.compressedSize) > 250) return fail(new Error('Suspicious ZIP compression ratio rejected.'));
        const item = { path: name, size: entry.uncompressedSize, type: path.extname(name).slice(1) || 'other' };
        if (!readable.test(name)) { files.push({ ...item, role: 'asset', risk: 'info', hash: null }); zip.readEntry(); return; }
        zip.openReadStream(entry, (error, stream) => {
          if (error) return fail(error);
          const chunks = []; let size = 0;
          stream.on('error', fail);
          stream.on('data', chunk => { size += chunk.length; if (size > LIMITS.file) { stream.destroy(); fail(new Error('Expanded file limit exceeded.')); } else chunks.push(chunk); });
          stream.on('end', () => { if (settled) return; const bytes = Buffer.concat(chunks); files.push({ ...item, text: bytes.toString('utf8'), hash: createHash('sha256').update(bytes).digest('hex'), role: 'source', risk: 'info' }); zip.readEntry(); });
        });
      });
      zip.readEntry();
    });
  });
}
