import fs from 'node:fs';
import path from 'node:path';

const ZIP_SIGNATURES = [
  Buffer.from([0x50, 0x4b, 0x03, 0x04]),
  Buffer.from([0x50, 0x4b, 0x05, 0x06]),
  Buffer.from([0x50, 0x4b, 0x07, 0x08]),
];
const LEGACY_WORD_SIGNATURE = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);

/**
 * Checks that the uploaded file's leading bytes match its allowed extension.
 * This is a lightweight format check, not malware scanning or full document validation.
 */
export function validateSubmissionFile(filePath: string, originalFilename: string): boolean {
  const extension = path.extname(originalFilename).toLowerCase();
  if (!['.pdf', '.doc', '.docx', '.zip'].includes(extension)) return false;

  let descriptor: number | undefined;
  try {
    descriptor = fs.openSync(filePath, 'r');
    const sample = Buffer.alloc(extension === '.pdf' ? 1024 : 8);
    const bytesRead = fs.readSync(descriptor, sample, 0, sample.length, 0);
    const header = sample.subarray(0, bytesRead);

    if (extension === '.pdf') return header.includes(Buffer.from('%PDF-'));
    if (extension === '.doc') return header.length >= 8 && header.subarray(0, 8).equals(LEGACY_WORD_SIGNATURE);
    return ZIP_SIGNATURES.some((signature) => header.length >= signature.length && header.subarray(0, signature.length).equals(signature));
  } catch {
    return false;
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}
