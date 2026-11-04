import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { validateSubmissionFile } from '../security/upload-validation.ts';

test('submission upload validation matches the allowed file signatures', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'learnora-upload-validation-'));
  try {
    const samples: Array<{ name: string; bytes: number[]; valid: boolean }> = [
      { name: 'document.pdf', bytes: [...Buffer.from('%PDF-1.7 sample')], valid: true },
      { name: 'document.doc', bytes: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], valid: true },
      { name: 'document.docx', bytes: [0x50, 0x4b, 0x03, 0x04, 0x00], valid: true },
      { name: 'document.zip', bytes: [0x50, 0x4b, 0x05, 0x06], valid: true },
      { name: 'fake.pdf', bytes: [...Buffer.from('<html>not a PDF</html>')], valid: false },
      { name: 'fake.docx', bytes: [...Buffer.from('plain text')], valid: false },
      { name: 'script.html', bytes: [...Buffer.from('<script>alert(1)</script>')], valid: false },
    ];

    for (const sample of samples) {
      const filePath = path.join(directory, sample.name);
      await writeFile(filePath, Buffer.from(sample.bytes));
      assert.equal(validateSubmissionFile(filePath, sample.name), sample.valid, sample.name);
    }
    assert.equal(validateSubmissionFile(path.join(directory, 'missing.pdf'), 'missing.pdf'), false);
    assert.equal(validateSubmissionFile(path.join(directory, 'document.pdf'), 'document.exe'), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
