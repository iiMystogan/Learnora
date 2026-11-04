import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

test('frontend does not introduce raw HTML or dynamic code execution sinks', async () => {
  const source = await readFile(path.join(process.cwd(), 'src', 'App.tsx'), 'utf8');
  const forbiddenPatterns = [
    /dangerouslySetInnerHTML/,
    /\\.innerHTML\\s*=/,
    /\\.outerHTML\\s*=/,
    /document\\.write\\s*\\(/,
    /\\beval\\s*\\(/,
    /new\\s+Function\\s*\\(/,
  ];

  for (const pattern of forbiddenPatterns) {
    assert.doesNotMatch(source, pattern, `Unexpected unsafe frontend sink: ${pattern}`);
  }
});
