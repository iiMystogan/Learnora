import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

test('frontend does not introduce raw HTML or dynamic code execution sinks', async () => {
  const source = await readFile(path.join(process.cwd(), 'src', 'App.tsx'), 'utf8');
  const forbiddenSinks = [
    'dangerouslySetInnerHTML',
    '.innerHTML =',
    '.outerHTML =',
    'document.write(',
    'eval(',
    'new Function(',
  ];

  for (const sink of forbiddenSinks) {
    assert.equal(source.includes(sink), false, `Unexpected unsafe frontend sink: ${sink}`);
  }
});
