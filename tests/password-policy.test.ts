import assert from 'node:assert/strict';
import { test } from 'node:test';
import { validatePassword } from '../security/password-policy.ts';

test('password policy accepts long passphrases without composition requirements', () => {
  assert.equal(validatePassword('correct horse battery staple'), null);
  assert.equal(validatePassword('Longer-unique!Passphrase-2026'), null);
});

test('password policy rejects passwords shorter than twelve Unicode characters', () => {
  assert.match(validatePassword('Short123!xx') || '', /minimaal 12 tekens/);
  assert.equal(validatePassword('éééééééééééé'), null, 'Unicode code points count as characters');
});

test('password policy rejects common passwords after case and separator normalization', () => {
  assert.match(validatePassword('PASSWORD-1234') || '', /minder voorspelbaar/);
  assert.match(validatePassword('Welcome_1234') || '', /minder voorspelbaar/);
  assert.match(validatePassword('123456789012') || '', /minder voorspelbaar/);
});

test('password policy rejects values larger than 1024 UTF-8 bytes', () => {
  assert.match(validatePassword('é'.repeat(513)) || '', /maximaal 1024 UTF-8-bytes/);
});
