const MIN_PASSWORD_CHARACTERS = 12;
const MAX_PASSWORD_BYTES = 1024;

// This is a deliberately small local denylist, not a claim to detect every
// breached password. Normalize case and separators to catch common variants.
const COMMON_PASSWORDS = new Set([
  'password',
  'password1',
  'password12',
  'password123',
  'password1234',
  'password12345',
  'password123456',
  'admin123',
  'admin1234',
  'administrator123',
  'welcome123',
  'welcome1234',
  'letmein123',
  'letmein1234',
  'qwerty123',
  'qwerty1234',
  'qwertyuiop',
  'qwertyuiop12',
  'abc123456789',
  'abcdefghijk',
  'abcdefghijkl',
  '123456789012',
  '1234567890',
  '111111111111',
  '000000000000',
  'iloveyou1234',
  'changeme1234',
  'student123456',
  'teacher123456',
]);

const normalizePassword = (value: string) => value.toLowerCase().replace(/[^a-z0-9]/g, '');

export const validatePassword = (value: unknown): string | null => {
  if (typeof value !== 'string') return 'Vul een wachtwoord in.';
  if (Array.from(value).length < MIN_PASSWORD_CHARACTERS) {
    return `Het wachtwoord moet minimaal ${MIN_PASSWORD_CHARACTERS} tekens bevatten.`;
  }
  if (Buffer.byteLength(value, 'utf8') > MAX_PASSWORD_BYTES) {
    return `Het wachtwoord mag maximaal ${MAX_PASSWORD_BYTES} UTF-8-bytes bevatten.`;
  }
  if (COMMON_PASSWORDS.has(normalizePassword(value))) {
    return 'Kies een minder voorspelbaar wachtwoord; dit wachtwoord of patroon komt te vaak voor.';
  }
  return null;
};
