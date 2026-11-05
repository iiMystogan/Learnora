import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveClientIpAddress } from '../security/client-ip.ts';

test('forwarded client IP is ignored unless explicitly trusted', () => {
  assert.deepEqual(
    resolveClientIpAddress('203.0.113.10', '10.0.0.4', false),
    { ip: '10.0.0.4', source: 'socket' },
  );
});

test('an explicitly trusted valid ingress header supplies the client IP', () => {
  assert.deepEqual(
    resolveClientIpAddress('203.0.113.10', '10.0.0.4', true),
    { ip: '203.0.113.10', source: 'trusted-header' },
  );
});

test('invalid trusted header falls back to the socket peer', () => {
  assert.deepEqual(
    resolveClientIpAddress('203.0.113.10, 10.0.0.4', '10.0.0.4', true),
    { ip: '10.0.0.4', source: 'socket' },
  );
});

test('missing or invalid socket address returns a stable unknown value', () => {
  assert.deepEqual(
    resolveClientIpAddress(undefined, undefined, false),
    { ip: 'unknown', source: 'socket' },
  );
});
