import { isIP } from 'node:net';

export type ClientIpSource = 'trusted-header' | 'socket';

export interface ClientIpAddress {
  ip: string;
  source: ClientIpSource;
}

/**
 * Resolve a client address without implicitly trusting proxy headers.
 * A forwarding header is authoritative only when the deployment explicitly
 * configures that exact header and its ingress trust boundary is documented.
 */
export function resolveClientIpAddress(
  forwardedValue: unknown,
  remoteAddress: unknown,
  trustForwardedHeader: boolean,
): ClientIpAddress {
  if (trustForwardedHeader && typeof forwardedValue === 'string') {
    const candidate = forwardedValue.trim();
    if (isIP(candidate)) return { ip: candidate, source: 'trusted-header' };
  }

  if (typeof remoteAddress === 'string' && isIP(remoteAddress)) {
    return { ip: remoteAddress, source: 'socket' };
  }

  return { ip: 'unknown', source: 'socket' };
}
