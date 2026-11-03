# Learnora network security and private networking

## Current deployment inventory (reviewed 4 November 2026)

The Railway production environment currently contains one application service: **Learnora**.

- Public HTTP domain: `learnora-production-4fa5.up.railway.app` (the user-facing application).
- Private DNS endpoint: `learnora.railway.internal`.
- Additional services in the production environment: none at the time of review.
- Public TCP proxies: none at the time of review.
- The application listens on its configured HTTP port and is not intended to expose a separate internal-only API listener.

This is an inventory snapshot, not a permanent guarantee. Re-check the live Railway environment before adding a service, TCP proxy, or internal integration.

## What the private network boundary means

Railway private networking is isolated by project and environment. Services in the same environment share the private-network trust boundary and can reach one another over their internal endpoints. Railway does not provide a per-service allowlist/firewall within that environment. Therefore, adding another service to production also adds another workload that can potentially reach Learnora's listening port.

At the current inventory, Learnora is the only service in that environment, so there is no separate peer service to restrict. The private endpoint is retained for platform networking compatibility; it is not treated as an authentication or authorization boundary. Application authorization must remain mandatory on every protected endpoint.

## Rules before adding internal services

1. Do not add a worker, database proxy, monitoring agent, or other service to production without reviewing whether it needs to contact Learnora.
2. Treat every service in the same Railway project environment as trusted to reach every listening port unless application-level authentication says otherwise.
3. Do not expose a TCP proxy to the Learnora HTTP listener.
4. Do not add unauthenticated internal routes on the assumption that `*.railway.internal` is private.
5. If a new internal caller is required, authenticate it at the application layer (for example, with a dedicated service credential or mutual TLS where the eventual platform supports it) and limit its permissions. Do not rely on source IP or private DNS as identity.
6. Review this document and the deployment inventory whenever services, domains, proxies, or environments change.

## Client IP and login rate limiting

Learnora does not trust `X-Forwarded-For` or any other forwarding header by default. The socket peer address is used as a fallback. Because a reverse proxy may make many visitors appear to share one socket address, the IP-wide login rate-limit bucket is enabled only when an operator explicitly configures a trusted ingress header.

Set `TRUSTED_CLIENT_IP_HEADER` only when all of the following are true:

- The configured ingress overwrites that exact header with the original client IP rather than appending to caller-supplied values.
- Every path to the application listener is trusted. There must be no untrusted private-network peer or TCP proxy that can bypass the ingress and send the header itself.
- The header contains exactly one IP address (IPv4 or IPv6), not a comma-separated proxy chain.

For the current Railway topology, `x-real-ip` is overwritten by the public HTTP edge, but private-network requests bypass that edge's header sanitization. Railway has confirmed that it does not provide a stable ingress peer range or an authenticated edge identity that the application can use to distinguish those paths. Trusting `x-real-ip` is therefore valid only while every service in the production environment is trusted and no other service or TCP proxy can reach the listener. Reassess before adding any service.

For another hosting provider, leave the setting unset until its proxy contract and all alternate ingress paths have been verified. Do not copy a Railway-specific header assumption to another provider.

When no trusted header is configured, Learnora avoids applying an IP-wide limit to the shared reverse-proxy socket address. The per-identity limit remains active. When a trusted header is configured and valid, both the identity and IP-wide limits apply.

## Portability

The application uses the provider-neutral `TRUSTED_CLIENT_IP_HEADER` setting rather than hard-coding Railway header names or proxy hop counts. Hosting-specific trust assumptions belong in deployment configuration and must be reviewed when the provider or network topology changes.

## References

- [Railway private networking](https://docs.railway.com/networking/private-networking)
- [How Railway private networking works](https://docs.railway.com/networking/private-networking/how-it-works)
- [Railway private networking and domains](https://docs.railway.com/networking/domains/working-with-domains)
- [Railway confirmation about trusted client IP and private-network bypass](https://station.railway.com/questions/asp-net-core-trusted-ingress-boundary-an-ea6cad35)

Last reviewed: 4 November 2026.
