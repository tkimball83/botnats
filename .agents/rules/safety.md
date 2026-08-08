# Safety

Fail closed. Mesh-wide auth limits. Signed envelopes.

## Authentication

- Treat authentication failures as denied.
- Keep auth fail-closed when NATS or JetStream is unavailable.
- Keep authentication attempt limits mesh-wide.
- Move active sessions on observed NICK changes.
- Require new authentication after CHGHOST or any identity change.
- Store revocations in JetStream KV with TTL matching session expiry.
- Sign the identity, expiry, issuer, version, and revocation state of every durable session mutation.
- Reject malformed, expired, future-dated, or incorrectly signed session records before they affect
  local authorization state.
- The fail-closed boundary is at authentication, not at operational IRC command execution. Durable
  `JOIN` and `PART` configuration changes still require JetStream.

## Coordination

- Bind signed NATS envelopes to their exact subjects.
- Avoid explicit Core NATS flushes when ordered subscribe and publish suffice.
- Rely on JetStream KV watches for state convergence; no manual sync protocol.
- Require complete initial replay from every state watch before reporting coordination readiness.
- Detect duplicate bot IDs via JetStream KV presence keys with instance ID comparison.
- Claim and refresh presence with compare-and-set so only the owning process can keep an ID live.
- Enforce unique bot IDs case-insensitively across the mesh.
- Do not gate admin command execution on coordinator readiness; the auth flow is the gate.

## Secrets

- Never log tokens, TOTP secrets, or channel keys.
- Keep the NATS monitoring port private.

## Connectivity

- Support both `irc://` and `ircs://`; do not assume TLS.
- Support token-authenticated `nats://`; do not require client certificates.
