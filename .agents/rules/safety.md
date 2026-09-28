# Safety

Fail closed. Mesh-wide auth limits. Signed envelopes.

## Authentication

- Treat authentication failures as denied.
- Authentication is the fail-closed gate: it requires NATS and JetStream for mesh-wide attempt
  limits and TOTP claim dedup.
- Once authenticated, operational IRC commands execute locally on cached session state without
  gating on coordinator readiness; durable `JOIN` and `PART` configuration changes still require
  JetStream.
- Require new authentication after NICK, CHGHOST, or any identity change; revoke the old
  identity's session.
- Store revocations in JetStream KV with TTL matching session expiry.
- Sign the identity, expiry, issuer, version, and revocation state of every durable session mutation.
- Reject malformed, expired, future-dated, or incorrectly signed session records before they affect
  local authorization state.

## Coordination

- Bind signed NATS envelopes to their exact subjects.
- Avoid explicit Core NATS flushes when ordered subscribe and publish suffice.
- Require complete initial replay from every state watch before reporting coordination readiness;
  invalidate readiness when a watch restarts.
- Claim each bot ID case-insensitively through its JetStream KV presence key with compare-and-set;
  detect duplicates by instance ID, and refresh only the revision this process owns.

## Secrets

- Never log tokens, TOTP secrets, or channel keys.
- Keep the NATS monitoring port private.

## Connectivity

- Support both `irc://` and `ircs://`; do not assume TLS.
- Support token-authenticated `nats://`; do not require client certificates.
