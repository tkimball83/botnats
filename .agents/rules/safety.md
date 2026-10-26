# Safety

Fail closed. Mesh-wide auth limits. Signed records and envelopes.

## Authentication

- Treat authentication failures as denied.
- AUTH requires NATS and JetStream for mesh-wide attempt limits and TOTP claim dedup.
- Once authenticated, IRC commands run on cached session state without waiting on coordinator
  readiness; durable `JOIN` and `PART` changes still require JetStream.
- Revoke a session on QUIT, NICK, CHGHOST, or any other identity change; the new identity must
  authenticate again.
- Store revocations in JetStream KV with TTL matching session expiry.
- Sign the network, identity, expiry, issuer, version, and revocation state of every durable
  session mutation.
- Reject malformed, expired, future-dated, or incorrectly signed session records before they
  affect local authorization.

## Coordination

- Bind signed NATS envelopes to their exact subjects.
- Avoid explicit Core NATS flushes when ordered subscribe and publish suffice.
- Report readiness only after every state watch completes its initial replay; a watch restart
  invalidates readiness.
- Claim each bot ID case-insensitively through its presence key with compare-and-set; detect
  duplicates by instance ID, refresh only the revision this process owns, and accept a presence
  record only under its own bot ID's key.

## Secrets

- Never log tokens, the TOTP or coordination secret, or channel keys.
- Keep the NATS monitoring port private.

## Connectivity

- Support both `irc://` and `ircs://`; do not assume TLS.
- Support token-authenticated `nats://`; do not require client certificates.
