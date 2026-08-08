# Architecture

Stateless bots share durable state through JetStream KV.

## Process model

- Scope each bot process to one IRC network.
- Allow multiple IRC servers as failover endpoints.
- Assume bots restart without local state.

## State ownership

- Store auth sessions, channel records, and auth limits in JetStream KV.
- Represent session revocation as a signed, versioned record; do not delete the durable session key to
  revoke access.
- Order competing channel and session mutations in their stores with compare-and-set, and make writers
  apply the authoritative record returned by the store.
- Use Core NATS pub/sub only for auto-coordination offers (op, invite, unban).
- Use JetStream KV watches for state convergence; no manual sync protocol.
- Cache JetStream KV state in bot memory for fast reads.
- Treat a watch as ready only after its initial replay completes; invalidate readiness when it restarts.
- Keep durable keys independent of negotiated IRC casemapping; rekey only in-memory IRC lookups.
- Claim each case-insensitive bot ID through its presence key, and refresh only the revision owned by
  that process.
- Access state through its owner; no forwarding properties.
- Pass an owning object to its helper, not callback bundles.
- Prefer direct callback wiring over reflective registries.

## Command model

- Execute admin commands (op, deop, ban, unban, invite) directly on the receiving bot.
- Do not relay admin commands through peer bots via NATS offers.
- Authentication is the fail-closed gate: it requires JetStream for rate limits and TOTP claim dedup.
- Once authenticated, operational IRC commands execute locally using cached session state; durable
  `JOIN` and `PART` configuration changes still require JetStream.

## Layout

- Prefer flat modules over subpackages; use subpackages for genuine domain boundaries, not arbitrary
  grouping.
- Merge related classes into one module rather than splitting across files with re-export layers.
