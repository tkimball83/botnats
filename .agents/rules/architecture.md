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
- Use Core NATS pub/sub only for auto-coordination requests (op, invite, limit, unban).
  Broadcast a request; every eligible peer acts after a short random delay and rechecks IRC state
  first. Occasional duplicate idempotent IRC commands are acceptable.
- Use JetStream KV watches for state convergence; no manual sync protocol.
- Cache JetStream KV state in bot memory for fast reads.
- Keep durable keys independent of negotiated IRC casemapping; rekey only in-memory IRC lookups.
- Access state through its owner; no forwarding properties, and no copies of another object's
  attributes in your own fields (`self.caps = bot.caps`).
- `Bot` is the composition root: it constructs and wires components, and runs maintenance and
  shutdown. Keep other behavior in owners (`caps`, the IRC client, `Tasks`, `SelfIdentity`).
- Components that coordinate several owners (IRC events, commands and AUTH, the channel manager,
  NATS callbacks) receive `Bot`; every other component receives only the owners it uses. Never
  pass callback bundles.
- Prefer direct callback wiring over reflective registries.

## Command model

- Execute admin commands (op, deop, ban, unban, invite) directly on the receiving bot.
- Do not relay admin commands through peer bots via NATS.

## Layout

- Prefer flat modules over subpackages; use subpackages for genuine domain boundaries, not arbitrary
  grouping.
- Keep one domain per module: split a module that holds two domains (authentication and command
  handling, say), and merge classes of one domain. Never add re-export layers.
