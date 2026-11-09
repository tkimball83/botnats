# Architecture

Stateless bots share durable state through JetStream KV.

## Process model

- One IRC network per bot process; multiple IRC servers are failover endpoints.
- Assume bots restart without local state.

## State ownership

- Store sessions, channel records, auth attempts, TOTP claims, and presence in JetStream KV.
- Revoke a session with a signed, versioned record; never delete its durable key to revoke it.
- Use Core NATS pub/sub only for help requests (op, invite, limit, unban): every eligible peer
  acts after a short random delay and rechecks IRC state first. Duplicate idempotent IRC
  commands are acceptable.
- Converge state through JetStream KV watches, cached in memory; no manual sync protocol.
- Keep durable keys independent of IRC casemapping; rekey only in-memory lookups.
- Access state through its owner: no forwarding properties, and no copies of another object's
  attributes (`self.caps = bot.caps`).
- `Bot` only constructs and wires components, and runs maintenance and shutdown. Behavior lives in
  its owners.
- Components that coordinate several owners (events, commands and AUTH, the channel manager, NATS
  callbacks) receive `Bot`; others receive only the owners they use. No callback bundles.
- Prefer direct callback wiring over reflective registries.

## Command model

- Admin commands (op, deop, ban, unban, invite) run on the receiving bot; never relay them
  through peers.

## Layout

- Prefer flat modules; use subpackages only for genuine domain boundaries.
- One domain per module: split a module that holds two, merge classes of one. No re-export
  layers.
