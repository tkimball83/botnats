# BotNATS

[![License](https://img.shields.io/badge/license-GPLv3-lightgreen)](https://www.gnu.org/licenses/gpl-3.0.en.html#license-text)

BotNATS is an IRC bot mesh. Core NATS carries coordination actions. JetStream KV
stores shared durable state and atomic authentication controls.

## Design

- Each bot connects independently to IRC and NATS.
- Peers converge through JetStream KV watches after startup and reconnecting.
- Signed, versioned channel records and part tombstones reject stale and forged state.
- Signed, versioned session records make authorization and revocation converge across restarts.
- Signed NATS messages bind a nonce and timestamp to the exact subject.
- Automatic op, invite, and unban recovery broadcasts a request; every eligible peer acts
  after a short random delay, rechecking IRC state first. A bot refused by a full channel
  asks peers to raise its limit by the number of bots left out. Admin commands execute
  directly on the receiving bot.
- Each bot ID atomically claims a case-insensitive presence key; duplicates remain unready.
- Authorization binds the visible nick, user, and host. Any identity change,
  NICK included, requires new authentication.

### State

| Data                           | Storage      | Lifetime                     |
| ------------------------------ | ------------ | ---------------------------- |
| Channel configuration and keys | JetStream KV | Until changed or removed     |
| Authorization sessions         | JetStream KV | One hour                     |
| Authentication attempts        | JetStream KV | Two hours                    |
| Used TOTP counters             | JetStream KV | Five minutes                 |
| Bot presence                   | JetStream KV | Configured presence TTL      |

File-backed JetStream preserves channel state and authentication controls across
bot and NATS restarts; sessions and presence still expire at their TTLs.

## Configuration

| Variable                      | Purpose                                                                        |
| ----------------------------- | ------------------------------------------------------------------------------ |
| `BOTNATS_CONFIG`              | JSON config path; `--config` overrides it; defaults to `/etc/botnats/bot.json` |
| `BOTNATS_COORDINATION_SECRET` | HMAC key; at least 32 bytes; required                                          |
| `BOTNATS_LOG_LEVEL`           | Python log level; defaults to `INFO`                                           |
| `BOTNATS_NATS_TOKEN`          | NATS client token; required                                                    |
| `BOTNATS_TOTP_SECRET`         | Base32 TOTP seed; at least 160 bits; required                                  |

Example `bot.json`:

```json
{
  "bot": {
    "health_port": 8080,
    "id": "mybot",
    "network": "undernet",
    "nickname": "mybot"
  },
  "coordination": {
    "maintenance_interval_seconds": 3,
    "presence_ttl_seconds": 15
  },
  "irc": {
    "channel_modes": "+nst",
    "connect_timeout_seconds": 30,
    "servers": [
      "irc://us.undernet.org:6667"
    ]
  },
  "nats": {
    "jetstream_replicas": 3,
    "monitor_port": 8222,
    "servers": [
      "nats://nats.internal:4222"
    ]
  }
}
```

| Setting                                     | Behavior                                                                  |
| ------------------------------------------- | ------------------------------------------------------------------------- |
| `bot.health_port`                           | HTTP liveness and readiness port; 8080 by default                         |
| `bot.id`                                    | Unique mesh ID; compared case-insensitively; required                     |
| `bot.network`                               | One IRC network per process; namespaces shared NATS state; required       |
| `bot.nickname`                              | Nickname and realname; username `botnats`; at most 9 characters; required |
| `coordination.maintenance_interval_seconds` | Seconds between maintenance cycles and presence heartbeats; 3 by default  |
| `coordination.presence_ttl_seconds`         | Must exceed the maintenance interval; 15 seconds by default               |
| `irc.channel_modes`                         | Required (`+`) and forbidden (`-`) modes; empty by default                |
| `irc.connect_timeout_seconds`               | Per-server connection timeout; 30 seconds by default                      |
| `irc.servers`                               | Ordered failover endpoints for the configured network; required           |
| `irc.verify_tls`                            | Applies only to `ircs://` connections; `true` by default                  |
| `nats.jetstream_replicas`                   | Use `3` only when three JetStream storage peers are present; 1 by default |
| `nats.monitor_port`                         | Connected-server monitoring port used by `STATUS`; 8222 by default        |
| `nats.servers`                              | `nats://` endpoints only, tried in any order; required                    |

Plain IRC exposes commands and responses, so use a trusted network when IRCS is
unavailable. JetStream requires file storage; persist each peer's directory.

The NATS client uses TLS only when the server requires it, and nothing stops an
on-path attacker from stripping that request and reading the token, so run NATS
on a private network.

Give the NATS token only to bot processes. NATS attaches no permissions to a
token and refuses one alongside configured users, so every token holder has the
bots' own permissions and other clients need a separate NATS deployment.
Signatures on channel, session, and presence records mean a holder of the token
but not the coordination secret cannot forge state a bot will accept, and the
attempt and claim buckets use secret-derived keys such a holder cannot compute.
None of that stops a writer from deleting or overwriting existing bucket
entries, so a hostile token holder can still churn state (for example,
repeatedly clobbering a presence key to stall a bot's readiness).

## Health

The HTTP server listens on `bot.health_port` (8080 by default):

| Path     | Success requires                                            |
| -------- | ----------------------------------------------------------- |
| `/`      | Process liveness                                            |
| `/ready` | IRC, synchronized NATS state, unique ID, and all KV stores  |

Use `/` for restart decisions and `/ready` for traffic admission.

## Authorization

Enroll the TOTP seed with SHA-1, six digits, and a 30-second period. Then send:

```text
/msg mybot AUTH <totp-code>
```

Authentication allows three attempts per host in a mesh-wide sliding one-hour
window; users sharing a hostname share that budget. Each TOTP counter can be
claimed once. An attempt over the limit, or made while NATS is unavailable, gets
no reply.

Use private messages for every command. Each bot accepts eight private messages
per host in a sliding 10-second window and drops the rest without reply, `AUTH`
included. Commands other than `AUTH` require an active session and are ignored
without one, as are commands from a nick, user, or host that is not valid UTF-8.

| Command    | Arguments                   | Action                       |
| ---------- | --------------------------- | ---------------------------- |
| `AUTH`     | `<totp-code>`               | Authenticate                 |
| `BAN`      | `<channel> <mask>`          | Add a ban                    |
| `DEOP`     | `<channel> <nick>`          | Remove operator status       |
| `GETBANS`  | `<channel>`                 | List tracked bans            |
| `GETCHANS` |                             | List tracked channels        |
| `GETMODES` | `<channel>`                 | Show tracked channel modes   |
| `GETUSERS` | `<channel>`                 | List tracked channel members |
| `INVITE`   | `<channel> <nick>`          | Invite a user                |
| `JOIN`     | `<channel> [key]`           | Add a desired channel        |
| `KICK`     | `<channel> <nick> [reason]` | Kick a user                  |
| `OP`       | `<channel> <nick>`          | Grant operator status        |
| `PART`     | `<channel>`                 | Remove a desired channel     |
| `STATUS`   |                             | Show bot and NATS status     |
| `UNBAN`    | `<channel> <mask>`          | Remove a tracked ban         |

Name an IRCnet safe channel in full, with its five-character ID (`!ABCDEchat`,
not `!chat`).

## Development

```sh
make unit
make integration
make test
```

`make integration` runs three NATS nodes, one IRC server, and three bots, one of
them over `ircs://`. It covers coordination, authentication, failover, restarts,
and channel convergence. It removes its containers and volumes afterward.

Install the pre-commit hook with `make hooks`. Build the amd64 image with:

```sh
docker build --platform linux/amd64 -t botnats .
```

The container workflow publishes `ghcr.io/tkimball83/botnats`. `latest` follows
the default branch; release tags publish matching image tags.
