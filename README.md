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
- Automatic op, invite, and unban recovery uses request, offer, and targeted grant flows; admin
  commands execute directly on the receiving bot.
- Each bot ID atomically claims a case-insensitive presence key; duplicates remain unready.
- Authorization binds the visible nick, user, and host. NICK moves the session;
  any other identity change requires new authentication.

### State

| Data                           | Storage      | Lifetime                     |
| ------------------------------ | ------------ | ---------------------------- |
| Channel configuration and keys | JetStream KV | Until changed or removed     |
| Authorization sessions         | JetStream KV | Configured session TTL       |
| Authentication attempts        | JetStream KV | Two minutes                  |
| Used TOTP counters             | JetStream KV | Five minutes                 |
| Bot presence                   | JetStream KV | Configured presence TTL      |

File-backed JetStream preserves channel state and authentication controls across
bot and NATS restarts; sessions and presence still expire at their configured TTLs.

## Configuration

| Variable                      | Purpose                                                      |
| ----------------------------- | ------------------------------------------------------------ |
| `BOTNATS_CONFIG`              | JSON config path; defaults to `/etc/botnats/bot.json`        |
| `BOTNATS_COORDINATION_SECRET` | HMAC key; at least 32 bytes                                  |
| `BOTNATS_LOG_LEVEL`           | Python log level; defaults to `INFO`                         |
| `BOTNATS_NATS_TOKEN`          | NATS client token                                            |
| `BOTNATS_TOTP_SECRET`         | Base32 TOTP seed; at least 160 bits                          |

Example `bot.json`:

```json
{
  "authorization": {
    "session_ttl_seconds": 3600
  },
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
    "channel_modes": "+npst",
    "connect_timeout_seconds": 30,
    "servers": [
      "irc://us.undernet.org:6667"
    ],
    "verify_tls": false
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

| Setting                                     | Behavior                                                    |
| ------------------------------------------- | ----------------------------------------------------------- |
| `authorization.session_ttl_seconds`         | Authorized session lifetime; maximum 86,400 seconds         |
| `bot.health_port`                           | HTTP liveness and readiness port; 8080 by default           |
| `bot.id`                                    | Unique mesh ID; compared case-insensitively                 |
| `bot.network`                               | One IRC network per process; namespaces shared NATS state   |
| `bot.nickname`                              | IRC nickname and connection identity                        |
| `coordination.maintenance_interval_seconds` | Seconds between maintenance cycles                          |
| `coordination.presence_ttl_seconds`         | Must exceed the maintenance interval                        |
| `irc.channel_modes`                         | Required (`+`) and forbidden (`-`) modes; empty by default  |
| `irc.connect_timeout_seconds`               | Per-server connection timeout                               |
| `irc.servers`                               | Ordered failover endpoints for the configured network       |
| `irc.verify_tls`                            | Applies only to `ircs://` connections                       |
| `nats.jetstream_replicas`                   | Use `3` only when three JetStream storage peers are present |
| `nats.monitor_port`                         | Connected-server monitoring port used by `STATUS`           |
| `nats.servers`                              | Ordered Core NATS failover endpoints                        |

Plain IRC exposes commands and responses, so use a trusted network when IRCS is
unavailable. JetStream requires file storage; persist each peer's directory.

Give the NATS token only to bot processes. Signatures on channel, session, and
presence records mean a holder of the token but not the coordination secret
cannot forge state a bot will accept, and the attempt and claim buckets use
secret-derived keys such a holder cannot compute. None of that stops a writer
from deleting or overwriting existing bucket entries, so a hostile token holder
can still churn state (for example, repeatedly clobbering a presence key to
stall a bot's readiness). NATS wildcards match whole subject tokens and each
bucket name is one token, so when the token is shared more widely, restrict the
buckets by their concrete names via server permissions — for a network named
`efnet`, `$KV.botnats_v1_efnet_presence.>`, and ideally the other four buckets
too (`auth_attempts`, `channels`, `sessions`, and `used_totp` under the same
`botnats_v1_efnet_` prefix).

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

Authentication allows three attempts per identity in a mesh-wide sliding
60-second window. Each TOTP counter can be claimed once.

Use private messages for every command. All commands except `AUTH` require an
active session.

| Command    | Arguments          | Action                           |
| ---------- | ------------------ | -------------------------------- |
| `AUTH`     | `<totp-code>`      | Authenticate                     |
| `BAN`      | `<channel> <mask>` | Add a ban                        |
| `DEOP`     | `<channel> <nick>` | Remove operator status           |
| `GETBANS`  | `<channel>`        | List tracked bans                |
| `GETMODES` | `<channel>`        | Show tracked channel modes       |
| `GETUSERS` | `<channel>`        | List tracked channel members     |
| `INVITE`   | `<channel> <nick>` | Invite a user                    |
| `JOIN`     | `<channel> [key]`  | Add a desired channel            |
| `OP`       | `<channel> <nick>` | Grant operator status            |
| `PART`     | `<channel>`        | Remove a desired channel         |
| `STATUS`   |                    | Show bot and NATS status         |
| `UNBAN`    | `<channel> <mask>` | Remove a tracked ban             |

## Development

```sh
make unit
make integration
make test
```

`make integration` runs three NATS nodes, one IRC server, and three bots. It
covers coordination, authentication, failover, restarts, and channel
convergence. It removes its containers and volumes afterward.

Install the pre-commit hook with `make hooks`. Build the amd64 image with:

```sh
docker build --platform linux/amd64 -t botnats .
```

The container workflow publishes `ghcr.io/tkimball83/botnats`. `latest` follows
the default branch; release tags publish matching image tags.
