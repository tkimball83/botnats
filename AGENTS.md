# AGENTS.md

BotNATS is a coordinated IRC bot mesh: stateless bot processes on one IRC network share durable
state through JetStream KV and coordinate help requests over Core NATS.

| Path                 | Description                                 |
| -------------------- | ------------------------------------------- |
| `src/botnats/`       | Bot wiring, events, commands, and channels  |
| `src/botnats/irc/`   | IRC client and protocol parsing             |
| `src/botnats/nats/`  | NATS coordination and JetStream stores      |
| `tests/unit/`        | Unit tests                                  |
| `tests/integration/` | Docker integration tests                    |

## Validation

Use the repository skills, not hand-built commands. Run `virtualenv` first, except before
`python-version`, which rebuilds the environment itself.

| Change                      | Skill            |
| --------------------------- | ---------------- |
| Python source               | `unit`           |
| Integration or coordination | `integration`    |
| Before handoff              | `test`           |
| Python version bump         | `python-version` |
| New module                  | `new-module`     |
| Release                     | `release`        |

## Setup

Enable the Codex review gate once: `/codex:setup --enable-review-gate`

## Rules

Rules live in `.agents/rules/`; do not add nested `AGENTS.md` files.

- @.agents/rules/architecture.md
- @.agents/rules/changes.md
- @.agents/rules/design.md
- @.agents/rules/safety.md
- @.agents/rules/testing.md
