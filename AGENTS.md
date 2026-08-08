# AGENTS.md

Guidance for agents working in this repository.

## Overview

BotNATS is a coordinated IRC bot mesh. Multiple stateless bot processes share one IRC network,
using JetStream KV for shared durable state and Core NATS pub/sub for auto-coordination offers.

| Path                   | Description                       |
| ---------------------- | --------------------------------- |
| `src/botnats/`         | Package source                    |
| `src/botnats/irc/`     | IRC client and protocol parsing   |
| `src/botnats/nats/`    | NATS coordination and JetStream   |
| `tests/`               | Unit tests                        |
| `tests/integration/`   | Docker integration tests          |

## Validation

Invoke the repository skills instead of reconstructing commands. Set up the project virtualenv
first.

| Change                      | Required skills  |
| --------------------------- | ---------------- |
| Any Python source           | `unit`           |
| Integration or coordination | `integration`    |
| Before handoff              | `test`           |
| Python version bump         | `python-version` |
| New module                  | `new-module`     |
| Version release             | `release`        |

Use the `virtualenv` skill before all other repository tooling except `python-version`, which cleans
and rebuilds the environment itself.

## Setup

Enable the review gate once: `/codex:setup --enable-review-gate`

## Imports

Rules live under `.agents/rules/`; do not add nested `AGENTS.md` files.

- @.agents/rules/architecture.md
- @.agents/rules/changes.md
- @.agents/rules/design.md
- @.agents/rules/safety.md
- @.agents/rules/testing.md
