---
name: integration
description: Run Docker integration tests.
---

# integration

Full Docker mesh: three NATS nodes, one IRC server, three bots.

```sh
make integration
```

Requires Docker. `tests/integration/run.py` owns the test secrets, starts the
compose mesh, runs each named phase in order (live coordinator, three-bot mesh,
NATS node failover, full NATS restart, session TTL change, recovery, serial bot
replacement) under a per-phase timeout, dumps compose logs on failure, and
always tears down. One bot connects over `ircs://`.

## Dependencies

- `virtualenv` skill
- Docker
