---
name: integration
description: Run Docker integration tests.
---

# integration

Full Docker mesh: three NATS nodes, one IRC server, three bots.

```sh
make integration
```

Requires Docker. `tests/integration/run.py` starts the compose mesh, runs each
named phase in order (live coordinator, NATS failover and restart, mesh, recovery,
serial bot replacement), dumps compose logs on failure, and always tears down.

## Dependencies

- `virtualenv` skill
- Docker
