---
name: integration
description: Run Docker integration tests.
---

# integration

Full Docker mesh: three NATS nodes, one IRC server, three bots.

```sh
make integration
```

Requires Docker. `tests/integration/run.sh` manages compose lifecycle, health
checks, serial bot replacement, and teardown. Logs are dumped on failure.

## Dependencies

- `virtualenv` skill
- Docker
