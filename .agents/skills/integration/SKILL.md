---
name: integration
description: Run Docker integration tests.
---

# integration

Docker mesh: three NATS nodes, one IRC server, and three bots, one of them over `ircs://`.

```sh
make integration
```

`tests/integration/run.py` owns the test secrets and runs each phase in order under a timeout:
live coordinator, three-bot mesh, NATS node failover, full NATS restart, presence TTL change,
recovery, and serial bot replacement. It dumps compose logs on failure and always tears down.

## Dependencies

- `virtualenv` skill
- Docker
