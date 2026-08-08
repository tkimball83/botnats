# Testing

Test every behavior change. Fakes for unit tests, Docker for integration.

## Unit tests

- Prefer `unittest` and standard-library test helpers.
- Use fakes for focused unit tests.

## Integration tests

- Use the Docker integration mesh for multi-bot coordination.
- Keep integration coverage for three NATS nodes, one IRC server, and three bots.
- Test multiple channels with different modes.
- Test serial replacement of every bot without losing channels, keys, or ops.
- Test full NATS restarts without losing durable state.

## Coverage

- Cover failure and reconnect paths when relevant.
- Cover missed events and eventual state convergence.
- Cover stale-write and compare-and-set conflicts for durable channel, session, and presence state.
- Cover watch replay and resynchronization before readiness.
- Run `make test` (unit + integration) before handoff.
