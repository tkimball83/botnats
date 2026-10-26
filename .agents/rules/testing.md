# Testing

Test every behavior change. Fakes for unit tests, Docker for integration.

## Unit tests

- Use `unittest` and standard-library helpers, with fakes for focused tests; `tests/unit/` needs
  no live NATS or IRC.
- Keep each test in `test_<module>.py` of the owner it exercises.
- Confirm each new test fails without the change it covers, and that a fake's defaults cannot
  satisfy its assertions.
- Fakes and stubs return what the real method returns.
- Bound every wait with `asyncio.timeout` so a regression fails instead of hanging. No real
  sleeps, wall-clock budgets, or frozen event-loop clocks.

## Integration tests

- Use the Docker mesh: three NATS nodes, one IRC server, three bots.
- Test multiple channels with different modes.
- Test serial replacement of every bot without losing channels, keys, or ops.
- Test full NATS restarts without losing durable state.

## Coverage

- Cover failure and reconnect paths, missed events, and eventual convergence.
- Cover stale writes and compare-and-set conflicts for channel, session, and presence state.
- Cover watch replay and resynchronization before readiness.
