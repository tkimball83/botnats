# Design

KISS, YAGNI, and SOLID guide every change.

## Simplicity

- Prefer the simplest solution; boring and readable beats clever.
- Validate input once, at the entry point; code past it trusts the result.
- When two approaches tie, pick the one with fewer moving parts.
- Write no code for speculative needs. Delete unused parameters, branches, and abstractions, and
  any parameter every caller, tests included, passes the same value.

## State convergence

- Validate and order durable records at the store boundary.
- Order competing channel, session, and presence mutations with compare-and-set, and apply the
  record the store returns.
- Retry only current, idempotent durable mutations; discard superseded pending work.
- Lock only shared mutable transitions that can actually overlap.

## SOLID

- One responsibility per module, class, and function; track each concern in one place.
- Fakes and implementations honor the same contracts.
- Keep protocols narrow: callers depend only on the methods they use.
- Depend on protocols at external boundaries (IRC, NATS); use concrete types internally.

## Code style

- Use GPL-3.0-only copyright and SPDX headers in source files.
- Ruff with `ALL` rules owns linting, formatting, and import order; add no overlapping tools.
- Fix findings instead of adding ignores. Ignores stay `COM812`, `D107`, `PLR2004`, and `PT027`,
  plus `S101` in tests.
