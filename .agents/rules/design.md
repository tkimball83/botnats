# Design

KISS, YAGNI, and the SOLID principles below guide every change.

## KISS

- Prefer the simplest solution that satisfies the requirement.
- Avoid clever tricks; boring and readable beats concise and opaque.
- Filter and validate input once, at the entry point; code past it trusts the result.
- One obvious way to do it; if two approaches tie, pick the one with fewer moving parts.

## YAGNI

- Do not add code for speculative future needs.
- Delete unused parameters, branches, and abstractions rather than keeping them for later.
- Delete parameters every caller, tests included, passes the same value.
- A feature earns its complexity when a concrete requirement demands it, not before.

## State convergence

- Validate and order durable records at the store boundary.
- Order competing channel, session, and presence mutations in their stores with compare-and-set, and
  apply the authoritative record the store returns.
- Retry only current, idempotent durable mutations; discard superseded pending work.
- Use local locks only around shared mutable transitions that can actually overlap.

## SOLID

- **Single responsibility:** each module, class, and function does one thing. Track each concern
  in one place; do not wrap an owner's mechanism in a second copy of it.
- **Liskov substitution:** fakes and implementations must honor the same contracts.
- **Interface segregation:** keep protocol classes narrow; callers should not depend on methods they
  do not use.
- **Dependency inversion:** depend on protocols at external boundaries (IRC, NATS) where fakes
  substitute; use concrete types internally.

## Headers

- Use GPL-3.0-only copyright and SPDX headers in source files.

## Linting

- Ruff with `ALL` rules. Fix findings instead of adding ignores.
- Ruff owns linting, formatting, and import order; do not add tools that overlap it.
- Keep ignores limited to `COM812`, `D107`, `PLR2004`, and `PT027` globally and `S101` in tests.
