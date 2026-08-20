# Design

KISS, YAGNI, and SOLID guide every change.

## KISS

- Prefer the simplest solution that satisfies the requirement.
- Avoid clever tricks; boring and readable beats concise and opaque.
- One obvious way to do it; if two approaches tie, pick the one with fewer moving parts.

## YAGNI

- Do not add code for speculative future needs.
- Delete unused parameters, branches, and abstractions rather than keeping them for later.
- A feature earns its complexity when a concrete requirement demands it, not before.

## State convergence

- Validate and order durable records at the store boundary.
- Use compare-and-set for competing writers and apply the authoritative winner locally.
- Retry only current, idempotent durable mutations; discard superseded pending work.
- Use local locks only around shared mutable transitions that can actually overlap.

## SOLID

- **Single responsibility:** each module, class, and function does one thing.
- **Open/closed:** extend behavior through composition and callbacks, not by modifying working code.
- **Liskov substitution:** fakes and implementations must honor the same contracts.
- **Interface segregation:** keep protocol classes narrow; callers should not depend on methods they
  do not use.
- **Dependency inversion:** depend on protocols, not concrete types.

## Headers

- Use GPL-3.0-only copyright and SPDX headers in source files.

## Linting

- Ruff with `ALL` rules. Fix findings instead of adding ignores.
- Keep ignores limited to `COM812`, `D107`, `PLR2004`, and `PT027` globally and `S101` in tests.
