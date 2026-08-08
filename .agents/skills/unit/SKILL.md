---
name: unit
description: Run the unit test suite.
---

# unit

Ruff check, ruff format, mypy, then unittest — in sequence.

```sh
make unit
```

Fix ruff findings; do not add ignores. Re-read any file ruff rewrites.

## Dependencies

- `virtualenv` skill
