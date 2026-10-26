---
name: unit
description: Run the unit test suite.
---

# unit

Block spacing, ruff check, ruff format, mypy, then unittest — in sequence.

```sh
make unit
```

Fix ruff findings; do not add ignores. Re-read any file blank-line-after-blocks rewrites.

## Dependencies

- `virtualenv` skill
