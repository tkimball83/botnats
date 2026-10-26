---
name: unit
description: Run the unit test suite.
---

# unit

Block spacing, ruff check, ruff format, mypy, then unittest:

```sh
make unit
```

Fix findings instead of adding ignores. Re-read any file blank-line-after-blocks rewrites.

## Dependencies

- `virtualenv` skill
