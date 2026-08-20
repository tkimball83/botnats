---
name: isort
description: Sort and check Python imports with isort.
---

# isort

```sh
venv/bin/isort --check-only --diff src tests
```

Fix reported files with `venv/bin/isort src tests`, then re-read any rewritten files.

## Dependencies

- `virtualenv` skill
