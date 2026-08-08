---
name: virtualenv
description: Set up the project virtualenv.
---

# virtualenv

All tooling runs from `venv/`, pinned to the Python in `.python-version`.

```sh
make venv
```

- `make venv` — create the venv.
- `make install` — venv + dev dependencies.
- `make hooks` — pre-commit hooks.
- `make clean` — remove venv and build artifacts.

Validation targets install their own dependencies. Run `make install` directly only when an
interactive tool is missing or outdated. `venv/` is git-ignored.
