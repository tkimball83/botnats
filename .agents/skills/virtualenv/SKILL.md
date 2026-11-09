---
name: virtualenv
description: Set up the project virtualenv.
---

# virtualenv

All tooling runs from the git-ignored `venv/`, built with the Python in `.python-version`.

- `make venv`: create the venv.
- `make install`: add the dev dependencies.
- `make hooks`: install the pre-commit hooks.
- `make clean`: remove the venv and build artifacts.

Validation targets install what they need; run `make install` yourself only for interactive
tools.
