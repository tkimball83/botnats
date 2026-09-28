---
name: blank-line-after-blocks
description: Add blank lines after Python control-flow blocks.
---

# blank-line-after-blocks

Separate completed `if`, `for`, `while`, `with`, and `try` blocks from the statement that
follows. Run from the repository root on `src` and `tests`, or on selected files:

```sh
venv/bin/blank-line-after-blocks src tests
venv/bin/blank-line-after-blocks src/botnats/{{ file }}.py
```

- Exit code 1 with `Rewriting` messages means files changed. Review the diff and rerun; a clean
  run exits 0. Investigate tracebacks and other errors.
- Use the `unit` skill afterward; `ruff format` must accept the result unchanged.
- The formatter does not infer boundaries between consecutive simple statements.
- CI enforces spacing through pre-commit, pinned to the version in `pyproject.toml`.

## Dependencies

- `virtualenv` skill
