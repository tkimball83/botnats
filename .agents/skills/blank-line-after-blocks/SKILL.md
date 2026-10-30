---
name: blank-line-after-blocks
description: Add blank lines after Python control-flow blocks.
---

# blank-line-after-blocks

Separate each completed `if`, `for`, `while`, `with`, or `try` block from the next statement:

```sh
venv/bin/blank-line-after-blocks src tests
```

Exit 1 with `Rewriting` means files changed: review the diff and rerun until it exits 0.
`ruff format` must accept the result unchanged. `make unit` and pre-commit run it too. It ignores
`async with` and `async for` blocks; add their blank lines by hand.

## Dependencies

- `virtualenv` skill
