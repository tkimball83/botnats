---
name: python-version
description: Bump the Python version across all project files.
---

# python-version

Update every file that pins the Python version:

| File                          | Pattern                                        |
| ----------------------------- | ---------------------------------------------- |
| `.python-version`             | `{{ version }}`                                |
| `Makefile`                    | `PYTHON ?= python{{ version }}`                |
| `pyproject.toml`              | `requires-python = ">={{ version }}"`          |
| `pyproject.toml`              | `target-version = "py{{ major }}{{ minor }}"`  |
| `Dockerfile`                  | `FROM python:{{ version }}-alpine`             |

Then clean and rebuild:

```sh
make clean
make test
```

The new ruff target version may enable new rules or auto-fix syntax changes.
Verify correctness before accepting.
