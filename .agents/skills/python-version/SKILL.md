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
| `Dockerfile`                  | `FROM python:{{ version }}.{{ patch }}-alpine` |

`{{ patch }}` is the newest patch release of `{{ version }}`.

Then clean and rebuild:

```sh
make clean
make test
```

Ruff takes its target version from `requires-python`; the new one may enable new rules or
auto-fix syntax changes.
Verify correctness before accepting.
