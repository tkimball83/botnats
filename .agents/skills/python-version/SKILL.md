---
name: python-version
description: Bump the Python version across all project files.
---

# python-version

Update every Python pin; `{{ patch }}` is the newest patch release of `{{ version }}`.

| File              | Pattern                                        |
| ----------------- | ---------------------------------------------- |
| `.python-version` | `{{ version }}`                                |
| `Makefile`        | `PYTHON ?= python{{ version }}`                |
| `pyproject.toml`  | `requires-python = ">={{ version }}"`          |
| `Dockerfile`      | `FROM python:{{ version }}.{{ patch }}-alpine` |

Then run `make clean` and `make test`. Ruff's target follows `requires-python`; review any new
findings or fixes it brings.
