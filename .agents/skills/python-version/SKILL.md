---
name: python-version
description: Bump the Python version across all project files.
---

# python-version

Update every Python pin; `{{ patch }}` is `N` in the newest `python:{{ version }}.N-alpine` tag on
Docker Hub.

| File              | Pattern                                        |
| ----------------- | ---------------------------------------------- |
| `.python-version` | `{{ version }}`                                |
| `pyproject.toml`  | `requires-python = ">={{ version }}"`          |
| `Dockerfile`      | `FROM python:{{ version }}.{{ patch }}-alpine` |

Then run `make clean` and `make test`. Ruff's target follows `requires-python`; review any new
findings or fixes it brings.
