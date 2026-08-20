# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

PYTHON ?= python3.14

.PHONY: all clean hooks install integration test unit venv

all: test

clean:
	$(RM) -r .mypy_cache .pytest_cache .ruff_cache build dist \
		src/*.egg-info venv
	find src tests -type d -name __pycache__ -prune -exec $(RM) -r {} +

install: venv
	venv/bin/pip install -e '.[dev]'

hooks: install
	venv/bin/pip install pre-commit==4.6.1
	venv/bin/pre-commit install

unit: install
	venv/bin/ruff check src tests
	venv/bin/ruff format --check src tests
	venv/bin/mypy src tests
	venv/bin/python -m unittest discover -s tests/unit -t . -v

integration: install
	sh tests/integration/run.sh

test: unit integration

venv: venv/bin/python

venv/bin/python:
	$(PYTHON) -m venv --upgrade-deps venv
