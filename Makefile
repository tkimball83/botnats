# Makefile

PYTHON ?= python3.14

.PHONY: all clean hooks install integration test unit

all: test

clean:
	$(RM) -r .mypy_cache .ruff_cache build dist \
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
	venv/bin/python -m unittest discover -s tests -v

integration: install
	sh tests/integration/run.sh

test: unit integration

venv:
	$(PYTHON) -m venv --upgrade-deps venv
