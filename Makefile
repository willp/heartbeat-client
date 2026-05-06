PYTHON ?= python
ifneq ("$(wildcard .venv/bin/python)","")
PYTHON := .venv/bin/python
endif

.PHONY: install-dev lint type test build check-dist clean pre-release

install-dev:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check .

type:
	mypy src

test: lint type
	PYTHONPATH=src $(PYTHON) -m pytest

build:
	$(PYTHON) -m build

check-dist:
	$(PYTHON) -m twine check dist/*

clean:
	rm -rf dist build *.egg-info src/*.egg-info .pytest_cache .mypy_cache .ruff_cache

pre-release: clean build check-dist
