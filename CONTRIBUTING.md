# Contributing

Thanks for helping improve `nhbclient`.

## Development Setup

1. Use Python 3.10+.
2. Clone the repository and create a virtual environment.
3. Install dependencies:

```bash
pip install -e ".[dev]"
pip install -e ".[typecheck]"
```

## Local Quality Checks

Run these before opening a pull request:

```bash
ruff check .
mypy src
pytest
python -m build
twine check dist/*
```

## Commit Convention

This repository uses [Commitizen](https://commitizen-tools.github.io/commitizen/)
with Conventional Commits.

Examples:

- `feat: add X`
- `fix: handle Y`
- `docs: clarify Z`

## Release Process

Versioning and changelog generation are managed by Commitizen:

```bash
pip install -e ".[release]"
cz bump
python -m build
twine check dist/*
```

Only publish artifacts from the freshly built version.
