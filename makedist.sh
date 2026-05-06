#!/bin/bash
set -e
if [ -d tests ]; then
    echo "Running tests..."
    python3 -m pytest tests/ -v || { echo "Tests failed!"; exit 1; }
fi
echo "Building distribution..."
python3 -m build