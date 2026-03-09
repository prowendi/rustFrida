#!/bin/bash
# Setup script to initialize the QuickJS submodule

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QUICKJS_DIR="$SCRIPT_DIR/quickjs-src"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -f "$QUICKJS_DIR/quickjs.c" ] && [ -f "$QUICKJS_DIR/quickjs.h" ]; then
    echo "QuickJS source already initialized at $QUICKJS_DIR"
    exit 0
fi

if ! command -v git &> /dev/null; then
    echo "Error: git not found."
    exit 1
fi

echo "Initializing QuickJS submodule..."
git -C "$REPO_ROOT" submodule update --init --recursive quickjs-hook/quickjs-src

if [ ! -f "$QUICKJS_DIR/quickjs.c" ] || [ ! -f "$QUICKJS_DIR/quickjs.h" ]; then
    echo "Error: QuickJS submodule initialization failed."
    exit 1
fi

echo "QuickJS submodule initialized at $QUICKJS_DIR"
