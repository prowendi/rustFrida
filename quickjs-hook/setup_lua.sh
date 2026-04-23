#!/bin/bash
set -e

LUA_VERSION="5.4.7"
LUA_DIR="lua-src"
LUA_TARBALL="lua-${LUA_VERSION}.tar.gz"
LUA_URL="https://www.lua.org/ftp/${LUA_TARBALL}"

cd "$(dirname "$0")"

if [ -f "${LUA_DIR}/lua.h" ]; then
    echo "Lua ${LUA_VERSION} source already exists in ${LUA_DIR}/"
    exit 0
fi

echo "Downloading Lua ${LUA_VERSION}..."
curl -L -o "${LUA_TARBALL}" "${LUA_URL}"

echo "Extracting..."
tar xzf "${LUA_TARBALL}"

rm -rf "${LUA_DIR}"
mv "lua-${LUA_VERSION}/src" "${LUA_DIR}"
rm -rf "lua-${LUA_VERSION}" "${LUA_TARBALL}"

# Remove standalone programs (we only need the library)
rm -f "${LUA_DIR}/lua.c" "${LUA_DIR}/luac.c"

echo "Lua ${LUA_VERSION} source ready in ${LUA_DIR}/"
ls "${LUA_DIR}"/*.h | head -5
