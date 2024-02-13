#!/usr/bin/env bash

set -ex

# Check if jq is installed
if ! [ -x "$(command -v jq)" ]; then
    echo "jq is not installed" >& 2
    exit 1
fi

# Clean previous packages
if [ -d "pkg" ]; then
    rm -rf pkg
fi

if [ -d "pkg-node" ]; then
    rm -rf pkg-node
fi

PKG_NAME="doughnut"

# Build for both targets
rustup run nightly wasm-pack build --target web --scope therootnetwork --out-name $PKG_NAME --release
rustup run nightly wasm-pack build --target nodejs --scope therootnetwork --out-name $PKG_NAME --release --out-dir pkg-node

# Merge nodejs & browser packages into `pkg/` directory
cp "pkg-node/${PKG_NAME}.js" "pkg/${PKG_NAME}_main.js"
sed "s/require[\(]'\.\/${PKG_NAME}/require\('\.\/${PKG_NAME}_main/" "pkg-node/${PKG_NAME}.js" > "pkg/${PKG_NAME}_bg.js"
jq ".files += [\"${PKG_NAME}_bg.js\"]" pkg/package.json \
  | jq ".main = \"${PKG_NAME}_main.js\"" > pkg/temp.json
mv pkg/temp.json pkg/package.json
