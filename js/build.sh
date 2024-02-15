#!/usr/bin/env bash

set -ex

# Check if jq is installed
if ! [ -x "$(command -v jq)" ]; then
    echo "jq is not installed" >& 2
    exit 1
fi

# Clean previous packages
if [ -d "doughnut-web" ]; then
    rm -rf doughnut-web
fi

if [ -d "doughnut-nodejs" ]; then
    rm -rf doughnut-nodejs
fi

# build for web js target
rustup run nightly wasm-pack build --target web --scope therootnetwork --out-name doughnut-web --release --out-dir doughnut-web
# modify package.json for web
jq '.name="@therootnetwork/doughnut-web"' doughnut-web/package.json > temp.json && mv temp.json doughnut-web/package.json

# build for nodejs target
rustup run nightly wasm-pack build --target nodejs --scope therootnetwork --out-name doughnut-nodejs --release --out-dir doughnut-nodejs
# modify package.json for nodejs
jq '.name="@therootnetwork/doughnut-nodejs"' doughnut-nodejs/package.json > temp.json && mv temp.json doughnut-nodejs/package.json
