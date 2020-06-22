#!/bin/bash
set -ex
echo "building js pkg for $1 out to: $2"
wasm-pack build \
    --target $1 \
    --scope plugnet \
    --out-name doughnut \
    --out-dir $2 \
    --release

# Remove wasm-pack generated files
# They are unintentionally excluding required files when `npm pack` is run
rm -rf $2/{package.json,README.md,.gitignore,LICENSE}

