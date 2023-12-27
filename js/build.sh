#!/bin/bash
set -ex
echo "building js pkg for $1 out to: $2"
rustup run nightly wasm-pack build \
    --target $1 \
    --scope trn \
    --out-name doughnut \
    --out-dir $2 \
    --release

# Add 'crypto' polyfill to js libs
echo "
// Polyfill to enable signing in some JS environments
// See: https://stackoverflow.com/questions/52612122/how-to-use-jest-to-test-functions-using-crypto-or-window-mscrypto
const crypto = require('crypto');
if(global.self !== undefined) {
  Object.defineProperty(global.self, 'crypto', {
    value: {
      getRandomValues: arr => crypto.randomBytes(arr.length)
    }
  });
}
" >> $2/doughnut.js

# Remove wasm-pack generated files
# They are unintentionally excluding required files when `npm pack` is run
cd $2
rm package.json README.md .gitignore LICENSE

