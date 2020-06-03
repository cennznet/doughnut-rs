# compile the rust codebase
wasm-pack build \
    --target nodejs \
    --scope plugnet \
    --out-name doughnut \
    --out-dir lib \
    --release

