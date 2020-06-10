# compile the rust codebase
echo "building js pkg for $1 out to: $2"
wasm-pack build \
    --target $1 \
    --scope plugnet \
    --out-name doughnut \
    --out-dir $2 \
    --release
