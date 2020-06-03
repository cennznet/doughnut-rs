# doughnut-rs
[![CircleCI](https://circleci.com/gh/cennznet/doughnut-rs.svg?style=svg)](https://circleci.com/gh/cennznet/doughnut-rs)  

Rust implementation of the doughnut binary codec.  
Currently compliant with version 0 spec.  

```rust
use doughnut_rs::v0::DoughnutV0;

let encoded_doughnut = vec![ <some bytes> ];
let doughnut = DoughnutV0::new(&encoded_doughnut)?;
```

Query permission domains
```rust
let domain: &[u8] = doughnut.get_domain("something")?;
```

Check a doughnut is valid to be used by a user (`who`) at a timestamp (`when`).  
```rust
use doughnut_rs::traits::DoughnutApi;
// ..
assert!(
  doughnut.validate(who, when).is_ok()
)
```

Verify a doughnut's signature (requires `std`)
```rust
use doughnut_rs::traits::DoughnutVerify;
// ..
assert!(doughnut.verify());
```

# Contributing
The following checks should pass  
```bash
# Do the usual
cargo fmt && \
cargo check && \
cargo test

# Check 'no std' mode compiles
cargo check --no-default-features
```

## Generate JS/Wasm bindings
This crate also provides generated JS bindings using [wasm-pack](https://rustwasm.github.io/docs/wasm-pack/). To generate the package run:
```bash
# install wasm pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# build
cd js/ && yarn build

# Run tests
yarn test
```

