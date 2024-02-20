# doughnut-rs 

Rust implementation of the doughnut binary codec.  
Currently compliant with version 0, 1 spec.  

```rust
use doughnut_rs::v1::DoughnutV1;

let encoded_doughnut = vec![ <some bytes> ];
let doughnut = DoughnutV1::new(&encoded_doughnut)?;
```

Query permission topping
```rust
let topping: &[u8] = doughnut.get_topping("something")?;
```

Check a doughnut is valid to be used by a user (`who`) at a timestamp (`when`).  
```rust
use doughnut_rs::traits::DoughnutApi;
// ..
assert!(
  doughnut.validate(who, when).is_ok()
)
```

Verify a doughnut's signature (requires `"crypto"` feature in `"no_std"` mode and rust nightly)
```rust
use doughnut_rs::traits::DoughnutVerify;
// ..
assert!(doughnut.verify().is_ok());
```

Sign a doughnut (requires `"crypto"` feature in `"no_std"` mode and rust nightly)
```rust
use doughnut_rs::traits::Signing;
let mut doughnut = DoughnutV1 { ... };
// ECDSA
assert!(doughnut.sign_ecdsa(<secret_key_bytes>).is_ok());
// EIP191
assert!(doughnut.sign_eip191(<secret_key_bytes>).is_ok());
```

# Contributing
The following checks should pass  
```bash
# Do the usual
cargo +nightly fmt && \
cargo check && \
cargo test

# Check 'no std' mode compiles
cargo check --no-default-features

# Check crypto functionality in 'no std' mode
cargo +nightly check --no-default-features
```

## Generate JS/Wasm bindings
This crate also provides generated JS bindings using [wasm-pack](https://rustwasm.github.io/docs/wasm-pack/).
See the [js](js/README.md) dir for usage.

To generate the package run:
```bash
# install wasm pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# build
cd js/ && yarn build

# Run tests
yarn test
```
