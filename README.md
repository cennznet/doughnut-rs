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
```
# Do the usual
cargo fmt && \
cargo build && \
cargo test

# Check 'no std' mode compiles
cargo +nightly check --no-default-features
```
