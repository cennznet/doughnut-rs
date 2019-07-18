# doughnut-rs
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

# Contributing
The following checks should pass  
```
# Do the usual
cargo fmt && cargo build && cargo test

# Check 'no std' mode compiles
cargo +nightly check --no-default-features
```
