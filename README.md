# doughnut-rs
Rust implementaiton of the doughnut binary codec.  
Currently compilant with version 0 spec.  

```rust
use doughnut_rs::v0::DoughnutV0;

let encoded_doughnut = vec![ <some bytes> ];
let doughnut = DoughnutV0::new(&encodec_doughnut)?;
```

Query permission domains
```rust
let domains = doughnut.domains(); // Build domain payload index
let encoded_domain_payload = domains.get("something")?;
```
