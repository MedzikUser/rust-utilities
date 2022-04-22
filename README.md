# Utilities for Rust

## Importing
The driver is available on [crates.io](https://crates.io/crates/rust_utilities). To use the driver in
your application, simply add it to your project's `Cargo.toml`.

```toml
[dependencies]
rust_utilities = "0.2.0"
```

## How to use?

### Compute Sha hash

Add `sha` features

```toml
[dependencies.rust_utilities]
version = "0.2.0"
features = ["sha"]
```

Quick and easy sha1, sha256 and sha512 hash calculation.

```rust
use rust_utilities::crypto::sha::{Algorithm, CryptographicHash};

let text = "test" // &str

let hash = hex::encode(CryptographicHash::hash(Algorithm::SHA1, text.as_bytes())); // String

println!("Output hash: {}", hash); // output: `a94a8fe5ccb19ba61c4c0873d391e987982fbbd3`
```
