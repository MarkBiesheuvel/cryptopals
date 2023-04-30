# The Cryptopals Crypto Challenges - Rust implementation

The [cryptopals crypto challenges](https://cryptopals.com/) are a collection of exercises that demonstrate attacks on real-world crypto.

## Examples
```rust
use std::error::Error;
use cryptopals::{Base64, Bytes};

fn main() -> Result<(), Box<dyn Error>> {
    let key = 42;
    let plaintext = Bytes::from("cryptopals");
    let ciphertext = Bytes::try_from(Base64("SVhTWl5FWktGWQ=="))?;

    assert_eq!(plaintext.single_byte_xor(key), ciphertext);

    Ok(())
}
```

## Commands for local development

```sh
# Format code
just fmt

# Code analysis by Rust clippy
just clippy

# Generate docs
just doc

# Run all tests
just test

# All of the above
just all
```