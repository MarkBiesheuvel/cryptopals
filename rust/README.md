# The Cryptopals Crypto Challenges - Rust implementation

The [cryptopals crypto challenges](https://cryptopals.com/) are a collection of exercises that demonstrate attacks on real-world crypto.

## Examples
```rust
use std::error::Error;
use cryptopals::{Base64, Bytes};

fn main() -> Result<(), Box<dyn Error>> {
    let key = 42;
    let plaintext = Bytes::from("cryptopals");
    let ciphertext = Bytes::try_from(Base64::from("SVhTWl5FWktGWQ=="))?;

    assert_eq!(plaintext.single_byte_xor(key), ciphertext);

    Ok(())
}
```

## Dependencies of adversaries

```text
attack_repeating_key_xor
  |
  |-> detect_block_size_repeating_key
  |     |
  |     |-> average_hamming_distance
  |
  |-> attack_single_byte_xor
        |
        |-> detect_english_text
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
just test-all

# All of the above
just all
```