# The Cryptopals Crypto Challenges - Rust implementation

The [cryptopals crypto challenges](https://cryptopals.com/) are a collection of exercises that demonstrate attacks on real-world crypto.

The challanges have been translated to test cases in Rust. The goal is to write a library that will pass all test cases.

## Examples

Here is an example of how the `cryptopals` library can be used to (weakly) encrypt a simple string.

```rust
use std::error::Error;
use cryptopals::{Base64, Bytes};

fn main() -> Result<(), Box<dyn Error>> {
    let key = 42;
    let plaintext = Bytes::from("cryptopals");
    let ciphertext = Bytes::try_from_base64("SVhTWl5FWktGWQ==")?;

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
        |-> find_english_text

find_aes_ecb_ciphertext
  |
  |-> average_hamming_distance
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