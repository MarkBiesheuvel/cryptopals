# The Cryptopals Crypto Challenges

The [cryptopals crypto challenges](https://cryptopals.com/) are a collection of exercises that demonstrate attacks on real-world crypto. This is my attempt at solving these challenges.

I am only working on these challenges occasionally, so I have not made much progress.

## Python

In September 2021 I first started with a [Python implementation](./python/) and expanded on this in and September 2022.

Here is an example of challenge 13 in Python:

```python
class TestChallenge13:

    def test_break_structured_cookie_oracle(self) -> None:
        oracle: StructuredCookieOracle = StructuredCookieOracle()
        ciphertext: Ciphertext = forge_admin_cookie(oracle)

        forged_profile: dict[str, str] = oracle.decrypt(ciphertext)
        assert forged_profile['role'] == 'admin'
```

## Rust

I began rewriting all the challenges again in [Rust](./rust/) in May 2023 and continued in December 2023.

Here is an example of challenge 6 in Rust
```rust
#[test]
fn challenge_6() -> TestResult {
    // Input
    let file = FileLineIterator::new("../../data/6.txt")?;
    let ciphertext = Bytes::try_from_base64(file)?;

    // Expected output
    let plaintext = funky_music()?;

    assert_eq!(adversary::attack_repeating_key_xor(&ciphertext)?, plaintext);

    ok()
}
```
