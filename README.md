# The Cryptopals Crypto Challenges

The [cryptopals crypto challenges](https://cryptopals.com/) are a collection of exercises that demonstrate attacks on real-world crypto. This is my attempt at solving these challenges.

Since the challenges share a lot of common functionality, such as byte conversions and operations, all the code is stored in a single module. Some challenges require a unique code for oracles and adversaries. The tests verify whether the adversary achieved their goal.

To test all the challenges:
```sh
commands/test
```

To verify code styling and type hints
```sh
commands/lint
```

To verify test coverage
```sh
commands/coverage
```
