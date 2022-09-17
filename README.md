# The Cryptopals Crypto Challenges

The [cryptopals crypto challenges](https://cryptopals.com/) are a collection of exercises that demonstrate attacks on real-world crypto. This is my attempt at solving these challanges.

Since the challanges share a lot of common functionality, such as byte conversions and operations, all the code is stored in a single module. Some challanges require a unique code for oracles and adversaries. The tests verify whether the adversary achieved their goal.

To test all the challenges:
```sh
py.test -v
```

To verify code styling:
```sh
pycodestyle
```

To verify the static typing:
```sh
mypy -p cryptopals -p tests --pretty
```
