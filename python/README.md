# Python implementation

Since the challenges share a lot of common functionality, such as byte conversions and operations, all the code is stored in a single module. Some challenges require a unique code for oracles and adversaries. The tests verify whether the adversary achieved their goal.

To test all the challenges:
```sh
just test
```

To verify code styling and type hints
```sh
just lint
```

To verify test coverage
```sh
just coverage
```