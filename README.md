# cbbs-rng
cbbs-rng - a fast research implementation of the cryptographically
secure Blum Blum Shub random number generator. Supports seeking.
Released to the public domain by Kamila Szewczyk - see COPYING.

Project homepage: https://github.com/kspalaiologos/cbbs-rng

## Building

```
$ cc -O3 -std=c23 -o bbs bbs.c
```

## Synopsis

Blum Blum Shub is a random number generator that produces a sequence
of values based on the formula:

```
f(n+1) = f(n)^2 mod M
```

Then, we obtain random numbers by considering `f(n) mod 2` for each
`n` starting with `n = 1`. The resulting bit sequence is the output
of the generator.

`M` is defined as a product of two safe Sophie Germain primes `p` and
`q` such that `p = 3 mod 4` and `q = 3 mod 4`. `f(0)` is a randomly
chosen seed that is coprime to `M`.

The generator can be seeked around to any position using Carmichael's
function of `M`, which degenerates to
`(p - 1)(q - 1) / gcd(p - 1, q - 1)` via Euler's theorem, stating that

```
f(i) = f(0)^(2^i mod Carmichael(M)) mod M
```

The generator is cryptographically secure under the assumption that
factoring `M` is computationally infeasible.

Various performance optimisations have been applied both to the process
of seeding the generator, as well as to the process of generating
random numbers.


