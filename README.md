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

## Security

BBS attracts amateur cryptographers due to its simplicity and the presence
of a so-called proof of security. The proof reduces to the hardness of
quadratic residuosity problem.

That said, there is no proof that QRP is as hard as factorisation (despite
the leading algorithm for QRP reducing to factorisation). There is also no
proof of the statement that factorization is very hard - albeit millenia of
research have not yet come up with an efficient factorization method, so it
must not be trivial. Accordingly, the security status of BBS is similar
to that of RSA. 

Other CSPRNGs (e.g. AES-OFB) do not have such a security proof, and instead
rely on the fact that none of the cryptographers who tried to break it managed
to do so.

The commonly cited proof of security of BBS states that a *large enough* value
of `M` renders the generator secure. However, the proof does not specify *how*
large `M` has to be to achieve a desired level of security.
[Research](https://berry.win.tue.nl/papers/ima05bbs.pdf) has shown that `M`
has to be enormously large to achieve any decent level of real security.
[Another paper](https://eprint.iacr.org/2011/442.pdf) claims that the algorithm
may not always be reducible to instances of QRP and suggests that BBS could be
solved `10^54 * n^3` times faster than QRP.

The author believes that a 8192-bit modulus is a good compromise between
security and performance, despite the final theoretical attack suggesting
a `10^54 * n^3` speedup. That said, the generator is also extremely slow.

The following Sophie Germain-safe primes have been calculated by the author
for use with the generator. The reader may substitute them for the values of
`p` and `q` in the source code, in order to decrease the startup time
of the generator:

```
256:
p = 0x5c5906be67a75ae0e321cfe8d4a77a7f
q = 0x1b218cd3e4bf641c6073e86b8e6b9687
512:
p = 0x9272b18be3bb488ca43d8a216df34b384f038bb72638345d0acaf6437696b8b7
q = 0xdeb6c5d9c2f23a8d9b8da3313c9ba614462f86223df2ceb5558dd9fbaf4f1747
1024:
p = 0x716eff6ad23845322b34d80092b7d15aa36401bf2a64a1e5e96d9f324e9775b2
f7f94f6a6b7c6ddeb2249dc339023d0ea6138d2cc84c14b09491f96ad0f074e7
q = 0xd7c8ddcee7b01cba2b353bcc4a21c6cc8b3d00d63aa3ab47122ed83bb8be7fa4
2140f07d392c57aad8b73564d87b39849dd58d52d0f00eca735f6fc6afeadca7
2048:
p = 0x5d33a7cf5ec6e2ebee512ce1c6799a5124bec8e7f9f7f2c72550c30b8cd3f776
b272bc9bf49509239b2c419b47294bd887e2871965aaac4021bf3c0ffbaf390788d05d
b1f5b25e822dbbbb2cea95469740eba17c109e50ae959f282b6ac3fdb75f8ea34e14e5
ff032c0a13122b223a627933bf6b115543fee221a994445d4a6f
q = 0x93f4fbdd207c34b7aef8cc063d1216f4847a575d5c3dd6791f37b01c8dbf88ca
3e38626c8dfe51e9001268189762c8f9914572ddcfe3c1625e2e1f411d2dc006f54911
590c4f0101956c332a28edc25247f1d2e86f282b7ce9766bf0b74a209d34897781fb59
eb2bba368e637fbb2ba8e7c6c1fe318f6b64df90aaf13eb2cac7
4096:
p = 0x901b6b1490fd8ded9d7b1e3cf8d9108304ac7360b60328b2e67ea33e09269bc5
73e2bcad7e68c1966fc714d6b5f49027b097d15f630ffb1ff4db0003b288b2dc722ad5
41c30d99c6df6284972e7f20c7f16c56a0d2c9bd72c3abbd29c52ac718c3a53c7444d7
1ec1037eb033545827dde81af108df87bcc1cabcd035193d2072ca218e1182c197418a
d897f84abaaabb1b5ee0503b237253ca6de5465eafa684d02b33340b2f8c231ad0d04b
3277fd0764df3a3ccf380f676cab0fbdad19e6aa21876f4061321f2162a1178e7dbcc1
f949cd75d21552d5c9e670a7e9c4fa9237332dacefd38c0924560c476e3748e9ad9160
bdb731493557aeb2d2c25dd1c667
q = 0x31aae12f3dded1d49130023f3b6fc7fdcf81defde7f67d241a956465701c80cb
c87c3800cc70276bf3e538bf1490248f6e7c2ac42a57a1c8c02d748be203636d5fdcdc
5a8b2d36d039678d2341e8f4e5ffb78ccd00ab72dc9c419d8b1d485fa3bfbb6f2e8b84
b318ea8c30ae5a938fa0ab095810d1f96b02f5bd7cd918efdbdfb0c9e12ee9f8c9c642
b53aa6ba7124f1f596e743ea2c6ef480b948e333744cfcbd06abd0ec6473b397374287
458299c70be4ae0fc7f9046f2a9662ad019f41e0112f1d0377c265891b3ed26ebbdd61
d3c9ee7b315536058886a05a34da601ef2ed603fdc3ea4059df0a5a1cf6e84c1d5779d
fc9fee4fedd57e8a32fbb9d4cdf7
8192:
p = 0x29ed85d1e846071f5cdb3b019487401f082c4ac2316db2916fa1278a7c312555
b5206e89b52270fe8d54a4f526ce35d0e1716b250f3d76107b4c9ed8ef2dcc30e927a0
39a960cca04656df06796554db16a6f9b6957b10355226e7f7ef840ea21c45429347a6
9acd1ad60037741ba0060735c676ed6b6cc453cd402ae5968760980a06ded7765fa086
788b2155f69b1d727d346c6f5c45b7231b59f43ee067b33329df7bf0b87123ee1759b3
ea17c6391513e8c9ebd13078fa86c08dcf9fa5974c5ca2c4228590b53f929a941b6371
dc9b579b824d90fa37ed7e64e00c862e7abb3891d0decb8da754c1e84af3133bd4d325
8ae2e96db19c797a7e8159760f6161f66789962df94f95184dd17a7264d1a99db85560
44a9640b9a19605d61a79162bd809dc4613d5aa84ac1a20a9c85e5905749c0aeb9542a
f00bd6b3569fdaf82894f58462e5cc0b114721ea289e8bc0deca4b806a29e38a7308e6
34de0a8c7510369de020d4bbaf4a01c4dde79b9f5db585b5689d7b905789ab05b7213c
b4d176e04508094c9024da06a05f96f8471287808f729770a105781096db76ba2476f6
c5efc06a0a05d98a5a8410f6900e09fd100b23f561eb439b11e824b0a614f642d12352
5f6bf9cd19ac704b740a20948a3ebd3faf88432e822ffe2ca3bbcfbe7846c335f6dd14
4296916d98f235bc7882008951fff70b7b32d629ca7344178f
q = 0x643f44a1505bce191f5135f4ba3913fa597830b90f718683cb3b205f01cc1d02
a135483b8859f90750cb3caca37183894ec1115d3a1be44aabd017a6c734d8f8af99fc
a0e4da780ffed8edc51c6fbe21600bafb263ad70356253405b0b3fc0c81550d33b7011
a950c0aa5d42eb964de026c9d2dd230d28e7ac1c60cd51c3de7f34181f686c0ab5d4d5
af6cb831908eedc85e97d09bd83fbafa598e96aa378796c559d51a4c2cbf86485c4abc
a09dda3ca1e0eddd373370ca1218e2dcbce6d7097e517ba822b8559a8ce6a7896721c9
9ef6978480230c650332c0560a9dbe9d242b28fb0ae9074d9727c4754b4ecf93bd6c8f
629c5149a75718810bf18225fda6b2c4b5d3afe282c9fb1f9418d73b85d097674bdab2
97f0913147d679c89f4f1a543fd0b4f30c396206d8b5cf37bbe29fc99d18796fd4c791
09eb579a67171d4538021363472f7cd3a68cb28f29779cb2d1d7fc393ecd60f18330ed
638fa8f9ceaa00360a4d7077b4eb90dc00347e7ea912c9f9f7945af57af79ed62214cc
4b70d2729b912444f4bcea8f62293191104298de8f4c3cd13a08e9a9341e70ca9cf298
d0ef5f635fd604e88d00daa999ca1f1b0de1fbd130b8282d03b942d5d8f8c116494709
fe213e8114afac4a3af3e47007c985460e9e406e7e01c90b72948006f5cff0a136e7d1
0f954d54ebb059b112315b14ef723cf493f0cfbee0f602c66f
```

## Improvements

A better starting prime generation algorithm. Decrease the overhead
of the generator. Currently the stream mode at 8192 bits of security
generates outputs at around 5KB/s. This is not acceptable for most
applications. But BBS is also a bad algorithm performance-wise.

