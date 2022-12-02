# Kleptographic Attack on Kyber KEM:

This project contains backdoor-ed implementation of the key generation procedure of Kyber KEM, with backdoor implemented using 1) pre-quantum ECDH and 2) post-quantum Classic McEliece KEM.

## Prerequisites

To run Classic Mceliece, you need to have the [libXKCP](https://github.com/XKCP/XKCP) library installed on your PC. In the main directory, you can clone this github repository. So run,
```sh
git clone https://github.com/XKCP/XKCP.git
cd XKCP/
make generic64/libXKCP.a
```
This generates a static library file `libXKCP.a` and a header file `libXKCP.a.headers`. Both have to be copied into the `ref` folder. So run,
```sh
cp -r bin/generic64/* ../ref
```

## Configuring the Implementation:

The backdoor is placed in the key-generation procedure. The file `klepto_attack.h` has a few compile time options to set.

* `KLEPTO_KEYGEN` enables the backdoor in the key generation procedure.
* `PRE_OR_POST_QUANTUM_BACKDOOR` helps you select whether you want to use a pre-quantum (`PRE_OR_POST_QUANTUM_BACKDOOR = 0`) or post-quantum backdoor (`PRE_OR_POST_QUANTUM_BACKDOOR = 1`).
* `DEBUG_PRINT` if enabled, prints whether attack succeeded.
The main wrapper script is `test_kyber.c`, which is used to run the kleptographic attack on Kyber. The backdoor related functions are mainly present in `indcpa.c`.

## Compilation:

The backdoor is only implemented for the recommended parameter sets of Kyber (`kyber768`). During compilation, there will be a lot of warnings. But, you can safely ignore them. So, run the following commands:
```sh
cd ../ref
make test_kyber768
```

## Execution:

To run:
```sh
./test_kyber768
```

## License
All code in this repository is released under the conditions of [CC0](http://creativecommons.org/publicdomain/zero/1.0/).
