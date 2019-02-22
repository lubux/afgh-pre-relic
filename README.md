# AFGH Proxy Re-Encryption with RELIC

Implements the AFGH proxy re-encryption scheme as presented in:

- [link](https://eprint.iacr.org/2005/028.pdf) Ateniese et al. Improved Proxy Reencryption Schemes with Applications to Secure Distributed Storage. In NDSS, 2006.

This code is ported from the additive homomorphic PRE in [Pilatus](http://www.vs.inf.ethz.ch/publ/papers/mshafagh_SenSys17_Pilatus.pdf).
The implementation uses the [relic toolkit](https://github.com/relic-toolkit/relic) as a backend for the underlying pairing-based crypto.

### Install Relic
The default settings to install relic.
```
./preset/gmp-pbc-128.sh
make 
sudo make install
```

or

```
./scripts/install-relic-ubuntu.sh
```


### Compile 
Cmake is required to compile the code.
```
cmake .
make
```
The `main.cpp` file contains the basic test code and shows how to use the library. 
```
./bin/relic-pre
```

The `benchmark_pre.cpp` file contains the simple benchmark code. 
```
./bin/relic_pre_re_enc_benchmark
```

### Performance Indicator
Benchmark results on on a MacBook Pro 2017 2.8 GHz Intel Core i7

```
-- Curve B12-P381:
Performing 1000 runs

Key Generation
        avg: 2140us
        min: 1925us
        max: 3295us

Key Encoding
        avg: 17us
        min: 14us
        max: 60us

Key Decoding
        avg: 323us
        min: 272us
        max: 688us

Encryption
        avg: 1074us
        min: 885us
        max: 1989us

Token Generation
        avg: 548us
        min: 441us
        max: 1034us

Token Encoding
        avg: 0us
        min: 0us
        max: 27us

Token Decoding
        avg: 124us
        min: 90us
        max: 335us

Re-Encryption
        avg: 1703us
        min: 1542us
        max: 3052us

Decryption
        avg: 892us
        min: 688us
        max: 1738us

```


### Experimental Code
This is experimental code and provides NO security guarantees.