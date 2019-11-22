# AFGH Proxy Re-Encryption with RELIC

[![Build status](https://travis-ci.org/lubux/afgh-pre-relic.svg?branch=master)](https://travis-ci.org/lubux/afgh-pre-relic)



Implements the AFGH proxy re-encryption scheme as presented in:

- [link](https://eprint.iacr.org/2005/028.pdf) Ateniese et al. Improved Proxy Reencryption Schemes with Applications to Secure Distributed Storage. In NDSS, 2006.

This code is ported from the additive homomorphic PRE in [Pilatus](http://www.vs.inf.ethz.ch/publ/papers/mshafagh_SenSys17_Pilatus.pdf) [Code](https://github.com/Talos-crypto/Pilatus).
The implementation uses the [relic toolkit](https://github.com/relic-toolkit/relic) as a backend for the underlying pairing-based crypto.

### Install Relic
The default settings to install relic.
```
./preset/gmp-pbc-bls381.sh
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
Performing 100 runs

Public Parameter Generation
	avg: 2120us
	min: 2104us
	max: 2203us

Public Parameter Encoding
	avg: 3us
	min: 3us
	max: 6us

Public Parameter Decoding
	avg: 7us
	min: 7us
	max: 17us

Secret Key Generation
	avg: 53us
	min: 45us
	max: 70us

Secret Key Encoding
	avg: 0us
	min: 0us
	max: 0us

Secret Key Decoding
	avg: 0us
	min: 0us
	max: 0us

Public Key Generation
	avg: 537us
	min: 513us
	max: 578us

Public Key Encoding
	avg: 1us
	min: 1us
	max: 1us

Public Key Decoding
	avg: 2us
	min: 2us
	max: 4us

Keypair Derivation
	avg: 594us
	min: 564us
	max: 628us

Encryption
	avg: 1368us
	min: 1265us
	max: 1524us

Decryption
	avg: 2785us
	min: 2699us
	max: 2887us

Token Generation
	avg: 648us
	min: 570us
	max: 717us

Token Encoding
	avg: 1us
	min: 1us
	max: 1us

Token Decoding
	avg: 2us
	min: 2us
	max: 3us

Re-Encryption
	avg: 2120us
	min: 2104us
	max: 2210us

Decryption (re-encrypted)
	avg: 1096us
	min: 978us
	max: 1209us

```


### Experimental Code
This is experimental code and provides NO security guarantees.
