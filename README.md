# AFGH Proxy Re-Encryption with RELIC

Implements the AFGH proxy re-encryption scheme as presented in:

- [link](https://eprint.iacr.org/2005/028.pdf) Ateniese et al. Improved Proxy Reencryption Schemes with Applications to Secure Distributed Storage. In NDSS, 2006.

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

### Experimental Code
This is experimental code and provides NO security guarantees.