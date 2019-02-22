# AFGH Proxy Re-Encryption with RELIC

Implements the AFGH proxy re-encryption scheme as presented in:
[link](https://eprint.iacr.org/2005/028.pdf) Ateniese et al. Improved Proxy Reencryption Schemes with Applications to Secure Distributed Storage. In NDSS, 2006.

The implementation uses the [relic toolkit](https://github.com/relic-toolkit/relic) as a backend for the underlying pairing-based crypto.

### Install Relic
The relic toolkit should be compiled with the desired curve