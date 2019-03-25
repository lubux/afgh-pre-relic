/*
 * Copyright (c) 2019, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author:
 *       Edward Oakes <eoakes@berkeley.edu>
 *       Lukas Burkhalter <lubu@inf.ethz.ch>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <chrono>
#include <gmpxx.h>
#include <iostream>

extern "C" {
#include "pre-afgh-relic.h"
}

using namespace std::chrono;

int print_stats(const char *desc, const char *unit, int n, uint64_t *times) {
  uint64_t sum = 0;
  uint64_t min = 0;
  uint64_t max = 0;
  for (int i = 0; i < n; i++) {
    sum += times[i];
    if (min == 0 || times[i] < min)
      min = times[i];
    if (times[i] > max)
      max = times[i];
  }
  std::cout << desc << std::endl;
  std::cout << "\tavg: " << int(float(sum) / float(n)) << unit << std::endl;
  std::cout << "\tmin: " << min << unit << std::endl;
  std::cout << "\tmax: " << max << unit << std::endl;
  std::cout << std::endl;
}

int run_benchmark(int runs) {
  pre_params_t params;
  pre_sk_t alice_sk, alice_sk_new, bob_sk;
  pre_pk_t alice_pk, alice_pk_new, bob_pk;
  pre_plaintext_t plaintext, decrypted;
  pre_ciphertext_t alice_cipher;
  pre_re_ciphertext_t bob_re_cipher;
  pre_token_t token_to_bob;
  int encoded_params_size, encoded_sk_size, encoded_pk_size, encoded_token_size;
  high_resolution_clock::time_point t1, t2;
  uint64_t params_gen[runs], params_encode[runs], params_decode[runs],
           sk_gen[runs], sk_encode[runs], sk_decode[runs], pk_gen[runs],
           pk_encode[runs], pk_decode[runs], keypair_derive[runs], key_encode[runs],
           encrypt[runs], decrypt[runs], key_decode[runs], token_gen[runs],
           token_encode[runs], token_decode[runs], re_encrypt[runs], decrypt_re[runs];

  std::cout << "Performing " << runs << " runs" << std::endl;
  std::cout << std::endl;

  for (int i = 0; i < runs; i++) {
    t1 = high_resolution_clock::now();
    pre_generate_params(params);
    t2 = high_resolution_clock::now();
    auto us = duration_cast<microseconds>(t2 - t1).count();
    params_gen[i] = (uint64_t)us;

    encoded_params_size = get_encoded_params_size(params);
    char params_str[encoded_params_size];

    t1 = high_resolution_clock::now();
    encode_params(params_str, encoded_params_size, params);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    params_encode[i] = (uint64_t)us;

    t1 = high_resolution_clock::now();
    decode_params(params, params_str, encoded_params_size);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    params_decode[i] = (uint64_t)us;

    t1 = high_resolution_clock::now();
    pre_generate_sk(alice_sk, params);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    sk_gen[i] = (uint64_t)us;

    encoded_sk_size = get_encoded_sk_size(alice_sk);
    char alice_sk_str[encoded_sk_size];

    t1 = high_resolution_clock::now();
    encode_sk(alice_sk_str, encoded_sk_size, alice_sk);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    sk_encode[i] = (uint64_t)us;

    t1 = high_resolution_clock::now();
    decode_sk(alice_sk, alice_sk_str, encoded_sk_size);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    sk_decode[i] = (uint64_t)us;

    encoded_pk_size = get_encoded_pk_size(alice_pk);
    char alice_pk_str[encoded_pk_size];

    t1 = high_resolution_clock::now();
    encode_pk(alice_pk_str, encoded_pk_size, alice_pk);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    pk_encode[i] = (uint64_t)us;

    t1 = high_resolution_clock::now();
    decode_pk(alice_pk, alice_pk_str, encoded_pk_size);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    pk_decode[i] = (uint64_t)us;

    t1 = high_resolution_clock::now();
    pre_derive_pk(alice_pk, params, alice_sk);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    pk_gen[i] = (uint64_t)us;

    t1 = high_resolution_clock::now();
    pre_derive_next_keypair(alice_sk_new, alice_pk_new, params, alice_sk, alice_pk);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    keypair_derive[i] = (uint64_t)us;

    pre_generate_sk(bob_sk, params);
    pre_derive_pk(bob_pk, params, bob_sk);

    pre_rand_plaintext(plaintext);

    t1 = high_resolution_clock::now();
    pre_encrypt(alice_cipher, params, alice_pk, plaintext);
    t2 = high_resolution_clock::now();
    encrypt[i] = (uint64_t)duration_cast<microseconds>(t2 - t1).count();

    t1 = high_resolution_clock::now();
    pre_decrypt(decrypted, params, alice_sk, alice_cipher);
    t2 = high_resolution_clock::now();
    decrypt[i] = (uint64_t)duration_cast<microseconds>(t2 - t1).count();

    t1 = high_resolution_clock::now();
    pre_generate_token(token_to_bob, params, alice_sk, bob_pk);
    t2 = high_resolution_clock::now();
    token_gen[i] =
        (uint64_t)duration_cast<microseconds>(t2 - t1).count();

    encoded_token_size = get_encoded_token_size(token_to_bob);
    char token_to_bob_str[encoded_token_size];

    t1 = high_resolution_clock::now();
    encode_token(token_to_bob_str, encoded_token_size, token_to_bob);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    token_encode[i] = (uint64_t)us;

    t1 = high_resolution_clock::now();
    decode_token(token_to_bob, token_to_bob_str, encoded_token_size);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    token_decode[i] = (uint64_t)us;

    t1 = high_resolution_clock::now();
    pre_apply_token(bob_re_cipher, token_to_bob, alice_cipher);
    t2 = high_resolution_clock::now();
    re_encrypt[i] = (uint64_t)duration_cast<microseconds>(t2 - t1).count();

    t1 = high_resolution_clock::now();
    pre_decrypt_re(decrypted, params, bob_sk, bob_re_cipher);
    t2 = high_resolution_clock::now();
    decrypt_re[i] = (uint64_t)duration_cast<microseconds>(t2 - t1).count();
  }
  print_stats("Public Parameter Generation", "us", runs, params_gen);
  print_stats("Public Parameter Encoding", "us", runs, params_encode);
  print_stats("Public Parameter Decoding", "us", runs, params_decode);
  print_stats("Secret Key Generation", "us", runs, sk_gen);
  print_stats("Secret Key Encoding", "us", runs, sk_encode);
  print_stats("Secret Key Decoding", "us", runs, sk_decode);
  print_stats("Public Key Generation", "us", runs, pk_gen);
  print_stats("Public Key Encoding", "us", runs, pk_encode);
  print_stats("Public Key Decoding", "us", runs, pk_decode);
  print_stats("Keypair Derivation", "us", runs, keypair_derive);
  print_stats("Encryption", "us", runs, encrypt);
  print_stats("Decryption", "us", runs, decrypt);
  print_stats("Token Generation", "us", runs, token_gen);
  print_stats("Token Encoding", "us", runs, token_encode);
  print_stats("Token Decoding", "us", runs, token_decode);
  print_stats("Re-Encryption", "us", runs, re_encrypt);
  print_stats("Decryption (re-encrypted)", "us", runs, decrypt_re);
}

int main(int argc, char *argv[]) {
  pre_init();

  int runs = 100;
  if (argc >= 2) {
    runs = atoi(argv[1]);
  }

  run_benchmark(runs);
  pre_cleanup();

  return 0;
}
