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
  gt_t msg, res;
  pre_keys_t alice_key, bob_key;
  pre_ciphertext_t alice_ciphers[runs], bob_ciphers[runs];
  pre_re_token_t token_to_bob;
  int encoded_key_size, encoded_token_size;
  high_resolution_clock::time_point t1, t2;
  uint64_t key_generation[runs], key_encoding[runs], encryption[runs],
      key_decoding[runs], token_generation[runs], token_encoding[runs],
      token_decoding[runs], re_encryption[runs], decryption[runs];

  std::cout << "Performing " << runs << " runs" << std::endl;
  std::cout << std::endl;

  for (int i = 0; i < runs; i++) {
    t1 = high_resolution_clock::now();
    pre_generate_keys(alice_key);
    t2 = high_resolution_clock::now();
    auto us = duration_cast<microseconds>(t2 - t1).count();
    key_generation[i] = (uint64_t)us;

    pre_generate_keys(bob_key);

    encoded_key_size = get_encoded_key_size(alice_key);
    char alice_key_str[encoded_key_size];

    t1 = high_resolution_clock::now();
    encode_key(alice_key_str, encoded_key_size, alice_key);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    key_encoding[i] = (uint64_t)us;

    t1 = high_resolution_clock::now();
    decode_key(alice_key, alice_key_str, encoded_key_size);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    key_decoding[i] = (uint64_t)us;

    gt_new(msg);
    gt_rand(msg);

    t1 = high_resolution_clock::now();
    pre_encrypt(alice_ciphers[i], alice_key, msg);
    t2 = high_resolution_clock::now();
    encryption[i] = (uint64_t)duration_cast<microseconds>(t2 - t1).count();

    t1 = high_resolution_clock::now();
    pre_generate_re_token(token_to_bob, alice_key, bob_key->pk_2);
    t2 = high_resolution_clock::now();
    token_generation[i] =
        (uint64_t)duration_cast<microseconds>(t2 - t1).count();

    encoded_token_size = get_encoded_token_size(token_to_bob);
    char token_to_bob_str[encoded_token_size];

    t1 = high_resolution_clock::now();
    encode_token(token_to_bob_str, encoded_token_size, token_to_bob);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    token_encoding[i] = (uint64_t)us;

    t1 = high_resolution_clock::now();
    decode_token(token_to_bob, token_to_bob_str, encoded_token_size);
    t2 = high_resolution_clock::now();
    us = duration_cast<microseconds>(t2 - t1).count();
    token_decoding[i] = (uint64_t)us;

    t1 = high_resolution_clock::now();
    pre_re_apply(token_to_bob, bob_ciphers[i], alice_ciphers[i]);
    t2 = high_resolution_clock::now();
    re_encryption[i] = (uint64_t)duration_cast<microseconds>(t2 - t1).count();

    t1 = high_resolution_clock::now();
    pre_decrypt(res, bob_key, bob_ciphers[i]);
    t2 = high_resolution_clock::now();
    decryption[i] = (uint64_t)duration_cast<microseconds>(t2 - t1).count();
  }
  print_stats("Key Generation", "us", runs, key_generation);
  print_stats("Key Encoding", "us", runs, key_encoding);
  print_stats("Key Decoding", "us", runs, key_decoding);
  print_stats("Encryption", "us", runs, encryption);
  print_stats("Token Generation", "us", runs, token_generation);
  print_stats("Token Encoding", "us", runs, token_encoding);
  print_stats("Token Decoding", "us", runs, token_decoding);
  print_stats("Re-Encryption", "us", runs, re_encryption);
  print_stats("Decryption", "us", runs, decryption);
}

int main(int argc, char *argv[]) {
  pre_init();

  int runs = 1000;
  if (argc >= 2) {
    runs = atoi(argv[1]);
  }

  run_benchmark(runs);
  pre_deinit();

  return 0;
}
