/*
 * Copyright (c) 2016, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author:
 *       Lukas Burkhalter <lubu@student.ethz.ch>
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

int basic_test() {

  pre_keys_t alice_key, bob_key;
  pre_ciphertext_t alice_cipher1, bob_re;
  pre_re_token_t token_to_bob;
  gt_t ms1;
  gt_t res;
  uint8_t key1[16];
  uint8_t key2[16];
  char ok = 1;

  // generate random message
  pre_rand_message(ms1);

  pre_generate_keys(alice_key);
  pre_generate_keys(bob_key);

  pre_encrypt(alice_cipher1, alice_key, ms1);

  pre_decrypt(res, alice_key, alice_cipher1);

  if (gt_cmp(ms1, res) == CMP_EQ) {
    std::cout << "OK!" << std::endl;
  } else {
    std::cout << "Failed!" << std::endl;
  }

  pre_generate_re_token(token_to_bob, alice_key, bob_key->pk_2);

  pre_re_apply(token_to_bob, bob_re, alice_cipher1);

  pre_decrypt(res, bob_key, bob_re);

  if (gt_cmp(ms1, res) == CMP_EQ) {
    std::cout << "OK!" << std::endl;
  } else {
    std::cout << "Failed!" << std::endl;
  }

  pre_map_to_key(key1, 16, res);
  pre_map_to_key(key2, 16, ms1);

  for (int i = 0; i < 16; i++) {
    if (key1[i] != key2[i]) {
      ok = 0;
      break;
    }
  }

  if (ok) {
    std::cout << "OK!" << std::endl;
  } else {
    std::cout << "Failed!" << std::endl;
  }

  return 0;
}

void encode_decode_test() {
  gt_t msg1, msg2, msg1_decoded;
  pre_keys_t alice_key, bob_key, alice_key_decoded;
  pre_ciphertext_t alice_cipher1, alice_cipher1_decode, bob_re, bob_re_decode;
  pre_re_token_t token_to_bob, token_to_bob_decode;
  gt_t res;
  char *buff;
  int key_size, msg_size;

  pre_rand_message(msg1);
  pre_rand_message(msg2);
  msg_size = get_encoded_msg_size(msg1);
  buff = (char *)malloc((size_t)msg_size);
  if (!encode_msg(buff, msg_size, msg1) == STS_OK) {
    std::cout << "Message encode error!" << std::endl;
    exit(1);
  }
  if (!decode_msg(msg1_decoded, buff, msg_size) == STS_OK) {
    std::cout << "Message decode error!" << std::endl;
    exit(1);
  }
  free(buff);

  if (gt_cmp(msg1, msg1_decoded) == CMP_EQ) {
    std::cout << "Decode Message OK!" << std::endl;
  } else {
    std::cout << "Decode Message Failed!" << std::endl;
  }

  pre_generate_keys(alice_key);
  pre_generate_keys(bob_key);
  pre_generate_re_token(token_to_bob, alice_key, bob_key->pk_2);
  pre_encrypt(alice_cipher1, alice_key, msg1);
  key_size = get_encoded_key_size(alice_key);
  buff = (char *)malloc((size_t)key_size);
  if (!encode_key(buff, key_size, alice_key) == STS_OK) {
    std::cout << "Key encode error!" << std::endl;
    exit(1);
  }
  if (!decode_key(alice_key_decoded, buff, key_size) == STS_OK) {
    std::cout << "Key decode error!" << std::endl;
    exit(1);
  }
  free(buff);

  if (bn_cmp(alice_key->sk, alice_key_decoded->sk) == CMP_EQ &&
      gt_cmp(alice_key->Z, alice_key_decoded->Z) == CMP_EQ &&
      g1_cmp(alice_key->pk, alice_key_decoded->pk) == CMP_EQ &&
      g2_cmp(alice_key->pk_2, alice_key_decoded->pk_2) == CMP_EQ &&
      g1_cmp(alice_key->g, alice_key_decoded->g) == CMP_EQ &&
      g2_cmp(alice_key->g2, alice_key_decoded->g2) == CMP_EQ &&
      alice_key->type == alice_key_decoded->type) {
    std::cout << "Decode Key OK!" << std::endl;
  } else {
    std::cout << "Decode Key Failed!" << std::endl;
  }

  key_size = get_encoded_token_size(token_to_bob);
  buff = (char *)malloc((size_t)key_size);
  encode_token(buff, key_size, token_to_bob);
  decode_token(token_to_bob_decode, buff, key_size);
  free(buff);

  if (g2_cmp(token_to_bob->re_token, token_to_bob_decode->re_token) == CMP_EQ) {
    std::cout << "Decode Token OK!" << std::endl;
  } else {
    std::cout << "Decode Token Failed!" << std::endl;
  }

  key_size = get_encoded_cipher_size(alice_cipher1);
  buff = (char *)malloc((size_t)key_size);
  encode_cipher(buff, key_size, alice_cipher1);
  decode_cipher(alice_cipher1_decode, buff, key_size);
  free(buff);

  if (gt_cmp(alice_cipher1->C1, alice_cipher1_decode->C1) == CMP_EQ &&
      g1_cmp(alice_cipher1->C2_G1, alice_cipher1_decode->C2_G1) == CMP_EQ) {
    std::cout << "Decode Cipher OK!" << std::endl;
  } else {
    std::cout << "Decode Cipher Failed!" << std::endl;
  }

  pre_re_apply(token_to_bob, bob_re, alice_cipher1);

  key_size = get_encoded_cipher_size(bob_re);
  buff = (char *)malloc((size_t)key_size);
  encode_cipher(buff, key_size, bob_re);
  decode_cipher(bob_re_decode, buff, key_size);
  free(buff);

  if (gt_cmp(bob_re->C1, bob_re_decode->C1) == CMP_EQ &&
      gt_cmp(bob_re->C2_GT, bob_re_decode->C2_GT) == CMP_EQ) {
    std::cout << "Decode Cipher level2 OK!" << std::endl;
  } else {
    std::cout << "Decode Cipher level2 Failed!" << std::endl;
  }
  pre_decrypt(res, alice_key, alice_cipher1);
  if (gt_cmp(res, msg1) == CMP_EQ) {
    std::cout << "Dec OK!" << std::endl;
  } else {
    std::cout << "Dec Failed!" << std::endl;
  }
}

int main() {
  pre_init();
  std::cout << "---- PRE Tests" << std::endl;
  basic_test();
  std::cout << "---- Encode/Decode Tests" << std::endl;
  encode_decode_test();
  pre_deinit();
  return 0;
}
