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
  pre_params_t params;
  pre_sk_t alice_sk, bob_sk;
  pre_pk_t alice_pk, bob_pk;
  pre_ciphertext_t cipher, re_cipher;
  pre_token_t token_to_bob;
  gt_t ms1, res;
  uint8_t key1[16];
  uint8_t key2[16];
  char ok = 1;

  // generate random message
  pre_rand_message(ms1);

  pre_generate_params(params);
  pre_generate_sk(params, alice_sk);
  pre_generate_pk(params, alice_sk, alice_pk);
  pre_generate_sk(params, bob_sk);
  pre_generate_pk(params, bob_sk, bob_pk);

  pre_encrypt(cipher, params, alice_pk, ms1);

  pre_decrypt(res, params, alice_sk, cipher);

  if (gt_cmp(ms1, res) == CMP_EQ) {
    std::cout << "Encrypt decrypt OK!" << std::endl;
  } else {
    std::cout << "Encrypt decrypt failed!" << std::endl;
  }

  pre_generate_token(token_to_bob, params, alice_sk, bob_pk);

  pre_apply_token(token_to_bob, re_cipher, cipher);

  pre_decrypt(res, params, bob_sk, re_cipher);

  if (gt_cmp(ms1, res) == CMP_EQ) {
    std::cout << "Re-encrypt decrypt OK!" << std::endl;
  } else {
    std::cout << "Re-encrypt decrypt failed!" << std::endl;
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
    std::cout << "Map to key OK!" << std::endl;
  } else {
    std::cout << "Map to key failed!" << std::endl;
  }

  return 0;
}

void encode_decode_test() {
  gt_t msg1, msg2, msg1_decoded;
  pre_params_t params, params_decoded;
  pre_sk_t alice_sk, bob_sk, alice_sk_decoded;
  pre_pk_t alice_pk, bob_pk, alice_pk_decoded;
  pre_ciphertext_t alice_cipher1, alice_cipher1_decode, bob_re, bob_re_decode;
  pre_token_t token_to_bob, token_to_bob_decode;
  gt_t res;
  int size;
  char *buff;

  pre_rand_message(msg1);
  pre_rand_message(msg2);
  size = get_encoded_msg_size(msg1);
  buff = (char *)malloc(size);
  if (!encode_msg(buff, size, msg1) == STS_OK) {
    std::cout << "Message encode error!" << std::endl;
    exit(1);
  }
  if (!decode_msg(msg1_decoded, buff, size) == STS_OK) {
    std::cout << "Message decode error!" << std::endl;
    exit(1);
  }
  free(buff);

  if (gt_cmp(msg1, msg1_decoded) == CMP_EQ) {
    std::cout << "Decode message OK!" << std::endl;
  } else {
    std::cout << "Decode message Failed!" << std::endl;
  }

  pre_generate_params(params);
  pre_generate_sk(params, alice_sk);
  pre_generate_pk(params, alice_sk, alice_pk);
  pre_generate_sk(params, bob_sk);
  pre_generate_pk(params, bob_sk, bob_pk);
  pre_generate_token(token_to_bob, params, alice_sk, bob_pk);
  pre_encrypt(alice_cipher1, params, alice_pk, msg1);

  size = get_encoded_params_size(params);
  buff = (char *)malloc(size);
  if (!encode_params(buff, size, params) == STS_OK) {
    std::cout << "Params encode error!" << std::endl;
    exit(1);
  }
  if (!decode_params(params_decoded, buff, size) == STS_OK) {
    std::cout << "Params decode error!" << std::endl;
    exit(1);
  }
  free(buff);

  if (gt_cmp(params->Z, params_decoded->Z) == CMP_EQ &&
      g1_cmp(params->g1, params_decoded->g1) == CMP_EQ &&
      g2_cmp(params->g2, params_decoded->g2) == CMP_EQ) {
    std::cout << "Decode params OK!" << std::endl;
  } else {
    std::cout << "Decode params failed!" << std::endl;
  }

  size = get_encoded_sk_size(alice_sk);
  buff = (char *)malloc(size);
  if (!encode_sk(buff, size, alice_sk) == STS_OK) {
    std::cout << "Secret key encode error!" << std::endl;
    exit(1);
  }
  if (!decode_sk(alice_sk_decoded, buff, size) == STS_OK) {
    std::cout << "Secret key decode error!" << std::endl;
    exit(1);
  }
  free(buff);

  if (bn_cmp(alice_sk->sk, alice_sk_decoded->sk) == CMP_EQ &&
      bn_cmp(alice_sk->inverse, alice_sk_decoded->inverse) == CMP_EQ) {
    std::cout << "Secret key OK!" << std::endl;
  } else {
    std::cout << "Secret key failed!" << std::endl;
  }

  size = get_encoded_pk_size(alice_pk);
  buff = (char *)malloc(size);
  if (!encode_pk(buff, size, alice_pk) == STS_OK) {
    std::cout << "Public key encode error!" << std::endl;
    exit(1);
  }
  if (!decode_pk(alice_pk_decoded, buff, size) == STS_OK) {
    std::cout << "Public key decode error!" << std::endl;
    exit(1);
  }
  free(buff);

  if (g1_cmp(alice_pk->pk1, alice_pk_decoded->pk1) == CMP_EQ &&
      g2_cmp(alice_pk->pk2, alice_pk_decoded->pk2) == CMP_EQ) {
    std::cout << "Decode public key OK!" << std::endl;
  } else {
    std::cout << "Decode public key failed!" << std::endl;
  }

  if (g1_cmp(alice_pk->pk1, alice_pk_decoded->pk1) == CMP_EQ &&
      g2_cmp(alice_pk->pk2, alice_pk_decoded->pk2) == CMP_EQ) {
    std::cout << "Public key OK!" << std::endl;
  } else {
    std::cout << "Public key failed!" << std::endl;
  }

  size = get_encoded_token_size(token_to_bob);
  buff = (char *)malloc(size);
  if (!encode_token(buff, size, token_to_bob) == STS_OK) {
    std::cout << "Token encode error!" << std::endl;
    exit(1);
  }
  if (!decode_token(token_to_bob_decode, buff, size) == STS_OK) {
    std::cout << "Token decode error!" << std::endl;
    exit(1);
  }
  free(buff);

  if (g2_cmp(token_to_bob->token, token_to_bob_decode->token) == CMP_EQ) {
    std::cout << "Decode token OK!" << std::endl;
  } else {
    std::cout << "Decode token failed!" << std::endl;
  }

  size = get_encoded_cipher_size(alice_cipher1);
  buff = (char *)malloc(size);
  encode_cipher(buff, size, alice_cipher1);
  decode_cipher(alice_cipher1_decode, buff, size);
  free(buff);

  if (gt_cmp(alice_cipher1->C1, alice_cipher1_decode->C1) == CMP_EQ &&
      g1_cmp(alice_cipher1->C2_G1, alice_cipher1_decode->C2_G1) == CMP_EQ) {
    std::cout << "Decode cipher OK!" << std::endl;
  } else {
    std::cout << "Decode cipher failed!" << std::endl;
  }

  pre_apply_token(token_to_bob, bob_re, alice_cipher1);

  size = get_encoded_cipher_size(bob_re);
  buff = (char *)malloc(size);
  encode_cipher(buff, size, bob_re);
  decode_cipher(bob_re_decode, buff, size);
  free(buff);

  if (gt_cmp(bob_re->C1, bob_re_decode->C1) == CMP_EQ &&
      gt_cmp(bob_re->C2_GT, bob_re_decode->C2_GT) == CMP_EQ) {
    std::cout << "Decode cipher level2 OK!" << std::endl;
  } else {
    std::cout << "Decode cipher level2 failed!" << std::endl;
  }
  pre_decrypt(res, params, alice_sk, alice_cipher1);
  if (gt_cmp(res, msg1) == CMP_EQ) {
    std::cout << "Decrypt OK!" << std::endl;
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
