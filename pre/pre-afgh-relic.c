/*
 * Copyright (c) 2019, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author:
 *       Lukas Burkhalter <lubu@inf.ethz.ch>
 *       Hossein Shafagh <shafagh@inf.ethz.ch>
 *       Pascal Fischli <fischlip@student.ethz.ch>
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

#include "pre-afgh-relic.h"
#include <limits.h>

// Finds the mod inverse of a modulo m
int mod_inverse(bn_t res, bn_t a, bn_t m) {
  bn_t tempGcd, temp;
  int result = STS_ERR;

  bn_null(tempGcd);
  bn_null(temp);

  TRY {

    bn_new(tempGcd);
    bn_new(temp);

    bn_gcd_ext(tempGcd, res, temp, a, m);
    if (bn_sign(res) == BN_NEG) {
      bn_add(res, res, m);
    }
    result = STS_OK;
  }
  CATCH_ANY { result = STS_ERR; }
  FINALLY {
    bn_free(tempGcd);
    bn_free(temp);
  }

  return result;
}

int pre_init() {
  if (core_init() != STS_OK) {
    core_clean();
    return STS_ERR;
  }

  if (pc_param_set_any() != STS_OK) {
    THROW(ERR_NO_CURVE);
    core_clean();
    return STS_ERR;
  }
  pc_param_print();
  return STS_OK;
}

int pre_deinit() {
  core_clean();
  return STS_OK;
}

int pre_params_clear(pre_params_t params) {
  int result = STS_ERR;

  TRY {
    assert(params);

    gt_free(params->Z);
    g1_free(params->g1);
    g2_free(params->g2);

    result = STS_OK;
  }
  CATCH_ANY { result = STS_ERR; }

  return result;
}

int pre_sk_clear(pre_sk_t sk) {
  int result = STS_ERR;

  TRY {
    assert(sk);

    bn_free(sk->sk);
    bn_free(sk->inverse);

    result = STS_OK;
  }
  CATCH_ANY { result = STS_ERR; }

  return result;
}

int pre_pk_clear(pre_pk_t pk) {
  int result = STS_ERR;

  TRY {
    assert(pk);

    g1_free(pk->pk1);
    g2_free(pk->pk2);

    result = STS_OK;
  }
  CATCH_ANY { result = STS_ERR; }

  return result;
}

int pre_rand_message(gt_t msg) {
  int result = STS_ERR;
  TRY {
    gt_new(msg);
    gt_rand(msg);
    result = STS_OK;
  }
  CATCH_ANY { result = STS_ERR; }

  return result;
}

int pre_map_to_key(uint8_t *key, int key_len, gt_t msg) {
  int result = STS_ERR;
  uint8_t *buffer;
  size_t buff_size;
  TRY {
    buff_size = (size_t)gt_size_bin(msg, 1);
    buffer = (uint8_t *)malloc(buff_size);
    if (!buffer) {
      return STS_ERR;
    }
    gt_write_bin(buffer, (int)buff_size, msg, 1);
    md_kdf2(key, key_len, buffer, (int)buff_size);
    result = STS_OK;
  }
  CATCH_ANY { result = STS_ERR; }
  FINALLY {
    if (buffer) {
      free(buffer);
    }
  };

  return result;
}

// cleanup and free sub-structures in 'ciphertext' (only if already initialized)
int pre_ciphertext_clear(pre_ciphertext_t ciphertext) {
  int result = STS_ERR;

  TRY {
    assert(ciphertext);
    assert(ciphertext->C1);
    assert(ciphertext->C2_G1 || ciphertext->C2_GT);

    if (ciphertext->group ==
        PRE_REL_CIPHERTEXT_IN_G_GROUP) { // test to detect if the structure is
                                         // already initialized); could it fail?
      gt_free(ciphertext->C1);
      g1_free(ciphertext->C2_G1);
      ciphertext->group = '\0';
    } else if (ciphertext->group == PRE_REL_CIPHERTEXT_IN_GT_GROUP) {
      gt_free(ciphertext->C1);
      gt_free(ciphertext->C2_GT);
      ciphertext->group = '\0';
    }
    result = STS_OK;
  }
  CATCH_ANY { result = STS_ERR; }

  return result;
}

int pre_generate_params(pre_params_t params) {
  int result = STS_ERR;

  g1_null(params->g1);
  g2_null(params->g2);
  gt_null(params->Z);
  bn_null(params->g1_ord);

  TRY {
    g1_new(params->g1);
    g2_new(params->g2);
    gt_new(params->Z);
    bn_new(params->g1_ord);

    g1_get_gen(params->g1);
    g2_get_gen(params->g2);

    /* pairing Z = e(g,g)*/
    pc_map(params->Z, params->g1, params->g2);

    g1_get_ord(params->g1_ord);

    result = STS_OK;
  }
  CATCH_ANY {
    result = STS_ERR;

    g1_null(params->g1);
    g2_null(params->g2);
    gt_null(params->Z);
    bn_null(params->g1_ord);
  };

  return result;
}

int pre_generate_sk(pre_params_t params, pre_sk_t sk) {
  int result = STS_ERR;

  bn_null(sk->sk);
  bn_null(sk->inverse);

  TRY {
    bn_new(sk->sk);
    bn_new(sk->inverse);

    // generate a random value, a, as secret key
    bn_rand_mod(sk->sk, params->g1_ord);

    // compute 1/a mod n for use later
    mod_inverse(sk->inverse, sk->sk, params->g1_ord);

    result = STS_OK;
  }
  CATCH_ANY {
    result = STS_ERR;

    bn_null(sk->sk);
    bn_null(sk->inverse);
  };

  return result;
}

int pre_generate_pk(pre_params_t params, pre_sk_t sk, pre_pk_t pk) {
  int result = STS_ERR;

  g1_null(pk->pk1);
  g2_null(pk->pk2);

  TRY {
    g1_new(pk->pk1);
    g2_new(pk->pk2);

    // compute the public key as pk1 = g1^a, pk2 = g2^a
    g1_mul_gen(pk->pk1, sk->sk);
    g2_mul_gen(pk->pk2, sk->sk);

    result = STS_OK;
  }
  CATCH_ANY {
    result = STS_ERR;

    g1_null(pk->pk1);
    g2_null(pk->pk2);
  };

  return result;
}

int pre_derive_next_pk(pre_pk_t pk) {
  int size, result = STS_ERR;
  bn_t hash_int;
  g1_t g1_hash_element;
  g2_t g2_hash_element;

  bn_null(hash_int);
  TRY {
    assert(pk);

    bn_new(hash_int);
    g1_new(g1_hash_element);
    g2_new(g2_hash_element);

    size = g1_size_bin(pk->pk1, 1);
    uint8_t buf[size], hash[64];
    g1_write_bin(buf, size, pk->pk1, 1);
    md_map_sh512(hash, buf, size);
    bn_read_bin(hash_int, hash, 64);

    g1_mul_gen(g1_hash_element, hash_int);
    g2_mul_gen(g2_hash_element, hash_int);

    g1_add(pk->pk1, pk->pk1, g1_hash_element);
    g2_add(pk->pk2, pk->pk2, g2_hash_element);

    result = STS_OK;
  }
  CATCH_ANY {
    result = STS_ERR;
  }
  FINALLY {
    bn_free(hash_int);
  }

  return result;
}

int pre_derive_next_keypair(pre_sk_t sk, pre_pk_t pk) {
  int size, result = STS_ERR;
  bn_t hash_int;
  g1_t g1_hash_element;
  g2_t g2_hash_element;

  bn_null(hash_int);
  TRY {
    assert(sk);
    assert(pk);

    bn_new(hash_int);
    g1_new(g1_hash_element);
    g2_new(g2_hash_element);

    size = g1_size_bin(pk->pk1, 1);
    uint8_t buf[size], hash[64];
    g1_write_bin(buf, size, pk->pk1, 1);
    md_map_sh512(hash, buf, size);
    bn_read_bin(hash_int, hash, 64);

    g1_mul_gen(g1_hash_element, hash_int);
    g2_mul_gen(g2_hash_element, hash_int);

    g1_add(pk->pk1, pk->pk1, g1_hash_element);
    g2_add(pk->pk2, pk->pk2, g2_hash_element);

    bn_add(sk->sk, sk->sk, hash_int);

    result = STS_OK;
  }
  CATCH_ANY {
    result = STS_ERR;
  }
  FINALLY {
    bn_free(hash_int);
  }

  return result;
}

int pre_generate_token(pre_token_t token, pre_params_t params, pre_sk_t sk, pre_pk_t pk) {
  int result = STS_ERR;

  g2_null(token->token);
  TRY {
    assert(token);
    assert(params);
    assert(sk);
    assert(pk);

    g2_new(token->token);

    /* g^b ^ 1/a*/
    g2_mul(token->token, pk->pk2, sk->inverse);

    result = STS_OK;
  }
  CATCH_ANY {
    result = STS_ERR;
    g2_null(token->token);
  };

  return result;
}

int pre_encrypt(pre_ciphertext_t ciphertext, pre_params_t params, pre_pk_t pk, gt_t plaintext) {
  int result = STS_ERR;
  bn_t r;

  bn_null(r);

  TRY {
    bn_new(r);

    gt_new(ciphertext->C1);
    g1_new(ciphertext->C2_G1);

    assert(ciphertext);
    assert(params);
    assert(pk);

    ciphertext->group = PRE_REL_CIPHERTEXT_IN_G_GROUP;

    /*
     * First Level Encryption
     * c = (c1, c2)     c1, c2 \in G
     *      c1 = Z^ar = e(g,g)^ar = e(g^a,g^r) = e(pk_a, g^r)
     *      c2 = m·Z^r
     */
    /* Compute C1 part: MZ^r*/
    /* random r in Zn  (re-use r) */
    bn_rand_mod(r, params->g1_ord);
    while (bn_is_zero(r)) {
      bn_rand_mod(r, params->g1_ord);
    }

    /* Z^r */
    gt_exp(ciphertext->C1, params->Z, r);

    /* Z^r*m */
    gt_mul(ciphertext->C1, ciphertext->C1, plaintext);

    /* Compute C2 part: G^ar = pk ^r*/
    /* g^ar = pk^r */
    g1_mul(ciphertext->C2_G1, pk->pk1, r);

    result = STS_OK;
  }
  CATCH_ANY {
    result = STS_ERR;
    gt_null(ciphertext->C1);
    g1_null(ciphertext->C2_G1);
  }
  FINALLY {
    bn_free(r);
  }

  return result;
}

int pre_decrypt(gt_t plaintext, pre_params_t params, pre_sk_t sk, pre_ciphertext_t ciphertext) {
  int result = STS_ERR;
  g2_t t1;
  gt_t t0;

  gt_null(t0);
  g2_null(t1);
  gt_null(plaintext);

  TRY {
    gt_new(t0);
    g2_new(t1);
    gt_new(plaintext);

    assert(params);
    assert(sk);
    assert(ciphertext);
    assert((ciphertext->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) ||
           (ciphertext->group == PRE_REL_CIPHERTEXT_IN_GT_GROUP));

    /*
     * M = (M.Z^r) / e(G^ar, G^1/a)
     * M = C1 / e(C2, G^1/a)
     */

    if (ciphertext->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) {
      /* g ^ 1/a*/
      g2_mul(t1, params->g2, sk->inverse);

      /* e(g^ar, g^-a) = Z^r */
      pc_map(plaintext, ciphertext->C2_G1, t1);
      // pbc_pmesg(3, "Z^r: %B\n", t2);
    } else {
      /* C2 = Z^ar
       * Compute: Z^ar^(1/a)*/
      if (bn_is_zero(sk->inverse)) {
        gt_set_unity(plaintext);
      } else {
        gt_exp(plaintext, ciphertext->C2_GT, sk->inverse);
      }
    }

    /* C1 / e(C2, g^a^-1) or C1/C2^(1/a) */
    gt_inv(t0, plaintext);
    gt_mul(plaintext, ciphertext->C1, t0);

    result = STS_OK;
  }
  CATCH_ANY { result = STS_ERR; }
  FINALLY {
    gt_free(t0);
    g1_free(t1);
  }

  return result;
}

int pre_apply_token(pre_token_t token, pre_ciphertext_t res,
                 pre_ciphertext_t ciphertext) {
  int result;
  TRY {
    assert(token);
    assert(res);
    assert(ciphertext);
    assert(ciphertext->group == PRE_REL_CIPHERTEXT_IN_G_GROUP);
    pre_ciphertext_clear(res);

    gt_new(res->C1);
    gt_new(res->C2_GT);

    gt_copy(res->C1, ciphertext->C1);

    /* level2: C2 = g^ar */
    /* level1: C2 = e(g^ar, g^(b/a) = Z^br*/
    pc_map(res->C2_GT, ciphertext->C2_G1, token->token);

    res->group = PRE_REL_CIPHERTEXT_IN_GT_GROUP;
    result = STS_OK;
  }
  CATCH_ANY {
    result = STS_ERR;
    gt_null(res->C1);
    gt_null(res->C2_GT);
  }

  return result;
}

int get_encoded_msg_size(gt_t msg) {
  return gt_size_bin(msg, 1);
}

int encode_msg(char *buff, int size, gt_t msg) {
  int next_size = gt_size_bin(msg, 1);
  if (size < next_size) {
    return STS_ERR;
  }
  gt_write_bin((uint8_t *)buff, next_size, msg, 1);
  return STS_OK;
}

int decode_msg(gt_t msg, char *buff, int size) {
  gt_new(msg);
  gt_read_bin(msg, (uint8_t *)buff, size);
  return STS_OK;
}

int get_encoded_token_size(pre_token_t token) {
  return g2_size_bin(token->token, 1);
}

int encode_token(char *buff, int size, pre_token_t token) {
  int next_size = g2_size_bin(token->token, 1);
  if (size < next_size) {
    return STS_ERR;
  }
  g2_write_bin((uint8_t *)buff, next_size, token->token, 1);
  return STS_OK;
}

int decode_token(pre_token_t token, char *buff, int size) {
  g2_new(token->token);
  g2_read_bin(token->token, (uint8_t *)buff, size);
  return STS_OK;
}

void write_size(char *buffer, int size) {
  buffer[0] = (char)((size >> 8) & 0xFF);
  buffer[1] = (char)(size & 0xFF);
}

int read_size(char *buffer) {
  return ((uint8_t)buffer[0] << 8) | ((uint8_t)buffer[1]);
}

int valid_bounds(char *base, char *curr, int next_size, int size) {
    int curr_size = (int)(curr-base);
    return curr_size+next_size+ENCODING_SIZE <= size;
}

int get_encoded_params_size(pre_params_t params) {
  int total_size = 0;
  total_size += gt_size_bin(params->Z, 1) + ENCODING_SIZE;
  total_size += g1_size_bin(params->g1, 1) + ENCODING_SIZE;
  total_size += g2_size_bin(params->g2, 1) + ENCODING_SIZE;
  total_size += bn_size_bin(params->g1_ord) + ENCODING_SIZE;
  return total_size;
}

int encode_params(char *buff, int size, pre_params_t params) {
  int next_size;
  char *curr = buff;

  next_size = gt_size_bin(params->Z, 1);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  write_size(curr, (u_int16_t)next_size);
  curr += ENCODING_SIZE;
  gt_write_bin((uint8_t *)curr, next_size, params->Z, 1);
  curr += next_size;

  next_size = g1_size_bin(params->g1, 1);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  write_size(curr, (u_int16_t)next_size);
  curr += ENCODING_SIZE;
  g1_write_bin((uint8_t *)curr, next_size, params->g1, 1);
  curr += next_size;

  next_size = g2_size_bin(params->g2, 1);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  write_size(curr, (u_int16_t)next_size);
  curr += ENCODING_SIZE;
  g2_write_bin((uint8_t *)curr, next_size, params->g2, 1);
  curr += next_size;

  next_size = bn_size_bin(params->g1_ord);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  write_size(curr, next_size);
  curr += ENCODING_SIZE;
  bn_write_bin((uint8_t *)curr, next_size, params->g1_ord);

  return STS_OK;
}

int decode_params(pre_params_t params, char *buff, int size) {
  int next_size, dyn_size = 0;
  char *curr = buff;
  if (size < 4) {
    return STS_ERR;
  }

  g1_new(params->g1);
  g2_new(params->g2);
  gt_new(params->Z);
  bn_new(params->g1_ord);

  next_size = read_size(curr);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  dyn_size += next_size + ENCODING_SIZE;
  if (size < dyn_size) {
    return STS_ERR;
  }
  curr += ENCODING_SIZE;
  gt_read_bin(params->Z, (uint8_t *)curr, next_size);
  curr += next_size;

  next_size = read_size(curr);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  dyn_size += next_size + ENCODING_SIZE;
  if (size < dyn_size) {
    return STS_ERR;
  }
  curr += ENCODING_SIZE;
  g1_read_bin(params->g1, (uint8_t *)curr, next_size);
  curr += next_size;

  next_size = read_size(curr);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  dyn_size += next_size + ENCODING_SIZE;
  if (size < dyn_size) {
    return STS_ERR;
  }
  curr += ENCODING_SIZE;
  g2_read_bin(params->g2, (uint8_t *)curr, next_size);
  curr += next_size;

  next_size = read_size(curr);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  dyn_size += next_size + ENCODING_SIZE;
  if (size < dyn_size) {
    return STS_ERR;
  }
  curr += ENCODING_SIZE;
  bn_read_bin(params->g1_ord, (uint8_t *)curr, next_size);
  curr += next_size;

  return STS_OK;
}

int get_encoded_sk_size(pre_sk_t sk) {
  int total_size = 0;
  total_size += bn_size_bin(sk->sk) + ENCODING_SIZE;
  total_size += bn_size_bin(sk->inverse) + ENCODING_SIZE;
  return total_size;
}

int encode_sk(char *buff, int size, pre_sk_t sk) {
  int next_size;
  char *curr = buff;

  next_size = bn_size_bin(sk->sk);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  write_size(curr, next_size);
  curr += ENCODING_SIZE;
  bn_write_bin((uint8_t *)curr, next_size, sk->sk);
  curr += next_size;

  next_size = bn_size_bin(sk->inverse);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  write_size(curr, next_size);
  curr += ENCODING_SIZE;
  bn_write_bin((uint8_t *)curr, next_size, sk->inverse);

  return STS_OK;
}

int decode_sk(pre_sk_t sk, char *buff, int size) {
  int next_size, dyn_size = 0;
  char *curr = buff;
  if (size < 4) {
    return STS_ERR;
  }

  bn_new(sk->sk);
  bn_new(sk->inverse);

  next_size = read_size(curr);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  dyn_size += next_size + ENCODING_SIZE;
  if (size < dyn_size) {
    return STS_ERR;
  }
  curr += ENCODING_SIZE;
  bn_read_bin(sk->sk, (uint8_t *)curr, next_size);
  curr += next_size;

  next_size = read_size(curr);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  dyn_size += next_size + ENCODING_SIZE;
  if (size < dyn_size) {
    return STS_ERR;
  }
  curr += ENCODING_SIZE;
  bn_read_bin(sk->inverse, (uint8_t *)curr, next_size);
  curr += next_size;

  return STS_OK;
}

int get_encoded_pk_size(pre_pk_t pk) {
  int total_size = 0;
  total_size += g1_size_bin(pk->pk1, 1) + ENCODING_SIZE;
  total_size += g2_size_bin(pk->pk2, 1) + ENCODING_SIZE;
  return total_size;
}

int encode_pk(char *buff, int size, pre_pk_t pk) {
  int next_size;
  char *curr = buff;

  next_size = g1_size_bin(pk->pk1, 1);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  write_size(curr, (u_int16_t)next_size);
  curr += ENCODING_SIZE;
  g1_write_bin((uint8_t *)curr, next_size, pk->pk1, 1);
  curr += next_size;

  next_size = g2_size_bin(pk->pk2, 1);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  write_size(curr, (u_int16_t)next_size);
  curr += ENCODING_SIZE;
  g2_write_bin((uint8_t *)curr, next_size, pk->pk2, 1);
  curr += next_size;

  return STS_OK;
}

int decode_pk(pre_pk_t pk, char *buff, int size) {
  int next_size, dyn_size = 0;
  char *curr = buff;
  if (size < 4) {
    return STS_ERR;
  }

  g1_new(pk->pk1);
  g2_new(pk->pk2);

  next_size = read_size(curr);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  dyn_size += next_size + ENCODING_SIZE;
  if (size < dyn_size) {
    return STS_ERR;
  }
  curr += ENCODING_SIZE;
  g1_read_bin(pk->pk1, (uint8_t *)curr, next_size);
  curr += next_size;

  next_size = read_size(curr);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  dyn_size += next_size + ENCODING_SIZE;
  if (size < dyn_size) {
    return STS_ERR;
  }
  curr += ENCODING_SIZE;
  g2_read_bin(pk->pk2, (uint8_t *)curr, next_size);
  curr += next_size;

  return STS_OK;
}

int get_encoded_cipher_size(pre_ciphertext_t cipher) {
  int size = 1;
  size += gt_size_bin(cipher->C1, 1) + ENCODING_SIZE;
  if (cipher->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) {
    size += g1_size_bin(cipher->C2_G1, 1) + ENCODING_SIZE;
  } else {
    size += gt_size_bin(cipher->C2_GT, 1) + ENCODING_SIZE;
  }
  return size;
}

int encode_cipher(char *buff, int size, pre_ciphertext_t cipher) {
  int next_size;
  char *curr = buff + 1;

  buff[0] = cipher->group;

  next_size = gt_size_bin(cipher->C1, 1);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  write_size(curr, (u_int16_t)next_size);
  curr += ENCODING_SIZE;
  gt_write_bin((uint8_t *)curr, next_size, cipher->C1, 1);
  curr += next_size;

  if (cipher->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) {
    next_size = g1_size_bin(cipher->C2_G1, 1);
    if (!valid_bounds(buff, curr, next_size, size)) {
      return STS_ERR;
    }
    write_size(curr, (u_int16_t)next_size);
    curr += ENCODING_SIZE;
    g1_write_bin((uint8_t *)curr, next_size, cipher->C2_G1, 1);
  } else {
    next_size = gt_size_bin(cipher->C2_GT, 1);
    if (!valid_bounds(buff, curr, next_size, size)) {
      return STS_ERR;
    }
    write_size(curr, (u_int16_t)next_size);
    curr += ENCODING_SIZE;
    gt_write_bin((uint8_t *)curr, next_size, cipher->C2_GT, 1);
  }
  return STS_OK;
}

int decode_cipher(pre_ciphertext_t cipher, char *buff, int size) {
  int next_size, dyn_size = 1;
  char *curr = buff + 1;
  if (size < 4) {
    return STS_ERR;
  }

  gt_new(cipher->C1);

  cipher->group = buff[0];

  next_size = read_size(curr);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  dyn_size += next_size + ENCODING_SIZE;
  if (size < dyn_size) {
    return STS_ERR;
  }
  curr += ENCODING_SIZE;
  gt_read_bin(cipher->C1, (uint8_t *)curr, next_size);
  curr += next_size;

  if (cipher->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) {
    g1_new(cipher->C2_G1);
    next_size = read_size(curr);
    if (!valid_bounds(buff, curr, next_size, size)) {
      return STS_ERR;
    }
    dyn_size += next_size + ENCODING_SIZE;
    if (size < dyn_size) {
      return STS_ERR;
    }
    curr += ENCODING_SIZE;
    g1_read_bin(cipher->C2_G1, (uint8_t *)curr, next_size);
  } else {
    gt_new(cipher->C2_GT);
    next_size = read_size(curr);
    if (!valid_bounds(buff, curr, next_size, size)) {
      return STS_ERR;
    }
    dyn_size += next_size + ENCODING_SIZE;
    if (size < dyn_size) {
      return STS_ERR;
    }
    curr += ENCODING_SIZE;
    gt_read_bin(cipher->C2_GT, (uint8_t *)curr, next_size);
  }

  return STS_OK;
}

int pre_cipher_clear(pre_ciphertext_t cipher) {
  gt_free(cipher->C1);
  if (cipher->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) {
    g1_free(cipher->C2_G1);
  } else {
    gt_free(cipher->C2_GT);
  }
  return STS_OK;
}

int pre_token_clear(pre_token_t token) {
  g2_free(token->token);
  return STS_OK;
}

int pre_ciphertext_init(pre_ciphertext_t ciphertext, char group) {
  gt_new(ciphertext->C1);
  if (group == PRE_REL_CIPHERTEXT_IN_G_GROUP) {
    g1_new(ciphertext->C2_G1);
  } else {
    gt_new(ciphertext->C2_GT);
  }
  ciphertext->group = group;
  return STS_OK;
}
