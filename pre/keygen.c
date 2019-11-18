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

// Helper function to compute 1/a mod m
int mod_inverse(bn_t res, bn_t a, bn_t m) {
  bn_t tempGcd, temp;
  int result = RLC_OK;

  bn_null(tempGcd);
  bn_null(temp);

  TRY {

    bn_new(tempGcd);
    bn_new(temp);

    bn_gcd_ext(tempGcd, res, temp, a, m);
    if (bn_sign(res) == RLC_NEG) {
      bn_add(res, res, m);
    }
  }
  CATCH_ANY { result = RLC_ERR; }
  FINALLY {
    bn_free(tempGcd);
    bn_free(temp);
  }

  return result;
}

int pre_generate_params(pre_params_t params) {
  int result = RLC_OK;

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
  }
  CATCH_ANY {
    result = RLC_ERR;

    g1_null(params->g1);
    g2_null(params->g2);
    gt_null(params->Z);
    bn_null(params->g1_ord);
  };

  return result;
}

int pre_generate_sk(pre_sk_t sk, pre_params_t params) {
  int result = RLC_OK;

  bn_null(sk->a);
  bn_null(sk->a_inv);

  TRY {
    bn_new(sk->a);
    bn_new(sk->a_inv);

    // generate a random value, a, as secret key
    bn_rand_mod(sk->a, params->g1_ord);

    // compute 1/a mod n for use later
    mod_inverse(sk->a_inv, sk->a, params->g1_ord);
  }
  CATCH_ANY {
    result = RLC_ERR;

    bn_null(sk->a);
    bn_null(sk->a_inv);
  };

  return result;
}

int pre_derive_pk(pre_pk_t pk, pre_params_t params, pre_sk_t sk) {
  int result = RLC_OK;

  g1_null(pk->pk1);
  g2_null(pk->pk2);

  TRY {
    g1_new(pk->pk1);
    g2_new(pk->pk2);

    // compute the public key as pk1 = g1^a, pk2 = g2^a
    g1_mul_gen(pk->pk1, sk->a);
    g2_mul_gen(pk->pk2, sk->a);
  }
  CATCH_ANY {
    result = RLC_ERR;

    g1_null(pk->pk1);
    g2_null(pk->pk2);
  };

  return result;
}

// Helper function to compute the hash of a public key (used for key derivation)
int hash_pk(bn_t hash, g1_t g1_hash, g2_t g2_hash, pre_pk_t pk) { 
  int result = RLC_ERR;

  int size;

  bn_null(hash);
  g1_null(g1_hash);
  g2_null(g2_hash);
  TRY {
    assert(pk);

    bn_new(hash);
    g1_new(g1_hash);
    g2_new(g2_hash);

    size = g1_size_bin(pk->pk1, 1);
    uint8_t buf[size], hash_vector[64];
    g1_write_bin(buf, size, pk->pk1, 1);
    md_map_sh512(hash_vector, buf, size);
    bn_read_bin(hash, hash_vector, 64);

    g1_mul_gen(g1_hash, hash);
    g2_mul_gen(g2_hash, hash);
  }
  CATCH_ANY {
    result = RLC_ERR;

    bn_null(hash_int);
    g1_null(g1_hash);
    g2_null(g2_hash);
  }
  FINALLY {
    bn_free(hash_int);
  }

  return result;
}

int pre_derive_next_pk(pre_pk_t new_pk, pre_pk_t old_pk) {
  int result = RLC_OK;

  bn_t hash;
  g1_t g1_hash;
  g2_t g2_hash;

  g1_null(new_pk->pk1);
  g2_null(new_pk->pk2);

  TRY {
    assert(old_pk);

    g1_new(new_pk->pk1);
    g1_new(new_pk->pk2);

    hash_pk(hash, g1_hash, g2_hash, old_pk);

    g1_add(new_pk->pk1, old_pk->pk1, g1_hash);
    g2_add(new_pk->pk2, old_pk->pk2, g2_hash);
  }
  CATCH_ANY {
    result = RLC_ERR;

    bn_free(hash);
    g1_free(g1_hash);
    g2_free(g2_hash);
    g1_free(new_pk->pk1);
    g2_free(new_pk->pk2);
  }
  FINALLY {
    bn_free(hash);
    g1_free(g1_hash);
    g2_free(g2_hash);
  }

  return result;
}

int pre_derive_next_keypair(pre_sk_t new_sk, pre_pk_t new_pk, 
		pre_params_t params, pre_sk_t old_sk, pre_pk_t old_pk) {
  int result = RLC_OK;

  bn_t hash;
  g1_t g1_hash;
  g2_t g2_hash;

  bn_null(new_sk->a);
  bn_null(new_sk->a_inv);
  g1_null(new_pk->pk1);
  g2_null(new_pk->pk2);

  TRY {
    assert(old_sk);
    assert(old_pk);

    bn_new(new_sk->a);
    bn_new(new_sk->a_inv);
    g1_new(new_pk->pk1);
    g2_new(new_pk->pk2);

    hash_pk(hash, g1_hash, g2_hash, old_pk);

    g1_add(new_pk->pk1, old_pk->pk1, g1_hash);
    g2_add(new_pk->pk2, old_pk->pk2, g2_hash);

    bn_add(new_sk->a, old_sk->a, hash);
    mod_inverse(new_sk->a_inv, new_sk->a, params->g1_ord);
  }
  CATCH_ANY {
    result = RLC_ERR;

    bn_free(hash);
    g1_free(g1_hash);
    g2_free(g2_hash);
    bn_free(new_sk->a);
    bn_free(new_sk->a_inv);
    g1_free(new_pk->pk1);
    g1_free(new_pk->pk2);
  }
  FINALLY {
    bn_free(hash);
    g1_free(g1_hash);
    g2_free(g2_hash);
  }

  return result;
}

int pre_generate_token(pre_token_t token, pre_params_t params,
		pre_sk_t sk, pre_pk_t pk) {
  int result = RLC_OK;

  g2_null(token->token);
  TRY {
    assert(token);
    assert(params);
    assert(sk);
    assert(pk);

    g2_new(token->token);

    /* g^b ^ 1/a*/
    g2_mul(token->token, pk->pk2, sk->a_inv);
  }
  CATCH_ANY {
    result = RLC_ERR;
    g2_null(token->token);
  };

  return result;
}
