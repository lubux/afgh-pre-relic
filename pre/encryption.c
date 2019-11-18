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

int pre_encrypt(pre_ciphertext_t ciphertext, pre_params_t params,
		pre_pk_t pk, pre_plaintext_t plaintext) {
  int result = RLC_OK;

  bn_t r;

  bn_null(r);

  TRY {
    bn_new(r);

    gt_new(ciphertext->c1);
    g1_new(ciphertext->c2);

    assert(ciphertext);
    assert(params);
    assert(pk);

    /*
     * First Level Encryption
     * c = (c1, c2)     c1, c2 \in G
     *      c1 = Z^ar = e(g,g)^ar = e(g^a,g^r) = e(pk_a, g^r)
     *      c2 = m·Z^r
     */
    /* Compute c1 part: MZ^r*/
    /* random r in Zn  (re-use r) */
    bn_rand_mod(r, params->g1_ord);
    while (bn_is_zero(r)) {
      bn_rand_mod(r, params->g1_ord);
    }

    /* Z^r */
    gt_exp(ciphertext->c1, params->Z, r);

    /* Z^r*m */
    gt_mul(ciphertext->c1, ciphertext->c1, plaintext->msg);

    /* Compute c2 part: G^ar = pk ^r*/
    /* g^ar = pk^r */
    g1_mul(ciphertext->c2, pk->pk1, r);
  }
  CATCH_ANY {
    result = RLC_ERR;
    gt_null(ciphertext->c1);
    g1_null(ciphertext->c2);
  }
  FINALLY {
    bn_free(r);
  }

  return result;
}

int pre_decrypt(pre_plaintext_t plaintext, pre_params_t params,
		pre_sk_t sk, pre_ciphertext_t ciphertext) {
  int result = RLC_OK;

  g2_t t1;
  gt_t t0;

  gt_null(t0);
  g2_null(t1);
  gt_null(plaintext->msg);

  TRY {
    gt_new(t0);
    g2_new(t1);
    gt_new(plaintext->msg);

    assert(params);
    assert(sk);
    assert(ciphertext);

    /*
     * M = (M.Z^r) / e(G^ar, G^1/a)
     * M = c1 / e(c2, G^1/a)
     */

    /* g ^ 1/a*/
    g2_mul(t1, params->g2, sk->a_inv);

    /* e(g^ar, g^-a) = Z^r */
    pc_map(plaintext->msg, ciphertext->c2, t1);
    // pbc_pmesg(3, "Z^r: %B\n", t2);

    /* c1 / e(c2, g^a^-1) or c1/c2^(1/a) */
    gt_inv(t0, plaintext->msg);
    gt_mul(plaintext->msg, ciphertext->c1, t0);
  }
  CATCH_ANY { result = RLC_ERR; }
  FINALLY {
    gt_free(t0);
    g1_free(t1);
  }

  return result;
}

int pre_decrypt_re(pre_plaintext_t plaintext, pre_params_t params,
		pre_sk_t sk, pre_re_ciphertext_t ciphertext) {
  int result = RLC_OK;

  gt_t t0;

  gt_null(t0);
  gt_null(plaintext->msg);

  TRY {
    gt_new(t0);
    gt_new(plaintext->msg);

    assert(params);
    assert(sk);
    assert(ciphertext);

    /*
     * M = (M.Z^r) / e(G^ar, G^1/a)
     * M = c1 / e(c2, G^1/a)
     */

    /* c2 = Z^ar
     * Compute: Z^ar^(1/a)*/
    if (bn_is_zero(sk->a_inv)) {
      gt_set_unity(plaintext->msg);
    } else {
      gt_exp(plaintext->msg, ciphertext->c2, sk->a_inv);
    }

    /* c1 / e(c2, g^a^-1) or c1/c2^(1/a) */
    gt_inv(t0, plaintext->msg);
    gt_mul(plaintext->msg, ciphertext->c1, t0);
  }
  CATCH_ANY { result = RLC_ERR; }
  FINALLY {
    gt_free(t0);
  }

  return result;
}

int pre_apply_token(pre_re_ciphertext_t re_ciphertext, pre_token_t token, 
                 pre_ciphertext_t ciphertext) {
  int result = RLC_OK;

  TRY {
    assert(token);
    assert(re_ciphertext);
    assert(ciphertext);
    pre_clean_re_ciphertext(re_ciphertext);

    gt_new(re_ciphertext->c1);
    gt_new(re_ciphertext->c2);

    gt_copy(re_ciphertext->c1, ciphertext->c1);

    /* level2: c2 = g^ar */
    /* level1: c2 = e(g^ar, g^(b/a) = Z^br*/
    pc_map(re_ciphertext->c2, ciphertext->c2, token->token);
  }
  CATCH_ANY {
    result = RLC_ERR;
    gt_null(re_ciphertext->c1);
    gt_null(re_ciphertext->c2);
  }

  return result;
}
