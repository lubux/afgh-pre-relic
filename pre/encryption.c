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

int pre_encrypt(pre_ciphertext_t ciphertext, pre_params_t params, pre_pk_t pk, gt_t plaintext) {
  int result = STS_OK;

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
  int result = STS_OK;

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
  int result = STS_OK;

  TRY {
    assert(token);
    assert(res);
    assert(ciphertext);
    assert(ciphertext->group == PRE_REL_CIPHERTEXT_IN_G_GROUP);
    pre_clean_cipher(res);

    gt_new(res->C1);
    gt_new(res->C2_GT);

    gt_copy(res->C1, ciphertext->C1);

    /* level2: C2 = g^ar */
    /* level1: C2 = e(g^ar, g^(b/a) = Z^br*/
    pc_map(res->C2_GT, ciphertext->C2_G1, token->token);

    res->group = PRE_REL_CIPHERTEXT_IN_GT_GROUP;
  }
  CATCH_ANY {
    result = STS_ERR;
    gt_null(res->C1);
    gt_null(res->C2_GT);
  }

  return result;
}
