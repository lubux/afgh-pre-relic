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

int pre_cleanup() {
  core_clean();
  return STS_OK;
}

int pre_rand_message(gt_t msg) {
  int result = STS_OK;

  TRY {
    gt_new(msg);
    gt_rand(msg);
  }
  CATCH_ANY {
    gt_free(msg);
    result = STS_ERR;
  }

  return result;
}

int pre_map_to_key(uint8_t *key, int key_len, gt_t msg) {
  int result = STS_OK;

  size_t buff_size;

  TRY {
    buff_size = (size_t)gt_size_bin(msg, 1);
    uint8_t buffer[buff_size];
    gt_write_bin(buffer, (int)buff_size, msg, 1);
    md_kdf2(key, key_len, buffer, (int)buff_size);
  }
  CATCH_ANY { result = STS_ERR; };

  return result;
}

int pre_clean_params(pre_params_t params) {
  int result = STS_OK;

  TRY {
    assert(params);

    gt_free(params->Z);
    g1_free(params->g1);
    g2_free(params->g2);
  }
  CATCH_ANY { result = STS_ERR; }

  return result;
}

int pre_clean_sk(pre_sk_t sk) {
  int result = STS_OK;

  TRY {
    assert(sk);

    bn_free(sk->sk);
    bn_free(sk->inverse);
  }
  CATCH_ANY { result = STS_ERR; }

  return result;
}

int pre_clean_pk(pre_pk_t pk) {
  int result = STS_OK;

  TRY {
    assert(pk);

    g1_free(pk->pk1);
    g2_free(pk->pk2);
  }
  CATCH_ANY { result = STS_ERR; }

  return result;
}

int pre_clean_token(pre_token_t token) {
  g2_free(token->token);
  return STS_OK;
}

int pre_clean_cipher(pre_ciphertext_t ciphertext) {
  int result = STS_OK;

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
  }
  CATCH_ANY { result = STS_ERR; }

  return result;
}
