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

////////////////////////////////////////
//    Encoding/Decoding Functions     //
////////////////////////////////////////

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

int get_encoded_plaintext_size(pre_plaintext_t plaintext) {
  return gt_size_bin(plaintext->msg, 1);
}

int encode_plaintext(char *buff, int size, pre_plaintext_t plaintext) {
  int next_size = gt_size_bin(plaintext->msg, 1);
  if (size < next_size) {
    return STS_ERR;
  }
  gt_write_bin((uint8_t *)buff, next_size, plaintext->msg, 1);
  return STS_OK;
}

int decode_plaintext(pre_plaintext_t plaintext, char *buff, int size) {
  gt_new(plaintext->msg);
  gt_read_bin(plaintext->msg, (uint8_t *)buff, size);
  return STS_OK;
}

int get_encoded_ciphertext_size(pre_ciphertext_t ciphertext) {
  int size = 1;
  size += gt_size_bin(ciphertext->C1, 1) + ENCODING_SIZE;
  if (ciphertext->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) {
    size += g1_size_bin(ciphertext->C2_G1, 1) + ENCODING_SIZE;
  } else {
    size += gt_size_bin(ciphertext->C2_GT, 1) + ENCODING_SIZE;
  }
  return size;
}

int encode_ciphertext(char *buff, int size, pre_ciphertext_t ciphertext) {
  int next_size;
  char *curr = buff + 1;

  buff[0] = ciphertext->group;

  next_size = gt_size_bin(ciphertext->C1, 1);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  write_size(curr, (u_int16_t)next_size);
  curr += ENCODING_SIZE;
  gt_write_bin((uint8_t *)curr, next_size, ciphertext->C1, 1);
  curr += next_size;

  if (ciphertext->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) {
    next_size = g1_size_bin(ciphertext->C2_G1, 1);
    if (!valid_bounds(buff, curr, next_size, size)) {
      return STS_ERR;
    }
    write_size(curr, (u_int16_t)next_size);
    curr += ENCODING_SIZE;
    g1_write_bin((uint8_t *)curr, next_size, ciphertext->C2_G1, 1);
  } else {
    next_size = gt_size_bin(ciphertext->C2_GT, 1);
    if (!valid_bounds(buff, curr, next_size, size)) {
      return STS_ERR;
    }
    write_size(curr, (u_int16_t)next_size);
    curr += ENCODING_SIZE;
    gt_write_bin((uint8_t *)curr, next_size, ciphertext->C2_GT, 1);
  }
  return STS_OK;
}

int decode_ciphertext(pre_ciphertext_t ciphertext, char *buff, int size) {
  int next_size, dyn_size = 1;
  char *curr = buff + 1;
  if (size < 4) {
    return STS_ERR;
  }

  gt_new(ciphertext->C1);

  ciphertext->group = buff[0];

  next_size = read_size(curr);
  if (!valid_bounds(buff, curr, next_size, size)) {
    return STS_ERR;
  }
  dyn_size += next_size + ENCODING_SIZE;
  if (size < dyn_size) {
    return STS_ERR;
  }
  curr += ENCODING_SIZE;
  gt_read_bin(ciphertext->C1, (uint8_t *)curr, next_size);
  curr += next_size;

  if (ciphertext->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) {
    g1_new(ciphertext->C2_G1);
    next_size = read_size(curr);
    if (!valid_bounds(buff, curr, next_size, size)) {
      return STS_ERR;
    }
    dyn_size += next_size + ENCODING_SIZE;
    if (size < dyn_size) {
      return STS_ERR;
    }
    curr += ENCODING_SIZE;
    g1_read_bin(ciphertext->C2_G1, (uint8_t *)curr, next_size);
  } else {
    gt_new(ciphertext->C2_GT);
    next_size = read_size(curr);
    if (!valid_bounds(buff, curr, next_size, size)) {
      return STS_ERR;
    }
    dyn_size += next_size + ENCODING_SIZE;
    if (size < dyn_size) {
      return STS_ERR;
    }
    curr += ENCODING_SIZE;
    gt_read_bin(ciphertext->C2_GT, (uint8_t *)curr, next_size);
  }

  return STS_OK;
}
