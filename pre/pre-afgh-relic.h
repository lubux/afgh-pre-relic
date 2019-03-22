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

#ifndef PRE_REL_ENC_H_
#define PRE_REL_ENC_H_

#include <assert.h>
#include <relic/relic_core.h>
#include <relic/relic_types.h>

#include <relic/relic_bn.h>
#include <relic/relic_ec.h>
#include <relic/relic_md.h>
#include <relic/relic_pc.h>

#define PRE_REL_KEYS_TYPE_SECRET 's'
#define PRE_REL_KEYS_TYPE_ONLY_PUBLIC 'p'

#define PRE_REL_CIPHERTEXT_IN_G_GROUP '1'
#define PRE_REL_CIPHERTEXT_IN_GT_GROUP '2'

#define ENCODING_SIZE 2

/**
 *  PRE public parameters
 */
struct pre_params_s {
  g1_t g1;     // generator for G1
  g2_t g2;     // generator for G2
  gt_t Z;      // Z = e(g1,g2)
  bn_t g1_ord; // order of g1
};
typedef struct pre_params_s *pre_rel_params_ptr;
typedef struct pre_params_s pre_params_t[1];

/**
 *  PRE secret key
 */
struct pre_sk_s {
  bn_t sk;      // secret factor a
  bn_t inverse; // 1/a mod n (n = order of g1)
};
typedef struct pre_sk_s *pre_rel_sk_ptr;
typedef struct pre_sk_s pre_sk_t[1];

/**
 *  PRE public key
 */
struct pre_pk_s {
  g1_t pk1; // public key g1^a
  g2_t pk2; // public key g2^a
};
typedef struct pre_pk_s *pre_rel_pk_ptr;
typedef struct pre_pk_s pre_pk_t[1];

int get_encoded_params_size(pre_params_t params);

int encode_params(char *buff, int size, pre_params_t params);

int decode_params(pre_params_t params, char *buff, int size);

int get_encoded_sk_size(pre_sk_t sk);

int encode_sk(char *buff, int size, pre_sk_t sk);

int decode_sk(pre_sk_t sk, char *buff, int size);

int get_encoded_pk_size(pre_pk_t pk);

int encode_pk(char *buff, int size, pre_pk_t pk);

/**
 * Decodes the encoded key from a buffer.
 * @param key the keys
 * @param buff the buffer containing the encoded key
 * @param size the buffer size of the encoded key
 * @return STS_OK if ok else STS_ERR
 */
int decode_pk(pre_pk_t pk, char *buff, int size);


/**
 * Returns the encoded msg size of the provided msg
 * @param msg
 * @return the size in bytes of the encoded msg
 */
int get_encoded_msg_size(gt_t msg);

/**
 * Encodes the given msg as a byte array.
 * @param buff the allocated buffer for the encoding
 * @param size the allocated buffer size
 * @param msg the msg
 * @return STS_OK if ok else STS_ERR
 */
int encode_msg(char *buff, int size, gt_t msg);

/**
 * Decodes the encoded msg from a buffer.
 * @param msg the msg
 * @param buff the buffer containing the encoded msg
 * @param size the buffer size of the encoded msg
 * @return STS_OK if ok else STS_ERR
 */
int decode_msg(gt_t msg, char *buff, int size);

/**
 * Represents a PRE re-encryption token
 */
struct pre_token_s {
  g2_t token;
};
typedef struct pre_token_s *pre_token_ptr;
typedef struct pre_token_s pre_token_t[1];

/**
 * Returns the encoded token size of the provided token
 * @param token the PRE token
 * @return the size in bytes of the encoded token
 */
int get_encoded_token_size(pre_token_t token);

/**
 * Encodes the given token as a byte array.
 * @param buff the allocated buffer for the encoding
 * @param size the allocated buffer size
 * @param token the token
 * @return STS_OK if ok else STS_ERR
 */
int encode_token(char *buff, int size, pre_token_t token);

/**
 * Decodes the encoded token from a byte buffer.
 * @param token the token
 * @param buff the buffer containing the encoded token
 * @param size the buffer size of the encoded token
 * @return STS_OK if ok else STS_ERR
 */
int decode_token(pre_token_t token, char *buff, int size);

/**
 * The representation of a PRE ciphertext.
 */
struct pre_ciphertext_s {
  gt_t C1;    // ciphertext part 1
  g1_t C2_G1; // ciphertext part 2 in G1
  gt_t C2_GT; // ciphertext part 2 in GT
  char group; // flag to indicate the working group
};
typedef struct pre_ciphertext_s *pre_rel_ciphertext_ptr;
typedef struct pre_ciphertext_s pre_ciphertext_t[1];

/**
 * Returns the encoded token size of the provided ciphertext
 * @param cipher the PRE ciphertext
 * @return the size in bytes of the encoded ciphertext
 */
int get_encoded_cipher_size(pre_ciphertext_t cipher);

/**
 * Encodes the given ciphertext as a byte array.
 * @param buff the allocated buffer for the encoding
 * @param size the allocated buffer size
 * @param cipher the ciphertext
 * @return STS_OK if ok else STS_ERR
 */
int encode_cipher(char *buff, int size, pre_ciphertext_t cipher);

/**
 * Decodes the encoded ciphertext from a byte buffer.
 * @param cipher the ciphertext
 * @param buff the buffer containing the encoded ciphertext
 * @param size the buffer size of the encoded ciphertext
 * @return STS_OK if ok else STS_ERR
 */
int decode_cipher(pre_ciphertext_t cipher, char *buff, int size);

/**
 * Inits the PRE libray (HAS TO BE CALLED BEFORE USE!)
 * @return  STS_OK if ok else STS_ERR
 */
int pre_init();

/**
 * Deinits the PRE library
 * @return STS_OK if ok else STS_ERR
 */
int pre_deinit();

/**
 * Computes a random gt element for encryption
 * @return STS_OK if ok else STS_ERR
 */
int pre_rand_message(gt_t msg);

/**
 * Maps a gt message to an encryption key
 * @return STS_OK if ok else STS_ERR
 */
int pre_map_to_key(uint8_t *key, int key_len, gt_t msg);

/**
 * Free a ciphertext
 * @param cipher
 * @return STS_OK if ok else STS_ERR
 */
int pre_cipher_clear(pre_ciphertext_t cipher);

/**
 * Free a token
 * @param token
 * @return STS_OK if ok else STS_ERR
 */
int pre_token_clear(pre_token_t token);

/**
 * Free a ciphertext
 * @param ciphertext
 * @return STS_OK if ok else STS_ERR
 */
int pre_ciphertext_clear(pre_ciphertext_t ciphertext);

int pre_generate_params(pre_params_t params);

int pre_generate_sk(pre_params_t params, pre_sk_t sk);

int pre_generate_pk(pre_params_t params, pre_sk_t sk, pre_pk_t pk);

int pre_derive_next_keypair(pre_sk_t sk, pre_pk_t pk);

int pre_encrypt(pre_ciphertext_t ciphertext, pre_params_t params, pre_pk_t pk, gt_t plaintext);

int pre_decrypt(gt_t plaintext, pre_params_t params, pre_sk_t sk, pre_ciphertext_t ciphertext);

int pre_generate_token(pre_token_t token, pre_params_t params, pre_sk_t sk, pre_pk_t pk);

/**
 * Re-encrypts the given ciphertext with the provided token
 * @param keys the PRE token
 * @param res the resulting ciphertext
 * @param ciphertext th input ciphertext
 * @return  STS_OK if ok else STS_ERR
 */
int pre_apply_token(pre_token_t token, pre_ciphertext_t res,
                 pre_ciphertext_t ciphertext);

#endif
