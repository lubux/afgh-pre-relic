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

#define PRE_REL_CIPHERTEXT_IN_G_GROUP '1'
#define PRE_REL_CIPHERTEXT_IN_GT_GROUP '2'

#define ENCODING_SIZE 2

////////////////////////////////////////
//         Struct definitions         //
////////////////////////////////////////

/**
 *  PRE public parameters
 *
 *  These must be shared by public/private keypairs that are
 *  encrypting/decrypting the same messages.
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
 *
 *  a_inverse is cached in the secret key to avoid redundant computation.
 */
struct pre_sk_s {
  bn_t a;         // secret factor a
  bn_t a_inverse; // 1/a mod n (n = order of g1)
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

/**
 * PRE ciphertext
 *
 * In the AFGH scheme, ciphertexts that have been encrypted with a public key
 * consist of an element in GT and an element in G1, while those that have been
 * re-encrypted with a token consist of two elements in G2. The 'group' field
 * denotes which of these types a ciphertext is.
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
 * PRE re-encryption token
 */
struct pre_token_s {
  g2_t token;
};
typedef struct pre_token_s *pre_token_ptr;
typedef struct pre_token_s pre_token_t[1];

////////////////////////////////////////
//      Initialization Functions      //
////////////////////////////////////////

/**
 * Initializes the PRE library
 *
 * *** Must be called before first use! ***
 */
int pre_init();

/**
 * Cleans up PRE library state
 */
int pre_cleanup();

////////////////////////////////////////
//      Message Utility Functions     //
////////////////////////////////////////

/**
 * Generate a random gt element for encryption
 *
 * @return STS_OK if ok else STS_ERR
 */
int pre_rand_message(gt_t msg);

/**
 * Maps a gt message to an encryption key using the standardized KDF2 function
 *
 * @return STS_OK if ok else STS_ERR
 */
int pre_map_to_key(uint8_t *key, int key_len, gt_t msg);

////////////////////////////////////////
//          Cleanup Functions         //
////////////////////////////////////////

/**
 * Frees all of the fields of a set of public parameters
 *
 * @param params the public parameters to clean
 * @return STS_OK if ok else STS_ERR
 */
int pre_clean_params(pre_params_t params);

/**
 * Frees all of the fields of a secret key
 *
 * @param sk the secret key to clean
 * @return STS_OK if ok else STS_ERR
 */
int pre_clean_sk(pre_params_t sk);

/**
 * Frees all of the fields of a public key
 *
 * @param pk the public key to clean
 * @return STS_OK if ok else STS_ERR
 */
int pre_clean_pk(pre_params_t pk);

/**
 * Frees all of the fields of a re-encryption token
 *
 * @param token the token to clean
 * @return STS_OK if ok else STS_ERR
 */
int pre_clean_token(pre_token_t token);

/**
 * Frees all of the fields of a ciphertext
 *
 * @param cipher the ciphertext to clean
 * @return STS_OK if ok else STS_ERR
 */
int pre_clean_cipher(pre_ciphertext_t cipher);

////////////////////////////////////////
//      Key generation Functions      //
////////////////////////////////////////

int pre_generate_params(pre_params_t params);

int pre_generate_sk(pre_params_t params, pre_sk_t sk);

int pre_generate_pk(pre_params_t params, pre_sk_t sk, pre_pk_t pk);

int pre_derive_next_keypair(pre_sk_t sk, pre_pk_t pk);

int pre_generate_token(pre_token_t token, pre_params_t params, pre_sk_t sk, pre_pk_t pk);

////////////////////////////////////////
//  Encryption/Decryption Functions   //
////////////////////////////////////////

int pre_encrypt(pre_ciphertext_t ciphertext, pre_params_t params, pre_pk_t pk, gt_t plaintext);

int pre_decrypt(gt_t plaintext, pre_params_t params, pre_sk_t sk, pre_ciphertext_t ciphertext);

/**
 * Re-encrypts the given ciphertext with the provided token
 * @param keys the PRE token
 * @param res the resulting ciphertext
 * @param ciphertext th input ciphertext
 * @return STS_OK if ok else STS_ERR
 */
int pre_apply_token(pre_token_t token, pre_ciphertext_t res,
                 pre_ciphertext_t ciphertext);

////////////////////////////////////////
//    Encoding/Decoding Functions     //
////////////////////////////////////////

/**
 * Computes the required buffer size to encode a set of public parameters
 *
 * @param params the parameters whose encoding size to compute
 * @return STS_OK if ok else STS_ERR
 */
int get_encoded_params_size(pre_params_t params);

/**
 * Encodes a set of public parameters to a byte buffer
 *
 * @param buff the resulting buffer
 * @param size the size of the buffer
 * @param params the public parameters to encode
 * @return STS_OK if ok else STS_ERR
 */
int encode_params(char *buff, int size, pre_params_t params);

/**
 * Decodes a set of public parameters from a byte buffer
 *
 * @param params the resulting public parameters
 * @param buff the buffer containing encoded public parameters
 * @param size the size of the buffer
 * @return STS_OK if ok else STS_ERR
 */
int decode_params(pre_params_t params, char *buff, int size);

/**
 * Computes the required buffer size to encode a secret key
 *
 * @param sk the secret key whose encoding size to compute
 * @return STS_OK if ok else STS_ERR
 */
int get_encoded_sk_size(pre_sk_t sk);

/**
 * Encodes a secret key to a byte buffer
 *
 * @param buff the resulting buffer
 * @param size the size of the buffer
 * @param sk the secret key to encode
 * @return STS_OK if ok else STS_ERR
 */
int encode_sk(char *buff, int size, pre_sk_t sk);

/**
 * Decodes a secret key from a byte buffer
 *
 * @param sk the resulting secret key
 * @param buff the buffer containing an encoded secret key
 * @param size the size of the buffer
 * @return STS_OK if ok else STS_ERR
 */
int decode_sk(pre_sk_t sk, char *buff, int size);

/**
 * Computes the required buffer size to encode a public key
 *
 * @param pk the public key whose encoding size to compute
 * @return STS_OK if ok else STS_ERR
 */
int get_encoded_pk_size(pre_pk_t pk);

/**
 * Encodes a public key to a byte buffer
 *
 * @param buff the resulting buffer
 * @param size the size of the buffer
 * @param pk the public key to encode
 * @return STS_OK if ok else STS_ERR
 */
int encode_pk(char *buff, int size, pre_pk_t pk);

/**
 * Decodes a public key from a byte buffer
 *
 * @param pk the resulting public key
 * @param buff the buffer containing an encoded public key
 * @param size the size of the buffer
 * @return STS_OK if ok else STS_ERR
 */
int decode_pk(pre_pk_t pk, char *buff, int size);

/**
 * Computes the required buffer size to encode a re-encryption token
 *
 * @param token the token whose encoding size to compute
 * @return STS_OK if ok else STS_ERR
 */
int get_encoded_token_size(pre_token_t token);

/**
 * Encodes a re-encryption token to a byte buffer
 *
 * @param buff the resulting buffer
 * @param size the size of the buffer
 * @param token the token to encode
 * @return STS_OK if ok else STS_ERR
 */
int encode_token(char *buff, int size, pre_token_t token);

/**
 * Decodes a re-encryption token from a byte buffer
 *
 * @param token the resulting token
 * @param buff the buffer containing an encoded token
 * @param size the size of the buffer
 * @return STS_OK if ok else STS_ERR
 */
int decode_token(pre_token_t token, char *buff, int size);

/**
 * Computes the required buffer size to encode a message
 *
 * @param msg the message whose encoding size to compute
 * @return STS_OK if ok else STS_ERR
 */
int get_encoded_msg_size(gt_t msg);

/**
 * Encodes a message to a byte buffer
 *
 * @param buff the resulting buffer
 * @param size the size of the buffer
 * @param msg the message to encode
 * @return STS_OK if ok else STS_ERR
 */
int encode_msg(char *buff, int size, gt_t msg);

/**
 * Decodes a message from a byte buffer
 *
 * @param msg the resulting message
 * @param buff the buffer containing an encoded message
 * @param size the size of the buffer
 * @return STS_OK if ok else STS_ERR
 */
int decode_msg(gt_t msg, char *buff, int size);

/**
 * Computes the required buffer size to encode a ciphertext
 *
 * @param cipher the ciphertext whose encoding size to compute
 * @return STS_OK if ok else STS_ERR
 */
int get_encoded_cipher_size(pre_ciphertext_t cipher);

/**
 * Encodes a ciphertext to a byte buffer
 *
 * @param buff the resulting buffer
 * @param size the size of the buffer
 * @param cipher the ciphertext to encode
 * @return STS_OK if ok else STS_ERR
 */
int encode_cipher(char *buff, int size, pre_ciphertext_t cipher);

/**
 * Decodes a ciphertext from a byte buffer
 *
 * @param cipher the resulting ciphertext
 * @param buff the buffer containing an encoded ciphertext
 * @param size the size of the buffer
 * @return STS_OK if ok else STS_ERR
 */
int decode_cipher(pre_ciphertext_t cipher, char *buff, int size);

#endif
