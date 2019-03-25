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
 *  a_inv is cached in the secret key to avoid redundant computation.
 */
struct pre_sk_s {
  bn_t a;         // secret factor a
  bn_t a_inv; // 1/a mod n (n = order of g1)
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
 * PRE re-encryption token
 */
struct pre_token_s {
  g2_t token;
};
typedef struct pre_token_s *pre_token_ptr;
typedef struct pre_token_s pre_token_t[1];

/**
 * PRE plaintext
 */
struct pre_plaintext_s {
  gt_t msg;
};
typedef struct pre_plaintext_s *pre_rel_plaintext_ptr;
typedef struct pre_plaintext_s pre_plaintext_t[1];

/**
 * PRE ciphertext that was encrypted directly a public key
 */
struct pre_ciphertext_s {
  gt_t c1; // ciphertext part 1 in GT
  g1_t c2; // ciphertext part 2 in G1
};
typedef struct pre_ciphertext_s *pre_rel_ciphertext_ptr;
typedef struct pre_ciphertext_s pre_ciphertext_t[1];

/**
 * PRE ciphertext that was re-encrypted to a second public key
 */
struct pre_re_ciphertext_s {
  gt_t c1; // ciphertext part 1 in GT
  gt_t c2; // ciphertext part 2 in GT
};
typedef struct pre_re_ciphertext_s *pre_rel_re_ciphertext_ptr;
typedef struct pre_re_ciphertext_s pre_re_ciphertext_t[1];

////////////////////////////////////////
//      Initialization Functions      //
////////////////////////////////////////

/**
 * Initializes the PRE library
 *
 * *** Must be called before first use! ***
 *
 * @return STS_OK if ok else STS_ERR
 */
int pre_init();

/**
 * Cleans up PRE library state
 *
 * @return STS_OK if ok else STS_ERR
 */
int pre_cleanup();

////////////////////////////////////////
//      Key generation Functions      //
////////////////////////////////////////

/**
 * Generates suitable public parameters for the scheme
 *
 * @param params the resulting public parameters
 * @return STS_OK if ok else STS_ERR
 */
int pre_generate_params(pre_params_t params);

/**
 * Generates a random secret key
 *
 * @param sk the resulting secret key
 * @param params the public parameters
 * @return STS_OK if ok else STS_ERR
 */
int pre_generate_sk(pre_sk_t sk, pre_params_t params);

/**
 * Derives the public key corresponding to the given secret key
 *
 * @param pk the resulting public key
 * @param params the public parameters
 * @param sk the secret key
 * @return STS_OK if ok else STS_ERR
 */
int pre_derive_pk(pre_pk_t pk, pre_params_t params, pre_sk_t sk);

/**
 * Derives a new public key from an existing one. The resulting
 * key will correspond to the secret key derived using pre_derive_next_keypair.
 *
 * @param new_pk the resulting public key
 * @param old_pk the existing public key
 * @return STS_OK if ok else STS_ERR
 */
int pre_derive_next_pk(pre_pk_t new_pk, pre_pk_t old_pk);

/**
 * Derives new secret and public keys from an existing pair
 *
 * @param new_sk the resulting secret key
 * @param new_pk the resulting public key
 * @param params the public parameters
 * @param old_sk the existing secret key
 * @param old_pk the existing public key
 * @return STS_OK if ok else STS_ERR
 */
int pre_derive_next_keypair(pre_sk_t new_sk, pre_pk_t new_pk, 
		pre_params_t params, pre_sk_t old_sk, pre_pk_t old_pk);

/**
 * Derives the re-encryption token from sk to pk
 *
 * @param token the resulting token
 * @param params initialized public parameters
 * @param sk an initialized secret key
 * @param pk an initialized public key
 * @return STS_OK if ok else STS_ERR
 */
int pre_generate_token(pre_token_t token, pre_params_t params,
		pre_sk_t sk, pre_pk_t pk);

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
int pre_clean_sk(pre_sk_t sk);

/**
 * Frees all of the fields of a public key
 *
 * @param pk the public key to clean
 * @return STS_OK if ok else STS_ERR
 */
int pre_clean_pk(pre_pk_t pk);

/**
 * Frees all of the fields of a re-encryption token
 *
 * @param token the token to clean
 * @return STS_OK if ok else STS_ERR
 */
int pre_clean_token(pre_token_t token);

/**
 * Frees all of the fields of a plaintext message
 *
 * @param plaintext the plaintext to clean
 * @return STS_OK if ok else STS_ERR
 */
int pre_clean_plaintext(pre_plaintext_t plaintext);

/**
 * Frees all of the fields of a ciphertext
 *
 * @param ciphertext the ciphertext to clean
 * @return STS_OK if ok else STS_ERR
 */
int pre_clean_ciphertext(pre_ciphertext_t ciphertext);

/**
 * Frees all of the fields of a re-encrypted ciphertext
 *
 * @param ciphertext the re-encrypted ciphertext to clean
 * @return STS_OK if ok else STS_ERR
 */
int pre_clean_re_ciphertext(pre_re_ciphertext_t ciphertext);

////////////////////////////////////////
//      Message Utility Functions     //
////////////////////////////////////////

/**
 * Generate a random plaintext message
 *
 * @return STS_OK if ok else STS_ERR
 */
int pre_rand_plaintext(pre_plaintext_t plaintext);

/**
 * Maps a plaintext message to an encryption key using KDF2
 *
 * @return STS_OK if ok else STS_ERR
 */
int pre_map_to_key(uint8_t *key, int key_len, pre_plaintext_t plaintext);

////////////////////////////////////////
//  Encryption/Decryption Functions   //
////////////////////////////////////////

/**
 * Encrypts a message to the given public key
 *
 * @param ciphertext the resulting ciphertext
 * @param params the public parameters
 * @param pk the public key
 * @param plaintext the message to encrypt
 * @return STS_OK if ok else STS_ERR
 */
int pre_encrypt(pre_ciphertext_t ciphertext, pre_params_t params,
		pre_pk_t pk, pre_plaintext_t plaintext);

/**
 * Decrypts a ciphertext with the given secret key
 *
 * @param plaintext the resulting plaintext
 * @param params the public parameters
 * @param sk the secret key
 * @param ciphertext the encrypted message
 * @return STS_OK if ok else STS_ERR
 */
int pre_decrypt(pre_plaintext_t plaintext, pre_params_t params,
		pre_sk_t sk, pre_ciphertext_t ciphertext);

/**
 * Decrypts a re-encrypted ciphertext with the given secret key
 *
 * @param plaintext the resulting plaintext
 * @param params the public parameters
 * @param sk the secret key
 * @param ciphertext the re-encrypted message
 * @return STS_OK if ok else STS_ERR
 */
int pre_decrypt_re(pre_plaintext_t plaintext, pre_params_t params,
		pre_sk_t sk, pre_re_ciphertext_t ciphertext);

/**
 * Re-encrypts the given ciphertext with the provided token
 * @param keys the PRE token
 * @param re_ciphertext the resulting ciphertext
 * @param ciphertext the input ciphertext
 * @return STS_OK if ok else STS_ERR
 */
int pre_apply_token(pre_re_ciphertext_t re_ciphertext, pre_token_t token,
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
 * Computes the required buffer size to encode a plaintext message
 *
 * @param plaintext the plaintext message whose encoding size to compute
 * @return STS_OK if ok else STS_ERR
 */
int get_encoded_plaintext_size(pre_plaintext_t plaintext);

/**
 * Encodes a plaintext message to a byte buffer
 *
 * @param buff the resulting buffer
 * @param size the size of the buffer
 * @param plaintext the plaintext message to encode
 * @return STS_OK if ok else STS_ERR
 */
int encode_plaintext(char *buff, int size, pre_plaintext_t plaintext);

/**
 * Decodes a plaintext message from a byte buffer
 *
 * @param plaintext the resulting plaintext
 * @param buff the buffer containing an encoded plaintext message
 * @param size the size of the buffer
 * @return STS_OK if ok else STS_ERR
 */
int decode_plaintext(pre_plaintext_t plaintext, char *buff, int size);

/**
 * Computes the required buffer size to encode a ciphertext
 *
 * @param ciphertext the ciphertext whose encoding size to compute
 * @return STS_OK if ok else STS_ERR
 */
int get_encoded_ciphertext_size(pre_ciphertext_t ciphertext);

/**
 * Encodes a ciphertext to a byte buffer
 *
 * @param buff the resulting buffer
 * @param size the size of the buffer
 * @param ciphertext the ciphertext to encode
 * @return STS_OK if ok else STS_ERR
 */
int encode_ciphertext(char *buff, int size, pre_ciphertext_t ciphertext);

/**
 * Decodes a ciphertext from a byte buffer
 *
 * @param ciphertext the resulting ciphertext
 * @param buff the buffer containing an encoded ciphertext
 * @param size the size of the buffer
 * @return STS_OK if ok else STS_ERR
 */
int decode_ciphertext(pre_ciphertext_t ciphertext, char *buff, int size);

/**
 * Computes the required buffer size to encode a re-encrypted ciphertext
 *
 * @param ciphertext the re-encrypted ciphertext whose encoding size to compute
 * @return STS_OK if ok else STS_ERR
 */
int get_encoded_re_ciphertext_size(pre_re_ciphertext_t ciphertext);

/**
 * Encodes a re-encrypted ciphertext to a byte buffer
 *
 * @param buff the resulting buffer
 * @param size the size of the buffer
 * @param ciphertext the re-encrypted ciphertext to encode
 * @return STS_OK if ok else STS_ERR
 */
int encode_re_ciphertext(char *buff, int size, pre_re_ciphertext_t ciphertext);

/**
 * Decodes a re-encrypted ciphertext from a byte buffer
 *
 * @param ciphertext the resulting re-encrypted ciphertext
 * @param buff the buffer containing an encoded re-encrypted ciphertext
 * @param size the size of the buffer
 * @return STS_OK if ok else STS_ERR
 */
int decode_re_ciphertext(pre_re_ciphertext_t ciphertext, char *buff, int size);

#endif
