/*
 * Copyright (c) 2016, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author:
 *       Lukas Burkhalter <lubu@student.ethz.ch>
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

#include "pre-hom.h"
#include <limits.h>


// Finds the mod inverse of a modulo m
int mod_inverse(bn_t res, bn_t a, bn_t m)
{
    bn_t tempGcd, temp;
    dig_t one = 1;
    int result = STS_ERR;

    bn_null(tempGcd);
    bn_null(temp);

    TRY {

        bn_new(tempGcd);
        bn_new(temp);

        bn_gcd_ext(tempGcd, res, temp, a, m);
        if(bn_sign(res)==BN_NEG) {
            bn_add(res, res, m);
        }
        result = STS_OK;
    }
    CATCH_ANY {
        result = STS_ERR;
    }
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
}

int pre_deinit() {
    core_clean();
    return STS_OK;
}

// cleanup and free sub-structures in 'keys'
int pre_keys_clear(pre_keys_t keys) {
    int result = STS_ERR;

    TRY {
        assert(keys);

        gt_free(keys->Z);
        g1_free(keys->g);
        g1_free(keys->pk);
        g2_free(keys->g2);
        g2_free(keys->pk_2);

        if (keys->type == PRE_REL_KEYS_TYPE_SECRET) {
            bn_free(keys->sk);
        }

        result = STS_OK;
    }
    CATCH_ANY {
        result = STS_ERR;
    }

    return result;
}

int pre_rand_message(gt_t msg) {
    int result = STS_ERR;
    TRY {
        gt_new(msg);
        gt_rand(msg);
        result = STS_OK;
    }
    CATCH_ANY {
        result = STS_ERR;
    }

    return result;
}

int pre_map_to_key(uint8_t *key, int key_len, gt_t msg) {
    int result = STS_ERR;
    uint8_t *buffer;
    size_t buff_size;
    TRY {
        buff_size = (size_t) gt_size_bin(msg, 1);
        buffer = (uint8_t *) malloc(buff_size);
        if (!buffer) {
            return STS_ERR;
        }
        gt_write_bin(buffer, (int) buff_size, msg, 1);
        md_kdf2(key, key_len, buffer, (int) buff_size);
    }
    CATCH_ANY {
        result = STS_ERR;
    } FINALLY {
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

        if (ciphertext->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) { // test to detect if the structure is already initialized); could it fail?
            gt_free(ciphertext->C1);
            g1_free(ciphertext->C2_G1);
            ciphertext->group='\0';
        } else  if (ciphertext->group == PRE_REL_CIPHERTEXT_IN_GT_GROUP) {
            gt_free(ciphertext->C1);
            gt_free(ciphertext->C2_GT);
            ciphertext->group='\0';
        }
        result = STS_OK;
    }
    CATCH_ANY {
        result = STS_ERR;
    }

    return result;
}

/* generate suitable pairing parameters and a pair of public/secret keys: they are stored in the structure 'keys'
 * if composite>0, then it results to n = q1q2, where q1 and q2 are primes with lower orders
 * if composite=0, then n has the same order as the prime q1. This curve is single prime
 */
int pre_generate_keys(pre_keys_t keys) {
    bn_t ord;
    int result = STS_ERR;

    bn_null(ord);
    bn_null(keys->n);
    bn_null(keys->sk);
    g1_null(keys->g);
    g1_null(keys->pk);
    g2_null(keys->g2);
    g2_null(keys->pk_2);
    //g2_null(keys->re_token);
    gt_null(keys->Z);

    TRY {
        bn_new(ord);
        bn_new(keys->sk);
        g1_new(keys->g);
        g1_new(keys->pk);
        g2_new(keys->g2);
        g2_new(keys->pk_2);
        gt_new(keys->Z);

        keys->type=PRE_REL_KEYS_TYPE_SECRET;

        g1_get_ord(ord);

        /* random generator random????*/
        g1_get_gen(keys->g);
        g2_get_gen(keys->g2); // If symmetric, these two generators should be the same

        /* define a random value as secret key and compute the public key as pk = g^sk*/
        bn_rand_mod(keys->sk, ord);

        g1_mul_gen(keys->pk, keys->sk);
        g2_mul_gen(keys->pk_2, keys->sk);

        /* pairing Z = e(g,g)*/
        pc_map(keys->Z, keys->g, keys->g2);

        result = STS_OK;
    }
    CATCH_ANY {
        result = STS_ERR;

        bn_null(keys->n);
        bn_null(keys->sk);
        g1_null(keys->g);
        g1_null(keys->pk);
        g2_null(keys->g2);
        g2_null(keys->pk_2);
        //g2_null(keys->re_token);
        gt_null(keys->Z);
    } FINALLY {
        bn_free(ord);
    };

    return result;
}

/* Since we are not storing the Settings, we have borrowed them from the first instance
 * Compute the secret and public key for follow-up users!
 */
int pre_generate_secret_key(pre_keys_t keys) {
    int result = STS_ERR;
    bn_t ord;

    TRY {
        assert(keys);
        bn_new(ord);
        g1_get_ord(ord);

        /* define a random value as secret key and compute the public key as pk = g^sk*/
        bn_rand_mod(keys->sk, ord);

        g1_mul_gen(keys->pk, keys->sk);
        g2_mul_gen(keys->pk_2, keys->sk);

        result = STS_OK;
    }
    CATCH_ANY {
        result = STS_ERR;
    } FINALLY {
        bn_free(ord);
    };

    return result;
}

/* Generate the re-encryption token towards Bob by means of his public key_b*/
int pre_generate_re_token(pre_re_token_t token, pre_keys_t keys, g2_t pk_2_b) {
    bn_t t, ord;
    int result = STS_ERR;

    bn_null(t);
    TRY {
        assert(keys);
        bn_new(ord);
        //assert(!element_is0(pk_pp_b));

        g1_get_ord(ord);
        g2_new(keys->re_token);
        bn_new(t);

        /* 1/a mod n */
        mod_inverse(t, keys->sk, ord);

        /* g^b ^ 1/a*/
        g2_mul(token->re_token, pk_2_b, t);

        result = STS_OK;
    }
    CATCH_ANY {
        result = STS_ERR;
        g2_null(keys->re_token);
    }
    FINALLY {
        bn_free(t);
        bn_free(ord);
    }

    return result;
}

/* encrypt the given plaintext (a number) using the public-key in 'keys';
 * the number of bits in the plaintext can be specified of autodetected (plaintext_bits=0)
 */
int pre_encrypt(pre_ciphertext_t ciphertext, pre_keys_t keys, gt_t plaintext) {
    bn_t r ,ord;
    int result = STS_ERR;

    bn_null(r);
    bn_null(m);
    gt_null(t);

    TRY {

        bn_new(r);
        bn_new(ord);

        gt_new(ciphertext->C1);
        g1_new(ciphertext->C2_G1);
        g1_get_ord(ord);

        assert(ciphertext);
        assert(keys);
        assert((keys->type == PRE_REL_KEYS_TYPE_SECRET) || (keys->type == PRE_REL_KEYS_TYPE_ONLY_PUBLIC));

        ciphertext->group=PRE_REL_CIPHERTEXT_IN_G_GROUP;

        /*
         * First Level Encryption
         * c = (c1, c2)     c1, c2 \in G
         *      c1 = Z^ar = e(g,g)^ar = e(g^a,g^r) = e(pk_a, g^r)
         *      c2 = m·Z^r
         */
        /* Compute C1 part: MZ^r*/
        /* random r in Zn  (re-use r) */
        bn_rand_mod(r, ord);
        while(bn_is_zero(r)) {
            bn_rand_mod(r, ord);
        }
        /* Z^r */
        gt_exp(ciphertext->C1, keys->Z, r);

        /* Z^r*m */
        gt_mul(ciphertext->C1, ciphertext->C1, plaintext);

        /* Compute C2 part: G^ar = pk ^r*/
        /* g^ar = pk^r */
        g1_mul(ciphertext->C2_G1, keys->pk, r);

        result = STS_OK;
    }
    CATCH_ANY {
        result = STS_ERR;
        gt_null(ciphertext->C1);
        g1_null(ciphertext->C2_G1);
    }
    FINALLY {
        bn_free(r);
        bn_free(ord);
    }

    return result;
}


int pre_decrypt(gt_t res, pre_keys_t keys, pre_ciphertext_t ciphertext) {
    g2_t t1;
    gt_t t0;
    bn_t t11, ord;
    int result = STS_ERR;

    bn_null(t11);
    gt_null(t0);
    g2_null(t1);
    gt_null(res);

    TRY {
        bn_new(t11);
        gt_new(t0);
        g2_new(t1);
        gt_new(res);
        bn_new(ord);

        assert(keys);
        assert(keys->type == PRE_REL_KEYS_TYPE_SECRET);
        assert(ciphertext);
        assert((ciphertext->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) || (ciphertext->group == PRE_REL_CIPHERTEXT_IN_GT_GROUP));

        g1_get_ord(ord);
        /*
         * M = (M.Z^r) / e(G^ar, G^1/a)
         * M = C1 / e(C2, G^1/a)
         */

        /* 1/a mod n */
        mod_inverse(t11, keys->sk, ord);

        if (ciphertext->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) {
            /* g ^ 1/a*/
            g2_mul(t1, keys->g2, t11);

            /* e(g^ar, g^-a) = Z^r */
            pc_map(res, ciphertext->C2_G1, t1);
            //pbc_pmesg(3, "Z^r: %B\n", t2);
        } else {
            /* C2 = Z^ar
             * Compute: Z^ar^(1/a)*/
            if(bn_is_zero(t11))  {
                gt_set_unity(res);
            } else {
                gt_exp(res, ciphertext->C2_GT, t11);
            }
        }

        /* C1 / e(C2, g^a^-1) or C1/C2^(1/a) */
        gt_inv(t0, res);
        gt_mul(res, ciphertext->C1, t0);
    }
    CATCH_ANY {
        result = STS_ERR;
    }
    FINALLY {
        gt_free(t0);
        g1_free(t1);
        bn_free(t11);
        bn_free(ord);
    }

    return result;
}


int pre_re_apply(pre_re_token_t token, pre_ciphertext_t res, pre_ciphertext_t ciphertext) {
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
        pc_map(res->C2_GT, ciphertext->C2_G1, token->re_token);

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

int get_encoded_token_size(pre_re_token_t token) {
    return g2_size_bin(token->re_token, 1);
}
int encode_token(char* buff, int size, pre_re_token_t token) {
    int size_type = get_encoded_token_size(token);
    if(size<size_type) {
        return STS_ERR;
    }
    g2_write_bin((uint8_t*) buff, size_type, token->re_token, 1);
    return STS_OK;
}
int decode_token(pre_re_token_t token, char* buff, int size) {
    g2_new(token->re_token);
    g2_read_bin(token->re_token,(uint8_t*) buff, size);
    return STS_OK;
}

int get_encoded_key_size(pre_keys_t key) {
    int total_size = 1;
    total_size+= gt_size_bin(key->Z, 1) + ENCODING_SIZE;
    total_size+= g1_size_bin(key->g, 1) + ENCODING_SIZE;
    total_size+= g1_size_bin(key->pk, 1) + ENCODING_SIZE;
    total_size+= g2_size_bin(key->g2, 1) + ENCODING_SIZE;
    total_size+= g2_size_bin(key->pk_2, 1) + ENCODING_SIZE;
    if(key->type==PRE_REL_KEYS_TYPE_SECRET) {
        total_size+=bn_size_bin(key->sk) + ENCODING_SIZE;
    }
    return total_size;
}

void write_size(char* buffer, int size) {
    buffer[0] = (char) ((size>>8) & 0xFF);
    buffer[1] = (char) (size & 0xFF);
}

int read_size(char* buffer) {
    return ((uint8_t) buffer[0]<<8) | ((uint8_t) buffer[1]);
}

int encode_key(char* buff, int size, pre_keys_t key) {
    int size_type = get_encoded_key_size(key), temp_size;
    char* cur_ptr = buff + 1;
    if(size<size_type) {
        return STS_ERR;
    }

    buff[0] = key->type;

    temp_size = gt_size_bin(key->Z, 1);
    write_size(cur_ptr, (u_int16_t) temp_size);
    cur_ptr += ENCODING_SIZE;
    gt_write_bin((uint8_t*) cur_ptr, temp_size, key->Z, 1);
    cur_ptr+=temp_size;

    temp_size = g1_size_bin(key->g, 1);
    write_size(cur_ptr, (u_int16_t) temp_size);
    cur_ptr += ENCODING_SIZE;
    g1_write_bin((uint8_t*) cur_ptr, temp_size, key->g, 1);
    cur_ptr += temp_size;

    temp_size = g1_size_bin(key->pk, 1);
    write_size(cur_ptr, (u_int16_t) temp_size);
    cur_ptr += ENCODING_SIZE;
    g1_write_bin((uint8_t*) cur_ptr, temp_size, key->pk, 1);
    cur_ptr += temp_size;

    temp_size = g2_size_bin(key->g2, 1);
    write_size(cur_ptr, (u_int16_t) temp_size);
    cur_ptr += ENCODING_SIZE;
    g2_write_bin((uint8_t*) cur_ptr, temp_size, key->g2, 1);
    cur_ptr += temp_size;

    temp_size = g2_size_bin(key->pk_2, 1);
    write_size(cur_ptr, (u_int16_t) temp_size);
    cur_ptr += ENCODING_SIZE;
    g2_write_bin((uint8_t*) cur_ptr, temp_size, key->pk_2, 1);
    cur_ptr += temp_size;

    if(key->type==PRE_REL_KEYS_TYPE_SECRET) {
        temp_size = bn_size_bin(key->sk);
        write_size(cur_ptr, temp_size);
        cur_ptr += ENCODING_SIZE;
        bn_write_bin((uint8_t*) cur_ptr, temp_size, key->sk);
    }

    return STS_OK;
}
int decode_key(pre_keys_t key, char* buff, int size) {
    int temp_size, dyn_size = 1;
    char* cur_ptr = buff+1;
    key->type = buff[0];
    if(size<4) {
        return STS_ERR;
    }

    g1_new(key->g);
    g1_new(key->pk);
    g2_new(key->g2);
    g2_new(key->pk_2);
    gt_new(key->Z);

    temp_size = read_size(cur_ptr);
    dyn_size += temp_size + ENCODING_SIZE;
    if(size<dyn_size) {
        return STS_ERR;
    }
    cur_ptr += ENCODING_SIZE;
    gt_read_bin(key->Z, (uint8_t*) cur_ptr, temp_size);
    cur_ptr += temp_size;

    temp_size = read_size(cur_ptr);
    dyn_size += temp_size + ENCODING_SIZE;
    if(size<dyn_size) {
        return STS_ERR;
    }
    cur_ptr += ENCODING_SIZE;
    g1_read_bin(key->g, (uint8_t*) cur_ptr, temp_size);
    cur_ptr += temp_size;

    temp_size = read_size(cur_ptr);
    dyn_size += temp_size + ENCODING_SIZE;
    if(size<dyn_size) {
        return STS_ERR;
    }
    cur_ptr += ENCODING_SIZE;
    g1_read_bin(key->pk, (uint8_t*) cur_ptr, temp_size);
    cur_ptr += temp_size;

    temp_size = read_size(cur_ptr);
    dyn_size += temp_size + ENCODING_SIZE;
    if(size<dyn_size) {
        return STS_ERR;
    }
    cur_ptr += ENCODING_SIZE;
    g2_read_bin(key->g2, (uint8_t*) cur_ptr, temp_size);
    cur_ptr += temp_size;

    temp_size = read_size(cur_ptr);
    dyn_size += temp_size + ENCODING_SIZE;
    if(size<dyn_size) {
        return STS_ERR;
    }
    cur_ptr += ENCODING_SIZE;
    g2_read_bin(key->pk_2, (uint8_t*) cur_ptr, temp_size);
    cur_ptr += temp_size;

    if(key->type==PRE_REL_KEYS_TYPE_SECRET) {
        bn_new(key->sk);
        temp_size = read_size(cur_ptr);
        cur_ptr += ENCODING_SIZE;
        bn_read_bin(key->sk, (uint8_t*) cur_ptr, temp_size);
    }
    return STS_OK;
}

int get_encoded_cipher_size(pre_ciphertext_t cipher) {
    int size = 1;
    size += gt_size_bin(cipher->C1, 1) + ENCODING_SIZE;
    if(cipher->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) {
        size += g1_size_bin(cipher->C2_G1, 1) + ENCODING_SIZE;
    } else {
        size += gt_size_bin(cipher->C2_GT, 1) + ENCODING_SIZE;
    }
    return size;
}
int encode_cipher(char* buff, int size, pre_ciphertext_t cipher){
    int size_type = get_encoded_cipher_size(cipher), temp_size;
    char* cur_ptr = buff+1;
    if(size<size_type) {
        return STS_ERR;
    }
    buff[0] = cipher->group;

    temp_size = gt_size_bin(cipher->C1, 1);
    write_size(cur_ptr, (u_int16_t) temp_size);
    cur_ptr += ENCODING_SIZE;
    gt_write_bin((uint8_t*) cur_ptr, temp_size, cipher->C1, 1);
    cur_ptr += temp_size;

    if(cipher->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) {
        temp_size = g1_size_bin(cipher->C2_G1, 1);
        write_size(cur_ptr, (u_int16_t) temp_size);
        cur_ptr += ENCODING_SIZE;
        g1_write_bin((uint8_t*) cur_ptr, temp_size, cipher->C2_G1, 1);
    } else {
        temp_size = gt_size_bin(cipher->C2_GT, 1);
        write_size(cur_ptr, (u_int16_t) temp_size);
        cur_ptr += ENCODING_SIZE;
        gt_write_bin((uint8_t*) cur_ptr, temp_size, cipher->C2_GT, 1);
    }
}
int decode_cipher(pre_ciphertext_t cipher, char* buff, int size){
    int temp_size, dyn_size = 1;
    char* cur_ptr = buff+1;
    if(size < 4) {
        return STS_ERR;
    }

    gt_new(cipher->C1);

    cipher->group = buff[0];

    temp_size = read_size(cur_ptr);
    dyn_size += temp_size + ENCODING_SIZE;
    if(size < dyn_size) {
        return STS_ERR;
    }
    cur_ptr += ENCODING_SIZE;
    gt_read_bin(cipher->C1, (uint8_t*) cur_ptr, temp_size);
    cur_ptr += temp_size;

    if(cipher->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) {
        g1_new(cipher->C2_G1);
        temp_size = read_size(cur_ptr);
        dyn_size += temp_size + ENCODING_SIZE;
        if(size < dyn_size) {
            return STS_ERR;
        }
        cur_ptr += ENCODING_SIZE;
        g1_read_bin(cipher->C2_G1, (uint8_t*) cur_ptr, temp_size);
    } else {
        gt_new(cipher->C2_GT);
        temp_size = read_size(cur_ptr);
        dyn_size += temp_size + ENCODING_SIZE;
        if(size < dyn_size) {
            return STS_ERR;
        }
        cur_ptr += ENCODING_SIZE;
        gt_read_bin(cipher->C2_GT, (uint8_t*) cur_ptr, temp_size);
    }

    return STS_OK;
}

int pre_cipher_clear(pre_ciphertext_t cipher) {
    gt_free(cipher->C1);
    if(cipher->group == PRE_REL_CIPHERTEXT_IN_G_GROUP) {
        g1_free(cipher->C2_G1);
    } else {
        gt_free(cipher->C2_GT);
    }
    return STS_OK;
}
int pre_token_clear(pre_re_token_t token) {
    g2_free(token->re_token);
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