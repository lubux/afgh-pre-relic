/*
 * Copyright (c) 2016, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author:
 *       Lukas Burkhalter <lubu@student.ethz.ch>
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


#include <iostream>
#include <gmpxx.h>
#include <chrono>

extern "C" {
#include "pre-hom.h"
}

using namespace std::chrono;


int basic_test() {

    pre_keys_t alice_key, bob_key;
    pre_ciphertext_t alice_cipher1, bob_re;
    pre_re_token_t token_to_bob;
    gt_t ms1;
    gt_t res;
    uint8_t key1[16];
    uint8_t key2[16];
    char ok = 1;

    // generate random message
    pre_rand_message(ms1);

    pre_generate_keys(alice_key);
    pre_generate_keys(bob_key);


    pre_encrypt(alice_cipher1, alice_key, ms1);

    pre_decrypt(res, alice_key, alice_cipher1);

    if (gt_cmp(ms1, res) == CMP_EQ) {
        std::cout << "OK!" << std::endl;
    } else {
        std::cout << "Failed!" << std::endl;
    }

    pre_generate_re_token(token_to_bob, alice_key, bob_key->pk_2);

    pre_re_apply(token_to_bob, bob_re, alice_cipher1);


    pre_decrypt(res, bob_key, bob_re);

    if (gt_cmp(ms1, res) == CMP_EQ) {
        std::cout << "OK!" << std::endl;
    } else {
        std::cout << "Failed!" << std::endl;
    }

    pre_map_to_key(key1, 16, res);
    pre_map_to_key(key2, 16, ms1);

    for (int i = 0; i < 16; i++) {
        if (key1[i] != key2[i]) {
            ok = 0;
            break;
        }
    }

    if (ok) {
        std::cout << "OK!" << std::endl;
    } else {
        std::cout << "Failed!" << std::endl;
    }

    return 0;
}

int main() {
    pre_init();
    basic_test();
    pre_deinit();
    return 0;
}