/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define HAVE_AESGCM
#include "aes_128_gcm.hpp"

#include <iostream>
#include <string.h>

namespace {

}  // namespace

Aes128Gcm::Aes128Gcm(const uint8_t* key_material, size_t key_material_len)
{
    assert(key_material);
    assert(key_material_len != 0ul);

    uint8_t info[] = "adb pairing_auth aes-128-gcm key";

    assert(wc_HKDF(WC_SHA256, (uint8_t*)key_material, (word32)key_material_len, nullptr, 0,
                info, (word32) (sizeof(info) - 1), key_, (word32)sizeof(key_)) == WOLFSSL_ERROR_NONE);

    cipher_ = EVP_aes_128_gcm();

    // encrypt
    encryptContext_ = wolfssl::UniquePtr<WOLFSSL_EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new());
    wolfSSL_EVP_CIPHER_CTX_init(encryptContext_.get());

    // decrypt
    decryptContext_ = wolfssl::UniquePtr<WOLFSSL_EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new());
    wolfSSL_EVP_CIPHER_CTX_init(decryptContext_.get());
}

size_t Aes128Gcm::Encrypt(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len)
{
    int written_sz, ret;
    std::vector<uint8_t> nonce(EVP_CIPHER_iv_length(cipher_), 0);
    memcpy(nonce.data(), &enc_sequence_, sizeof(enc_sequence_));

    assert(EVP_EncryptInit(encryptContext_.get(), cipher_, key_, nonce.data()) == SSL_SUCCESS);

    ret = EVP_EncryptUpdate(encryptContext_.get(), out, &written_sz, in, (int)in_len);
    
    if (ret != WOLFSSL_SUCCESS || written_sz > out_len){
        std::cerr  << "Failed to encrypt (in_len=" << in_len << ", out_len=" << out_len
                   << ", out_len_needed=" << EncryptedSize(in_len) << ")";
        return 0;
    }

    ret = EVP_EncryptFinal(encryptContext_.get(), out, &written_sz);

    if (ret != WOLFSSL_SUCCESS || written_sz > out_len || written_sz != in_len){
        std::cerr  << "Failed to encrypt (in_len=" << in_len << ", out_len=" << out_len
        << ", out_len_needed=" << EncryptedSize(in_len) << ")";
        return 0;
    }


    // the last 16 bytes are the tag. Copy the tag into those last 16 bytes as boringssl does
    assert((out_len - in_len) == taglen_);
    assert(EVP_CIPHER_CTX_ctrl(encryptContext_.get(), EVP_CTRL_GCM_GET_TAG, taglen_, (void*)(out + in_len)) == SSL_SUCCESS);

    ++enc_sequence_;
    return written_sz + taglen_;
}

size_t Aes128Gcm::Decrypt(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len)
{
    int written_sz;
    std::vector<uint8_t> nonce(EVP_CIPHER_iv_length(cipher_), 0);
    memcpy(nonce.data(), &dec_sequence_, sizeof(dec_sequence_));

    assert(EVP_DecryptInit(decryptContext_.get(), cipher_, key_, nonce.data()) == SSL_SUCCESS);

    // copy tag from the end of encrypted data. The tag should be 16 bytes or AES_BLOCK_SIZE.
    assert(EVP_CIPHER_CTX_ctrl(decryptContext_.get(), EVP_CTRL_GCM_SET_TAG, taglen_, (void*)(in + (in_len - taglen_))) == SSL_SUCCESS);

    in_len -= taglen_; // ignore the tag at the end of the encrypted data

    int ret = EVP_DecryptUpdate(decryptContext_.get(), out, &written_sz, in, (int)in_len);

    if (ret != WOLFSSL_SUCCESS || written_sz > out_len){
        std::cerr  << "Failed to decrypt (in_len=" << in_len << ", out_len=" << out_len
                   << ", out_len_needed=" << DecryptedSize(in_len) << ")" << std::endl;
        return 0;
    }

    ret = EVP_DecryptFinal(decryptContext_.get(), out, &written_sz);

    if (ret != WOLFSSL_SUCCESS || written_sz > out_len){
        std::cerr  << "Failed to decrypt (in_len=" << in_len << ", out_len=" << written_sz
                   << ", out_len_needed=" << DecryptedSize(in_len) << ")" << std::endl;
        std::cerr  << "Error: " << wolfSSL_ERR_get_error() << std::endl;
        return 0;
    }

    ++dec_sequence_;
    return written_sz;
}

size_t Aes128Gcm::EncryptedSize(size_t size) {
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/aead.h.html#EVP_AEAD_CTX_seal
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/aead.h.html#EVP_AEAD_max_overhead
    return size + (taglen_); // google stores the tag at the end of the enc data.
}

size_t Aes128Gcm::DecryptedSize(size_t size) {
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/aead.h.html#EVP_AEAD_CTX_open
    return size - (taglen_); // google stores the tag at the end of the enc data.
}


