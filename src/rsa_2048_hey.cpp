/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "adb_env.hpp"
#include "crypto.hpp"
#include "rsa_2048_key.hpp"
#include "android_pubkey.hpp"

#include <iostream>

static int EVP_EncodedLength(size_t *out_len, size_t len)
{
  if (len + 2 < len) {
    return 0;
  }
  len += 2;
  len /= 3;

  if (((len << 2) >> 2) != len) {
    return 0;
  }
  len <<= 2;

  if (len + 1 < len) {
    return 0;
  }
  len++;

  *out_len = len;
  return 1;
}

#undef EVP_EncodeBlock

/* MARK:WOLFSSL: We have to write a wrapper to escape newline chars. `wolfSSL_EVP_EncodeBlock()` doesn't do that by default */
static int
EVP_EncodeBlock(unsigned char *out, const unsigned char *in, int inLen)
{
    word32 ret = (word32)-1;
    WOLFSSL_ENTER("EVP_EncodeBlock");

    if (out == NULL || in == NULL)
        return WOLFSSL_FATAL_ERROR;

    if (Base64_Encode_NoNl(in, inLen, out, &ret) == 0)
        return (int)ret;
    else
        return WOLFSSL_FATAL_ERROR;
}



bool CalculatePublicKey(std::string* out, WOLFSSL_RSA* private_key) {
    uint8_t binary_key_data[ANDROID_PUBKEY_ENCODED_SIZE];
    if (!android_pubkey_encode(private_key, binary_key_data, sizeof(binary_key_data))) {
        std::cerr << "Failed to convert to public key";
        return false;
    }

    size_t expected_length;
    if (!EVP_EncodedLength(&expected_length, sizeof(binary_key_data))) {
        std::cerr << "Public key too large to base64 encode";
        return false;
    }

    out->resize(expected_length + 128);
    size_t actual_length = EVP_EncodeBlock((uint8_t*)out->data(), binary_key_data, sizeof(binary_key_data));
    auto test = out->size();
    if(test == actual_length)
        printf("\n");
    out->resize(actual_length);
    out->append(" ");
    out->append(GetLoginNameUTF8());
    out->append("@");
    out->append(GetHostNameUTF8());
    return true;
}
