//
//  crypto.cpp
//  qrterm
//
//  Created by John Othwolo on 3/7/23.
//  Copyright © 2023 John Othwolo. All rights reserved.
//

#include "crypto.hpp"

namespace wolfssl {

// specialization
#define DECLARE_EXPLICIT_DESTRUCTOR(Type, TypeFreeFunction_Hook)    \
    template<> void                                                 \
    _OpaqueUniquePtr::opaque_deleter<Type>::operator()(Type *it) {  \
        TypeFreeFunction_Hook(it);                                  \
    }

DECLARE_EXPLICIT_DESTRUCTOR(WOLFSSL_STACK, wolfSSL_sk_free); // TODO: how to implement freenode?
DECLARE_EXPLICIT_DESTRUCTOR(X509, wolfSSL_X509_free);
DECLARE_EXPLICIT_DESTRUCTOR(X509_NAME, wolfSSL_X509_NAME_free);
DECLARE_EXPLICIT_DESTRUCTOR(X509_NAME_ENTRY, wolfSSL_X509_NAME_ENTRY_free);
DECLARE_EXPLICIT_DESTRUCTOR(X509_PUBKEY, wolfSSL_X509_PUBKEY_free);
DECLARE_EXPLICIT_DESTRUCTOR(X509_ALGOR, wolfSSL_X509_ALGOR_free);
//DECLARE_EXPLICIT_DESTRUCTOR(X509_CHAIN, wolfSSL_X509_CHAIN_free);
//DECLARE_EXPLICIT_DESTRUCTOR(X509_PKCS12, wolfSSL_X509_PKCS12_free);
DECLARE_EXPLICIT_DESTRUCTOR(X509_INFO, wolfSSL_X509_INFO_free);
DECLARE_EXPLICIT_DESTRUCTOR(WOLFSSL_BIO, wolfSSL_BIO_free);
DECLARE_EXPLICIT_DESTRUCTOR(WOLFSSL_CTX, wolfSSL_CTX_free);
DECLARE_EXPLICIT_DESTRUCTOR(WOLFSSL_EVP_PKEY, wolfSSL_EVP_PKEY_free);
DECLARE_EXPLICIT_DESTRUCTOR(WOLFSSL, wolfSSL_free);
DECLARE_EXPLICIT_DESTRUCTOR(WOLFSSL_EVP_CIPHER_CTX, wolfSSL_EVP_CIPHER_CTX_free);
DECLARE_EXPLICIT_DESTRUCTOR(SPAKE2_CTX, SPAKE2_CTX_free);
}

//DECLARE_EXPLICIT_DESTRUCTOR();
