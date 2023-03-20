////
////  sssl_cert.cpp
////  qrterm
////
////  Created by John Othwolo on 3/7/23.
////  Copyright © 2023 John Othwolo. All rights reserved.
////
//
//#include "sssl_cert.hpp"
//
//#include <vector>
//
//enum leaf_cert_and_privkey_result_t {
//    leaf_cert_and_privkey_error,
//    leaf_cert_and_privkey_ok,
//    leaf_cert_and_privkey_mismatch,
//};
//
//bool ssl_is_key_type_supported(int key_type) {
//  return key_type == EVP_PKEY_RSA || key_type == EVP_PKEY_EC;
//}
//
//// check_leaf_cert_and_privkey checks whether the certificate in |leaf_buffer|
//// and the private key in |privkey| are suitable and coherent. It returns
//// |leaf_cert_and_privkey_error| and pushes to the error queue if a problem is
//// found. If the certificate and private key are valid, but incoherent, it
//// returns |leaf_cert_and_privkey_mismatch|. Otherwise it returns
//// |leaf_cert_and_privkey_ok|.
//static enum leaf_cert_and_privkey_result_t
//check_leaf_cert_and_privkey(BIO *leaf_buffer, EVP_PKEY *privkey)
//{
//    EVP_PKEY *pubkeyRaw = nullptr;
//    wolfSSL_d2i_PUBKEY_bio(leaf_buffer, &pubkeyRaw);
//    wolfssl::UniquePtr<EVP_PKEY> pubkey = wolfssl::UniquePtr<EVP_PKEY>(pubkeyRaw);
//    if (!pubkey) {
////        OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
//        return leaf_cert_and_privkey_error;
//    }
//    
//    if (!ssl_is_key_type_supported(EVP_PKEY_id(pubkey.get()))) {
////        OPENSSL_PUT_ERROR(SSL, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
//        return leaf_cert_and_privkey_error;
//    }
//    
//    // An ECC certificate may be usable for ECDH or ECDSA. We only support ECDSA
//    // certificates, so sanity-check the key usage extension.
//    if (EVP_PKEY_id(pubkey.get()) == EVP_PKEY_EC &&
//        !ssl_cert_check_key_usage(&cert_cbs, key_usage_digital_signature)) {
////        OPENSSL_PUT_ERROR(SSL, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
//        return leaf_cert_and_privkey_error;
//    }
//    
//    if (privkey != NULL &&
//        // Sanity-check that the private key and the certificate match.
//        !ssl_compare_public_and_private_key(pubkey.get(), privkey)) {
//        ERR_clear_error();
//        return leaf_cert_and_privkey_mismatch;
//    }
//    
//    return leaf_cert_and_privkey_ok;
//}
//
//static int cert_set_chain_and_key(
//    CERT *cert, BIO *const *certs, size_t num_certs,
//    EVP_PKEY *privkey, const SSL_PRIVATE_KEY_METHOD *privkey_method) {
//  if (num_certs == 0 || (privkey == NULL && privkey_method == NULL)) {
////    OPENSSL_PUT_ERROR(SSL, ERR_R_PASSED_NULL_PARAMETER);
//    return 0;
//  }
//
//  if (privkey != NULL && privkey_method != NULL) {
////    OPENSSL_PUT_ERROR(SSL, SSL_R_CANNOT_HAVE_BOTH_PRIVKEY_AND_METHOD);
//    return 0;
//  }
//
//  switch (check_leaf_cert_and_privkey(certs[0], privkey)) {
//    case leaf_cert_and_privkey_error:
//      return 0;
//    case leaf_cert_and_privkey_mismatch:
////      OPENSSL_PUT_ERROR(SSL, SSL_R_CERTIFICATE_AND_PRIVATE_KEY_MISMATCH);
//      return 0;
//    case leaf_cert_and_privkey_ok:
//      break;
//  }
//
//  wolfssl::UniquePtr<STACK_OF(BIO)> certs_sk(wolfSSL_sk_new_null());
//  if (!certs_sk) {
//    return 0;
//  }
//
//  for (size_t i = 0; i < num_certs; i++) {
//      wolfSSL_EVP_PKEY_up_ref(certs[i]);
//      wolfSSL_sk_push_node(certs_sk.get(), certs[i])
//    if (!PushToStack(certs_sk.get(), 0)) {
//      return 0;
//    }
//  }
//
//  cert->privatekey = UpRef(privkey);
//  cert->key_method = privkey_method;
//
//  cert->chain = std::move(certs_sk);
//  return 1;
//}
