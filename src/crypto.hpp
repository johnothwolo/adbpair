//
//  crypto.h
//  qrterm
//
//  Created by John Othwolo on 3/6/23.
//  Copyright © 2023 John Othwolo. All rights reserved.
//

#ifndef crypto_h
#define crypto_h

#define DEBUG_WOLFSSL
#define WOLFSSL_AES_256
#define HAVE_HKDF
#define OPENSSL_ALL
#define OPENSSL_EXTRA
#define HAVE_KEYING_MATERIAL

#define HAVE_ED25519
#define HAVE_ED25519_VERIFY // spake2
#define WOLFSSL_ED25519_STREAMING_VERIFY

#define WOLFSSL_BASE64_DECODE

#include <functional>
#include <signal.h>

#include <wolfssl/ssl.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/rsa.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/hmac.h>
#include <wolfssl/openssl/rand.h>
#include <wolfssl/openssl/buffer.h>
#include <wolfssl/openssl/ed25519.h>

#include <wolfssl/wolfcrypt/logging.h>

#include "spake25519.h"

namespace wolfssl
{
namespace _OpaqueUniquePtr {

template<typename T>
struct opaque_deleter {
    void operator()(T *it);
};

}

template<typename T>
using UniquePtr = std::unique_ptr<T, _OpaqueUniquePtr::opaque_deleter<T>>;

template<class _Tp, class... _Args>
inline _LIBCPP_INLINE_VISIBILITY
typename std::__unique_if<_Tp>::__unique_single
to_UniquePtr(_Args&&... __args)
{
    return UniquePtr<_Tp>(new _Tp(_VSTD::forward<_Args>(__args)...));
}

} // wolfssl

#endif /* crypto_h */
