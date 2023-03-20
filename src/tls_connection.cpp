/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "tls_connection.hpp"

#include <limits.h>

#include <algorithm>
#include <iostream>
#include <vector>
#include <string>

typedef std::vector<unsigned char> CRYPTO_BUFFER;


namespace tls {

namespace {

static constexpr char kExportedKeyLabel[] = "adb-label";

class TlsConnectionImpl : public TlsConnection {
  public:
    explicit
    TlsConnectionImpl(std::string_view cert, std::string_view priv_key, borrowed_fd fd);
    
    ~TlsConnectionImpl() override;

    bool AddTrustedCertificate(std::string_view cert) override;
    void SetWolfSSLVerifyCallback(WolfSSLVerifyCb cb) override;
    void SetCertVerifyCallback(CertVerifyCb cb) override;
    void SetCertificateCallback(SetCertCb cb) override;
    
    std::vector<uint8_t> ExportKeyingMaterial(size_t length) override;
    void EnableClientPostHandshakeCheck(bool enable) override;
    TlsError DoHandshake() override;
    std::vector<uint8_t> ReadFully(size_t size) override;
    bool ReadFully(void* buf, size_t size) override;
    bool WriteFully(std::string_view data) override;

    static wolfssl::UniquePtr<EVP_PKEY> EvpPkeyFromPEM(std::string_view pem);
    static std::unique_ptr<CRYPTO_BUFFER> BufferFromPEM(std::string_view pem);

  private:
    static int SSLSetWolfSSLVerifyCb(X509_STORE_CTX* ctx, void* opaque, int code);
    static int SSLSetCertVerifyCb(X509_STORE_CTX* ctx, void* opaque);
    static int SSLSetCertCb(SSL* ssl, void* opaque);

    static wolfssl::UniquePtr<X509> X509FromBuffer(std::unique_ptr<CRYPTO_BUFFER> buffer);
    static const char* SSLErrorString();
    void Invalidate();
    TlsError GetFailureReason(int err);
    const char* RoleToString() { return kClientRoleStr; }

    wolfssl::UniquePtr<EVP_PKEY> priv_key_;
    std::unique_ptr<CRYPTO_BUFFER> cert_;

    wolfssl::UniquePtr<STACK_OF(X509_NAME)> ca_list_;
    wolfssl::UniquePtr<SSL_CTX> ssl_ctx_;
    wolfssl::UniquePtr<SSL> ssl_;
    std::vector<wolfssl::UniquePtr<X509>> known_certificates_;
    bool client_verify_post_handshake_ = false;

    // MARK:WOLFSSL: wolfssl-specific verify Callback
    WolfSSLVerifyCb wolfssl_verify_cb_ = nullptr;
    CertVerifyCb cert_verify_cb_;
    SetCertCb set_cert_cb_;
    borrowed_fd fd_;
    const char *kClientRoleStr = (const char*)"[client]: ";
};  // TlsConnectionImpl

TlsConnectionImpl::TlsConnectionImpl(std::string_view cert, std::string_view priv_key, borrowed_fd fd) : fd_(fd)
{
    assert(!cert.empty() && !priv_key.empty());
    std::cerr << RoleToString() << "Initializing adbwifi TlsConnection" << std::endl;
    cert_ = BufferFromPEM(cert);
    assert(cert_);
    priv_key_ = EvpPkeyFromPEM(priv_key);
    assert(priv_key_);
}

TlsConnectionImpl::~TlsConnectionImpl() {
    // shutdown the SSL connection
    if (ssl_ != nullptr) {
        wolfSSL_FreeArrays(ssl_.get()); // MARK:WOLFSSL: free handshake arrays
        SSL_shutdown(ssl_.get());
    }
}

// static
const char* TlsConnectionImpl::SSLErrorString() {
    auto sslerr = ERR_peek_last_error();
    return ERR_reason_error_string(sslerr);
}

// static
wolfssl::UniquePtr<EVP_PKEY> TlsConnectionImpl::EvpPkeyFromPEM(std::string_view pem) {
    wolfssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem.data(),(int) pem.size()));
    return wolfssl::UniquePtr<EVP_PKEY>(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
}

// static
std::unique_ptr<CRYPTO_BUFFER> TlsConnectionImpl::BufferFromPEM(std::string_view pem) {
    // WOLFSSL: wolfSSL requires the PEM header, don't remove it.
    return std::unique_ptr<CRYPTO_BUFFER>(new CRYPTO_BUFFER(pem.data(), pem.data() + pem.size()));
}

// static
wolfssl::UniquePtr<X509> TlsConnectionImpl::X509FromBuffer(std::unique_ptr<CRYPTO_BUFFER> buffer) {
    X509 *ret = nullptr;
    const uint8_t *inp;
    
    if (!buffer) {
        return nullptr;
    }
    
    if (buffer->size() > LONG_MAX) {
        return NULL;
    }
    
    inp = buffer->data();
    
    if (wolfSSL_d2i_X509(&ret, &inp, (int)buffer->size()) == nullptr || inp != buffer->data() + buffer->size()) {
      X509_free(ret);
      return NULL;
    }

    return wolfssl::UniquePtr<X509>(ret);
}

// static
int TlsConnectionImpl::SSLSetWolfSSLVerifyCb(X509_STORE_CTX* ctx, void* opaque, int code) {
    auto* p = reinterpret_cast<TlsConnectionImpl*>(opaque);
    return p->wolfssl_verify_cb_(code, ctx);
}

// static
int TlsConnectionImpl::SSLSetCertVerifyCb(X509_STORE_CTX* ctx, void* opaque) {
    auto* p = reinterpret_cast<TlsConnectionImpl*>(opaque);
    return p->cert_verify_cb_(ctx);
}


// static
int TlsConnectionImpl::SSLSetCertCb(SSL* ssl, void* opaque) {
    auto* p = reinterpret_cast<TlsConnectionImpl*>(opaque);
    return p->set_cert_cb_(ssl);
}

bool TlsConnectionImpl::AddTrustedCertificate(std::string_view cert) {
    // Create X509 buffer from the certificate string
    auto buf = X509FromBuffer(BufferFromPEM(cert));
    if (buf == nullptr) {
        std::cerr << RoleToString() << "Failed to create a X509 buffer for the certificate." << std::endl;
        return false;
    }
    known_certificates_.push_back(std::move(buf));
    return true;
}

// MARK:WOLFSSL: for some reason there are 2 callbacks. ADB seems to expect one callback from openssl.
void TlsConnectionImpl::SetWolfSSLVerifyCallback(WolfSSLVerifyCb cb) {
    wolfssl_verify_cb_ = cb;
}

void TlsConnectionImpl::SetCertVerifyCallback(CertVerifyCb cb) {
    cert_verify_cb_ = cb;
}

void TlsConnectionImpl::SetCertificateCallback(SetCertCb cb) {
    set_cert_cb_ = cb;
}


std::vector<uint8_t> TlsConnectionImpl::ExportKeyingMaterial(size_t length) {
    if (ssl_.get() == nullptr) {
        return {};
    }

    wolfSSL_Debugging_ON();
    std::vector<uint8_t> out(length);
    int ret = SSL_export_keying_material(ssl_.get(), out.data(), out.size(), kExportedKeyLabel,
                                                    sizeof(kExportedKeyLabel), nullptr, 0, false);
    
    wolfSSL_FreeArrays(ssl_.get());
    wolfSSL_Debugging_OFF();
    
    if (ret != WOLFSSL_SUCCESS) {
        std::cerr << RoleToString()
        << "Unable to generate key material [" << SSLErrorString() << "]" << std::endl;
        
        raise(SIGTRAP);
        return {};
    }
    return out;
}

void TlsConnectionImpl::EnableClientPostHandshakeCheck(bool enable) {
    client_verify_post_handshake_ = enable;
}

TlsConnection::TlsError TlsConnectionImpl::GetFailureReason(int err) {
    switch (ERR_GET_REASON(err)) {
        case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:
//        case SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE:
//        case SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED:
//        case SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED:
        case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:
//        case SSL_R_TLSV1_ALERT_ACCESS_DENIED:
        case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
//        case SSL_R_TLSV1_CERTIFICATE_REQUIRED:
            return TlsError::PeerRejectedCertificate;
        case SSL_R_CERTIFICATE_VERIFY_FAILED:
            return TlsError::CertificateRejected;
        default:
            return TlsError::UnknownFailure;
    }
}

TlsConnection::TlsError TlsConnectionImpl::DoHandshake() {
    int ret = 0;
    
    std::cerr << RoleToString() << "Starting adbwifi tls handshake" << std::endl;
    ssl_ctx_.reset(SSL_CTX_new(TLS_method()));
    // TODO: Remove set_max_proto_version() once external/boringssl is updated
    // past
    // https://boringssl.googlesource.com/boringssl/+/58d56f4c59969a23e5f52014e2651c76fea2f877
    if (ssl_ctx_.get() == nullptr ||
        !SSL_CTX_set_min_proto_version(ssl_ctx_.get(), TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(ssl_ctx_.get(), TLS1_3_VERSION)) {
        std::cerr << RoleToString() << "Failed to create SSL context" << std::endl;
        return TlsError::UnknownFailure;
    }

    // Register user-supplied known certificates
    for (auto const& cert : known_certificates_) {
        if (X509_STORE_add_cert(SSL_CTX_get_cert_store(ssl_ctx_.get()), cert.get()) == 0) {
            std::cerr << RoleToString() << "Unable to add certificates into the X509_STORE" << std::endl;
            return TlsError::UnknownFailure;
        }
    }

    // Custom certificate verification
    if (cert_verify_cb_) {
        SSL_CTX_set_cert_verify_callback(ssl_ctx_.get(), SSLSetCertVerifyCb, this);
    }

    // set select certificate callback, if any.
    if (set_cert_cb_) {
        SSL_CTX_set_cert_cb(ssl_ctx_.get(), SSLSetCertCb, this);
    }

    // Server-allowed client CA list
    if (ca_list_ != nullptr) {
        wolfssl::UniquePtr<STACK_OF(X509_NAME)> names(SSL_dup_CA_list(ca_list_.get()));
        SSL_CTX_set_client_CA_list(ssl_ctx_.get(), names.release());
    }

    // Register our certificate and private key.
    std::vector<char> cert_chain(cert_->begin(), cert_->end());

    if (!wolfSSL_CTX_use_PrivateKey(ssl_ctx_.get(), priv_key_.get()))
    {
        std::cerr << RoleToString()
                  << "Unable to register the certificate private key [" << SSLErrorString() << "]" << std::endl;
        Invalidate();
        return TlsError::UnknownFailure;
    }

    ret = wolfSSL_CTX_use_certificate_chain_buffer(ssl_ctx_.get(), (uint8_t*)cert_chain.data(), (long)cert_chain.size());
    
    if (ret != SSL_SUCCESS) {
        std::cerr << RoleToString()
                  << "Unable to register the certificate chain file [" << SSLErrorString() << "]" << std::endl;
        Invalidate();
        return TlsError::UnknownFailure;
    }
    
    // MARK:WOLFSSL: set verfiy callback. wolfSSL needs special treatment smh.
    SSL_CTX_set_verify(ssl_ctx_.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, wolfssl_verify_cb_);

    // Okay! Let's try to do the handshake!
    ssl_.reset(SSL_new(ssl_ctx_.get()));
    if (!SSL_set_fd(ssl_.get(), fd_)) {
        std::cerr << RoleToString() << "SSL_set_fd failed. [" << SSLErrorString() << "]" << std::endl;
        return TlsError::UnknownFailure;
    }

    SSL_set_connect_state(ssl_.get());
    
    // MARK:WOLFSSL: save arrays for calls like `SSL_export_keying_material()`
    wolfSSL_KeepArrays(ssl_.get());
    
    if (SSL_do_handshake(ssl_.get()) != 1) {
        std::cerr << RoleToString() << "Handshake failed in SSL_accept/SSL_connect ["
                   << SSLErrorString() << "]" << std::endl;
        auto sslerr = ERR_get_error();
        Invalidate();
        return GetFailureReason((int)sslerr);
    }

    if (client_verify_post_handshake_) {
        uint8_t check;
        // Try to peek one byte for any failures. This assumes on success that
        // the server actually sends something.
        if (SSL_peek(ssl_.get(), &check, 1) <= 0) {
            std::cerr << RoleToString() << "Post-handshake SSL_peek failed [" << SSLErrorString()
                       << "]" << std::endl;
            auto sslerr = ERR_get_error();
            Invalidate();
            return GetFailureReason((int)sslerr);
        }
    }

    std::cerr << RoleToString() << "Handshake succeeded." << std::endl;
    return TlsError::Success;
}

void TlsConnectionImpl::Invalidate() {
    ssl_.reset();
    ssl_ctx_.reset();
}

std::vector<uint8_t> TlsConnectionImpl::ReadFully(size_t size) {
    std::vector<uint8_t> buf(size);
    if (!ReadFully(buf.data(), buf.size())) {
        return {};
    }

    return buf;
}

bool TlsConnectionImpl::ReadFully(void* buf, size_t size) {
    assert(size > 0U);
    if (!ssl_) {
        std::cerr << RoleToString() << "Tried to read on a null SSL connection" << std::endl;
        return false;
    }

    size_t offset = 0;
    uint8_t* p8 = reinterpret_cast<uint8_t*>(buf);
    while (size > 0) {
        int bytes_read = SSL_read(ssl_.get(), p8 + offset, (int)std::min(static_cast<size_t>(INT_MAX), size));
        if (bytes_read <= 0) {
            std::cerr << RoleToString() << "SSL_read failed [" << SSLErrorString() << "]" << std::endl;
            return false;
        }
        size -= bytes_read;
        offset += bytes_read;
    }
    return true;
}

bool TlsConnectionImpl::WriteFully(std::string_view data) {
    assert(!data.empty());
    if (!ssl_) {
        std::cerr << RoleToString() << "Tried to read on a null SSL connection";
        return false;
    }

    while (!data.empty()) {
        int bytes_out = SSL_write(ssl_.get(), data.data(), (int)std::min(static_cast<size_t>(INT_MAX), data.size()));
        if (bytes_out <= 0) {
            std::cerr << RoleToString() << "SSL_write failed [" << SSLErrorString() << "]" << std::endl;
            return false;
        }
        data = data.substr(bytes_out);
    }
    return true;
}
}  // namespace

// static

std::unique_ptr<TlsConnection> TlsConnection::Create(std::string_view cert,
                                                std::string_view priv_key, borrowed_fd fd) {
    assert(!cert.empty());
    assert(!priv_key.empty());

    return std::make_unique<TlsConnectionImpl>(cert, priv_key, fd);
}

// static
bool TlsConnection::SetCertAndKey(SSL* ssl, std::string_view cert, std::string_view priv_key) {
    assert(ssl);
    // Note: declaring these in local scope is okay because
    // SSL_set_chain_and_key will increase the refcount (bssl::UpRef).
    auto x509_cert = TlsConnectionImpl::BufferFromPEM(cert);
    auto evp_pkey = TlsConnectionImpl::EvpPkeyFromPEM(priv_key);
    if (x509_cert == nullptr || evp_pkey == nullptr) {
        return false;
    }

    std::vector<char*> cert_chain = { (char*)x509_cert->data(), };

    if (!wolfSSL_use_certificate_chain_buffer(ssl, (uint8_t*)cert_chain.data(), (long)cert_chain.size()))
    {
        std::cerr << "SSL_use_certificate_chain_buffer() failed" << std::endl;
        return false;
    }
    
    if (!wolfSSL_use_PrivateKey(ssl, evp_pkey.get()))
    {
        std::cerr << "SSL_use_PrivateKey() failed" << std::endl;
        return false;
    }
    return true;
}

}  // namespace tls
