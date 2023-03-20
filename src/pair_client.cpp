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

#include "crypto.hpp"
#include "rsa_2048_key.hpp"
#include "pair_client.hpp"
#include "adb_utils.hpp"
#include "sockets.hpp"
#include "pairing_connection.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <experimental/filesystem>

using namespace std::experimental;

struct ConnectionDeleter {
    void operator()(PairingConnectionCtx* p) { pairing_connection_destroy(p); }
};  // ConnectionDeleter

using PairingConnectionCtxPtr = std::unique_ptr<PairingConnectionCtx, ConnectionDeleter>;

class AdbKnownHosts {
    
    const char DC4 = 0x14;
    const char SYN = 0x16;
    const char NEWLINE = 0xa;
    const char RECORD_SEPARATOR[4] = { NEWLINE, SYN, NEWLINE, DC4 };
    
    bool                        file_was_created_;
    bool                        initialized_;
    unsigned                    added_; // support delete?
    bool                        commited_;
    std::vector<std::string>    hosts_;
    std::fstream                hosts_file_;
    const std::string           hosts_file_path_;
    unsigned                    og_num_hosts_;
    
    
    AdbKnownHosts(const std::string &known_hosts_path) :
    hosts_file_path_(known_hosts_path),
    initialized_(false), added_(0), og_num_hosts_(0),
    commited_(false)
    {
        if (!filesystem::exists(known_hosts_path))
            file_was_created_ = true;
        else
            file_was_created_ = false;
            
        hosts_file_ = std::fstream(hosts_file_path_, std::ios::binary | std::ios::in | std::ios::out);
        if(!hosts_file_.is_open())
            return;
        
        std::stringstream sstream;
        sstream << hosts_file_.rdbuf();
        std::string fileString = sstream.str();
        
        size_t pos = fileString.find(RECORD_SEPARATOR, 0);
        while(pos != std::string::npos)
        {
            size_t start = pos;
            size_t end = pos = fileString.find(RECORD_SEPARATOR, pos+1);
            
            if (pos == std::string::npos){
                hosts_.push_back(std::string(fileString.data() + sizeof(RECORD_SEPARATOR) + start));
            } else {
                hosts_.push_back(std::string(fileString.data() + sizeof(RECORD_SEPARATOR) + start,
                                              end - (start + sizeof(RECORD_SEPARATOR))));
            }
            og_num_hosts_++;
            
        }
        
        initialized_ = true;
        seek_to_end();
        
    }
    
    inline void seek_to_end(void)
    {
        hosts_file_.seekg(0, std::ios::end);
    }
    
    std::string new_record(const std::string &host)
    {
        std::stringstream ret;
        ret << RECORD_SEPARATOR;
        ret << host; // print host guid immediately after
        // don't print newline before or after the host guid
        return ret.str();
    }
    
public:
    
    static AdbKnownHosts* WithFile(const std::string &known_hosts_path)
    {
        AdbKnownHosts *ret = new AdbKnownHosts(known_hosts_path);
        assert(ret);
        if (ret->initialized_) {
            return ret;
        } else {
            delete ret;
            return nullptr;
        }
    }
    
    bool exists(const std::string host)
    {
        for (auto &iter : hosts_) {
            // FIXME: check string?
            if (iter == host) {
                return true;
            }
        }
        
        return false;
    }
    
    void addHost(const std::string host)
    {
        // insurance
        if (!exists(host)){
            hosts_.push_back(host);
            added_++;
            commited_ = false;
        }
    }
    
    bool commit(void) {

        // append the changes if any are made
        if (added_ && !commited_){
            
            // new hosts are at the end of the original list
            auto noobs = hosts_.begin() + og_num_hosts_;
            
            // loop through the new hosts and add'em to the file
            for (auto iter = noobs; iter != hosts_.end(); iter++) {
                auto record = new_record(*iter);
                hosts_file_.write(record.c_str(), record.size());
                
                // upgrade this known host from added to on-disk
                og_num_hosts_++; // update on-disk hosts number
                added_--; // decrement
            }

            commited_ = true;
        
            // seek to end
            seek_to_end();
            
            return hosts_.size() == og_num_hosts_;
            
        } else {
            // do nothing
            return true;
        }
    }
    
    ~AdbKnownHosts()
    {
        // impossible. our constrcutor is private. But just in case somebody modifies this class.
        if (!initialized_)
            return;
        
        // commit any changes.
        commit();
        
        // close file
        hosts_file_.close();
        
        if (file_was_created_){
            try {
                filesystem::permissions(hosts_file_path_, filesystem::perms::owner_all);
            } catch (std::exception& e) {
                std::cout << e.what() << std::endl;
            }
        }
    }
    
};

using AdbKnownHostsPtr = std::shared_ptr<AdbKnownHosts>;

struct PairInfo {
    int deviceFd;
    PeerInfo peerInfo;
    pthread_cond_t condVar = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    PairingConnectionCtxPtr context;
};

static_assert(sizeof(PeerInfo) == kMaxPeerInfoSize, "PeerInfo has weird size");

const char kBasicConstraints[] = "critical,CA:TRUE";
const char kKeyUsage[] = "critical,keyCertSign,cRLSign,digitalSignature";
const char kSubjectKeyIdentifier[] = "hash";
constexpr int kCertLifetimeSeconds = 10 * 365 * 24 * 60 * 60;

#pragma mark - Cert stuff

bool add_ext(WOLFSSL_X509* cert, int nid, const char* value) {
    size_t len = strlen(value) + 1;
    std::vector<char> mutableValue(value, value + len);
    WOLFSSL_X509V3_CTX context;

    wolfSSL_X509V3_set_ctx_nodb(&context);

    wolfSSL_X509V3_set_ctx(&context, cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ex = X509V3_EXT_nconf_nid(nullptr, &context, nid, mutableValue.data());
    if (!ex) {
        return false;
    }

    X509_add_ext(cert, ex, -1);
    wolfSSL_X509_EXTENSION_free(ex);
    return true;
}


WOLFSSL_X509* GenerateX509Certificate(WOLFSSL_EVP_PKEY* pkey)
{
    assert(pkey);
    
    WOLFSSL_X509* x509 = wolfSSL_X509_new();
    
    if (!x509) {
        std::cout << "Unable to allocate x509 container" << std::endl;
        return nullptr;
    }
    
    wolfSSL_X509_set_version(x509, 2);

    wolfSSL_ASN1_INTEGER_set(wolfSSL_X509_get_serialNumber(x509), 1);
    wolfSSL_X509_gmtime_adj(wolfSSL_X509_get_notBefore(x509), 0);
    wolfSSL_X509_gmtime_adj(wolfSSL_X509_get_notAfter(x509), kCertLifetimeSeconds);

    if (!wolfSSL_X509_set_pubkey(x509, pkey)) {
        std::cout << "Unable to set x509 public key" << std::endl;
        return nullptr;
    }

    WOLFSSL_X509_NAME* name = wolfSSL_X509_get_subject_name(x509);
    
    if (!name) {
        std::cout << "Unable to get x509 subject name" << std::endl;
        return nullptr;
    }
    
    wolfSSL_X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("US"), -1, -1, 0);
    wolfSSL_X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("Android"), -1, -1, 0);
    wolfSSL_X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("Adb"), -1, -1, 0);
    if (!wolfSSL_X509_set_issuer_name(x509, name)) {
        std::cout << "Unable to set x509 issuer name";
        return nullptr;
    }

    add_ext(x509, NID_basic_constraints, kBasicConstraints);
    add_ext(x509, NID_key_usage, kKeyUsage);
    add_ext(x509, NID_subject_key_identifier, kSubjectKeyIdentifier);

    int bytes = wolfSSL_X509_sign(x509, pkey, EVP_sha256());
    if (bytes <= 0) {
        std::cout << "Unable to sign x509 certificate" << std::endl;
        return nullptr;
    }

    return x509;
}

std::string X509ToPEMString(X509* x509) {
    BIO *bio = BIO_new(BIO_s_mem());
    int rc = PEM_write_bio_X509(bio, x509);
    if (rc != 1) {
        BIO_free(bio);
        std::cerr << "PEM_write_bio_X509 failed" << std::endl;
        return "";
    }

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    if (!mem || !mem->data || !mem->length) {
        BIO_free(bio);
        std::cerr << "BIO_get_mem_ptr failed" << std::endl;
        return "";
    }
    
    auto ret = std::string(mem->data, mem->length);
    
    BIO_free(bio);
    return ret;
}

std::string Key_ToPEMString(EVP_PKEY* pkey) {
    auto bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    int rc = PEM_write_bio_PKCS8PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    
    if (rc <= 0) {
        char error[1024];
        wolfSSL_ERR_error_string(wolfSSL_ERR_get_error(), error);
        BIO_free(bio);
        std::cerr << "PEM_write_bio_PKCS8PrivateKey failed: " << error << std::endl;
        return "";
    }

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    if (!mem || !mem->data || !mem->length) {
        BIO_free(bio);
        std::cerr << "BIO_get_mem_ptr failed" << std::endl;
        return "";
    }

    auto ret = std::string(mem->data, mem->length);
    
    BIO_free(bio);
    
    return ret;
}

#pragma mark Pair stuff

static std::string get_user_key_path() {
    std::string android_dir = adb_get_homedir_path() + OS_PATH_SEPARATOR + ".android";
    struct stat buf;
    if (stat(android_dir.c_str(), &buf) == -1) {
        if (mkdir(android_dir.c_str(), 0750) == -1) {
            std::cerr << "Cannot mkdir '" << android_dir << "'";
        }
    }
    
    return android_dir + OS_PATH_SEPARATOR + "adbkey";
}

static void fake_RSA_free(WOLFSSL_RSA* rsa)
{
    WOLFSSL_MSG("fake deleter invoked\n");
}

static std::shared_ptr<RSA> read_key_file(const std::string& file, EVP_PKEY**_pkey = nullptr) {
    std::unique_ptr<FILE, decltype(&fclose)> fp(fopen(file.c_str(), "r"), fclose);
    std::shared_ptr<RSA> ret = nullptr;
    RSA *key;
    BIO *bio;
    EVP_PKEY *pkey = nullptr;
    char* name = nullptr;
    char* header = nullptr;
    uint8_t* data = nullptr;
    long data_len = 0;
    
    if (!fp) {
        std::cerr << "Failed to open '" << file << "'";
        return nullptr;
    }
    
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    
    assert(wolfSSL_BIO_set_fp(bio, fp.get(), BIO_CLOSE) == SSL_SUCCESS);
    
    if (!PEM_read_bio(bio, &name, &header, &data, &data_len)) {
        std::cerr << "Failed to read certificate";
        wolfSSL_BIO_free(bio);
        return nullptr;
    }
    
    auto p = data;
    d2i_AutoPrivateKey(&pkey, (const uint8_t**)&p, data_len);
    if (!pkey) {
        wolfSSL_BIO_free(bio);
        return nullptr;
    }
    
    key = pkey->rsa;
    
    if (_pkey != nullptr){
        *_pkey = pkey;
        ret = std::shared_ptr<RSA>(key, fake_RSA_free); // pointer is managed by EVP_PKEY
    } else {
        ret = std::shared_ptr<RSA>(key, RSA_free); // pointer is managed by us...
        pkey->rsa = nullptr;
        EVP_PKEY_free(pkey);
    }
    
    
    if (key == nullptr) {
        std::cerr << "Failed to read key from '" << file << "'";
        ERR_print_errors_fp(stderr);
        RSA_free(key);
        wolfSSL_BIO_free(bio);
        return nullptr;
    }
    
    wolfSSL_BIO_free(bio);
    return ret;
}

EVP_PKEY* adb_auth_get_user_privkey() {
    EVP_PKEY* pkey;
    std::shared_ptr<RSA> rsa_privkey;
    std::string path;
    
    path = get_user_key_path();
    if (path.empty()) {
        std::cerr << "Error getting user key filename" << std::endl;
        return nullptr;
    }

    rsa_privkey = read_key_file(path, &pkey);
    if (!rsa_privkey || !pkey) {
        std::cerr << "Failed to allocate key" << std::endl;
        return nullptr;
    }

    return pkey;
}

static std::string get_user_known_hosts_path() {
    return adb_get_android_dir_path() + OS_PATH_SEPARATOR + "adb_known_hosts.pb";
}

AdbKnownHostsPtr load_known_hosts_from_file(const std::string& path) {
    // Check for file existence.
    struct stat buf;
    if (stat(path.c_str(), &buf) == -1) {
        std::cout << "Known hosts file [" << path << "] does not exist..." << std::endl;
        return nullptr;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Unable to open [" << path << "]." << std::endl;
        return nullptr;
    }
    
    return AdbKnownHostsPtr(AdbKnownHosts::WithFile(path));
}

bool adb_wifi_is_known_host(const std::string& host) {
    std::string path = get_user_known_hosts_path();
    if (path.empty()) {
        std::cerr << "Error getting user known hosts filename" << std::endl;
        return false;
    }

    AdbKnownHostsPtr known_hosts = load_known_hosts_from_file(path);
    
    if (!known_hosts){
        return false;
    }

    return known_hosts->exists(host);
}

static bool pubkey_from_privkey(std::string* out, const std::string& path) {
    std::shared_ptr<RSA> privkey = read_key_file(path);
    if (!privkey) {
        return false;
    }
    return CalculatePublicKey(out, privkey.get());
}

std::string adb_auth_get_userkey() {
    std::string path = get_user_key_path();
    if (path.empty()) {
        std::cerr << "Error getting user key filename" << std::endl;
        return "";
    }

    std::string result;
    if (!pubkey_from_privkey(&result, path)) {
        return "";
    }
    return result;
}

static bool write_known_host_to_file(std::string& known_host) {
    std::string path = get_user_known_hosts_path();
    if (path.empty()) {
        std::cerr << "Error getting user known hosts filename" << std::endl;
        return false;
    }

    AdbKnownHostsPtr known_hosts = load_known_hosts_from_file(path);
    
    known_hosts->addHost(known_host); // add host guid
    
    if (!known_hosts->commit()) {
        std::cerr << "Unable to write out adb_knowns_hosts" << std::endl;
        return false;
    }
    
    return true;
}

static std::vector<uint8_t> stringToUint8(const std::string& str) {
    auto* p8 = reinterpret_cast<const uint8_t*>(str.data());
    return std::vector<uint8_t>(p8, p8 + str.length());
}

int network_connect(const std::string& host, int port, int type, int timeout, std::string* error) {
    int getaddrinfo_error = 0;
    int fd = socket_network_client_timeout(host.c_str(), port, type, timeout, &getaddrinfo_error);
    if (fd != -1) {
        return fd;
    }
    if (getaddrinfo_error != 0) {
        *error = StringPrintf("failed to resolve host: '%s': %s", host.c_str(), gai_strerror(getaddrinfo_error));
        std::cerr << *error;
    } else {
        *error = StringPrintf("failed to connect to '%s:%d': %s", host.c_str(), port, strerror(errno));
        std::cerr << *error;
    }
    return -1;
}

// static
void PairingClient_OnPairingResult(const PeerInfo* peer_info, int /* fd */, void* opaque) {
    auto pinfo = (PairInfo *)opaque;
    pthread_mutex_lock(&pinfo->mutex);
    pinfo->peerInfo = *peer_info;
    pthread_mutex_unlock(&pinfo->mutex);
    pthread_cond_signal(&pinfo->condVar);
    printf("Pairing complete with result: %d\n", 0);
}

bool
PairingClient_Start(PairInfo *pinfo, const std::string& ip_addr, unsigned short port,
                    const std::vector<uint8_t>& pswd, const std::vector<uint8_t>& cert,
                    const std::vector<uint8_t>& priv_key)
{
    int off = 1;
    std::string err;
    const int timeout = 10;  // seconds
    
    assert(port > 0 && port <= 65535);
    
    pinfo->deviceFd = network_connect(ip_addr, port, SOCK_STREAM, timeout, &err);
    if (pinfo->deviceFd == -1) {
        std::cerr << "Failed to start pairing connection client [" << err << "]" << std::endl;
        return false;
    }
    setsockopt(pinfo->deviceFd, IPPROTO_TCP, TCP_NODELAY, &off, sizeof(off));
    
    pinfo->context = PairingConnectionCtxPtr(pairing_connection_client_new(pswd.data(), pswd.size(), &pinfo->peerInfo,
                                  cert.data(), cert.size(), priv_key.data(), priv_key.size()));
    
    
    if (!pairing_connection_start(pinfo->context.get(), pinfo->deviceFd,
                                  PairingClient_OnPairingResult, pinfo)) {
        std::cerr << "PairingClient failed to start the PairingConnection" << std::endl;
        return false;
    }
    
    return true;
}

int adb_wifi_pair_device(const std::string& ip_addr, unsigned short port, const std::string& password)
{
    std::string parsed_host;
    std::string err;
    
    printf("Connecting to -> %s:%d\n", ip_addr.c_str(), port);
    
    wolfSSL_Init();
    
    if (port <= 0 || port > 65535) {
        std::cerr << "Invalid port while parsing address [" + ip_addr + "]" << std::endl;
        return -1;
    }

    auto priv_key = adb_auth_get_user_privkey();
    auto x509_cert = GenerateX509Certificate(priv_key);
    if (!x509_cert) {
        std::cerr << "Unable to create X509 certificate for pairing" << std::endl;
        return (-1);
    }
    
    auto cert_str = X509ToPEMString(x509_cert);
    auto priv_str = Key_ToPEMString(priv_key);
    
    // Send our public key on pairing success
    PeerInfo system_info = { .type = ADB_RSA_PUB_KEY };
    std::string public_key = adb_auth_get_userkey();
    assert(public_key.size() <= sizeof(system_info.data) - 1);  // -1 for null byte
    memcpy(system_info.data, public_key.data(), public_key.size());
    
    auto pswd8 = stringToUint8(password);
    auto cert8 = stringToUint8(cert_str);
    auto priv8 = stringToUint8(priv_str);
    
    std::string response;

    PairInfo pinfo = {
        .deviceFd   = -1,
        .peerInfo   = system_info,
        .condVar    = PTHREAD_COND_INITIALIZER,
        .mutex      = PTHREAD_MUTEX_INITIALIZER,
        .context    = nullptr,
    };
    
    if (!PairingClient_Start(&pinfo, ip_addr, port, pswd8, cert8, priv8)) {
        std::cerr << "Failed: Unable to start pairing client." << std::endl;
        return -1;
    }
    
    pthread_cond_wait(&pinfo.condVar, &pinfo.mutex);

    if (pinfo.peerInfo.type != ADB_DEVICE_GUID) {
        response = "Failed: Successfully paired but server returned unknown response=";
        response += pinfo.peerInfo.type;
        return -1;
    }
    std::string device_guid = reinterpret_cast<const char*>(pinfo.peerInfo.data);
    response = "Successfully paired to " + ip_addr + ":" + std::to_string(port) + " [guid=" + device_guid + "]";

    // Write to adb_known_hosts
    write_known_host_to_file(device_guid);

    std::cout << response << std::endl;
    
    auto fd = network_connect(ip_addr, port, SOCK_STREAM, 0, &response);
    
    close(fd);
    
    // pairing context destorys itself

    exit(0);
    __builtin_unreachable();
}





