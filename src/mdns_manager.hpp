//
//  mdns_client.hpp
//  qrterm
//
//  Created by John Othwolo on 3/4/23.
//  Copyright © 2023 John Othwolo. All rights reserved.
//

#ifndef mdns_client_hpp
#define mdns_client_hpp

#include <cstdlib>
#include <string>

#include "dnssd/dns_sd.h"

int ParseVersionFromTxtRecord(uint16_t txt_len, const unsigned char* txt_record);

class AdbMdnsManager {
public:
    AdbMdnsManager(std::string hostString, std::string passcode) :
    mainQueue(dispatch_get_main_queue()),
    hostString(hostString),
    passcode(passcode),
    port(0)
    {
    }
    
    static void on_service_browsed(DNSServiceRef sdRef, DNSServiceFlags flags,
                                   uint32_t interfaceIndex, DNSServiceErrorType errorCode,
                                   const char *serviceName, const char *regtype,
                                   const char *replyDomain, void *context);
    
    static void register_resolved_mdns_service(DNSServiceRef sdref, DNSServiceFlags flags,
                                               uint32_t interface_index, DNSServiceErrorType error_code,
                                               const char* fullname, const char* host_target,
                                               uint16_t port, uint16_t txt_len,
                                               const unsigned char* txt_record, void* context);
    
    static void register_service_ip(DNSServiceRef sdref, DNSServiceFlags flags,
                                    uint32_t interface_index, DNSServiceErrorType error_code,
                                    const char* hostname, const sockaddr* address, uint32_t ttl,
                                    void* context);
    
public:
    void SetServiceRefDispatchQueue(DNSServiceRef sdref);
    void DestroyManager(void);
    
public:
    DNSServiceRef browseRef = nullptr;
    DNSServiceRef resolveRef = nullptr;
    DNSServiceRef addrInfoRef = nullptr;
    
public:
    const dispatch_queue_main_t mainQueue;
    const std::string hostString;
    const std::string passcode;
    int port;
};

#endif /* mdns_client_hpp */
