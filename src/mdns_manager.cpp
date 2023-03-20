//
//  main.cpp
//  qrterm
//
//  Created by John Othwolo on 3/2/23.
//  Copyright © 2023 John Othwolo. All rights reserved.
//

#include <vector>

__BEGIN_DECLS
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
__END_DECLS

#include "pair_client.hpp"
#include "mdns_manager.hpp"


#define debug(fmt...) printf("%s():", __func__); printf(fmt); printf("\n");

#define ADB_SERVICE_NAME "_adb-tls-pairing._tcp.local"

// FIXME: fix the instances and frees in the callback functions...

void AdbMdnsManager::on_service_browsed(DNSServiceRef sdref, DNSServiceFlags flags,
                                      uint32_t interface_index, DNSServiceErrorType error_code,
                                      const char* service_name, const char* regtype,
                                      const char* domain, void* context)
{
    AdbMdnsManager *manager = (AdbMdnsManager *)context;
    
    if (error_code != kDNSServiceErr_NoError) {
        debug("Got error %d during mDNS browse.", error_code);
        manager->DestroyManager();
        return;
    }
    
    if (flags & kDNSServiceFlagsAdd) {
        DNSServiceErrorType ret = DNSServiceResolve(&manager->resolveRef, 0, interface_index,
                                                    service_name, regtype, domain,
                                                    AdbMdnsManager::register_resolved_mdns_service, context);
        
        manager->SetServiceRefDispatchQueue(manager->resolveRef);
        
        debug("DNSServiceResolve found new service_name=[%s] regtype=[%s] domain=[%s] : %d",
          service_name, regtype, domain, ret);
        
    } else {
        debug("Discover lost service_name=[%s] regtype=[%s] domain=[%s]", service_name, regtype, domain);
        manager->DestroyManager();
        return;
    }
}


void AdbMdnsManager::register_resolved_mdns_service(DNSServiceRef sdref, DNSServiceFlags flags,
                                                  uint32_t interface_index, DNSServiceErrorType error_code,
                                                  const char* fullname, const char* host_target,
                                                  uint16_t port, uint16_t txt_len,
                                                  const unsigned char* txt_record, void* context)
{
    AdbMdnsManager *manager = (AdbMdnsManager *)context;
    char local_fullname[1024] = {0}, *str = 0;
    
    debug("Resolved a service.");

    if (error_code != kDNSServiceErr_NoError) {
        debug("Got error %d resolving service.", error_code);
        manager->DestroyManager();
        return;
    }
    
    if (!fullname) {
        debug("mDNSResponder returned a NULL string.");
        manager->DestroyManager();
        return;
    }
    
    strcpy(local_fullname, fullname);
    str = strtok(local_fullname, ".");
    
    // this makes sure we're connecting to a service advertising our unique hostname
    if (strcmp(local_fullname, manager->hostString.c_str()) != 0) {
        debug("%s is not the service we're looking for.", local_fullname);
        // if we don't match the service, deallocate the dnsref for this service
        manager->DestroyManager();
        return;
    }
    
    manager->port = ntohs(port);
    
    // TODO: Reject certain combinations of invalid or mismatched client and
    // service versions here before creating anything.
    // At the moment, there is nothing to reject, so accept everything
    // as an optimistic default.
    auto service_version = ParseVersionFromTxtRecord(txt_len, txt_record);

    /* TODO: We should be able to get IPv6 support by adding
     * kDNSServiceProtocol_IPv6 to the flags below. However, when we do
     * this, we get served link-local addresses that are usually useless to
     * connect to. What's more, we seem to /only/ get those and nothing else.
     * If we want IPv6 in the future we'll have to figure out why.
     */
    DNSServiceErrorType ret = DNSServiceGetAddrInfo(&manager->addrInfoRef, 0, interface_index, kDNSServiceProtocol_IPv4,
                                                    host_target, AdbMdnsManager::register_service_ip, context);

    if (ret == kDNSServiceErr_NoError) {
        debug("Got %d from DNSServiceGetAddrInfo.", ret);
    } else {
        debug("DNSServiceGetAddrInfo(sdref=%p, host_target=%s) returned %d", sdref, host_target, ret);
        manager->DestroyManager();
        return;
    }

    debug("Client version: %d Service version: %d\n", 1, service_version);
    
    manager->SetServiceRefDispatchQueue(manager->addrInfoRef);

//    if (flags) { /* Only ever equals MoreComing or 0 */
//        debug("releasing discovered service");
//    }
}

void AdbMdnsManager::register_service_ip(DNSServiceRef sdref, DNSServiceFlags flags,
                                         uint32_t interface_index, DNSServiceErrorType error_code,
                                         const char* hostname, const sockaddr* address, uint32_t ttl,
                                         void* context)
{
    debug("sdref=%p flags=0x%08x error_code=%u ttl=%u", sdref, flags, error_code, ttl);
    // Only resolve the address once. If the address or port changes, we'll just get another
    // registration.
    AdbMdnsManager *manager = (AdbMdnsManager *)context;

    if (error_code != kDNSServiceErr_NoError) {
        debug("Got error while looking up ip_addr [%u]", error_code);
        DNSServiceRefDeallocate(sdref);
        return;
    }

    if (flags & kDNSServiceFlagsAdd) {
        auto saddr = reinterpret_cast<const sockaddr_in*>(address);

        std::string response;
        std::string host;
        std::string pass;
        
        
        if (address->sa_family == AF_INET) {
            host = inet_ntoa(saddr->sin_addr);
        } else if (address->sa_family == AF_INET6) {
            debug("IPv6 adresses aren't yet supported");
            raise(SIGSTOP);
            // FIXME: inet_ntoa() doesn't support IPv6, so update use inet_ntop() later...
        } else {  // Should be impossible
            debug("mDNS resolved non-IP address.");
            DNSServiceRefDeallocate(sdref);
            return;
        }
        
        debug("Resolved IP address for [%s]. Attempting to connect to Device.", hostname);
        
        adb_wifi_pair_device(host, manager->port, manager->passcode);
        
    } else {
        debug("Device disappeared")
        DNSServiceRefDeallocate(sdref);
    }
}


void AdbMdnsManager::SetServiceRefDispatchQueue(DNSServiceRef sdref)
{
    if (sdref) {
        DNSServiceSetDispatchQueue(sdref, mainQueue);
    } else {
        debug("sdref is unexpectedly NULL");
    }
}

void AdbMdnsManager::DestroyManager(void)
{
    if (browseRef) {
        DNSServiceRefDeallocate(browseRef);
    }
    
    if (resolveRef) {
        DNSServiceRefDeallocate(resolveRef);
    }
    
    if (addrInfoRef) {
        DNSServiceRefDeallocate(addrInfoRef);
    }
}


// Returns the version the device wanted to advertise,
// or -1 if parsing fails.
int ParseVersionFromTxtRecord(uint16_t txt_len, const unsigned char* txt_record)
{
    if (!txt_len) return -1;
    if (!txt_record) return -1;

    // https://tools.ietf.org/html/rfc6763
    // """
    // 6.1.  General Format Rules for DNS TXT Records
    //
    // A DNS TXT record can be up to 65535 (0xFFFF) bytes long.  The total
    // length is indicated by the length given in the resource record header
    // in the DNS message.  There is no way to tell directly from the data
    // alone how long it is (e.g., there is no length count at the start, or
    // terminating NULL byte at the end).
    // """

    // Let's trust the TXT record's length byte
    // Worst case, it wastes 255 bytes
    std::vector<char> record_str(txt_len + 1, '\0');
    char* str = record_str.data();

    memcpy(str, txt_record + 1 /* skip the length byte */, txt_len);

    // Check if it's the version key
    static const char* version_key = "v=";
    size_t version_key_len = strlen(version_key);

    if (strncmp(version_key, str, version_key_len)) return -1;

    auto value_start = str + version_key_len;

    long parsed_number = strtol(value_start, 0, 10);

    // No valid conversion. Also, 0
    // is not a valid version.
    if (!parsed_number) return -1;

    // Outside bounds of int.
    if (parsed_number < INT_MIN || parsed_number > INT_MAX) return -1;

    // Possibly valid version
    return static_cast<int>(parsed_number);
}
