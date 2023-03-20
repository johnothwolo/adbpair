//
//  main.cpp
//  qrterm
//
//  Created by John Othwolo on 3/2/23.
//  Copyright © 2023 John Othwolo. All rights reserved.
//

#include "QrToPng.h"

__BEGIN_DECLS
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
__END_DECLS

#include "mdns_manager.hpp"
#include "adb_utils.hpp"

#if defined(_WIN32) || defined(_WIN64)
    #define OS_NAME "Windows"
#elif __APPLE__ || __MACH__
    #define OS_NAME "macOS"
#elif __linux__
    #define OS_NAME "Linux"
#elif __FreeBSD__
    #define OS_NAME "FreeBSD"
#elif __NetBSD__
    #define OS_NAME "NetBSD"
#elif __OpenBSD__
    #define OS_NAME "OpenBSD"
#elif __DragonFly__
    #define OS_NAME "DragonFlyBSD"
#elif __HAIKU__
    #define OS_NAME "Haiku"
#elif __unix || __unix__
    #define OS_NAME "Unix"
#else
    #define OS_NAME "OtherOS"
#endif

#define ADB_QR_TEXT_FMT  "WIFI:T:ADB;S:%s;P:%s;;"
#define ADB_SERVICE_NAME "_adb-tls-pairing._tcp."

enum {
    PASSCODE_LEN = 9,
    HOST_RAND_ID_LEN = 6
};

extern bool tlv_PrintPNG(std::vector<unsigned char> &imageData);


    extern "C" {
#include <CoreFoundation/CoreFoundation.h>
    }
#define D(fmt...) printf(fmt); printf("\n");

std::string gen_random(size_t len)
{
    std::stringstream result;
    for (size_t i = 0; i < len; ++i) {
        int randomChar = arc4random_uniform(26+26+10);
        if (randomChar < 26)
            result << (char) ('a' + randomChar);
        else if (randomChar < 26+26)
            result << (char) ('A' + randomChar - 26);
        else
            result << (char) ('0' + randomChar - 26 - 26);
    }
    
    return result.str();
}

int main(int argc, char* argv[]) {
    std::string qrString;
    std::string hostString;
    std::string passcode;

#ifndef TESTING
    // generate host string
    hostString = std::string(OS_NAME"-") + gen_random(HOST_RAND_ID_LEN);
    // generate passcode
    passcode = gen_random(PASSCODE_LEN);
#else
    hostString = "macOS-cE4aQJHH4";
    passcode = "wyIIgEKWM";
#endif
    
    // copy hostname and passcode to qr string
    qrString = StringPrintf(ADB_QR_TEXT_FMT, hostString.c_str(), passcode.c_str());

#pragma mark - IMG stuff
    
    std::ostringstream fileStream(std::ios::binary);
    int imgSize = 300;
    int minModulePixelSize = 3;
    auto exampleQrPng1 = QrToPng(imgSize, minModulePixelSize, qrString, qrcodegen::QrCode::Ecc::MEDIUM);
#ifdef TESTING
    std::cout << "Writing Example QR code 1 (normal) to \x1b[1m stdout \x1b[0m with text: '" << qrString << "', size: "
              << imgSize << "x" << imgSize << ", qr module pixel size: "
              << minModulePixelSize << ". " << std::endl;
#endif
    if (!exampleQrPng1.writeToPNG(fileStream)) {
        std::cerr << "Failure..." << std::endl;
        return -1;
    }

    size_t tp = fileStream.tellp();
    auto fileStreamString = fileStream.str();
    std::vector<unsigned char> pngBuffer(fileStreamString.c_str(), fileStreamString.c_str() + tp);

    if (tlv_PrintPNG(pngBuffer) != true){
        std::cerr << "Failed to generate QR Code..." << std::endl;
        return -1;
    }
    
#pragma mark - DNS stuff
    
    /*
     TODO: Windows stuff...
         DNS_STATUS DnsServiceBrowse(
             PDNS_SERVICE_BROWSE_REQUEST pRequest,
             PDNS_SERVICE_CANCEL         pCancel
         );
     */
   
    AdbMdnsManager pairManager(hostString, passcode);
    
    // browse devices
    int ret = DNSServiceBrowse(&pairManager.browseRef, 0, 0, ADB_SERVICE_NAME, nullptr,
                               AdbMdnsManager::on_service_browsed, &pairManager);
    
    // make sure error is zero
    assert(!ret);
    // set dispatch to listen for messages on main queue.
    pairManager.SetServiceRefDispatchQueue(pairManager.browseRef);
    
    // wait for messages on main queue. Never returns..
    dispatch_main();
    
    return 0;
}
