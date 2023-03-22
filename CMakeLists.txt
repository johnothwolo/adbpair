cmake_minimum_required(VERSION 3.19)
project(pairdb C CXX)

set(CMAKE_CXX_STANDARD 14)

set(EXTERNAL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external)

add_subdirectory(${EXTERNAL_DIR})

add_executable(pairdb
        src/adb_env.cpp
        src/adb_env.hpp
        src/adb_utils.cpp
        src/adb_utils.hpp
        src/aes_128_gcm.cpp
        src/aes_128_gcm.hpp
        src/android_pubkey.cpp
        src/android_pubkey.hpp
        src/CImg.h
        src/crypto.cpp
        src/crypto.hpp
        src/main.cpp
        src/mdns_manager.cpp
        src/mdns_manager.hpp
        src/pair_client.cpp
        src/pair_client.hpp
        src/pairing_auth.cpp
        src/pairing_auth.hpp
        src/pairing_connection.cpp
        src/pairing_connection.hpp
        src/png_buffer.hpp
        src/QrCode.cpp
        src/QrCode.hpp
        src/QrToPng.cpp
        src/QrToPng.h
        src/rsa_2048_hey.cpp
        src/rsa_2048_key.hpp
        src/socket_network_client_unix.cpp
        src/socket_network_windows.cpp
        src/sockets.cpp
        src/sockets.hpp
        src/TinyPngOut.cpp
        src/TinyPngOut.hpp
        src/tls_connection.cpp
        src/tls_connection.hpp
        src/tlv.cpp

        src/spake25519/cbs.h
        src/spake25519/cbs.c
        src/spake25519/edwards25519_fiat.h
        src/spake25519/edwards25519_tables.h
        src/spake25519/edwards25519.c
        src/spake25519/edwards25519.h
        src/spake25519/spake25519.c
        src/spake25519/spake25519.h

        src/dnssd/dns_sd.h
        src/dnssd/dnssd_clientstub.c
        src/dnssd/dnssd_clientstub.h
        src/dnssd/dnssd_ipc.c
        src/dnssd/dnssd_ipc.h
        src/dnssd/mdns_strict.h
        src/dnssd/strict.h
        )

add_dependencies(pairdb wolfssl png_static)

if (APPLE)
  target_link_libraries(pairdb PUBLIC "-framework CoreFoundation -framework Security")
endif()


##### WolfSSL #####
###################

# WolfSSL include directories
target_include_directories(pairdb PRIVATE ${EXTERNAL_DIR}/wolfssl)
# Link against WolfSSL
# NOTE: since we forced a static library build, we may have to link against the archive.
set(WOLFSSL_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/external/wolfssl/libwolfssl.a)
target_link_libraries(pairdb PRIVATE "-Wl,-all_load,${WOLFSSL_LIBRARIES}")



###### LibPNG ######
####################

# libpng include directories
# NOTE: Since we copy png.h to the bindir, we can exclude the png's sourcedir from list of includes
#       this fixes the error:
#                external/libpng/png.h:330:13: fatal error: 'pnglibconf.h' file not found
#
#target_include_directories(pairdb PRIVATE ${EXTERNAL_DIR}/libpng)
configure_file(${EXTERNAL_DIR}/libpng/png.h 
                ${CMAKE_CURRENT_BINARY_DIR}/external/libpng/png.h COPYONLY) # we have to manually copy png.h
configure_file(${EXTERNAL_DIR}/libpng/pngconf.h 
                ${CMAKE_CURRENT_BINARY_DIR}/external/libpng/pngconf.h COPYONLY) # we also have to manually copy png.h

# add libpng generated files from libpng during build
target_include_directories(pairdb PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/external/libpng)
# Link against libpng
target_link_libraries(pairdb PRIVATE png_static)

