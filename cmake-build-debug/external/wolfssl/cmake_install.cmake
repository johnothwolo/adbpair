# Install script for directory: /Users/john/CLionProjects/pairdb/external/wolfssl

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/objdump")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/Users/john/CLionProjects/pairdb/cmake-build-debug/external/wolfssl/libwolfssl.a")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwolfssl.a" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwolfssl.a")
    execute_process(COMMAND "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ranlib" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwolfssl.a")
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/wolfssl" TYPE DIRECTORY FILES "/Users/john/CLionProjects/pairdb/external/wolfssl/wolfssl/" FILES_MATCHING REGEX "/[^/]*\\.h$" REGEX "(internal.h|cyassl/ctaocrypt/port|wolfssl/wolfcrypt/port/nrf51.h|wolfssl/wolfcrypt/port/arm|wolfssl/wolfcrypt/port/cypress|wolfssl/wolfcrypt/port/espressif|wolfssl/wolfcrypt/port/iotsafe|wolfssl/wolfcrypt/port/nxp|wolfssl/wolfcrypt/port/pic|wolfssl/wolfcrypt/port/renesas|wolfssl/wolfcrypt/port/silabs|wolfssl/wolfcrypt/port/st|wolfssl/wolfcrypt/port/ti|wolfssl/wolfcrypt/port/xilinx|wolfssl/wolfcrypt/port/atmel|wolfssl/wolfcrypt/port/af_alg|wolfssl/wolfcrypt/port/kcapi|wolfssl/wolfcrypt/port/devcrypto|wolfssl/wolfcrypt/async.h|wolfssl/wolfcrypt/wc_pkcs11.h|wolfssl/wolfcrypt/pkcs11.h|wolfssl/wolfcrypt/port/cavium|wolfssl/wolfcrypt/port/intel|wolfssl/wolfcrypt/sp.h|wolfssl/wolfcrypt/selftest.h|wolfssl/wolfcrypt/fips.h|wolfssl/wolfcrypt/port/caam)" EXCLUDE)
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/cyassl" TYPE DIRECTORY FILES "/Users/john/CLionProjects/pairdb/external/wolfssl/cyassl/" FILES_MATCHING REGEX "/[^/]*\\.h$" REGEX "(internal.h|cyassl/ctaocrypt/port|wolfssl/wolfcrypt/port/nrf51.h|wolfssl/wolfcrypt/port/arm|wolfssl/wolfcrypt/port/cypress|wolfssl/wolfcrypt/port/espressif|wolfssl/wolfcrypt/port/iotsafe|wolfssl/wolfcrypt/port/nxp|wolfssl/wolfcrypt/port/pic|wolfssl/wolfcrypt/port/renesas|wolfssl/wolfcrypt/port/silabs|wolfssl/wolfcrypt/port/st|wolfssl/wolfcrypt/port/ti|wolfssl/wolfcrypt/port/xilinx|wolfssl/wolfcrypt/port/atmel|wolfssl/wolfcrypt/port/af_alg|wolfssl/wolfcrypt/port/kcapi|wolfssl/wolfcrypt/port/devcrypto|wolfssl/wolfcrypt/async.h|wolfssl/wolfcrypt/wc_pkcs11.h|wolfssl/wolfcrypt/pkcs11.h|wolfssl/wolfcrypt/port/cavium|wolfssl/wolfcrypt/port/intel|wolfssl/wolfcrypt/sp.h|wolfssl/wolfcrypt/selftest.h|wolfssl/wolfcrypt/fips.h|wolfssl/wolfcrypt/port/caam)" EXCLUDE)
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/wolfssl" TYPE DIRECTORY FILES "/Users/john/CLionProjects/pairdb/external/wolfssl/wolfssl/" FILES_MATCHING REGEX "/[^/]*\\.h$" REGEX "(internal.h|cyassl/ctaocrypt/port|wolfssl/wolfcrypt/port/nrf51.h|wolfssl/wolfcrypt/port/arm|wolfssl/wolfcrypt/port/cypress|wolfssl/wolfcrypt/port/espressif|wolfssl/wolfcrypt/port/iotsafe|wolfssl/wolfcrypt/port/nxp|wolfssl/wolfcrypt/port/pic|wolfssl/wolfcrypt/port/renesas|wolfssl/wolfcrypt/port/silabs|wolfssl/wolfcrypt/port/st|wolfssl/wolfcrypt/port/ti|wolfssl/wolfcrypt/port/xilinx|wolfssl/wolfcrypt/port/atmel|wolfssl/wolfcrypt/port/af_alg|wolfssl/wolfcrypt/port/kcapi|wolfssl/wolfcrypt/port/devcrypto|wolfssl/wolfcrypt/async.h|wolfssl/wolfcrypt/wc_pkcs11.h|wolfssl/wolfcrypt/pkcs11.h|wolfssl/wolfcrypt/port/cavium|wolfssl/wolfcrypt/port/intel|wolfssl/wolfcrypt/sp.h|wolfssl/wolfcrypt/selftest.h|wolfssl/wolfcrypt/fips.h|wolfssl/wolfcrypt/port/caam)" EXCLUDE)
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/cyassl" TYPE DIRECTORY FILES "/Users/john/CLionProjects/pairdb/external/wolfssl/cyassl/" FILES_MATCHING REGEX "/[^/]*\\.h$" REGEX "(internal.h|cyassl/ctaocrypt/port|wolfssl/wolfcrypt/port/nrf51.h|wolfssl/wolfcrypt/port/arm|wolfssl/wolfcrypt/port/cypress|wolfssl/wolfcrypt/port/espressif|wolfssl/wolfcrypt/port/iotsafe|wolfssl/wolfcrypt/port/nxp|wolfssl/wolfcrypt/port/pic|wolfssl/wolfcrypt/port/renesas|wolfssl/wolfcrypt/port/silabs|wolfssl/wolfcrypt/port/st|wolfssl/wolfcrypt/port/ti|wolfssl/wolfcrypt/port/xilinx|wolfssl/wolfcrypt/port/atmel|wolfssl/wolfcrypt/port/af_alg|wolfssl/wolfcrypt/port/kcapi|wolfssl/wolfcrypt/port/devcrypto|wolfssl/wolfcrypt/async.h|wolfssl/wolfcrypt/wc_pkcs11.h|wolfssl/wolfcrypt/pkcs11.h|wolfssl/wolfcrypt/port/cavium|wolfssl/wolfcrypt/port/intel|wolfssl/wolfcrypt/sp.h|wolfssl/wolfcrypt/selftest.h|wolfssl/wolfcrypt/fips.h|wolfssl/wolfcrypt/port/caam)" EXCLUDE)
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/doc/wolfssl/example" TYPE FILE FILES
    "/Users/john/CLionProjects/pairdb/external/wolfssl/examples/echoserver/echoserver.c"
    "/Users/john/CLionProjects/pairdb/external/wolfssl/examples/sctp/sctp-server.c"
    "/Users/john/CLionProjects/pairdb/external/wolfssl/examples/sctp/sctp-client-dtls.c"
    "/Users/john/CLionProjects/pairdb/external/wolfssl/examples/sctp/sctp-client.c"
    "/Users/john/CLionProjects/pairdb/external/wolfssl/examples/sctp/sctp-server-dtls.c"
    "/Users/john/CLionProjects/pairdb/external/wolfssl/examples/echoclient/echoclient.c"
    "/Users/john/CLionProjects/pairdb/external/wolfssl/examples/server/server.c"
    "/Users/john/CLionProjects/pairdb/external/wolfssl/examples/benchmark/tls_bench.c"
    "/Users/john/CLionProjects/pairdb/external/wolfssl/examples/client/client.c"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/doc/wolfssl" TYPE FILE FILES
    "/Users/john/CLionProjects/pairdb/external/wolfssl/doc/README.txt"
    "/Users/john/CLionProjects/pairdb/external/wolfssl/certs/taoCert.txt"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/wolfssl/wolfssl-config.cmake")
    file(DIFFERENT EXPORT_FILE_CHANGED FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/wolfssl/wolfssl-config.cmake"
         "/Users/john/CLionProjects/pairdb/cmake-build-debug/external/wolfssl/CMakeFiles/Export/lib/cmake/wolfssl/wolfssl-config.cmake")
    if(EXPORT_FILE_CHANGED)
      file(GLOB OLD_CONFIG_FILES "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/wolfssl/wolfssl-config-*.cmake")
      if(OLD_CONFIG_FILES)
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/wolfssl/wolfssl-config.cmake\" will be replaced.  Removing files [${OLD_CONFIG_FILES}].")
        file(REMOVE ${OLD_CONFIG_FILES})
      endif()
    endif()
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/wolfssl" TYPE FILE FILES "/Users/john/CLionProjects/pairdb/cmake-build-debug/external/wolfssl/CMakeFiles/Export/lib/cmake/wolfssl/wolfssl-config.cmake")
  if("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/wolfssl" TYPE FILE FILES "/Users/john/CLionProjects/pairdb/cmake-build-debug/external/wolfssl/CMakeFiles/Export/lib/cmake/wolfssl/wolfssl-config-debug.cmake")
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" TYPE FILE FILES "/Users/john/CLionProjects/pairdb/cmake-build-debug/external/wolfssl/support/wolfssl.pc")
endif()

