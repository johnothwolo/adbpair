############################################################################
#############|\    /|####/\#####/‾‾‾‾‾##|‾‾‾‾|####|‾‾‾‾‾|##|‾‾‾‾‾ ##########
#############| \  / |###/  \###|      ##|____|####|     |##|_____ ##########
#############|  \/  |##/----\##|      ##|   \ ####|     |##      |##########
#############|      |#/      \##\_____##|    \####|_____|## _____|##########
############################################################################

###################################################################
# Analogue for 'set' command which defines readonly variable. #####
###################################################################

# Usage: 
# set_readonly(FOO value) 
###################################################################
macro(set_readonly VAR)
  # Set the variable itself
  set("${VAR}" "${ARGN}")
  # Store the variable's value for restore it upon modifications.
  set("_${VAR}_readonly_val" "${ARGN}")
  # Register a watcher for a variable
  variable_watch("${VAR}" readonly_guard)
endmacro()

# Watcher for a variable which emulates readonly property.
macro(readonly_guard VAR access value current_list_file stack)
  if ("${access}" STREQUAL "MODIFIED_ACCESS")
    message(WARNING "Attempt to change readonly variable '${VAR}'!")
    # Restore a value of the variable to the initial one.
    set(${VAR} "${_${VAR}_readonly_val}")
  endif()
endmacro()

###################################################################
###################################################################
###################################################################
###################################################################


## NOTE: CMAKE_CURRENT_BINARY_DIR changes according to the directory CMakeLists.txt is in.

#### libpng configurable options ####
#####################################

set(PNG_STATIC ON CACHE BOOL "" FORCE)
set(PNG_SHARED OFF CACHE BOOL "" FORCE)
set(PNG_EXECUTABLES OFF CACHE BOOL "" FORCE) # we only want lib
set(PNG_TESTS OFF CACHE BOOL "" FORCE) # we only want lib
set(SKIP_INSTALL_ALL OFF CACHE BOOL "" FORCE) # we only want lib
add_subdirectory(${EXTERNAL_DIR}/libpng ${CMAKE_CURRENT_BINARY_DIR}/libpng)



#### Specify the build configuration for wolfSSL ####
#####################################################

# cmake .. -DWOLFSSL_OPENSSLEXTRA:STRING=yes -DWOLFSSL_CERTGEN:STRING=yes -DWOLFSSL_CERTREQ:STRING=yes -DCMAKE_C_FLAGS_DEBUG:STRING="-g" -DWOLFSSL_AESGCM:STRING=yes -DWOLFSSL_HKDF:STRING=yes -DWOLFSSL_KEYGEN:STRING=yes -DWOLFSSL_DEBUG:STRING=yes -DCMAKE_C_FLAGS:STRING="-DOPENSSL_ALL -DHAVE_KEYING_MATERIAL"

set(WOLFSSL_OPENSSLEXTRA    "yes")
set(WOLFSSL_CERTGEN         "yes")
set(WOLFSSL_CERTREQ         "yes")
set(WOLFSSL_AESGCM          "yes")
set(WOLFSSL_HKDF            "yes")
set(WOLFSSL_KEYGEN          "yes")
set(CMAKE_C_FLAGS           "${CMAKE_C_FLAGS}-DOPENSSL_ALL -DHAVE_KEYING_MATERIAL -DOPENSSL_EXTRA -DOPENSSL_ALL")
# # -DCMAKE_BUILD_TYPE=Release
set(WOLFSSL_DEBUG           "yes")
set(CMAKE_C_FLAGS_DEBUG     "-g")
set_readonly(BUILD_SHARED_LIBS OFF)

add_subdirectory(${EXTERNAL_DIR}/wolfssl ${CMAKE_CURRENT_BINARY_DIR}/wolfssl)