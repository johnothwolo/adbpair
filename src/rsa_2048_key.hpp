//
//  rsa_2048_key.h
//  qrterm
//
//  Created by John Othwolo on 3/6/23.
//  Copyright © 2023 John Othwolo. All rights reserved.
//

#ifndef rsa_2048_key_h
#define rsa_2048_key_h

#include <string>

#include "crypto.hpp"

// Generates the public key from the RSA private key.
bool CalculatePublicKey(std::string* out, WOLFSSL_RSA* private_key);

#endif /* rsa_2048_key_h */
