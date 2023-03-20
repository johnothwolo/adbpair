//
//  spake25519.hpp
//  qrterm
//
//  Created by John Othwolo on 3/7/23.
//  Copyright © 2023 John Othwolo. All rights reserved.
//

#ifndef spake25519_hpp
#define spake25519_hpp

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct spake2_ctx_st SPAKE2_CTX;

// SPAKE2.
//
// SPAKE2 is a password-authenticated key-exchange. It allows two parties,
// who share a low-entropy secret (i.e. password), to agree on a shared key.
// An attacker can only make one guess of the password per execution of the
// protocol.
//
// See https://tools.ietf.org/html/draft-irtf-cfrg-spake2-02.

// spake2_role_t enumerates the different “roles” in SPAKE2. The protocol
// requires that the symmetry of the two parties be broken so one participant
// must be “Alice” and the other be “Bob”.
enum spake2_role_t {
  spake2_role_alice,
  spake2_role_bob,
};

// SPAKE2_CTX_new creates a new |SPAKE2_CTX| (which can only be used for a
// single execution of the protocol). SPAKE2 requires the symmetry of the two
// parties to be broken which is indicated via |my_role| – each party must pass
// a different value for this argument.
//
// The |my_name| and |their_name| arguments allow optional, opaque names to be
// bound into the protocol. For example MAC addresses, hostnames, usernames
// etc. These values are not exposed and can avoid context-confusion attacks
// when a password is shared between several devices.
SPAKE2_CTX *SPAKE2_CTX_new(
    enum spake2_role_t my_role,
    const uint8_t *my_name, size_t my_name_len,
    const uint8_t *their_name, size_t their_name_len);


// SPAKE2_CTX_free frees |ctx| and all the resources that it has allocated.
void SPAKE2_CTX_free(SPAKE2_CTX *ctx);


// SPAKE2_MAX_MSG_SIZE is the maximum size of a SPAKE2 message.
#define SPAKE2_MAX_MSG_SIZE 32

// SPAKE2_generate_msg generates a SPAKE2 message given |password|, writes
// it to |out| and sets |*out_len| to the number of bytes written.
//
// At most |max_out_len| bytes are written to |out| and, in order to ensure
// success, |max_out_len| should be at least |SPAKE2_MAX_MSG_SIZE| bytes.
//
// This function can only be called once for a given |SPAKE2_CTX|.
//
// It returns one on success and zero on error.
int SPAKE2_generate_msg(SPAKE2_CTX *ctx, uint8_t *out,
                                       size_t *out_len, size_t max_out_len,
                                       const uint8_t *password,
                                       size_t password_len);

// SPAKE2_MAX_KEY_SIZE is the maximum amount of key material that SPAKE2 will
// produce.
#define SPAKE2_MAX_KEY_SIZE 64

// SPAKE2_process_msg completes the SPAKE2 exchange given the peer's message in
// |their_msg|, writes at most |max_out_key_len| bytes to |out_key| and sets
// |*out_key_len| to the number of bytes written.
//
// The resulting keying material is suitable for:
//   a) Using directly in a key-confirmation step: i.e. each side could
//      transmit a hash of their role, a channel-binding value and the key
//      material to prove to the other side that they know the shared key.
//   b) Using as input keying material to HKDF to generate a variety of subkeys
//      for encryption etc.
//
// If |max_out_key_key| is smaller than the amount of key material generated
// then the key is silently truncated. If you want to ensure that no truncation
// occurs then |max_out_key| should be at least |SPAKE2_MAX_KEY_SIZE|.
//
// You must call |SPAKE2_generate_msg| on a given |SPAKE2_CTX| before calling
// this function. On successful return, |ctx| is complete and calling
// |SPAKE2_CTX_free| is the only acceptable operation on it.
//
// Returns one on success or zero on error.
int SPAKE2_process_msg(SPAKE2_CTX *ctx, uint8_t *out_key,
                                      size_t *out_key_len,
                                      size_t max_out_key_len,
                                      const uint8_t *their_msg,
                                      size_t their_msg_len);


#if defined(__cplusplus)
}
#endif


#endif /* spake25519_hpp */
