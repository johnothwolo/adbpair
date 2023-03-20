//
//  cbs.h
//  qrterm
//
//  Created by John Othwolo on 3/16/23.
//  Copyright © 2023 John Othwolo. All rights reserved.
//

#ifndef cbs_h
#define cbs_h

#include <stdlib.h>

// CRYPTO ByteString

typedef struct cbs_st {
  const uint8_t *data;
  size_t len;
} CBS;

__BEGIN_DECLS

void            CBS_init(CBS *cbs, const uint8_t *data, size_t len);
const uint8_t*  CBS_data(const CBS *cbs);
size_t          CBS_len(const CBS *cbs);
int             CBS_stow(const CBS *cbs, uint8_t **out_ptr, size_t *out_len);

__END_DECLS

#endif /* cbs_h */
