//
//  cbs.c
//  qrterm
//
//  Created by John Othwolo on 3/16/23.
//  Copyright © 2023 John Othwolo. All rights reserved.
//

#include "cbs.h"
#include <stdlib.h>
#include <string.h>

void *OPENSSL_memdup(const void *data, size_t size) {
  if (size == 0) {
    return NULL;
  }

  void *ret = malloc(size);
  if (ret == NULL) {
    return NULL;
  }

  memcpy(ret, data, size);
  return ret;
}

void CBS_init(CBS *cbs, const uint8_t *data, size_t len) {
  cbs->data = data;
  cbs->len = len;
}

const uint8_t *CBS_data(const CBS *cbs) {
  return cbs->data;
}

size_t CBS_len(const CBS *cbs) {
  return cbs->len;
}

int CBS_stow(const CBS *cbs, uint8_t **out_ptr, size_t *out_len) {
  free(*out_ptr);
  *out_ptr = NULL;
  *out_len = 0;

  if (cbs->len == 0) {
    return 1;
  }
  *out_ptr = (unsigned char*)OPENSSL_memdup((char*)cbs->data, cbs->len);
  if (*out_ptr == NULL) {
    return 0;
  }
  *out_len = cbs->len;
  return 1;
}
