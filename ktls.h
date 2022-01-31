/*
 * Copyright (C) 2020 Sheng Mao.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#ifndef __BTRFS_KTLS_H__
#define __BTRFS_KTLS_H__

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ktls_session;
extern int ktls_verbose;
extern int ktls_key_num;
key_serial_t *ktls_key_list;
extern int ktls_client_key_num;
  
enum { KTLS_INVALID_FD = -1 };

struct ktls_session *ktls_create_session(bool is_sender);
void ktls_destroy_session(struct ktls_session *session);

int ktls_set_psk_session(struct ktls_session *session);

int ktls_set_tls_mode(struct ktls_session *session, const char *mode);

int ktls_handshake_tls(struct ktls_session *session, int sock);

#ifdef __cplusplus
}
#endif

#endif // __BTRFS_KTLS_H__
