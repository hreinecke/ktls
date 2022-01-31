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

enum { KTLS_INVALID_FD = -1 };

struct ktls_session *ktls_create_session(bool is_sender);
void ktls_destroy_session(struct ktls_session *session);

// ktls_set_psk_session sets PSK (pre-shared key). username is NULL-terminated
// string; passwd is sized string. Memory of both strings are managed by
// caller. currently, this API only allows to set PSK before calling
// ktls_handshake_*()
int ktls_set_psk_session(struct ktls_session *session, const char *username,
			 const unsigned char *passwd, const size_t sz_passwd);

int ktls_set_psk_session_from_password_prompt(struct ktls_session *session,
					      const char *username);

int ktls_set_psk_session_from_keyfile(struct ktls_session *session,
				      const char *username,
				      const char *key_file);

int ktls_set_tls_mode(struct ktls_session *session, const char *mode);

int ktls_handshake_tls(struct ktls_session *session, int sock);

// ktls_create_sock_oneshot returns a sock fd on success.
int ktls_create_sock_oneshot(struct ktls_session *session, const char *host,
			     const char *port);

#ifdef __cplusplus
}
#endif

#endif // __BTRFS_KTLS_H__
