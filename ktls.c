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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>

#include <linux/tls.h>

#include <gnutls/gnutls.h>

#include <keyutils.h>

#include "ktls.h"

int ktls_client_key_num;

enum { KTLS_MAX_PASSWORD_LENGTH = 256, KTLS_MAX_PRIORITY_STRING_LENTH = 256 };

enum {
	KTLS_STAGE_NOT_HANDSHAKED,
	KTLS_STAGE_HAS_HANDSHAKED,
};

enum ktls_tls_mode_t {
	KTLS_TLS_12_128_GCM = 0,
	KTLS_TLS_13_128_GCM,
	KTLS_TLS_12_256_GCM
};

struct ktls_session {
	gnutls_session_t session;
	gnutls_certificate_credentials_t crt_cred;

	gnutls_psk_server_credentials_t psk_cred_server;
	gnutls_psk_client_credentials_t psk_cred_client;

	uint8_t role;
	uint8_t stage;
	enum ktls_tls_mode_t tls_mode;
};

static void ktls_print_logs(int level, const char *msg)
{
	if (ktls_verbose >= level)
		printf("GnuTLS [%d]: %s", level, msg);
}

struct ktls_session *ktls_create_session(bool is_sender)
{
	struct ktls_session *session = NULL;

	session = (struct ktls_session *)malloc(sizeof(struct ktls_session));
	explicit_bzero(session, sizeof(*session));

	gnutls_global_init();

	session->role = is_sender ? GNUTLS_CLIENT : GNUTLS_SERVER;
	session->stage = KTLS_STAGE_NOT_HANDSHAKED;

	gnutls_init(&session->session, session->role);

	gnutls_global_set_log_level(ktls_verbose);
	gnutls_global_set_log_function(ktls_print_logs);

	return session;
}

void ktls_destroy_session(struct ktls_session *session)
{
	if (!session)
		return;

	if (session->crt_cred)
		gnutls_certificate_free_credentials(session->crt_cred);

	if (session->psk_cred_server)
		gnutls_psk_free_server_credentials(session->psk_cred_server);

	if (session->psk_cred_client)
		gnutls_psk_free_client_credentials(session->psk_cred_client);

	if (session->session) {
		if (session->stage == KTLS_STAGE_HAS_HANDSHAKED)
			gnutls_bye(session->session, GNUTLS_SHUT_RDWR);
		gnutls_deinit(session->session);
	}

	gnutls_global_deinit();

	explicit_bzero(session, sizeof(*session));
}

int ktls_set_tls_mode(struct ktls_session *session, const char *mode)
{
	if (!session)
		return EXIT_FAILURE;

	if (!strcmp("tls_12_128_gcm", mode))
		session->tls_mode = KTLS_TLS_12_128_GCM;
	else if (!strcmp("tls_13_128_gcm", mode))
		session->tls_mode = KTLS_TLS_13_128_GCM;
	else if (!strcmp("tls_12_256_gcm", mode))
		session->tls_mode = KTLS_TLS_12_256_GCM;
	else {
		fprintf(stderr, "unknown tls mode: %s", mode);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

#define INIT_GCM_WITH_MODE(V, X)					\
	{								\
		struct tls12_crypto_info_aes_gcm_##X crypto_info;	\
									\
		crypto_info.info.version = TLS_##V##_VERSION;		\
		crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_##X;	\
		memcpy(crypto_info.iv, seq_number,			\
		       TLS_CIPHER_AES_GCM_##X##_IV_SIZE);		\
		memcpy(crypto_info.rec_seq, seq_number,			\
		       TLS_CIPHER_AES_GCM_##X##_REC_SEQ_SIZE);		\
		if (cipher_key.size != TLS_CIPHER_AES_GCM_##X##_KEY_SIZE) { \
			fprintf(stderr,					\
				"mismatch in send key size: %d != %d\n", \
				cipher_key.size,			\
				TLS_CIPHER_AES_GCM_##X##_KEY_SIZE);	\
			goto cleanup;					\
		}							\
		memcpy(crypto_info.key, cipher_key.data,		\
		       TLS_CIPHER_AES_GCM_##X##_KEY_SIZE);		\
		memcpy(crypto_info.salt, iv.data,			\
		       TLS_CIPHER_AES_GCM_##X##_SALT_SIZE);		\
		if (setsockopt(sock, SOL_TLS, is_sender ? TLS_TX : TLS_RX, \
			       &crypto_info, sizeof(crypto_info))) {	\
			fprintf(stderr, "fail to set kernel tls: %s",	\
				strerror(errno));			\
			goto cleanup;					\
		}							\
	}

int ktls_handshake_tls(struct ktls_session *session, int sock)
{
	int rc = 0;
	bool is_sender = false;
	int handshake_retry = 3;
	char tls_priority_list[KTLS_MAX_PRIORITY_STRING_LENTH];
	const char *tls_priority_templ =
		"NONE:+MAC-ALL:+COMP-NULL:+SIGN-ALL:+GROUP-ALL:+ECDHE-PSK:+DHE-PSK:%s:%s";
	const char *tls_priority_ver_mode = NULL;

	gnutls_datum_t mac_key;
	gnutls_datum_t iv;
	gnutls_datum_t cipher_key;
	unsigned char seq_number[8];

	if (!session || !session->session)
		return EXIT_FAILURE;

	is_sender = session->role == GNUTLS_CLIENT;

	if (is_sender && session->psk_cred_client) {
		rc = gnutls_credentials_set(session->session, GNUTLS_CRD_PSK,
					    session->psk_cred_client);
		if (rc != GNUTLS_E_SUCCESS) {
			fprintf(stderr, "fail to set PSK for client: %s",
			      gnutls_strerror(rc));
			goto cleanup;
		}
	}

	if (!is_sender && session->psk_cred_server) {
		rc = gnutls_credentials_set(session->session, GNUTLS_CRD_PSK,
					    session->psk_cred_server);
		if (rc != GNUTLS_E_SUCCESS) {
			fprintf(stderr, "fail to set PSK for server: %s",
			      gnutls_strerror(rc));
			goto cleanup;
		}
	}

	if (session->crt_cred) {
		rc = gnutls_credentials_set(session->session,
					    GNUTLS_CRD_CERTIFICATE,
					    session->crt_cred);

		if (rc == GNUTLS_E_SUCCESS) {
			fprintf(stderr, "fail to set certificate: %s",
			      gnutls_strerror(rc));
			goto cleanup;
		}
	}

	if (setsockopt(sock, SOL_TCP, TCP_ULP, "tls", sizeof("tls"))) {
		fprintf(stderr, "fail to set kernel TLS on socket: %s", strerror(errno));
		goto cleanup;
	}

	switch (session->tls_mode) {
	case KTLS_TLS_12_128_GCM:
		tls_priority_ver_mode = "+VERS-TLS1.2:+AES-128-GCM";
		break;
	case KTLS_TLS_13_128_GCM:
		tls_priority_ver_mode = "+VERS-TLS1.3:+AES-128-GCM";
		break;
	case KTLS_TLS_12_256_GCM:
		tls_priority_ver_mode = "+VERS-TLS1.2:+AES-256-GCM";
		break;
	}

	snprintf(tls_priority_list, KTLS_MAX_PRIORITY_STRING_LENTH,
		 tls_priority_templ,
		 is_sender ? "+CTYPE-CLI-ALL" : "+CTYPE-SRV-ALL",
		 tls_priority_ver_mode);

	rc = gnutls_priority_set_direct(session->session, tls_priority_list,
					NULL);
	if (rc != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "fail to set priority: %s", gnutls_strerror(rc));
		goto cleanup;
	}

	gnutls_transport_set_int(session->session, sock);

	gnutls_handshake_set_timeout(session->session,
				     GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	do {
		if (handshake_retry < 0) {
			fprintf(stderr, "exhaust retries on handshake");
			break;
		}
		rc = gnutls_handshake(session->session);
		handshake_retry--;
	} while (rc < 0 && !gnutls_error_is_fatal(rc));

	if (gnutls_error_is_fatal(rc)) {
		fprintf(stderr, "fail on handshake: %s", gnutls_strerror(rc));
		goto cleanup;
	}
	if (ktls_verbose > 0) {
		char *desc = gnutls_session_get_desc(session->session);

		printf("TLS session info: %s\n", desc);
		gnutls_free(desc);
	}

	session->stage = KTLS_STAGE_HAS_HANDSHAKED;

	rc = gnutls_record_get_state(session->session, is_sender ? 0 : 1,
				     &mac_key, &iv, &cipher_key, seq_number);
	if (rc != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "fail on retrieve TLS record: %s", gnutls_strerror(rc));
		goto cleanup;
	}

	switch (session->tls_mode) {
	case KTLS_TLS_12_128_GCM:
		INIT_GCM_WITH_MODE(1_2, 128);
		break;
	case KTLS_TLS_13_128_GCM:
		INIT_GCM_WITH_MODE(1_3, 128);
		break;
	case KTLS_TLS_12_256_GCM:
		INIT_GCM_WITH_MODE(1_2, 256);
		break;
	}

	if (ktls_verbose > 0)
		fprintf(stderr, "ktls init done\n");

	return EXIT_SUCCESS;

cleanup:
	return EXIT_FAILURE;
}

static int ktls_cmp_datum(const gnutls_datum_t *lhs, const gnutls_datum_t *rhs)
{
	if (!lhs && !rhs)
		return EXIT_SUCCESS;

	if (!lhs || !rhs)
		return EXIT_FAILURE;

	if (lhs->size != rhs->size)
		return EXIT_FAILURE;

	return memcmp(lhs->data, rhs->data, lhs->size);
}

static int tls_psk_client_callback(gnutls_session_t session,
				   char **username,
				   gnutls_datum_t *key)
{
	char *tmp_id, *ptr;
	void *tmp_data;
	int ret;

	if (ktls_client_key_num >= ktls_key_num) {
		fprintf(stderr, "Invalid client key number %d\n",
			ktls_client_key_num);
		return EXIT_FAILURE;
	}
	fprintf(stdout, "Checking client id %d\n", ktls_client_key_num);
	ret = keyctl_describe_alloc(ktls_key_list[ktls_client_key_num],
				    &tmp_id);
	if (ret <= 0) {
		fprintf(stderr, "Failed to describe client key %d\n",
			ktls_client_key_num);
		goto out_failure;
	}
	ptr = strrchr(tmp_id, ';');
	if (!ptr) {
		fprintf(stderr, "Invalid key identity %s\n", tmp_id);
		goto out_free_id;
	}
	*username = malloc(strlen(ptr) + 1);
	if (!username) {
		fprintf(stderr, "Failed to allocate identity\n");
		goto out_free_id;
	}
	strcpy(*username, ptr);
	free(tmp_id);
	ret = keyctl_read_alloc(ktls_key_list[ktls_client_key_num],
				&tmp_data);
	if (ret <= 0) {
		fprintf(stderr, "Failed to read client key %d\n",
			ktls_client_key_num);
		goto out_failure;
	}
	key->data = tmp_data;
	key->size = ret;
	return EXIT_SUCCESS;
out_free_id:
	free(tmp_id);
out_failure:
	ktls_client_key_num++;
	return EXIT_FAILURE;
}

static int tls_psk_server_callback(gnutls_session_t session,
				   const char *username,
				   gnutls_datum_t *key)
{
	int i;

	fprintf(stdout, "Checking server id %s\n", username);
	for (i = 0; i < ktls_key_num; i++) {
		char *tmp_id, *ptr;
		void *tmp_data;
		gnutls_datum_t tmp_psk;
		int ret;

		ret = keyctl_describe_alloc(ktls_key_list[i],
					    &tmp_id);
		if (ret <= 0)
			continue;
		ptr = strrchr(tmp_id, ';');
		if (!ptr || strcmp(ptr, username)) {
			free(tmp_id);
			fprintf(stderr, "Non-matching username %s\n", tmp_id);
			continue;
		}
		free(tmp_id);
		ret = keyctl_read_alloc(ktls_key_list[i], &tmp_data);
		if (ret <= 0)
			continue;
		tmp_psk.data = tmp_data;
		tmp_psk.size = ret;
		if (!ktls_cmp_datum(key, &tmp_psk)) {
			free(tmp_psk.data);
			return EXIT_SUCCESS;
		}
		free(tmp_psk.data);
	}
	
	return EXIT_FAILURE;
}

int ktls_set_psk_session(struct ktls_session *session)
{
	bool is_sender = false;
	int rc = 0;

	if (!session || !session->session)
		goto cleanup;

	is_sender = session->role == GNUTLS_CLIENT;

	if (!is_sender && !session->psk_cred_server) {
		rc = gnutls_psk_allocate_server_credentials(
			&session->psk_cred_server);
		if (rc != GNUTLS_E_SUCCESS) {
			fprintf(stderr, "fail on set psk for server: %s",
			      gnutls_strerror(rc));
			goto cleanup;
		}
		gnutls_psk_set_server_credentials_function(
			session->psk_cred_server, tls_psk_server_callback);
	}

	if (is_sender && !session->psk_cred_client) {
		rc = gnutls_psk_allocate_client_credentials(
			&session->psk_cred_client);
		if (rc != GNUTLS_E_SUCCESS) {
			fprintf(stderr, "fail on set psk for client: %s",
				gnutls_strerror(rc));
			goto cleanup;
		}
		gnutls_psk_set_client_credentials_function(
			session->psk_cred_client, tls_psk_client_callback);
		ktls_client_key_num = 0;
	}

	return EXIT_SUCCESS;

cleanup:
	return EXIT_FAILURE;
}
