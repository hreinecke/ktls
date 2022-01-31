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

#include <common/utils.h>

#include "ktls.h"

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

static gnutls_datum_t ktls_psk_username = { 0 };
static gnutls_datum_t ktls_psk_key = { 0 };

static void ktls_print_logs(int level, const char *msg)
{
	if (bconf.verbose >= level)
		printf("GnuTLS [%d]: %s", level, msg);
}

int ktls_set_psk_session_from_password_prompt(struct ktls_session *session,
					      const char *username)
{
	struct termios orig_term_flags, passwd_term_flags;
	char passwd[KTLS_MAX_PASSWORD_LENGTH];
	int passwd_sz = 0;
	int stdin_fd = 0;

	passwd[0] = '\0';

	stdin_fd = fileno(stdin);

	if (!isatty(stdin_fd)) {
		error("tty needed for password input");
		return EXIT_FAILURE;
	}

	tcgetattr(stdin_fd, &orig_term_flags);
	passwd_term_flags = orig_term_flags;
	passwd_term_flags.c_lflag &= ~ECHO;
	passwd_term_flags.c_lflag |= ECHONL;

	if (tcsetattr(stdin_fd, TCSANOW, &passwd_term_flags)) {
		error("fail to hide password: %s", strerror(errno));
		return EXIT_FAILURE;
	}

	printf("password: ");
	if (!fgets(passwd, sizeof(passwd), stdin)) {
		error("no password read");
		return EXIT_FAILURE;
	}

	if (tcsetattr(fileno(stdin), TCSANOW, &orig_term_flags)) {
		error("fail to reset tty: %s", strerror(errno));
		return EXIT_FAILURE;
	}

	passwd_sz = strlen(passwd);
	if (passwd_sz <= 0) {
		error("no password read");
		return EXIT_FAILURE;
	}
	if (passwd[passwd_sz - 1] == '\n') {
		passwd[passwd_sz - 1] = '\0';
		passwd_sz--;
	}

	return ktls_set_psk_session(session, username,
				    (const unsigned char *)passwd, passwd_sz);
}

int ktls_set_psk_session_from_keyfile(struct ktls_session *session,
				      const char *username,
				      const char *key_file)
{
	int rc = GNUTLS_E_SUCCESS;
	struct stat file_stat;
	size_t sz = 0;
	FILE *fp = NULL;
	gnutls_datum_t input = { NULL, 0UL };
	gnutls_datum_t output = { NULL, 0UL };

	if (stat(key_file, &file_stat)) {
		error("fail to open keyfile: %s", strerror(errno));
		goto cleanup;
	}

	fp = fopen(key_file, "r");
	if (!fp) {
		error("fail to open keyfile: %s", strerror(errno));
		goto cleanup;
	}

	input.size = file_stat.st_size;

	input.data = gnutls_malloc(input.size);

	sz = fread(input.data, 1, input.size, fp);

	if (sz != input.size) {
		error("fail to read PEM");
		goto cleanup;
	}

	rc = gnutls_pem_base64_decode2(NULL, &input, &output);
	if (rc != GNUTLS_E_SUCCESS) {
		error("Error! fail to decode PEM: %s", gnutls_strerror(rc));
		goto cleanup;
	}

	return ktls_set_psk_session(session, username, output.data,
				    output.size);

cleanup:
	return EXIT_FAILURE;
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

	gnutls_global_set_log_level(bconf.verbose);
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

static int ktls_connect_or_bind(int *sock, bool is_sender, int protocol,
				struct sockaddr *serv_addr, size_t serv_addr_sz)
{
	*sock = 0;

	*sock = socket(protocol, SOCK_STREAM, 0);
	if (*sock == KTLS_INVALID_FD) {
		error("could not create socket: %s", strerror(errno));
		goto cleanup;
	}

	if (is_sender) {
		if (connect(*sock, serv_addr, serv_addr_sz)) {
			error("fail to connect to server: %s", strerror(errno));
			goto cleanup;
		}
		return EXIT_SUCCESS;
	}

	if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 },
		       sizeof(int))) {
		error("fail to connect to server: %s", strerror(errno));
		goto cleanup;
	}

	if (bind(*sock, serv_addr, serv_addr_sz) || listen(*sock, 1)) {
		error("fail to serve as server: %s", strerror(errno));
		goto cleanup;
	}

	return EXIT_SUCCESS;

cleanup:
	if (*sock >= 0)
		close(*sock);
	return EXIT_FAILURE;
}

static int ktls_connect_domain(int *sock, bool is_sender, const char *host,
			       const uint16_t port)
{
	struct addrinfo hints = { 0 }, *res = NULL;
	int rc = 0;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	if (getaddrinfo(host, NULL, &hints, &res)) {
		error("fail to get address info: %s", strerror(errno));
		return EXIT_FAILURE;
	}

	while (res) {
		switch (res->ai_family) {
		case AF_INET:
			explicit_bzero(&addr4, sizeof(addr4));
			addr4.sin_addr =
				((struct sockaddr_in *)res->ai_addr)->sin_addr;
			addr4.sin_port = port;
			addr4.sin_family = res->ai_family;
			if (!ktls_connect_or_bind(
				    sock, is_sender, res->ai_family,
				    (struct sockaddr *)&addr4, sizeof(addr4))) {
				goto cleanup;
			}
			break;
		case AF_INET6:
			explicit_bzero(&addr6, sizeof(addr6));
			addr6.sin6_addr =
				((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
			addr6.sin6_port = port;
			addr6.sin6_family = res->ai_family;
			if (!ktls_connect_or_bind(
				    sock, is_sender, res->ai_family,
				    (struct sockaddr *)&addr6, sizeof(addr6))) {
				goto cleanup;
			}
			break;
		}
		res = res->ai_next;
	}

	freeaddrinfo(res);
	return EXIT_FAILURE;

cleanup:
	freeaddrinfo(res);
	return rc;
}

static int ktls_connect_ip(int *sock, bool is_sender, const char *host,
			   const uint16_t port)
{
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	struct sockaddr *serv_addr = NULL;
	size_t serv_addr_sz = 0;
	sa_family_t protol = AF_INET;

	explicit_bzero(&addr4, sizeof(addr4));
	explicit_bzero(&addr6, sizeof(addr6));

	if (inet_pton(AF_INET, host, &addr4.sin_addr) == 1) {
		serv_addr = (struct sockaddr *)&addr4;
		serv_addr_sz = sizeof(addr4);
		protol = addr4.sin_family = AF_INET;
		addr4.sin_port = port;
	}

	if (!serv_addr && inet_pton(AF_INET6, host, &addr6.sin6_addr) == 1) {
		serv_addr = (struct sockaddr *)&addr6;
		serv_addr_sz = sizeof(addr6);
		protol = addr6.sin6_family = AF_INET6;
		addr6.sin6_port = port;
	}

	if (!serv_addr)
		return KTLS_INVALID_FD;

	return ktls_connect_or_bind(sock, is_sender, protol, serv_addr,
				    serv_addr_sz);
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
		error("unknown tls mode: %s", mode);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

#define INIT_GCM_WITH_MODE(V, X)                                               \
	{                                                                      \
		struct tls12_crypto_info_aes_gcm_##X crypto_info;              \
\
		crypto_info.info.version = TLS_##V##_VERSION;                  \
		crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_##X;         \
		memcpy(crypto_info.iv, seq_number,                             \
		       TLS_CIPHER_AES_GCM_##X##_IV_SIZE);                      \
		memcpy(crypto_info.rec_seq, seq_number,                        \
		       TLS_CIPHER_AES_GCM_##X##_REC_SEQ_SIZE);                 \
		if (cipher_key.size != TLS_CIPHER_AES_GCM_##X##_KEY_SIZE) {    \
			error("mismatch in send key size: %d != %d\n",         \
			      cipher_key.size,                                 \
			      TLS_CIPHER_AES_GCM_##X##_KEY_SIZE);              \
			goto cleanup;                                          \
		}                                                              \
		memcpy(crypto_info.key, cipher_key.data,                       \
		       TLS_CIPHER_AES_GCM_##X##_KEY_SIZE);                     \
		memcpy(crypto_info.salt, iv.data,                              \
		       TLS_CIPHER_AES_GCM_##X##_SALT_SIZE);                    \
		if (setsockopt(sock, SOL_TLS, is_sender ? TLS_TX : TLS_RX,     \
			       &crypto_info, sizeof(crypto_info))) {           \
			error("fail to set kernel tls: %s", strerror(errno));  \
			goto cleanup;                                          \
		}                                                              \
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
			error("fail to set PSK for client: %s",
			      gnutls_strerror(rc));
			goto cleanup;
		}
	}

	if (!is_sender && session->psk_cred_server) {
		rc = gnutls_credentials_set(session->session, GNUTLS_CRD_PSK,
					    session->psk_cred_server);
		if (rc != GNUTLS_E_SUCCESS) {
			error("fail to set PSK for server: %s",
			      gnutls_strerror(rc));
			goto cleanup;
		}
	}

	if (session->crt_cred) {
		rc = gnutls_credentials_set(session->session,
					    GNUTLS_CRD_CERTIFICATE,
					    session->crt_cred);

		if (rc == GNUTLS_E_SUCCESS) {
			error("fail to set certificate: %s",
			      gnutls_strerror(rc));
			goto cleanup;
		}
	}

	if (setsockopt(sock, SOL_TCP, TCP_ULP, "tls", sizeof("tls"))) {
		error("fail to set kernel TLS on socket: %s", strerror(errno));
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
		error("fail to set priority: %s", gnutls_strerror(rc));
		goto cleanup;
	}

	gnutls_transport_set_int(session->session, sock);

	gnutls_handshake_set_timeout(session->session,
				     GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	do {
		if (handshake_retry < 0) {
			error("exhaust retries on handshake");
			break;
		}
		rc = gnutls_handshake(session->session);
		handshake_retry--;
	} while (rc < 0 && !gnutls_error_is_fatal(rc));

	if (gnutls_error_is_fatal(rc)) {
		error("fail on handshake: %s", gnutls_strerror(rc));
		goto cleanup;
	}
	if (bconf.verbose > 0) {
		char *desc = gnutls_session_get_desc(session->session);

		printf("TLS session info: %s\n", desc);
		gnutls_free(desc);
	}

	session->stage = KTLS_STAGE_HAS_HANDSHAKED;

	rc = gnutls_record_get_state(session->session, is_sender ? 0 : 1,
				     &mac_key, &iv, &cipher_key, seq_number);
	if (rc != GNUTLS_E_SUCCESS) {
		error("fail on retrieve TLS record: %s", gnutls_strerror(rc));
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

	if (bconf.verbose > 0)
		fprintf(stderr, "ktls init done\n");

	return EXIT_SUCCESS;

cleanup:
	return EXIT_FAILURE;
}

static int ktls_cp_datum(gnutls_datum_t *to, const gnutls_datum_t *from)
{
	if (!to || !from)
		return EXIT_FAILURE;

	to->size = from->size;
	to->data = (unsigned char *)gnutls_malloc(to->size);
	memmove(to->data, from->data, to->size);

	return EXIT_SUCCESS;
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

static int ktls_set_datum(gnutls_datum_t *to, const unsigned char *from,
			  int from_size)
{
	if (!to || !from || !from_size)
		return EXIT_FAILURE;

	if (from_size < 0)
		from_size = strlen((const char *)from);

	to->size = from_size;
	to->data = (unsigned char *)gnutls_malloc(to->size);
	memmove(to->data, from, from_size);

	return EXIT_SUCCESS;
}

static int tls_psk_client_callback(gnutls_session_t session,
				   gnutls_datum_t *username,
				   gnutls_datum_t *key)
{
	if (ktls_cp_datum(username, &ktls_psk_username) ||
	    ktls_cp_datum(key, &ktls_psk_key))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

static int tls_psk_server_callback(gnutls_session_t session,
				   const gnutls_datum_t *username,
				   gnutls_datum_t *key)
{
	if (ktls_cmp_datum(username, &ktls_psk_username) ||
	    ktls_cp_datum(key, &ktls_psk_key))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

int ktls_set_psk_session(struct ktls_session *session, const char *username,
			 const unsigned char *passwd, const size_t sz_passwd)
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
			error("fail on set psk for server: %s",
			      gnutls_strerror(rc));
			goto cleanup;
		}
		gnutls_psk_set_server_credentials_function2(
			session->psk_cred_server, tls_psk_server_callback);
	}

	if (is_sender && !session->psk_cred_client) {
		rc = gnutls_psk_allocate_client_credentials(
			&session->psk_cred_client);
		if (rc != GNUTLS_E_SUCCESS) {
			error("fail on set psk for client: %s",
			      gnutls_strerror(rc));
			goto cleanup;
		}
		gnutls_psk_set_client_credentials_function2(
			session->psk_cred_client, tls_psk_client_callback);
	}

	if (!ktls_psk_key.size)
		gnutls_free(ktls_psk_key.data);

	if (!ktls_psk_username.size)
		gnutls_free(ktls_psk_username.data);

	if (ktls_set_datum(&ktls_psk_username, (const unsigned char *)username,
			   -1) ||
	    ktls_set_datum(&ktls_psk_key, passwd, sz_passwd))
		goto cleanup;

	return EXIT_SUCCESS;

cleanup:
	return EXIT_FAILURE;
}

int ktls_create_sock_oneshot(struct ktls_session *session, const char *host,
			     const char *port)
{
	int sock = 0;
	int nport = 0;
	bool is_sender;

	if (!session || !session->session)
		return EXIT_FAILURE;

	is_sender = session->role == GNUTLS_CLIENT;

	nport = atoi(port);

	if (nport >= 0 && nport <= 65535)
		nport = htons((uint16_t)nport);

	if (ktls_connect_ip(&sock, is_sender, host, (uint16_t)nport))
		if (ktls_connect_domain(&sock, is_sender, host, nport))
			goto cleanup;

	if (!is_sender) {
		int accepted_sock = KTLS_INVALID_FD;

		accepted_sock = accept(sock, (struct sockaddr *)NULL, NULL);
		close(sock);
		sock = accepted_sock;
	}

	if (ktls_handshake_tls(session, sock))
		goto cleanup;

	return sock;

cleanup:
	close(sock);
	return KTLS_INVALID_FD;
}