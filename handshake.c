// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Oracle and/or its affiliates.
 *
 * Handle a request for a TLS handshake on behalf of an
 * in-kernel TLS consumer.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <netinet/tcp.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <keyutils.h>

#include <linux/tls.h>

#include "tlshd.h"

#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#ifndef SOL_TLS
#define SOL_TLS 282
#endif

#ifndef TLS_KEY
#define TLS_KEY 4
#endif

#ifndef TLS_CIPHER
#define TLS_CIPHER 5
#endif

#ifndef TLS_SERVER_MODE
#define TLS_SERVER_MODE 6
#endif

/*
 * Current RPC-with-TLS prototype implementations are limited to TLSv1.2,
 * but will eventually grow support for TLS v1.3. For security reasons,
 * this min version must be set to NO LOWER THAN TLS v1.2. This setting
 * is to be increased when tlshd matriculates to product quality.
 */
#define TLSD_MIN_TLS_VERSION	TLS1_2_VERSION

/* Not yet included in uapi headers */
#define TLS_DONE		(3)

char *tlshd_truststore = NULL;
key_serial_t *tlshd_keylist;
size_t tlshd_keylist_size;

static unsigned int tlshd_psk_client_cb(SSL *ssl, const char *hint,
					char *identity,
					unsigned int max_identity_len,
					unsigned char *psk,
					unsigned int max_psk_len)
{
	int ret, i;
	char *psk_identity;
	key_serial_t tls_key;

	if (hint)
		syslog(LOG_DEBUG, "Received PSK identity hint '%s'\n", hint);

	psk_identity = malloc(max_identity_len);
	if (!psk_identity) {
		errno = ENOMEM;
		return -1;
	}

	/*
	 * lookup PSK identity and PSK key based on the given identity hint here
	 */
	for (i = 0; i < tlshd_keylist_size; i++) {
		ret = keyctl_describe(tlshd_keylist[i], psk_identity,
				      max_identity_len);
		if (ret < 0) {
			syslog(LOG_INFO, "failed to describe key %08x\n",
			       tlshd_keylist[i]);
			continue;
		}
		if (hint && strcmp(psk_identity, hint))
			continue;
		tls_key = tlshd_keylist[i];
		strncpy(identity, psk_identity, max_identity_len);
		break;
	}
	if (ret < 0 || (unsigned int)ret > max_identity_len) {
		syslog(LOG_WARNING, "failed to get TLS identity\n");
		errno = ENOKEY;
		return -1;
	}

        syslog(LOG_DEBUG, "using psk identity '%s' len=%d\n", identity,
	       ret);
	ret = keyctl_read(tls_key, (char *)psk, max_psk_len);
	if (ret < 0) {
		syslog(LOG_ERR, "failed to read key");
	} else {
		syslog(LOG_DEBUG, "read %d key bytes\n", ret);
	}
	return ret;
}

/*
 * Notify the kernel that the user space handshake process has completed
 * and the socket is ready to be used or that the handshake failed.
 */
static void tlshd_handshake_complete(int fd, int status)
{
	char buf[10];

	if (snprintf(buf, sizeof(buf), "%d", status) < 0) {
		tlshd_log_perror("snprintf");
		return;
	}
	if (setsockopt(fd, SOL_TLS, TLS_DONE, buf, strlen(buf)))
		tlshd_log_perror("setsockopt");
}

static void tlshd_push_handshake(SSL *ssl, int fd, struct sockaddr *addr)
{
	X509 *cert;

	switch (SSL_do_handshake(ssl)) {
	case 1:
		/* Verify a server certificate was presented */
		cert = SSL_get_peer_certificate(ssl);
		if (!cert) {
			tlshd_log_liberrors();
			tlshd_handshake_complete(fd, -EACCES);
			return;
		}
		X509_free(cert);

		/* Verify the result of chain verification (RFC 4158) */
		if (SSL_get_verify_result(ssl) != X509_V_OK) {
			tlshd_log_liberrors();
			tlshd_handshake_complete(fd, -EACCES);
			return;
		}

		/* TODO hostname verification */

		break;
	case 0:
		tlshd_log_failure(addr);
		tlshd_log_liberrors();
		tlshd_handshake_complete(fd, -EACCES);
		return;
	default:
		tlshd_log_liberrors();
		tlshd_handshake_complete(fd, -EACCES);
		return;
	}

	/*
	 * OpenSSL 3.0.0 has automatically pushed the session
	 * information into the socket.
	 */
	tlshd_handshake_complete(fd, 0);
	tlshd_log_success(addr);
}

static void tlshd_initial_handshake(SSL_CTX *ctx, int fd, struct sockaddr *addr)
{
	BIO *bio;
	SSL *ssl;

	/*
	 * NOCLOSE prevents the library from sending a session closure
	 * alert when the file descriptor is closed.
	 */
	bio = BIO_new_fd(fd, BIO_NOCLOSE);
	if (!bio) {
		tlshd_log_liberrors();
		return;
	}

	ssl = NULL;
	BIO_get_ssl(bio, &ssl);
	if (!ssl) {
		tlshd_log_liberrors();
		goto out_bio_free;
	}

	tlshd_push_handshake(ssl, fd, addr);

	SSL_free(ssl);
out_bio_free:
	BIO_free_all(bio);
}

/*
 * The OpenSSL renegotiation APIs for TLSv1.2 and TLSv1.3 are not the same.
 * Call the appropriate library API based on the TLS version that was
 * initially negotiated.
 */
static void tlshd_renegotiate_session_key(SSL_CTX *ctx, int fd,
					  struct sockaddr *addr)
{
	BIO *bio;
	SSL *ssl;

	/*
	 * NOCLOSE prevents the library from sending a session closure
	 * alert when the file descriptor is closed.
	 */
	bio = BIO_new_fd(fd, BIO_NOCLOSE);
	if (!bio) {
		tlshd_log_liberrors();
		return;
	}

	ssl = SSL_new(ctx);
	if (!ssl) {
		tlshd_log_liberrors();
		goto out_bio_free;
	}
	switch (SSL_version(ssl)) {
	case TLS1_2_VERSION:
		if (!SSL_renegotiate(ssl)) {
			tlshd_log_liberrors();
			tlshd_handshake_complete(fd, -EACCES);
			goto out_ssl_free;
		}
		break;
	case TLS1_3_VERSION:
		if (!SSL_key_update(ssl, SSL_KEY_UPDATE_REQUESTED)) {
			tlshd_log_liberrors();
			tlshd_handshake_complete(fd, -EACCES);
			goto out_ssl_free;
		}
		break;
	default:
		goto out_ssl_free;
	}

	/* Force the library to perform the renegotiation now. */
	tlshd_push_handshake(ssl, fd, addr);

out_ssl_free:
	SSL_free(ssl);
out_bio_free:
	BIO_free_all(bio);
}

void tlshd_load_psk_list(int fd)
{
	socklen_t optlen;
	unsigned int key_size;

	if (getsockopt(fd, SOL_TLS, TLS_KEY, &key_size, &optlen) < 0) {
		tlshd_log_perror("getsockopt TLS_KEY");
		return;
	}
	tlshd_keylist = malloc((key_size + 1) * 4);
	if (!tlshd_keylist) {
		tlshd_log_perror("malloc keylist");
		return;
	}
	if (getsockopt(fd, SOL_TLS, TLS_KEY, &tlshd_keylist, &optlen) < 0) {
		tlshd_log_perror("getsockopt keylist");
		free(tlshd_keylist);
		tlshd_keylist = NULL;
		return;
	}
	tlshd_keylist_size = key_size;
}

/**
 * tlshd_service_socket - Service a kernel socket needing a key operation
 * @fd: socket descriptor of kernel socket to service
 * @addr: remote socket address of @fd
 * @addrlen: length of @addr
 *
 * This function notifies the kernel when the library has finished.
 */
void tlshd_service_socket(int fd, struct sockaddr *addr, socklen_t addrlen)
{
	const SSL_METHOD *method;
	socklen_t optlen;
	char optval[20];
	unsigned char server_mode;
	SSL_CTX *ctx;

	switch (addr->sa_family) {
	case AF_INET:
		tlshd_log_start(addr);
		break;
	default:
		fprintf(stderr, "Unrecognized address family\n");
		return;
	}

	/*
	 * Documentation states that OpenSSL library state does not
	 * survive a fork(2) call, so we initialize the library
	 * here instead of in main().
	 */
	SSL_library_init();
	SSL_load_error_strings();

	optlen = 1;
	if (getsockopt(fd, SOL_TLS, TLS_SERVER_MODE, &server_mode, &optlen)) {
		tlshd_log_perror("getsockopt");
		server_mode = 0;
	}
	if (server_mode)
		method = TLS_server_method();
	else
		method = TLS_client_method();
	if (!method) {
		tlshd_log_liberrors();
		return;
	}

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		tlshd_log_liberrors();
		return;
	}

	if (tlshd_truststore) {
		if (!SSL_CTX_load_verify_locations(ctx, tlshd_truststore, NULL)) {
			tlshd_log_liberrors();
			goto out_ctx_free;
		}
	}

	tlshd_load_psk_list(fd);

	SSL_CTX_set_psk_client_callback(ctx, tlshd_psk_client_cb);

	if (!SSL_CTX_set_min_proto_version(ctx, TLSD_MIN_TLS_VERSION)) {
		tlshd_log_liberrors();
		goto out_ctx_free;
	}

	/*
	 * If TLS_ULP is already set to "tls", we've serviced this socket
	 * before and have already performed an initial handshake. Key
	 * renegotiation is needed instead of a handshake.
	 */
	optlen = sizeof(optval);
	if (!getsockopt(fd, SOL_TCP, TCP_ULP, optval, &optlen)) {
		tlshd_log_perror("getsockopt");
		goto out_ctx_free;
	}
	if (strcmp(optval, "tls") == 0)
		tlshd_renegotiate_session_key(ctx, fd, addr);
	else
		tlshd_initial_handshake(ctx, fd, addr);

out_ctx_free:
	SSL_CTX_free(ctx);
	if (tlshd_keylist)
		free(tlshd_keylist);
}
