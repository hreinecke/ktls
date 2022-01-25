/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Oracle and/or its affiliates.
 *
 * Handle a request for a TLS handshake on behalf of an
 * in-kernel TLS consumer.
 */

#define ARRAY_SIZE(a)		(sizeof(a) / sizeof((a)[0]))

extern char *tlshd_truststore;

/* handshake.c */
extern void tlshd_service_socket(int fd, struct sockaddr *addr,
				 socklen_t addrlen);

/* log.c */
extern void tlshd_log_start(const struct sockaddr *sap);
extern void tlshd_log_success(const struct sockaddr *sap);
extern void tlshd_log_failure(const struct sockaddr *sap);
extern void tlshd_log_perror(const char *prefix);
extern void tlshd_log_liberrors(void);
extern void tlshd_log_init(const char *progname, bool debug);
extern void tlshd_log_close(void);
