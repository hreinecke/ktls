// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Oracle and/or its affiliates.
 *
 * Handle a request for a TLS handshake on behalf of an
 * in-kernel TLS consumer.
 */

#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include <arpa/inet.h>
#include <netinet/ip.h>

#include <openssl/err.h>

#include "tlshd.h"

/**
 * tlshd_log_start - Emit "start of handshake" notification
 * @sap: remote address to log
 *
 */
void tlshd_log_start(const struct sockaddr *sap)
{
	char dst[INET_ADDRSTRLEN];
	struct in_addr src = ((struct sockaddr_in *)sap)->sin_addr;

	if (inet_ntop(AF_INET, &src, dst, sizeof(dst)))
		syslog(LOG_INFO, "Starting handshake with %s\n", dst);
}

/**
 * tlshd_log_success - Emit "handshake successful" notification
 * @sap: remote address to log
 *
 */
void tlshd_log_success(const struct sockaddr *sap)
{
	char dst[INET_ADDRSTRLEN];
	struct in_addr src = ((struct sockaddr_in *)sap)->sin_addr;

	if (inet_ntop(AF_INET, &src, dst, sizeof(dst)))
		syslog(LOG_INFO, "Handshake with %s was successful\n", dst);
}

/**
 * tlshd_log_failure - Emit "handshake failed" notification
 * @sap: remote address to log
 *
 */
void tlshd_log_failure(const struct sockaddr *sap)
{
	char dst[INET_ADDRSTRLEN];
	struct in_addr src = ((struct sockaddr_in *)sap)->sin_addr;

	if (inet_ntop(AF_INET, &src, dst, sizeof(dst)))
		syslog(LOG_INFO, "Handshake with %s failed\n", dst);
}

/**
 * tlshd_log_perror - Emit "system call failed" notification
 * @sap: remote address to log
 *
 */
void tlshd_log_perror(const char *prefix)
{
	syslog(LOG_ERR, "%s: %s\n", prefix, strerror(errno));
}

static int tlshd_log_error_cb(const char *str, size_t len, void *u)
{
	syslog(LOG_ERR, "%.*s\n", (int)len, str);
}

/**
 * tlshd_log_liberrors - Emit "library call failed" notification
 * @sap: remote address to log
 *
 */
void tlshd_log_liberrors(void)
{
	ERR_print_errors_cb(tlshd_log_error_cb, NULL);
}

/**
 * tlshd_log_init - Initialize audit logging
 * @progname: NUL-terminated string containing program name
 * @debug: if true, log to stderr as well
 *
 */
void tlshd_log_init(const char *progname, bool debug)
{ 
	int option;

	option = LOG_NDELAY;
	if (debug)
		option |= LOG_PERROR;
	openlog(progname, option, LOG_AUTH);
}

/**
 * tlshd_log_close - Release audit logging resources
 *
 */
void tlshd_log_close(void)
{
	closelog();
}
