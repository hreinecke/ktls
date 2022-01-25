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
#include <stdio.h>
#include <poll.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "tlshd.h"

/* Not yet included in uapi headers */
#define AF_TLSH			(46)

#define TLSH_LISTENER_BACKLOG	(20)

static const char *optstring = "dhT:";
static const struct option longopts[] = {
	{ "debug",		no_argument,		0, 'd' },
	{ "help",		no_argument,		0, 'h' },
	{ "trust-store",	required_argument,	0, 'T' },
	{ NULL,			0,			0, 0 }
};

static void tlshd_parse_poll_result(struct pollfd *fds, nfds_t nfds)
{
	struct sockaddr addr;
	socklen_t addrlen;
	pid_t pid;
	int i, fd;

	for (i = 0; i < nfds; i++) {
		if (!(fds[i].revents & POLLIN))
			continue;

		fd = accept(fds[i].fd, &addr, &addrlen);
		if (fd == -1) {
			/*
			 * Linux accept(2) passes already-pending network
			 * errors on the new socket as an error code from
			 * accept(2).
			 */
			tlshd_log_perror("accept");
			continue;
		}

		pid = fork();
		if (!pid) {
			tlshd_service_socket(fd, &addr, addrlen);
			tlshd_log_close();
			exit(EXIT_SUCCESS);
		} else
			close(fd);
	}
}

int main(int argc, char **argv)
{
	union {
		struct sockaddr_in	sin;
		struct sockaddr_in6	sin6;
		struct sockaddr		sa;
	} u;
	struct pollfd fds[2];
	char *progname;
	bool debug;
	int c, i;

	debug = false;
	tlshd_truststore = NULL;
	progname = basename(argv[0]);
	while ((c = getopt_long(argc, argv, optstring, longopts, NULL)) != -1) {
		switch (c) {
		case 'd':
			debug = true;
			break;
		case 'T':
			tlshd_truststore = optarg;
			break;
		case 'h':
		default:
			fprintf(stderr, "usage: %s [-dT]\n", progname);
		}
	}

	tlshd_log_init(progname, debug);

	fds[0].fd = socket(AF_TLSH, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (fds[0].fd == -1) {
		tlshd_log_perror("socket");
		return EXIT_FAILURE;
	}

	fds[1].fd = socket(AF_TLSH, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (fds[1].fd == -1) {
		tlshd_log_perror("socket");
		goto out_close0;
	}

	u.sin.sin_family = AF_INET;
	u.sin.sin_addr.s_addr = INADDR_ANY;
	if (bind(fds[0].fd, &u.sa, sizeof(u.sin))) {
		tlshd_log_perror("bind");
		goto out_close1;
	}
	if (listen(fds[0].fd, TLSH_LISTENER_BACKLOG)) {
		tlshd_log_perror("listen");
		goto out_close1;
	}

	u.sin6.sin6_family = AF_INET6;
	u.sin6.sin6_addr = in6addr_any;
	if (bind(fds[1].fd, &u.sa, sizeof(u.sin6))) {
		tlshd_log_perror("bind");
		goto out_close1;
	}
	if (listen(fds[1].fd, TLSH_LISTENER_BACKLOG)) {
		tlshd_log_perror("listen");
		goto out_close1;
	}

	while (1) {
		for (i = 0; i < ARRAY_SIZE(fds); i++) {
			fds[i].events = POLLIN;
			fds[i].revents = 0;
		}
		if (poll(fds, ARRAY_SIZE(fds), -1)) {
			tlshd_log_perror("poll");
			goto out_close1;
		}
		tlshd_parse_poll_result(fds, ARRAY_SIZE(fds));
	}

out_close1:
	close(fds[1].fd);
out_close0:
	close(fds[0].fd);
	tlshd_log_close();
	return EXIT_SUCCESS;
}
