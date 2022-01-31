/*
 * ktls_netlink.c - dump TLS netlink events
 *
 * Copyright (C) 2022 Hannes Reinecke <hare@suse.de>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 *
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <linux/netlink.h>

#include <keyutils.h>

#include "ktls.h"

key_serial_t *ktls_key_list;
int ktls_key_num;

#define NETLINK_TLS 24

#define TLS_NL_MAGIC 0x544C
#define TLS_NL_VERSION 0x01
#define TLS_NL_CLIENT_MODE 0x00
#define TLS_NL_SERVER_MODE 0x01

int ktls_verbose = 0;

struct tls_nl_msg {
	u_int16_t magic;
	u_int8_t version;
	u_int8_t mode;
	u_int32_t fd;
	u_int32_t key_num;
	u_int32_t key_serial[0];
};

int main(int argc, char *argv[])
{
	int sock;
	struct sockaddr_nl snl;
	int retval;

	if (getuid() != 0) {
		printf("need to be root, exit\n");
		exit(1);
	}

	memset(&snl, 0x00, sizeof(struct sockaddr_nl));
	snl.nl_family = AF_NETLINK;
	snl.nl_pid = getpid();
	snl.nl_groups = 0xffffffff;

	sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_TLS);
	if (sock == -1) {
		printf("error getting socket, exit\n");
		exit(1);
	}

	retval = bind(sock, (struct sockaddr *) &snl,
		      sizeof(struct sockaddr_nl));
	if (retval < 0) {
		printf("bind failed, exit\n");
		goto exit;
	}

	while (1) {
		static unsigned char buffer[512];
		struct nlmsghdr *nhdr;
		struct tls_nl_msg *tls_msg;
		struct ktls_session *session;
		bool is_server = false;
		ssize_t buflen;
		int i;

		buflen = recv(sock, &buffer, sizeof(buffer), 0);
		if (buflen <  0) {
			printf("error receiving message\n");
			continue;
		}

		if ((size_t)buflen > sizeof(buffer)-1)
			buflen = sizeof(buffer)-1;

		for (i = 0; i < buflen; i++) {
			fprintf(stdout,"%02x ",buffer[i]);
			if ((i % 8) == 7)
				fprintf(stdout,"\n");
		}

		nhdr = (struct nlmsghdr *)buffer;
		tls_msg = (struct tls_nl_msg *)(++nhdr);
		if (tls_msg->magic != TLS_NL_MAGIC) {
			fprintf(stderr,"Invalid TLS Netlink message %02x\n",
				tls_msg->magic);
			continue;
		}

		if (tls_msg->magic != TLS_NL_MAGIC) {
			fprintf(stderr, "Invalid TLS Netlink magic %d\n",
				tls_msg->magic);
			continue;
		}

		fprintf(stdout, "fd: %d\n", tls_msg->fd);
		fprintf(stdout, "number of keys: %d\n", tls_msg->key_num);
		for (i = 0; i < tls_msg->key_num; i++) {
			int err;
			char *key_id;

			fprintf(stdout, "key serial %d: %08x\n",
				i, tls_msg->key_serial[i]);
			err = keyctl_describe_alloc(tls_msg->key_serial[i],
						    &key_id);
			if (err < 0) {
				fprintf(stderr, "Invalid key serial %08x\n",
					tls_msg->key_serial[i]);
				continue;
			}
			fprintf(stdout, "Key identity: %s\n", key_id);
			free(key_id);
		}
		if (tls_msg->fd < 0) {
			fprintf(stdout, "No tls filedescriptor\n");
			continue;
		}
		ktls_key_list = malloc(tls_msg->key_num * sizeof(key_serial_t));
		if (!ktls_key_list) {
			fprintf(stderr, "Failed to allocate ktls key list\n");
			goto close_and_continue;
		}
		memcpy(ktls_key_list, tls_msg->key_serial,
		       tls_msg->key_num * sizeof(key_serial_t));
		ktls_key_num = tls_msg->key_num;
		is_server = tls_msg->mode == TLS_NL_SERVER_MODE;
		session = ktls_create_session(is_server);
		if (!session) {
			fprintf(stderr, "Failed to create ktls session\n");
			goto free_and_continue;
		}
		if (ktls_set_psk_session(session))
			goto destroy_and_continue;

		ktls_handshake_tls(session, tls_msg->fd);
	destroy_and_continue:
		ktls_destroy_session(session);
	free_and_continue:
		free(ktls_key_list);
		ktls_key_list = NULL;
		ktls_key_num = 0;
	close_and_continue:
		close(tls_msg->fd);
	}

exit:
	close(sock);
	exit(1);
}
