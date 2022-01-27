#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#include <getopt.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <zlib.h>
#include <keyutils.h>

static int add_to_keyring(const char *key_ring, const char *key_type,
			  char *identity, unsigned char *key_data, size_t key_len)
{
	key_serial_t user_keyring_id, keyring_id;
	key_serial_t key;
	int err, ret;

	user_keyring_id = keyctl_get_keyring_ID(KEY_SPEC_USER_KEYRING, false);
	if (user_keyring_id < 0) {
		fprintf(stderr, "@u keyring not available, error %d\n", errno);
		return ENODEV;
	}
	printf("adding %s key '%s'\n", key_type, identity);
	key = add_key(key_type, identity, key_data, key_len, user_keyring_id);
	if (key < 0) {
		fprintf(stderr, "adding %s key '%s' to user keyring failed, error %d\n",
			key_type, identity, errno);
		return ENOKEY;
	}
	err = keyctl_setperm(key, KEY_POS_ALL | (KEY_USR_ALL & ~KEY_USR_SETATTR));
	if (err) {
		fprintf(stderr, "setperm %s key '%s' failed, error %d\n",
			key_type, identity, errno);
		ret = errno;
		goto out_revoke;
	}

	keyring_id = find_key_by_type_and_desc("keyring", key_ring, 0);
	if (keyring_id < 0) {
		fprintf(stderr, "'%s' keyring not found, purging key\n", key_ring);
		ret = ENXIO;
		goto out_revoke;
	}
	err = keyctl_link(key, keyring_id);
	if (err) {
		fprintf(stderr, "link %s key to .nvme keyring failed, error %d\n",
			key_type, errno);
		ret = errno;
		goto out_revoke;
	}
	err = keyctl_unlink(key, user_keyring_id);
	if (!err)
		return 0;
out_revoke:
	keyctl_revoke(key);
	return ret;
}

static int derive_tls_key(const EVP_MD *md,
			  const char *hostnqn, const char *subsysnqn,
			  unsigned char *retained_key, int key_len)
{
	EVP_PKEY_CTX *ctx;
	char *psk_identity;
	unsigned char *psk;
	size_t psk_len;
	int err, i;

	psk_identity = malloc(strlen(hostnqn) + strlen(subsysnqn) + 12);
	if (!psk_identity)
		return ENOMEM;

	sprintf(psk_identity, "NVMe0R%02d %s %s", md == EVP_sha256() ? 1 : 2,
		hostnqn, subsysnqn);

	psk = malloc(key_len);
	if (!psk) {
		err = ENOMEM;
		goto out_free_identity;
	}
	psk_len = key_len;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ctx) {
		err = ENOMEM;
		goto out_free_psk;
	}

	err = -ENOKEY;
	if (EVP_PKEY_derive_init(ctx) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_set1_hkdf_key(ctx, retained_key, key_len) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, "tls13 ", 6) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, "nvme-tls-psk", 12) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, psk_identity,
					strlen(psk_identity)) <= 0)
		goto out_free_ctx;

	if (EVP_PKEY_derive(ctx, psk, &psk_len) <= 0) {
		fprintf(stderr, "EVP_KDF_derive failed\n");
	}

	err = add_to_keyring(".tls", "tls", psk_identity, psk, psk_len);
	if (err) {
		printf("TLS keyring not available\ngenerated TLS key\n%s\n",
		       psk_identity);
		for (i = 0; i < psk_len; i++)
			printf("%02x", psk[i]);
		printf("\n");
	}

out_free_ctx:
	EVP_PKEY_CTX_free(ctx);	
out_free_psk:
	free(psk);
out_free_identity:
	free(psk_identity);

	return err;
}

static unsigned char *derive_retained_key(const EVP_MD *md, const char *hostnqn,
					  unsigned char *generated_key,
					  size_t key_len)
{
	unsigned char *retained_key;
	EVP_PKEY_CTX *ctx;
	size_t retained_len;
	char *identity;
	int err, i;

	identity = malloc(strlen(hostnqn) + 4);
	if (!identity)
		return NULL;

	sprintf(identity, "%02d %s",
		md == EVP_sha256() ? 1 : 2, hostnqn);

	retained_key = malloc(key_len);
	if (!retained_key) {
		err = ENOMEM;
		goto out_free_identity;
	}

	retained_len = key_len;
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ctx)
		goto out_free_retained_key;

	err = -ENOKEY;
	if (EVP_PKEY_derive_init(ctx) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_set1_hkdf_key(ctx, generated_key, key_len) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, "tls13 ", 6) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, "HostNQN", 7) <= 0)
		goto out_free_ctx;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, hostnqn, strlen(hostnqn)) <= 0)
		goto out_free_ctx;

	if (EVP_PKEY_derive(ctx, retained_key, &retained_len) <= 0) {
		fprintf(stderr, "EVP_KDF derive failed\n");
		err = ENOKEY;
		goto out_free_ctx;
	}

	err = add_to_keyring(".nvme", "psk", identity, retained_key, retained_len);
	if (err) {
		fprintf(stderr, ".nvme keyring not available, error %d\n", err);
		printf("generated NVMe PSK\n%s\n", identity);
		for (i = 0; i < retained_len; i++)
			printf("%02x", retained_key[i]);
		printf("\n");
	}

out_free_ctx:
	EVP_PKEY_CTX_free(ctx);
out_free_retained_key:
	if (err) {
		free(retained_key);
		retained_key = NULL;
	}
out_free_identity:
	free(identity);
	return retained_key;
}

static int import_key(const char *keyfile, const char *hostnqn,
		      const char *subsysnqn)
{
	int fd, err;
	struct stat st;
	char *key_buf, *ptr;
	unsigned char decoded_key[128];
	unsigned char *retained_key;
	unsigned int hmac;
	size_t len, key_len;
	u_int32_t crc = 0, key_crc;
	const EVP_MD *md;

	fd = open(keyfile, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return errno;
	}
	if (fstat(fd, &st) < 0) {
		err = errno;
		perror("fstat");
		close(fd);
		return err;
	}
	key_buf = malloc(st.st_size);
	if (!key_buf) {
		perror("malloc");
		close(fd);
		return ENOMEM;
	}
	len = read(fd, key_buf, st.st_size);
	close(fd);
	if (len < st.st_size) {
		perror("read");
		err = EINVAL;
		goto out_free;
	}

	if (sscanf(key_buf, "NVMeTLSkey-1:%02x:*s", &hmac) != 1) {
		fprintf(stderr, "Invalid key header '%s'\n", key_buf);
		err = EINVAL;
		goto out_free;
	}
	switch (hmac) {
	case 1:
		md = EVP_sha256();
		break;
	case 2:
		md = EVP_sha384();
		break;
	default:
		fprintf(stderr, "Invalid key hmac %d\n", hmac);
		err = EINVAL;
		goto out_free;
	}

	ptr = strrchr(key_buf, ':');
	if (!ptr) {
		fprintf(stderr, "Missing trailing colon in key '%s'\n",
			key_buf);
		err = EINVAL;
		free(key_buf);
		goto out_free;
	}
	*ptr = '\0';
	ptr = key_buf + 16;
	err = EVP_DecodeBlock(decoded_key, (const unsigned char *)ptr,
			      strlen(ptr));
	if (err < 0) {
		fprintf(stderr, "Base64 decoding failed (%s, len %lu, error %d)\n",
			key_buf, strlen(key_buf), err);
		goto out_free;
	}
	key_len = err;
	key_len -= 4;
	if (key_len != 32 && key_len != 48) {
		fprintf(stderr, "Invalid key length %lu\n", key_len);
		err = EINVAL;
		goto out_free;
	}

	crc = crc32(crc, decoded_key, key_len);
	key_crc = ((u_int32_t)decoded_key[key_len]) |
		((u_int32_t)decoded_key[key_len + 1] << 8) |
		((u_int32_t)decoded_key[key_len + 2] << 16) |
		((u_int32_t)decoded_key[key_len + 3] << 24);
	if (key_crc != crc) {
		fprintf(stderr, "CRC mismatch (key %08x, crc %08x)\n",
			key_crc, crc);
		err = EINVAL;
		goto out_free;
	}
	printf("Valid NVMe TLS key (HMAC %d, length %ld, CRC %08x)\n",
	       hmac, key_len, crc);
	
	err = 0;

	/* Derive retained key */
	retained_key = derive_retained_key(md, hostnqn,
					   decoded_key, key_len);
	if (!retained_key) {
		fprintf(stderr, "Failed to derive retained key\n");
		err = ENOKEY;
		goto out_free;
	}

	/* Derive TLS key */
	err  = derive_tls_key(md, hostnqn, subsysnqn, retained_key, key_len);
	if (err) {
		fprintf(stderr, "Failed to generate TLS key, error %d\n", err);
	}
	free(retained_key);
out_free:
	free(key_buf);
	return err;
}

static const char *optstring = "hk:ln:s:";
static const struct option longopts[] = {
	{ "list-keys",		no_argument,		0, 'l' },
	{ "hostnqn",		required_argument,	0, 'n' },
	{ "subsysnqn",		required_argument,	0, 's' },
	{ "key-file",		required_argument,	0, 'k' },
	{ NULL,			0,			0, 0 },
};

int main(int argc, char **argv)
{
	const char *progname = basename(argv[0]);
	const char *key_file, *hostnqn = NULL, *subnqn = NULL;
	char c;
	int err;

	while ((c = getopt_long(argc, argv, optstring, longopts, NULL)) != -1) {
		switch (c) {
		case 'k':
			key_file = optarg;
			break;
		case 'n':
			hostnqn = optarg;
			break;
		case 's':
			subnqn = optarg;
			break;
		case 'l':
#if 0
			err = list_key(void);
#endif
			break;
		case 'h':
		default:
			fprintf(stderr, "usage: %s [-klns]\n", progname);
		}
	}

	if (key_file) {
		if (!hostnqn) {
			fprintf(stderr, "Missing host NQN\n");
			return 1;
		}
		err = import_key(key_file, hostnqn, subnqn);
	}
	return err ? 1 : 0;
}
