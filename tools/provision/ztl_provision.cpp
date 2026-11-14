/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
/*
 * Provisioning tool (host, secure environment): make what the leaf needs
 * from the identities, with the code of the reference.
 *   ztl_provision <own.secret> <peer.public>...
 * Output, one item per line:
 *   self <address>            own address, 10 hexadecimal digits
 *   pub <128 digits>          own public key (sent in HELLO; not a secret)
 *   peer <address> <64 digits> one line per peer: its address and the first
 *                             32 bytes of the key agreed with it (SECRET)
 * The pairwise key is SHA-512 of the Curve25519 result (ECC::agree() of the
 * reference); the leaf uses bytes 0 .. 31. The own secret stays on the host.
 */
#include <cstdio>
#include <cstring>

#include "Constants.hpp"
#include "Identity.hpp"
#include "Utils.hpp"

using namespace ZeroTier;

static bool read_identity(const char *path, Identity &id)
{
	char text[1024];
	FILE *f = fopen(path, "r");

	if (!f) {
		return false;
	}
	const size_t n = fread(text, 1, sizeof(text) - 1, f);

	fclose(f);
	text[n] = 0;
	text[strcspn(text, "\r\n")] = 0;
	const bool ok = id.fromString(text);

	Utils::burn(text, sizeof(text));
	return ok;
}

static void hex(const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		printf("%02x", p[i]);
	}
}

int main(int argc, char **argv)
{
	Identity own;

	if (argc < 3) {
		fprintf(stderr, "usage: ztl_provision <own.secret> <peer.public>...\n");
		return 64;
	}
	if (!read_identity(argv[1], own) || !own.hasPrivate()) {
		fprintf(stderr, "cannot read a secret identity from %s\n", argv[1]);
		return 66;
	}
	printf("self %.10llx\npub ", (unsigned long long)own.address().toInt());
	hex(own.publicKey().data, ZT_ECC_PUBLIC_KEY_SET_LEN);
	printf("\n");
	for (int i = 2; i < argc; i++) {
		Identity peer;
		uint8_t key[ZT_SYMMETRIC_KEY_SIZE];

		if (!read_identity(argv[i], peer) || !peer.locallyValidate() || !own.agree(peer, key)) {
			fprintf(stderr, "cannot use the identity in %s\n", argv[i]);
			return 66;
		}
		printf("peer %.10llx ", (unsigned long long)peer.address().toInt());
		hex(key, 32);
		printf("\n");
		Utils::burn(key, sizeof(key));
	}
	return 0;
}
