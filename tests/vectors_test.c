/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Host test: the cryptographic code against test vectors from the reference
 * (tests/vectors/reference.txt, made by tests/oracle/gen.sh).
 *   P: Poly1305 tag.  S: Salsa20/12 key stream blocks 0, 1, 2.
 *   A: whole packet. ztl_auth_seal() must give the reference's bytes;
 *      ztl_auth_open() must accept them and give the plain packet back, and
 *      must refuse the packet, without changing it, after any one-bit change
 *      outside the hop count, with a wrong length and with a wrong key.
 * Usage: vectors_test <file>. Exit status 0 only if every vector passes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ztl/node.h"

#define LINE_MAX_LEN 20000u

static unsigned long g_fail, g_checks;

#define CHECK(cond, ...) \
	do { \
		g_checks++; \
		if (!(cond)) { \
			g_fail++; \
			fprintf(stderr, "line %lu: ", g_line); \
			fprintf(stderr, __VA_ARGS__); \
			fputc('\n', stderr); \
		} \
	} while (0)

static unsigned long g_line;

static int hexval(int c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	return -1;
}

/* Parse one hexadecimal field ("-" is the empty field). Returns its length
 * in bytes and moves *s after it, or stops the program. */
static size_t field(char **s, uint8_t *out, size_t max)
{
	char *p = *s;
	size_t n = 0;

	while (*p == ' ') {
		p++;
	}
	if (*p == '-') {
		p++;
	} else {
		while (hexval(p[0]) >= 0 && hexval(p[1]) >= 0) {
			if (n == max) {
				fprintf(stderr, "line %lu: field too long\n", g_line);
				exit(2);
			}
			out[n++] = (uint8_t)(hexval(p[0]) * 16 + hexval(p[1]));
			p += 2;
		}
	}
	if (*p != ' ' && *p != '\n' && *p != '\0') {
		fprintf(stderr, "line %lu: bad character\n", g_line);
		exit(2);
	}
	*s = p;
	return n;
}

static void test_poly(char *s)
{
	static uint8_t key[32], msg[ZTL_PKT_MAX], want[16], got[16];
	const size_t kl = field(&s, key, sizeof(key));
	const size_t n = field(&s, msg, sizeof(msg));
	const size_t tl = field(&s, want, sizeof(want));

	CHECK(kl == 32 && tl == 16, "Poly1305 vector format");
	ztl_poly1305(got, msg, n, key);
	CHECK(memcmp(got, want, 16) == 0, "Poly1305 tag differs (message of %zu bytes)", n);
}

static void test_salsa(char *s)
{
	uint8_t key[32], iv[8], want[192], got[64];
	const size_t kl = field(&s, key, sizeof(key));
	const size_t il = field(&s, iv, sizeof(iv));
	const size_t wl = field(&s, want, sizeof(want));

	CHECK(kl == 32 && il == 8 && wl == 192, "Salsa20 vector format");
	for (uint32_t b = 0; b < 3u; b++) {
		ztl_salsa2012_block(got, key, iv, b);
		CHECK(memcmp(got, &want[64u * b], 64) == 0, "Salsa20/12 block %u differs", (unsigned)b);
	}
	/* The XOR function starts at block 1. */
	uint8_t buf[128];

	memset(buf, 0, sizeof(buf));
	ztl_salsa2012_xor(buf, 100, key, iv);
	CHECK(memcmp(buf, &want[64], 100) == 0, "Salsa20/12 XOR differs");
	CHECK(buf[100] == 0, "Salsa20/12 XOR wrote past its length");
}

/* One changed packet must be refused and left as it is. */
static void expect_refused(const uint8_t *key, const uint8_t *pkt, size_t len, int enc, const char *what, size_t at)
{
	static uint8_t buf[ZTL_PKT_MAX];

	memcpy(buf, pkt, len);
	const int r = ztl_auth_open(key, buf, len, enc);

	CHECK(r == 0, "accepted with %s (%zu)", what, at);
	CHECK(memcmp(buf, pkt, len) == 0, "refused packet was changed, %s (%zu)", what, at);
}

static void test_armor(char *s)
{
	static uint8_t key[32], plain[ZTL_PKT_MAX], want[ZTL_PKT_MAX], buf[ZTL_PKT_MAX];
	const size_t kl = field(&s, key, sizeof(key));
	size_t len, wl;
	int enc;

	/* The encrypt field is one digit, not a hexadecimal byte pair. */
	while (*s == ' ') {
		s++;
	}
	enc = (*s == '1');
	CHECK(*s == '0' || *s == '1', "packet vector format (encrypt)");
	s++;
	len = field(&s, plain, sizeof(plain));
	wl = field(&s, want, sizeof(want));
	CHECK(kl == 32 && len == wl && len >= ZTL_PKT_MIN, "packet vector format");

	/* Seal gives the reference's bytes. */
	memcpy(buf, plain, len);
	ztl_auth_seal(key, buf, len, enc);
	CHECK(memcmp(buf, want, len) == 0, "sealed packet differs (%zu bytes, encrypt %d)", len, enc);

	/* Open accepts the reference's packet and gives the plain payload. */
	memcpy(buf, want, len);
	CHECK(ztl_auth_open(key, buf, len, enc) == 1, "reference packet refused (%zu bytes, encrypt %d)", len, enc);
	CHECK(memcmp(buf, want, ZTL_PKT_IDX_VERB) == 0, "open changed the header");
	CHECK(memcmp(&buf[ZTL_PKT_IDX_VERB], &plain[ZTL_PKT_IDX_VERB], len - ZTL_PKT_IDX_VERB) == 0,
	      "opened payload differs");

	/* One-bit changes: every bit of the first 64 bytes, then every 7th byte. */
	for (size_t i = 0; i < len; i = (i < 64u) ? i + 1u : i + 7u) {
		for (unsigned int bit = 0; bit < 8u; bit++) {
			if (!enc && i == ZTL_PKT_IDX_VERB && bit < 5u) {
				continue; /* the caller may give only HELLO without decryption */
			}
			memcpy(buf, want, len);
			buf[i] ^= (uint8_t)(1u << bit);
			if (i == ZTL_PKT_IDX_FLAGS && bit < 3u) {
				/* The hop count is not protected: relays change it. */
				CHECK(ztl_auth_open(key, buf, len, enc) == 1, "refused after a hop count change");
			} else {
				expect_refused(key, buf, len, enc, "one bit changed in byte", i);
			}
		}
	}
	if (len > ZTL_PKT_MIN) {
		expect_refused(key, want, len - 1u, enc, "length shorter by one", len);
	}
	key[31] ^= 0x80u;
	expect_refused(key, want, len, enc, "another key (byte 31)", len);
	key[31] ^= 0x80u;
	key[0] ^= 0x01u;
	expect_refused(key, want, len, enc, "another key (byte 0)", len);
}

int main(int argc, char **argv)
{
	static char line[LINE_MAX_LEN];
	unsigned long np = 0, ns = 0, na = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <vector file>\n", argv[0]);
		return 2;
	}
	FILE *f = fopen(argv[1], "r");

	if (f == NULL) {
		perror(argv[1]);
		return 2;
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		g_line++;
		if (strchr(line, '\n') == NULL) {
			fprintf(stderr, "line %lu: too long\n", g_line);
			return 2;
		}
		switch (line[0]) {
		case 'P': test_poly(line + 1); np++; break;
		case 'S': test_salsa(line + 1); ns++; break;
		case 'A': test_armor(line + 1); na++; break;
		case '#': break;
		default: fprintf(stderr, "line %lu: unknown kind\n", g_line); return 2;
		}
	}
	fclose(f);
	printf("vectors: %lu Poly1305, %lu Salsa20/12, %lu packets; %lu checks, %lu failed\n", np, ns, na, g_checks, g_fail);
	/* A file without vectors is a failure, not a pass. */
	return (g_fail == 0 && np > 0 && ns > 0 && na > 0) ? 0 : 1;
}
