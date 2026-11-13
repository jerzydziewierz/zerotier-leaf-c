/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Host test: the cryptographic code against test vectors from the reference
 * (tests/vectors/reference.txt, made by tests/oracle/gen.sh).
 *   P: Poly1305 tag.  S: Salsa20/12 key stream blocks 0, 1, 2.
 *   T: one Salsa20/12 key stream block with a given block number.
 *   A: whole packet. ztl_auth_seal() must give the reference's bytes;
 *      ztl_auth_open() must accept them and give the plain packet back, and
 *      must refuse the packet, without changing it, after any one-bit change
 *      outside the hop count, with a wrong length and with a wrong key.
 *   Z: packet payload and its LZ4 block. ztl_lz4_decode() must give the
 *      payload, in a buffer of exactly that size, and must refuse a buffer
 *      that is one byte smaller and a block that is one byte shorter.
 *   M: Ethernet address of a node on a network (ztl_mac_of()).
 *   D: dictionary made by the reference, a key, and its value or "none"
 *      (ztl_dict_get(); also with a buffer that is one byte too small).
 * Usage: vectors_test <file>. Exit status 0 only if every vector passes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "leaf_internal.h"
#include "ztl/lz4.h"

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

static void test_salsa_block(char *s)
{
	uint8_t key[32], iv[8], no[4], want[64], got[64];
	const size_t kl = field(&s, key, sizeof(key));
	const size_t il = field(&s, iv, sizeof(iv));
	const size_t nl = field(&s, no, sizeof(no));
	const size_t wl = field(&s, want, sizeof(want));

	CHECK(kl == 32 && il == 8 && nl == 4 && wl == 64, "Salsa20 block vector format");
	const uint32_t block = ((uint32_t)no[0] << 24) | ((uint32_t)no[1] << 16) | ((uint32_t)no[2] << 8) | no[3];

	ztl_salsa2012_block(got, key, iv, block);
	CHECK(memcmp(got, want, 64) == 0, "Salsa20/12 block %lu differs", (unsigned long)block);
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

static void test_lz4(char *s)
{
	static uint8_t plain[ZTL_PKT_MAX], comp[ZTL_PKT_MAX];
	const size_t pl = field(&s, plain, sizeof(plain));
	const size_t cl = field(&s, comp, sizeof(comp));

	CHECK(pl > 64 && cl >= 1 && cl < pl, "LZ4 vector format");
	/* Buffers of the exact sizes, from the heap: the address sanitizer
	 * then sees any access outside them. */
	uint8_t *src = malloc(cl), *dst = malloc(pl), *shorter = malloc(cl - 1u + 1u);

	if (src == NULL || dst == NULL || shorter == NULL) {
		exit(2);
	}
	memcpy(src, comp, cl);
	CHECK(ztl_lz4_decode(dst, pl, src, cl) == pl, "LZ4: wrong length (%zu bytes)", pl);
	CHECK(memcmp(dst, plain, pl) == 0, "LZ4: decoded bytes differ (%zu bytes)", pl);
	CHECK(ztl_lz4_decode(dst, pl - 1u, src, cl) == 0, "LZ4: output buffer one byte too small accepted");
	memcpy(shorter, comp, cl - 1u);
	CHECK(ztl_lz4_decode(dst, pl, shorter, cl - 1u) == 0, "LZ4: block one byte too short accepted");
	free(src);
	free(dst);
	free(shorter);
}

static void test_mac(char *s)
{
	uint8_t addr[5], nwid[8], want[6], got[6];
	const size_t al = field(&s, addr, sizeof(addr));
	const size_t nl = field(&s, nwid, sizeof(nwid));
	const size_t wl = field(&s, want, sizeof(want));

	CHECK(al == 5 && nl == 8 && wl == 6, "MAC vector format");
	ztl_mac_of(got, addr, nwid);
	CHECK(memcmp(got, want, 6) == 0, "Ethernet address differs");
}

static void test_dict(char *s)
{
	static uint8_t dict[ZTL_PKT_MAX], want[ZTL_PKT_MAX], got[ZTL_PKT_MAX];
	uint8_t key[8];
	const size_t dl = field(&s, dict, sizeof(dict));
	const size_t kl = field(&s, key, sizeof(key));
	int absent = 0;
	size_t wl = 0;

	while (*s == ' ') {
		s++;
	}
	if (strncmp(s, "none", 4) == 0) {
		absent = 1;
	} else {
		wl = field(&s, want, sizeof(want));
	}
	CHECK(kl >= 1, "dictionary vector format");
	/* The dictionary in a heap block of its exact size (see test_lz4). */
	uint8_t *d = malloc(dl ? dl : 1u), *out = malloc(wl ? wl : 1u);

	if (d == NULL || out == NULL) {
		exit(2);
	}
	memcpy(d, dict, dl);
	const int r = ztl_dict_get(d, dl, key, kl, got, sizeof(got));

	if (absent) {
		CHECK(r == -1, "dictionary: value found for an absent key");
	} else {
		CHECK(r == (int)wl && memcmp(got, want, wl) == 0, "dictionary: value differs (%d, expected %zu bytes)", r, wl);
		CHECK(ztl_dict_get(d, dl, key, kl, out, wl) == (int)wl && memcmp(out, want, wl) == 0,
		      "dictionary: value differs in a buffer of its exact size");
		if (wl > 0) {
			CHECK(ztl_dict_get(d, dl, key, kl, out, wl - 1u) == -1,
			      "dictionary: buffer one byte too small accepted");
		}
	}
	free(d);
	free(out);
}

int main(int argc, char **argv)
{
	static char line[LINE_MAX_LEN];
	unsigned long np = 0, ns = 0, na = 0, nz = 0, nm = 0, nd = 0;

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
		case 'T': test_salsa_block(line + 1); ns++; break;
		case 'A': test_armor(line + 1); na++; break;
		case 'Z': test_lz4(line + 1); nz++; break;
		case 'M': test_mac(line + 1); nm++; break;
		case 'D': test_dict(line + 1); nd++; break;
		case '#': break;
		default: fprintf(stderr, "line %lu: unknown kind\n", g_line); return 2;
		}
	}
	fclose(f);
	printf("vectors: %lu Poly1305, %lu Salsa20/12, %lu packets, %lu LZ4, %lu MAC, %lu dictionary; %lu checks, %lu failed\n", np, ns,
	       na, nz, nm, nd, g_checks, g_fail);
	/* A file without vectors is a failure, not a pass. */
	return (g_fail == 0 && np > 0 && ns > 0 && na > 0 && nz > 0 && nm > 0 && nd > 0) ? 0 : 1;
}
