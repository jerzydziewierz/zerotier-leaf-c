// SPDX-License-Identifier: Apache-2.0
// Test vector generator. It calls the reference implementation (ZeroTier One
// core: Packet::armor(), Poly1305::compute(), Salsa20::crypt12()) on fixed
// pseudo-random inputs and prints inputs and outputs as hexadecimal text.
// The C leaf must give the same bytes (tests/vectors_test.c).
// Line formats:
//   P <key 32> <message, "-" if empty> <tag 16>
//   S <key 32> <iv 8> <key stream of blocks 0, 1, 2: 192 bytes>
//   T <key 32> <iv 8> <block number, 8 hex digits> <that key stream block: 64 bytes>
//   A <key 32> <encrypt 0|1> <packet before armor> <packet after armor>
#include "Identity.hpp"
#include "Packet.hpp"
#include "Poly1305.hpp"
#include "Salsa20.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace ZeroTier;

static uint64_t g_state = 0x243f6a8885a308d3ULL;

static uint64_t rnd(void) // splitmix64: fixed sequence, the same on every host
{
	uint64_t z = (g_state += 0x9e3779b97f4a7c15ULL);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

static void fill(uint8_t* p, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		p[i] = (uint8_t)rnd();
	}
}

static void hex(const uint8_t* p, size_t n)
{
	if (n == 0) {
		fputs("-", stdout);
	}
	for (size_t i = 0; i < n; i++) {
		printf("%02x", p[i]);
	}
}

static void poly_line(const uint8_t key[32], const uint8_t* m, size_t n)
{
	uint8_t tag[16];
	Poly1305::compute(tag, m, (unsigned int)n, key);
	fputs("P ", stdout);
	hex(key, 32);
	putchar(' ');
	hex(m, n);
	putchar(' ');
	hex(tag, 16);
	putchar('\n');
}

static void armor_line(size_t len, int encrypt)
{
	uint8_t key[32];
	std::vector<uint8_t> plain(len);
	fill(key, 32);
	fill(plain.data(), len);
	if (! encrypt) {
		plain[27] = (uint8_t)((plain[27] & 0xe0) | 0x01); // only HELLO goes unencrypted
	}
	Packet pkt(plain.data(), (unsigned int)len);
	pkt.armor(key, encrypt != 0, false, nullptr, Identity());
	if (pkt.size() != len) {
		fprintf(stderr, "armor changed the length\n");
		exit(1);
	}
	fputs("A ", stdout);
	hex(key, 32);
	printf(" %d ", encrypt);
	hex(plain.data(), len);
	putchar(' ');
	hex((const uint8_t*)pkt.data(), len);
	putchar('\n');
}

int main(void)
{
	uint8_t key[32], msg[2048];

	// Poly1305: every length around the block size, then long messages.
	for (size_t n = 0; n <= 80; n++) {
		fill(key, 32);
		fill(msg, n);
		poly_line(key, msg, n);
	}
	static const size_t longs[] = { 255, 256, 257, 1024, 2020, 2021, 2032, 2047, 2048 };
	for (size_t n : longs) {
		fill(key, 32);
		fill(msg, n);
		poly_line(key, msg, n);
	}
	// Poly1305 edge cases: largest limbs and carries, and results at and
	// just above 2^130 - 5 before the last reduction.
	for (int k = 0; k < 6; k++) {
		memset(key, (k & 1) ? 0xff : 0x00, 16);
		memset(key + 16, (k & 2) ? 0xff : 0x00, 16);
		memset(msg, 0xff, sizeof(msg));
		for (size_t n : { (size_t)16, (size_t)17, (size_t)32, (size_t)48, (size_t)2021 }) {
			if (k >= 4) {
				fill(key, 16); // random r, all-ones message
			}
			poly_line(key, msg, n);
		}
	}
	// r = 2, one block m with (m + 2^128) * 2 = 2^130 - 5 + d for d = 1 and 3.
	memset(key, 0, 32);
	key[0] = 2;
	memset(msg, 0xff, 16);
	msg[0] = 0xfe; // m = 2^128 - 2: h = 2^130 - 4
	poly_line(key, msg, 16);
	msg[0] = 0xff; // m = 2^128 - 1: h = 2^130 - 2
	poly_line(key, msg, 16);
	msg[0] = 0xfd; // m = 2^128 - 3: h = 2^130 - 6, just below
	poly_line(key, msg, 16);
	memset(key + 16, 0xff, 16); // with the largest pad
	poly_line(key, msg, 16);
	msg[0] = 0xfe;
	poly_line(key, msg, 16);

	// Salsa20/12: three consecutive blocks of key stream.
	for (int k = 0; k < 16; k++) {
		uint8_t iv[8], zero[192], ks[192];
		fill(key, 32);
		fill(iv, 8);
		if (k == 0) {
			memset(key, 0, 32);
			memset(iv, 0, 8);
		}
		if (k == 1) {
			memset(key, 0xff, 32);
			memset(iv, 0xff, 8);
		}
		memset(zero, 0, sizeof(zero));
		Salsa20 s20(key, iv);
		s20.crypt12(zero, ks, sizeof(ks));
		fputs("S ", stdout);
		hex(key, 32);
		putchar(' ');
		hex(iv, 8);
		putchar(' ');
		hex(ks, sizeof(ks));
		putchar('\n');
	}

	// Salsa20/12: single blocks with numbers above 255 (a packet never
	// needs them; the block function takes any number).
	for (int k = 0; k < 2; k++) {
		static uint8_t zero[64 * 1026], ks[64 * 1026];
		uint8_t iv[8];
		fill(key, 32);
		fill(iv, 8);
		memset(zero, 0, sizeof(zero));
		Salsa20 s20(key, iv);
		s20.crypt12(zero, ks, sizeof(ks));
		for (unsigned int b : { 255u, 256u, 257u, 511u, 512u, 1025u }) {
			fputs("T ", stdout);
			hex(key, 32);
			putchar(' ');
			hex(iv, 8);
			printf(" %08x ", b);
			hex(ks + 64u * b, 64);
			putchar('\n');
		}
	}

	// Whole packets through Packet::armor(): every length up to 160, then
	// lengths around key stream block ends, then long packets.
	for (size_t len = 28; len <= 160; len++) {
		armor_line(len, 1);
		armor_line(len, 0);
	}
	static const size_t lens[] = { 27 + 192, 27 + 193, 283, 284, 600, 1280, 1400, 1428, 1500, 2000, 2046, 2047, 2048 };
	for (size_t len : lens) {
		for (int rep = 0; rep < 1; rep++) {
			armor_line(len, 1);
			armor_line(len, 0);
		}
	}
	return 0;
}
