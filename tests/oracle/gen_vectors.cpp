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
//   Z <packet payload> <the same payload after Packet::compress() (one LZ4 block)>
//   M <address 5> <network ID 8> <Ethernet address 6 of that node on that network>
//   D <dictionary> <key, as bytes> <value, "-" if empty; the word "none" if the key is absent>
#include "Dictionary.hpp"
#include "Identity.hpp"
#include "MAC.hpp"
#include "Packet.hpp"
#include "Poly1305.hpp"
#include "Salsa20.hpp"

#include <algorithm>
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

// One payload through Packet::compress(). No line if the reference would
// send it as it is (64 bytes or less, or not smaller after compression).
static void lz4_line(const std::vector<uint8_t>& body)
{
	std::vector<uint8_t> plain(28 + body.size());
	fill(plain.data(), 28);
	plain[27] &= 0x1f;
	memcpy(plain.data() + 28, body.data(), body.size());
	Packet pkt(plain.data(), (unsigned int)plain.size());
	if (! pkt.compress()) {
		return;
	}
	fputs("Z ", stdout);
	hex(body.data(), body.size());
	putchar(' ');
	hex((const uint8_t*)pkt.data() + 28, pkt.size() - 28);
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

	// LZ4 (new kinds of vectors go below this line: one random stream, so
	// the vectors above stay as they are).
	// Runs of one byte: long matches at offset 1, lengths that need extension bytes.
	for (size_t n : { (size_t)65, (size_t)66, (size_t)83, (size_t)84, (size_t)300, (size_t)339, (size_t)340, (size_t)1000, (size_t)2020 }) {
		lz4_line(std::vector<uint8_t>(n, (uint8_t)rnd()));
	}
	// Repeated patterns: matches that overlap their own output.
	for (size_t period : { (size_t)2, (size_t)3, (size_t)4, (size_t)5, (size_t)7, (size_t)8, (size_t)13, (size_t)16, (size_t)31, (size_t)64, (size_t)255, (size_t)256, (size_t)300 }) {
		std::vector<uint8_t> v(2020);
		fill(v.data(), period);
		for (size_t i = period; i < v.size(); i++) {
			v[i] = v[i - period];
		}
		lz4_line(v);
	}
	// Text in the form of a network configuration, with binary values.
	for (int k = 0; k < 12; k++) {
		std::vector<uint8_t> v;
		static const char* keys[] = { "v=7\n", "nwid=c0ffee0001000001\n", "ts=19a7c3f5e21\n", "r=2a\n", "id=1a2b3c4d5e\n", "f=6\n", "ml=20\n", "t=0\n", "mtu=500\n", "n=testnet\n", "ctmd=1b7740\n" };
		const size_t want = 100 + (size_t)(rnd() % 1900);
		while (v.size() < want) {
			const char* t = keys[rnd() % 11];
			v.insert(v.end(), t, t + strlen(t));
			if ((rnd() & 3) == 0) {
				const size_t bin = (size_t)(rnd() % 120);
				v.push_back('C');
				v.push_back('=');
				for (size_t i = 0; i < bin; i++) {
					v.push_back((uint8_t)((rnd() & 1) ? rnd() : 0));
				}
				v.push_back('\n');
			}
		}
		v.resize(std::min(v.size(), (size_t)2020));
		lz4_line(v);
	}
	// Random bytes with repeated stretches: literal runs of every size between matches.
	for (int k = 0; k < 24; k++) {
		std::vector<uint8_t> v(66 + (size_t)(rnd() % 1955));
		fill(v.data(), v.size());
		for (int rep = 0; rep < 1 + (int)(rnd() % 12); rep++) {
			const size_t len = 4 + (size_t)(rnd() % 400);
			const size_t to = (size_t)(rnd() % v.size());
			const size_t from = (size_t)(rnd() % (to + 1));
			for (size_t i = 0; i < len && to + i < v.size(); i++) {
				v[to + i] = v[from + i];
			}
		}
		lz4_line(v);
	}

	// Ethernet address from node address and network ID (MAC::fromAddress()).
	for (int k = 0; k < 24; k++) {
		uint8_t a[5], n[8], m[6];
		fill(a, 5);
		fill(n, 8);
		if (k < 4) {
			n[7] = (uint8_t)(0x50 + k); // first byte would be 0x52: the reference changes it
		}
		uint64_t nw = 0;
		for (int i = 0; i < 8; i++) {
			nw = (nw << 8) | n[i];
		}
		MAC mac;
		mac.fromAddress(Address(a, 5), nw);
		mac.copyTo(m, 6);
		fputs("M ", stdout);
		hex(a, 5);
		putchar(' ');
		hex(n, 8);
		putchar(' ');
		hex(m, 6);
		putchar('\n');
	}

	// Dictionaries made by Dictionary::add(): keys that are the start of
	// other keys, values with every byte that needs an escape.
	for (int k = 0; k < 12; k++) {
		static const char* keys[] = { "v", "nwid", "ts", "t", "tt", "id", "I", "C", "COO", "mtu", "r", "RT" };
		Dictionary<2048> d;
		std::vector<uint8_t> values[12];
		bool have[12] = {};
		const int start = (int)(rnd() % 12);
		for (int j = 0; j < 12; j++) {
			const int i = (start + j * 5) % 12; // every key once, order differs between dictionaries
			if ((rnd() & 3) == 0) {
				continue;
			}
			values[i].resize((size_t)(rnd() % ((rnd() & 3) ? 12 : 300)));
			for (auto& c : values[i]) {
				static const uint8_t special[] = { 0, 10, 13, '=', '\\', 'n', 'r', 'e', '0' };
				c = (rnd() & 1) ? special[rnd() % sizeof(special)] : (uint8_t)rnd();
			}
			have[i] = d.add(keys[i], (const char*)values[i].data(), (int)values[i].size());
		}
		for (int i = 0; i < 12; i++) {
			fputs("D ", stdout);
			hex((const uint8_t*)d.data(), d.sizeBytes());
			putchar(' ');
			hex((const uint8_t*)keys[i], strlen(keys[i]));
			putchar(' ');
			if (have[i]) {
				hex(values[i].data(), values[i].size());
			}
			else {
				fputs("none", stdout);
			}
			putchar('\n');
		}
	}
	return 0;
}
