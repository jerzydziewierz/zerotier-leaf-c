# Bug report: the C leaf accepts a recorded packet again (replay)

State: 2026-11-14. Code: `src/rx.c` (`ztl_rx()`, the receive gate), `src/leaf.c` (what an accepted packet does). Not a regression: the leaf never had a defence, and ZeroTier protocol v1 has none either. It is a limit that is stated in the public documents (`README.md`, `reports/NOT_PROVEN.md` N-7, `reports/PROOFS.md` "What all of this does not show"). ✅ Decided by Grey, 2026-11-14 (A-ztram-s4-6): replay is recorded as a limitation, with the possible mitigations noted in `reports/NOT_PROVEN.md` N-7; nothing is built. This file keeps the analysis for the day that changes.

## What happens

Someone on the underlay path records one authentic datagram and sends it again later. The gate finds a right MAC (the key of one packet depends on the header and the pairwise key only), so the packet passes. Effects in `src/leaf.c`:

- a FRAME, EXT_FRAME or MULTICAST_FRAME is delivered to the host again (the application sees the Ethernet frame twice; TCP ignores it, UDP and ICMP do not);
- the peer counts as heard (`ps[i].seen`, `rx_ms`), so a silent peer can be kept "reachable";
- a HELLO or ECHO draws the same answer again; an ERROR "need certificate" (18 bytes) draws a certificate push and a subscription each time: a small amplifier, with no rate limit;
- NOT affected: OK and configuration answers count once, for the waiting request ID only; a pushed configuration must be newer than the newest one taken since the start.

## What is known

- 💡 [CODE] Stock peers give every packet a RANDOM 64-bit ID: `from-source/ZeroTierOne/node/Packet.hpp:1086` and `:1131` (`Utils::getSecureRandom(field(ZT_PACKET_IDX_IV, 8), 8)`). There is no counter. So the usual window ("accept only IDs above the highest seen, with a bitmap for reordering") is NOT possible. (The leaf's own sent IDs are a counter from a random start; that is the leaf's choice and peers do not care.)
- 💡 [CODE] The reference keeps no replay state for packets either; it limits the rate of some answers (review round 3, `reports/PROOFS.md`).
- With AES-GMAC-SIV (suite 3) the packet ID field is derived from the tag, still not a counter: no help.

## Options (none started)

1. **Filter of recent IDs.** For each peer a ring of the last N accepted packet IDs; a packet whose ID is in the ring is dropped after authentication (count it). N = 32: 7 × 32 × 8 = 1,792 bytes of RAM, a linear scan of 32 words for each packet, about 150 bytes of code. Stops an immediate replay and a replay storm of one packet; does NOT stop a replay after more than N other packets from that peer. Proof side: easy to state ("a delivered packet's ID was not in the ring; afterwards it is"), a ghost model is not needed. ⚠️ A fragmented packet has one ID for both datagrams: filter the complete packet, after reassembly.
2. **Time-based filter on top of 1.** Not possible in the protocol: packets carry no time stamp (HELLO does: a HELLO with a time stamp not above the last one from that peer could be refused; ⚠️ a peer whose clock steps back would be locked out until its clock passes the old value).
3. **Rate limit of answers** (HELLO → OK, ECHO → OK, "need certificate" → certificate): one answer of each kind for each peer in a time window. Small, closes the amplifier, independent of 1.
4. **State it as a limit** and rely on the layers above (TCP, SSH, TLS are not harmed by a duplicate frame). This is today's state.

🥦 Agent's view: 1 with N = 32 plus 3 is cheap and honest if the documents keep saying what it does not stop. Grey decides (A9 of 2026-11-13 was "after the measurements"; the measurements are done).
