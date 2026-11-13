# What a stock ZeroTier peer expects from this leaf

State: 2026-11-13. 💡 The leaf now implements what this page lists under "must", and exchanges frames with the reference core on a host (see [PROOFS.md](PROOFS.md), "Attempts on the protocol layer"); a stock daemon and a stock controller as the other side are the next test. A reading of the reference source (ZeroTier One 1.16.2, revision `fe29cd88`, directory `node/` unless another is named; line numbers are of that revision with the project's patches, stock behaviour reported). It answers the design questions D-6 and D-8 of [CHECKLIST.md](../CHECKLIST.md): which messages the leaf must send, answer and parse, and whether a leaf without an identity secret can do all of it. Evidence tags: [CODE] read in the source, [INFERRED] concluded from it. Nothing here was measured yet. Older peers (1.4 to 1.14) were not read for these points.

## Result in short

- 💡 **A plain member signs nothing.** HELLO, OK, the configuration request, frames, multicast and the credential push are authenticated by the pairwise MAC only. The identity secret is used for the per-peer key agreement (`Peer.cpp:60`), which the provisioning tool does off-device, and for one optional feature (next point). Signatures (`Node.cpp:885`, credentials) are made by the controller only. [CODE] So decision D-8 holds.
- ⚠️ **Encrypted HELLO needs the secret and AES.** A peer with `encryptedHelloEnabled` sends HELLO with extended armor; opening it uses the receiver's secret key (`Packet.cpp:1171-1191`). Default off (`service/OneService.cpp:2901`). Deployer rule D-5a stays: keep it off at peers of the leaf.
- ⚠️ **LZ4 decompression is required.** The controller compresses every configuration reply (`Node.cpp:889`), and there is no negotiation and no way to refuse (`ZT_NETWORKCONFIG_FLAG_DISABLE_COMPRESSION` is defined and never used). Compressed too: MULTICAST_LIKE, NETWORK_CREDENTIALS, PUSH_DIRECT_PATHS, MULTICAST_FRAME above 64 payload bytes. Not compressed: FRAME, EXT_FRAME, HELLO, OK, ERROR, ECHO (`Switch.cpp` has no `compress()` call). Condition: payload above 64 bytes and the output is smaller (`Packet.cpp:1285`). [CODE] The leaf needs a bounded LZ4 decoder for the configuration; for the other compressed verbs it may drop the packet.
- ⚠️ **The certificate of membership (COM) expires.** A peer accepts the leaf's frames only while the leaf's COM agrees with its own within the network's window (default 30 min, range 5 min to 2 h). The leaf must ask for its configuration again and push the new COM well inside that window. [CODE + INFERRED]
- ⚠️ **Version 11 in every HELLO and OK(HELLO)**: a peer uses AES as soon as it has learned a version of 12 or more (`Peer.hpp:657-660`).

## Key derivation (for the provisioning tool)

`ECC::agree`: Curve25519 scalar multiplication of the own secret and the peer's public key (first 32 bytes of each), then SHA-512 of the result; the first 48 bytes are the peer key (`ECC.cpp:2456-2469`). Salsa20/12 and Poly1305 use bytes 0 to 31; bytes 32 to 47 feed the AES key derivation only (`Peer.cpp:65-68`). The same key serves both directions; the directions differ through the per-packet key mixing. [CODE]

## HELLO

Payload as sent (`Peer.cpp:430-455`): protocol version (1 byte, the leaf sends 11), major, minor (1 byte each), revision (2), timestamp in ms (8), identity (71 bytes: address 5, type `0x00`, public key 64, secret-key length `0x00`), destination address as the sender sees it (`0x04` + IPv4 + port, `0x06` + IPv6 + port, or `0x00`), planet ID (8), planet timestamp (8), then an encrypted part with the moons. Sent with suite 0: MAC only. The receiver treats everything after the identity as optional (`IncomingPacket.cpp:476-500`), so the leaf can stop after the planet fields with ID 0 (no planet comes back then) and needs no `cryptField`. [CODE]

What the receiver checks (`IncomingPacket.cpp:367-557`): version at least 4; source address equals the identity's address; for a known peer the identity must be the same and the MAC must be right; for an unknown peer a rate limit per source /24 (silent drop: the leaf must retry), key agreement, MAC, then the memory-hard identity check. The timestamp is only echoed. Then OK(HELLO). [CODE]

Timing: a peer sends a full HELLO every 60 s per path (`ZT_PEER_PING_PERIOD`), and on a non-OK packet from an unknown path. A peer learns a path to the leaf **only from an OK** that matches a HELLO it sent (`Peer.cpp:136`), so the leaf must answer HELLO. A peer forgets a member after 500 s without any packet (`ZT_PEER_ACTIVITY_TIMEOUT`); a path is alive for 19 s after the last packet and is kept for 243 s.

## OK and ERROR

OK: in-reply-to verb (1), in-reply-to packet ID (8), payload. ERROR: the same plus an error code (1) before the payload (`Packet.hpp:236-243`). OK(HELLO) payload: echoed timestamp (8), protocol version (1, the leaf sends 11), major, minor (1 each), revision (2), the sender's address as seen by the responder, optional worlds. The receiver ignores an OK whose packet ID it does not expect. Smallest OK(HELLO) from the leaf: 22 payload bytes. [CODE]

## Verbs from a stock peer or controller

| Verb | When | What the leaf must do |
|---|---|---|
| HELLO | every 60 s per path; on a first packet | answer OK(HELLO) |
| ECHO | heartbeat on a path silent for 14 s | answer OK(ECHO) with the payload, or send anything often enough |
| FRAME, EXT_FRAME | data | deliver; EXT_FRAME flag `0x10` asks for an acknowledgement |
| MULTICAST_FRAME | broadcast and multicast, ARP | deliver; layout: network (8), flags (1), optional COM (`0x01`), gather limit (`0x02`, 4), source MAC (`0x04`, 6), destination MAC (6), ADI (4), ethertype (2), frame |
| ERROR NEED_MEMBERSHIP_CERTIFICATE | the peer has no valid COM of the leaf | push the COM; the peer keeps the frame for 5 s and tries again every 500 ms |
| NETWORK_CONFIG (push) | member or network changed | take as a configuration; the answer is optional |
| NETWORK_CREDENTIALS, MULTICAST_LIKE, PUSH_DIRECT_PATHS | from peers that send frames to the leaf | may be ignored |
| WHOIS, RENDEZVOUS, MULTICAST_GATHER | to roots and controllers only | never arrive at a leaf |
| ACK, QOS_MEASUREMENT, PATH_NEGOTIATION_REQUEST | only with a bond policy at the peer | ignore |
| USER_MESSAGE, REMOTE_TRACE | on request only | ignore |

## Network configuration

Request (`Network.cpp:1492-1506`): network ID (8), dictionary length (2), metadata dictionary, then 16 bytes (revision and timestamp, zero the first time). The controller reads only the dictionary and drops repeated requests within 1 s. Useful metadata: `v=7`, `revr=1`, `pv=b` (values are hexadecimal; format `key=value` lines). A non-empty dictionary is needed for later pushes. [CODE]

Reply (`Node.cpp:864-891`): OK(NETWORK_CONFIG_REQUEST), or NETWORK_CONFIG for a push: network ID (8), chunk length (2), chunk, flags (1), update ID (8), total length (4), chunk index (4), `0x01`, signature length (2, value 96), signature. Each chunk is LZ4-compressed, then cut into fragments at the path MTU. A stock controller's chunk can be 9,740 bytes; the leaf accepts what fits in two fragments and 2,048 bytes (the reference module has the same limit; the lab network has MTU 1280 for it). The leaf does not check the signature: it accepts the configuration only directly from the pinned controller, under the pairwise MAC (D-8).

Dictionary keys the leaf needs: `v` version, `nwid` network, `ts` timestamp, `id` issued-to address, `t` type (0 = private), `mtu`, `I` static addresses, `C` COM as an opaque blob. Optional: `r` revision, `ctmd` COM window, `f` flags, `ml` multicast limit, `RT` routes. Not needed: rules, capabilities, tags, DNS, SSO, legacy keys.

## Membership between members

A peer accepts a frame from the leaf when the leaf's stored COM agrees with its own and is signed by the controller (`Membership.hpp:90-93`, `CertificateOfMembership.cpp:46-132`). The COM binds to the member through the SHA-384 of the member's public identity, not through a member signature. The leaf sends its COM as it came in the `C` key: 272 bytes (`0x01`, count 7, seven triples of 8-byte values, signer address 5, signature 96), either as NETWORK_CREDENTIALS (COM, `0x00`) or inside EXT_FRAME with flag `0x01`. Stock timing: on the first frame to a peer, after each configuration update, every 500 s, and on the ERROR above. The leaf itself admits peers by pinning, not by their COM (Z-m-39 in the workspace memory).

## Multicast and ARP

ARP for IPv4 uses the group "broadcast MAC, ADI = the IPv4 address". A stock sender sends to the members it knows for the group, and asks the controller (MULTICAST_GATHER) when it knows too few. Members announce their groups with MULTICAST_LIKE (entries: network 8, MAC 6, ADI 4) every 60 s to the controller and to members; entries expire after 600 s. Without a planet the controller is the only place peers ask. So the leaf sends MULTICAST_LIKE for its ARP group to the controller and, after its COM, to its peers. [CODE + INFERRED]

## Open points

- ✅ [MEASURED] Size of a real configuration: the dictionary that a stock 1.16.2 controller gives a member of a small private network (one address, one route, default rules) is 1,121 bytes plain; the packet around it adds about 140. The leaf's plain buffer holds 2,020.
- ⚠️ [UNVERIFIED] Request metadata: the leaf sends `v=7`, the vendor and version numbers and no `revr` (rules engine revision). By the comments in the reference, a controller then sends one "accept" rule and no capabilities or tags. The controller source is not in the tree that was read; the first run against a stock controller will show it.
- 🌱 The same reading for peers 1.4 to 1.14.
- 🌱 Verb counts from a run of the reference node (D-6), to confirm this table by measurement.
