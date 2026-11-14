# C leaf: cost of a network MTU above 1500 (strand ztram, s6)

**Decision (Grey, 2026-11-14): the MTU stays as it is (leaf takes 1280..1500). Revisit only if it becomes a problem.**

State 2026-11-14. Read-only analysis of `` at `13503c9`, the stock ZeroTier One 1.16.2 core (`from-source/ZeroTierOne`, git `HEAD`; the working tree there has `GREY_ZT_EMBEDDED` changes, so stock lines are cited from `git show HEAD:<file>`), and Zephyr main in `from-source/zephyr-main-ws/zephyr` with the build `build-app-leaf`. No prover ran, nothing was built for the board. Sizes of structures come from a compile of `sizeof` with the target compiler (`arm-zephyr-eabi-gcc -mcpu=cortex-m7`). Tags: [CODE] read in source, [ARITH] computed from code or measured constants, [GUESS] judgement not yet checked.

## 1. Answer in short

Grey's hope is half right. A larger network MTU does NOT reduce ZeroTier-layer reassembly in the leaf: at the lab MTU of 1280 no frame is ever cut into ZeroTier fragments, at 2800 every received frame above 1394 bytes is. It DOES move the threshold for IP-layer reassembly (which the board does not do) from 1280 to 2800 bytes, but only if the leaf's own interface also takes 2800. On the send side (the sensor stream) the leaf never reassembles at any MTU; it only cuts a packet in two, which costs a 16-byte header write. A larger MTU helps the sender by fewer frames per byte and a little less overhead, not by less reassembly.

Full support of 2800 costs about 4.5 KB of leaf and adapter RAM plus 1.6 KB to 14 KB of Zephyr buffer pools, small code changes, one contract change, and a re-run of WP and the mutation list. The cheaper option (take a 2800 network, keep the own MTU at 1500) costs 0 bytes and about two lines, and leaves UDP/ICMP of 1473 to 2772 payload bytes from peers silently lost.

## 2. Three kinds of "reassembly" (question 1)

- ZeroTier-layer fragments: one ZeroTier packet in more than one UDP datagram. The leaf joins a head and one fragment in `src/reasm.c` (two parts at most, `include/ztl/wire.h:27`, `src/wire.c:41`). [CODE]
- IP-layer fragments: one IP datagram cut by the sending host because it is larger than the network MTU. Zephyr can join them only with `CONFIG_NET_IPV4_FRAGMENT`, which is off in the build (`build-app-leaf/zephyr/.config:1780`). [CODE]
- TCP segments: TCP never sends a segment larger than the MSS, and the MSS follows the interface MTU (Zephyr `subsys/net/ip/tcp.c:4821-4856` takes `net_if_get_mtu()`). TCP needs no IP reassembly. [CODE]

How a stock sender cuts a packet: it starts with `mtu = ZT_DEFAULT_PHYSMTU` (1432, `include/ZeroTierOne.h:98`) and changes it only for a physical path with a configured MTU (stock `node/Switch.cpp:1103-1109`, `node/Topology.hpp:318-327`). The head is `min(size, 1432)`; each further fragment carries up to 1432 − 16 = 1416 bytes (stock `Switch.cpp:1110`, `:1130-1140`; fragment header 16 bytes, `Packet.hpp:208`). A stock sender sends a unicast frame to the leaf as `FRAME` (stock `Switch.cpp:546-550`): 28-byte header + network ID 8 + ethertype 2 = 38 bytes before the frame. `MULTICAST_FRAME` has 49 bytes before the frame (53 with a gather limit; stock `OutboundMulticast.cpp:54-66`), `EXT_FRAME` 51 (only from bridges, stock `Switch.cpp:553-560`). [CODE]

Datagrams per packet from a stock sender (frame length L is the IP datagram, without the 14-byte Ethernet header) [ARITH]:

| L (bytes) | FRAME packet | datagrams | MULTICAST_FRAME packet | datagrams |
|---|---|---|---|---|
| 1280 | 1,318 | 1 | 1,329 | 1 |
| 1394 | 1,432 | 1 | 1,443 | 2 |
| 1500 | 1,538 | 2 (head 1,432 + fragment 122) | 1,549 | 2 |
| 2800 | 2,838 | 2 (head 1,432 + fragment 1,422) | 2,849 | 3 (last fragment carries 1 byte) |

Two datagrams carry at most 1,432 + 1,416 = 2,848 bytes, so the largest frame in two parts is 2,810 for `FRAME`, 2,799 for `MULTICAST_FRAME` (2,795 with gather limit) and 2,797 for `EXT_FRAME` [ARITH]. The reference says the same in words: "A 2800 byte payload still fits into two packets" (`include/ZeroTierOne.h:95`). [CODE]

So yes, the leaf already reassembles ZeroTier fragments at MTU 1500: every frame of 1,395 to 1,500 bytes arrives in two parts. The host interop test asserts this (`tests/host/leaf_node.c:222`: with a 1500 frame, `fragments > 0`). At the lab's MTU 1280 a frame never arrives in two parts. [CODE, ARITH]

Reassemblies for the same received data, bulk TCP from a peer to the leaf, full segments [ARITH]: MTU 1280: 0 per MB (806 datagrams per MB). MTU 1500: 685 per MB (1,370 datagrams). MTU 2800: 362 per MB (724 datagrams). Against today's 1280, MTU 2800 means more ZeroTier reassembly, not less; against 1500 it halves it.

What does go down with MTU 2800 is IP-layer reassembly: a peer sends UDP and ICMP of up to 2,772 payload bytes as one IP datagram in one frame, where today (1280) anything above 1,252 is cut by the peer's kernel and lost at the board (`ping -s 1400` today). This holds only if the board's interface MTU is 2800 too (option A). [ARITH]

## 3. Option A: the leaf takes MTU up to 2800 (question 2)

### 3.1 Ceiling

The sensible ceiling is 2800. It is the stock default (`node/Constants.hpp:290`) and the largest common MTU whose unicast frames still fit two datagrams of a stock sender (2,810, section 2). Above it a received frame needs three or more parts: `ZTL_FRAG_TOTAL_MAX` 2 (`wire.h:27`), the fragment rule `0x21` (`wire.h:29`, `wire.c:41-43`), the slot layout "head plus one right-aligned fragment" (`reasm.h:20-34`) and the reassembly proofs B-1 to B-6 all assume two parts. That is a rewrite of the reassembly and its proofs, and each slot would grow to 7 × 1,432 = 10,024 bytes (stock `Packet.hpp:185`). Not costed further. [CODE, ARITH]

The stock node clamps the configured MTU to 1280..10000 (stock `node/NetworkConfig.cpp:393-399`); it does not refuse. The leaf can do the same: accept 1280..10000, use `min(mtu, 2800)`. Option A then works on any network, with frames above 2800 from peers dropped (the option B behaviour, one level higher). [CODE]

### 3.2 Constants and checks in the leaf

- `ZTL_MTU_MAX` 1500 → 2800 (`include/ztl/leaf.h:41`). [CODE]
- `ZTL_PKT_MAX` 2048 → 2848 (`include/ztl/wire.h:12`). 2848 is the most that the leaf's own two-datagram send carries: `src/leaf.c:66` asserts `ZTL_PKT_MAX − ZTL_UDP_MAX + 16 ≤ ZTL_UDP_MAX`, with `ZTL_UDP_MAX` 1432 (`leaf.h:34`) that is ≤ 2848, met with equality. [CODE, ARITH]
- `src/leaf.c:64` asserts `28 + MC_FRAME_HDR + ZTL_MTU_MAX ≤ ZTL_PKT_MAX`; `MC_FRAME_HDR` is 21 (`leaf.c:47`), so 2,849 > 2,848: the build stops. The own multicast send (`leaf.c:501`) would write one byte past the packet. Fix: in `ztl_frame_to()` refuse a group-address frame longer than `ZTL_PKT_MAX − 28 − 21` = 2,799 bytes and state the assertion for `FRAME` (38 + 2,800 = 2,838 ≤ 2,848). Effect: a broadcast of exactly 2,800 bytes from the board is refused. Unicast is not affected. [CODE, ARITH]
- `ZTL_PLAIN_MAX` = `ZTL_PKT_MAX − 28` (`leaf.h:39`) becomes 2,820. A compressed `MULTICAST_FRAME` with a 2,800-byte frame decodes to 21 + 2,800 = 2,821 bytes and is refused (`leaf.c:1007`, counted `rx_bad_lz4`). Uncompressed it needs three datagrams anyway. Accept as a limit, or give `ZTL_PLAIN_MAX` its own value (+N bytes). [CODE, ARITH]
- Configuration check `mtu > ZTL_MTU_MAX` (`leaf.c:607`) and store (`leaf.c:638`): change to the clamp of 3.1. Also: the leaf refuses a configuration without the `mtu` key (`leaf.c:607`, `ztl_dict_get_hex` must succeed); the stock node takes 2800 then (stock `NetworkConfig.cpp:393`). A stock controller always writes the key [GUESS], so this is a corner. [CODE]
- Size assertions guarded by `#if ... ZTL_PKT_MAX == 2048u` (`leaf.c:71-72`, `rx.c:12-13`) turn off silently at 2848; they must get the new values (9,536 and 6,040). [CODE]
- The second datagram rule (`leaf.c:286-298`, contract `leaf.h:243-253`) stays: the second part is 16 + (P − 1,432) ≤ 1,432. [CODE, ARITH]

### 3.3 RAM, computed

- `struct ztl_reasm_slot` 2,072 → 2,872 (+800 each, 2 slots, `ZTL_RX_SLOTS` 2, `reasm.h:11`). `struct ztl_node` 4,440 → 6,040 (+1,600). [ARITH, target sizeof]
- `plain` 2,020 → 2,820 (+800, `leaf.h:100`). [ARITH]
- `struct ztl_leaf` 7,136 → 9,536 (+2,400). Matches `nm` of `build-app-leaf`: `leaf` is 0x1be0 = 7,136 today. [ARITH, target sizeof]
- Adapter (`zephyr/ztl_zephyr.c:34-36`): `tx_buf[ZTL_PKT_MAX]` 2,048 → 2,848 (+800); `frame_buf[ZTL_MTU_MAX]` 1,500 → 2,800 (+1,300); `rx_buf` 1,473 unchanged (underlay datagrams stay ≤ 1,472, `ztl_zephyr.c:30`). [CODE, ARITH]
- Leaf + adapter: +4,500 bytes. With the A2 variant (3.6): +4,740. [ARITH]
- Stacks: no stack buffer depends on `ZTL_PKT_MAX` (the buffers are static; `ZTL_WORKER_STACK_SIZE` 3,072 unchanged). [CODE]

### 3.4 Zephyr adapter

- `ETH_NET_DEVICE_INIT(..., ZTL_MTU_MAX)` (`ztl_zephyr.c:301-302`) and the send check `n > ETH_HDR + ZTL_MTU_MAX` (`:242`) follow the constant. `apply_config()` sets the interface MTU from the leaf (`:107`), so with the clamp the interface gets `min(network MTU, 2800)`. [CODE]
- Receive: `frame_to_pkt()` allocates `ETH_HDR + f->len` (`:132`). Zephyr limits that allocation to interface MTU + Ethernet header for this L2 (`subsys/net/ip/net_pkt.c:1218-1222`), so a 2,814-byte frame fits once the interface MTU is 2800. [CODE]

### 3.5 Zephyr itself

- Ethernet L2 carries frames above 1500 on a virtual interface: `subsys/net/l2/ethernet/ethernet.c` has no MTU or frame-length check; `NET_ETH_MTU` 1500 is used only by VLAN, bridge and drivers (`rg` over `subsys/net`). `net_if_set_mtu()` stores any `uint16_t` (`include/zephyr/net/net_if.h:1604-1612`). The underlay (USB NCM) is not affected: its datagrams stay ≤ 1,472 + 28 bytes. [CODE]
- IP fragmentation and reassembly: not needed for datagrams up to 2800. Without `CONFIG_NET_IPV4_FRAGMENT` the stack limits a packet to the interface MTU (`net_pkt.c:1210-1215`). [CODE]
- Buffer pools. Today: `CONFIG_NET_BUF_DATA_SIZE=128`, fixed size, `CONFIG_NET_BUF_TX_COUNT=36`, `CONFIG_NET_BUF_RX_COUNT=96`, `CONFIG_NET_PKT_TX/RX_COUNT=14` (`build-app-leaf/zephyr/.config:119-122, 1284, 1853`). One buffer costs 128 data + 28 header = 156 bytes (`nm`: `_net_buf_tx_bufs` 1,008 / 36 = 28, `net_buf_data_tx_bufs` 4,608 / 36 = 128). One `net_pkt` costs 72 bytes (`_k_mem_slab_buf_tx_pkts` 1,008 / 14). [CODE, ARITH]
- ⚠️ TX pool is too small for one 2,800-byte frame. `CONFIG_NET_TC_TX_COUNT=1` and `CONFIG_NET_TC_TX_SKIP_FOR_HIGH_PRIO` off (`.config:1282, 1793`), so every send goes through the one TX thread (`subsys/net/ip/net_if.c:397-403`, `net_private.h:225-233`). `ztl_dev_send()` runs in that thread and sends both underlay datagrams with `zsock_sendto()`; they are queued to the same thread and are freed only after `ztl_dev_send()` returns. So the overlay frame and both datagrams hold buffers at the same time: ceil(2,814/128) + ceil(1,474/128) + ceil(1,464/128) = 22 + 12 + 12 = 46 > 36. At 1500 it is 12 + 12 + 2 = 26. The UDP allocation waits up to 1 s (`net_context.c:76`, `:3373`, not shortened by `MSG_DONTWAIT`), in the TX thread, for buffers that only that thread can free. Prediction: each 2,800-byte frame from the board stalls the TX thread up to 1 s and loses its second datagram. [CODE, ARITH; the stall itself is not observed]
- TCP from the board holds the unacknowledged data in its send queue and copies it into each segment (`tcp.c:1849-1854`), so one full segment needs queue 22 + segment 22 + datagrams 24 = 68 buffers at 2800 [ARITH]. Side finding: at MTU 1500, which the leaf accepts today, the same count is 12 + 12 + 12 + 2 = 38 > 36; the lab runs 1280 (10 + 11 + 11 = 32). [ARITH; TCP buffer use from the default TX pool is GUESS from reading]
- Minimum TX change: 36 → 46 (+10 × 156 = +1,560 bytes) for UDP; 36 → 68 (+4,992) for one TCP segment; suggested 96 (+9,360) so that a few segments can be in flight [GUESS sizing; measure with `CONFIG_NET_BUF_POOL_USAGE`].
- RX pool: one 2,800 frame takes 22 buffers on the overlay plus 12 per underlay datagram until the leaf reads it. 96 buffers hold 4 full frames queued for the RX thread instead of 8 at 1500 (96/22, 96/12). Correct without change; +32 buffers (+4,992 bytes) keeps about the same frame count [ARITH, GUESS sizing].
- An alternative to more buffers is a larger `CONFIG_NET_BUF_DATA_SIZE` (fewer 28-byte headers); it changes every pool, the underlay included, and needs its own measurement [GUESS].

### 3.6 Variant A2: own datagrams of 1,472 bytes

With `ZTL_UDP_MAX` 1,472 (the underlay MTU 1500, as `ztl_zephyr.c:30` already assumes for receive) and `ZTL_PKT_MAX` 2 × 1,472 − 16 = 2,928, all assertions hold with 79 bytes to spare: multicast and compressed multicast of 2,800 work on send. Cost +240 bytes over A (leaf 9,776, `sizeof` checked). Received packets from stock peers still come in 1,432-byte parts. Risk: an underlay path below 1500 (PPPoE, VPN) cuts the leaf's datagrams at IP level; that is why the reference uses 1,432 (`ZeroTierOne.h:91-97`). [CODE, ARITH]

## 4. Option B: accept MTU 2800, keep the own MTU at 1500 (question 3)

Change: in `config_apply()` accept 1280..10000 and store `l->mtu = min(mtu, 1500)` (`leaf.c:607`, `:638`). All contracts that bound frames by `ZTL_MTU_MAX` or `l->mtu`, the invariant `ztl_leaf_ok` (`leaf.h:103-106`) and the adapter stay as they are. RAM 0 bytes (+4 with a new counter). [CODE]

What peers see (their tap MTU is the network MTU, stock `service/OneService.cpp:3630`) [CODE, ARITH; peer behaviour GUESS from standard IP]:

- TCP both ways works: the board announces MSS 1,460 from its interface MTU (`tcp.c:4821-4856`), and the peer sends no larger segment.
- The board's own sends stay ≤ 1,500: no change.
- UDP and ICMP from a peer with an IP datagram of 1,501..2,800 bytes (payload 1,473..2,772): the peer sends one frame, the leaf drops it, no ICMP error goes back: silent loss. Frames of 1,501..2,010 bytes are counted as `rx_bad_form` (`leaf.c:825-827`); frames of 2,011..2,800 make a packet above 2,048 bytes, which the reassembly drops without a counter (`reasm.c:164-167`, `rx.c:114`).
- Datagrams above 2,800: the peer cuts them at IP level; lost as today.
- Broadcast and multicast frames above 1,500: dropped.
- Better than today's 1280: payloads up to 1,472 arrive in one frame, so `ping -s 1400` works (today it does not).

As a stated limit this is acceptable for a node that mostly sends [GUESS]: it is the same as one host with MTU 1500 on a LAN with a larger MTU, a common case. The weak point is that the loss is silent. A counter for "frame longer than own MTU" (+4 bytes, one new contract clause in the gate for the uncounted reassembly drop) makes it visible on `ztl status`.

## 5. Other options

- C: Zephyr IPv4 reassembly, `CONFIG_NET_IPV4_FRAGMENT=y` with `NET_IPV4_FRAGMENT_MAX_COUNT` (default 1), `NET_IPV4_FRAGMENT_MAX_PKT` (default 2), `NET_IPV4_FRAGMENT_TIMEOUT` (default 5 s) (`subsys/net/ip/Kconfig.ipv4:174-224`). Independent of the leaf and of the MTU: it removes the IP-layer limit for any size (fragments × MTU), and lets the board send UDP larger than its MTU. RAM: one `struct net_ipv4_reassembly` per slot (`ipv4.h:339-354`, small) plus the RX buffers that the waiting fragments hold. Code: Zephyr's own, not proved; it runs only on frames that passed the leaf's gate, so only a pinned peer can feed it. [CODE; code size GUESS, not built]
- D: option A with the clamp of 3.1 (accept 1280..10000, use up to 2800). This is my preferred form of A: no network is refused, the deployer changes nothing.
- E (reference point, not what Grey asked): MTU 1394 on the controller makes every `FRAME` one datagram (38 + 1,394 = 1,432). It is the best send efficiency without any fragment, but it is again a controller setting.
- B+: in option B, answer a too-long frame with ICMP "fragmentation needed" (MTU 1500). The peer then cuts at 1500 at IP level, which the board can join only with option C. Not worth it alone. [GUESS]

## 6. Proof and test work (question 4)

WP proves each function against contracts written with the symbolic constants, so the size does not change WP time (`reports/PROOFS.md:311`). The heavy CBMC harnesses already run at reduced packet sizes (64 bytes for B-3/B-4, 40 bytes for C-2, `PROOFS.md:343-353, 410-417`; `proofs/remote.sh:10, 37`), so their time does not change either; at full size they did not finish even at 2048 (F-15). [CODE]

```yaml
- item: "Static assertions leaf.c:64, :66, :71-72; rx.c:12-13; reasm.c:7"
  option_A: ":64 fails (2849 > 2848), restate for FRAME; :66 holds with equality; :71-72 and rx.c:12-13 need 9536 and 6040"
  option_B: "no change"
- item: "Contract of ztl_frame_to (leaf.h:214-227) and its proof"
  option_A: "new clause: a group-address frame above 2799 bytes gives 0; WP re-run of leaf.c"
  option_B: "no change"
- item: "Invariant ztl_leaf_ok (leaf.h:103-106), L-28"
  option_A: "text follows ZTL_MTU_MAX (1280..2800); statement in PROOFS.md:198-202 changes"
  option_B: "no change (stored MTU still <= 1500); WP re-run of leaf.c for the new clamp"
- item: "L-26 bounds (PROOFS.md:188-192, NOT_PROVEN.md:69)"
  option_A: "frame 1..2800, packet 28..2848; same proof, new numbers"
  option_B: "no change"
- item: "Reassembly B-1..B-6, gate C-1/C-2"
  option_A: "re-run WP (symbolic, same time); CBMC unchanged at 64/40 bytes; texts PROOFS.md:309, :311, :352 say 2048"
  option_B: "no change"
- item: "proofs/wire_cbmc.c:42 reference model"
  option_A: "literal 2048 ('the reference buffer is also 2048', the bounded reference) must become ZTL_PKT_MAX; cbmc, cbmc32 and cover re-run at the larger array (GUESS: small growth, unwind 9 has no loop over the buffer)"
  option_B: "no change"
- item: "proofs/wire_eva.c:19-23"
  option_A: "follows ZTL_PKT_MAX; re-run (GUESS: same time)"
  option_B: "no change"
- item: "Mutation list proofs/run.sh:129-137, 201, 213, 216, 231-234"
  option_A: "patterns use the symbols and still apply; add one for the multicast length guard; whole list again (about 3 h on the prover host, workspace memory Z-m-50)"
  option_B: "the pattern ' || mtu < ZTL_MTU_MIN || mtu > ZTL_MTU_MAX' (:213, :234) must follow the changed check, else NOT APPLIED; add 'MTU not clamped' (WP rejects it through the invariant)"
- item: "tests/proto_test.c"
  option_A: ":827 add 2800 (and 9000 with the clamp, expecting 2800); :111 damage 1 uses 9999, which the clamp accepts: use 10001 or 1279; :471, :505 unchanged; :754, :769 follow ZTL_MTU_MAX"
  option_B: ":111 as for A; :827 add 2800 expecting a stored 1500; a frame of 1501 from a peer is dropped"
- item: "Host interop (tests/host/leaf_node.c:27, :222; interop.py:28; README-MORE.md:133)"
  option_A: "frame buffer 2800, choice --frame-size 2800, condition 'needs two datagrams' (> 1394) instead of '>= 1500'"
  option_B: "add a case: 2800 network, 1600 frame from the reference is dropped"
- item: "Reference test node grey_zerotier/tests/host_node.cpp:22, :167, :275 (workspace, not the public repo)"
  option_A: "frame buffer 2800, network MTU from the environment instead of 1500; reference_node is the stock core (tests/CMakeLists.txt:6, 22), so it sends 2800 frames"
  option_B: "network MTU 2800"
- item: "Board check (needs Grey's authorization to flash)"
  option_A: "ping -s 1400 and -s 2772 from a stock peer; UDP stream of 2772-byte payloads from the board; TX buffer use with CONFIG_NET_BUF_POOL_USAGE"
  option_B: "ping -s 1472 passes, -s 1473 is dropped and counted"
- item: "Documents"
  both: "README.md:36, :53; reports/PROTOCOL.md:64; PROOFS.md:190-191, :201, :309, :311, :352, :1061, :1082; NOT_PROVEN.md:69; reports/zerotier-leaf-tutorial-1.md:132; leaf.c:68-70 and rx.c:5-7 RAM comments"
```

## 7. Send side for the sensor stream (question 5)

Unicast `FRAME` from the leaf, full frames, underlay overhead 42 bytes per datagram (Ethernet 14, IPv4 20, UDP 8; NCM framing not counted). Leaf cycles from `reports/PERFORMANCE.md:23`: send 29,000 per packet + 55 per byte. [ARITH]

| Network MTU | UDP payload | datagrams | bytes on underlay | UDP efficiency | TCP efficiency | frames per MB | datagrams per MB | leaf cycles per payload byte |
|---|---|---|---|---|---|---|---|---|
| 1280 | 1,252 | 1 | 1,360 | 92.1 % | 91.2 % | 799 | 799 | 79 |
| 1394 | 1,366 | 1 | 1,474 | 92.7 % | 91.9 % | 732 | 732 | 77 |
| 1500 | 1,472 | 2 | 1,638 | 89.9 % | 89.1 % | 679 | 1,359 | 76 |
| 2800 | 2,772 | 2 | 2,938 | 94.4 % | 93.9 % | 361 | 722 | 66 |

Reading: MTU 1500 is the worst for a sender (each full frame drags a 122-byte second datagram). 2800 is the best: +2.3 points of efficiency against 1280, 17 % fewer leaf cycles per byte, 55 % fewer frames and 10 % fewer underlay datagrams per byte. Most of the cost per echo is outside the leaf (adapter, sockets, network stack, USB; `PERFORMANCE.md:81`). Per-frame costs (overlay stack, TCP/IP per segment, leaf fixed part) fall by about half; per-datagram costs (UDP socket, underlay, USB) fall by about 10 %. Which of the two dominates is not measured [GUESS]: expected gain in board CPU per byte somewhere between 10 % and 50 %. A UDP sender gets this only if it writes datagrams of up to 2,772 bytes; TCP gets it automatically through the MSS.

The send path needs no reassembly in the leaf at any MTU; the peer joins the parts. An upload stream gets back only ACKs and control packets, which are one datagram. [CODE `leaf.c:269-298`, ARITH]

## 8. Cost per option

| Option | RAM (bytes) | Code change | Proof and test work | Limit that stays |
|---|---|---|---|---|
| B: accept ≤ 10000, own MTU 1500 | 0 (+4 with counter) | about 2 lines in `config_apply()` | WP leaf.c, mutation patterns :213/:234 + one new, proto_test :111/:827, one interop case, docs | UDP/ICMP payload 1,473..2,772 from peers silently lost |
| A: MTU 2800 (refuse above) | leaf +2,400, adapter +2,100, Zephyr TX ≥ +1,560 (UDP) / +4,992 (one TCP segment) / +9,360 (suggested 96), RX +4,992 (suggested) → 6,060 minimum, 18,852 suggested | constants, multicast guard, two size assertions | WP all units, cbmc/cbmc32/cover/eva re-run, wire_cbmc.c:42, full mutation list (~3 h) + one new, proto_test, interop at 2800, host_node.cpp, docs, board check | networks above 2800 refused; broadcast of exactly 2,800 refused |
| D: A + clamp (recommended) | as A | as A + the clamp | as A + the B test cases | frames above 2800 from peers dropped |
| A2: D with 1,472-byte datagrams | as A + 240 | as D, `ZTL_UDP_MAX` 1,472 | as D; also L-26 periodic packet bound 1,432 → 1,472 | underlay paths below 1500 cut the leaf's datagrams |
| C: Zephyr IPv4 reassembly | small static + RX buffers while waiting (GUESS) | Kconfig only | none in the leaf; board test | unproved Zephyr code behind the gate |
| N-part reassembly (MTU > 2800) | about 10,024 per slot | rewrite of reasm and wire rules | new reassembly proofs | — (not recommended) |

## 9. Recommendation

D: take any network MTU, use up to 2800, raise `CONFIG_NET_BUF_TX_COUNT` to at least 68 (better 96) and measure the pools on the board. RAM is cheap here (about 19 KB on 1 MB), the proof work is mostly re-runs because the contracts are symbolic, and only one contract gets a new clause. It removes the controller setting, fixes the IP-layer limit for datagrams up to 2,800 bytes, and gives the sensor sender its best overhead. If the proof re-run cannot be paid now, B is a safe first step with no RAM and no new risk, and D can follow. C is an independent decision for datagrams above the MTU.

Do not expect less ZeroTier-layer reassembly from any of these: at 2800 the receive path joins two parts for every frame above 1,394 bytes, and the reassembly code (proved, two slots) carries more of the traffic than at 1280.

## 10. Questions for Grey

- ❓ Q-ztram-mtu-1: Did "reassemble" mean the IP layer (Zephyr cannot join IP fragments) or the leaf's ZeroTier reassembly? Section 2 says MTU 2800 helps the first and adds to the second.
- ❓ Q-ztram-mtu-2: Option D (full 2800 with clamp) or option B (accept 2800, stay at 1500) first?
- ❓ Q-ztram-mtu-3: Does the sensor stream use UDP or TCP, and of what datagram size? With UDP, the gain of 2800 comes only with datagrams above 1,472 bytes of payload.
- ❓ Q-ztram-mtu-4: TX buffer pool: 46 (UDP only), 68 (one TCP segment) or 96? Or a larger `CONFIG_NET_BUF_DATA_SIZE`? Either way a board measurement with `CONFIG_NET_BUF_POOL_USAGE` decides.
- ❓ Q-ztram-mtu-5: The side finding of 3.5 predicts that TCP sends from the board stall at network MTU 1500 today (38 TX buffers needed, 36 present). Check it on the board now, or only together with the MTU work?
- ❓ Q-ztram-mtu-6: Keep the leaf's datagrams at 1,432 bytes (as the reference), or use 1,472 (A2) so that broadcast and compressed multicast of 2,800 also work?
- ❓ Q-ztram-mtu-7: Add a counter for "frame longer than the own MTU" (including the reassembly drop, which today counts nothing)? It changes the gate contract C-1 ("at most one refusal counter grows").
- ❓ Q-ztram-mtu-8: Enable Zephyr IPv4 reassembly (option C) for datagrams above the MTU, accepting unproved Zephyr code behind the gate?
- ❓ Q-ztram-mtu-9: With 2800 more of the received traffic is two-part; keep `ZTL_RX_SLOTS` at 2 (+2,872 bytes per extra slot) unless a test with several peers shows evictions?
