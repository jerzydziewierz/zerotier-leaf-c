# Bug report: open points of the Zephyr adapter of the C leaf

State: 2026-11-14. Code: `zephyr/ztl_zephyr.c` (one thread of its own, one mutex `lock`, one UDP socket, virtual Ethernet device `ztl`). The adapter runs on the Teensy (ping, Telnet, SSH over the overlay; 360,000 full-size echoes in one hour without loss). It has no test and no proof. None of the points below was seen as a failure; each is a place where a failure is possible and the fix is not decided.

## A-1 ✅ closed

✅ in support of a deadlock-free adapter, when a received packet brings a frame or a new configuration, `worker()` copies what the stack needs under the leaf's lock, releases the lock, and only then calls `net_recv_data()` and the interface functions (2026-11-14; board: ping, SSH, soak). Still under the lock: `zsock_sendto()` on the underlay socket, in the worker and in `ztl_dev_send()` (same order of locks in both).

## A-2 🥦 `rx_filtered` grows slowly on the board

- Seen 2026-11-14, one-hour soak: `rx_filtered` went from 12 to 266, about 4 for each minute, steady, while 370,000 datagrams from pinned endpoints were taken and no echo was lost.
- Seen: 8 to 12 datagrams in the first minutes of each run are dropped unread because their source endpoint (address and port) is not a pinned endpoint (`from_endpoint()`).
- Not known: who sends them. Guess: a stock peer that also sends from its second or third UDP port, or a peer's packet for the old board identity. Not looked at with a capture.
- Effect so far: none seen (no loss in 10,000 echoes). If a peer chose a non-pinned port as its only path, the leaf would be deaf to it.
- To do: capture on the lab bridge (`tcpdump -ni <lab bridge> udp and host <board underlay address> and not port 9993` needs Grey's sudo), or add a counter per source port to `ztl status`.

## A-3 🌱 Not ported from the reference adapter

`grey_zerotier/src/client.cpp` has three things that came from hardware findings (workspace memory Z-m-13) and that the leaf adapter does not have: private packet pools (overlay RX slab, underlay TX pool), ARP gleaning (learn the sender of each authenticated IPv4 frame, because Zephyr's ARP pending queue is not bounded), and a check that the overlay subnet does not overlap the underlay. Under load or flood the leaf adapter can starve where the reference adapter does not. Not measured.

## A-4 🌱 No test

Nothing checks the adapter but the runs on the board. Candidates: a `native_sim` build with two instances, or the board against `tests/host/leaf_node.c` with the roles reversed.
