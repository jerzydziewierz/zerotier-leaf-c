# ZeroTier leaf in C: exploration checklist

Strand `ztram` (TODO Z-48). This folder holds the new solution: a wire-compatible ZeroTier leaf in C with no general heap. The reference solution is `../grey_zerotier/` (public: `../grey-zerotier-public/`); it stays as the differential oracle. Baseline to beat: 110,508 B add-on linked RAM, 509 KB flash (`compile_probe` pair, 2026-11-12).

Each item is closed with one line: what was tried, on which code, the result, and the limit. Evidence tags: [CODE] read in source, [MEASURED] run here, [UNVERIFIED] not yet checked.

## Theorems to aim for

| ID | Statement | Status |
|---|---|---|
| T1 | No undefined behaviour for any received datagram of 0..2048 bytes | 🔴 |
| T2 | Static bound on stack depth and on total RAM (no recursion, no heap, bounded loops) | 🔴 |
| T3 | No frame reaches the overlay interface unless a pinned peer authenticated it | 🔴 |
| T4 | Parse and serialise are inverse for every accepted message | 🔴 |

## Design levers

| ID | Item | Status |
|---|---|---|
| D-1 | No general heap: static typed tables (peers, paths, config), one per-call arena, fixed rings (reassembly, TX wait, WHOIS) | 🔄 so far: `struct ztl_node` holds everything (peer table, reassembly, counters); no heap, no arena needed yet |
| D-2 | C instead of C++: no exceptions, no libstdc++, no `SharedPtr`; packet path becomes eligible for ITCM | 🔄 ISO C11, no C library calls, no function pointers so far |
| D-3 | In-place packet processing in one contiguous buffer; no 2 KB packets by value on the stack | 🔄 unfragmented packets are processed in the datagram buffer; a fragmented packet is joined in its reassembly slot; largest stack frame so far 96 B (`ztl_rx`) |
| D-4 | Memory budget table: every struct, count and size, checked at build time (`_Static_assert`) | 🔄 `_Static_assert` on `struct ztl_reasm` (4,144 B for 2 slots) and on the target layout of `struct ztl_view`. Current RAM = `sizeof(struct ztl_node)` (about 4.5 KB: 7 peers × 38 B + reassembly + counters). 🌱 one budget table for the whole node when keys and TX state exist |
| D-5 | **Leaf without AES.** 💡 [CODE] `node/Peer.hpp:659` `aesKeysIfSupported()` gives AES keys only when the remote protocol version is ≥ 12; `Packet::armor()` then uses Salsa20/12 + Poly1305 (suite 1). `ZT_PROTO_VERSION_MIN` is 4. So a leaf that announces protocol version 11 in HELLO should get suite 1 in both directions, and needs no AES, no GMAC, no HMAC-SHA384 key derivation (used only for the AES keys, `Peer.cpp:65-67`). ⚠️ Cost: version 13 features are lost (encrypted HELLO, ephemeral keying), and Salsa20/12 is the legacy suite. ✅ [MEASURED] 2026-11-12, host loopback: a leaf core with `ZT_PROTO_VERSION 11`, `aesKeysIfSupported()` always null and `abort()` on both AES code paths passes `tests/interop.py` normal (1500 B and 69 B frames, 7 peers), deny and tamper against the unchanged version-13 reference core. The leaf must do two things: announce version 11 (so that peers send suite 1) and never choose AES itself (upstream chooses by the remote's version). Limit: this ran the reference core, not the C leaf; peers were the 1.16.2 reference core, not a stock `zerotier-one` daemon or the lab controller. ⚠️ D-5a (deployer rule): a peer with `encryptedHelloEnabled` in `local.conf` sends HELLO with extended armor (AES-CTR + ephemeral key, `Packet.cpp:1171`), which a leaf without AES cannot read. [CODE] Default is false (`service/OneService.cpp:2901`). Do not enable it at peers of the leaf. ⚠️ Flag bit 7 with suite 1 is the old "encrypted" flag, set by every peer up to 1.14 on each encrypted packet: accept it. ⚠️ Peers choose the suite from the learned version; incoming AES packets are still possible and the classifier drops them. Grey accepts the loss of encrypted HELLO and ephemeral keying (A-ztram-s2-16). 🌱 Next: same test on the board network; cycles per packet (AES-GMAC-SIV is today's main cost, ≈ 1 M cycles per packet). | 🔄 |
| D-6 | Protocol scope: list the verbs and paths that the interop tests exercise (verb counter in the reference core) | 🌱 |
| D-7 | C-rusted discipline: own no-op annotation header (optional, bounds, exclusive/shared, init, nominal types); checked by the open tools below. ECLAIR evaluation: letter in `../dev-docs/email-draft-bugseng-c-rusted.md` | 🌱 |
| D-8 | **No public-key cryptography on the device** (Grey, A-ztram-s1-1/-2, 2026-11-13): fixed-function node, assigned to its network in the factory, provisioned in a secure environment with one 32-byte pairwise key per pinned peer; network configuration accepted only directly from the pinned controller under its pairwise key. No X25519, no Ed25519, no SHA-512 on the device. 🌱 Provisioning tool on the host computes the pairwise keys with the reference code; ❓ check what in HELLO / OK(HELLO) and in the config exchange still needs the identity public key bytes or a signature that a stock peer verifies | 🌱 |

## Provers and checkers

Order = recommended order of trial. "Have" = installed on this host on 2026-11-12.

| ID | Tool | Class | What it can prove here | Have | Status |
|---|---|---|---|---|---|
| P-1 | CBMC 5.95.1 | Bounded model checking | T1 for all inputs up to the bound; assertions; fits the fixed peer count and 2048 B cap | ✅ `/usr/bin/cbmc` | ♻️ `proofs/wire_cbmc.c`: `ztl_classify()` for every buffer of 0..2049 bytes, exact-size allocation: 457 checks, 0 failed; result equal to a model of the reference receive path in both directions, two listed differences (AES); 11 of 11 cover targets; `run.sh mutate`: 9 of 9 deliberate errors rejected |
| P-2 | Frama-C Eva (24.0, 2022) | Abstract interpretation | T1 without bounds; alarms list. Nearest open relative of the C-rusted Analyzer | ✅ apt (reports 25.0-beta) | ♻️ `proofs/wire_eva.c` (Frama-C 33.0): 0 run-time-error alarms, preconditions valid; cannot decide the contract behaviours on unknown bytes (left to P-1, P-3) |
| P-3 | Frama-C WP + ACSL, provers Z3 4.8.12, CVC5 1.1.2 through Why3 1.6.0 | Deductive | Function contracts: T4, table invariants, parts of T3 with crypto as axioms | ✅ through P-4 (Ubuntu `frama-c-base` has no WP plug-in) | ♻️ contract of `ztl_classify()` in `include/ztl/wire.h` plus generated run-time-error guards: 129 of 129 goals proved, for every length and content; exact contract (complete, disjoint behaviours) except the packet-id value; ⚠️ provers time out on shift/mask reasoning, so decode with direct comparisons |
| P-4 | Frama-C 33.0 + Alt-Ergo 2.6.4 (opam switch `ztl`, `proofs/opam-setup.sh`) | as P-2, P-3 | Same, newer WP and Eva | ✅ opam 2.6.1 in `~/.local/bin` (release binary, SHA-512 checked) | ✅ installed; Eva and WP both use it |
| P-5 | GCC `-fstack-usage` + call graph | Static stack bound | T2 | ✅ SDK GCC 14.3 | ♻️ `run.sh target`: `ztl_classify` 24 B stack, 186 B code (Cortex-M7, `-Os`) |
| P-6 | VeriFast | Separation logic | Ownership and aliasing as proof objects; closest to C-rusted's ownership ideas | 🔴 binary release, vendor download | 🔴 |
| P-7 | CN (Cerberus) | Separation-logic refinement types | As P-6, with a formal C semantics | 🔴 opam | 🔴 |
| P-8 | RefinedC | Ownership types, foundational (Coq) | As P-6, proof checked by Coq | 🔴 opam | 🔴 |
| P-9 | VST + CompCert (Coq 8.18) | Foundational | One small function end to end, for the experience and the comparison | Coq ✅; VST 🔴 opam | 🔴 |
| P-10 | Isabelle + AutoCorres | Foundational (seL4 style) | As P-9 | 🔴 download | 🔴 |
| P-11 | ESBMC | Bounded model checking, k-induction | Cross-check of P-1; unbounded loops by k-induction | 🔴 binary release | 🔴 |
| P-12 | ProVerif or Tamarin | Symbolic protocol model | Handshake secrecy and authentication, independent of C code; no published ZeroTier analysis found | 🔴 opam / download | 🔴 |
| P-13 | TLA+ (TLC) | State-machine model checking | Peer/path/reassembly state machines: no stuck state, bounded queues | 🔴 download (Java) | 🔴 |
| P-14 | HACL* (verified C from F*) | Verified crypto, reuse | Ed25519, X25519, Poly1305, SHA-512 with existing proofs. ⚠️ [CODE] HACL* `Hacl_Salsa20.c` is fixed at 20 rounds (10 double rounds, no round parameter); ZeroTier uses Salsa20/12, so the stream cipher is not covered: keep ZeroTier's Salsa20 and check it with P-1/P-3 against HACL*'s structure, or generate a 12-round variant from the F* source | 🔴 vendor source build | 🌱 |
| P-15 | Differential test against the reference core | Testing, not proof | Same outputs for the same packet traces; fuzz corpus | ✅ host tests exist | 🌱 |
| P-16 | ECLAIR C-rusted Analyzer | Commercial | The C-rusted annotations themselves | 🔴 licence | 📞 letter |
| P-17 | Wolfram Engine 15.0 (`wolframscript` on `user@big-prover-host`, installed by Grey 2026-11-13) | Computer algebra, not a proof checker | Arithmetic inside the cryptography (V-10): Poly1305 limb and carry bounds modulo 2^130 − 5, curve formulas as polynomial identities (Gröbner bases), exact nonce-collision probability (V-2). Use it to FIND certificates (cofactors, bounds, witnesses) and check them with an independent small tool | ✅ on big-prover-host | 🌱 |

## Further proof targets

From two independent reviews (`reports/PROOFS.md`, "Independent reviews"): V-1..V-12 from review 1, V-13..V-23 from review 2. Difficulty L/M/H. Order accepted by Grey (A-ztram-s2-22): settle rule questions (V-13, D-5a) ✅, thin memory and layout budget (D-4, V-17) 🔄, reassembly (V-4) ♻️, authentication gate with a narrow crypto interface (V-1) 🔄, then real Salsa20/12 and Poly1305 (V-10) 🌱.

| ID | Property | Tool | Diff. | Status |
|---|---|---|---|---|
| V-1 | Authentication before effects: failed authentication changes no peer, config, replay or path state and delivers no frame; suite 0 dispatches HELLO only; authorised network checked as well as peer | WP/CBMC; Tamarin for identity binding | M–H | ♻️ `ztl_rx()` contract in `include/ztl/node.h` (ghost record of the primitive call): WP 173 of 173, full size, both models; the primitive is a contract only. CBMC cross-check at 64 B (`proofs/rx_cbmc.c`): cover 8 of 8, main run ❗ no result after 6 h on big-prover-host (retry at 40 B). Gate mutants: 7 of 7 rejected. 🌱 Extend to config, replay and path state when they exist |
| V-2 | Nonce life cycle: no key stream position reused for different data, across restart, wrap and concurrent sends (packet IDs are random IVs with a 3-bit counter, not sequence numbers) | TLA+, WP/CBMC | M–H | 🔴 |
| V-3 | Replay: an accepted packet has no second effect within a stated window or key epoch; unauthenticated input cannot poison that history; no config rollback | TLA+, then CBMC/WP | M | 🔴 |
| V-4 | Reassembly: order-independent result; duplicates and conflicting parts cannot splice or extend; total length ≤ 2048 (two legal datagrams can exceed it); authentication before dispatch | CBMC, WP | M | ♻️ `src/reasm.c` as small functions with contracts (`src/reasm_internal.h`): WP 245 of 245 goals and both arrival orders 44 of 44 (`proofs/reasm_wp.c`), full 2048 B, both models; 7 of 7 mutants rejected. CBMC cross-check at 64 B on current code: step 520, order 588, duplicates 577, timeout 518 checks, 0 failed. 🌱 Timeout and oldest-slot rules are not in the WP contract of `ztl_slot_for()` yet |
| V-5 | Bounded cost and recovery under hostile input: ≤ B operations per datagram; no eviction of pinned peers; slots expire; capacity returns after a flood | WP, TLC | M | 🔴 |
| V-6 | Timer and counter wrap equal an ideal monotonic clock within a stated maximum gap; saturating counters never wrap into permission | CBMC, WP | L–M | 🔴 |
| V-7 | Zephyr ownership and life cycle: each packet buffer released exactly once; no view outlives its buffer; stop waits, wipes, and stale callbacks cannot touch a restarted instance | Separation logic (P-6..P-8), TLC | M–H | 🔴 |
| V-8 | Secret lifetime: temporary keys, Poly1305 keys and plaintext scratch cleared on every exit, also in the compiled code | WP/CBMC + object-code inspection | M–H | 🔴 |
| V-9 | Constant time: no branch or address depends on a secret; MAC comparison leaks no prefix length | Relational CBMC or ct-verif | H | 🔴 |
| V-10 | Crypto and composition: Salsa20 with exactly six double rounds; Poly1305 against its definition; clamping, endianness, partial blocks, 8-byte truncated tag; key mangling excludes the mutable hop bits | Coq/WP, CBMC equivalence | H | 🔴 |
| V-11 | Trace refinement against the reference core for supported inputs, or a stated stricter rejection | CBMC equivalence, abstract model | M–H | 🔴 |
| V-13 | ⚠️ Wire-spec refinement: for every datagram 0–2049 B, classification equals a model built from the reference receive path (`Switch.cpp`, `Packet.hpp`), every intended difference listed. Two rule errors (16-byte fragment, extended armor) were found by review, not by tools | CBMC equivalence + differential corpus; small Coq model later | M | 🔄 CBMC model of the reference receive path in `proofs/wire_cbmc.c` ✅; corpus through both programs 🌱 (V-21) |
| V-14 | Exact consumption: every variable-length record inside its region, cursors only increase, counts match, trailing bytes consumed or explicitly allowed | WP/CBMC | M | 🔴 |
| V-15 | Version and cipher negotiation as a state machine: never emit suites 2/3; reject extended armor and non-HELLO suite 0; behaviour for unknown, stale and cached peer versions | TLA+, CBMC reachability | M | 🔴 |
| V-16 | Request/reply correlation: OK, ERROR, WHOIS and config replies take effect only for an outstanding request with the same packet ID, peer, verb, network and key epoch, once | TLA+, CBMC sequences | M | 🔴 |
| V-17 | ABI and integer portability: same proofs with a 32-bit data model, `_Static_assert` layout probes, wire reads byte-wise and endian-independent | CBMC, WP, target compiler | L–M | ♻️ `run.sh cbmc32` (CBMC `--arch arm` on sources preprocessed by the target compiler) and `wp32` (`-machdep gcc_x86_32`) pass; the target layout `_Static_assert` holds in the target build and in CBMC's arm model. ⚠️ With host headers CBMC's ILP32 model makes `uint64_t` 32 bits wide: always preprocess with the target compiler. WP's model is x86-32, not ARM, for struct layout |
| V-18 | Global table invariants after every public operation: unique pinned identities, each live path owned by one peer, counts ≤ 7/14/1, no half-updated key state | WP, CBMC sequences | M | 🔴 |
| V-19 | Thread and interrupt atomicity: identity and key stable during one authentication; retained references carry a generation that stop/restart invalidates | TLA+, concurrent CBMC | M–H | 🔴 |
| V-20 | Start from arbitrary RAM contents: nothing is live before `ztl_init`; invariants hold before callbacks are enabled | CBMC with nondeterministic pre-state | M | 🔴 |
| V-21 | Proof maintenance: manifest of network-reading source files, each with a harness, or the run fails; tool versions and opam lock recorded; mutants also for contracts and harnesses; differential corpus generated from cover targets | runner, CI | L | 🌱 |
| V-22 | Fault containment for a stated fault model (single bit flip in control metadata), atomic persistent storage if anything is written at run time | CBMC fault injection, TLA+ | M–H | 🔴 |
| V-23 | Progress: every public call returns within fixed loop bounds; watchdog fed only on real progress; cycle and power budgets by measurement, not by proof | CBMC/WP, measurement | M–H | 🔴 |
| V-12 | Whole-system RAM (stacks, pools, alignment) and stack bound including interrupts; compiled code keeps the proved behaviour | Link map, call graph, VST/CompCert samples | M–H | 🔴 |

## Proof method (learned so far)

- ♻️ **Small functions with contracts, proved one by one with WP** is the method that scales to the full packet size. Write code for it from the start: each function does one thing, takes `(pointer, length)` or `(buffer, offsets)`, and its contract says which bytes change and what they equal afterwards.
- ⛔ Whole-module CBMC at full packet size: the SAT formula does not fit (built-in solver stops at its own limit near 78 GB; external Kissat/CaDiCaL passed 370 GB while still encoding). More RAM does not help. Use CBMC at reduced size (`-DZTL_PKT_MAX=64u`) as an independent cross-check, and for bit-level facts.
- ⚠️ WP provers time out on shift-and-mask reasoning: decode with direct comparisons, and let CBMC link the bit-level form to the wire format.
- ⚠️ In an ACSL assertion, a local variable inside `\at(..., Pre)` is out of scope: write `\at(buf[\at(expr, Here)], Pre)`.
- ⚠️ CBMC with a 32-bit model and host headers gives `uint64_t` 32 bits: preprocess with the target compiler.
- ⚠️ No C library calls in the leaf (own bounded copy loops): the provers then analyse the code that runs, and CBMC's `memcpy` model was the first cause of the memory blow-up.
- ⚠️ Intended unsigned wrap-around (clock subtraction) is marked with `#pragma CPROVER check disable "unsigned-overflow"` on that one line; cryptography will need its own profile for this check.
- All prover runs go through `proofs/on-remote.sh` (default `prover-host`) and `proofs/remote.sh` (default `user@big-prover-host`); none on the workstation.

## Supply chain

Grey authorised opam for this strand on 2026-11-12 (Z-m-36); opam 2.6.1 is the official release binary in `~/.local/bin` (Ubuntu's 2.1.5 lacks security fixes). System libraries for opam builds come from apt through Grey (`graphviz`, `libgmp-dev` so far). Binary releases (VeriFast, ESBMC, Isabelle, TLA+) go under `../from-source/` or `../dl/` with a recorded SHA-256; ask Grey per tool.
