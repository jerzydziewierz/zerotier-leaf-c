# Provable ZeroTier leaf in C: exploration checklist

Strand `ztram`;
mode:prototype (TODO Z-48). 
This folder holds the new solution: a wire-compatible ZeroTier leaf in C with no general heap. 

The reference solution is `../grey_zerotier/` (public: `../grey-zerotier-public/`); it stays as the differential oracle. Baseline to beat: 110,508 B add-on linked RAM, 509 KB flash (`compile_probe` pair, 2026-11-12).

❓ = Question for Grey to answer
🥦 = Hypothesis, idea for consideration
💡 = Finding, observation, information
🔴 = Not ready to start
⛔ = Do not attempt. Had that idea, but seems like a bad idea now.
🌱 = Ready to start
⬆️ or ⏭ = In progress at the time of the last update. No reportable result yet
🔄 = Worked on, continuing — can resume but won't finish today.
    * 🔄✅ means "today's bit has been completed, resume tomorrow"
📞 = Waiting for an external event
❗️ = Started, but no success yet due to a solvable problem on the way. On hold
❌ = Tried this, it did not help
✅ = Finished, successful, no need to revisit
♻️ = Done at least once, good result, do that again
⚠️ = High urgency
⚠️⚠️⚠️ = Mega urgency
📅 = Date of next action/review
👥 = Delegated to ...

Each item is closed with one line: what was tried, on which code, the result, and the limit. Evidence tags: [CODE] read in source, [MEASURED] run here, [UNVERIFIED] not yet checked.

## Theorems to aim for

| ID | Statement | Status |
|---|---|---|
| T1 | No undefined behaviour for any received datagram of 0..2048 bytes | 🔄 receive path up to the authenticated, decrypted packet: WP run-time-error guards and "no wrap", full size (reads of unwritten memory are outside WP) |
| T2 | Static bound on stack depth and on total RAM (no recursion, no heap, bounded loops) | 🔴 |
| T3 | No frame reaches the overlay interface unless a pinned peer authenticated it | 🔄 gate proved against the primitive's contract (V-1); "yes means a right MAC" rests on test vectors (V-10); no frame handling yet |
| T4 | Parse and serialise are inverse for every accepted message | 🔴 |
| T5 | Functions never crashes or raises exception for any input | 🔴 |
| T6 | Functions correctly returns error for invalid inputs | 🔴 |
| T7 | Functions always terminates in finite time for any input | 🔴 |
| T8 | Functions output always satisfies the contract (so that downstream function can trust it without further checks) | 🔴 |

## Preferred properties

* Minimise RAM usage, including inter-function data passing costs
* This restricted leaf must be compatible with regular zerotier leafs and controllers

## Design levers

| ID | Item | Status |
|---|---|---|
| D-1 | No general heap: static typed tables (peers, paths, config), one per-call arena, fixed rings (reassembly, TX wait, WHOIS) | ♻️ `struct ztl_leaf` holds everything (gate state, per-peer timers, configuration, certificate, one plain buffer); no heap, no arena, no queue: the caller's one packet buffer is the only other memory |
| D-2 | C instead of C++: no exceptions, no libstdc++, no `SharedPtr`; packet path becomes eligible for ITCM | 🔄 ISO C11, no C library calls, no function pointers so far |
| D-3 | In-place packet processing in one contiguous buffer; no 2 KB packets by value on the stack | 🔄 unfragmented packets are processed in the datagram buffer; a fragmented packet is joined in its reassembly slot; largest stack frame so far 96 B (`ztl_rx`) |
| D-4 | Memory budget table: every struct, count and size, checked at build time (`_Static_assert`) | 🔄 All state is `struct ztl_node`: 4,440 B on the target, pinned by `_Static_assert` in `src/rx.c` (own address and padding 6, peers 7 × 38 = 266, reassembly 2 × 2,072 = 4,144, counters 24). Stack of the receive path, from `-fstack-usage` and the call graph by hand: 456 B (`ztl_rx` 96, `ztl_auth_open` 72, then key stream 288 or tag 272). With the protocol layer: `struct ztl_leaf` 7,136 B on the target (gate 4,440, plain buffer 2,020, certificate 296, per-peer state 168, public key 64, rest 148); receive stack 88 B (`ztl_input`) above the gate's 456. Zephyr module in a firmware build: 15,799 B with thread stack (3,136) and buffers (packet 2,048, frame 1,500, datagram 1,473). 🌱 `_Static_assert` for `struct ztl_leaf`; call-graph tool instead of the hand sum (V-12) |
| D-5 | **Leaf without AES.** 💡 [CODE] `node/Peer.hpp:659` `aesKeysIfSupported()` gives AES keys only when the remote protocol version is ≥ 12; `Packet::armor()` then uses Salsa20/12 + Poly1305 (suite 1). `ZT_PROTO_VERSION_MIN` is 4. So a leaf that announces protocol version 11 in HELLO should get suite 1 in both directions, and needs no AES, no GMAC, no HMAC-SHA384 key derivation (used only for the AES keys, `Peer.cpp:65-67`). ⚠️ Cost: version 13 features are lost (encrypted HELLO, ephemeral keying), and Salsa20/12 is the legacy suite. ✅ [MEASURED] 2026-11-12, host loopback: a leaf core with `ZT_PROTO_VERSION 11`, `aesKeysIfSupported()` always null and `abort()` on both AES code paths passes `tests/interop.py` normal (1500 B and 69 B frames, 7 peers), deny and tamper against the unchanged version-13 reference core. The leaf must do two things: announce version 11 (so that peers send suite 1) and never choose AES itself (upstream chooses by the remote's version). Limit: this ran the reference core, not the C leaf; peers were the 1.16.2 reference core, not a stock `zerotier-one` daemon or the lab controller. ⚠️ D-5a (deployer rule): a peer with `encryptedHelloEnabled` in `local.conf` sends HELLO with extended armor (AES-CTR + ephemeral key, `Packet.cpp:1171`), which a leaf without AES cannot read. [CODE] Default is false (`service/OneService.cpp:2901`). Do not enable it at peers of the leaf. ⚠️ Flag bit 7 with suite 1 is the old "encrypted" flag, set by every peer up to 1.14 on each encrypted packet: accept it. ⚠️ Peers choose the suite from the learned version; incoming AES packets are still possible and the classifier drops them. Grey accepts the loss of encrypted HELLO and ephemeral keying (A-ztram-s2-16). 🌱 Next: same test on the board network; cycles per packet (AES-GMAC-SIV is today's main cost, ≈ 1 M cycles per packet). | 🔄 |
| D-6 | Protocol scope: which verbs the leaf must send, answer and parse | 🔄 ✅ Reading of the reference: [reports/PROTOCOL.md](reports/PROTOCOL.md) (HELLO, OK, ECHO, configuration, credentials, multicast, timings). ✅ Implemented in `src/leaf.c` and exchanged with the reference node on a host (`tests/host/interop.py`). 🌱 A stock `zerotier-one` and a stock controller as the other side (first run on the board); verb counter in the reference host node as a measurement; older peers |
| D-7 | C-rusted discipline: own no-op annotation header (optional, bounds, exclusive/shared, init, nominal types); checked by the open tools below. ECLAIR evaluation: letter in `../dev-docs/email-draft-bugseng-c-rusted.md` | 🌱 |
| D-8 | **No public-key cryptography on the device** (Grey, A-ztram-s1-1/-2, 2026-11-13): fixed-function node, assigned to its network in the factory, provisioned in a secure environment with one 32-byte pairwise key per pinned peer; network configuration accepted only directly from the pinned controller under its pairwise key. No X25519, no Ed25519, no SHA-512 on the device. ✅ [CODE] A plain member signs nothing; apart from the key agreement only "encrypted HELLO" needs the secret, and that stays off (D-5a): [reports/PROTOCOL.md](reports/PROTOCOL.md). ⚠️ Consequences found there: the controller always LZ4-compresses the configuration (a bounded decoder is required, D-9); the membership certificate must be refreshed inside its time window. ✅ Provisioning tool on the host (`tools/provision/`): pairwise key = first 32 bytes of SHA-512 of the Curve25519 result, computed by the reference code (trusted component, not proved); the board's own secret never enters the firmware. ⚠️ Stated limits: the leaf does not evaluate network rules; a configuration must fit one chunk | 🔄 |
| D-9 | Bounded LZ4 block decoder with proof (input and output limits, no read or write outside, every loop bounded): needed for the configuration reply, which a stock controller always compresses (`Node.cpp:889`). ✅ `src/lz4.c` (196 B of code): WP 133 of 133 goals in both data models; 58 blocks made by the reference's `Packet::compress()` decode to the same bytes, in buffers of the exact size; a buffer one byte too small and a block one byte too short are refused; 8 deliberate errors rejected. Every compressed packet from a pinned peer is decoded, not only the configuration. ⚠️ No contract says that the output is the LZ4 meaning of the block (vectors do) | ♻️ |

## Provers and checkers

Order = recommended order of trial. "Have" = installed on this host on 2026-11-12.

| ID | Tool | Class | What it can prove here | Have | Status |
|---|---|---|---|---|---|
| P-1 | CBMC 5.95.1 | Bounded model checking | T1 for all inputs up to the bound; assertions; fits the fixed peer count and 2048 B cap | ✅ `/usr/bin/cbmc` | ♻️ `proofs/wire_cbmc.c`: `ztl_classify()` for every buffer of 0..2049 bytes, exact-size allocation: 506 checks, 0 failed; result equal to a model of the reference receive path in both directions, two listed differences (AES); 11 of 11 cover targets. Reassembly at 64 B (4 harnesses) and gate at 40 B (891 checks, 2 h) pass; gate at 64 B: no result in 6 h. Cryptography (`proofs/crypto_cbmc.c`): limb-limit induction step passes in seconds (runner step `cbmcpoly`); equivalence with reference-form models and seal-then-open: no result after 4 h. `run.sh mutate`: 50 deliberate errors, all rejected |
| P-2 | Frama-C Eva (24.0, 2022) | Abstract interpretation | T1 without bounds; alarms list. Nearest open relative of the C-rusted Analyzer | ✅ apt (reports 25.0-beta) | ♻️ `proofs/wire_eva.c` (Frama-C 33.0): 0 run-time-error alarms, preconditions valid; cannot decide the contract behaviours on unknown bytes (left to P-1, P-3) |
| P-3 | Frama-C WP + ACSL, provers Z3 4.8.12, CVC5 1.1.2 through Why3 1.6.0 | Deductive | Function contracts: T4, table invariants, parts of T3 with crypto as axioms | ✅ through P-4 (Ubuntu `frama-c-base` has no WP plug-in) | ♻️ 7 units, 1,795 goals (32-bit model 1,794), all proved at the full packet size, with unsigned overflow and downcast checks on: exact classifier contract with the packet-id value; reassembly with the whole slot rule; the gate; the cryptography (memory safety, no wrap, the gate's contract of the primitive, Poly1305 step arithmetic). ⚠️ provers time out on shift/mask reasoning: write decoding as comparisons and arithmetic |
| P-4 | Frama-C 33.0 + Alt-Ergo 2.6.4 (opam switch `ztl`, `proofs/opam-setup.sh`) | as P-2, P-3 | Same, newer WP and Eva | ✅ opam 2.6.1 in `~/.local/bin` (release binary, SHA-512 checked) | ✅ installed; Eva and WP both use it |
| P-5 | GCC `-fstack-usage` + call graph | Static stack bound | T2 | ✅ SDK GCC 14.3 | ♻️ `run.sh target`: 3,090 B code for six files (Cortex-M7, `-Os`), largest frame 176 B (`ztl_salsa2012_block`), receive path 456 B by hand sum; no undefined symbol outside the leaf |
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
| P-17 | Wolfram Engine 15.0 (`wolframscript` on `user@big-prover-host`, installed by Grey 2026-11-13) | Computer algebra, not a proof checker | Arithmetic inside the cryptography (V-10). Use it to FIND certificates (cofactors, bounds, witnesses) that a prover then checks | ✅ on big-prover-host | ♻️ `proofs/poly_identity.wl`: the folding identity of the Poly1305 block step holds (expansion gives 0); worst cases under the contract: sums 2^58.4 of 64 bits, last carry 30.4 bits, limb 1 exceeds 26 bits by at most 101. 🥦 Grey (2026-11-13): use `FindInstance` and relatives to find the witness where an automatic prover fails on "there is a k"; first candidate: the multipliers for the whole-message Poly1305 invariant |

## Further proof targets

From two independent reviews (`reports/PROOFS.md`, "Independent reviews"): V-1..V-12 from review 1, V-13..V-23 from review 2. Difficulty L/M/H. Order accepted by Grey (A-ztram-s2-22): settle rule questions (V-13, D-5a) ✅, thin memory and layout budget (D-4, V-17) 🔄, reassembly (V-4) ♻️, authentication gate with a narrow crypto interface (V-1) 🔄, then real Salsa20/12 and Poly1305 (V-10) 🌱.

| ID | Property | Tool | Diff. | Status |
|---|---|---|---|---|
| V-1 | Authentication before effects: failed authentication changes no peer, config, replay or path state and delivers no frame; suite 0 dispatches HELLO only; authorised network checked as well as peer | WP/CBMC; Tamarin for identity binding | M–H | ♻️ `ztl_rx()` contract in `include/ztl/node.h` (ghost record of the primitive call: key, packet, length, answer): WP, full size, both models. The primitive is now code that meets the assumed contract (`src/auth.c`); the delivered body is bound to the authenticated packet; the suite rule is applied to the complete packet. ⚠️ The primitive's contract does not say WHEN it answers yes (test vectors do). CBMC cross-check (`proofs/rx_cbmc.c`): cover 8 of 8, main run ✅ at 40 B on current code (891 checks, 1 h 52 min), ❗ no result at 64 B after 6 h. 🌱 Extend to config, replay and path state when they exist |
| V-2 | Nonce life cycle: no key stream position reused for different data, across restart, wrap and concurrent sends | TLA+, WP/CBMC | M–H | 🔄 Rule in the code: the platform must give `ztl_init()` 64 true random bits at each start; packet IDs count up from them, one per packet, in one place (`begin()`). Within one run no ID repeats before 2^64 packets; across restarts the chance of two runs sharing an ID is about (packets per run × restarts²) / 2^64. Test: the deliberate error "packet ID not advanced" is rejected. ⚠️ Not proved; the random source is the integrator's duty (the Zephyr adapter refuses to start without `sys_csrand_get()`) |
| V-3 | Replay: an accepted packet has no second effect within a stated window or key epoch; unauthenticated input cannot poison that history; no config rollback | TLA+, then CBMC/WP | M | 🔄 Done in code and tests: answers count once; no configuration older than the newest taken since the start (not across a restart); a refusal by the controller only for the waiting request. 🔴 Not done: a replayed frame is delivered again, a replayed packet marks its peer as heard and draws the same answer; no rate limit. Needs a per-peer window of packet IDs after authentication |
| V-4 | Reassembly: order-independent result; duplicates and conflicting parts cannot splice or extend; total length ≤ 2048 (two legal datagrams can exceed it); authentication before dispatch | CBMC, WP | M | ♻️ `src/reasm.c` as small functions with contracts (`src/reasm_internal.h`): WP at full 2048 B, both models, both arrival orders (`proofs/reasm_wp.c`). The slot choice has its whole rule in the contract (timeout with clock wrap, first match, oldest replaced only when every slot is live). CBMC cross-check at 64 B on current code: step 572, order 640, duplicates 629, timeout 570 checks, 0 failed. 🌱 `ztl_reasm_input()` does not yet pass the timeout rule on to its own contract |
| V-5 | Bounded cost and recovery under hostile input: ≤ B operations per datagram; no eviction of pinned peers; slots expire; capacity returns after a flood | WP, TLC | M | 🔴 |
| V-6 | Timer and counter wrap equal an ideal monotonic clock within a stated maximum gap; saturating counters never wrap into permission | CBMC, WP | L–M | 🔴 |
| V-7 | Zephyr ownership and life cycle: each packet buffer released exactly once; no view outlives its buffer; stop waits, wipes, and stale callbacks cannot touch a restarted instance | Separation logic (P-6..P-8), TLC | M–H | 🔴 |
| V-8 | Secret lifetime: temporary keys, Poly1305 keys and plaintext scratch cleared on every exit, also in the compiled code | WP/CBMC + object-code inspection | M–H | 🔄 Every array that held key material is wiped before return (`ztl_wipe`, `ztl_wipe32`: per-packet key, key stream block, Salsa state, Poly1305 r, h, block, tag); WP proves the wipe functions write zeros; an assembly barrier keeps the writes (build error on an unknown compiler). ⚠️ Not covered: scalar copies in registers and stack slots; no tool checks that each exit path calls the wipe (a removed call passes everything) |
| V-9 | Constant time: no branch or address depends on a secret; MAC comparison leaks no prefix length | Relational CBMC or ct-verif | H | 🔄 By construction and by reading the target code only: compare without early exit (`subs`, `uxtab`, one `clz` at the end), Poly1305 final selection by `mul`/`mla` with 0 or 1, no table lookups, loops depend on lengths only. Intended leak: whether the MAC was right (the answer, and the decryption time). ⚠️ A compare with an early exit passes every proof and vector: needs a relational check |
| V-10 | Crypto and composition: Salsa20 with exactly six double rounds; Poly1305 against its definition; clamping, endianness, partial blocks, 8-byte truncated tag; key mangling excludes the mutable hop bits | Coq/WP, CBMC equivalence | H | 🔄 `src/salsa.c`, `src/poly.c`, `src/auth.c`. ✅ Test vectors from the reference `armor()`, Poly1305 and Salsa20/12 (step `vectors`). ✅ WP: no wrap anywhere; Poly1305 limb limits for any length; value contracts for bytes to limbs, block add, block multiply (exact, with the multiple of 2^130 − 5 named) and the final reduction to tag bytes. ✅ CBMC induction step for the limb limits. ❗ CBMC equivalence of whole functions with models in the reference's form (Salsa20/12 block; Poly1305 up to 33 bytes) and seal-then-open: no result in 4 h; 🌱 per-step equivalence instead (workspace TODO Z-49). 🌱 Whole-message Poly1305 contract (recurrence invariant, clamp, padding); Salsa20/12 value contract; "when does open answer yes" in the contract |
| V-11 | Trace refinement against the reference core for supported inputs, or a stated stricter rejection | CBMC equivalence, abstract model | M–H | 🔴 |
| V-13 | ⚠️ Wire-spec refinement: for every datagram 0–2049 B, classification equals a model built from the reference receive path (`Switch.cpp`, `Packet.hpp`), every intended difference listed. Two rule errors (16-byte fragment, extended armor) were found by review, not by tools | CBMC equivalence + differential corpus; small Coq model later | M | 🔄 CBMC model of the reference receive path in `proofs/wire_cbmc.c` ✅; corpus through both programs 🌱 (V-21) |
| V-14 | Exact consumption: every variable-length record inside its region, cursors only increase, counts match, trailing bytes consumed or explicitly allowed | WP/CBMC | M | 🔄 Written into the parsers of `src/leaf.c` (certificate length, optional fields of frames, configuration chunk, address list) and tested: protocol test with exact-size heap blocks under the address sanitizer, deliberate errors "certificate in a frame not checked for its length" and "ECHO longer than a packet answered" rejected. 🌱 As WP contracts |
| V-15 | Version and cipher negotiation as a state machine: never emit suites 2/3; reject extended armor and non-HELLO suite 0; behaviour for unknown, stale and cached peer versions | TLA+, CBMC reachability | M | 🔴 |
| V-16 | Request/reply correlation: OK, ERROR, WHOIS and config replies take effect only for an outstanding request with the same packet ID, peer, verb, network and key epoch, once | TLA+, CBMC sequences | M | 🔄 In the code: OK(HELLO) and the configuration answer count once, for the waiting packet ID and peer; a pushed configuration only from the controller and only if newer. Fixed test cases and 4 deliberate errors (other request, taken twice, any peer, older push) rejected. 🌱 As a contract or model |
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
- ♻️ **Arithmetic without wrap, written as arithmetic.** WP runs with `-warn-unsigned-overflow -warn-unsigned-downcast`. Bytes to words as `p[0] + 256 * p[1] + ...`; limbs with `/` and `%` by powers of two; a result modulo 2^32 as `((uint64_t)a + b) % 4294967296`; a rotation as low bits times 2^c plus high bits. The target compiler emits the same loads, adds and `ror`. The provers then get linear arithmetic and prove value statements, where shifts and masks time out.
- ♻️ **Put the witness into the contract.** "x is a multiple of p" and "there is a k" make the prover search and gave unstable results (the same goal passed and timed out). State the equality with the multiplier named; where it is not a program value, return it through a ghost parameter (`/*@ ghost (uint64_t \ghost *carry) */`). 🥦 Where the witness is not obvious, find it with computer algebra (P-17).
- ♻️ In value contracts use a macro for a sum, not an ACSL logic function: the prover need not unfold a definition through the memory model.
- ⚠️ In a contract or invariant, a predicate at the entry state takes a label, `pred{Pre}(r, x)`, not `\at(pred(r, x), Pre)` or `\old(pred(r, \result))`: the arguments would be evaluated at entry too, where a local or `\result` does not exist.
- ⚠️ A ghost counter that is compared with its entry value needs "below the maximum" as a precondition, which no long-running caller can prove. Count from the start of the call.
- ⚠️ At `-Os` GCC turns a zeroing loop or a zero initializer into a call to `memset`; the runner fails on any undefined symbol that is not `ztl_`. The wipe loops carry an assembly barrier that also stops this.
- ⚠️ WP has no notion of "not initialized": a read of a never-written field is some integer to it. Do not read fields of unused entries.
- A second runner copy (`ZTL_TAG`) keeps its results apart: remote directory `ztl<TAG>`, local `proofs/out-tag<TAG>/`.
- All prover runs go through `proofs/on-remote.sh` (default `prover-host`) and `proofs/remote.sh` (default `user@big-prover-host`); none on the workstation.

## Supply chain

Grey authorised opam for this strand on 2026-11-12 (Z-m-36); opam 2.6.1 is the official release binary in `~/.local/bin` (Ubuntu's 2.1.5 lacks security fixes). System libraries for opam builds come from apt through Grey (`graphviz`, `libgmp-dev` so far). Binary releases (VeriFast, ESBMC, Isabelle, TLA+) go under `../from-source/` or `../dl/` with a recorded SHA-256; ask Grey per tool.
