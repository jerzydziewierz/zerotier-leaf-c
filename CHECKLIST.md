# Provable ZeroTier leaf in C: exploration checklist

Strand `ztram`;
mode:prototype (TODO Z-48). 
This folder holds the new solution: a wire-compatible ZeroTier leaf in C with no general heap. 

The reference solution is `../grey_zerotier/` (public: `../grey-zerotier-public/`); it stays as the differential oracle. Baseline to beat: the RAM and the code that the reference adds; the figures are in `README-MORE.md`, "Status".


--

Work and progress markers:

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

--

Each item is closed with one line: what was tried, on which code, the result, and the limit. Evidence tags: [CODE] read in source, [MEASURED] run here, [UNVERIFIED] not yet checked.

## Theorems to aim for

```yaml
- id: T1
  statement: "No undefined behaviour for any received datagram of 0..2048 bytes"
  status: >-
    ✅ for the whole leaf (all nine source files), at full size, in both data models, for the kinds
    of error that WP checks: invalid pointer use, access outside the named memory, division by zero,
    shift out of range, signed overflow; and, stricter than C, no unsigned wrap and no lossy
    conversion (L-1 to L-5 in `reports/PROOFS.md`, list of proofs). ⚠️ Outside WP's model: reads of
    memory that was never written, pointer alignment, the compiled code
- id: T2
  statement: "Static bound on stack depth and on total RAM (no recursion, no heap, bounded loops)"
  status: >-
    🔄 RAM: all state is one `struct ztl_leaf`, 7,136 B on the target, pinned by `_Static_assert`
    (D-4); no heap. Loops: each of the 36 has a proved bound (T7). No recursion (by reading; no tool
    states it). Stack: per function from `-fstack-usage`, summed by hand along the call graph (D-4).
    🌱 a tool for the stack sum, interrupts included (V-12)
- id: T3
  statement: "No frame reaches the overlay interface unless a pinned peer authenticated it"
  status: >-
    🔄 Proved as structure, for the whole leaf: `ztl_input()` gives a frame or a reply only after the
    gate's one call of the authentication primitive answered yes, with the key of a pinned peer
    whose address is the packet's source (L-13, L-23). Not proved: that a yes means a right MAC
    (test vectors from the reference, V-10); a replayed packet passes again (V-3)
- id: T4
  statement: "Parse and serialise are inverse for every accepted message"
  status: "🔴"
- id: T5
  statement: "Functions never crashes or raises exception for any input"
  status: >-
    ✅ every function of the nine source files, both data models (L-1): for every input that meets
    the function's preconditions. For the public functions these are "valid buffers that do not
    overlap, and a started node": the contents and the length of a datagram are free. ⚠️ Limits of
    WP's model as in T1
- id: T6
  statement: "Functions correctly returns error for invalid inputs"
  status: >-
    🔄 Proved exactly where the rule is in a contract: the classifier drops by the exact written rule
    and writes nothing (L-7); without a yes the gate delivers nothing and leaves its output
    untouched (L-13 to L-15); after the answer no, `ztl_auth_open()` leaves the packet unchanged
    (L-17); a configuration with an MTU out of range cannot come into use (L-28). Not proved,
    tested: which LZ4 blocks, dictionaries and protocol messages are refused (E-2, E-4, E-5 in
    `reports/PROOFS.md`); their contracts bound memory and results only
- id: T7
  statement: "Functions always terminates in finite time for any input"
  status: >-
    ✅ each of the 36 loops has a bound that WP proves (loop variant); no function calls itself and
    none calls outside the leaf (the target build fails on any undefined symbol), so every call
    returns (L-4). ⚠️ A bound in loop rounds, not in seconds: no timing statement (V-23)
- id: T8
  statement: >-
    Functions output always satisfies the contract (so that downstream function can trust it without
    further checks)
  status: >-
    ✅ every function is proved against its own contract, and each caller is proved from the
    contracts of what it calls, not from their code (L-6); the public contracts are in
    `include/ztl/`. ⚠️ A contract can say too little: the deliberate errors and the search for
    contradictory preconditions are the guard (E-7, E-10)
- id: T9
  statement: "Functions never read memory outside bounds (no risk of leaking system data)"
  status: >-
    ✅ every read is proved to lie inside memory that the contract names as readable (L-2); for the
    LZ4 decoder also: no match copies from before the start of the output (L-21). ⚠️ A read of own
    memory that was never written is outside WP's model (found once by review, F-24); the protocol
    test runs under the address sanitizer with exact-size heap blocks for that
- id: T10
  statement: "Functions never write memory outside bounds (no side effects)"
  status: >-
    ✅ each contract lists what the function may change (`assigns`), and WP proves that nothing else
    changes (L-3). For `ztl_input()` the list leaves out the own address, the pinned peers and their
    keys, the public key, the network ID and the controller index (L-24)
```


## Preferred properties

* Minimise RAM usage, including inter-function data passing costs
* This restricted leaf must be compatible with regular zerotier leafs and controllers

## Design levers

```yaml
- id: D-1
  item: >-
    No general heap: static typed tables (peers, paths, config), one per-call arena, fixed rings
    (reassembly, TX wait, WHOIS)
  status: >-
    ♻️ `struct ztl_leaf` holds everything (gate state, per-peer timers, configuration, certificate,
    one plain buffer); no heap, no arena, no queue: the caller's one packet buffer is the only other
    memory
- id: D-2
  item: >-
    C instead of C++: no exceptions, no libstdc++, no `SharedPtr`; packet path becomes eligible for
    ITCM
  status: "🔄 ISO C11, no C library calls, no function pointers so far"
- id: D-3
  item: "In-place packet processing in one contiguous buffer; no 2 KB packets by value on the stack"
  status: >-
    🔄 unfragmented packets are processed in the datagram buffer; a fragmented packet is joined in
    its reassembly slot; largest stack frame 176 B (`ztl_salsa2012_block`); no packet lies on the stack
- id: D-4
  item: >-
    Memory budget table: every struct, count and size, checked at build time (`_Static_assert`)
  status: >-
    🔄 All state is one `struct ztl_leaf`: 7,136 B on the target, pinned by `_Static_assert` in
    `src/leaf.c` (gate 4,440, plain buffer 2,020, certificate 296, per-peer state 7 × 32 = 224,
    public key 64, rest 92). The gate is `struct ztl_node`, pinned in `src/rx.c` (own address and
    padding 6, peers 7 × 38 = 266, reassembly 2 × 2,072 = 4,144, counters 24). Stack, from
    `-fstack-usage` and the call graph by hand: 456 B below the gate (`ztl_rx` 96, `ztl_auth_open`
    72, then key stream 288 or tag 272), `ztl_input` 80 B above it. Zephyr module in a firmware build: 15,832 B with thread stack (3,136) and buffers (packet 2,048, frame 1,500, datagram
    1,473). 🌱 call-graph tool instead of the hand sum (V-12)
- id: D-5
  item: >-
    Leaf without AES. 💡 [CODE] `node/Peer.hpp:659` `aesKeysIfSupported()` gives AES keys only when
    the remote protocol version is ≥ 12; `Packet::armor()` then uses Salsa20/12 + Poly1305 (suite
    1). `ZT_PROTO_VERSION_MIN` is 4. So a leaf that announces protocol version 11 in HELLO should
    get suite 1 in both directions, and needs no AES, no GMAC, no HMAC-SHA384 key derivation (used
    only for the AES keys, `Peer.cpp:65-67`). ⚠️ Cost: version 13 features are lost (encrypted
    HELLO, ephemeral keying), and Salsa20/12 is the legacy suite. ✅ [MEASURED] 2026-11-12, host
    loopback: a leaf core with `ZT_PROTO_VERSION 11`, `aesKeysIfSupported()` always null and
    `abort()` on both AES code paths passes the reference solution's `../grey_zerotier/tests/interop.py` normal (1500 B and 69 B frames, 7
    peers), deny and tamper against the unchanged version-13 reference core. The leaf must do two
    things: announce version 11 (so that peers send suite 1) and never choose AES itself (upstream
    chooses by the remote's version). Limit: this ran the reference core, not the C leaf; peers were
    the 1.16.2 reference core, not a stock `zerotier-one` daemon or the lab controller. ⚠️ D-5a
    (deployer rule): a peer with `encryptedHelloEnabled` in `local.conf` sends HELLO with extended
    armor (AES-CTR + ephemeral key, `Packet.cpp:1171`), which a leaf without AES cannot read. [CODE]
    Default is false (`service/OneService.cpp:2901`). Do not enable it at peers of the leaf. ⚠️ Flag
    bit 7 with suite 1 is the old "encrypted" flag, set by every peer up to 1.14 on each encrypted
    packet: accept it. ⚠️ Peers choose the suite from the learned version; incoming AES packets are
    still possible and the classifier drops them. Grey accepts the loss of encrypted HELLO and
    ephemeral keying (A-ztram-s2-16). ✅ The C leaf itself now runs on the board network (D-6). 🌱 Cycles per packet
    (AES-GMAC-SIV is today's main cost, ≈ 1 M cycles per packet).
  status: "🔄"
- id: D-6
  item: "Protocol scope: which verbs the leaf must send, answer and parse"
  status: >-
    🔄 ✅ Reading of the reference: [reports/PROTOCOL.md](reports/PROTOCOL.md) (HELLO, OK, ECHO,
    configuration, credentials, multicast, timings). ✅ Implemented in `src/leaf.c` and exchanged
    with the reference node on a host (`tests/host/interop.py`). ✅ A stock controller and stock
    1.16.2 peers as the other side, on the board (an observation, see `reports/PROOFS.md`, "What all
    of this does not show"). 🌱 Verb counter in the reference host node as a measurement; older peers
- id: D-7
  item: >-
    C-rusted discipline: own no-op annotation header (optional, bounds, exclusive/shared, init,
    nominal types); checked by the open tools below. ECLAIR evaluation: letter in
    `../dev-docs/email-draft-bugseng-c-rusted.md`
  status: >-
    🔄 `include/ztl/annot.h` exists (no nominal types yet) and every public header uses it; no tool
    checks the annotations themselves (P-16)
- id: D-8
  item: >-
    No public-key cryptography on the device (Grey, A-ztram-s1-1/-2, 2026-11-13): fixed-function
    node, assigned to its network in the factory, provisioned in a secure environment with one
    32-byte pairwise key per pinned peer; network configuration accepted only directly from the
    pinned controller under its pairwise key. No X25519, no Ed25519, no SHA-512 on the device. ✅
    [CODE] A plain member signs nothing; apart from the key agreement only "encrypted HELLO" needs
    the secret, and that stays off (D-5a): [reports/PROTOCOL.md](reports/PROTOCOL.md). ⚠️
    Consequences found there: the controller always LZ4-compresses the configuration (a bounded
    decoder is required, D-9); the membership certificate must be refreshed inside its time window.
    ✅ Provisioning tool on the host (`tools/provision/`): pairwise key = first 32 bytes of SHA-512
    of the Curve25519 result, computed by the reference code (trusted component, not proved); the
    board's own secret never enters the firmware. ⚠️ Stated limits: the leaf does not evaluate
    network rules; a configuration must fit one chunk
  status: "🔄"
- id: D-9
  item: >-
    Bounded LZ4 block decoder with proof (input and output limits, no read or write outside, every
    loop bounded): needed for the configuration reply, which a stock controller always compresses
    (`Node.cpp:889`). ✅ `src/lz4.c` (196 B of code): WP 133 of 133 goals in both data models; 58
    blocks made by the reference's `Packet::compress()` decode to the same bytes, in buffers of the
    exact size; a buffer one byte too small and a block one byte too short are refused; 8 deliberate
    errors rejected. Every compressed packet from a pinned peer is decoded, not only the
    configuration. ⚠️ No contract says that the output is the LZ4 meaning of the block (vectors do)
  status: "♻️"
```

## Provers and checkers

Order = recommended order of trial. "Have" = installed on this host on 2026-11-12.

```yaml
- id: P-1
  tool: "CBMC 5.95.1"
  class: "Bounded model checking"
  can_prove_here: >-
    T1 for all inputs up to the bound; assertions; fits the fixed peer count and 2048 B cap
  have: "✅ `/usr/bin/cbmc`"
  status: >-
    ♻️ `proofs/wire_cbmc.c`: `ztl_classify()` for every buffer of 0..2049 bytes, exact-size
    allocation: 506 checks, 0 failed; result equal to a model of the reference receive path in both
    directions, two listed differences (AES); 11 of 11 cover targets. Reassembly at 64 B (4
    harnesses) and gate at 40 B (891 checks, 1 h 25 min) pass; gate at 64 B: no result in 6 h. Cryptography
    (`proofs/crypto_cbmc.c`): limb-limit induction step passes in seconds (runner step `cbmcpoly`);
    equivalence with reference-form models and seal-then-open: no result after 4 h. `run.sh mutate`:
    102 deliberate errors in 114 tool runs (CBMC, WP, test vectors, protocol test), all rejected
- id: P-2
  tool: "Frama-C Eva (24.0, 2022)"
  class: "Abstract interpretation"
  can_prove_here: "T1 without bounds; alarms list. Nearest open relative of the C-rusted Analyzer"
  have: "✅ apt (reports 25.0-beta)"
  status: >-
    ♻️ `proofs/wire_eva.c` (Frama-C 33.0): 0 run-time-error alarms, preconditions valid; cannot
    decide the contract behaviours on unknown bytes (left to P-1, P-3)
- id: P-3
  tool: "Frama-C WP + ACSL, provers Z3 4.8.12, CVC5 1.1.2 through Why3 1.6.0"
  class: "Deductive"
  can_prove_here: "Function contracts: T4, table invariants, parts of T3 with crypto as axioms"
  have: "✅ through P-4 (Ubuntu `frama-c-base` has no WP plug-in)"
  status: >-
    ♻️ 10 units (the nine source files and the two arrival orders of reassembly), 3,971 goals
    (32-bit model 3,976), all proved at the full packet size, with unsigned overflow and downcast
    checks on: exact classifier contract with the packet-id value; reassembly with the whole slot
    rule; the gate; the cryptography (memory safety, no wrap, the gate's contract of the primitive,
    Poly1305 step arithmetic); the LZ4 decoder and the dictionary reader (memory safety); the whole
    protocol layer (memory safety, data invariant, authentication before effects, one packet ID for
    each packet, bounds). The statements: `reports/PROOFS.md`, list of proofs. ⚠️ provers time out
    on shift/mask reasoning: write decoding as comparisons and arithmetic
- id: P-4
  tool: "Frama-C 33.0 + Alt-Ergo 2.6.4 (opam switch `ztl`, `proofs/opam-setup.sh`)"
  class: "as P-2, P-3"
  can_prove_here: "Same, newer WP and Eva"
  have: "✅ opam 2.6.1 in `~/.local/bin` (release binary, SHA-512 checked)"
  status: "✅ installed; Eva and WP both use it"
- id: P-5
  tool: "GCC `-fstack-usage` + call graph"
  class: "Static stack bound"
  can_prove_here: "T2"
  have: "✅ SDK GCC 14.3"
  status: >-
    ♻️ `run.sh target`: 7,688 B code for nine files (Cortex-M7, `-Os`), largest frame 176 B
    (`ztl_salsa2012_block`), receive path 456 B below the gate and 80 B above it by hand sum; no
    undefined symbol outside the leaf
- id: P-6
  tool: "VeriFast"
  class: "Separation logic"
  can_prove_here: "Ownership and aliasing as proof objects; closest to C-rusted's ownership ideas"
  have: "🔴 binary release, vendor download"
  status: "🔴"
- id: P-7
  tool: "CN (Cerberus)"
  class: "Separation-logic refinement types"
  can_prove_here: "As P-6, with a formal C semantics"
  have: "🔴 opam"
  status: "🔴"
- id: P-8
  tool: "RefinedC"
  class: "Ownership types, foundational (Coq)"
  can_prove_here: "As P-6, proof checked by Coq"
  have: "🔴 opam"
  status: "🔴"
- id: P-9
  tool: "VST + CompCert (Coq 8.18)"
  class: "Foundational"
  can_prove_here: "One small function end to end, for the experience and the comparison"
  have: "Coq ✅; VST 🔴 opam"
  status: "🔴"
- id: P-10
  tool: "Isabelle + AutoCorres"
  class: "Foundational (seL4 style)"
  can_prove_here: "As P-9"
  have: "🔴 download"
  status: "🔴"
- id: P-11
  tool: "ESBMC"
  class: "Bounded model checking, k-induction"
  can_prove_here: "Cross-check of P-1; unbounded loops by k-induction"
  have: "🔴 binary release"
  status: "🔴"
- id: P-12
  tool: "ProVerif or Tamarin"
  class: "Symbolic protocol model"
  can_prove_here: >-
    Handshake secrecy and authentication, independent of C code; no published ZeroTier analysis
    found
  have: "🔴 opam / download"
  status: "🔴"
- id: P-13
  tool: "TLA+ (TLC)"
  class: "State-machine model checking"
  can_prove_here: "Peer/path/reassembly state machines: no stuck state, bounded queues"
  have: "🔴 download (Java)"
  status: "🔴"
- id: P-14
  tool: "HACL* (verified C from F*)"
  class: "Verified crypto, reuse"
  can_prove_here: >-
    Ed25519, X25519, Poly1305, SHA-512 with existing proofs. ⚠️ [CODE] HACL* `Hacl_Salsa20.c` is
    fixed at 20 rounds (10 double rounds, no round parameter); ZeroTier uses Salsa20/12, so the
    stream cipher is not covered: keep ZeroTier's Salsa20 and check it with P-1/P-3 against HACL*'s
    structure, or generate a 12-round variant from the F* source
  have: "🔴 vendor source build"
  status: "🌱"
- id: P-15
  tool: "Differential test against the reference core"
  class: "Testing, not proof"
  can_prove_here: "Same outputs for the same packet traces; fuzz corpus"
  have: "✅ host tests exist"
  status: >-
    🔄 `tests/host/interop.py`: the leaf against the reference node on loopback, five cases pass (E-6
    in `reports/PROOFS.md`). 🌱 Same packet traces through both; fuzz corpus
- id: P-16
  tool: "ECLAIR C-rusted Analyzer"
  class: "Commercial"
  can_prove_here: "The C-rusted annotations themselves"
  have: "🔴 licence"
  status: "📞 letter"
- id: P-17
  tool: "Wolfram Engine 15.0 (`wolframscript` on the large prover host, installed 2026-11-13)"
  class: "Computer algebra, not a proof checker"
  can_prove_here: >-
    Arithmetic inside the cryptography (V-10). Use it to FIND certificates (cofactors, bounds,
    witnesses) that a prover then checks
  have: "✅ on the large prover host"
  status: >-
    ♻️ `proofs/poly_identity.wl`: the folding identity of the Poly1305 block step holds (expansion
    gives 0); worst cases under the contract: sums 2^58.4 of 64 bits, last carry 30.4 bits, limb 1
    exceeds 26 bits by at most 101. 🥦 Grey (2026-11-13): use `FindInstance` and relatives to find
    the witness where an automatic prover fails on "there is a k"; first candidate: the multipliers
    for the whole-message Poly1305 invariant
```

## Further proof targets

From two independent reviews (`reports/PROOFS.md`, "Independent reviews"): V-1..V-12 from review 1, V-13..V-23 from review 2. Difficulty L/M/H. Order accepted by Grey (A-ztram-s2-22): settle rule questions (V-13, D-5a) ✅, thin memory and layout budget (D-4, V-17) 🔄, reassembly (V-4) ♻️, authentication gate with a narrow crypto interface (V-1) ♻️, then real Salsa20/12 and Poly1305 (V-10) 🔄.

```yaml
- id: V-1
  property: >-
    Authentication before effects: failed authentication changes no peer, config, replay or path
    state and delivers no frame; suite 0 dispatches HELLO only; authorised network checked as well
    as peer
  tool: "WP/CBMC; Tamarin for identity binding"
  difficulty: "M–H"
  status: >-
    ♻️ `ztl_rx()` contract in `include/ztl/node.h` (ghost record of the primitive call: key, packet,
    length, answer): WP, full size, both models. The primitive is now code that meets the assumed
    contract (`src/auth.c`); the delivered body is bound to the authenticated packet; the suite rule
    is applied to the complete packet. ⚠️ The primitive's contract does not say WHEN it answers yes
    (test vectors do). CBMC cross-check (`proofs/rx_cbmc.c`): cover 8 of 8, main run ✅ at 40 B on
    current code (891 checks, 1 h 25 min, CBMC 6.6.0), ❗ no result at 64 B after 6 h. ✅ Extended to the whole
    leaf: the contract of `ztl_input()` says that a reply or a frame comes only after the gate's one
    call that answered yes, and its list of what may change leaves out the own address, the pinned
    peers, their keys, the public key, the network ID and the controller index (L-23, L-24). 🔴
    Replay (V-3)
- id: V-2
  property: >-
    Nonce life cycle: no key stream position reused for different data, across restart, wrap and
    concurrent sends
  tool: "TLA+, WP/CBMC"
  difficulty: "M–H"
  status: >-
    🔄 Rule in the code: the platform must give `ztl_init()` 64 true random bits at each start;
    packet IDs count up from them, one per packet, in one place (`begin()`). Within one run no ID
    repeats before 2^64 packets; across restarts the chance of two runs sharing an ID is about
    (packets per run × restarts²) / 2^64. ✅ Proved (WP): every function that builds a packet moves
    the counter by exactly one (to 0 only after 2^64 − 1), and a call that builds no packet leaves
    it (L-25); the deliberate errors "packet ID not advanced" and "two IDs for one answer" are
    rejected. ⚠️ Not proved: no repeat across restarts; the random source is the integrator's duty
    (the Zephyr adapter refuses to start without `sys_csrand_get()`). One caller at a time (V-19)
- id: V-3
  property: >-
    Replay: an accepted packet has no second effect within a stated window or key epoch;
    unauthenticated input cannot poison that history; no config rollback
  tool: "TLA+, then CBMC/WP"
  difficulty: "M"
  status: >-
    🔄 Done in code and tests: answers count once; no configuration older than the newest taken since
    the start (not across a restart); a refusal by the controller only for the waiting request. 🔴
    Not done: a replayed frame is delivered again, a replayed packet marks its peer as heard and
    draws the same answer; no rate limit. Needs a per-peer window of packet IDs after authentication
- id: V-4
  property: >-
    Reassembly: order-independent result; duplicates and conflicting parts cannot splice or extend;
    total length ≤ 2048 (two legal datagrams can exceed it); authentication before dispatch
  tool: "CBMC, WP"
  difficulty: "M"
  status: >-
    ♻️ `src/reasm.c` as small functions with contracts (`src/reasm_internal.h`): WP at full 2048 B,
    both models, both arrival orders (`proofs/reasm_wp.c`). The slot choice has its whole rule in
    the contract (timeout with clock wrap, first match, oldest replaced only when every slot is
    live). CBMC cross-check at 64 B on current code: step 572, order 640, duplicates 629, timeout
    570 checks, 0 failed. 🌱 `ztl_reasm_input()` does not yet pass the timeout rule on to its own
    contract
- id: V-5
  property: >-
    Bounded cost and recovery under hostile input: ≤ B operations per datagram; no eviction of
    pinned peers; slots expire; capacity returns after a flood
  tool: "WP, TLC"
  difficulty: "M"
  status: "🔴"
- id: V-6
  property: >-
    Timer and counter wrap equal an ideal monotonic clock within a stated maximum gap; saturating
    counters never wrap into permission
  tool: "CBMC, WP"
  difficulty: "L–M"
  status: "🔴"
- id: V-7
  property: >-
    Zephyr ownership and life cycle: each packet buffer released exactly once; no view outlives its
    buffer; stop waits, wipes, and stale callbacks cannot touch a restarted instance
  tool: "Separation logic (P-6..P-8), TLC"
  difficulty: "M–H"
  status: "🔴"
- id: V-8
  property: >-
    Secret lifetime: temporary keys, Poly1305 keys and plaintext scratch cleared on every exit, also
    in the compiled code
  tool: "WP/CBMC + object-code inspection"
  difficulty: "M–H"
  status: >-
    🔄 Every array that held key material is wiped before return (`ztl_wipe`, `ztl_wipe32`:
    per-packet key, key stream block, Salsa state, Poly1305 r, h, block, tag); WP proves the wipe
    functions write zeros; an assembly barrier keeps the writes (build error on an unknown
    compiler). ⚠️ Not covered: scalar copies in registers and stack slots; no tool checks that each
    exit path calls the wipe (a removed call passes everything)
- id: V-9
  property: >-
    Constant time: no branch or address depends on a secret; MAC comparison leaks no prefix length
  tool: "Relational CBMC or ct-verif"
  difficulty: "H"
  status: >-
    🔄 By construction and by reading the target code only: compare without early exit (`subs`,
    `uxtab`, one `clz` at the end), Poly1305 final selection by `mul`/`mla` with 0 or 1, no table
    lookups, loops depend on lengths only. Intended leak: whether the MAC was right (the answer, and
    the decryption time). ⚠️ A compare with an early exit passes every proof and vector: needs a
    relational check
- id: V-10
  property: >-
    Crypto and composition: Salsa20 with exactly six double rounds; Poly1305 against its definition;
    clamping, endianness, partial blocks, 8-byte truncated tag; key mangling excludes the mutable
    hop bits
  tool: "Coq/WP, CBMC equivalence"
  difficulty: "H"
  status: >-
    🔄 `src/salsa.c`, `src/poly.c`, `src/auth.c`. ✅ Test vectors from the reference `armor()`,
    Poly1305 and Salsa20/12 (step `vectors`). ✅ WP: no wrap anywhere; Poly1305 limb limits for any
    length; value contracts for bytes to limbs, block add, block multiply (exact, with the multiple
    of 2^130 − 5 named) and the final reduction to tag bytes. ✅ CBMC induction step for the limb
    limits. ❗ CBMC equivalence of whole functions with models in the reference's form (Salsa20/12
    block; Poly1305 up to 33 bytes) and seal-then-open: no result in 4 h; 🌱 per-step equivalence
    instead (workspace TODO Z-49). 🌱 Whole-message Poly1305 contract (recurrence invariant, clamp,
    padding); Salsa20/12 value contract; "when does open answer yes" in the contract
- id: V-11
  property: >-
    Trace refinement against the reference core for supported inputs, or a stated stricter rejection
  tool: "CBMC equivalence, abstract model"
  difficulty: "M–H"
  status: "🔴"
- id: V-13
  property: >-
    ⚠️ Wire-spec refinement: for every datagram 0–2049 B, classification equals a model built from
    the reference receive path (`Switch.cpp`, `Packet.hpp`), every intended difference listed. Two
    rule errors (16-byte fragment, extended armor) were found by review, not by tools
  tool: "CBMC equivalence + differential corpus; small Coq model later"
  difficulty: "M"
  status: >-
    🔄 CBMC model of the reference receive path in `proofs/wire_cbmc.c` ✅; corpus through both
    programs 🌱 (V-21)
- id: V-14
  property: >-
    Exact consumption: every variable-length record inside its region, cursors only increase, counts
    match, trailing bytes consumed or explicitly allowed
  tool: "WP/CBMC"
  difficulty: "M"
  status: >-
    🔄 Written into the parsers of `src/leaf.c` (certificate length, optional fields of frames,
    configuration chunk, address list) and tested: protocol test with exact-size heap blocks under
    the address sanitizer, deliberate errors "certificate in a frame not checked for its length" and
    "ECHO longer than a packet answered" rejected. ✅ The memory side is proved: every parser of
    `src/leaf.c` stays inside its record (E-9 in `reports/PROOFS.md`). 🌱 "Trailing bytes are
    consumed or refused" as a contract
- id: V-15
  property: >-
    Version and cipher negotiation as a state machine: never emit suites 2/3; reject extended armor
    and non-HELLO suite 0; behaviour for unknown, stale and cached peer versions
  tool: "TLA+, CBMC reachability"
  difficulty: "M"
  status: "🔴"
- id: V-16
  property: >-
    Request/reply correlation: OK, ERROR, WHOIS and config replies take effect only for an
    outstanding request with the same packet ID, peer, verb, network and key epoch, once
  tool: "TLA+, CBMC sequences"
  difficulty: "M"
  status: >-
    🔄 In the code: OK(HELLO) and the configuration answer count once, for the waiting packet ID and
    peer; a pushed configuration only from the controller and only if newer. Fixed test cases and 4
    deliberate errors (other request, taken twice, any peer, older push) rejected. 🌱 As a contract
    or model
- id: V-17
  property: >-
    ABI and integer portability: same proofs with a 32-bit data model, `_Static_assert` layout
    probes, wire reads byte-wise and endian-independent
  tool: "CBMC, WP, target compiler"
  difficulty: "L–M"
  status: >-
    ♻️ `run.sh cbmc32` (CBMC `--arch arm` on sources preprocessed by the target compiler) and `wp32`
    (`-machdep gcc_x86_32`) pass; the target layout `_Static_assert` holds in the target build and
    in CBMC's arm model. ⚠️ With host headers CBMC's ILP32 model makes `uint64_t` 32 bits wide:
    always preprocess with the target compiler. WP's model is x86-32, not ARM, for struct layout
- id: V-18
  property: >-
    Global table invariants after every public operation: unique pinned identities, each live path
    owned by one peer, counts ≤ 7/14/1, no half-updated key state
  tool: "WP, CBMC sequences"
  difficulty: "M"
  status: >-
    🔄 `ztl_leaf_ok()` in `include/ztl/leaf.h` (reassembly memory valid, certificate length within
    its buffer, controller index in range, MTU 1280 to 1500 and a certificate while a configuration
    is in use) is proved after start and after every public call (L-28); the peer table (addresses,
    pinned marks, keys) is written by `ztl_init()` and `ztl_pin()` only: no other public function
    has it in its list of what may change (L-24). 🔴 Not in the invariant: unique pinned addresses
    (`ztl_pin()` refuses a second one in code and in a test)
- id: V-19
  property: >-
    Thread and interrupt atomicity: identity and key stable during one authentication; retained
    references carry a generation that stop/restart invalidates
  tool: "TLA+, concurrent CBMC"
  difficulty: "M–H"
  status: "🔴"
- id: V-20
  property: >-
    Start from arbitrary RAM contents: nothing is live before `ztl_init`; invariants hold before
    callbacks are enabled
  tool: "CBMC with nondeterministic pre-state"
  difficulty: "M"
  status: "🔴"
- id: V-21
  property: >-
    Proof maintenance: manifest of network-reading source files, each with a harness, or the run
    fails; tool versions and opam lock recorded; mutants also for contracts and harnesses;
    differential corpus generated from cover targets
  tool: "runner, CI"
  difficulty: "L"
  status: >-
    🔄 All nine files of `src/` are WP units; `run.sh smoke` looks for contradictory preconditions
    and unreachable code. 🌱 The runner lists its units by name: a check that every file of `src/` is
    in the list; versions and lock file; mutants of contracts; the corpus
- id: V-22
  property: >-
    Fault containment for a stated fault model (single bit flip in control metadata), atomic
    persistent storage if anything is written at run time
  tool: "CBMC fault injection, TLA+"
  difficulty: "M–H"
  status: "🔴"
- id: V-23
  property: >-
    Progress: every public call returns within fixed loop bounds; watchdog fed only on real
    progress; cycle and power budgets by measurement, not by proof
  tool: "CBMC/WP, measurement"
  difficulty: "M–H"
  status: >-
    🔄 Every public call returns: each loop has a proved bound (T7). 🔴 No bound as a number of
    operations; cycles per packet not measured yet
- id: V-12
  property: >-
    Whole-system RAM (stacks, pools, alignment) and stack bound including interrupts; compiled code
    keeps the proved behaviour
  tool: "Link map, call graph, VST/CompCert samples"
  difficulty: "M–H"
  status: "🌱 first step: a call-graph tool for the stack sum (T2, D-4); the rest 🔴"
```

## Proof method (learned so far)

- ♻️ **Small functions with contracts, proved one by one with WP** is the method that scales to the full packet size. Write code for it from the start: each function does one thing, takes `(pointer, length)` or `(buffer, offsets)`, and its contract says which bytes change and what they equal afterwards.
- ⛔ Whole-module CBMC at full packet size: the SAT formula does not fit (built-in solver stops at its own limit near 78 GB; external Kissat/CaDiCaL passed 370 GB while still encoding). More RAM does not help. Use CBMC at reduced size (`-DZTL_PKT_MAX=64u`) as an independent cross-check, and for bit-level facts.
- ⚠️ WP provers time out on shift-and-mask reasoning: decode with direct comparisons, and let CBMC link the bit-level form to the wire format.
- ⚠️ In an ACSL assertion, a local variable inside `\at(..., Pre)` is out of scope: write `\at(buf[\at(expr, Here)], Pre)`.
- ⚠️ CBMC with a 32-bit model and host headers gives `uint64_t` 32 bits: preprocess with the target compiler.
- ⚠️ No C library calls in the leaf (own bounded copy loops): the provers then analyse the code that runs, and CBMC's `memcpy` model was the first cause of the memory blow-up.
- ⚠️ No intended unsigned wrap-around in `src/`: the clock difference is `(2^32 + now - then) % 2^32` in 64-bit arithmetic. `#pragma CPROVER check disable "unsigned-overflow"` is left only in two CBMC harnesses (`proofs/reasm_cbmc.c`, `proofs/crypto_cbmc.c`), on the lines that model a wrap.
- ♻️ **Arithmetic without wrap, written as arithmetic.** WP runs with `-warn-unsigned-overflow -warn-unsigned-downcast`. Bytes to words as `p[0] + 256 * p[1] + ...`; limbs with `/` and `%` by powers of two; a result modulo 2^32 as `((uint64_t)a + b) % 4294967296`; a rotation as low bits times 2^c plus high bits. The target compiler emits the same loads, adds and `ror`. The provers then get linear arithmetic and prove value statements, where shifts and masks time out.
- ♻️ **Put the witness into the contract.** "x is a multiple of p" and "there is a k" make the prover search and gave unstable results (the same goal passed and timed out). State the equality with the multiplier named; where it is not a program value, return it through a ghost parameter (`/*@ ghost (uint64_t \ghost *carry) */`). 🥦 Where the witness is not obvious, find it with computer algebra (P-17).
- ♻️ In value contracts use a macro for a sum, not an ACSL logic function: the prover need not unfold a definition through the memory model.
- ⚠️ In a contract or invariant, a predicate at the entry state takes a label, `pred{Pre}(r, x)`, not `\at(pred(r, x), Pre)` or `\old(pred(r, \result))`: the arguments would be evaluated at entry too, where a local or `\result` does not exist.
- ⚠️ A ghost counter that is compared with its entry value needs "below the maximum" as a precondition, which no long-running caller can prove. Count from the start of the call.
- ⚠️ At `-Os` GCC turns a zeroing loop or a zero initializer into a call to `memset`; the runner fails on any undefined symbol that is not `ztl_`. The wipe loops carry an assembly barrier that also stops this.
- ⚠️ WP has no notion of "not initialized": a read of a never-written field is some integer to it. Do not read fields of unused entries.
- A second runner copy (`ZTL_TAG`) keeps its results apart: remote directory `ztl<TAG>`, local `proofs/out-tag<TAG>/`.
- All prover runs go through `proofs/on-remote.sh` (host: `ZTL_REMOTE` in the local file `.env`) and `proofs/remote.sh` (host: `ZTL_REMOTE_BIG`); none on the workstation.

## Supply chain

Grey authorised opam for this strand on 2026-11-12 (Z-m-36); opam 2.6.1 is the official release binary in `~/.local/bin` (Ubuntu's 2.1.5 lacks security fixes). System libraries for opam builds come from apt through Grey (`graphviz`, `libgmp-dev` so far). Binary releases (VeriFast, ESBMC, Isabelle, TLA+) go under `../from-source/` or `../dl/` with a recorded SHA-256; ask Grey per tool.
