# Checks and proofs attempted

State: 2026-11-13, after two rounds of independent review of the receive path and the cryptography; the protocol layer (last section of attempts) had one review round by two models, read only, with no run of any tool, before it got its contracts. This report lists every check and proof that was tried on the C leaf, in plain words: what was asked, which tool answered, the result, and what the result does not show. No prover runs on the workstation. Run them on another host with `proofs/on-remote.sh start` then `proofs/on-remote.sh wait` (about half an hour), and `proofs/on-remote.sh start mutate` for the deliberate errors; exit status 0 of `wait` means every tool ran and reported the expected result. The large CBMC harnesses run one per unit with `proofs/remote.sh`. The chapter [List of proofs](#list-of-proofs) is the short form: every statement that a tool proves, with its number. Every change that made a contract or a check stronger is listed, with the wrong program it would have accepted before, in the project workspace (`dev-docs/improvements-applied.md`).

## What is under test

Nine source files. Six are the receive path up to an authenticated and decrypted packet: the classifier `ztl_classify()` (`src/wire.c`), the reassembly `ztl_reasm_input()` (`src/reasm.c`), the receive gate `ztl_rx()` (`src/rx.c`), and behind the gate the cryptography: Salsa20/12 (`src/salsa.c`), Poly1305 (`src/poly.c`) and their composition `ztl_auth_open()` / `ztl_auth_seal()` (`src/auth.c`). Together 3,076 bytes of code on the Cortex-M7 at `-Os`, 4,440 bytes of RAM (`struct ztl_node`), at most 456 bytes of stack on the receive path, no call into a C library. Three more are the protocol layer on top of that gate: the LZ4 decoder (`src/lz4.c`), the dictionary reader (`src/dict.c`) and the messages and timers (`src/leaf.c`); 4,612 bytes of code more, 7,136 bytes of RAM for the whole leaf (`struct ztl_leaf`). The sections below take them one at a time.

The classifier (196 bytes of code, 32 bytes of stack) receives the payload of one UDP datagram from the network, a pointer and a length, and decides one of three things:

- **Head**: the datagram is a candidate ZeroTier packet, or the first part of one. Rule: length 28 to 2048 bytes; byte 13 is not `0xff`; in the flags (byte 18) the cipher suite (bits 3 to 5) is 1, or it is 0 and bit 7 is clear. (Suite 0 with bit 7 is "extended armor", which needs AES. Suite 1 with bit 7 is normal: peers up to version 1.14 set that bit on every encrypted packet.)
- **Fragment**: the datagram is the second part of a packet that was cut in two. Rule: length 17 to 2048 bytes; byte 13 is `0xff`; byte 14 is `0x21` ("part 1 of 2").
- **Drop**: everything else.

For a head or a fragment it fills a small record (`struct ztl_view`) with the packet number and with pointers to the addresses and the payload inside the caller's buffer. For a drop it must not touch that record. "Candidate" is meant literally: nothing in the datagram is trusted or authenticated at this point.

## Three kinds of tool

```yaml
- tool: "CBMC (bounded model checker)"
  how_it_works: >-
    It turns the program and "any input up to this size" into one large logic formula and asks a
    solver for an input that breaks a check.
  strength: "Exact within the bound; handles bit operations with ease; gives a counterexample."
  weakness: "Says nothing beyond the bound."
- tool: "Frama-C Eva (abstract interpretation)"
  how_it_works: "It runs the program on sets of values instead of single values."
  strength: "Never misses a run-time error on the paths it analyses; no annotations needed."
  weakness: "Can raise false alarms; cannot decide properties that depend on unknown input bytes."
- tool: "Frama-C WP (deductive proof)"
  how_it_works: >-
    It turns the code and a written contract into logic formulas ("goals") and gives each to
    automatic provers.
  strength: "No bound and no approximation: holds for every input."
  weakness: "Needs a written contract; provers are weak on bit operations."
```

A "contract" states what must be true before the call (the buffer is readable for `len` bytes, the record is writable, the two do not overlap) and what is true after it (the three rules above and the exact value of each field). It is in `include/ztl/wire.h`.

## List of proofs

Every statement below is proved by a tool for every input that its contract allows, at the full packet size of 2,048 bytes unless a size is named. "WP" is Frama-C WP with the provers Alt-Ergo, Z3 and CVC5, in a 64-bit and a 32-bit data model, with the checks for run-time errors, unsigned wrap and lossy conversion switched on: 3,971 goals in the 64-bit model and 3,976 in the 32-bit model, all proved. Each part names the chapter of this report with the details and the limits: [classifier](#attempts-on-the-classifier), [reassembly](#attempts-on-reassembly), [receive gate](#attempts-on-the-receive-gate), [cryptography](#attempts-on-the-cryptography), [protocol layer](#attempts-on-the-protocol-layer). What is NOT proved is in the chapter [What all of this does not show](#what-all-of-this-does-not-show).

```yaml
- part: "Every function in src/ (nine source files, the whole leaf)"
  chapter: "all chapters of attempts below"
  proved:
    - id: L-1
      statement: >-
        No run-time error: no division by zero, no shift out of range, no signed overflow, no
        invalid pointer use
      tool: "WP"
    - id: L-2
      statement: "No read outside the memory that the contract names"
      tool: "WP"
    - id: L-3
      statement: >-
        No write outside the memory that the contract names; each contract lists what the function
        may change, and nothing else changes
      tool: "WP"
    - id: L-4
      statement: >-
        Every loop ends (each of the 36 loops has a proved bound) and no function calls itself:
        every call returns
      tool: "WP (loop variants); no recursion in the code"
    - id: L-5
      statement: "No unsigned sum or product wraps; no conversion to a narrower type loses bits"
      tool: "WP"
    - id: L-6
      statement: >-
        What a function returns meets its written contract, so its caller is proved from the
        contract alone
      tool: "WP"
- part: "Datagram classifier (src/wire.c)"
  chapter: "#attempts-on-the-classifier"
  proved:
    - id: L-7
      statement: >-
        The answer (head, fragment, drop) follows the exact written rule in both directions; the
        three cases cover every input and never overlap; every field of the result has its exact
        value; on drop nothing is written
      tool: >-
        WP 165 goals; CBMC for every buffer of 0 to 2,049 bytes, 506 checks (507 in the 32-bit
        model)
    - id: L-8
      statement: >-
        The rule equals a model of the reference receive path, with two listed differences (packets
        that need AES)
      tool: "CBMC"
    - id: L-9
      statement: "Each of the 11 kinds of outcome can happen in the harness"
      tool: "CBMC reachability"
- part: "Reassembly (src/reasm.c)"
  chapter: "#attempts-on-reassembly"
  proved:
    - id: L-10
      statement: >-
        Head then fragment, and fragment then head, both give the head bytes followed by the
        fragment bytes; a total above 2,048 bytes gives nothing
      tool: "WP 293 + 44 goals; CBMC at 64-byte packets"
    - id: L-11
      statement: >-
        Slot rule: a part older than 5 s does not count (32-bit clock that wraps); the first waiting
        slot of this packet is used; a waiting packet is given up only when every slot holds one,
        and then the oldest
      tool: "WP; CBMC at 64-byte packets"
    - id: L-12
      statement: >-
        The reassembly memory is valid after every call; a returned packet is the datagram itself or
        one freed slot
      tool: "WP; CBMC at 64-byte packets (induction over call sequences)"
- part: "Receive gate (src/rx.c)"
  chapter: "#attempts-on-the-receive-gate"
  proved:
    - id: L-13
      statement: >-
        Authentication before effects: a packet is delivered only after exactly one call of the
        authentication primitive that answered yes, with the key of a pinned peer whose address is
        the packet's source, for a packet addressed to this node; a yes is never thrown away
      tool: "WP 189 goals; CBMC at 40-byte packets"
    - id: L-14
      statement: >-
        An unencrypted packet reaches the primitive, and is delivered, only if its verb is HELLO
      tool: "WP; CBMC"
    - id: L-15
      statement: >-
        Without delivery the output is untouched and at most one refusal counter grows by one; the
        own address and the peer table are never written
      tool: "WP; CBMC"
    - id: L-16
      statement: >-
        The delivered body is the rest of exactly the packet that was authenticated, and lies in the
        datagram or in the node's reassembly memory
      tool: "WP"
- part: "Packet authentication and encryption (src/auth.c, src/salsa.c, src/poly.c)"
  chapter: "#attempts-on-the-cryptography"
  proved:
    - id: L-17
      statement: >-
        ztl_auth_open() writes only the bytes from the verb byte onward; after the answer no, or
        without decryption, the packet is unchanged
      tool: "WP 248 goals"
    - id: L-18
      statement: >-
        Poly1305: the five limbs stay inside their limits for a message of any length up to the packet size (2,048 bytes), so no
        product, sum or carry leaves its type
      tool: "WP 572 goals; CBMC induction step, 1,720 checks"
    - id: L-19
      statement: >-
        Poly1305, each step as a statement about numbers: bytes to limbs; add a block; multiply
        (exactly h times r minus a named multiple of 2^130 - 5); final reduction to the tag bytes
      tool: "WP; the identity also checked by computer algebra"
    - id: L-20
      statement: >-
        The comparison of the MAC answers 1 exactly when all bytes are equal; the wipe functions
        write zeros
      tool: "WP"
- part: "Protocol layer (src/lz4.c, src/dict.c, src/leaf.c)"
  chapter: "#attempts-on-the-protocol-layer"
  proved:
    - id: L-21
      statement: >-
        LZ4 decoder: for every block and every output size up to 2,048 bytes, no access outside the block or the
        output, and no match that copies from before the start of the output
      tool: "WP 133 goals"
    - id: L-22
      statement: >-
        Dictionary reader: for every dictionary up to 2,048 bytes and every key up to 8 bytes, no access outside the dictionary, the key
        or the value buffer
      tool: "WP 267 goals"
    - id: L-23
      statement: >-
        Authentication before effects for the whole leaf: ztl_input() gives a reply packet or a
        frame only after the receive gate made exactly one call of the authentication primitive and
        it answered yes
      tool: "WP (part of the 1,779 goals of src/leaf.c)"
    - id: L-24
      statement: >-
        After the start (ztl_init(), ztl_pin()) no call writes the node's own address, the table of
        pinned peers and their keys, the public key, the network ID or the controller index: they
        are in no list of what ztl_input(), ztl_poll() or ztl_frame_to() may change
      tool: "WP"
    - id: L-25
      statement: >-
        One packet ID (the encryption nonce) for each packet: every call that builds a packet moves
        the counter by exactly one, and a call that builds none leaves it
      tool: "WP"
    - id: L-26
      statement: >-
        What leaves the leaf is bounded: a delivered frame has 1 to 1,500 bytes and is readable for
        its whole length; a reply has 28 to 2,048 bytes; a periodic packet has 28 to 1,432 bytes
      tool: "WP"
    - id: L-27
      statement: >-
        A frame from the host goes out only with a configuration, to a pinned peer that was heard,
        with 1 to MTU bytes
      tool: "WP"
    - id: L-28
      statement: >-
        The data invariant of the node (valid reassembly memory, certificate length within its
        buffer, controller index in range, MTU 1,280 to 1,500 while a configuration is in use) holds
        after start and after every call
      tool: "WP"
    - id: L-29
      statement: >-
        The second datagram of a long packet is a 16-byte header with the packet ID and the
        destination, then exactly the bytes that the first datagram did not carry; both fit 1,432
        bytes
      tool: "WP"
```

Each proof holds under these assumptions: the caller meets the stated preconditions (valid, separate buffers); the tools' model of C (no notion of reading memory that was never written; pointer alignment not checked); the compiler and the hardware are correct. The contracts are written by hand: 102 deliberate errors in the code (114 tool runs), each rejected by the tool named for it, are the guard against contracts that say too little (A-6, B-6, C-4, D-9, E-7).

## Attempts on the classifier

```yaml
- id: A-1
  asked: >-
    For every buffer of every length 0 to 2049 bytes, with any contents: does the function ever read
    outside the buffer, write outside the record, overflow an integer, shift by an illegal amount,
    or convert a value with loss? The buffer is allocated with exactly `len` bytes, so one byte too
    far is an error.
  tool: "CBMC 5.95.1"
  result: >-
    ✅ 490 automatic checks, 0 failed (pointer dereferences, pointer calculations, overflows, shifts,
    allocation). With the 16 assertions of A-2 the tool reports 506 in total.
  does_not_show: >-
    Lengths above 2049 (WP covers them). Callers that pass a bad pointer. Kinds of undefined
    behaviour that CBMC has no check for. This run uses the host's 64-bit data model; A-5b repeats
    it with 32 bits.
- id: A-2
  asked: >-
    For the same inputs: is the answer exactly what the reference would do, in both directions? The
    harness holds a model of the reference receive path, written line by line from `Switch.cpp`,
    `IncomingPacket.cpp` and `Packet.cpp` in the reference's own form. The leaf must accept exactly
    the datagrams that the reference would go on to authenticate without AES, and must drop the two
    listed differences (AES-GMAC-SIV packets, extended-armor packets). Also: packet number = first 8
    bytes, most significant first; each pointer at its exact offset; payload ends at the buffer end
    and is not empty; cipher and "more parts follow" flag decoded right; after a drop the record is
    unchanged.
  tool: "CBMC"
  result: "✅ 16 assertions, 0 failed."
  does_not_show: >-
    The model is still a reading of the reference source, not the reference itself; a run of both
    programs on the same inputs is the stronger check (V-21). Address checks (to this node, not from
    this node) are not in the classifier.
- id: A-3
  asked: >-
    Can each outcome really happen in the harness? (If "head" could never occur, A-2 would pass
    without meaning anything.) Eleven targets: drop at length 0 and 2049; head at 28 and 2048; head
    with suite 0; head with suite 1 and bit 7; fragment at 17 and 2048; drop of an empty fragment,
    of an extended-armor head and of an AES-GMAC-SIV head.
  tool: "CBMC `--cover`"
  result: "✅ 11 of 11 reached."
  does_not_show: "This is \"each target can happen\", not branch coverage."
- id: A-4
  asked: >-
    Can any run-time error occur, and does the call meet the contract's preconditions? Unknown
    contents, length 0 to 2049.
  tool: "Frama-C 33.0 Eva"
  result: >-
    ✅ 0 run-time alarms; 9 preconditions valid; all 62 statements of the 4 analysed functions reached.
  does_not_show: >-
    The three outcome rules: Eva cannot decide which rule applies to unknown bytes. Its log has 20 "postcondition ... behaviour may be inactive" warnings for them and 2 "postcondition got status unknown" for the packet number's value; these are not evaluated and the runner ignores exactly these two kinds of warning. Reads between `len` and the end of its fixed
    2049-byte array.
- id: A-5
  asked: >-
    Does the code meet the full contract for every length and every content, with no bound? This
    includes: exact rule for each outcome, exact value of every field (the packet number too, since
    it is computed as plain arithmetic), nothing written on a drop, the three rules cover every
    input and never overlap, no run-time error, and no unsigned sum or product that wraps (D-2
    explains this stricter setting).
  tool: "Frama-C 33.0 WP with Alt-Ergo 2.6.4, CVC5 1.1.2, Z3 4.8.12"
  result: "✅ 165 of 165 goals proved."
  does_not_show: >-
    Pointer alignment: WP skips this check, so the proof assumes that the caller passes a correctly
    aligned record. The proof is about the C source, not about the compiled machine code. It assumes
    the caller meets the preconditions.
- id: A-5b
  asked: >-
    Do A-1, A-2 and A-5 still hold when `size_t` and pointers are 32 bits wide, as on the target?
  tool: "CBMC `--arch arm` on sources preprocessed by the target compiler; WP `-machdep gcc_x86_32`"
  result: "✅ 507 checks, 0 failed (includes the target layout assertion); 165 of 165 goals."
  does_not_show: "WP's 32-bit model is x86, not ARM, so its struct layout can differ."
- id: A-6
  asked: >-
    Do the proofs fail when the code is wrong? Ten deliberate errors, one at a time: head one byte
    too short; packet number with its halves swapped; packet number with its bytes reversed; always
    "drop"; record written and then "drop"; payload pointer one byte too far; empty fragment
    accepted; extended-armor head accepted; suite 1 with bit 7 refused; suite 3 accepted.
  tool: "`proofs/run.sh mutate` (CBMC, cover, WP)"
  result: "✅ 10 of 10 rejected."
  does_not_show: >-
    Only ten errors. Errors in the contract or in the harness itself are not injected.
- id: A-7
  asked: >-
    Does the code compile for the target without warnings, and how much code and stack does it use?
  tool: >-
    GCC 14.3 for Cortex-M7, `-Wall -Wextra -Wpedantic -Werror -fstack-usage` (`proofs/run.sh
    target`)
  result: "✅ No warnings; 196 bytes of code, 32 bytes of stack, static."
  does_not_show: "Stack of the whole program (for the receive path: D-4 of `CHECKLIST.md`)."
```

Which tool caught which error (first five errors, measured once by hand before `mutate` existed): CBMC caught all five. WP caught four; it missed the byte-order error because the contract then left the packet number's value to CBMC (it states the value now: A-5). Eva caught none, because none is a run-time error in its fixed-size array; its job here is the absence of crashes.

## Attempts on reassembly

`ztl_reasm_input()` in `src/reasm.c` (500 bytes of code, at most 88 bytes of stack, 4,144 bytes of RAM for two waiting packets, no call into a C library) joins a packet that arrives as a head and one fragment. Rules: either order of arrival gives head bytes followed by the fragment payload; a total above 2048 bytes gives nothing; a second head or second fragment for a waiting packet is ignored; parts more than 5 s apart are not joined; with no free place the oldest waiting packet is replaced. The result is not yet authenticated.

The module is built from small functions, each with its own contract (`src/reasm_internal.h`): copy bytes; move bytes down inside one buffer; choose a slot; put a head into a slot; put a fragment into a slot. **Each function is proved against its contract alone, and a caller is proved with the contracts of what it calls, not with their code.** That is why these proofs hold at the full 2048-byte size and take seconds: the provers never follow a copy byte by byte, they use "after the call, byte j of the destination equals the old byte j of the source".

```yaml
- id: B-1
  asked: >-
    Does every function of the module meet its contract, for every input that the contract allows,
    at the full packet size, with no run-time error? The contracts say, for example: the copy
    changes only the destination and makes it equal to the source; the chosen slot waits for this
    packet number or is free; after "put head" the slot holds exactly the head bytes, and if a
    fragment was waiting, the fragment bytes now follow the head. Also: the validity rule for the
    reassembly memory holds after every call, and a returned packet is readable for its whole
    length. The slot choice states its whole rule: a part older than 5 s (on a 32-bit clock that
    wraps) does not count as waiting; the first waiting slot with this packet number is the result
    and no waiting packet is lost; without a match the result is free, and a waiting packet is given
    up only when every slot holds one, and then the oldest.
  tool: "Frama-C 33.0 WP (64-bit and 32-bit model)"
  result: "✅ 293 of 293 goals in each model."
  does_not_show: >-
    `ztl_reasm_input()` does not yet repeat the timeout rule in its own contract (its callers see
    "the result is the datagram or one freed slot"). Reads of memory that was never written: WP has
    no such notion (F-24). Alignment of the caller's pointers (WP skips that check).
- id: B-2
  asked: >-
    Head then fragment, and fragment then head: do both give exactly the head bytes followed by the
    fragment payload when the total fits, and nothing when it does not? Written as two five-line
    functions (`proofs/reasm_wp.c`) and proved from the contracts of "put head" and "put fragment"
    alone.
  tool: "Frama-C WP, full size"
  result: "✅ 44 of 44 goals in each model."
  does_not_show: >-
    Other packets arriving in between (they use other slots; B-1 shows that a slot function changes
    only its own slot).
- id: B-3
  asked: >-
    Independent cross-check with a different method: take ANY valid reassembly memory, give it any
    one classified datagram at any clock value. Any memory or arithmetic error? Memory valid again?
    Returned packet exactly the datagram or one freed slot? (Induction: covers input sequences of
    every length.)
  tool: "CBMC, packet size set to 64 bytes"
  result: "✅ 572 checks, 0 failed (current code, CBMC 6.6.0)."
  does_not_show: >-
    The full packet size: with 2048 bytes CBMC's SAT formula does not fit (F-15). CBMC shares no
    contract text with WP, so it would catch a wrong contract.
- id: B-4
  asked: >-
    Same cross-check for: both arrival orders byte for byte; a second head or second fragment
    ignored; parts further apart than the timeout never joined, for every value of the 32-bit clock
    including its wrap-around.
  tool: "CBMC 6.6.0, 64-byte packets"
  result: "✅ 640, 629 and 570 checks, 0 failed (current code)."
  does_not_show: >-
    As B-3. A device that makes no call for more than 2^31 ms (about 25 days); stated as a rule for
    the caller.
- id: B-5
  asked: >-
    Does the module compile for the target without warnings and without any call into a C library,
    within its RAM budget?
  tool: "Target build"
  result: "✅"
  does_not_show: "—"
- id: B-6
  asked: >-
    Do the proofs fail when the reassembly code is wrong? Eleven deliberate errors: total may exceed
    the limit by one; payload moved from the wrong place; last head byte not copied; fragment stored
    one byte too far; copy loop stops one byte early; slot kept after a join; validity check accepts
    an empty fragment; timeout never applied; a part of exactly the timeout age dropped; the newest
    packet replaced instead of the oldest; clock difference without the wrap.
  tool: "Mutation step (WP)"
  result: "✅ 11 of 11 rejected."
  does_not_show: "Only eleven errors."
```

## Attempts on the receive gate

`ztl_rx()` in `src/rx.c` (96 bytes of stack) is the only way a packet reaches the rest of the node. Order of steps: classify; the datagram must be addressed to this node and must not claim to come from it; reassemble; on the complete packet apply the address rule and the cipher suite rule again, find the source in the table of pinned peers, refuse an unencrypted packet unless it is HELLO, then call the authentication primitive `ztl_auth_open()` with that peer's key. Only a "yes" from the primitive delivers the packet. The gate is proved against the CONTRACT of the primitive, not against its code, so the gate proof does not depend on the cryptography; section "Attempts on the cryptography" shows that the code of the primitive meets that contract.

```yaml
- id: C-1
  asked: >-
    "Authentication before effects", as a contract on `ztl_rx()` and proved from the contracts of
    the classifier, the reassembly and the primitive. For every node state with valid reassembly
    memory and every datagram: the primitive is called at most once; a packet is delivered only
    after one call that answered yes; that call used the key of a pinned peer whose address equals
    the packet's source; the packet is addressed to this node; an unencrypted packet reaches the
    primitive, and is delivered, only if its verb is HELLO; a yes is never thrown away; the node's
    own address and the peer table are never written; without delivery the output record is
    untouched and at most one refusal counter grows, by one; with delivery only the "ok" counter
    grows; the delivered body is the rest of exactly the packet and length that the primitive was
    asked about, and it lies in the datagram or in the node's reassembly memory with its 28 header
    bytes readable before it; the mode given to the primitive (decrypt or not) is the one in the
    packet's flags; the reassembly memory stays valid; no run-time error.
  tool: "Frama-C WP (64-bit and 32-bit model), full packet size"
  result: "✅ 189 of 189 goals in each model."
  does_not_show: >-
    WHEN the primitive answers yes: its contract says what it may change ("a no changes nothing; a
    yes may rewrite the encrypted part"), not that a yes means a right MAC. That link is D-1 (test
    vectors), not a proof. The proof records the call in proof-only variables (ghost state: call
    count, answer, key, packet, length); they do not exist in the program, and the ghost lines are
    part of the text that a reader must trust. What the caller does with the delivered packet.
- id: C-2
  asked: >-
    Independent cross-check with CBMC and a stand-in primitive that may answer yes or no for any
    input: the same properties, stated a second time in the harness (`proofs/rx_cbmc.c`).
  tool: "CBMC, packet size reduced"
  result: >-
    ✅ At 40-byte packets, current code (after F-36): 891 checks, 0 failed, 1 h 25 min in all (CBMC 6.6.0). The code before F-36 gave the same result with CBMC 5.95.1 (1 h 52 min of solving). Reachability: 8 of 8 outcomes reached. ❗ At 64-byte packets no result: 50-minute limit on the prover host, then 6-hour limit on the large one, still solving. An early run gave one useful failure (F-17).
  does_not_show: >-
    Packets above 40 bytes: 40 bytes hold a header and 12 payload bytes, so a head and a fragment
    that join are both near their smallest size. The full size rests on WP (C-1) and the deliberate
    errors (C-4).
- id: C-3
  asked: "Does the gate compile for the target without warnings?"
  tool: "Target build"
  result: "✅ 354 bytes of code, 96 bytes of stack."
  does_not_show: "—"
- id: C-4
  asked: >-
    Do the proofs fail when the gate is wrong? Seven deliberate errors: unencrypted packet of any
    verb goes to the primitive; delivery although the primitive said no; key of another peer;
    address rule not applied to the complete packet; a peer that is not pinned accepted; two
    counters grow for one refusal; address compare ignores the last byte.
  tool: "Mutation step (WP)"
  result: "✅ 7 of 7 rejected (all modules together: see E-7)."
  does_not_show: "Only seven errors."
```

## Attempts on the cryptography

`ztl_auth_open()` and `ztl_auth_seal()` in `src/auth.c` do what the reference does for cipher suites 0 and 1 (`Packet::dearmor()`, `Packet::armor()`): mix header fields into the peer key (packet number, both addresses, flags without the hop count, packet length); run Salsa20/12 with that key and the packet number; take the first 32 bytes of key stream block 0 as a one-time Poly1305 key; for suite 1, XOR the payload with the key stream from block 1; the MAC is the first 8 bytes of the Poly1305 tag of the payload as it travels (after encryption). Code: 2,026 bytes (Salsa20/12 592, Poly1305 1,080, composition 354); stack below the gate 360 bytes; the reference keeps a key stream buffer of about 2.9 KB on the stack for the same work.

The code is written in an unusual style, for the provers. There is no intended wrap-around: a sum modulo 2^32 is written `((uint64_t)a + b) % 4294967296`, a rotation as "low bits times 2^c plus high bits", bytes to a word as `p[0] + 256 * p[1] + ...`, and Poly1305 splits numbers with `/` and `%` by powers of two where one would expect shifts and masks. The target compiler emits the same instructions as for the usual style (checked: one `ror` per rotation, `umull` for the 25 products). The provers get plain arithmetic.

```yaml
- id: D-1
  asked: >-
    Does the code give the same bytes as the reference? Vectors are made by the reference itself
    (`tests/oracle/gen_vectors.cpp` calls `Packet::armor()`, `Poly1305::compute()`,
    `Salsa20::crypt12()`): 125 Poly1305 tags (every length 0 to 80, long messages up to 2,048 bytes,
    hand-made cases where the sum is at or just above 2^130 − 5 before the last reduction), 28
    Salsa20/12 key stream vectors (blocks 0 to 2, and single blocks up to number 1025), 292 whole
    packets of 28 to 2,048 bytes in both suites. For each packet: seal gives the reference's bytes;
    open accepts them and gives the plain payload; open refuses, and leaves the packet unchanged,
    after every one-bit change in the first 64 bytes and in every 7th byte after that (the hop count
    excepted: relays change it, and open must still accept), with a length shorter by one, and with
    a key that differs in one bit.
  tool: "Host test with address and undefined-behaviour sanitizers (`proofs/run.sh vectors`)"
  result: "✅ 0 failed (the step, with the vectors of E-2 and E-4: 369,459 checks)."
  does_not_show: >-
    A test, not a proof: only these inputs. The reference was built for a 64-bit host. Peers other
    than version 1.16.2.
- id: D-2
  asked: >-
    For every input that the contracts allow, at the full packet size: no read or write outside the
    buffers, no run-time error, every loop ends, and no unsigned sum, product or conversion loses
    bits (C allows that; here it is forbidden, so each `+` and `*` needs a proof that the result
    fits). The function `ztl_auth_open()` meets the contract that the gate proof used: it writes
    only the bytes from the verb byte onward, and after an answer 0 (or without decryption) those
    bytes are as before.
  tool: >-
    Frama-C WP, both data models, `-warn-unsigned-overflow -warn-unsigned-downcast` on all units
  result: >-
    ✅ 281 + 572 + 248 goals for the three files (32-bit model: 280 + 572 + 248; all units together:
    see the list of proofs).
  does_not_show: >-
    When open answers 1 (see C-1). Timing. That each exit path wipes its secrets: WP proves that the
    wipe functions write zeros, not that they are called.
- id: D-3
  asked: >-
    Poly1305, the limbs: can any of the 25 products, any sum of five of them, or any carry leave its
    type, for a message of any length? The proof is an invariant: before each block the five limbs
    are below 2^26 (limb 1 below 2^26 + 4096), and one block step keeps that.
  tool: >-
    WP (part of D-2); CBMC as an independent induction step from ANY limb values inside the limits
    (`-DH_POLY_STEP`)
  result: "✅ WP proved; CBMC 0 of 1,720 checks failed (CBMC 5.95.1; step `cbmcpoly` of the runner)."
  does_not_show: "—"
- id: D-4
  asked: >-
    Poly1305, the arithmetic of each step, as statements about numbers: (a) five limbs made from 16
    bytes stand for the same number as the bytes; (b) adding a block adds the numbers; (c) the
    multiplication gives exactly `h · r − (2^130 − 5) · k`, and the contract names k: the part of
    the product at 2^130 and above plus the last carry; (d) the last step gives tag bytes that stand
    for `((h mod 2^130 − 5) mod 2^128 + pad) mod 2^128`; a lemma, proved for all numbers, says that
    this is `(h mod 2^130 − 5 + pad) mod 2^128`, the form in the definition.
  tool: "WP (part of the 572 goals of `src/poly.c`)"
  result: "✅ proved, every length and content."
  does_not_show: >-
    The whole function. No contract says that the loop feeds every block exactly once, that r is
    clamped as the definition says, or that the last short block is padded right; the step
    statements are not yet joined into "the tag of this message". Errors there are caught by D-1
    only (see D-9).
- id: D-5
  asked: >-
    The same arithmetic, asked of a computer algebra system: is the identity behind (c) true as
    polynomials, and what are the true worst cases?
  tool: "Wolfram Engine 15.0 (`proofs/poly_identity.wl`), not a proof checker"
  result: >-
    ✅ The difference expands to 0. Largest sum 2^58.4 (of 64 bits); largest last carry 30.4 bits;
    limb 1 exceeds 26 bits by at most 101 (the invariant allows 4,096).
  does_not_show: >-
    It checks the formulas as I typed them into its language, not the C code. Its value is
    independence: a third method agrees with WP and CBMC.
- id: D-6
  asked: >-
    Independent cross-check of Salsa20/12: is `ztl_salsa2012_block()` equal, bit for bit, to a model
    written in the form of D. J. Bernstein's reference code (the form the reference core uses:
    sixteen named words, shifts, wrap-around), for every key, IV and block number?
  tool: "CBMC (`-DH_SALSA`)"
  result: >-
    ❗ No result: stopped by the 4-hour limit on the large prover host, still solving. Two forms of the same 12 rounds
    of add, rotate, XOR are hard for a SAT solver to recognise as equal. 🌱 Next attempt: compare one
    double round, not the whole function (queued, see "does not show").
  does_not_show: "Everything."
- id: D-7
  asked: >-
    The same for Poly1305 against a model in the form of poly1305-donna, 32-bit version, for every
    key and every message of 0 to 33 bytes.
  tool: "CBMC (`-DH_POLY`)"
  result: >-
    ❗ No result: stopped by the 4-hour limit on the large prover host, still solving. 🌱 Next attempt: compare one
    block step from any limbs inside the limits (queued).
  does_not_show: "Everything."
- id: D-8
  asked: >-
    Seal then open with the same key gives "yes" and the original payload, for every key and every
    packet of 28 to 96 bytes in both suites.
  tool: "CBMC (`-DH_ROUNDTRIP`, packet size 96)"
  result: "❗ No result: stopped by the 4-hour limit on the large prover host at 38 GB (limit 40 GB), still solving."
  does_not_show: >-
    Not a statement about forgery: that a changed packet is refused cannot be proved this way (a MAC
    can be met by chance, with probability 2^-64 per try).
- id: D-9
  asked: >-
    Do the checks fail when the cryptography is wrong? Deliberate errors, each tried with the tool
    named: see the table below.
  tool: "Mutation step"
  result: "✅ 22 errors, 28 tool runs, every one rejected by the tool named."
  does_not_show: "Errors that no tool here can see: listed under the table."
- id: D-10
  asked: >-
    Does it compile for the target without warnings and without a C library call, and what does the
    compiled code look like where secrets are handled?
  tool: "Target build; reading the disassembly"
  result: >-
    ✅ No warnings, no undefined symbol outside the leaf. The MAC compare has no early exit
    (subtract, accumulate, one `clz` at the end). The last Poly1305 selection is `mul`/`mla` with 0
    or 1, no branch. The wipe loops are present as stores.
  does_not_show: >-
    Reading is not proof; a new compiler version needs a new reading. Scalar copies of key material
    in registers and stack slots are not wiped.
```

Which tool rejected which deliberate error in the cryptography. "rejected" means that the tool ran and reported the error. "not tried" means that no contract of that tool speaks about the place of the error, so it cannot see it: these rows show where the proofs end and the tests carry the claim alone.

| Deliberate error | WP | Test vectors |
|---|---|---|
| Salsa20/12: five double rounds instead of six | not tried | rejected |
| Salsa20/12: one rotation by 9 instead of 7 | not tried | rejected |
| Salsa20/12: block number not used | not tried | rejected |
| Salsa20/12: only the low byte of the block number used | not tried | rejected |
| Payload key stream starts at block 0, the block of the MAC key | not tried | rejected |
| XOR runs one byte past the buffer | rejected | — |
| Poly1305: one folded product without the factor 5 | rejected | rejected |
| Poly1305: last carry comes back without the factor 5 | rejected | rejected |
| Poly1305: no final reduction when h ≥ 2^130 − 5 | rejected | rejected (by the hand-made vectors only) |
| Poly1305: limb 2 taken from the wrong bits | rejected | — |
| Poly1305: a sum that can leave 32 bits | rejected | — |
| Poly1305: clamp of r forgotten on one word | not tried | rejected |
| Poly1305: one full block skipped far into a long message | not tried | rejected (by the 2,032- to 2,048-byte vectors only) |
| Poly1305: the 1 after a full block is missing | not tried | rejected |
| Poly1305: the 1 after the last short block is missing | not tried | rejected |
| Open: the answer is always yes | not tried | rejected |
| Open: only 7 of the 8 MAC bytes compared | not tried | rejected |
| Compare ignores the last byte | rejected | rejected |
| Open: decryption although the MAC is wrong | rejected | rejected |
| Key mixing: hop count mixed into the key | not tried | rejected |
| Key mixing: packet length not mixed in | not tried | rejected |
| Seal: suite bits of the caller left in the flags | rejected | rejected |

Errors that pass every check here, found by thinking and by review, not by a tool: a compare that stops at the first different byte (same answers, leaks how many bytes were right); a removed call of a wipe function; a wipe that the compiler deletes on another compiler (now a build error unless the compiler is known).

## Attempts on the protocol layer

`src/leaf.c` (4,106 bytes of code) is everything between the gate and the host: it answers HELLO and ECHO, sends its own HELLO, asks the controller for the network configuration and reads the answer, pushes its certificate of membership, announces its multicast groups, and turns frames into packets and back. It reads only packets that passed the gate, so every input here comes from a pinned peer with a right MAC; the checks below treat such a peer as possibly faulty or hostile all the same. `src/lz4.c` (196 bytes) decodes compressed packets; `src/dict.c` (310 bytes) reads the configuration format. The layer does no input or output: it fills one packet buffer that the caller sends.

The layer was written and tested first (E-5, E-6), then given contracts (E-9). For the proofs the code changed in three ways, with the same behaviour: state flags became separate 0-or-1 bytes in place of bits of one byte; dictionary keys became byte arrays (no pointer casts); the receive gate's contract now says where the delivered packet lies.

```yaml
- id: E-1
  asked: >-
    LZ4 decoder, for every block of 0 to 2,048 bytes and every output size up to 2,048: any read
    outside the block, any write outside the output, any match that copies from before the start of
    the output, any sum that wraps, any loop that does not end?
  tool: "Frama-C WP, both data models, strict flags"
  result: "✅ 133 of 133 goals."
  does_not_show: >-
    That the output is what LZ4 means by the block: the contract speaks of memory and limits only
    (E-2 is the evidence for the bytes). Which blocks are accepted: this decoder refuses a block
    that ends after a match, as the reference's decoder does, but no check compares the two on
    malformed blocks.
- id: E-2
  asked: >-
    Does the decoder give the reference's bytes? 58 payloads compressed by the reference's own
    `Packet::compress()`: runs of one byte (matches at offset 1, lengths that need extension bytes),
    repeated patterns of period 2 to 300 (matches that overlap their own output), configuration-like
    text with binary values, random bytes with repeated stretches. Each is decoded into a heap block
    of exactly the plain size; then again with a block one byte smaller, and with the input one byte
    shorter.
  tool: "Host test with sanitizers (step `vectors`)"
  result: "✅ All 58 equal; every shortened case refused."
  does_not_show: >-
    Only these inputs. Blocks that a compressor never makes (E-5 feeds random and damaged blocks,
    but only checks memory and limits).
- id: E-3
  asked: >-
    Dictionary reader: any read outside the dictionary or the key, any write outside the value
    buffer, any loop that does not end, for every dictionary up to 2,048 bytes?
  tool: "Frama-C WP, both data models"
  result: "✅ 267 of 267 goals (first form: 243 of 245, see F-31)."
  does_not_show: "That the value returned is the right one (E-4)."
- id: E-4
  asked: >-
    Does the reader answer as the reference's reader? 144 lookups in dictionaries made by the
    reference's writer `Dictionary::add()` (keys that are the start of other keys, values with every
    byte that needs an escape, absent keys), and 54 lookups in hand-made dictionaries that the
    writer never makes (carriage return as line end, a line without "=", a key twice, empty values,
    a zero byte in the middle, a backslash at the end), answered by the reference's reader
    `Dictionary::get()`. Also: value buffer of the exact size; one byte too small must be refused
    (the reference cuts the value; the leaf refuses, which is stricter). 24 Ethernet addresses from
    node address and network ID against `MAC::fromAddress()`.
  tool: "Host test with sanitizers (step `vectors`)"
  result: "✅ 198 + 24, all equal."
  does_not_show: "Only these inputs."
- id: E-5
  asked: >-
    The whole layer with known answers and under hostile input. Part 1, 270 fixed checks: the first
    packets are one HELLO for each peer and nothing else; HELLO is answered with OK(HELLO) that
    carries the packet ID, the time stamp and protocol version 11; nothing encrypted goes to a peer
    that was never heard; an OK counts once and only for the waiting request; a configuration is
    refused when it comes from a peer that is not the controller, answers another request, is for
    another node or network, is a public network, has an MTU out of range, a cut certificate or a
    wrong total length, or (pushed) is not newer; frames are delivered only with a configuration,
    with 1 to MTU bytes, from the peer's own Ethernet address, to this node or a group; a
    certificate in front of a frame is skipped by its exact length; the peer's "need certificate"
    brings the certificate again; frames from the host go to the peer that owns the address,
    broadcasts to every reachable peer; each packet has the next packet ID; a silent peer gets HELLO
    only. Part 2, 300,000 random rounds: authentic packets of every verb with random or damaged
    bodies, compressed or not, whole or in two parts, single flipped bits, random datagrams, random
    LZ4 blocks, random frames from the host, with time jumps. Each datagram is in a heap block of
    its exact size. After each call: a reply opens with the peer's key; a delivered frame lies
    inside the datagram or the leaf; nothing happens for a datagram without a right MAC; a packet
    sent in two datagrams joins to one that the peer's key opens.
  tool: "Host test with address and undefined-behaviour sanitizers (step `proto`)"
  result: >-
    ✅ 1,681,597 checks, 0 failed, no sanitizer report; 183,812 packets passed the gate, 53,841
    frames delivered, 5,275 configurations taken, 377 packets sent in two parts.
  does_not_show: >-
    A test: only these inputs, and the checks I thought of. The expected answers are my reading of
    the protocol, the same reading as the code (E-6 is the independent check of that reading).
- id: E-6
  asked: >-
    Does it talk to the reference? The leaf on one loopback UDP socket, the reference node on
    another: the reference core (protocol version 13, with AES) with a test controller, from the
    reference solution's host tests. Throw-away identities; the leaf gets its pairwise key from the
    provisioning tool. Both sides send a fixed IPv4 frame and an ARP request every 200 ms once they
    are configured, and count what arrives. Cases: frames of 69, 1,280 and 1,500 bytes (1,500 needs
    two datagrams in both directions); a controller that refuses the leaf; both sides change one bit
    of every datagram they send.
  tool: "`tests/host/interop.py` (a test, on the workstation, not in the proof runner)"
  result: >-
    ✅ All five cases pass on the code of this report. Normal cases (figures of one run): both sides
    configured, 26 frames and 29 ARP requests at the leaf, 27 and 27 at the reference in 6 s, none
    wrong; the leaf decoded 2 compressed packets (the configuration and the peer's credentials).
    Refused member: no configuration, no frame. Changed datagrams: no frame on either side.
  does_not_show: >-
    A stock `zerotier-one` program or a stock controller as the other side: the reference node is
    the same core built from source, with the patches of the reference solution, and a controller
    written for the test. Other peer versions. More than one peer. Loss, reordering, delay. In the
    "changed datagrams" case the reference never answers, so it tests the reference's refusal of the
    leaf's packets, not the leaf's refusal (D-1 and E-5 test that).
- id: E-7
  asked: >-
    Do the checks fail when the new code is wrong? 52 deliberate errors: 8 in the LZ4 decoder (4 for
    WP, 4 for the vectors), 5 in the dictionary reader, 39 in the protocol layer. Of these 39, 35
    are for the protocol test (among them: packet ID not advanced, HELLO or OK that says protocol
    version 13, frame delivered without a configuration, from a foreign source, for a third station,
    longer than the MTU or of another network, configuration from any peer, for another request,
    taken twice, older, for another node or network, certificate length not checked, "fragmented"
    flag not set, encrypted packets to a peer that was never heard) and 10 are for WP (E-9); 6
    errors are in both groups.
  tool: "Mutation step"
  result: >-
    ✅ 52 of 52 rejected, in 58 tool runs. A tool run is one line of the list in `proofs/run.sh`: one error with the tool named for it. (The ten classifier errors of A-6 name three tools in one line; such a line counts as rejected when at least one of the three reports the error.) The whole list of all chapters,
    in one run on the code of this report: 102 errors, 114 tool runs, every one rejected. One
    survived at first and two more were reported wrongly (F-29, F-30); two did not apply for a time
    (F-35).
  does_not_show: >-
    Errors that no check here sees. Known ones: a block that ends after a match accepted (no vector
    has one); timer values (a HELLO period of 61 s passes); anything in the Zephyr adapter.
- id: E-8
  asked: >-
    Does it compile for the target without warnings and without a C library call? Size and stack?
  tool: "Target build (step `target`); a firmware build with the Zephyr adapter"
  result: >-
    ✅ `leaf.c` 4,106, `dict.c` 310, `lz4.c` 196 bytes; largest new frame 160 bytes (configuration),
    `ztl_input()` 80 bytes above the gate. In the firmware build: leaf 7,694 bytes of code in all,
    adapter 2,364 (and 761 for its shell command); RAM `struct ztl_leaf` 7,136 bytes, whole Zephyr module 15,832 bytes with a 3 KB thread stack.
  does_not_show: >-
    The adapter (`zephyr/`) has no test of its own; it runs on one board (see "What all of this does
    not show").
- id: E-9
  asked: >-
    Contracts for every function of `src/leaf.c` (31 functions), a data invariant for the node, and
    four statements about the whole leaf: (1) `ztl_input()` gives a reply or a frame only after the
    gate's one call of the authentication primitive answered yes; (2) `ztl_input()` never writes the
    own address, the pinned peers, their keys, the public key, the network ID or the controller
    index; (3) each built packet takes exactly one packet ID and a call that builds none takes none;
    (4) bounds: frame 1 to 1,500 bytes and readable, reply 28 to 2,048 bytes, periodic packet 28 to
    1,432 bytes. Also: a frame from the host goes out only with a configuration, to a pinned peer
    that was heard, with 1 to MTU bytes; the second datagram of a long packet is the right header
    and exactly the rest. And for every function: no run-time error, no access outside the named
    memory, no wrap, every loop ends.
  tool: "Frama-C WP, both data models, strict flags"
  result: >-
    ✅ 1,779 of 1,779 goals (32-bit model: 1,785 of 1,785). The first run with contracts proved 1,751
    of 1,759; the rest needed the packet ID statement on three answer functions, the reassembly
    start contract in the header, and one change of the code (F-34). Ten deliberate errors against
    these proofs rejected by WP (packet ID not advanced, two IDs for one answer, answer without a
    yes from the gate, ECHO longer than a packet, certificate length not checked, frame above the
    MTU, MTU out of range, fragment header without the destination, host frame above the buffer,
    address list read past its end).
  does_not_show: >-
    What the messages mean. No contract says that a HELLO has the right fields, that the timers fire
    when they should, that a refused configuration is refused: that is E-5, E-6 and E-7 (tests). The
    statement about frames is "after a yes from the gate", not "this frame was sent by that peer"
    (the link from yes to a right MAC is D-1, test vectors). Replay: a recorded packet passes the
    gate again.
- id: E-10
  asked: >-
    Can a contract here prove too much? A function whose preconditions contradict each other, or a
    call that can never return, makes every statement after it provable. For each function, each
    call and each statement, WP also tries to prove "false" at that place; a success is a
    contradiction, or code that no input reaches. All ten units.
  tool: "Frama-C WP with `-wp-smoke-tests` (step `smoke`, part of the default run)"
  result: >-
    ✅ 1,000 such tests, none succeeded. The first run found three, all at one branch of the receive
    gate that no input reaches (F-36).
  does_not_show: >-
    A test that does not succeed means that the provers found no contradiction within a short time
    limit, not that none exists. That the code under the contracts can run is shown by the tests
    that reach it (E-5: 183,812 packets through the gate). Contracts that are consistent and say too
    little: E-7.
```

## Related experiment on the reference core (not on this code)

```yaml
- id: R-1
  asked: >-
    Can a leaf without AES talk to a normal ZeroTier node? The reference C++ core, built to announce
    protocol version 11, never to select AES, and to abort if any AES code is reached, against the
    unchanged version-13 reference core.
  method: "Host interoperability test on loopback (a test, not a proof)"
  result: >-
    ✅ Normal traffic (1500- and 69-byte frames, 7 peers), denied membership and tampered packets all
    behave as expected.
  does_not_show: >-
    Anything about the C leaf (for that: E-6). A stock `zerotier-one` program or the lab controller
    as the peer. A peer with "encrypted HELLO" switched on: such a peer sends its HELLO with
    extended armor, which a leaf without AES cannot read. The setting is off by default
    (`service/OneService.cpp`, `encryptedHelloEnabled`, default false), so this is a rule for the
    deployer: do not switch it on at peers of the leaf (D-5a). That peers never send AES: a peer
    chooses its suite from the version it has learned, so the leaf must still reject AES packets,
    and it does (A-3).
```

## Attempts that failed or were changed

```yaml
- id: F-1
  happened: "Ubuntu's Frama-C package has no WP plug-in."
  consequence: "Frama-C 33.0 and Alt-Ergo come from opam (`proofs/opam-setup.sh`)."
- id: F-2
  happened: >-
    Eva started directly on the function (no harness) reported a certain out-of-bounds read. It was
    a false alarm: Eva invents its own small buffer and ignores the stated buffer size.
  consequence: "A harness (`proofs/wire_eva.c`) supplies the buffer."
- id: F-3
  happened: >-
    The first contract only limited the successful answers. A function that always answers "drop"
    would have passed all three tools (found by review 1).
  consequence: >-
    The contract and the CBMC harness now state the exact rule for each outcome, in both directions
    (A-2, A-5), and A-3 was added.
- id: F-4
  happened: >-
    With the exact contract, WP left 30 of 127 goals unproved (time-out). Cause: the code took byte
    14 apart with a shift and a mask, and the provers could not connect "upper half is 2 and lower
    half is 1" with the simplified form of the same statement.
  consequence: >-
    The code now compares byte 14 with `0x21` and tests flag bits directly: simpler code, same
    behaviour. CBMC confirms that this equals the wire-format rule (A-2). After the change: 126 of
    126.
- id: F-5
  happened: >-
    Eva cannot evaluate the three outcome rules on unknown input, also when the analysis is split by
    length and by the deciding bytes.
  consequence: "Eva is used for run-time errors and preconditions only (A-4)."
- id: F-6
  happened: >-
    The first runner script accepted a WP run with "0 of 0 goals" and replaced the tool's exit
    status (review 1). Later the Eva gate still passed if its summary was missing (review 2).
  consequence: >-
    `proofs/run.sh` now needs, for each tool: exit status 0, a non-zero number of checks, all
    passed, and the expected summary lines present.
- id: F-7
  happened: >-
    The rules accepted a fragment of exactly 16 bytes (header only, no payload). The reference
    receive path handles a fragment only when it is longer than 16 bytes (`Switch.cpp`, `len > 16`).
    All three tools had "proved" the wrong rule, because the rule itself was wrong (found by review
    2).
  consequence: "Fragments now need 17 bytes. A cover target and a mutant guard it."
- id: F-8
  happened: >-
    The rules accepted heads with the "extended armor" flag. In the reference that flag means a
    second encryption pass with AES and an ephemeral key, which this leaf does not have (found by
    review 2).
  consequence: "Such heads are now dropped. A cover target and a mutant guard it."
- id: F-9
  happened: >-
    Code size was reported as 188 bytes in one file and 174 in another, and the mutation results
    came from hand-run commands.
  consequence: "`proofs/run.sh target` and `proofs/run.sh mutate` make both repeatable."
- id: F-10
  happened: >-
    The fix for F-8 was too broad: it dropped every head with bit 7. But every peer up to version
    1.14 sets bit 7 on each Salsa20-encrypted packet (old "encrypted" flag, `setCipher()` in those
    versions), and the reference ignores the bit with suite 1. The leaf would have refused all
    traffic from such peers. Found while writing the reference model for A-2, by reading older
    upstream sources; the tests against the 1.16 reference could not show it.
  consequence: "Bit 7 is refused only with suite 0. A cover target and a mutant guard it."
- id: F-11
  happened: >-
    The first 32-bit CBMC run failed in the harness itself. Cause: with the host's C headers and a
    32-bit model, `uint64_t` became 32 bits wide, so the tool analysed a program that the target
    never runs.
  consequence: >-
    The 32-bit step preprocesses with the target compiler and its headers; the layout assertion then
    holds in CBMC as well.
- id: F-12
  happened: >-
    The first reassembly proof ran on the workstation at full packet size and used all its memory;
    the session had to be restarted.
  consequence: >-
    Heavy proofs run on another host with a memory limit per process (`proofs/remote.sh`); no prover runs on the workstation (the runner refuses).
- id: F-13
  happened: >-
    With the C library's `memcpy` and with harness datagrams of unknown size, CBMC needed more than
    16 GB even for 128-byte packets.
  consequence: >-
    The module copies with its own bounded loop (which also removes the library call from the target
    code), and the harness uses fixed-size arrays.
- id: F-14
  happened: >-
    Two "failures" were not errors in the code: the clock subtraction wraps on purpose, and the
    check for unsigned overflow flagged it (in the code and in the harness).
  consequence: >-
    The wrap is marked as intended at exactly those two lines; the check stays on everywhere else.
- id: F-15
  happened: >-
    The full-size reassembly proof with CBMC failed three times. The built-in SAT solver stopped
    with "out of memory" at 78 GB on a machine with 900 GB free: its own size limit, not the
    machine's. With two other SAT solvers the formula alone passed 370 GB each and was still
    growing; those runs were stopped.
  consequence: >-
    Reassembly was split into small functions with contracts and proved with WP at full size (B-1,
    B-2). CBMC stays as a cross-check at 64 bytes.
- id: F-16
  happened: >-
    A mutation step that was stopped half-way left one deliberate error in `src/reasm.c`, and that
    file was committed. The proofs on the next run would have rejected it; it was found before that,
    by a leftover backup file.
  consequence: >-
    The file was restored. The mutation step now changes a copy of the sources, never the sources.
- id: F-17
  happened: >-
    The first gate proof failed the check "the packet given to the primitive is addressed to this
    node". Cause: the gate trusted that a head waiting in the reassembly memory had passed the
    address check when it arrived. That is true in real runs, but the gate's own code did not
    guarantee it.
  consequence: >-
    The gate applies the address rule to the complete packet as well. It no longer depends on what
    an earlier call left in memory.
- id: F-18
  happened: >-
    The remote runner reported failure whenever a remote command printed nothing, so a correct start
    looked like an error and the "wait" step never ran.
  consequence: "Fixed; the exit status is now that of the remote command."
- id: F-19
  happened: >-
    The gate proof with WP stopped at 167 of 168 goals, then 170 of 172, with different goals
    failing from run to run: the provers lost track of what six separate writes to the output record
    leave unchanged.
  consequence: >-
    The writes moved into one small function with the contract "only the output record changes".
    Then 173 of 173. Same lesson as for reassembly: small functions with contracts.
- id: F-20
  happened: >-
    The first WP run with the stricter setting (no unsigned wrap) failed in two older places: the
    packet number was built with `v << 8` in a loop, and the clock difference wrapped on purpose
    under a `#pragma`.
  consequence: >-
    Both are plain arithmetic now. The packet number's value moved into the WP contract (A-5), and
    the clock difference got an exact contract, which made the slot rule provable (B-1). No
    `#pragma` is left in `src/`.
- id: F-21
  happened: >-
    A rotation written with a variable count, `(v % (1 << (32 - c))) << c`, left three goals
    unproved; so did the same with constant counts and a shift.
  consequence: >-
    Four macros with the constants written out, as arithmetic (`(v % 2^25) * 2^7 + v / 2^25`). The
    compiler still emits one `ror`.
- id: F-22
  happened: >-
    The target build failed although every proof passed: the compiler had turned the wipe loop, and
    a zero initializer, into calls of the C library's `memset`.
  consequence: >-
    The wipe loops carry a barrier that the compiler cannot see through; the initializer became a
    wipe call. The rule "no undefined symbol" in the runner is what found it.
- id: F-23
  happened: >-
    Poly1305 value proofs, three failures on the way. (1) With the limb value as an ACSL logic
    function, goals that compare two memory states timed out; as a macro they pass. (2) The block
    step as one function ("add, then multiply") needed a substitution inside a product; no prover
    did it; split into two functions, each contract is direct. (3) The multiplication stated as
    "congruent modulo 2^130 − 5" was unstable: the same goal passed in one run and timed out in the
    next, because the prover must find the multiplier.
  consequence: >-
    The contract now names the multiplier (D-4 c), with the last carry as a proof-only output.
    General lesson: where a statement needs a witness, write the witness down; where it is not
    obvious, let computer algebra find it and the prover check it.
- id: F-24
  happened: >-
    Found by review, invisible to WP: the slot scan read the time stamp of a free slot, which
    `ztl_reasm_init()` never writes. For WP an unwritten integer is just some integer.
  consequence: "The time is read only for slots in use."
- id: F-25
  happened: >-
    Found by both reviews: `ztl_auth_open()` took "decrypt or not" as a free argument, so the
    contract allowed opening an unencrypted HELLO as if it were encrypted. The gate never did that.
  consequence: >-
    The contract requires that the mode is the suite in the packet's flags, and the gate applies the
    suite rule to the complete packet so that it can prove this at the call.
- id: F-26
  happened: >-
    Found by review: the mutation step called a deliberate error "rejected" whenever the tool run
    failed, also when the changed file no longer compiled.
  consequence: >-
    "Rejected" now needs a tool that ran and reported the error; other failures are "BROKEN" and
    fail the step.
- id: F-27
  happened: >-
    Found by review: two deliberate errors passed all vectors. "Only the low byte of the block
    number" (packets need at most 33 blocks) and "skip block 126 of a message" (the longest test
    message had 126 full blocks).
  consequence: >-
    Vectors for block numbers up to 1025 and messages up to 2,048 bytes; both errors are in the
    mutation list.
- id: F-28
  happened: "CBMC stopped the seal-then-open harness with \"too many addressed objects\"."
  consequence: "More object bits (`--object-bits 12`)."
- id: F-29
  happened: >-
    Two deliberate errors in the protocol layer were caught by the address sanitizer, and the
    mutation step still called them "BROKEN": the sanitizer writes "ERROR" in capitals, and the
    runner's summary line kept only lines with "rror". Two more were "BROKEN" for a plain reason:
    the change made a parameter unused, which is a compile error here.
  consequence: >-
    The summary line takes the sanitizer's report; the two errors were rewritten so that every name
    stays in use.
- id: F-30
  happened: >-
    The deliberate error "a dictionary value does not end at a carriage return" survived all 144
    dictionary vectors. They were made by the reference's writer, which never writes that byte as a
    line end.
  consequence: >-
    54 hand-made dictionaries, answered by the reference's reader (E-4). A reader must be tested
    with input from outside its writer's range.
- id: F-31
  happened: >-
    The dictionary reader's first form left 2 of 245 goals unproved: the loop over lines could not
    be shown to end, because the helper "is this byte a line end" had no statement about its result,
    and a comparison went through a cast between pointer types. A second form left 2 of 269: a key
    byte was converted from `char`, which can be negative, and the "start of this line" in a loop
    invariant was written with a label that means the inner loop's own round.
  consequence: >-
    The helper's contract states its result; keys are bytes; the line start is a proof-only
    variable. 267 of 267.
- id: F-32
  happened: >-
    The target build failed once more on a call to `memset`: the compiler had replaced a zeroing
    loop in the new code (see F-22).
  consequence: >-
    The same barrier as in the wipe loops. The rule "no undefined symbol" found it again.
- id: F-33
  happened: >-
    Two of the first failures of the protocol test were errors in the test: it put a raw byte 13
    into a hand-made configuration (the reader, rightly, ended the value there), and it read the
    verb of a packet that was still encrypted.
  consequence: "Test corrected. The first one led to F-30."
- id: F-34
  happened: >-
    With contracts on the whole protocol layer, one goal of `ztl_input()` stayed open, in the 32-bit
    model only (time-out): "the reply length is 0, or 28 to 2,048" on the path of a verb whose
    handler makes no reply. The statement was true: such a handler cannot write the reply length.
    But the prover had to get that from the handler's list of what it may change, through its model
    of memory.
  consequence: >-
    The reply length stays in a local variable and goes to the caller once, at the one exit. Then
    1,779 of 1,779 goals (32-bit model: 1,785 of 1,785). Same lesson as F-19: do not make the prover
    reason about what a call leaves unchanged; write the code so that the question does not come up.
- id: F-35
  happened: >-
    Two deliberate errors in the protocol layer stopped applying when the lines that they change
    were rewritten after review round 3: their text patterns no longer matched. The mutation step
    reports that ("NOT APPLIED") and fails, but the partial runs in between selected other errors by
    name, so these two were in no run. Found by a dry application of every error to the sources.
  consequence: >-
    Both patterns corrected; the protocol test rejects each. "Every error rejected" is claimed only
    from a run of the whole list in one piece (E-7).
- id: F-36
  happened: >-
    The first run of the search for unreachable code (E-10) reported three places, all in the
    receive gate: after the call of the authentication primitive the gate tested once more that an
    unencrypted packet is HELLO, "so that the rule does not depend on that property of the
    primitive". WP proves that no input reaches the inside of that test: the primitive's contract
    says that a plain open changes nothing. The branch could never run, so no test could ever
    exercise it.
  consequence: >-
    The branch is removed; an assertion that WP proves says the same at that place. If the
    primitive's contract is ever weakened, the gate proof fails there. Gate: 189 goals in place of
    193.
```

## What all of this does not show

- The protocol layer talks to the reference node on a host and, in a first run on a Teensy 4.1, to a stock controller and three stock 1.16.2 peers (configuration taken, ping with full-size frames, Telnet and SSH sessions over the overlay; a few minutes, no error counter moved). One measurement there: 5,000 echo requests at each of two sizes (56 and 1,252 bytes), none lost. These runs are observations, not tests: no soak, no rate limit found, no hostile peer. `src/leaf.c` is proved for memory safety, for its bounds and for four statements about the whole leaf (E-9, L-23 to L-29); what its messages mean and when its timers fire is tested, not proved (E-5, E-6, E-7). The Zephyr adapter has no proof and no test of its own.
- The leaf trusts its provisioning: the pairwise keys come from a host tool that uses the reference's key agreement code, which is taken as correct here (tested through E-6, not proved).
- The leaf does not check the controller's signature on a configuration (it takes one only from the pinned controller, under the pairwise MAC) and does not evaluate the network's rules.
- **No protection against replay.** A recorded authentic packet, sent again by someone on the path, delivers its frame again, marks the peer as heard, and draws the same answer (an 18-byte "need certificate" draws a certificate and a subscription each time). The answers to requests are safe (they count once, for the waiting packet ID). No rate limit on answers.
- Deployment limits: network MTU 1280 to 1500 (the stock default is 2800: set it on the controller); the configuration must fit one chunk and 2,020 bytes after decompression; only broadcast and ARP reach the leaf as multicast.
- **No proof says that "yes" from `ztl_auth_open()` means a right MAC.** The proofs show memory safety, no wrap, what may change, and the arithmetic of each Poly1305 step. That the composition equals ZeroTier's is shown by test vectors from the reference (D-1) only: the CBMC comparisons of whole functions (D-6 to D-8) gave no result in 4 hours. Comparisons of single steps are queued behind the protocol work.
- Salsa20/12 has no statement about its output in WP at all; Poly1305 has none for the whole message (D-4).
- Constant time and the wiping of secrets are by construction and by reading the compiled code (D-10).
- **The rules are a reading of the reference source.** A proof shows that the code follows the written rules, not that the rules are right. F-7, F-8 and F-10 were errors of this kind, and no tool found them. A-2 now compares against a model of the reference receive path (V-13); the model is still written by hand, and older peer versions matter as well as the pinned reference.
- "Accepted" does not mean "authentic". A head or fragment is still untrusted data.
- The record holds pointers into the caller's buffer, and it does not keep the raw flags. Nothing yet proves that later code stops using the pointers before the buffer is reused, or that it reads the flags again correctly.
- The proofs use the tools' models of C (64-bit and 32-bit). The target's exact struct layout, the compiler and timing are outside them (V-17).
- New source files are not picked up by the runner on their own: it lists its units by name. A file that reads network input without a proof does not make the run fail (V-21). Today all nine files in `src/` are in the list.
- The contracts are written by hand. A contract that is too weak proves less than it seems to; the deliberate errors (A-6, B-6, C-4, D-9, E-7), the CBMC cross-checks (B-3, B-4, C-2) and the search for contradictory preconditions (E-10) are the guard against that.

## Independent reviews

Two other models, here called helper model A and helper model B, reviewed the proofs and the code of the primary model, read-only, in two rounds: the classifier (helper model B on the improved state), then the cryptography, the gate and the new slot contract. Their claims were checked against the files before any change.

**Review 1 (helper model A)** found F-3 and F-6 and that the first Eva summary did not support the claim "postconditions checked". Its main advice: prove behaviour across packets before adding more provers to one small function. Its proposals are V-1 to V-12 in `CHECKLIST.md`: authentication before effects; nonce life cycle; replay; reassembly; bounded cost and recovery under hostile input; timer and counter wrap; Zephyr buffer ownership; secret lifetime; constant time; cryptographic correctness; trace equivalence with the reference; whole-system RAM, stack and compiled-code bounds.

**Review 2 (helper model B)** found F-7, F-8, the second half of F-6 and F-9, the unclear check counts, the over-broad "0 alarms" wording for Eva, and the wrong statement that alignment is no risk for this function. It also showed that R-1 says nothing about peers with encrypted HELLO. Its main point: the correctness of the rules is now the weakest link. Its proposals are V-13 to V-23: classification equal to a model taken from the reference receive path; exact consumption of variable-length records; version and cipher negotiation as a state machine; reply matched to an outstanding request; global table invariants; atomic key and table access across threads and interrupts; target data layout and integer widths; safe start from arbitrary RAM contents; containment of single bit flips in control data; atomic persistent storage; progress and watchdog behaviour; plus two practices: a test corpus generated from the proof targets and run through both implementations, and a manifest so that every network-reading source file must have a proof.

Both reviews agree on the next code: reassembly and the authentication gate. Review 2 adds an order: first settle the open rule questions and write a thin memory and layout budget, then reassembly, then the gate with a narrow interface to the cryptography, then the real Salsa20/12 and Poly1305 behind that interface.

**Round 3, the protocol layer (both models, same question, independently, by reading only).** Both checked every message layout against the reference field by field and found no wrong offset, length or byte order, and no access outside a buffer. Both found, and the code now has: a new configuration did not send the new certificate to the peers, and the certificate period equalled the shortest window a network can set (now: after every configuration, and every 2 minutes); a change of the address prefix alone did not reach the Zephyr interface; a refusal by the controller was ignored (now: for the waiting request it ends the use of the network); an ARP reply to the broadcast address was sent with the group of an ARP request. helper model A also found: the answer to a request could bring back a configuration older than a pushed one (now: never older than the newest one taken since the start); a refused answer ended the wait and so delayed the next request; HELLO, OK(HELLO) and the configuration tail were accepted in forms that the reference refuses (now checked); the tests never compared the packet ID inside an OK with the packet it answers (now they do). helper model B found the controller source in the reference tree that the primary model had missed, which settles what a controller sends to a node without a rules engine (one "accept" rule). Not changed, and stated as limits below: **no protection against replay** (a recorded authentic packet delivers its frame again, counts as "peer heard", and draws the same answer; the reference protocol has none either, but the reference limits the rate of some answers and the leaf does not); only two multicast groups are announced (broadcast, and broadcast with the own address for ARP), and requests to list group members are not answered; a network with the stock default MTU of 2800 is refused (the leaf takes 1280 to 1500); packet IDs are unique within one run and only very probably across restarts; the adapter holds its mutex across calls into the network stack that take the stack's own locks (changed since: the adapter now makes those calls after it has released the mutex). Five deliberate errors for the new rules were added.

**Round 2, the cryptography (both models, same question, independently).** Both found F-25 and both showed that the primitive's contract does not say when the answer is yes (now stated under C-1 and in "does not show"). helper model A found F-26, the silent fallback of the wipe barrier on an unknown compiler, that the gate's proof record named the key but not the packet, and the "low byte of the block number" error of F-27. helper model B found F-24, the "skip block 126" error of F-27, and that result files from two parallel runs had mixed. Both pointed at what is still open: the whole-message Poly1305 contract, a relational check for constant time, scalar copies of secrets. One objection was not followed: helper model B asked to keep the proof-only call counter across calls instead of starting it at 0 in each call; a counter that only grows needs "below its maximum" as a precondition, which no caller that runs for ever can prove.
