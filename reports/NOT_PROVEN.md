# What is proved and what is not, element by element

A checklist for a review. Each element of the system has two parts: what a tool proves about it today (with the numbers of the statements in [PROOFS.md](PROOFS.md#list-of-proofs)), and an open list of what is NOT proved, each with the evidence that stands in for a proof today and with what would close it. Tick a box when the point is reviewed; an entry leaves this list when a tool proves it.

Words: "proved" = a tool shows it for every input that the contract allows (Frama-C WP unless another tool is named). "Tested" = shown for the inputs of a test only. "Read" = a person or a review read the code or the compiled code; no tool checks it.

Two statements hold for every function of the nine source files and are not repeated below (L-1 to L-6): no run-time error, no read or write outside the memory that the contract names, no arithmetic wrap or lossy conversion, every loop ends, and the result meets the function's contract. The limits of these words are in the last chapter.

## 1. Datagram classifier (`src/wire.c`)

Proved: the answer (head, fragment, drop) follows the exact written rule in both directions, every field of the result has its exact value, nothing is written on a drop (L-7); the rule equals a model of the reference receive path for every datagram of 0 to 2,049 bytes (L-8, CBMC); every kind of outcome can happen (L-9).

- [ ] **N-1 The model of the reference is written by hand.** L-8 compares the code with a reading of the reference source, not with the reference program. Stands in: three review rounds; the board run with stock peers. Would close it: the same datagrams through both programs (a corpus made from the proof's reachability targets).
- [ ] **N-2 Peers older than the pinned reference version.** One rule error of this kind was found by reading older sources (F-10), not by a tool. Would close it: the same comparison against older releases.

## 2. Reassembly (`src/reasm.c`)

Proved: both arrival orders give the head bytes, then the fragment bytes; nothing above 2,048 bytes (L-10); the whole rule for waiting packets with a clock that wraps (L-11); the memory stays valid and a returned packet is the datagram or one freed slot (L-12). Cross-checked with CBMC at 64-byte packets.

- [ ] **N-3 `ztl_reasm_input()` does not state the timeout rule in its own contract.** The rule is proved for the function that chooses the slot; callers see only "the datagram or one freed slot". Would close it: the rule in the outer contract.
- [ ] **N-4 A caller that makes no call for more than 2^31 ms (about 25 days).** The clock difference is then wrong. Stated as a rule for the caller; nothing checks it.
- [ ] **N-5 The CBMC cross-check holds at 64 bytes only.** At full size the formula does not fit (F-15). The full size rests on WP alone.

## 3. Receive gate (`src/rx.c`)

Proved: a packet is delivered only after exactly one call of the authentication function that answered yes, with the key of a pinned peer whose address is the packet's source, for a packet addressed to this node (L-13); an unencrypted packet passes only as HELLO (L-14); without delivery nothing changes but one counter (L-15); the delivered body is the rest of exactly the authenticated packet (L-16). Cross-checked with CBMC at 40-byte packets.

- [ ] **N-6 The proof uses proof-only variables.** The record "one call, answer yes, this key, this packet" is kept in ghost variables that do not exist in the program. The ghost lines are text that the reader must trust. Stands in: the CBMC harness states the same properties a second time without them.
- [ ] **N-7 Replay.** A recorded authentic packet passes the gate again: its frame is delivered again and it draws the same answer. Stock peers number their packets with random values, so "accept only higher numbers" is not possible; a filter for the last N numbers is a design decision that is open. Nothing stands in.
- [ ] **N-8 The CBMC cross-check holds at 40 bytes only** (no result at 64 bytes in 6 hours).

## 4. Opening and sealing a packet (`src/auth.c`)

Proved: `ztl_auth_open()` writes only the bytes from the verb byte onward, and after the answer no, or without decryption, the packet is unchanged (L-17); the comparison answers 1 exactly when all bytes are equal; the wipe functions write zeros (L-20).

- [ ] **N-9 ⚠️ "Yes" means a right MAC.** The contract says what the function may change, not when it answers yes. A function that always answers yes passes every proof. This is the weakest link of "authentication before effects". Stands in: 292 packets made by the reference, each opened, and refused after every one-bit change; the deliberate errors "always yes" and "7 of 8 bytes compared" are rejected by these tests only. Would close it: a specification of the tag in the contract (needs N-13 and N-11).
- [ ] **N-10 Seal then open gives back the payload.** The CBMC attempt gave no result in 4 hours. Stands in: the test vectors, and every exchange with a stock peer.
- [ ] **N-11 The key mixing and the use of the key stream** (which header fields go into the key; block 0 for the MAC key, block 1 onward for the payload; the MAC over the encrypted bytes; 8 of 16 tag bytes). Tested only.
- [ ] **N-12 Constant time.** The comparison has no early exit and the last Poly1305 selection has no branch: by construction and by reading the compiled code. A comparison with an early exit would pass every proof and every test. Would close it: a relational check (two runs, different secrets, same path).
- [ ] **N-12b Every exit wipes its secrets.** The wipe functions are proved; that each exit path calls them is read, not proved. Copies of secrets in registers and stack slots are not wiped at all.

## 5. Poly1305 (`src/poly.c`)

Proved: the five limbs stay inside their limits for a message of any length up to the packet size, so no product, sum or carry leaves its type (L-18; also by a CBMC induction step); each step is exact arithmetic: bytes to limbs, add a block, multiply modulo 2^130 − 5 with the multiplier named, final reduction to the tag bytes (L-19; the identity also by computer algebra).

- [ ] **N-13 The whole function.** No contract says that the loop feeds every block exactly once, that the key is clamped as the definition says, or that the last short block is padded right: the proved steps are not joined into "this is the tag of this message". Stands in: 125 tags from the reference, with hand-made cases at the edge of the modulus. Would close it: a recurrence invariant over the blocks.

## 6. Salsa20/12 (`src/salsa.c`)

Proved: only the common statements (memory, no wrap, loops end).

- [ ] **N-14 Any statement about the output.** Nothing proves that the key stream is Salsa20 with 12 rounds. Stands in: 28 key stream vectors from the reference; five deliberate errors (round count, one rotation, block number) are rejected by the vectors only. The CBMC comparison with a model in the reference's form gave no result in 4 hours. Would close it: the comparison one double round at a time, or a value contract.

## 7. LZ4 decoder (`src/lz4.c`)

Proved: for every block and every output size up to 2,048 bytes, no access outside the block or the output, and no match that copies from before the start of the output (L-21).

- [ ] **N-15 The output is what LZ4 means by the block.** The contract speaks of memory only. Stands in: 58 blocks compressed by the reference decode to the same bytes.
- [ ] **N-16 Which malformed blocks are refused.** Tested with shortened inputs and random blocks; not compared with the reference decoder on malformed input.

## 8. Dictionary reader (`src/dict.c`)

Proved: for every dictionary up to 2,048 bytes and every key up to 8 bytes, no access outside the dictionary, the key or the value buffer (L-22).

- [ ] **N-17 The value returned is the right one.** Stands in: 198 lookups answered by the reference's reader, 54 of them in dictionaries that the reference's writer never makes.

## 9. Protocol layer (`src/leaf.c`)

Proved: no reply and no frame leaves `ztl_input()` without the gate's yes (L-23); after the start no call writes the own address, the pinned peers, their keys, the public key, the network ID or the controller index (L-24); each built packet takes exactly one packet number, the nonce of its encryption (L-25); bounds: a frame for the host has 1 to 1,500 bytes and is readable, a packet has 28 to 2,048 bytes (L-26); a frame from the host goes out only with a configuration, to a pinned peer that was heard, with 1 to MTU bytes (L-27); the data invariant of the node holds after every call (L-28); the second datagram of a long packet is the right header and exactly the rest (L-29).

- [ ] **N-18 ⚠️ What the messages mean.** No contract says that a HELLO, an OK, a configuration request, a certificate push or a subscription has the right fields in the right places. Stands in: 270 fixed checks with known answers; the exchange with the reference node on a host; the board as a member of a network with a stock controller and stock peers; 35 deliberate errors for the protocol test, all rejected (29 of them by that test only).
- [ ] **N-19 Which received messages are refused.** A configuration from a peer that is not the controller, for another node or network, older than the last one, with a cut certificate; a frame from a foreign source, for a third station, of another network: all are code and tests. The invariant only bounds what an accepted configuration can set (MTU, certificate length).
- [ ] **N-20 Answers are matched to requests.** "An OK counts once, and only for the waiting request" is code and tests.
- [ ] **N-21 Timers and progress.** That HELLO, the configuration request, the certificate and the subscription go out when they are due, and that the leaf comes back after silence, is tested with a few cases. A HELLO period of 61 s in place of 60 passes every check.
- [ ] **N-22 Parsing and building are inverse** (theorem T4 of the checklist). Not started.
- [ ] **N-23 The packet number does not repeat across restarts.** Proved within one run. The start value must be 64 random bits from the platform at each start: a duty of the integrator, checked by nothing.
- [ ] **N-24 The frame pointer.** A delivered frame is a pointer into the datagram or into the leaf, valid until the next call. Nothing proves that the caller stops using it in time (the Zephyr adapter copies it at once: read).
- [ ] **N-25 Limits by design, not errors:** no check of the controller's signature on a configuration; no evaluation of the network's rules; a configuration must fit one chunk; only broadcast and ARP as multicast.

## 10. Zephyr adapter (`zephyr/`)

Proved: nothing.

- [ ] **N-26 ⚠️ Everything.** Threads and the one mutex, the order of locks against the network stack, ownership of packet buffers, the socket, the set-up of the interface. Stands in: runs on one board (ping, Telnet, SSH, echo sweeps and a soak without loss). No test of its own.
- [ ] **N-27 One call at a time.** Every proof of the core is about one call that nothing interrupts. That the adapter never makes two calls at once rests on its mutex, by reading.
- [ ] **N-28 Not ported from the reference adapter:** private packet pools, learning of peers' Ethernet addresses from authenticated frames, a check that overlay and underlay subnets do not overlap. Behaviour under flood is not measured.

## 11. Provisioning (`tools/provision/`)

Proved: nothing.

- [ ] **N-29 The pairwise keys.** They are made on a host by the reference's own key agreement code, which is taken as correct. Stands in: every authenticated exchange with a stock peer needs the right key.
- [ ] **N-30 The firmware holds the pairwise keys.** Who can read the firmware can read them. A rule for the deployer.

## 12. The method itself

- [ ] **N-31 ⚠️ The rules are a reading of the reference.** A proof shows that the code follows the written rule, not that the rule is right. Three rule errors were found by review and by reading, none by a tool (F-7, F-8, F-10).
- [ ] **N-32 The contracts are written by hand.** A contract that says too little proves less than it seems. Stands in: 102 deliberate errors, each rejected; 1,000 smoke tests found no contradiction; three review rounds. These are samples, not proofs.
- [ ] **N-33 The tools' model of C.** No notion of reading memory that was never written (one such read was found by review, F-24); pointer alignment is not checked; the 32-bit model is x86, not ARM, for the layout of structures.
- [ ] **N-34 The compiled code.** The proofs are about the C source. The compiler, the linker and the processor are trusted. Stands in: the target build without warnings, and reading the compiled code where secrets are handled.
- [ ] **N-35 Stack depth.** Per function from the compiler, summed by hand along the call graph; interrupts are not included. No tool bounds it.
- [ ] **N-36 Time.** No statement about how long a call takes; measurements are in [PERFORMANCE.md](PERFORMANCE.md).
- [ ] **N-37 The provers are trusted.** Each goal is proved by at least one of three provers; an error in a prover or in Frama-C would not be seen. Stands in: CBMC as a second method for the classifier, the reassembly and the gate; the deliberate errors.
