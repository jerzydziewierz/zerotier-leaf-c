## Part of a bigger work

This is one part of a larger project: ZeroTier overlay networking on the Zephyr RTOS, first target Teensy 4.1 (NXP i.MX RT1062, Cortex-M7).

```yaml
- part: "Reference solution"
  where: "https://github.com/jerzydziewierz/zephyr-zerotier-leaf"
  what: >-
    Restricted ZeroTier One 1.16.2 C++ core as a Zephyr module, tested on hardware with stock
    ZeroTier peers. About 110 KB of added RAM.
- part: "This repository"
  where: "`zerotier-leaf-c`"
  what: >-
    The same wire protocol written again in C: no heap, fixed tables, bounded packets, with proofs.
    The reference solution is its test oracle.
- part: "Zephyr integration, application, measurements"
  where: "the project workspace (not public)"
  what: "Zephyr adapter, the Teensy application, USB networking work, bench results."
- part: "Write-ups"
  where: "https://www.rey.wiki/george"
  what: "Measured results and reports."
```

The goal of this part is twofold: reduce RAM far below the reference solution, and find out how far several theorem-proving methods get on real embedded network code. The plan is to show both solutions side by side in the public repository when this one can talk to a network.

Paths such as `../grey_zerotier/` and `../dl/sdk/` in scripts and documents point into the project workspace, in which this repository is one folder. The proof runner needs the Zephyr SDK ARM compiler from there (or `ZTL_CC`).


## Status

```yaml
- module: "Datagram classifier"
  file: "`src/wire.c`"
  state: >-
    ✅ proved: exact contract (WP), all inputs up to 2049 bytes (CBMC), checked against a model of
    the reference receive path
- module: "Reassembly (head + one fragment)"
  file: "`src/reasm.c`"
  state: >-
    ✅ proved at full packet size (WP, small functions with contracts); cross-checked with CBMC at
    reduced size
- module: "Receive gate (\"authentication before effects\")"
  file: "`src/rx.c`"
  state: >-
    ✅ proved with WP against the contract of the authentication primitive, at full packet size;
    cross-checked with CBMC at 40-byte packets
- module: "Packet authentication and encryption (key mixing, Salsa20/12, Poly1305, open and seal)"
  file: "`src/auth.c`, `src/salsa.c`, `src/poly.c`"
  state: >-
    ✅ same bytes as the reference on test vectors made by the reference; proved with WP: memory
    safety, no arithmetic wrap, the contract that the gate uses, the arithmetic of each Poly1305
    step. ⏭ Not yet proved: Poly1305 over a whole message, any statement about the Salsa20/12
    output, constant time
- module: "LZ4 block decoder (a controller always compresses the configuration)"
  file: "`src/lz4.c`"
  state: >-
    ✅ proved with WP for every input: no access outside either buffer, no wrap, every loop ends;
    same bytes as the reference on 58 blocks made by the reference
- module: "Dictionary reader (configuration format)"
  file: "`src/dict.c`"
  state: >-
    ✅ proved with WP for memory safety; same answers as the reference reader on 198 dictionaries
- module: >-
    Protocol messages: HELLO, OK, ECHO, configuration request and reply, certificate push, multicast
    subscription, frames both ways, sends in two datagrams
  file: "`src/leaf.c`, `include/ztl/leaf.h`"
  state: >-
    ✅ proved with WP, every function: memory safety, no arithmetic wrap, every loop ends, the data
    invariant of the node, authentication before effects for the whole leaf, one packet ID for each
    packet, bounds on every frame and packet. ✅ exchanges frames with the reference node on a host
    (loopback test); protocol test with known answers and random authentic packets under sanitizers.
    ⏭ Not proved, tested only: what the messages mean, when the timers fire
- module: "Provisioning (pairwise keys from the identities, with the reference code)"
  file: "`tools/provision/`"
  state: >-
    ✅ used by the loopback test. The key agreement is the reference's code: a trusted component, not
    proved
- module: "Zephyr adapter (virtual Ethernet interface, one thread, no heap)"
  file: "`zephyr/`"
  state: >-
    ⏭ runs on the Teensy 4.1 (first run 2026-11-13: member of a network with a stock controller and
    stock peers; ping, Telnet and SSH sessions); no proof, no test of its own, no soak
```

Deliberate errors (mutation step): 102 errors in 114 tool runs, every one rejected by the tool that should see it. Measured in a firmware build for the Cortex-M7: code of the leaf 7,694 bytes, Zephyr adapter 2,100 bytes; RAM of the leaf 7,136 bytes (`struct ztl_leaf`), of the whole Zephyr module 15.8 KB with its thread stack and three packet buffers. The reference solution adds about 110 KB of RAM and 400 KB of code.

"Proved" here means: the code meets its written contract, for the tools' model of C. It does not mean that the contract is the right one, that the compiler is correct, or anything about timing. [reports/PROOFS.md](reports/PROOFS.md) lists every check and proof attempted, in plain words, with what each one does not show, and the attempts that failed.

## Documents

- [reports/PROOFS.md](reports/PROOFS.md): every proof and check, explained for a reader who is not a specialist; limits; failed attempts.
- [reports/PROTOCOL.md](reports/PROTOCOL.md): what a stock ZeroTier peer and controller expect from this leaf (messages, timings, configuration, membership), read from the reference source.
- [CHECKLIST.md](CHECKLIST.md): target theorems, design levers, the list of provers to try and their status, further proof targets, the proof method learned so far.

## Check

```sh
proofs/on-remote.sh start          # all steps: CBMC (64- and 32-bit model, reachability), Eva, WP (both models, then a search for contradictory contracts and unreachable code), target build, test vectors, protocol test
proofs/on-remote.sh start mutate   # deliberate errors in the code; each must be rejected
proofs/on-remote.sh wait           # wait for the end, copy results back; exit status 0 = all pass
proofs/on-remote.sh status | stop | fetch
```

No prover runs on the workstation. `proofs/on-remote.sh` copies the sources to another host (`ZTL_REMOTE`, default `prover-host`) and runs `proofs/run.sh` there as one systemd unit with a memory limit (`ZTL_MEM`, default 20G) and a time limit; `proofs/run.sh` refuses to start otherwise. The host needs `cbmc`, `z3`, `cvc5` (Ubuntu packages), Frama-C with WP and Alt-Ergo in the opam switch `ztl` (`proofs/opam-setup.sh start`, needs apt `graphviz` and `libgmp-dev`), and the Zephyr SDK ARM compiler in `~/ztl-sdk/arm-zephyr-eabi`. Results come back as `proofs/out-<step>.txt`.

The CBMC harnesses for reassembly, for the receive gate and for the cryptography are large; they run one per unit through `proofs/remote.sh start|status|stop|fetch` (`ZTL_REMOTE`, default `user@big-prover-host`), at reduced packet size (see `reports/PROOFS.md`).

Host tests (they need no prover; a C compiler, Python 3, and for the first one the reference source and its test node):

```sh
tests/host/build.sh <ZeroTier One source tree> /tmp/ztl-host    # leaf_node (with sanitizers) and the provisioning tool
python3 tests/host/interop.py /tmp/ztl-host <reference_node> [--mode normal|deny|tamper] [--frame-size 69|1280|1500]
```

`interop.py` makes throw-away identities, starts the reference node (reference core with a test controller, from the reference solution's host tests) and the leaf on two loopback UDP sockets, and passes when both sides received the other's frames and ARP requests and no wrong frame. `proofs/run.sh proto` (part of the default run) is the protocol test without a peer: fixed cases with known answers, then random authentic packets.

Zephyr: add this folder to `EXTRA_ZEPHYR_MODULES`, set `CONFIG_ZTL=y`, and call `ztl_zephyr_start()` with the provisioning data (`zephyr/include/ztl_zephyr.h`; `tools/provision/ztl_header.py` writes them as a C header). ⚠️ That header holds the pairwise keys: keep it and the firmware built from it on trusted hosts.

The test vectors in `tests/vectors/reference.txt` come from the reference implementation. `tests/oracle/gen.sh <ZeroTier One source tree>` makes them again (on a build host); `proofs/run.sh vectors` checks the leaf against them. `proofs/poly_identity.wl` is an independent check of the Poly1305 arithmetic with a computer algebra system.

## Rules for the code

- No `malloc`, no recursion, no variable-length arrays, no C library calls; every loop has a constant bound.
- Every function that reads network input takes `(pointer, length)` and has a contract that WP proves; the classifier, the reassembly and the receive gate also have a CBMC harness in `proofs/`.
- No arithmetic wraps: every sum, product and conversion is proved to stay in its type; a result modulo 2^32 is written with `%`. No `#pragma` that switches a check off.
- Interfaces carry the annotations of `include/ztl/annot.h` and, where a deductive proof is intended, an ACSL contract.
- Sizes are constants in headers; RAM is the sum of static objects.

Plan, theorems and the list of provers to try: [CHECKLIST.md](CHECKLIST.md). Every check and proof attempted so far, explained in plain words with its limits: [reports/PROOFS.md](reports/PROOFS.md).
