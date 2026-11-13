# zerotier-leaf-c: a theorem-proved ZeroTier client in C

This repository holds one thing: an implementation of a ZeroTier protocol v1 client ("leaf" node) in ISO C11 for small microcontrollers, written so that its properties can be machine-checked, together with the proofs. Every function that touches network input has a written contract, and tools (Frama-C WP, CBMC, Frama-C Eva) check the code against it.

⏭ Work in progress. It is not a usable network client yet.

## Part of a bigger work

This is one part of a larger project: ZeroTier overlay networking on the Zephyr RTOS, first target Teensy 4.1 (NXP i.MX RT1062, Cortex-M7).

| Part | Where | What |
|---|---|---|
| Reference solution | https://github.com/jerzydziewierz/zephyr-zerotier-leaf | Restricted ZeroTier One 1.16.2 C++ core as a Zephyr module, tested on hardware with stock ZeroTier peers. About 110 KB of added RAM. |
| **This repository** | `zerotier-leaf-c` | The same wire protocol written again in C: no heap, fixed tables, bounded packets, with proofs. The reference solution is its test oracle. |
| Zephyr integration, application, measurements | the project workspace (not public) | Zephyr adapter, the Teensy application, USB networking work, bench results. |
| Write-ups | https://www.rey.wiki/george | Measured results and reports. |

The goal of this part is twofold: reduce RAM far below the reference solution, and find out how far several theorem-proving methods get on real embedded network code. The plan is to show both solutions side by side in the public repository when this one can talk to a network.

Paths such as `../grey_zerotier/` and `../dl/sdk/` in scripts and documents point into the project workspace, in which this repository is one folder. The proof runner needs the Zephyr SDK ARM compiler from there (or `ZTL_CC`).

## Design in one paragraph

A fixed-function node: at most 7 pinned peers, one network, packets of at most 2048 bytes in at most two parts, cipher suite Salsa20/12 + Poly1305 only (the node announces protocol version 11, so peers do not use AES with it). It is assigned to its network at provisioning time, in a secure environment, with one pairwise key per peer; no public-key cryptography runs on the device. No `malloc`, no C library calls, no recursion; RAM is the sum of static objects.

## Status

| Module | File | State |
|---|---|---|
| Datagram classifier | `src/wire.c` | ✅ proved: exact contract (WP), all inputs up to 2049 bytes (CBMC), checked against a model of the reference receive path |
| Reassembly (head + one fragment) | `src/reasm.c` | ✅ proved at full packet size (WP, small functions with contracts); cross-checked with CBMC at reduced size |
| Receive gate ("authentication before effects") | `src/rx.c` | ✅ proved with WP against the contract of the authentication primitive; CBMC cross-check has no result yet |
| Packet authentication and encryption (key mixing, Salsa20/12, Poly1305, open and seal) | `src/auth.c`, `src/salsa.c`, `src/poly.c` | ✅ same bytes as the reference on test vectors made by the reference; proved with WP: memory safety, no arithmetic wrap, the contract that the gate uses, the arithmetic of each Poly1305 step. ⏭ Not yet proved: Poly1305 over a whole message, any statement about the Salsa20/12 output, constant time |
| Protocol messages (HELLO, configuration, frames), LZ4 decoder for the configuration, send path, Zephyr adapter | — | 🔴 not started; what a stock peer expects is in [reports/PROTOCOL.md](reports/PROTOCOL.md) |

Deliberate errors (mutation step): 50 errors in 56 tool runs, every one rejected by the tool that should see it. Code size of all modules: 3,090 bytes on Cortex-M7; RAM 4,440 bytes; stack of the receive path at most 456 bytes.

"Proved" here means: the code meets its written contract, for the tools' model of C. It does not mean that the contract is the right one, that the compiler is correct, or anything about timing. [reports/PROOFS.md](reports/PROOFS.md) lists every check and proof attempted, in plain words, with what each one does not show, and the attempts that failed.

## Documents

- [reports/PROOFS.md](reports/PROOFS.md): every proof and check, explained for a reader who is not a specialist; limits; failed attempts.
- [reports/PROTOCOL.md](reports/PROTOCOL.md): what a stock ZeroTier peer and controller expect from this leaf (messages, timings, configuration, membership), read from the reference source.
- [CHECKLIST.md](CHECKLIST.md): target theorems, design levers, the list of provers to try and their status, further proof targets, the proof method learned so far.

## Check

```sh
proofs/on-remote.sh start          # all steps: CBMC (64- and 32-bit model, reachability), Eva, WP (both models), target build, test vectors
proofs/on-remote.sh start mutate   # deliberate errors in the code; each must be rejected
proofs/on-remote.sh wait           # wait for the end, copy results back; exit status 0 = all pass
proofs/on-remote.sh status | stop | fetch
```

No prover runs on the workstation. `proofs/on-remote.sh` copies the sources to another host (`ZTL_REMOTE`, default `prover-host`) and runs `proofs/run.sh` there as one systemd unit with a memory limit (`ZTL_MEM`, default 20G) and a time limit; `proofs/run.sh` refuses to start otherwise. The host needs `cbmc`, `z3`, `cvc5` (Ubuntu packages), Frama-C with WP and Alt-Ergo in the opam switch `ztl` (`proofs/opam-setup.sh start`, needs apt `graphviz` and `libgmp-dev`), and the Zephyr SDK ARM compiler in `~/ztl-sdk/arm-zephyr-eabi`. Results come back as `proofs/out-<step>.txt`.

The CBMC harnesses for reassembly, for the receive gate and for the cryptography are large; they run one per unit through `proofs/remote.sh start|status|stop|fetch` (`ZTL_REMOTE`, default `user@big-prover-host`), at reduced packet size (see `reports/PROOFS.md`).

The test vectors in `tests/vectors/reference.txt` come from the reference implementation. `tests/oracle/gen.sh <ZeroTier One source tree>` makes them again (on a build host); `proofs/run.sh vectors` checks the leaf against them. `proofs/poly_identity.wl` is an independent check of the Poly1305 arithmetic with a computer algebra system.

## Rules for the code

- No `malloc`, no recursion, no variable-length arrays, no C library calls; every loop has a constant bound.
- Every function that reads network input takes `(pointer, length)` and has a CBMC harness in `proofs/`.
- No arithmetic wraps: every sum, product and conversion is proved to stay in its type; a result modulo 2^32 is written with `%`. No `#pragma` that switches a check off.
- Interfaces carry the annotations of `include/ztl/annot.h` and, where a deductive proof is intended, an ACSL contract.
- Sizes are constants in headers; RAM is the sum of static objects.

Plan, theorems and the list of provers to try: [CHECKLIST.md](CHECKLIST.md). Every check and proof attempted so far, explained in plain words with its limits: [reports/PROOFS.md](reports/PROOFS.md).

Licence: Apache-2.0.
