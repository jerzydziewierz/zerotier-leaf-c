# Future work

Items that were looked at, costed or measured, and not done. Each says what is known and what the next step would be.

## Speed: calls inside the Salsa20/12 block

State (2026-11-14, read from the machine code of the target compiler, `-mcpu=cortex-m7 -mthumb`; not measured on the board):

```yaml
- flags: "-Os (the firmware build)"
  quarter_round_calls_per_64_byte_block: 48
  salsa_c_code_bytes: 592
- flags: "-O2"
  quarter_round_calls_per_64_byte_block: 48
  salsa_c_code_bytes: 728
- flags: "-O2 -finline-limit=2000"
  quarter_round_calls_per_64_byte_block: 0
  salsa_c_code_bytes: 1680
- flags: "-O3 -finline-limit=2000 -funroll-loops"
  quarter_round_calls_per_64_byte_block: 0
  salsa_c_code_bytes: 2492
```

- `quarter_round()` stays a real call at `-Os` and `-O2`: 8 calls for each double round, 6 double rounds for each 64-byte block. Each call costs a branch, a push and a pop of four registers, one argument from the stack, and a pipeline refill. Estimate, not measured: about a fifth to a quarter of the Salsa20/12 time.
- A compiler flag removes the calls without a change in the source. The 16-word state stays in memory (`x[a]` with an index), so the loads and stores remain, and the code grows about three times.
- The `%` and `/` that the source uses for the provers cost nothing: GCC compiles `(v % 2^25) * 128 + v / 2^25` to one `eor` with `ror #25`. There is no divide instruction in the cipher.
- Size of the possible gain: the leaf takes about 75,000 of the about 500,000 cycles that the overlay adds to one 16-byte echo ([PERFORMANCE.md](PERFORMANCE.md)). A quarter of the cipher time is a few percent of the leaf and probably less than 2 % of the echo. The larger part is in the adapter, the UDP socket and the second pass through the network stack and USB.
- Proofs: compiler flags do not change what is proved (WP and CBMC prove the C; the compiler is trusted). They change the figures of the runner's `target` step (code size and stack for each file) and the stack table of the tutorial (`tools/callgraph/callgraph.py`). A source change that keeps the state in registers (16 named locals instead of `x[16]`) needs new contracts, a WP run and new deliberate errors.
- Next step, if speed matters: two firmware builds, the present one and one with `-O2 -finline-limit=2000` for `src/salsa.c` and `src/poly.c` only (module `zephyr/CMakeLists.txt`), and cycles for each echo from `ztl status` for both. Before that: the adapter and network-stack path, which holds most of the cycles.
