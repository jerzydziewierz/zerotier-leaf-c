# Developer documents

Working documents of the C leaf: open points, decisions with their costs, measurements, and the review procedure. The reader-facing reports are in [`../reports/`](../reports/).

| Path | Purpose | Read when |
|---|---|---|
| [`AGENT-TESTS.md`](AGENT-TESTS.md) | Checks done by procedure (AT-n); AT-1: the documents agree with each other and with the code (mechanical check + an independent read) | Before a push; at handover |
| [`improvements-applied.md`](improvements-applied.md) | Every contract change and tightening, one paragraph each: what the contract accepted before, how it was found, what changed | After any contract or runner change; when writing about the proofs |
| [`bug-report-ztl-zephyr-adapter.md`](bug-report-ztl-zephyr-adapter.md) | Open points of the Zephyr adapter: datagrams from endpoints that are not pinned (`rx_filtered`), features not ported from the reference adapter, no test | Work on `zephyr/` |
| [`bug-report-ztl-replay.md`](bug-report-ztl-replay.md) | A recorded authentic packet is accepted again; stock peers use random packet IDs, so only a filter of recent IDs is possible; options and costs. Decided: a stated limitation (`reports/NOT_PROVEN.md` N-7) | Before any work on replay |
| [`ztram-mtu-cost.md`](ztram-mtu-cost.md) | Cost of a network MTU above 1500 (options, RAM, proof work). Decided 2026-11-14: the MTU stays at 1280..1500 | If the MTU limit becomes a problem |
| [`leaf-results/`](leaf-results/) | Measurements on the Teensy 4.1: echo round trip against size (`2026-11-13-final/`), cycles for each echo against the reference (`2026-11-14-cycles/`) | Performance work; figures |

The tools that made the measurements and the mechanical document check are in the private project workspace (`scripts/leaf_docs_check.py`, `scripts/leaf_echo_size.sh`, `scripts/overlay_cycles.py`).
