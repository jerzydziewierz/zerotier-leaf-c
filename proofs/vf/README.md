# VeriFast pilot: lock discipline of the Zephyr adapter

State: 2026-11-14. This directory holds a MODEL of `zephyr/ztl_zephyr.c` that VeriFast 26.10 verifies, and variants of the model that VeriFast must reject. A proof of the model is a proof about the model. It is evidence about the adapter only as far as the model follows the adapter (by hand, by reading) and the stub contracts are right. It closes none of N-26 or N-27 in `reports/NOT_PROVEN.md`. Verification of the REAL adapter file is future work (see the last sections).

Files: `ztl_zephyr_model.c` (the model), `vf_stubs.h` (contracts of the leaf and of Zephyr, no bodies), `run.sh` (all cases, on a host that has `verifast`).

## What VeriFast is, in ten lines

VeriFast runs each C function once, symbolically, against its contract (`requires` / `ensures`). The state it tracks is a "heap" of chunks: each chunk is the permission to use one piece of memory (`x |-> v`) or one abstract resource (a predicate such as `net_pkt(p)`). This is separation logic: `A &*& B` means that A and B are permissions for DIFFERENT memory, so that two holders can never touch the same byte.

- Ownership. A read needs some share of the chunk (`[1/2]x |-> v`). A write needs the whole chunk. A chunk cannot be copied. If a function has no chunk for `tx_buf`, it cannot touch `tx_buf`: VeriFast stops with "No matching heap chunks".
- Predicate. A named bundle of chunks (`leaf_inv()` below). `open` unpacks it, `close` packs it.
- Lock invariant. A mutex is created together with a predicate. The predicate's chunks go INTO the mutex. `lock` hands them out, `unlock` takes them back. So the guarded memory is reachable only between lock and unlock, and this is how "guarded by lock" becomes a checked fact and not a comment.
- Leak check. At the end of a function every chunk must be given back through `ensures`, or VeriFast reports "Function leaks heap chunks" (or cannot find a chunk that `ensures` needs). A return with the mutex held fails here, because the caller's share of the mutex is locked inside `k_mutex_held`.
- What Frama-C/WP, CBMC and Eva (the tools used on the leaf core) do not give: a compositional argument about threads. Each thread is verified alone; the rule that chunks cannot be copied makes the result hold for every interleaving.

## The encoding

```yaml
leaf_inv:        # the lock invariant, model: "predicate leaf_inv()"
  holds: ["ztl_leaf_core(&leaf)", "half of adapter_fixed()", "tx_buf", "frame_buf", "in_cycles", "out_cycles", "in_calls", "out_calls", "in_max", "out_max"]
worker_only:     # owned by the worker thread; no other thread has a share
  holds: ["rx_buf", "have_ip", "have_prefix"]
adapter_fixed:   # "fixed after start": written only before the worker exists; read-only afterwards
  holds: ["leaf.pinned (real: leaf.node.peer[i].pinned)", "endpoint[]", "sock", "overlay", "underlay_if", "local_port", "overlay_mac"]
  split: "one half in leaf_inv, one half with the caller of ztl_zephyr_start(), then with the worker"
start_right:     # the right to call ztl_zephyr_start(); becomes the worker's resources
  holds: ["1/4 of the mutex", "half of adapter_fixed()", "worker_only()"]
k_mutex_not_held: # token "this thread does not hold the mutex"
  taken_by: "k_mutex_lock"
  given_by: ["k_mutex_unlock", "k_mutex_lock that timed out", "thread entry (assumed)", "k_mutex_init"]
```

"No stack call under the lock" (P2) uses the token `k_mutex_not_held(m, thread)`. It is an abstract predicate with no body and no lemma that makes one, so it cannot be copied or made from nothing. `k_mutex_lock()` consumes it and `k_mutex_unlock()` produces it. Every stub of class U (below) requires it and gives it back. A thread that holds the mutex has no token and cannot call a class U function. This is the simplest sound encoding for ONE mutex. VeriFast's own `threading.h` has a general one (`lockset` and lock levels, which also proves freedom from deadlock between several locks); it needs a level for every lock of the network stack, which the pilot does not model. A side effect: the model refuses a second lock by the owner, which Zephyr allows.

"Fixed after start" (GRey's decision A-ztram-vf-8; the comment before `from_endpoint()` in the adapter, lines 150 to 158, cites this encoding). What the model proves, exactly: a write of `adapter_fixed()` state needs the WHOLE permission, that is both halves. Both halves are in one thread only inside `ztl_zephyr_start()`, in its two locked sections (lines 355 to 379, and 388 to 390 where `sock` is stored), and only while that thread still owns `start_right()`, that is before the worker exists. After a successful start one half is in the lock invariant and the other half belongs to the worker for ever (the worker's loop never gives it up). So after the start every thread has at most a read share, with or without the lock, and no write of `leaf.pinned`, `endpoint[]`, `sock`, `overlay`, `underlay_if`, `local_port`, `overlay_mac` verifies (`VF_BAD_WRITE_ENDPOINT`, `VF_BAD_WRITE_PINNED`: "Assignment requires full permission"). A write inside `ztl_zephyr_start()` but outside the lock does not verify either (`VF_BAD_SOCK_UNLOCKED`). The model does NOT prove that the real `ztl_zephyr_start()` runs at most once: there the atomic variable `running` decides, here the caller must own `start_right()`.

Stub classes in `vf_stubs.h`:

```yaml
class_U:  # require the token: never called with the mutex held
  - zsock_poll
  - net_recv_data
  - net_if_carrier_off, net_if_carrier_on, net_if_up
  - net_if_ipv4_addr_add, net_if_ipv4_addr_rm, net_if_ipv4_set_netmask_by_addr
  - net_if_get_mtu, net_if_set_mtu
  - net_if_set_link_addr
  - zsock_socket_udp, zsock_bind_to, zsock_close   # real: socket, net_if_get_name, setsockopt, bind, close
class_L:  # THE ONE ACCEPTED EXCEPTION: called by the adapter WITH the mutex held; no token; accepted, not proved safe
  - zsock_sendto          # token with VF_STRICT_SEND
  - net_pkt_rx_alloc_with_buffer, net_pkt_write, net_pkt_unref, net_pkt_read, net_pkt_cursor_init, net_pkt_get_len
other:    # no token asked
  - zsock_recvfrom        # the adapter calls it without the mutex; the model does not demand that
  - k_uptime_get_32, k_cycle_get_32, k_yield, sys_csrand_get, atomic_*
```

The split into U and L is an INPUT of the proof, taken from the comments of the adapter (lines 227 and 228 in `worker()`, line 380 in `ztl_zephyr_start()`) and from `dev-docs/bug-report-ztl-zephyr-adapter.md` (A-1). VeriFast does not check that a class L function is harmless under the lock.

## Model and adapter, function by function

Line numbers are those of `zephyr/ztl_zephyr.c`. Each lock, unlock and leaf call in the model carries a `/* line N */` comment.

```yaml
- fn: "send_packet"
  lines: "56-72"
  model: "same loop; needs tx_buf (only the lock gives it) and a share of adapter_fixed (endpoint, sock)"
  differs: "endpoint[i] passed as two values; \"?:\" written as if/else"
- fn: "overlay_down"
  lines: "75-83"
  model: "requires the token and worker_only"
- fn: "apply_config"
  lines: "94-119"
  model: "requires the token (comment \"WITHOUT the lock\" is now checked); same order of net_if_* calls"
  differs: "ip is one integer; the mask is a stub; the \"&&\" with net_if_get_mtu() is a nested if"
- fn: "frame_to_pkt"
  lines: "124-147"
  model: "alloc, write, unref on error; returns NULL or one owned packet"
  differs: "the 14-byte header (138-140) is left out; what f->data points to is not modelled"
- fn: "from_endpoint"
  lines: "159-168"
  model: "reads leaf.pinned and endpoint[] with a HALF share, without the lock"
- fn: "worker"
  lines: "170-240"
  model: "lock 180, ztl_poll 181, send_packet 182, unlock 184, zsock_poll 185, zsock_recvfrom 193, lock 207, ztl_input 209, send_packet 216, copy of the configuration 218-222, frame_to_pkt 224, unlock 226, apply_config 230, net_recv_data 232, k_yield 238"
  differs: "\"while ((n = ztl_poll()) != 0)\" is a loop with break; from_endpoint() is called before the \"||\" test, not inside it; \"cfg = { 0 }\" is three assignments; the frame is set to zero before use; nested calls go through temporaries"
- fn: "ztl_dev_send"
  lines: "243-282"
  model: "checks before the lock, lock with timeout 255 and its failure path, net_pkt_read 260, ztl_frame_to 268, send_packet 275, unlock 280"
  differs: "no dev parameter; \"&&\" of two reads is nested ifs; sys_get_be16 is a stub"
- fn: "socket_open"
  lines: "315-335"
  model: "socket 319, bind 326-328, close on error; returns the descriptor; requires the token; does not touch sock"
  differs: "net_if_get_name + setsockopt + bind are one stub; errno is not modelled"
- fn: "ztl_zephyr_start"
  lines: "337-404"
  model: "checks, atomic_cas 346, lock 355, ztl_init 356, ztl_pin 360, endpoint writes, copy of leaf.mac to overlay_mac 377, unlock 379, socket_open 382, second locked section 388-390 with the store of sock 389, net_if_set_link_addr 394, thread creation 400"
  differs: "\"*config\" is read through stubs; \"running\" is replaced by the resource start_right; memcpy is a stub; k_thread_name_set is left out"
- fn: "ztl_zephyr_get_status"
  lines: "406-433"
  model: "lock 417, reads of leaf and counters, unlock 432"
  differs: "the result is one number; lines 408-416 (atomics, \"overlay\" read before the lock) are left out"
- fn: "ztl_iface_init, ztl_dev_init, device definition"
  lines: "284-312"
  model: "not modelled; main() sets \"overlay\" before any thread exists"
- fn: "stack_thread, main"
  lines: "none"
  model: "the environment. main() owns all globals (VeriFast \"module\" chunk), builds the lock invariant, starts one thread that calls ztl_dev_send() and ztl_zephyr_get_status() for ever, and calls ztl_zephyr_start(). It shows that the contracts can be met from the first state of the program."
```

## Results

Run 2026-11-14 with `proofs/vf/run.sh` (it works from any working directory and writes no file) on a host with VeriFast 26.10 (source build of tag 26.10), `-c -target ILP32`. Times are wall time of one run on that host.

```yaml
- case: "good"
  expect: "pass"
  redux: "0 errors found (316 statements verified), 0.16 s"
  z3v4.5: "0 errors found (316 statements verified), 3.5 s"
- case: "VF_BAD_NO_LOCK         # ztl_frame_to() before the lock, in ztl_dev_send()"
  expect: "fail"
  message: "No matching heap chunks: ztl_leaf_core(leaf)"
  where: "the requires clause of ztl_frame_to"
- case: "VF_BAD_STACK_LOCKED    # net_recv_data() before the unlock of line 226"
  expect: "fail"
  message: "No matching heap chunks: k_mutex_not_held(_, currentThread)"
  where: "the requires clause of net_recv_data"
- case: "VF_BAD_EARLY_RETURN    # return between lock and unlock in ztl_dev_send()"
  expect: "fail"
  message: "No matching heap chunks: [q]k_mutex(lock, leaf_inv)"
  where: "the ensures clause of ztl_dev_send (the share is inside k_mutex_held)"
- case: "VF_BAD_LOOP_KEEPS      # \"continue\" between lock and unlock in worker()"
  expect: "fail"
  message: "No matching heap chunks: [1/4]k_mutex(lock, leaf_inv)"
  where: "the loop invariant of the receive loop"
- case: "VF_BAD_RX_BUF          # ztl_dev_send() writes rx_buf"
  expect: "fail"
  message: "No matching heap chunks: integer__(rx_buf, 1, false, _)"
  where: "the requires clause of net_pkt_read"
- case: "VF_BAD_START_LOCKED    # socket_open() before the unlock of line 379 (the adapter before the fix of F-2)"
  expect: "fail"
  message: "No matching heap chunks: k_mutex_not_held(lock, currentThread)"
  where: "the call of socket_open() in ztl_zephyr_start"
- case: "VF_BAD_SOCK_UNLOCKED   # \"sock = s\" after the unlock, without the second locked section (the adapter before the fix of F-5)"
  expect: "fail"
  message: "Writing to a global variable requires full permission."
  where: "the assignment, in ztl_zephyr_start"
- case: "VF_BAD_WRITE_ENDPOINT  # worker() writes endpoint[] after the start, without the lock"
  expect: "fail"
  message: "Assignment requires full permission."
  where: "the assignment, in worker"
- case: "VF_BAD_WRITE_PINNED    # ztl_dev_send() writes the pinned table, WITH the lock"
  expect: "fail"
  message: "Assignment requires full permission."
  where: "the assignment, in ztl_dev_send"
- case: "VF_STRICT_SEND         # not an error: the accepted exception, zsock_sendto() made class U"
  expect: "fail"
  message: "No matching heap chunks: k_mutex_not_held(lock, currentThread)"
  where: "the call of send_packet() in worker (line 216)"
```

Both provers give the same verdict for every case (22 runs, all as expected, `run.sh` exit status 0, last line `run.sh: all cases as expected`). `run.sh` checks for each failing case the text of the first error and the function in which VeriFast stops, so that a variant cannot "fail" for a wrong reason such as a syntax error. Checked once by hand and not kept in `run.sh`: `//@ assert false;` after the statement that maps to each of the lines 184, 216, 226, 230, 238, 275, 280, 379, 382, 389, 390, 394, 400, 432 is rejected (Redux), so these points are reachable in the proof and the contracts are not contradictory there.

What the passing model shows, for the model:

- P1. Every call of `ztl_init`, `ztl_pin`, `ztl_input`, `ztl_poll`, `ztl_frame_to` and every use of `tx_buf` (also `ztl_tx_second`, `zsock_sendto`), `frame_buf` and the six timing counters happens in a thread that holds the mutex. `rx_buf`, `have_ip`, `have_prefix` are used by the worker only. The "fixed after start" state is read without the lock and never written after the start (section "The encoding"). Depends on: the stubs of the leaf name the right memory (`ztl_leaf_core`, `ztl_leaf_pins`, `tx`), and the model's globals are the adapter's globals.
- P2. No class U function is called by a thread that holds the mutex, with no exception at start-up any more. The one accepted exception is class L (`zsock_sendto()` and `net_pkt_*()` under the lock). Depends on: the class lists above; the token given to each new thread and to the caller of `ztl_dev_send()`.
- P3. No function returns, and no loop starts its next turn, with the mutex held. `k_mutex_lock(K_FOREVER)` is taken to succeed always; the timeout path of line 255 is checked as a path without the mutex.
- By-product: each `net_pkt` that the worker allocates is given to the stack, or released, exactly once (lines 142, 232 to 234), given the stub contract "net_recv_data() takes the packet unless it fails".

## Findings about the real adapter

- ✅ F-1 The leaf is not used only under the lock: `from_endpoint()` reads `leaf.node.peer[i].pinned` and `endpoint[]` without it (lines 162, 163); the worker reads `sock` (176, 193) and `overlay` (232) the same way. Decision: kept, as "fixed after start"; the adapter says so before `from_endpoint()`. The model proves "no write after the start" as stated in section "The encoding". "Never written by the leaf" rests on the ACSL `assigns` clauses (`reports/PROOFS.md`, L-24), which the stubs copy.
- ✅ F-2 `ztl_zephyr_start()` called `socket_open()` and `net_if_set_link_addr()` with the mutex held. Fixed in the adapter: both come after the unlock (lines 382, 394), with a copy of `leaf.mac` taken under the lock (line 377). The model follows the new order; the old order is the variant `VF_BAD_START_LOCKED`.
- ✅ F-3 The contract of `ztl_input()` did not bound `*peer`. Fixed in `include/ztl/leaf.h`: `*tx_len != 0 ==> *peer < ZTL_PEERS && l->node.peer[*peer].pinned != 0`, proved with WP. The stub of the model now takes the bound from that contract; it is no longer an assumption of the model.
- 💡 F-4 Known and accepted: `zsock_sendto()` runs with the mutex held (bug report A-1). `VF_STRICT_SEND` is rejected at the first such path that VeriFast meets (line 216); by reading, the paths start at lines 182, 216 and 275.
- ✅ F-5 Found by the model after the fix of F-2: `socket_open()` then wrote `sock` without the lock, while `send_packet()` reads `sock` under the lock in the thread of `ztl_dev_send()`. Only the atomic variable `usable` kept the two apart, and the model could follow the code only with an assumption about `usable`. Fixed in the adapter: `socket_open()` returns the descriptor (lines 315 to 335) and `ztl_zephyr_start()` stores it in `sock` in a second short locked section (lines 388 to 390). `sock` is in `adapter_fixed()` again: written with the lock and the right to start, read under the lock on the send path, read by the worker as "fixed after start" (the worker is created at line 400, after the store). The assumption and its stub are removed. The order before this fix is the variant `VF_BAD_SOCK_UNLOCKED`.

## Limits

- It is a model, made by hand. Nothing checks that it follows `ztl_zephyr.c`; a change of the adapter does not break this proof. The "differs" entries above are all the known differences.
- The stubs are assumptions: 35 Zephyr functions, 7 leaf functions, 9 helper stubs. In particular the proof of P2 says nothing about what the class L functions do inside the stack, and nothing about the stack's own locks. It is not a proof of freedom from deadlock.
- Assumed about the environment: a thread that enters `ztl_dev_send()` does not hold the adapter's mutex (so: `zsock_sendto()` under the lock never leads to `ztl_dev_send()` in the same thread; the socket is bound to the underlay for this reason, line 326); one caller owns the right to start. No property of the model depends on `usable` any more.
- A Zephyr mutex can be locked again by its owner; the model forbids it. So the model proves that the adapter never needs that.
- Not modelled: the atomic variables (`running`, `usable`, counters): every `atomic_*` stub has an empty contract, so the model proves nothing from `usable` and nothing about it (for example that `ztl_dev_send()` does no work before the first configuration); the contents of buffers; lengths against buffer sizes except where the split of `tx_buf`, `rx_buf` and `frame_buf` needs them; the frame pointer of N-24 (`f->data` is passed to `net_pkt_write()` without a permission); "ztl_init() before any other call"; `ztl_leaf_ok`; interrupt context; thread priorities; time.
- Arithmetic on the timing counters is marked `truncating` (wrap-around is intended there). No other overflow check is switched off.
- VeriFast itself and its two provers are trusted. Target model: ILP32.

## Future work: verify the real file

Decision A-ztram-vf-9: verification of the real `zephyr/ztl_zephyr.c` with VeriFast is future work. What it needs:

1. A VeriFast-only view of the leaf's headers. Either a filter that turns each ACSL comment (`/*@ ... */` and `//@`) of `include/ztl/*.h` into a plain comment before VeriFast reads it, with the VeriFast contracts kept in a side file; or generated headers. The side file is `vf_stubs.h` with the real `struct ztl_leaf` (nested arrays of structures: more `open`/`close` work, and predicates for `node.peer[i]`).
2. VeriFast-only headers for the Zephyr API in use (the 35 functions of `vf_stubs.h` and macros: `K_MUTEX_DEFINE`, `K_THREAD_STACK_DEFINE`, `ETH_NET_DEVICE_INIT`, `BUILD_ASSERT`, `ARG_UNUSED`, `atomic_t`, `k_timeout_t`, the socket structures), selected with `-I` in place of Zephyr's own. Zephyr's real headers are far outside what VeriFast parses.
3. Small edits of `ztl_zephyr.c` that VeriFast's C subset needs (seen in this pilot): no call inside a larger expression where the order of evaluation matters, no assignment inside a loop condition, one declarator for each global declaration, no `= { 0 }` for a structure whose address is taken. And the annotations themselves (about 221 annotation lines in the model, contracts included), which Frama-C would also try to read: they need a marker that only one tool takes, or the adapter stays outside Frama-C's file list (it is today). Seen in VeriFast 26.10: a block that the preprocessor skips must not end with a `//@` line.
4. A level for each stack lock (`lockset` of `threading.h`) if freedom from deadlock is wanted, and contracts for the class L functions taken from Zephyr's source.
5. A model of the atomic variables (`usable`, `running`) with VeriFast's ghost critical sections, to turn the assumption of `start_right()` (one start) into a proof.

## Decisions (questions to GRey, with the answers taken)

- ✅ Q-ztram-vf-6 Stack calls under the lock at start-up (F-2): moved after the unlock in the adapter. The model follows; no start-up exception is left.
- ✅ Q-ztram-vf-7 Bound of `*peer` (F-3): the ACSL contract of `ztl_input()` is extended and proved with WP.
- ✅ Q-ztram-vf-8 Reads without the lock (F-1): kept as "fixed after start", annotated in the adapter.
- ✅ Q-ztram-vf-9 The real file: future work (section above).
- ✅ Q-ztram-vf-10 The pilot is a standard step of the proof runner: `proofs/vf/run.sh`, on a host that has `verifast`.
- ✅ Q-ztram-vf-11 `sock` written outside the lock (F-5): yes, the descriptor is stored in a second short locked section; the model proves it without an assumption.
