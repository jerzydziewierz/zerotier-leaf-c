# Formally proven ZeroTier client for microcontrollers and embedded

| Note: may rename this project once it is more complete. Ideas for a good name welcome. FormalTier?

An implementation of a ZeroTier protocol v1 client ("leaf" node) in ISO C11 for small microcontrollers, 

Implemented from wire protocol with verifiable primitives, 

So that its stated properties can be machine-checked and proven in a theorem prover.

Every function that touches network input has a written contract, and tools (Frama-C WP, CBMC, Frama-C Eva, Wolfram Mathematica) check the code against it.

⏭ Work in progress. Currently It runs on a Teensy 4.1 under Zephyr as a member of a private network with a stock controller and stock 1.16.2 peers (ping, Telnet and SSH over the overlay); As of 2026-11-14, the proofs are incomplete, but there seem to be no obstacles to complete the proofs. see [checklist](CHECKLIST.md)

# Why

My concept is that instead of fixing and patching old software, and working through theories and models of C, which are often undecideable, 

We should re-implement it in such a way that they can be checked, and reasoned about.

In the same way in which AI revolution was enabled by reimplementation of restricted (differentiable) function set over real numbers,

We have a restricted set over integers that can be used to implement, maybe not every functionality thinkable, but enough of it to be useful in practice and hold the properties that make it provably correct.


## Design in one paragraph

Since I am just one researcher working out of my private funds in spare time,
the design is purposfully limited to be tractible.

The design constraints below make it a "restricted zerotier leaf node" in other words, a node that is fully compatible with zerotier network, but has limited capabilities.

Headline limits:
* one zerotier network only
* at most 7 pinned peers, 
* packets of at most 2048 bytes in at most two parts, 
* cipher suite Salsa20/12 + Poly1305 only (the node announces protocol version 11, so peers do not use AES with it). 
* It is assigned to its network at provisioning time, in a secure environment, with one pairwise key per peer; no public-key cryptography runs on the device. 
* No `malloc`, no C library calls, no recursion; RAM is the sum of static objects. 

It follows that:
* The core does no input or output and keeps no clock: 
  * an adapter gives it each received datagram (`ztl_input()`), 
  * asks it regularly for the packets that are due (`ztl_poll()`), 
  * and gives it each frame that the host sends (`ztl_frame_to()`).

Limits by design: 
* it does not evaluate the network's flow rules 
  * (it admits pinned peers and tells the controller that it has no rules engine); 
* it takes a network configuration only directly from the pinned controller, without checking the controller's signature, and only when the configuration fits one chunk; 
* it does not relay, bridge or discover peers; 
* it has no protection against replayed packets (a stated limit, as in the reference; possible mitigations: [NOT_PROVEN.md](reports/NOT_PROVEN.md), N-7); 
* the network's MTU must be 1280 to 1500 (set it on the controller: the stock default is 2800).


## What IS proven

Proved by machine for every input, not shown by tests: Frama-C WP with three automatic provers checks each function of the leaf against a written contract, at the full packet size of 2,048 bytes, in a 64-bit and a 32-bit data model (3,971 and 3,976 proof goals, all proved). CBMC checks the datagram classifier a second time, with a different method. The complete list, statement by statement: [List of proofs](reports/PROOFS.md#list-of-proofs).

* **For every function of the leaf** (all nine source files): 
  * no run-time error; 
  * no read and no write outside the memory that its contract names; 
  * no sum, product or conversion that wraps or loses bits; 
  * every loop ends, so every call returns; 
  * the result meets the contract, so the caller needs no further check. ([L-1 to L-6](reports/PROOFS.md#list-of-proofs))
* **Datagram classifier**: head, fragment or drop by the exact written rule, in both directions; the rule equals a model of the reference receive path for every datagram of 0 to 2,049 bytes. ([details](reports/PROOFS.md#attempts-on-the-classifier))
* **Reassembly**: both arrival orders give the head bytes, then the fragment bytes; nothing above 2,048 bytes; the whole rule for waiting packets, with a clock that wraps. ([details](reports/PROOFS.md#attempts-on-reassembly))
* **Authentication before effects, receive gate**: a packet passes only after exactly one call of the authentication function that answered yes, with the key of a pinned peer whose address is the packet's source. ([details](reports/PROOFS.md#attempts-on-the-receive-gate))
* **Authentication before effects, whole leaf**: no reply packet and no frame for the host comes out of `ztl_input()` without that yes; after the start no call writes the own address, the pinned peers or their keys. ([details](reports/PROOFS.md#attempts-on-the-protocol-layer))
* **One packet ID for each packet**: the ID is the nonce of the encryption; every call that builds a packet moves the counter by exactly one. 
* **Bounds on everything that leaves the leaf**: a frame for the host has 1 to 1,500 bytes and is readable; a packet has 28 to 2,048 bytes; a frame from the host goes out only to a pinned peer that was heard. 
* **Cryptography**: the Poly1305 limbs stay inside their limits for a message of any length up to the packet size; each Poly1305 step is proved as a statement about numbers; a refused packet is left unchanged. ([details](reports/PROOFS.md#attempts-on-the-cryptography))
* **LZ4 decoder and configuration reader**: no access outside their buffers for any input up to the packet size, however malformed. 

The proofs notice wrong code: 102 deliberate errors were put into the sources, one at a time, and each was rejected by the tool that should see it.

Approximate cost of running the proofs: one full default run (`proofs/on-remote.sh start`, which runs `proofs/run.sh`) takes about 32 minutes on a 32-core Linux host, with a memory peak of 5 GB; nearly all of it is WP in the two data models and the smoke step. The whole list of deliberate errors (`mutate`) takes about 2 hours more.

## NOT proven, but still tested

Shown only by tests against the reference implementation: 
* what the messages mean and when the timers fire; 
* that a "yes" of the authentication means a right MAC (the cipher and the MAC give the reference's bytes on test vectors). 

Shown only by reading the compiled code: 
* constant time of the MAC comparison. 

Not there at all: 
* protection against replayed packets. 

"Proved" means that the code meets its written contract in the tools' model of C; the contracts are written by hand, and the compiler is trusted. 

All limits, and the attempts that failed: [What all of this does not show](reports/PROOFS.md#what-all-of-this-does-not-show).


[More details](README-MORE.md)


Licence: none granted. This is private intellectual property, published for reading only: all rights reserved, reproduction prohibited. See [LICENSE](LICENSE).
