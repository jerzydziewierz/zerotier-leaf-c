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
* it has no protection against replayed packets yet; 
* the network's MTU must be 1280 to 1500 (set it on the controller: the stock default is 2800).


## What IS proven

* (to be written)


[More details](README-MORE.md)


Licence: Apache-2.0.
