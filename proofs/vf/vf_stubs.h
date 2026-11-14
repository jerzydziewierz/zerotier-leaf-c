/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
/*
 * VeriFast specifications of the functions that the model of the Zephyr
 * adapter calls: the leaf (include/ztl/leaf.h) and Zephyr (kernel, sockets,
 * network interface, packets).
 *
 * These are STUBS. No function here has a body that VeriFast checks. Each
 * contract is an assumption about the real function. The proof of the model
 * is only as good as these contracts. README.md lists them by class.
 *
 * VeriFast and Frama-C read the same annotation comments, so VeriFast
 * cannot read the real headers of the leaf. This file replaces them for
 * the model. Types are reduced to what the lock discipline needs.
 */
#ifndef ZTL_VF_STUBS_H
#define ZTL_VF_STUBS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
/* ssize_t: VeriFast defines it. */


/* ---- Constants: same values as include/ztl/ and zephyr/ztl_zephyr.c ---- */
#define ZTL_PEERS    7
#define ZTL_PKT_MAX  2048
#define ZTL_UDP_MAX  1432
#define ZTL_FRAG_HDR 16
#define ZTL_MTU_MAX  1500
#define ZTL_ETH_ALEN 6
#define ZTL_IN_REPLY  0x01u
#define ZTL_IN_FRAME  0x02u
#define ZTL_IN_CONFIG 0x04u

/* ---- The leaf ---- */

/* Model of struct ztl_leaf: the fields that the adapter reads, and one
 * field that stands for all the others. */
struct ztl_leaf {
	uint8_t pinned[ZTL_PEERS]; /* real: node.peer[i].pinned */
	uint8_t seen[ZTL_PEERS];   /* real: ps[i].seen */
	uint32_t stats;            /* real: struct ztl_stats stats */
	uint16_t mtu;
	uint8_t have_config;
	uint8_t ctrl;
	uint8_t prefix;
	uint8_t ip[4];
	uint8_t mac[ZTL_ETH_ALEN];
	uint8_t other;             /* stands for every other field */
};

/* Model of struct ztl_frame, without dst and src (the adapter only copies them). */
struct ztl_frame {
	uint16_t ethertype;
	uint16_t len;
	const uint8_t *data;
};

/*@
// The part of the leaf that only ztl_init() and ztl_pin() write. ztl_input(),
// ztl_poll() and ztl_frame_to() never write it (their ACSL "assigns" clauses).
predicate ztl_leaf_pins(struct ztl_leaf *l;) = l->pinned[..ZTL_PEERS] |-> ?pins;

// The rest of the leaf: every call of the leaf can write it.
predicate ztl_leaf_core(struct ztl_leaf *l;) =
    l->seen[..ZTL_PEERS] |-> ?seen &*& l->stats |-> ?stats &*& l->mtu |-> ?mtu &*&
    l->have_config |-> ?have_config &*& l->ctrl |-> ?ctrl &*& l->prefix |-> ?prefix &*&
    l->ip[..4] |-> ?ip &*& l->mac[..ZTL_ETH_ALEN] |-> ?mac &*& l->other |-> ?other &*& struct_ztl_leaf_padding(l);

predicate ztl_frame(struct ztl_frame *f;) =
    f->ethertype |-> ?ethertype &*& f->len |-> ?len &*& f->data |-> ?data;
@*/

struct ztl_zephyr_config; /* read through the stubs below; its memory is not modelled */

/* Real: ztl_init(l, config->self, config->pub, config->nwid, first_id). */
void ztl_init(struct ztl_leaf *l, const struct ztl_zephyr_config *config, uint64_t first_packet_id);
	//@ requires ztl_leaf_core(l) &*& ztl_leaf_pins(l);
	//@ ensures ztl_leaf_core(l) &*& ztl_leaf_pins(l);

/* Real: ztl_pin(l, config->peers[k].addr, config->peers[k].key). */
int ztl_pin(struct ztl_leaf *l, const struct ztl_zephyr_config *config, unsigned int k);
	//@ requires ztl_leaf_core(l) &*& ztl_leaf_pins(l);
	//@ ensures ztl_leaf_core(l) &*& ztl_leaf_pins(l) &*& -1 <= result &*& result < ZTL_PEERS;

/* From the ACSL contract of ztl_input() in include/ztl/leaf.h: a reply
 * (*tx_len != 0) comes with *peer < ZTL_PEERS. The adapter uses *peer as an
 * index (send_packet). */
unsigned int ztl_input(struct ztl_leaf *l, uint8_t *dgram, size_t len, uint32_t now_ms, uint8_t *tx, size_t *tx_len,
		       unsigned int *peer, struct ztl_frame *frame);
	/*@ requires ztl_leaf_core(l) &*& [?f]ztl_leaf_pins(l) &*& dgram[..len] |-> ?d0 &*& tx[..ZTL_PKT_MAX] |-> ?t0 &*&
	             *tx_len |-> ?n0 &*& *peer |-> ?p0 &*& ztl_frame(frame); @*/
	/*@ ensures ztl_leaf_core(l) &*& [f]ztl_leaf_pins(l) &*& dgram[..len] |-> ?d1 &*& tx[..ZTL_PKT_MAX] |-> ?t1 &*&
	            *tx_len |-> ?n1 &*& n1 <= ZTL_PKT_MAX &*& *peer |-> ?p1 &*& (n1 == 0 || p1 < ZTL_PEERS) &*&
	            ztl_frame(frame); @*/

size_t ztl_poll(struct ztl_leaf *l, uint32_t now_ms, uint8_t *tx, unsigned int *peer);
	//@ requires ztl_leaf_core(l) &*& [?f]ztl_leaf_pins(l) &*& tx[..ZTL_PKT_MAX] |-> ?t0 &*& *peer |-> ?p0;
	/*@ ensures ztl_leaf_core(l) &*& [f]ztl_leaf_pins(l) &*& tx[..ZTL_PKT_MAX] |-> ?t1 &*& *peer |-> ?p1 &*&
	            result <= ZTL_UDP_MAX &*& (result == 0 || p1 < ZTL_PEERS); @*/

/* dst points to a local array of the caller: its memory is not modelled. */
size_t ztl_frame_to(struct ztl_leaf *l, unsigned int i, const uint8_t *dst, uint16_t ethertype, const uint8_t *data,
		    size_t len, uint8_t *tx);
	/*@ requires ztl_leaf_core(l) &*& [?f]ztl_leaf_pins(l) &*& [?g]integers_(data, 1, false, len, ?d) &*&
	             tx[..ZTL_PKT_MAX] |-> ?t0; @*/
	/*@ ensures ztl_leaf_core(l) &*& [f]ztl_leaf_pins(l) &*& [g]integers_(data, 1, false, len, d) &*& tx[..ZTL_PKT_MAX] |-> ?t1 &*&
	            result <= ZTL_PKT_MAX &*& (result == 0 || i < ZTL_PEERS); @*/

size_t ztl_tx_first(size_t len);
	//@ requires true;
	//@ ensures result == (len > ZTL_UDP_MAX ? ZTL_UDP_MAX : len);

size_t ztl_tx_second(uint8_t *pkt, size_t len, size_t *at);
	//@ requires pkt[..ZTL_PKT_MAX] |-> ?t0 &*& *at |-> ?a0;
	/*@ ensures pkt[..ZTL_PKT_MAX] |-> ?t1 &*& *at |-> ?a1 &*&
	            (ZTL_UDP_MAX < len && len <= ZTL_PKT_MAX ?
	                 a1 == ZTL_UDP_MAX - ZTL_FRAG_HDR && result == len - ZTL_UDP_MAX + ZTL_FRAG_HDR :
	                 a1 == a0 && result == 0); @*/

/* ---- Zephyr kernel ---- */

struct k_mutex {
	int opaque;
};

typedef int k_timeout_t; /* real: a structure */
#define K_NO_WAIT 0
#define K_FOREVER (-1)
#define K_MSEC(ms) (ms)

/*@
// A share of the mutex, with the lock invariant inv: the resource that the
// mutex guards. A thread gets inv() at lock and must give it back at unlock.
predicate k_mutex(struct k_mutex *m; predicate() inv);

// This thread holds the mutex.
predicate k_mutex_held(struct k_mutex *m, predicate() inv, int thread, real share);

// The token "this thread does NOT hold the mutex". It cannot be copied. Lock
// takes it, unlock gives it back. A function that must not run while the
// mutex is held requires it. The model has exactly one mutex.
predicate k_mutex_not_held(struct k_mutex *m, int thread);

predicate k_mutex_init_ghost_arg(predicate() inv) = true;
@*/

/* Stands for K_MUTEX_DEFINE. The caller gives the guarded resource away. */
void k_mutex_init(struct k_mutex *m);
	//@ requires k_mutex_init_ghost_arg(?inv) &*& m->opaque |-> _ &*& inv();
	//@ ensures k_mutex(m, inv) &*& k_mutex_not_held(m, currentThread);

/* Stricter than Zephyr: a Zephyr mutex can be locked again by its owner.
 * The model refuses that (the token is gone after the first lock). */
int k_mutex_lock(struct k_mutex *m, k_timeout_t timeout);
	//@ requires [?f]k_mutex(m, ?inv) &*& k_mutex_not_held(m, currentThread);
	/*@ ensures result == 0 ?
	                k_mutex_held(m, inv, currentThread, f) &*& inv() :
	                timeout != K_FOREVER &*& [f]k_mutex(m, inv) &*& k_mutex_not_held(m, currentThread); @*/

int k_mutex_unlock(struct k_mutex *m);
	//@ requires k_mutex_held(m, ?inv, currentThread, ?f) &*& inv();
	//@ ensures [f]k_mutex(m, inv) &*& k_mutex_not_held(m, currentThread);

uint32_t k_uptime_get_32(void);
	//@ requires true;
	//@ ensures true;
uint32_t k_cycle_get_32(void);
	//@ requires true;
	//@ ensures true;
void k_yield(void);
	//@ requires true;
	//@ ensures true;
int sys_csrand_get(uint64_t *dst);
	//@ requires *dst |-> _;
	//@ ensures *dst |-> ?v;

/* Atomic variables: used by every thread without the mutex. The kernel
 * makes each operation atomic. They are outside the ownership model. */
typedef int atomic_t;
int atomic_get(atomic_t *a);
	//@ requires true;
	//@ ensures true;
void atomic_inc(atomic_t *a);
	//@ requires true;
	//@ ensures true;
void atomic_set(atomic_t *a, int v);
	//@ requires true;
	//@ ensures true;
void atomic_clear(atomic_t *a);
	//@ requires true;
	//@ ensures true;
bool atomic_cas(atomic_t *a, int old_value, int new_value);
	//@ requires true;
	//@ ensures true;

/* A thread function gets its resources (thread_data) and starts without the
 * mutex of the adapter. It must not end with the mutex held. */
//@ predicate_family thread_data(void *entry)(struct k_mutex *m);
typedef void k_thread_entry_t(struct k_mutex *m);
	//@ requires thread_data(this)(m) &*& k_mutex_not_held(m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);

/* Real: k_thread_create(&thread, stack, size, entry, NULL, NULL, NULL, prio, 0, K_NO_WAIT).
 * The argument m is not in the real call: it names the mutex of the token. */
void k_thread_create(k_thread_entry_t *entry, struct k_mutex *m);
	//@ requires is_k_thread_entry_t(entry) == true &*& thread_data(entry)(m);
	//@ ensures true;

/* ---- Zephyr network stack ---- */

struct net_if;
struct net_pkt;
//@ predicate net_pkt(struct net_pkt *pkt); // one reference to a packet

#define NET_AF_INET 1
#define ZSOCK_MSG_DONTWAIT 0x40

/* Model of struct net_sockaddr_in (flat). */
struct net_sockaddr_in {
	uint16_t sin_family;
	uint16_t sin_port;
	uint32_t sin_addr;
};

/*
 * Class U ("upcall"): functions that take locks of the network stack or
 * that wait. Each requires the token: the caller does not hold the mutex.
 */
int zsock_poll(int fd, int timeout_ms); /* real: (struct zsock_pollfd *, 1, timeout) */
	//@ requires k_mutex_not_held(?m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);

/* Takes the reference when the result is not negative. */
int net_recv_data(struct net_if *iface, struct net_pkt *pkt);
	//@ requires net_pkt(pkt) &*& k_mutex_not_held(?m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread) &*& (result < 0 ? net_pkt(pkt) : true);

void net_if_carrier_off(struct net_if *iface);
	//@ requires k_mutex_not_held(?m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);
void net_if_carrier_on(struct net_if *iface);
	//@ requires k_mutex_not_held(?m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);
int net_if_up(struct net_if *iface);
	//@ requires k_mutex_not_held(?m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);
bool net_if_ipv4_addr_rm(struct net_if *iface, uint32_t addr);
	//@ requires k_mutex_not_held(?m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);
void *net_if_ipv4_addr_add(struct net_if *iface, uint32_t addr);
	//@ requires k_mutex_not_held(?m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);
bool net_if_ipv4_set_netmask_by_addr(struct net_if *iface, uint32_t addr, uint32_t mask);
	//@ requires k_mutex_not_held(?m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);
uint16_t net_if_get_mtu(struct net_if *iface);
	//@ requires k_mutex_not_held(?m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);
void net_if_set_mtu(struct net_if *iface, uint16_t mtu);
	//@ requires k_mutex_not_held(?m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);

/* Called by ztl_zephyr_start() after it has released the mutex. Class U. */
/* Real: socket, net_if_get_name, setsockopt(SO_BINDTODEVICE), bind; close on error. */
int zsock_socket_udp(void);
	//@ requires k_mutex_not_held(?m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);
int zsock_bind_to(int fd, struct net_if *iface, uint16_t port);
	//@ requires k_mutex_not_held(?m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);
int zsock_close(int fd);
	//@ requires k_mutex_not_held(?m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);
int net_if_set_link_addr(struct net_if *iface, uint8_t *addr, uint8_t len);
	//@ requires k_mutex_not_held(?m, currentThread) &*& [?f]integers_(addr, 1, false, len, ?a);
	//@ ensures k_mutex_not_held(m, currentThread) &*& [f]integers_(addr, 1, false, len, a);

/*
 * Class L ("under the lock"): THE ONE ACCEPTED EXCEPTION to "no call into the
 * network stack with the mutex held". These are the calls that the adapter
 * makes while it holds the mutex: zsock_sendto() and net_pkt_*(). No token is
 * required: the model ACCEPTS them under the lock, it does not prove that
 * they are safe there. The
 * assumption is that none of them waits for the mutex of the adapter or
 * calls ztl_dev_send() in the same thread.
 * With VF_STRICT_SEND, zsock_sendto() is class U, and the model must then fail.
 */
#ifdef VF_STRICT_SEND
#define ZTL_VF_SEND_CALL k_mutex_not_held(?m_, currentThread)
#define ZTL_VF_SEND_BACK k_mutex_not_held(m_, currentThread)
#else
#define ZTL_VF_SEND_CALL true
#define ZTL_VF_SEND_BACK true
#endif

/* Real: the destination is a pointer to endpoint[i]; here its two fields by value. */
ssize_t zsock_sendto(int fd, const uint8_t *buf, size_t len, int flags, uint32_t to_addr, uint16_t to_port);
	//@ requires ZTL_VF_SEND_CALL &*& [?f]integers_(buf, 1, false, len, ?b);
	//@ ensures ZTL_VF_SEND_BACK &*& [f]integers_(buf, 1, false, len, b);

ssize_t zsock_recvfrom(int fd, uint8_t *buf, size_t len, int flags, struct net_sockaddr_in *from);
	/*@ requires buf[..len] |-> ?b0 &*& from->sin_family |-> _ &*& from->sin_port |-> _ &*&
	             from->sin_addr |-> _; @*/
	/*@ ensures buf[..len] |-> ?b1 &*& from->sin_family |-> ?fam &*& from->sin_port |-> ?port &*&
	            from->sin_addr |-> ?addr &*& -1 <= result &*& result <= len; @*/

/* The data pointer and length are not modelled (see README.md, limits). */
struct net_pkt *net_pkt_rx_alloc_with_buffer(struct net_if *iface, size_t size, k_timeout_t timeout);
	//@ requires true;
	//@ ensures result == 0 ? true : net_pkt(result);
int net_pkt_write(struct net_pkt *pkt, const void *data, size_t len);
	//@ requires net_pkt(pkt);
	//@ ensures net_pkt(pkt);
void net_pkt_unref(struct net_pkt *pkt);
	//@ requires net_pkt(pkt);
	//@ ensures true;
size_t net_pkt_get_len(struct net_pkt *pkt);
	//@ requires [?f]net_pkt(pkt);
	//@ ensures [f]net_pkt(pkt);
void net_pkt_cursor_init(struct net_pkt *pkt);
	//@ requires net_pkt(pkt);
	//@ ensures net_pkt(pkt);
int net_pkt_read(struct net_pkt *pkt, uint8_t *buf, size_t len);
	//@ requires net_pkt(pkt) &*& integers__(buf, 1, false, len, _); // the buffer need not hold values yet
	//@ ensures net_pkt(pkt) &*& buf[..len] |-> ?b1;

/* ---- Pure helpers of the model (no shared state) ---- */

/* Real: sys_get_be16(&hdr[12]) on a local array. */
uint16_t model_ethertype(const uint8_t *hdr);
	//@ requires true;
	//@ ensures true;
/* Real: memcpy(&cfg.ip.s_addr, leaf.ip, 4). */
uint32_t model_load_ip(const uint8_t *ip);
	//@ requires [?f]integers_(ip, 1, false, 4, ?v);
	//@ ensures [f]integers_(ip, 1, false, 4, v);
/* Real: net_htonl(UINT32_MAX << (32u - prefix)). */
uint32_t model_mask(uint8_t prefix);
	//@ requires true;
	//@ ensures true;
/* Real: memcpy(overlay_mac, leaf.mac, ZTL_ETH_ALEN). */
void model_copy_mac(uint8_t *to, const uint8_t *from);
	//@ requires to[..ZTL_ETH_ALEN] |-> ?t0 &*& [?f]integers_(from, 1, false, ZTL_ETH_ALEN, ?v);
	//@ ensures to[..ZTL_ETH_ALEN] |-> v &*& [f]integers_(from, 1, false, ZTL_ETH_ALEN, v);
/* Real: config == NULL || ... || config->port == 0u (line 342), and the fields of *config. */
bool model_config_ok(const struct ztl_zephyr_config *config);
	//@ requires true;
	//@ ensures true;
unsigned int model_config_peer_count(const struct ztl_zephyr_config *config);
	//@ requires true;
	//@ ensures true;
uint16_t model_config_port(const struct ztl_zephyr_config *config);
	//@ requires true;
	//@ ensures true;
uint16_t model_config_peer_port(const struct ztl_zephyr_config *config, unsigned int k);
	//@ requires true;
	//@ ensures true;
uint32_t model_config_ipv4(const struct ztl_zephyr_config *config, unsigned int k);
	//@ requires true;
	//@ ensures true;

#endif
