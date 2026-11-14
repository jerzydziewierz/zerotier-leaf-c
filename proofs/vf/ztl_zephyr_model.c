/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
/*
 * MODEL of the lock discipline of zephyr/ztl_zephyr.c, for VeriFast.
 *
 * This file is NOT the adapter. It is a copy of the adapter's structure,
 * made by hand: the same functions, the same order of lock and unlock, the
 * same calls into the leaf and into the network stack, in the same order.
 * Each function names the lines of zephyr/ztl_zephyr.c that it follows.
 * Data that does not bear on the lock is reduced (see "MODEL:" comments
 * and README.md). A proof of this file is a proof about this file.
 *
 * Proved here (given the contracts in vf_stubs.h):
 *   P1  The leaf, tx_buf, frame_buf and the timing counters are used only
 *       by a thread that holds the mutex. rx_buf is used only by the worker.
 *   P2  No function of class U (vf_stubs.h) is called with the mutex held.
 *       Class L (zsock_sendto(), net_pkt_*()) is the one accepted exception.
 *   P3  Every path gives the mutex back.
 *
 * Variants with one deliberate error each (run.sh; each must fail):
 *   VF_BAD_NO_LOCK       ztl_dev_send() calls ztl_frame_to() without the lock
 *   VF_BAD_STACK_LOCKED  worker() calls net_recv_data() before the unlock
 *   VF_BAD_EARLY_RETURN  ztl_dev_send() returns with the lock held
 *   VF_BAD_LOOP_KEEPS    worker() starts the next turn of its loop with the lock held
 *   VF_BAD_RX_BUF        ztl_dev_send() writes rx_buf (worker only)
 *   VF_BAD_START_LOCKED  ztl_zephyr_start() calls socket_open() before the unlock
 *   VF_BAD_SOCK_UNLOCKED ztl_zephyr_start() stores the descriptor in "sock" without the lock
 *   VF_BAD_WRITE_ENDPOINT  worker() writes endpoint[] after the start
 *   VF_BAD_WRITE_PINNED  ztl_dev_send() writes the pinned table, with the lock held
 * A variant that keeps the real code and makes the rule stricter (must fail):
 *   VF_STRICT_SEND       the accepted exception: zsock_sendto() under the lock
 */
#include "vf_stubs.h"

#define ETH_HDR      14
#define ETH_IPV4     0x0800
#define ETH_ARP      0x0806
#define UDP_RX_MAX   1472
#define RX_BUF_LEN   1473 /* UDP_RX_MAX + 1 */
#define CONFIG_ZTL_RX_BATCH 8
#define ENETDOWN  115
#define EMSGSIZE  122
#define EBUSY     16
#define EINVAL    22
#define EALREADY  120
#define EIO       5

/* Lines 32 to 50. MODEL: endpoint[] is two flat arrays. */
static struct k_mutex lock;
static struct ztl_leaf leaf;
static uint8_t tx_buf[ZTL_PKT_MAX];    /* guarded by lock */
static uint8_t frame_buf[ZTL_MTU_MAX]; /* guarded by lock */
static uint8_t rx_buf[RX_BUF_LEN];     /* leaf thread only */
static uint32_t endpoint_addr[ZTL_PEERS]; /* by peer index; fixed after start */
static uint16_t endpoint_port[ZTL_PEERS];
static struct net_if *overlay;
static struct net_if *underlay_if;
static int sock;
static uint16_t local_port;
/* MODEL: one declaration for each variable (VeriFast's parser). */
static atomic_t running;
static atomic_t usable;
static atomic_t wire_tx;
static atomic_t wire_rx;
static atomic_t rx_filtered;
static atomic_t tx_dropped;
static atomic_t rx_dropped;
static uint32_t have_ip;     /* leaf thread only */
static uint8_t have_prefix;  /* leaf thread only */
static uint64_t in_cycles; /* guarded by lock, as the five that follow */
static uint64_t out_cycles;
static uint32_t in_calls;
static uint32_t out_calls;
static uint32_t in_max;
static uint32_t out_max;
static uint8_t overlay_mac[ZTL_ETH_ALEN]; /* copy of leaf.mac; fixed after start */

/*@
// State that is written only before the worker exists (ztl_zephyr_start(),
// with the lock AND the right to start) and only read afterwards. It is
// cut in two halves. One half is in the lock invariant. The other half
// goes from the caller of ztl_zephyr_start() to the worker. A half allows
// reads only; a write needs both halves. So the worker can read this state
// without the lock (from_endpoint(), lines 162 and 163), and nothing can
// write it once the worker has its half: after the start every thread has
// only a read share.
predicate adapter_fixed() =
    ztl_leaf_pins(&leaf) &*& endpoint_addr[..ZTL_PEERS] |-> ?addrs &*& endpoint_port[..ZTL_PEERS] |-> ?ports &*&
    sock |-> ?s &*& overlay |-> ?o &*& underlay_if |-> ?u &*& local_port |-> ?lp &*&
    overlay_mac[..ZTL_ETH_ALEN] |-> ?mac;

// The lock invariant: what the mutex guards. Only k_mutex_lock() gives it.
predicate leaf_inv() =
    ztl_leaf_core(&leaf) &*& [1/2]adapter_fixed() &*&
    tx_buf[..ZTL_PKT_MAX] |-> ?tx &*& frame_buf[..ZTL_MTU_MAX] |-> ?fr &*&
    in_cycles |-> ?ic &*& out_cycles |-> ?oc &*& in_calls |-> ?inc &*& out_calls |-> ?outc &*&
    in_max |-> ?im &*& out_max |-> ?om;

// What the worker thread alone owns.
predicate worker_only() =
    rx_buf[..RX_BUF_LEN] |-> ?rx &*& have_ip |-> ?ip &*& have_prefix |-> ?prefix;

// The right to start the adapter. MODEL: in the real code the atomic
// variable "running" decides who may start (line 346); here the caller
// must own this right. It holds everything that the worker will need.
predicate worker_lock() = [1/4]k_mutex(&lock, leaf_inv); // packed, so that it does not merge with the caller's share
predicate start_right() = worker_lock() &*& [1/2]adapter_fixed() &*& worker_only();

predicate_family_instance thread_data(worker)(struct k_mutex *m) =
    m == &lock &*& start_right();
@*/

/* Lines 56 to 72. "Lock held": the contract asks for tx_buf, and only the lock gives it. */
static void send_packet(unsigned int i, size_t len)
	/*@ requires [?f]adapter_fixed() &*& tx_buf[..ZTL_PKT_MAX] |-> ?t0 &*& len <= ZTL_PKT_MAX &*&
	             (len == 0 || i < ZTL_PEERS)
#ifdef VF_STRICT_SEND
	             &*& k_mutex_not_held(&lock, currentThread)
#endif
	    ; @*/
	/*@ ensures [f]adapter_fixed() &*& tx_buf[..ZTL_PKT_MAX] |-> ?t1
#ifdef VF_STRICT_SEND
	             &*& k_mutex_not_held(&lock, currentThread)
#endif
	    ; @*/
{
	size_t at = 0;
	size_t n = ztl_tx_first(len);

	for (int part = 0; part < 2 && n != 0u; part++)
		/*@ invariant [f]adapter_fixed() &*& tx_buf[..ZTL_PKT_MAX] |-> ?t &*& at |-> ?a &*& 0 <= part &*&
		              a + n <= ZTL_PKT_MAX &*& (n == 0 || i < ZTL_PEERS)
#ifdef VF_STRICT_SEND
		              &*& k_mutex_not_held(&lock, currentThread)
#endif
		    ; @*/
	{
		//@ open [f]adapter_fixed();
		//@ integers__split(tx_buf, a);
		//@ integers__split(tx_buf + a, n);
		const ssize_t sent = zsock_sendto(sock, &tx_buf[at], n, ZSOCK_MSG_DONTWAIT, endpoint_addr[i],
						  endpoint_port[i]);
		//@ integers__join(tx_buf + a);
		//@ integers__join(tx_buf);
		//@ close [f]adapter_fixed();

		if (sent == (ssize_t)n) {
			atomic_inc(&wire_tx);
		} else {
			atomic_inc(&tx_dropped);
		}
		if (part == 0) {
			n = ztl_tx_second(tx_buf, len, &at);
		} else {
			n = 0u;
		}
	}
}

/* Lines 75 to 83. */
static void overlay_down(void)
	//@ requires [?f]adapter_fixed() &*& worker_only() &*& k_mutex_not_held(&lock, currentThread);
	//@ ensures [f]adapter_fixed() &*& worker_only() &*& k_mutex_not_held(&lock, currentThread);
{
	//@ open [f]adapter_fixed();
	//@ open worker_only();
	atomic_clear(&usable);
	net_if_carrier_off(overlay);
	if (have_ip != 0u) {
		net_if_ipv4_addr_rm(overlay, have_ip);
		have_ip = 0;
	}
	//@ close worker_only();
	//@ close [f]adapter_fixed();
}

/* Lines 86 to 90. MODEL: ip is one integer. */
struct overlay_config {
	uint32_t ip;
	uint16_t mtu;
	uint8_t prefix;
};

/* Lines 94 to 119. Leaf thread, WITHOUT the lock: the contract asks for the token. */
static void apply_config(const struct overlay_config *c)
	/*@ requires [?g]c->ip |-> ?cip &*& [g]c->mtu |-> ?cmtu &*& [g]c->prefix |-> ?cprefix &*&
	             [?f]adapter_fixed() &*& worker_only() &*& k_mutex_not_held(&lock, currentThread); @*/
	/*@ ensures [g]c->ip |-> cip &*& [g]c->mtu |-> cmtu &*& [g]c->prefix |-> cprefix &*&
	            [f]adapter_fixed() &*& worker_only() &*& k_mutex_not_held(&lock, currentThread); @*/
{
	const uint32_t ip = c->ip;
	uint32_t mask;

	if (c->prefix == 0u) {
		overlay_down();
		return;
	}
	//@ open [f]adapter_fixed();
	//@ open worker_only();
	if (atomic_get(&usable) != 0 && ip == have_ip && c->prefix == have_prefix) {
		const uint16_t mtu_now = net_if_get_mtu(overlay);

		if (mtu_now == c->mtu) {
			//@ close worker_only();
			//@ close [f]adapter_fixed();
			return;
		}
	}
	//@ close worker_only();
	//@ close [f]adapter_fixed();
	overlay_down();
	//@ open [f]adapter_fixed();
	//@ open worker_only();
	net_if_set_mtu(overlay, c->mtu);
	if (net_if_ipv4_addr_add(overlay, ip) == NULL) {
		//@ close worker_only();
		//@ close [f]adapter_fixed();
		return;
	}
	have_ip = ip;
	have_prefix = c->prefix;
	mask = model_mask(c->prefix);
	net_if_ipv4_set_netmask_by_addr(overlay, ip, mask);
	net_if_carrier_on(overlay);
	net_if_up(overlay);
	atomic_set(&usable, 1);
	//@ close worker_only();
	//@ close [f]adapter_fixed();
}

/* Lines 124 to 147. MODEL: the 14-byte header (lines 138 to 140) is left out. */
static struct net_pkt *frame_to_pkt(const struct ztl_frame *f)
	//@ requires [?g]ztl_frame(f) &*& [?h]adapter_fixed();
	//@ ensures [g]ztl_frame(f) &*& [h]adapter_fixed() &*& (result == 0 ? true : net_pkt(result));
{
	struct net_pkt *pkt;

	//@ open [g]ztl_frame(f);
	//@ open [h]adapter_fixed();
	if (atomic_get(&usable) == 0 || (f->ethertype != ETH_IPV4 && f->ethertype != ETH_ARP)) {
		atomic_inc(&rx_dropped);
		//@ close [h]adapter_fixed();
		return NULL;
	}
	pkt = net_pkt_rx_alloc_with_buffer(overlay, (size_t)ETH_HDR + f->len, K_NO_WAIT);
	//@ close [h]adapter_fixed();
	if (pkt == NULL) {
		atomic_inc(&rx_dropped);
		return NULL;
	}
	if (net_pkt_write(pkt, f->data, f->len) != 0) {
		net_pkt_unref(pkt);
		atomic_inc(&rx_dropped);
		return NULL;
	}
	return pkt;
}

/* Lines 159 to 168. Called by the worker WITHOUT the lock: a half of adapter_fixed() is enough to read. */
static bool from_endpoint(const struct net_sockaddr_in *from)
	//@ requires [?g]from->sin_addr |-> ?addr &*& [g]from->sin_port |-> ?port &*& [?f]adapter_fixed();
	//@ ensures [g]from->sin_addr |-> addr &*& [g]from->sin_port |-> port &*& [f]adapter_fixed();
{
	for (unsigned int i = 0; i < ZTL_PEERS; i++)
		//@ invariant [g]from->sin_addr |-> addr &*& [g]from->sin_port |-> port &*& [f]adapter_fixed();
	{
		//@ open [f]adapter_fixed();
		//@ open [f]ztl_leaf_pins(&leaf);
		const bool same = leaf.pinned[i] != 0 && from->sin_addr == endpoint_addr[i] &&
				  from->sin_port == endpoint_port[i];
		//@ close [f]ztl_leaf_pins(&leaf);
		//@ close [f]adapter_fixed();
		if (same) {
			return true;
		}
	}
	return false;
}

/* Lines 170 to 240. MODEL: the parameter m (real: three unused pointers). */
static void worker(struct k_mutex *m) //@ : k_thread_entry_t
	//@ requires thread_data(worker)(m) &*& k_mutex_not_held(m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);
{
	//@ open thread_data(worker)(m);
	//@ open start_right();
	//@ open worker_lock();
	for (;;)
		/*@ invariant [1/4]k_mutex(&lock, leaf_inv) &*& k_mutex_not_held(&lock, currentThread) &*&
		              [1/2]adapter_fixed() &*& worker_only(); @*/
	{
		unsigned int peer = 0;
		size_t n;
		int fd;

		k_mutex_lock(&lock, K_FOREVER); /* line 180 */
		//@ open leaf_inv();
		/* MODEL: "while ((n = ztl_poll(...)) != 0u)" is written as a loop with a break. */
		for (;;)
			/*@ invariant ztl_leaf_core(&leaf) &*& [1/2]adapter_fixed() &*& tx_buf[..ZTL_PKT_MAX] |-> ?tx &*&
			              peer |-> ?p; @*/
		{
			//@ open [1/2]adapter_fixed();
			const uint32_t now = k_uptime_get_32();
			n = ztl_poll(&leaf, now, tx_buf, &peer); /* line 181 */
			//@ close [1/2]adapter_fixed();
			if (n == 0u) {
				break;
			}
			send_packet(peer, n);
		}
		//@ close leaf_inv();
		k_mutex_unlock(&lock); /* line 184 */
		//@ open [1/2]adapter_fixed();
		fd = sock; /* line 176: read without the lock, "fixed after start" */
		//@ close [1/2]adapter_fixed();
		const int ready = zsock_poll(fd, 100); /* line 185 */
		if (ready <= 0) {
			continue;
		}
		for (int k = 0; k < CONFIG_ZTL_RX_BATCH; k++)
			/*@ invariant [1/4]k_mutex(&lock, leaf_inv) &*& k_mutex_not_held(&lock, currentThread) &*&
			              [1/2]adapter_fixed() &*& worker_only() &*& peer |-> ?p; @*/
		{
			struct net_sockaddr_in from;
			struct ztl_frame frame;
			size_t tx_len = 0;
			struct overlay_config cfg;
			struct net_pkt *up = NULL;
			unsigned int r;
			ssize_t got;
			bool known;

#ifdef VF_BAD_WRITE_ENDPOINT
			/* Deliberate error: a write of "fixed after start" state after the start.
			 * (No ghost "close" follows: VeriFast must stop at the write.) */
			//@ open [1/2]adapter_fixed();
			endpoint_port[0] = 0;
#endif
			//@ open worker_only();
			got = zsock_recvfrom(fd, rx_buf, RX_BUF_LEN, ZSOCK_MSG_DONTWAIT, &from); /* line 193 */
			if (got < 0) {
				//@ close worker_only();
				break;
			}
			known = from_endpoint(&from);
			if (got == 0 || (size_t)got > UDP_RX_MAX || from.sin_family != NET_AF_INET || !known) {
				atomic_inc(&rx_filtered);
				//@ close worker_only();
				continue;
			}
			atomic_inc(&wire_rx);
			cfg.ip = 0;
			cfg.mtu = 0;
			cfg.prefix = 0;
			frame.ethertype = 0; /* MODEL: VeriFast wants the frame initialised before its address is used */
			frame.len = 0;
			frame.data = NULL;
			//@ close ztl_frame(&frame);

			k_mutex_lock(&lock, K_FOREVER); /* line 207 */
			//@ open leaf_inv();
			const uint32_t t0 = k_cycle_get_32();
			//@ open [1/2]adapter_fixed();
			//@ integers__split(rx_buf, got);
			const uint32_t now = k_uptime_get_32();
			r = ztl_input(&leaf, rx_buf, (size_t)got, now, tx_buf, &tx_len, &peer, &frame); /* line 209 */
			//@ integers__join(rx_buf);
			//@ close [1/2]adapter_fixed();
			const uint32_t t1 = k_cycle_get_32();
			const uint32_t dt = /*@truncating@*/ (t1 - t0);

#ifdef VF_BAD_LOOP_KEEPS
			/* Deliberate error: the next turn of the loop starts with the lock held. */
			if (r == 0u) {
				//@ close leaf_inv();
				//@ close worker_only();
				continue;
			}
#endif
			in_cycles = /*@truncating@*/ (in_cycles + dt);
			in_calls = /*@truncating@*/ (in_calls + 1);
			in_max = (in_max > dt) ? in_max : dt;
			if ((r & ZTL_IN_REPLY) != 0u) {
				send_packet(peer, tx_len); /* line 216 */
			}
			//@ open ztl_leaf_core(&leaf);
			if ((r & ZTL_IN_CONFIG) != 0u && leaf.have_config != 0u && leaf.prefix != 0u) {
				cfg.ip = model_load_ip(leaf.ip);
				cfg.mtu = leaf.mtu;
				cfg.prefix = leaf.prefix;
			}
			//@ close ztl_leaf_core(&leaf);
			if ((r & ZTL_IN_FRAME) != 0u) {
				up = frame_to_pkt(&frame); /* line 224 */
			}
#ifdef VF_BAD_STACK_LOCKED
			/* Deliberate error: a class U call before the unlock. */
			if (up != NULL) {
				//@ open [1/2]adapter_fixed();
				const int bad = net_recv_data(overlay, up);
				if (bad < 0) {
					net_pkt_unref(up);
				}
				//@ close [1/2]adapter_fixed();
				up = NULL;
			}
#endif
			//@ close leaf_inv();
			k_mutex_unlock(&lock); /* line 226 */
			//@ close worker_only();
			if ((r & ZTL_IN_CONFIG) != 0u) {
				apply_config(&cfg); /* line 230 */
			}
			if (up != NULL) {
				//@ open [1/2]adapter_fixed();
				const int rc = net_recv_data(overlay, up); /* line 232 */
				if (rc < 0) {
					net_pkt_unref(up);
					atomic_inc(&rx_dropped);
				}
				//@ close [1/2]adapter_fixed();
			}
			//@ open ztl_frame(&frame);
		}
		k_yield(); /* line 238 */
	}
}

/* Lines 243 to 282. Called by a thread of the network stack. ASSUMED: that
 * thread does not hold the mutex of the adapter (the token in the contract).
 * MODEL: no "dev" parameter; the result tells the stack nothing about pkt. */
static int ztl_dev_send(struct net_pkt *pkt)
	//@ requires net_pkt(pkt) &*& [?q]k_mutex(&lock, leaf_inv) &*& k_mutex_not_held(&lock, currentThread);
	//@ ensures net_pkt(pkt) &*& [q]k_mutex(&lock, leaf_inv) &*& k_mutex_not_held(&lock, currentThread);
{
	uint8_t hdr[ETH_HDR];
	const size_t n = net_pkt_get_len(pkt);

	if (atomic_get(&usable) == 0) { /* line 249 */
		return -ENETDOWN;
	}
	if (n <= (size_t)ETH_HDR || n > (size_t)(ETH_HDR + ZTL_MTU_MAX)) {
		return -EMSGSIZE;
	}
#ifdef VF_BAD_NO_LOCK
	/* Deliberate error: a call of the leaf without the lock. */
	ztl_frame_to(&leaf, 0, hdr, ETH_IPV4, frame_buf, n - ETH_HDR, tx_buf);
#endif
#ifdef VF_BAD_RX_BUF
	/* Deliberate error: this thread writes the buffer of the worker. */
	net_pkt_read(pkt, rx_buf, 1);
#endif
	if (k_mutex_lock(&lock, K_MSEC(200)) != 0) { /* line 255 */
		atomic_inc(&tx_dropped);
		return -EBUSY;
	}
	//@ open leaf_inv();
#ifdef VF_BAD_WRITE_PINNED
	/* Deliberate error: a write of the pinned table after the start. The lock is held.
	 * (No ghost "close" follows: VeriFast must stop at the write.) */
	//@ open [1/2]adapter_fixed();
	//@ open [1/2]ztl_leaf_pins(&leaf);
	leaf.pinned[0] = 0;
#endif
	net_pkt_cursor_init(pkt);
	if (net_pkt_read(pkt, hdr, ETH_HDR) == 0) {
		//@ integers__split(frame_buf, n - ETH_HDR);
		const int rd = net_pkt_read(pkt, frame_buf, n - ETH_HDR); /* line 260 */
		//@ integers__join(frame_buf);
		if (rd == 0) {
			const uint16_t ethertype = model_ethertype(hdr);

			if (ethertype == ETH_IPV4 || ethertype == ETH_ARP) {
#ifdef VF_BAD_EARLY_RETURN
				/* Deliberate error: a return that keeps the lock. */
				if (frame_buf[0] == 0xff) {
					//@ close leaf_inv();
					return -EINVAL;
				}
#endif
				for (unsigned int i = 0; i < ZTL_PEERS; i++)
					/*@ invariant ztl_leaf_core(&leaf) &*& [1/2]adapter_fixed() &*&
					              tx_buf[..ZTL_PKT_MAX] |-> ?tx &*& frame_buf[..ZTL_MTU_MAX] |-> ?fr &*&
					              out_cycles |-> ?oc &*& out_calls |-> ?outc &*& out_max |-> ?om; @*/
				{
					const uint32_t t0 = k_cycle_get_32();
					//@ open [1/2]adapter_fixed();
					//@ integers__split(frame_buf, n - ETH_HDR);
					const size_t len = ztl_frame_to(&leaf, i, hdr, ethertype, frame_buf, n - ETH_HDR,
									tx_buf); /* line 268 */
					//@ integers__join(frame_buf);
					//@ close [1/2]adapter_fixed();
					const uint32_t t1 = k_cycle_get_32();
					const uint32_t dt = /*@truncating@*/ (t1 - t0);

					if (len != 0u) {
						out_cycles = /*@truncating@*/ (out_cycles + dt);
						out_calls = /*@truncating@*/ (out_calls + 1);
						out_max = (out_max > dt) ? out_max : dt;
						send_packet(i, len); /* line 275 */
					}
				}
			}
		}
	}
	//@ close leaf_inv();
	k_mutex_unlock(&lock); /* line 280 */
	return 0;
}

/* Lines 315 to 335. Called by ztl_zephyr_start() AFTER the unlock: the contract asks for
 * the token. Returns the descriptor or a negative number; it does not write "sock". */
static int socket_open(void)
	//@ requires [?f]underlay_if |-> ?u &*& [f]local_port |-> ?lp &*& k_mutex_not_held(&lock, currentThread);
	//@ ensures [f]underlay_if |-> u &*& [f]local_port |-> lp &*& k_mutex_not_held(&lock, currentThread);
{
	const int s = zsock_socket_udp(); /* line 319 */

	if (s < 0) {
		return -EIO;
	}
	if (zsock_bind_to(s, underlay_if, local_port) != 0) { /* lines 326 to 328 */
		zsock_close(s);
		return -EIO;
	}
	return s;
}

/* Lines 337 to 404. MODEL: *config is read through stubs. The caller owns
 * the right to start; if the start fails, the caller keeps it. */
int ztl_zephyr_start(const struct ztl_zephyr_config *config, struct net_if *underlay)
	//@ requires [?q]k_mutex(&lock, leaf_inv) &*& k_mutex_not_held(&lock, currentThread) &*& start_right();
	/*@ ensures [q]k_mutex(&lock, leaf_inv) &*& k_mutex_not_held(&lock, currentThread) &*&
	            (result == 0 ? true : start_right()); @*/
{
	uint64_t first_id;
	int ret;

	if (!model_config_ok(config)) {
		return -EINVAL;
	}
	if (!atomic_cas(&running, 0, 1)) { /* line 346 */
		return -EALREADY;
	}
	if (sys_csrand_get(&first_id) != 0) {
		atomic_clear(&running);
		return -EIO;
	}
	//@ open start_right();
	k_mutex_lock(&lock, K_FOREVER); /* line 355 */
	//@ open leaf_inv();
	/* Both halves of adapter_fixed() are here now: this thread can write it. */
	//@ open [1/2]adapter_fixed();
	//@ open [1/2]adapter_fixed();
	ztl_init(&leaf, config, first_id); /* line 356 */
	ret = 0;
	const unsigned int peer_count = model_config_peer_count(config);

	for (unsigned int i = 0; i < peer_count && ret == 0; i++)
		/*@ invariant ztl_leaf_core(&leaf) &*& ztl_leaf_pins(&leaf) &*& endpoint_addr[..ZTL_PEERS] |-> ?addrs &*&
		              endpoint_port[..ZTL_PEERS] |-> ?ports; @*/
	{
		const int at = ztl_pin(&leaf, config, i); /* line 360 */
		const uint16_t port = model_config_peer_port(config, i);
		const uint32_t ipv4 = model_config_ipv4(config, i);

		if (at < 0 || port == 0u) {
			ret = -EINVAL;
		} else {
			endpoint_port[at] = port;
			endpoint_addr[at] = ipv4;
		}
	}
	//@ open ztl_leaf_core(&leaf);
	if (ret == 0 && leaf.ctrl >= ZTL_PEERS) {
		ret = -EINVAL;
	}
	if (ret == 0) {
		underlay_if = underlay;
		local_port = model_config_port(config);
		model_copy_mac(overlay_mac, leaf.mac); /* line 377 */
	}
	//@ close ztl_leaf_core(&leaf);
#ifdef VF_BAD_START_LOCKED
	/* Deliberate error: a call into the network stack before the unlock. */
	if (ret == 0) {
		const int early = socket_open();

		if (early < 0) {
			ret = early;
		}
	}
#endif
	//@ close [1/2]adapter_fixed();
	//@ close [1/2]adapter_fixed();
	//@ close leaf_inv();
	k_mutex_unlock(&lock); /* line 379 */
	/* From here this thread has a read share of adapter_fixed() only. */
	if (ret == 0) {
		//@ open [1/2]adapter_fixed();
		const int s = socket_open(); /* line 382 */
		//@ close [1/2]adapter_fixed();

		if (s < 0) {
			ret = s;
		} else {
#ifndef VF_BAD_SOCK_UNLOCKED
			/* The second locked section: both halves of adapter_fixed() again, so "sock" can be written. */
			k_mutex_lock(&lock, K_FOREVER); /* line 388 */
			//@ open leaf_inv();
			//@ open [1/2]adapter_fixed();
			//@ open [1/2]adapter_fixed();
			sock = s; /* line 389 */
			//@ close [1/2]adapter_fixed();
			//@ close [1/2]adapter_fixed();
			//@ close leaf_inv();
			k_mutex_unlock(&lock); /* line 390 */
#else
			/* Deliberate error: the store without the lock (the adapter between the two fixes).
			 * (No ghost "close" follows: VeriFast must stop at the write.) */
			//@ open [1/2]adapter_fixed();
			sock = s;
#endif
		}
	}
	if (ret == 0) {
		//@ open [1/2]adapter_fixed();
		net_if_set_link_addr(overlay, overlay_mac, ZTL_ETH_ALEN); /* line 394 */
		//@ close [1/2]adapter_fixed();
	}
	if (ret != 0) {
		atomic_clear(&running);
		//@ close start_right();
		return ret;
	}
	//@ close start_right();
	//@ close thread_data(worker)(&lock);
	k_thread_create(worker, &lock); /* line 400 */
	return 0;
}

/* Lines 406 to 433. MODEL: the result structure is reduced to one sum. The part
 * before the lock (lines 408 to 416: atomic variables, "overlay") is left out. */
uint32_t ztl_zephyr_get_status(void)
	//@ requires [?q]k_mutex(&lock, leaf_inv) &*& k_mutex_not_held(&lock, currentThread);
	//@ ensures [q]k_mutex(&lock, leaf_inv) &*& k_mutex_not_held(&lock, currentThread);
{
	uint32_t peers_seen = 0;

	k_mutex_lock(&lock, K_FOREVER); /* line 417 */
	//@ open leaf_inv();
	//@ open ztl_leaf_core(&leaf);
	//@ open [1/2]adapter_fixed();
	//@ open [1/2]ztl_leaf_pins(&leaf);
	uint32_t s = leaf.stats;
	s = in_calls;
	s = out_calls;
	for (unsigned int i = 0; i < ZTL_PEERS; i++)
		/*@ invariant [1/2]integers_(leaf.pinned, 1, false, ZTL_PEERS, ?pins) &*& leaf.seen[..ZTL_PEERS] |-> ?seen &*&
		              peers_seen <= i; @*/
	{
		if (leaf.pinned[i] != 0 && leaf.seen[i] != 0u) {
			peers_seen++;
		}
	}
	//@ close [1/2]ztl_leaf_pins(&leaf);
	//@ close [1/2]adapter_fixed();
	//@ close ztl_leaf_core(&leaf);
	//@ close leaf_inv();
	k_mutex_unlock(&lock); /* line 432 */
	return peers_seen;
}

/*
 * The environment. Not in the adapter: it shows that the contracts above
 * can be met from the first state of the program (all globals owned by
 * main), with two threads that use the adapter at the same time.
 */

/* A thread of the network stack (or of the shell): sends frames, reads the status. */
//@ predicate_family_instance thread_data(stack_thread)(struct k_mutex *m) = m == &lock &*& [1/4]k_mutex(&lock, leaf_inv);

static void stack_thread(struct k_mutex *m) //@ : k_thread_entry_t
	//@ requires thread_data(stack_thread)(m) &*& k_mutex_not_held(m, currentThread);
	//@ ensures k_mutex_not_held(m, currentThread);
{
	//@ open thread_data(stack_thread)(m);
	for (;;)
		//@ invariant [1/4]k_mutex(&lock, leaf_inv) &*& k_mutex_not_held(&lock, currentThread);
	{
		struct net_pkt *pkt = net_pkt_rx_alloc_with_buffer(NULL, 100, K_NO_WAIT);

		if (pkt != NULL) {
			ztl_dev_send(pkt);
			net_pkt_unref(pkt);
		}
		ztl_zephyr_get_status();
	}
}

int main() //@ : main_full(ztl_zephyr_model)
	//@ requires module(ztl_zephyr_model, true);
	//@ ensures true;
{
	//@ open_module();
	/* The atomic variables go to the kernel's atomic operations: outside the ownership model. */
	//@ leak running |-> _ &*& usable |-> _ &*& wire_tx |-> _ &*& wire_rx |-> _;
	//@ leak rx_filtered |-> _ &*& tx_dropped |-> _ &*& rx_dropped |-> _;
	/* Stands for ztl_iface_init() (lines 284 to 291): the stack sets "overlay" before any thread uses the adapter. */
	overlay = NULL;
	//@ close ztl_leaf_pins(&leaf);
	//@ close ztl_leaf_core(&leaf);
	//@ close adapter_fixed();
	//@ open adapter_fixed();
	//@ close [1/2]adapter_fixed();
	//@ close [1/2]adapter_fixed();
	//@ close leaf_inv();
	//@ close worker_only();
	//@ close k_mutex_init_ghost_arg(leaf_inv);
	k_mutex_init(&lock); /* stands for K_MUTEX_DEFINE(lock), line 32 */
	//@ close worker_lock();
	//@ close start_right();
	//@ close thread_data(stack_thread)(&lock);
	k_thread_create(stack_thread, &lock);
	if (ztl_zephyr_start(NULL, NULL) != 0) {
		//@ leak start_right();
	}
	ztl_zephyr_get_status();
	//@ leak [_]k_mutex(&lock, leaf_inv) &*& k_mutex_not_held(&lock, currentThread);
	return 0;
}
