/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Zephyr adapter of the leaf.
 *
 * The leaf (struct ztl_leaf) and the packet buffer tx_buf are used by two
 * threads: the leaf thread (timers, received datagrams) and whatever thread
 * sends a frame through the virtual interface. One mutex guards them. While
 * it is held, sockets are used with "do not wait" and received frames go to
 * the network stack's own queue; the calls still take locks of the network
 * stack for a short time (not analysed for every configuration of Zephyr).
 */
#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/socket.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/byteorder.h>
#include "ztl_zephyr.h"

BUILD_ASSERT(CONFIG_NET_TC_RX_COUNT >= 1 && !IS_ENABLED(CONFIG_NET_TC_RX_SKIP_FOR_HIGH_PRIO),
	     "received frames must go through the RX queue of the network stack");

#define ETH_HDR      14u
#define ETH_IPV4     0x0800u
#define ETH_ARP      0x0806u
#define UDP_RX_MAX   1472u /* largest UDP payload on an underlay with MTU 1500 */

static K_MUTEX_DEFINE(lock);
static struct ztl_leaf leaf;
static uint8_t tx_buf[ZTL_PKT_MAX];     /* guarded by lock */
static uint8_t frame_buf[ZTL_MTU_MAX];  /* guarded by lock */
static uint8_t rx_buf[UDP_RX_MAX + 1u]; /* leaf thread only */
static struct net_sockaddr_in endpoint[ZTL_PEERS]; /* by peer index; fixed after start */
static struct net_if *overlay;
static struct net_if *underlay_if;
static int sock = -1;
static uint16_t local_port;
static atomic_t running, usable;
static atomic_t wire_tx, wire_rx, rx_filtered, tx_dropped, rx_dropped;
static struct net_in_addr have_ip; /* address on the interface now, or 0 */
static uint8_t have_prefix;        /* and its network part, in bits */
static uint8_t placeholder_mac[ZTL_ETH_ALEN] = { 0x02, 0x5a, 0x54, 0x4c, 0x00, 0x01 };

K_THREAD_STACK_DEFINE(ztl_stack, CONFIG_ZTL_WORKER_STACK_SIZE);
static struct k_thread ztl_thread;

/* Send the packet of len bytes in tx_buf to peer i, in one or two datagrams. Lock held. */
static void send_packet(unsigned int i, size_t len)
{
	size_t at = 0;
	size_t n = ztl_tx_first(len);

	for (int part = 0; part < 2 && n != 0u; part++) {
		const ssize_t sent = zsock_sendto(sock, &tx_buf[at], n, ZSOCK_MSG_DONTWAIT,
						  (const struct net_sockaddr *)&endpoint[i], sizeof(endpoint[i]));

		if (sent == (ssize_t)n) {
			atomic_inc(&wire_tx);
		} else {
			atomic_inc(&tx_dropped);
		}
		n = (part == 0) ? ztl_tx_second(tx_buf, len, &at) : 0u;
	}
}

/* Take the interface down and remove its address. */
static void overlay_down(void)
{
	atomic_clear(&usable);
	net_if_carrier_off(overlay);
	if (have_ip.s_addr != 0u) {
		(void)net_if_ipv4_addr_rm(overlay, &have_ip);
		have_ip.s_addr = 0;
	}
}

/* Make the interface agree with the configuration of the leaf. Lock held. */
static void apply_config(void)
{
	struct net_in_addr ip, mask;

	if ((leaf.flags & ZTL_L_CONFIG) == 0u || leaf.prefix == 0u) {
		overlay_down();
		return;
	}
	memcpy(&ip.s_addr, leaf.ip, 4);
	if (atomic_get(&usable) && ip.s_addr == have_ip.s_addr && leaf.prefix == have_prefix &&
	    net_if_get_mtu(overlay) == leaf.mtu) {
		return;
	}
	overlay_down();
	net_if_set_mtu(overlay, leaf.mtu);
	if (net_if_ipv4_addr_add(overlay, &ip, NET_ADDR_MANUAL, 0) == NULL) {
		return;
	}
	have_ip = ip;
	have_prefix = leaf.prefix;
	mask.s_addr = net_htonl(UINT32_MAX << (32u - leaf.prefix));
	(void)net_if_ipv4_set_netmask_by_addr(overlay, &ip, &mask);
	net_if_carrier_on(overlay);
	(void)net_if_up(overlay);
	atomic_set(&usable, 1);
}

/* Give one frame from a peer to the network stack. Lock held (f->data can point into the leaf). */
static void deliver(const struct ztl_frame *f)
{
	uint8_t hdr[ETH_HDR];
	struct net_pkt *pkt;

	if (!atomic_get(&usable) || (f->ethertype != ETH_IPV4 && f->ethertype != ETH_ARP)) {
		atomic_inc(&rx_dropped);
		return;
	}
	pkt = net_pkt_rx_alloc_with_buffer(overlay, ETH_HDR + f->len, NET_AF_UNSPEC, 0, K_NO_WAIT);
	if (pkt == NULL) {
		atomic_inc(&rx_dropped);
		return;
	}
	memcpy(hdr, f->dst, ZTL_ETH_ALEN);
	memcpy(&hdr[ZTL_ETH_ALEN], f->src, ZTL_ETH_ALEN);
	sys_put_be16(f->ethertype, &hdr[2u * ZTL_ETH_ALEN]);
	if (net_pkt_write(pkt, hdr, sizeof(hdr)) != 0 || net_pkt_write(pkt, f->data, f->len) != 0 ||
	    net_recv_data(overlay, pkt) < 0) {
		net_pkt_unref(pkt);
		atomic_inc(&rx_dropped);
	}
}

/* Is this datagram from the pinned endpoint of a peer? */
static bool from_endpoint(const struct net_sockaddr_in *from)
{
	for (unsigned int i = 0; i < ZTL_PEERS; i++) {
		if (leaf.node.peer[i].pinned && from->sin_addr.s_addr == endpoint[i].sin_addr.s_addr &&
		    from->sin_port == endpoint[i].sin_port) {
			return true;
		}
	}
	return false;
}

static void worker(void *a, void *b, void *c)
{
	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);
	for (;;) {
		struct zsock_pollfd p = { .fd = sock, .events = ZSOCK_POLLIN };
		unsigned int peer = 0;
		size_t n;

		k_mutex_lock(&lock, K_FOREVER);
		while ((n = ztl_poll(&leaf, k_uptime_get_32(), tx_buf, &peer)) != 0u) {
			send_packet(peer, n);
		}
		k_mutex_unlock(&lock);
		if (zsock_poll(&p, 1, 100) <= 0) {
			continue;
		}
		for (int k = 0; k < CONFIG_ZTL_RX_BATCH; k++) {
			struct net_sockaddr_in from;
			net_socklen_t from_len = sizeof(from);
			struct ztl_frame frame;
			size_t tx_len = 0;
			const ssize_t got = zsock_recvfrom(sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT,
							   (struct net_sockaddr *)&from, &from_len);

			if (got < 0) {
				break;
			}
			if (got == 0 || (size_t)got > UDP_RX_MAX || from.sin_family != NET_AF_INET || !from_endpoint(&from)) {
				atomic_inc(&rx_filtered);
				continue;
			}
			atomic_inc(&wire_rx);
			k_mutex_lock(&lock, K_FOREVER);
			const unsigned int r = ztl_input(&leaf, rx_buf, (size_t)got, k_uptime_get_32(), tx_buf, &tx_len, &peer, &frame);

			if ((r & ZTL_IN_REPLY) != 0u) {
				send_packet(peer, tx_len);
			}
			if ((r & ZTL_IN_CONFIG) != 0u) {
				apply_config();
			}
			if ((r & ZTL_IN_FRAME) != 0u) {
				deliver(&frame);
			}
			k_mutex_unlock(&lock);
		}
		/* A source that sends without pause must not keep other threads from running. */
		k_yield();
	}
}

/* Ethernet driver "send": one frame from the network stack to the peers. */
static int ztl_dev_send(const struct device *dev, struct net_pkt *pkt)
{
	uint8_t hdr[ETH_HDR];
	const size_t n = net_pkt_get_len(pkt);

	ARG_UNUSED(dev);
	if (!atomic_get(&usable)) {
		return -ENETDOWN;
	}
	if (n <= ETH_HDR || n > ETH_HDR + ZTL_MTU_MAX) {
		return -EMSGSIZE;
	}
	if (k_mutex_lock(&lock, K_MSEC(200)) != 0) {
		atomic_inc(&tx_dropped);
		return -EBUSY;
	}
	net_pkt_cursor_init(pkt);
	if (net_pkt_read(pkt, hdr, sizeof(hdr)) == 0 && net_pkt_read(pkt, frame_buf, n - ETH_HDR) == 0) {
		const uint16_t ethertype = sys_get_be16(&hdr[2u * ZTL_ETH_ALEN]);

		if (ethertype == ETH_IPV4 || ethertype == ETH_ARP) {
			/* A frame to a group address goes to every reachable peer, a
			 * frame to one address to the peer that owns it. */
			for (unsigned int i = 0; i < ZTL_PEERS; i++) {
				const size_t len = ztl_frame_to(&leaf, i, hdr, ethertype, frame_buf, n - ETH_HDR, tx_buf);

				if (len != 0u) {
					send_packet(i, len);
				}
			}
		}
	}
	k_mutex_unlock(&lock);
	return 0;
}

static void ztl_iface_init(struct net_if *iface)
{
	overlay = iface;
	net_if_set_link_addr(iface, placeholder_mac, sizeof(placeholder_mac), NET_LINK_ETHERNET);
	ethernet_init(iface);
	net_if_flag_set(iface, NET_IF_NO_AUTO_START);
	net_if_carrier_off(iface);
}

static int ztl_dev_init(const struct device *dev)
{
	ARG_UNUSED(dev);
	return 0;
}

static const struct ethernet_api ztl_api = {
	.iface_api.init = ztl_iface_init,
	.send = ztl_dev_send,
};

ETH_NET_DEVICE_INIT(ztl_overlay, "ztl", ztl_dev_init, NULL, NULL, NULL, CONFIG_ETH_INIT_PRIORITY, &ztl_api,
		    ZTL_MTU_MAX);

static int socket_open(void)
{
	struct net_ifreq req = { 0 };
	struct net_sockaddr_in local = { .sin_family = NET_AF_INET, .sin_port = net_htons(local_port) };

	sock = zsock_socket(NET_AF_INET, NET_SOCK_DGRAM, NET_IPPROTO_UDP);
	if (sock < 0) {
		return -errno;
	}
	/* Only the underlay: a datagram that comes through the virtual
	 * interface itself must never reach the leaf. */
	if (net_if_get_name(underlay_if, req.ifr_name, sizeof(req.ifr_name)) < 0 ||
	    zsock_setsockopt(sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_BINDTODEVICE, &req, sizeof(req)) != 0 ||
	    zsock_bind(sock, (const struct net_sockaddr *)&local, sizeof(local)) != 0) {
		const int e = (errno != 0) ? -errno : -ENODEV;

		(void)zsock_close(sock);
		sock = -1;
		return e;
	}
	return 0;
}

int ztl_zephyr_start(const struct ztl_zephyr_config *config, struct net_if *underlay)
{
	uint64_t first_id;
	int ret;

	if (config == NULL || underlay == NULL || overlay == NULL || underlay == overlay || config->peers == NULL ||
	    config->peer_count < 1u || config->peer_count > ZTL_PEERS || config->port == 0u) {
		return -EINVAL;
	}
	if (!atomic_cas(&running, 0, 1)) {
		return -EALREADY;
	}
	/* The first packet ID: true random bits, new at every start. Packet
	 * IDs count up from it and are the nonces of the encryption. */
	if (sys_csrand_get(&first_id, sizeof(first_id)) != 0) {
		atomic_clear(&running);
		return -EIO;
	}
	k_mutex_lock(&lock, K_FOREVER);
	ztl_init(&leaf, config->self, config->pub, config->nwid, first_id);
	ret = 0;
	for (unsigned int i = 0; i < config->peer_count && ret == 0; i++) {
		const struct ztl_zephyr_peer *p = &config->peers[i];
		const int at = ztl_pin(&leaf, p->addr, p->key);

		if (at < 0 || p->port == 0u) {
			ret = -EINVAL;
		} else {
			endpoint[at].sin_family = NET_AF_INET;
			endpoint[at].sin_port = net_htons(p->port);
			memcpy(&endpoint[at].sin_addr.s_addr, p->ipv4, 4);
		}
	}
	if (ret == 0 && leaf.ctrl >= ZTL_PEERS) {
		ret = -EINVAL; /* no peer is the controller of the network */
	}
	if (ret == 0) {
		underlay_if = underlay;
		local_port = config->port;
		ret = socket_open();
	}
	if (ret == 0) {
		/* The Ethernet address follows from the node address and the network. */
		(void)net_if_set_link_addr(overlay, leaf.mac, ZTL_ETH_ALEN, NET_LINK_ETHERNET);
	}
	k_mutex_unlock(&lock);
	if (ret != 0) {
		atomic_clear(&running);
		return ret;
	}
	k_thread_create(&ztl_thread, ztl_stack, K_THREAD_STACK_SIZEOF(ztl_stack), worker, NULL, NULL, NULL,
			CONFIG_ZTL_WORKER_PRIORITY, 0, K_NO_WAIT);
	k_thread_name_set(&ztl_thread, "ztl");
	return 0;
}

void ztl_zephyr_get_status(struct ztl_zephyr_status *s)
{
	s->running = (int)atomic_get(&running);
	s->usable = (int)atomic_get(&usable);
	s->ifindex = (overlay != NULL) ? net_if_get_by_iface(overlay) : 0;
	s->wire_tx = (uint32_t)atomic_get(&wire_tx);
	s->wire_rx = (uint32_t)atomic_get(&wire_rx);
	s->rx_filtered = (uint32_t)atomic_get(&rx_filtered);
	s->tx_dropped = (uint32_t)atomic_get(&tx_dropped);
	s->rx_dropped = (uint32_t)atomic_get(&rx_dropped);
	s->peers_seen = 0;
	k_mutex_lock(&lock, K_FOREVER);
	s->leaf = leaf.stats;
	s->gate = leaf.node.rx;
	for (unsigned int i = 0; i < ZTL_PEERS; i++) {
		if (leaf.node.peer[i].pinned && (leaf.ps[i].flags & ZTL_P_SEEN) != 0u) {
			s->peers_seen++;
		}
	}
	k_mutex_unlock(&lock);
}
