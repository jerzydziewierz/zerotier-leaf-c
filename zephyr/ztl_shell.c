/* SPDX-License-Identifier: Apache-2.0 */
/* Shell command "ztl status": counters of the adapter and of the leaf. No key material. */
#include <zephyr/shell/shell.h>
#include "ztl_zephyr.h"

static int cmd_status(const struct shell *sh, size_t argc, char **argv)
{
	struct ztl_zephyr_status s;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	ztl_zephyr_get_status(&s);
	shell_print(sh, "running=%d usable=%d iface=%d peers_seen=%u", s.running, s.usable, s.ifindex, s.peers_seen);
	shell_print(sh, "wire_tx=%u wire_rx=%u rx_filtered=%u tx_dropped=%u rx_dropped=%u", s.wire_tx, s.wire_rx,
		    s.rx_filtered, s.tx_dropped, s.rx_dropped);
	shell_print(sh, "gate ok=%u not_wire=%u not_ours=%u no_peer=%u bad_suite=%u bad_auth=%u", s.gate.ok, s.gate.not_wire,
		    s.gate.not_ours, s.gate.no_peer, s.gate.bad_suite, s.gate.bad_auth);
	shell_print(sh, "leaf lz4=%u bad_lz4=%u bad_form=%u no_config=%u ignored=%u frames=%u tx_packets=%u configs=%u config_bad=%u",
		    s.leaf.rx_lz4, s.leaf.rx_bad_lz4, s.leaf.rx_bad_form, s.leaf.rx_no_config, s.leaf.rx_ignored,
		    s.leaf.rx_frames, s.leaf.tx_packets, s.leaf.configs, s.leaf.config_bad);
	shell_print(sh, "cycles (%u per second): ztl_input calls=%u avg=%u max=%u; ztl_frame_to packets=%u avg=%u max=%u",
		    s.cycles_per_sec, s.in_calls, s.in_avg, s.in_max, s.out_calls, s.out_avg, s.out_max);
	shell_print(sh, "ram: leaf %u bytes", (unsigned int)sizeof(struct ztl_leaf));
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(ztl_cmds, SHELL_CMD(status, NULL, "Counters of the ZeroTier leaf", cmd_status),
			       SHELL_SUBCMD_SET_END);
SHELL_CMD_REGISTER(ztl, &ztl_cmds, "ZeroTier leaf in C", NULL);
