/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 *  SRv6 Mobile User Plane implementation
 *
 *  Author:
 *  Yuya Kusakabe <yuya.kusakabe@gmail.com>
 */
#ifndef _LINUX_SEG6_MOBILE_H
#define _LINUX_SEG6_MOBILE_H

enum {
	SEG6_MOBILE_UNSPEC,
	SEG6_MOBILE_ACTION,
	SEG6_MOBILE_MAPPED_SID,
	SEG6_MOBILE_COUNTERS,
	SEG6_MOBILE_PDU_TYPE,
	SEG6_MOBILE_V6_SRC_PREFIX_LEN,
	SEG6_MOBILE_SR_PREFIX_LEN,
	SEG6_MOBILE_SRC_ADDR,
	SEG6_MOBILE_UDP6_ZEROCSUM_TX,
	SEG6_MOBILE_SRH,
	SEG6_MOBILE_VRFTABLE,
	__SEG6_MOBILE_MAX,
};

#define SEG6_MOBILE_MAX	(__SEG6_MOBILE_MAX - 1)

enum {
	SEG6_MOBILE_ACTION_UNSPEC	= 0,
	/* swap IPv6 DA with the mapped SID, leave SRH untouched */
	SEG6_MOBILE_ACTION_END_MAP	= 1,
	/* SRv6 to IPv4/GTP-U encap */
	SEG6_MOBILE_ACTION_END_M_GTP4_E	= 2,
	/* SRv6 to IPv6/GTP-U encap */
	SEG6_MOBILE_ACTION_END_M_GTP6_E	= 3,
	/* IPv6/GTP-U decap into SR Policy */
	SEG6_MOBILE_ACTION_END_M_GTP6_D	= 4,
	/* IPv6/GTP-U drop-in decap into SR Policy */
	SEG6_MOBILE_ACTION_END_M_GTP6_D_DI	= 5,
	/* IPv4/GTP-U headend encap into SR Policy */
	SEG6_MOBILE_ACTION_H_M_GTP4_D	= 6,

	__SEG6_MOBILE_ACTION_MAX,
};

#define SEG6_MOBILE_ACTION_MAX	(__SEG6_MOBILE_ACTION_MAX - 1)

/* SRv6 Mobile Behavior counters are encoded as netlink attributes
 * guaranteeing the correct alignment.
 * Each counter is identified by a different attribute type (i.e.
 * SEG6_MOBILE_CNT_PACKETS).
 *
 * - SEG6_MOBILE_CNT_PACKETS: identifies a counter that counts the number
 *   of packets that have been CORRECTLY processed by an SRv6 Behavior
 *   instance (i.e., packets that generate errors or are dropped are NOT
 *   counted).
 *
 * - SEG6_MOBILE_CNT_BYTES: identifies a counter that counts the total
 *   amount of traffic in bytes of all packets that have been CORRECTLY
 *   processed by an SRv6 Behavior instance (i.e., packets that generate
 *   errors or are dropped are NOT counted).
 *
 * - SEG6_MOBILE_CNT_ERRORS: identifies a counter that counts the number
 *   of packets that have NOT been properly processed by an SRv6 Behavior
 *   instance (i.e., packets that generate errors or are dropped).
 */
enum {
	SEG6_MOBILE_CNT_UNSPEC,
	SEG6_MOBILE_CNT_PACKETS,
	SEG6_MOBILE_CNT_BYTES,
	SEG6_MOBILE_CNT_ERRORS,
	SEG6_MOBILE_CNT_PAD,		/* pad for 64 bits values */
	__SEG6_MOBILE_CNT_MAX,
};

#define SEG6_MOBILE_CNT_MAX	(__SEG6_MOBILE_CNT_MAX - 1)

#endif /* _LINUX_SEG6_MOBILE_H */
