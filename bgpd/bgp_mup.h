/*
 * BGP-MUP header for packet handling
 * Copyright (C) 2023 Yuya Kusakabe
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_BGP_MUP_H
#define _FRR_BGP_MUP_H

#include "stream.h"

#include "bgpd/bgpd.h"

#define BGP_MUP_ROUTE_PREFIXLEN (sizeof(struct mup_prefix) * 8)

extern size_t bgp_mup_prefix_size(const struct prefix *p);

extern void bgp_mup_encode_prefix(struct stream *s, afi_t afi,
				  const struct prefix *p,
				  const struct prefix_rd *prd,
				  bool addpath_capable, uint32_t addpath_tx_id);

extern int bgp_nlri_parse_mup(struct peer *peer, struct attr *attr,
			      struct bgp_nlri *packet, int withdraw);

#endif /* _FRR_BGP_MUP_H */
