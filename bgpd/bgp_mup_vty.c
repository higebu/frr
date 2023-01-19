/*
 * VTY functions for BGP-MUP
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

#include <zebra.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mup_vty.h"

// static void bgp_mup_show_route_rd_header(struct vty *vty,
// 					  struct bgp_dest *rd_dest,
// 					  json_object *json, char *rd_str,
// 					  int len)
// {
// 	uint16_t type;
// 	struct rd_as rd_as;
// 	struct rd_ip rd_ip;
// 	const uint8_t *pnt;
// 	const struct prefix *p = bgp_dest_get_prefix(rd_dest);
// 
// 	pnt = p->u.val;
// 
// 	/* Decode RD type. */
// 	type = decode_rd_type(pnt);
// 
// 	if (!json)
// 		vty_out(vty, "Route Distinguisher: ");
// 
// 	switch (type) {
// 	case RD_TYPE_AS:
// 		decode_rd_as(pnt + 2, &rd_as);
// 		snprintf(rd_str, len, "%u:%d", rd_as.as, rd_as.val);
// 		if (json)
// 			json_object_string_add(json, "rd", rd_str);
// 		else
// 			vty_out(vty, "%s\n", rd_str);
// 		break;
// 
// 	case RD_TYPE_AS4:
// 		decode_rd_as4(pnt + 2, &rd_as);
// 		snprintf(rd_str, len, "%u:%d", rd_as.as, rd_as.val);
// 		if (json)
// 			json_object_string_add(json, "rd", rd_str);
// 		else
// 			vty_out(vty, "%s\n", rd_str);
// 		break;
// 
// 	case RD_TYPE_IP:
// 		decode_rd_ip(pnt + 2, &rd_ip);
// 		snprintfrr(rd_str, len, "%pI4:%d", &rd_ip.ip, rd_ip.val);
// 		if (json)
// 			json_object_string_add(json, "rd", rd_str);
// 		else
// 			vty_out(vty, "%s\n", rd_str);
// 		break;
// 
// 	default:
// 		if (json) {
// 			snprintf(rd_str, len, "Unknown");
// 			json_object_string_add(json, "rd", rd_str);
// 		} else {
// 			snprintf(rd_str, len, "Unknown RD type");
// 			vty_out(vty, "%s\n", rd_str);
// 		}
// 		break;
// 	}
// }

static void bgp_mup_show_route_header(struct vty *vty, struct bgp *bgp,
				       uint64_t tbl_ver, json_object *json)
{
	if (json)
		return;

	vty_out(vty,
		"BGP table version is %" PRIu64 ", local router ID is %pI4\n",
		tbl_ver, &bgp->router_id);
	vty_out(vty,
		"Status codes: s suppressed, d damped, h history, * valid, > best, i - internal\n");
	vty_out(vty, "Origin codes: i - IGP, e - EGP, ? - incomplete\n");
	vty_out(vty,
		"MUP ISD prefix: [1]:[1]:[PrefixLen]:[Prefix]\n");
	vty_out(vty,
		"MUP DSD prefix: [1]:[2]:[Address]\n");
	vty_out(vty, "MUP Type 1 prefix: [1]:[3]:[PrefixLen]:[Prefix]\n");
	vty_out(vty, "MUP Type 2 prefix: [1]:[4]:[EndpointAddressLen]:[EndpointAddress]:[TEID]\n");
	vty_out(vty, "%s", BGP_SHOW_HEADER_WIDE);
}

int bgp_mup_show_all_routes(struct vty *vty, struct bgp *bgp, afi_t afi, struct bgp_table *table, int type,
				    bool use_json, int detail)
{
	struct bgp_path_info *pi;
	struct bgp_dest *dest;
	unsigned long total_count = 0;
	json_object *json_paths = NULL;
	int header = 1;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		pi = bgp_dest_get_bgp_path_info(dest);
		if (pi == NULL)
			continue;
		if (use_json) {
			json_paths = json_object_new_array();
		}
		const struct prefix *p = bgp_dest_get_prefix(dest);
		for (; pi; pi = pi->next) {
			total_count++;
			if (header) {
				bgp_mup_show_route_header(vty, bgp, 0, json_paths);
				header = 0;
			}
			if (detail) {
				route_vty_out_detail(
					vty, bgp, dest,
					bgp_dest_get_prefix(dest), pi,
					afi, SAFI_MUP,
					RPKI_NOT_BEING_USED, json_paths);
			} else
				route_vty_out(vty, p, pi, 0, SAFI_MUP,
					      json_paths, true);
		}
		if (use_json) {
			vty_json(vty, json_paths);
			json_paths = NULL;
		}
	}
	if (use_json)
		return CMD_SUCCESS;

	if (total_count)
		vty_out(vty,
			"\nDisplayed  %ld MUP entries\n",
			total_count);
	else
		vty_out(vty, "No MUP prefixes\n");

	return CMD_SUCCESS;
}
