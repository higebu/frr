/*
 * BGP-MUP header for VTY functions
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

#ifndef _FRR_BGP_MUP_VTY_H
#define _FRR_BGP_MUP_VTY_H

#include "bgpd/bgp_vty.h"

extern int bgp_mup_show_all_routes(struct vty *vty, struct bgp *bgp, afi_t afi, struct bgp_table *table, int type,
				    bool use_json, int detail);

#endif /* _FRR_BGP_MUP_VTY_H */
