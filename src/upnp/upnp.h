/**
 * @file upnp.h Universal Plug N Play API
 * @ingroup core
 *
 * gaim
 *
 * Gaim is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _GAIM_UPNP_H_
#define _GAIM_UPNP_H_

#include <libxml/parser.h>
#include <string.h>
#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Sends a discovery request to search for a UPnP enabled IGD that
 * contains the WANIPConnection service that will allow us to receive the
 * public IP address of the IGD, and control it for forwarding ports.
 * The result will be cached for further use.
 */
int gaim_upnp_discover (struct GNUNET_CONFIGURATION_Handle *cfg, int sock);

/**
 * Gets the IP address from a UPnP enabled IGD that sits on the local
 * network, so when getting the network IP, instead of returning the
 * local network IP, the public IP is retrieved.  This is a cached value from
 * the time of the UPnP discovery.
 *
 * @return The IP address of the network, or NULL if something went wrong
 */
const char *gaim_upnp_get_public_ip (void);

/**
 * Maps Ports in a UPnP enabled IGD that sits on the local network to
 * this gaim client. Essentially, this function takes care of the port
 * forwarding so things like file transfers can work behind NAT firewalls
 *
 * @param cfg configuration to use
 * @param do_add TRUE/GNUNET_YES to add, FALSE/GNUNET_NO to remove
 * @param portmap The port to map to this client
 * @param protocol The protocol to map, either "TCP" or "UDP"
 */
int gaim_upnp_change_port_mapping (struct GNUNET_CONFIGURATION_Handle *cfg,
                                   int do_add,
                                   uint16_t portmap, const char *protocol);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* _GAIM_UPNP_H_ */
