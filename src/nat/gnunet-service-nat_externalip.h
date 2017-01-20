/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2015, 2016, 2017 GNUnet e.V.

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * Code to figure out what our external IPv4 address(es) might
 * be (external IPv4s are what is seen on the rest of the Internet).
 *
 * This can be implemented using different methods, and we allow
 * the main service to be notified about changes to what we believe
 * is our external IPv4 address.  
 *
 * Note that this is explicitly only about NATed systems; if one
 * of our network interfaces has a global IP address this does
 * not count as "external".
 *
 * @file nat/gnunet-service-nat_externalip.h
 * @brief Functions for monitoring external IPv4 addresses
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_NAT_EXTERNALIP_H
#define GNUNET_SERVICE_NAT_EXTERNALIP_H

#include "platform.h"


/**
 * We have changed our opinion about being NATed in the first
 * place. Adapt our probing.
 *
 * @param have_nat #GNUNET_YES if we believe we are behind NAT
 */
void
GN_nat_status_changed (int have_nat);


/**
 * Function we call when we believe our external IPv4 address changed.
 *
 * @param cls closure
 * @param ip address to add/remove
 * @param add_remove #GNUNET_YES to add, #GNUNET_NO to remove
 */
typedef void
(*GN_NotifyExternalIPv4Change)(void *cls,
			       const struct in_addr *ip,
			       int add_remove);


/**
 * Handle to monitor for external IP changes.
 */
struct GN_ExternalIPMonitor;


/**
 * Start monitoring external IPv4 addresses.
 *
 * @param cb function to call on changes
 * @param cb_cls closure for @a cb
 * @return handle to cancel
 */
struct GN_ExternalIPMonitor *
GN_external_ipv4_monitor_start (GN_NotifyExternalIPv4Change cb,
				void *cb_cls);


/**
 * Stop calling monitor.
 *
 * @param mon monitor to call
 */
void
GN_external_ipv4_monitor_stop (struct GN_ExternalIPMonitor *mon);


#endif
