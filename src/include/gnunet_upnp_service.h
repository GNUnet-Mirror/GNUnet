/*
     This file is part of GNUnet
     (C) 2006 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file include/gnunet_upnp_service.h
 * @brief API for UPnP access
 * @author Christian Grothoff
 */

#ifndef GNUNET_UPNP_SERVICE_H
#define GNUNET_UPNP_SERVICE_H

#include "gnunet_resolver_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Get the external IP address for the local machine and
 * install a port mapping if possible.  The external port
 * will be returned as part of the address.
 *
 * @param cfg configuration to use
 * @param domain communication domain (i.e. PF_INET or PF_INET6)
 * @param type communication semantics (SOCK_STREAM, SOCK_DGRAM)
 * @param protocol protocol to use, 0 for default (see protocols(5))
 * @param port port to map
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
  * @param callback function to call with the external address;
 *        function will be called with NULL on error
 * @param cls closure for callback
 */
int
GNUNET_UPNP_get_ip (struct GNUNET_CONFIGURATION_Handle *cfg, int domain,
                    int type, int protocol, uint16_t port,
                    struct GNUNET_TIME_Relative timeout,
                    GNUNET_RESOLVER_AddressCallback callback, void *cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
