/*
     This file is part of GNUnet.
     (C) 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file include/gnunet_nat_lib.h
 * @brief Library handling UPnP and NAT-PMP port forwarding and
 *     external IP address retrieval
 *
 * @author Milan Bouchet-Valat
 */

#ifndef GNUNET_NAT_LIB_H
#define GNUNET_NAT_LIB_H 1

#include "platform.h"
#include "gnunet_util_lib.h"
#include "upnp.h"
#include "natpmp.h"

#include <inttypes.h>

/**
 * Used to communicate with the UPnP and NAT-PMP plugins 
 * FIXME: move to src/nat/common.h
 */
enum GNUNET_NAT_port_forwarding
  {
    GNUNET_NAT_PORT_ERROR,
    GNUNET_NAT_PORT_UNMAPPED,
    GNUNET_NAT_PORT_UNMAPPING,
    GNUNET_NAT_PORT_MAPPING,
    GNUNET_NAT_PORT_MAPPED
  };


/**
 * Signature of the callback passed to GNUNET_NAT_register.
 *
 * @param cls closure
 * @param add_remove GNUNET_YES to mean the new public IP address, GNUNET_NO to mean
 *     the previous (now invalid) one
 * @param addr either the previous or the new public IP address
 * @param addrlen actual lenght of the address
 */
typedef void (*GNUNET_NAT_AddressCallback) (void *cls, int add_remove,
                                            const struct sockaddr * addr,
                                            socklen_t addrlen);

/**
 * Handle for active NAT registrations.
 */
struct GNUNET_NAT_Handle;

/**
 * Attempt to enable port redirection and detect public IP address contacting
 * UPnP or NAT-PMP routers on the local network. Use addr to specify to which
 * of the local host's addresses should the external port be mapped. The port
 * is taken from the corresponding sockaddr_in[6] field.
 *
 * @param sched the sheduler used in the program
 * @param addr the local address packets should be redirected to
 * @param addrlen actual lenght of the address
 * @param callback function to call everytime the public IP address changes
 * @param callback_cls closure for callback
 * @return NULL on error, otherwise handle that can be used to unregister 
 */
struct GNUNET_NAT_Handle *GNUNET_NAT_register (struct GNUNET_SCHEDULER_Handle
                                               *sched,
                                               const struct sockaddr *addr,
                                               socklen_t addrlen,
                                               GNUNET_NAT_AddressCallback
                                               callback, void *callback_cls);

/**
 * Stop port redirection and public IP address detection for the given handle.
 * This frees the handle, after having sent the needed commands to close open ports.
 *
 * @param h the handle to stop
 */
void GNUNET_NAT_unregister (struct GNUNET_NAT_Handle *h);

/**
 * Compare the sin(6)_addr fields of AF_INET or AF_INET(6) sockaddr.
 * FIXME: move to src/nat/common.h or so.
 * 
 * @param a first sockaddr
 * @param b second sockaddr
 * @return 0 if addresses are equal, non-null value otherwise 
 */
int GNUNET_NAT_cmp_addr (const struct sockaddr *a, 
			 const struct sockaddr *b);


#endif 

/* end of gnunet_nat_lib.h */
