/*
     This file is part of GNUnet.
     Copyright (C) 2011-2014, 2016 GNUnet e.V.

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
 * @file nat/gnunet-service-nat_mini.c
 * @brief functions for interaction with miniupnp; tested with miniupnpc 1.5
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_NAT_MINI_H
#define GNUNET_SERVICE_NAT_MINI_H


/**
 * Signature of a callback that is given an IP address.
 *
 * @param cls closure
 * @param addr the address, NULL on errors
 * @param result #GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 */
typedef void
(*GNUNET_NAT_IPCallback) (void *cls,
                          const struct in_addr *addr,
                          enum GNUNET_NAT_StatusCode result);


/**
 * Opaque handle to cancel #GNUNET_NAT_mini_get_external_ipv4() operation.
 */
struct GNUNET_NAT_ExternalHandle;


/**
 * Try to get the external IPv4 address of this peer.
 *
 * @param cb function to call with result
 * @param cb_cls closure for @a cb
 * @return handle for cancellation (can only be used until @a cb is called), NULL on error
 */
struct GNUNET_NAT_ExternalHandle *
GNUNET_NAT_mini_get_external_ipv4_ (GNUNET_NAT_IPCallback cb,
                                   void *cb_cls);


/**
 * Cancel operation.
 *
 * @param eh operation to cancel
 */
void
GNUNET_NAT_mini_get_external_ipv4_cancel_ (struct GNUNET_NAT_ExternalHandle *eh);


/**
 * Handle to a mapping created with upnpc.
 */
struct GNUNET_NAT_MiniHandle;


/**
 * Signature of the callback passed to #GNUNET_NAT_register() for
 * a function to call whenever our set of 'valid' addresses changes.
 *
 * @param cls closure
 * @param add_remove #GNUNET_YES to mean the new public IP address, #GNUNET_NO to mean
 *     the previous (now invalid) one, #GNUNET_SYSERR indicates an error
 * @param addr either the previous or the new public IP address
 * @param addrlen actual length of the @a addr
 * @param result #GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 */
typedef void
(*GNUNET_NAT_MiniAddressCallback) (void *cls,
                                   int add_remove,
                                   const struct sockaddr *addr,
                                   socklen_t addrlen,
                                   enum GNUNET_NAT_StatusCode result);


/**
 * Start mapping the given port using (mini)upnpc.  This function
 * should typically not be used directly (it is used within the
 * general-purpose #GNUNET_NAT_register() code).  However, it can be
 * used if specifically UPnP-based NAT traversal is to be used or
 * tested.
 *
 * @param port port to map
 * @param is_tcp #GNUNET_YES to map TCP, #GNUNET_NO for UDP
 * @param ac function to call with mapping result
 * @param ac_cls closure for @a ac
 * @return NULL on error
 */
struct GNUNET_NAT_MiniHandle *
GNUNET_NAT_mini_map_start (uint16_t port,
                           int is_tcp,
                           GNUNET_NAT_MiniAddressCallback ac,
                           void *ac_cls);


/**
 * Remove a mapping created with (mini)upnpc.  Calling
 * this function will give 'upnpc' 1s to remove the mapping,
 * so while this function is non-blocking, a task will be
 * left with the scheduler for up to 1s past this call.
 *
 * @param mini the handle
 */
void
GNUNET_NAT_mini_map_stop (struct GNUNET_NAT_MiniHandle *mini);


#endif
