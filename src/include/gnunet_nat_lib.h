/*
     This file is part of GNUnet.
     (C) 2007, 2008, 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_nat_lib.h
 * @brief Library handling UPnP and NAT-PMP port forwarding and
 *     external IP address retrieval
 *
 * @author Milan Bouchet-Valat
 */

#ifndef GNUNET_NAT_LIB_H
#define GNUNET_NAT_LIB_H

#include "gnunet_util_lib.h"

/**
 * Signature of the callback passed to GNUNET_NAT_register for
 * a function to call whenever our set of 'valid' addresses changes.
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
 * Signature of the callback passed to GNUNET_NAT_register
 * for a function to call whenever someone asks us to do connection
 * reversal.
 *
 * @param cls closure
 * @param addr public IP address of the other peer
 * @param addrlen actual lenght of the address
 */
typedef void (*GNUNET_NAT_ReversalCallback) (void *cls,
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
 * is taken from the corresponding sockaddr_in[6] field.  The NAT module
 * should call the given callback for any 'plausible' external address.
 *
 * @param cfg configuration to use
 * @param is_tcp GNUNET_YES for TCP, GNUNET_NO for UDP
 * @param adv_port advertised port (port we are either bound to or that our OS
 *                 locally performs redirection from to our bound port).
 * @param num_addrs number of addresses in 'addrs'
 * @param addrs list of local addresses packets should be redirected to
 * @param addrlens actual lengths of the addresses
 * @param address_callback function to call everytime the public IP address changes
 * @param reversal_callback function to call if someone wants connection reversal from us,
 *        NULL if connection reversal is not supported
 * @param callback_cls closure for callback
 * @return NULL on error, otherwise handle that can be used to unregister
 */
struct GNUNET_NAT_Handle *
GNUNET_NAT_register (const struct GNUNET_CONFIGURATION_Handle *cfg, int is_tcp,
                     uint16_t adv_port, unsigned int num_addrs,
                     const struct sockaddr **addrs, const socklen_t * addrlens,
                     GNUNET_NAT_AddressCallback address_callback,
                     GNUNET_NAT_ReversalCallback reversal_callback,
                     void *callback_cls);


/**
 * Test if the given address is (currently) a plausible IP address for this peer.
 *
 * @param h the handle returned by register
 * @param addr IP address to test (IPv4 or IPv6)
 * @param addrlen number of bytes in addr
 * @return GNUNET_YES if the address is plausible,
 *         GNUNET_NO if the address is not plausible,
 *         GNUNET_SYSERR if the address is malformed
 */
int
GNUNET_NAT_test_address (struct GNUNET_NAT_Handle *h, const void *addr,
                         socklen_t addrlen);


/**
 * We learned about a peer (possibly behind NAT) so run the
 * gnunet-nat-client to send dummy ICMP responses to cause
 * that peer to connect to us (connection reversal).
 *
 * @param h handle (used for configuration)
 * @param sa the address of the peer (IPv4-only)
 */
void
GNUNET_NAT_run_client (struct GNUNET_NAT_Handle *h,
                       const struct sockaddr_in *sa);



/**
 * Stop port redirection and public IP address detection for the given handle.
 * This frees the handle, after having sent the needed commands to close open ports.
 *
 * @param h the handle to stop
 */
void
GNUNET_NAT_unregister (struct GNUNET_NAT_Handle *h);


/**
 * Handle to a NAT test.
 */
struct GNUNET_NAT_Test;

/**
 * Function called to report success or failure for
 * NAT configuration test.
 *
 * @param cls closure
 * @param success GNUNET_OK on success, GNUNET_NO on failure,
 *                GNUNET_SYSERR if the test could not be
 *                properly started (internal failure)
 */
typedef void (*GNUNET_NAT_TestCallback) (void *cls, int success);

/**
 * Start testing if NAT traversal works using the
 * given configuration (IPv4-only).
 *
 * @param cfg configuration for the NAT traversal
 * @param is_tcp GNUNET_YES to test TCP, GNUNET_NO to test UDP
 * @param bnd_port port to bind to, 0 for connection reversal
 * @param adv_port externally advertised port to use
 * @param report function to call with the result of the test
 * @param report_cls closure for report
 * @return handle to cancel NAT test
 */
struct GNUNET_NAT_Test *
GNUNET_NAT_test_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       int is_tcp, uint16_t bnd_port, uint16_t adv_port,
                       GNUNET_NAT_TestCallback report, void *report_cls);


/**
 * Stop an active NAT test.
 *
 * @param tst test to stop.
 */
void
GNUNET_NAT_test_stop (struct GNUNET_NAT_Test *tst);


/**
 * Signature of a callback that is given an IP address.
 *
 * @param cls closure
 * @param addr the address, NULL on errors
 */
typedef void (*GNUNET_NAT_IPCallback) (void *cls, const struct in_addr * addr);



/**
 * Opaque handle to cancel "GNUNET_NAT_mini_get_external_ipv4" operation.
 */
struct GNUNET_NAT_ExternalHandle;


/**
 * Try to get the external IPv4 address of this peer.
 *
 * @param timeout when to fail
 * @param cb function to call with result
 * @param cb_cls closure for 'cb'
 * @return handle for cancellation (can only be used until 'cb' is called), NULL on error
 */
struct GNUNET_NAT_ExternalHandle *
GNUNET_NAT_mini_get_external_ipv4 (struct GNUNET_TIME_Relative timeout,
                                   GNUNET_NAT_IPCallback cb, void *cb_cls);


/**
 * Cancel operation.
 *
 * @param eh operation to cancel
 */
void
GNUNET_NAT_mini_get_external_ipv4_cancel (struct GNUNET_NAT_ExternalHandle *eh);


/**
 * Handle to a mapping created with upnpc.
 */
struct GNUNET_NAT_MiniHandle;


/**
 * Start mapping the given port using (mini)upnpc.  This function
 * should typically not be used directly (it is used within the
 * general-purpose 'GNUNET_NAT_register' code).  However, it can be
 * used if specifically UPnP-based NAT traversal is to be used or
 * tested.
 *
 * @param port port to map
 * @param is_tcp GNUNET_YES to map TCP, GNUNET_NO for UDP
 * @param ac function to call with mapping result
 * @param ac_cls closure for 'ac'
 * @return NULL on error
 */
struct GNUNET_NAT_MiniHandle *
GNUNET_NAT_mini_map_start (uint16_t port, int is_tcp,
                           GNUNET_NAT_AddressCallback ac, void *ac_cls);


/**
 * Remove a mapping created with (mini)upnpc.  Calling
 * this function will give 'upnpc' 1s to remove tha mapping,
 * so while this function is non-blocking, a task will be
 * left with the scheduler for up to 1s past this call.
 *
 * @param mini the handle
 */
void
GNUNET_NAT_mini_map_stop (struct GNUNET_NAT_MiniHandle *mini);


#endif

/* end of gnunet_nat_lib.h */
