/*
     This file is part of GNUnet.
     Copyright (C) 2007-2017 GNUnet e.V.

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
 * @author Christian Grothoff
 * @author Milan Bouchet-Valat
 *
 * @file
 * Service for testing and autoconfiguration of
 * NAT traversal functionality
 *
 * @defgroup nat  NAT testing library
 *
 * @{
 */

#ifndef GNUNET_NAT_AUTO_SERVICE_H
#define GNUNET_NAT_AUTO_SERVICE_H

#include "gnunet_util_lib.h"


/**
 * Handle to a NAT test.
 */
struct GNUNET_NAT_Test;


/**
 * Function called to report success or failure for
 * NAT configuration test.
 *
 * @param cls closure
 * @param result #GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 */
typedef void
(*GNUNET_NAT_TestCallback) (void *cls,
			    enum GNUNET_NAT_StatusCode result);


/**
 * Handle an incoming STUN message.  This function is useful as
 * some GNUnet service may be listening on a UDP port and might
 * thus receive STUN messages while trying to receive other data.
 * In this case, this function can be used to process replies
 * to STUN requests.
 *
 * The function does some basic sanity checks on packet size and
 * content, try to extract a bit of information.
 * 
 * At the moment this only processes BIND requests, and returns the
 * externally visible address of the request to the rest of the
 * NAT logic.
 *
 * @param nh handle to the NAT service
 * @param sender_addr address from which we got @a data
 * @param sender_addr_len number of bytes in @a sender_addr
 * @param data the packet
 * @param data_size number of bytes in @a data
 * @return #GNUNET_OK on success
 *         #GNUNET_NO if the packet is not a STUN packet
 *         #GNUNET_SYSERR on internal error handling the packet
 */
int
GNUNET_NAT_stun_handle_packet (struct GNUNET_NAT_Handle *nh,
			       const struct sockaddr *sender_addr,
			       size_t sender_addr_len,
			       const void *data,
                               size_t data_size);


/**
 * Handle to a request given to the resolver.  Can be used to cancel
 * the request prior to the timeout or successful execution.  Also
 * used to track our internal state for the request.
 */
struct GNUNET_NAT_STUN_Handle;


/**
 * Make Generic STUN request. Sends a generic stun request to the
 * server specified using the specified socket.  If we do this,
 * we need to watch for possible responses and call
 * #GNUNET_NAT_stun_handle_packet() on incoming packets.
 *
 * @param server the address of the stun server
 * @param port port of the stun server, in host byte order
 * @param sock the socket used to send the request, must be a
 *             UDP socket
 * @param cb callback in case of error
 * @param cb_cls closure for @a cb
 * @return NULL on error
 */
struct GNUNET_NAT_STUN_Handle *
GNUNET_NAT_stun_make_request (const char *server,
                              uint16_t port,
                              struct GNUNET_NETWORK_Handle *sock,
                              GNUNET_NAT_TestCallback cb,
                              void *cb_cls);


/**
 * Cancel active STUN request. Frees associated resources
 * and ensures that the callback is no longer invoked.
 *
 * @param rh request to cancel
 */
void
GNUNET_NAT_stun_make_request_cancel (struct GNUNET_NAT_STUN_Handle *rh);


/**
 * Start testing if NAT traversal works using the given configuration
 * (IPv4-only).  The transport adapters should be down while using
 * this function.
 *
 * @param cfg configuration for the NAT traversal
 * @param proto protocol to test, i.e. IPPROTO_TCP or IPPROTO_UDP
 * @param bind_ip IPv4 address to bind to
 * @param bnd_port port to bind to, 0 to test connection reversal
 * @param extern_ip IPv4 address to externally advertise
 * @param extern_port externally advertised port to use
 * @param report function to call with the result of the test
 * @param report_cls closure for @a report
 * @return handle to cancel NAT test
 */
struct GNUNET_NAT_Test *
GNUNET_NAT_test_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       uint8_t proto,
		       struct in_addr bind_ip,
                       uint16_t bnd_port,
		       struct in_addr extern_ip,
                       uint16_t extern_port,
                       GNUNET_NAT_TestCallback report,
                       void *report_cls);


/**
 * Stop an active NAT test.
 *
 * @param tst test to stop.
 */
void
GNUNET_NAT_test_stop (struct GNUNET_NAT_Test *tst);


/**
 * Handle to auto-configuration in progress.
 */
struct GNUNET_NAT_AutoHandle;


/**
 * Converts `enum GNUNET_NAT_StatusCode` to string
 *
 * @param err error code to resolve to a string
 * @return point to a static string containing the error code
 */
const char *
GNUNET_NAT_status2string (enum GNUNET_NAT_StatusCode err);


/**
 * Function called with the result from the autoconfiguration.
 *
 * @param cls closure
 * @param diff minimal suggested changes to the original configuration
 *             to make it work (as best as we can)
 * @param result #GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 * @param type what the situation of the NAT
 */
typedef void
(*GNUNET_NAT_AutoResultCallback)(void *cls,
                                 const struct GNUNET_CONFIGURATION_Handle *diff,
                                 enum GNUNET_NAT_StatusCode result,
                                 enum GNUNET_NAT_Type type);


/**
 * Start auto-configuration routine.  The transport adapters should
 * be stopped while this function is called.
 *
 * @param cfg initial configuration
 * @param cb function to call with autoconfiguration result
 * @param cb_cls closure for @a cb
 * @return handle to cancel operation
 */
struct GNUNET_NAT_AutoHandle *
GNUNET_NAT_autoconfig_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
			     GNUNET_NAT_AutoResultCallback cb,
			     void *cb_cls);


/**
 * Abort autoconfiguration.
 *
 * @param ah handle for operation to abort
 */
void
GNUNET_NAT_autoconfig_cancel (struct GNUNET_NAT_AutoHandle *ah);


#endif

/** @} */  /* end of group */

/* end of gnunet_nat_auto_service.h */
