/*
     This file is part of GNUnet.
     (C) 2007-2014 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 * @author Milan Bouchet-Valat
 */

#ifndef GNUNET_NAT_LIB_H
#define GNUNET_NAT_LIB_H

#include "gnunet_util_lib.h"


/**
 * Signature of the callback passed to #GNUNET_NAT_register() for
 * a function to call whenever our set of 'valid' addresses changes.
 *
 * @param cls closure
 * @param add_remove #GNUNET_YES to mean the new public IP address, #GNUNET_NO to mean
 *     the previous (now invalid) one
 * @param addr either the previous or the new public IP address
 * @param addrlen actual length of the @a addr
 */
typedef void
(*GNUNET_NAT_AddressCallback) (void *cls,
                               int add_remove,
                               const struct sockaddr *addr,
                               socklen_t addrlen);


/**
 * Signature of the callback passed to #GNUNET_NAT_register().
 * for a function to call whenever someone asks us to do connection
 * reversal.
 *
 * @param cls closure
 * @param addr public IP address of the other peer
 * @param addrlen actual lenght of the @a addr
 */
typedef void
(*GNUNET_NAT_ReversalCallback) (void *cls,
                                const struct sockaddr *addr,
                                socklen_t addrlen);


/**
 * Handle for active NAT registrations.
 */
struct GNUNET_NAT_Handle;


/**
 * Error Types for the NAT subsystem (which can then later be converted/resolved to a string)
 */
enum GNUNET_NAT_StatusCode
{
  /**
   * Just the default
   */
  GNUNET_NAT_ERROR_SUCCESS = GNUNET_OK,

  /**
   * IPC Failure
   */
  GNUNET_NAT_ERROR_IPC_FAILURE,

  /**
   * Failure in network subsystem, check permissions
   */
  GNUNET_NAT_ERROR_INTERNAL_NETWORK_ERROR,

  /**
   * test timed out
   */
  GNUNET_NAT_ERROR_TIMEOUT,

  /**
   * detected that we are offline
   */
  GNUNET_NAT_ERROR_NOT_ONLINE,

  /**
   * `upnpc` command not found
   */
  GNUNET_NAT_ERROR_UPNPC_NOT_FOUND,

  /**
   * Failed to run `upnpc` command
   */
  GNUNET_NAT_ERROR_UPNPC_FAILED,

  /**
   * `upnpc' command took too long, process killed
   */
  GNUNET_NAT_ERROR_UPNPC_TIMEOUT,

  /**
   * `upnpc' command failed to establish port mapping
   */
  GNUNET_NAT_ERROR_UPNPC_PORTMAP_FAILED,

  /**
   * `external-ip' command not found
   */
  GNUNET_NAT_ERROR_EXTERNAL_IP_UTILITY_NOT_FOUND,

  /**
   * Failed to run `external-ip` command
   */
  GNUNET_NAT_ERROR_EXTERNAL_IP_UTILITY_FAILED,

  /**
   * `external-ip' command output invalid
   */
  GNUNET_NAT_ERROR_EXTERNAL_IP_UTILITY_OUTPUT_INVALID,

  /**
   * "no valid address was returned by `external-ip'"
   */
  GNUNET_NAT_ERROR_EXTERNAL_IP_ADDRESS_INVALID,

  /**
   * Could not determine interface with internal/local network address
   */
  GNUNET_NAT_ERROR_NO_VALID_IF_IP_COMBO,

  /**
   * No working gnunet-helper-nat-server found
   */
  GNUNET_NAT_ERROR_HELPER_NAT_SERVER_NOT_FOUND,

  /**
   * NAT test could not be initialized
   */
  GNUNET_NAT_ERROR_NAT_TEST_START_FAILED,

  /**
   * NAT test timeout
   */
  GNUNET_NAT_ERROR_NAT_TEST_TIMEOUT,

  /**
   * NAT test failed to initiate
   */
  GNUNET_NAT_ERROR_NAT_REGISTER_FAILED,

  /**
   *
   */
  GNUNET_NAT_ERROR_HELPER_NAT_CLIENT_NOT_FOUND,

  /**
   *
   */
  GNUNET_NAT_ERROR_
};


/**
 * Converts `enum GNUNET_NAT_StatusCode` to string
 *
 * @param err error code to resolve to a string
 * @return point to a static string containing the error code
 */
const char *
GNUNET_NAT_status2string (enum GNUNET_NAT_StatusCode err);


/**
 * Attempt to enable port redirection and detect public IP address
 * contacting UPnP or NAT-PMP routers on the local network. Use addr
 * to specify to which of the local host's addresses should the
 * external port be mapped. The port is taken from the corresponding
 * sockaddr_in[6] field.  The NAT module should call the given
 * callback for any 'plausible' external address.
 *
 * @param cfg configuration to use
 * @param is_tcp #GNUNET_YES for TCP, #GNUNET_NO for UDP
 * @param adv_port advertised port (port we are either bound to or that our OS
 *                 locally performs redirection from to our bound port).
 * @param num_addrs number of addresses in @a addrs
 * @param addrs list of local addresses packets should be redirected to
 * @param addrlens actual lengths of the addresses in @a addrs
 * @param address_callback function to call everytime the public IP address changes
 * @param reversal_callback function to call if someone wants connection reversal from us,
 *        NULL if connection reversal is not supported
 * @param callback_cls closure for callbacks
 * @return NULL on error, otherwise handle that can be used to unregister
 */
struct GNUNET_NAT_Handle *
GNUNET_NAT_register (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     int is_tcp,
                     uint16_t adv_port,
                     unsigned int num_addrs,
                     const struct sockaddr **addrs,
                     const socklen_t *addrlens,
                     GNUNET_NAT_AddressCallback address_callback,
                     GNUNET_NAT_ReversalCallback reversal_callback,
                     void *callback_cls);


/**
 * Test if the given address is (currently) a plausible IP address for
 * this peer.
 *
 * @param h the handle returned by register
 * @param addr IP address to test (IPv4 or IPv6)
 * @param addrlen number of bytes in @a addr
 * @return #GNUNET_YES if the address is plausible,
 *         #GNUNET_NO if the address is not plausible,
 *         #GNUNET_SYSERR if the address is malformed
 */
int
GNUNET_NAT_test_address (struct GNUNET_NAT_Handle *h,
                         const void *addr,
                         socklen_t addrlen);


/**
 * We learned about a peer (possibly behind NAT) so run the
 * gnunet-nat-client to send dummy ICMP responses to cause
 * that peer to connect to us (connection reversal).
 *
 * @param h handle (used for configuration)
 * @param sa the address of the peer (IPv4-only)
 * @return #GNUNET_SYSERR on error, #GNUNET_NO if nat client is disabled,
 *         #GNUNET_OK otherwise
 */
int
GNUNET_NAT_run_client (struct GNUNET_NAT_Handle *h,
                       const struct sockaddr_in *sa);


/**
 * Stop port redirection and public IP address detection for the given
 * handle.  This frees the handle, after having sent the needed
 * commands to close open ports.
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
 * @param result #GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 */
typedef void (*GNUNET_NAT_TestCallback) (void *cls,
                                         enum GNUNET_NAT_StatusCode result);


/**
 * Start testing if NAT traversal works using the
 * given configuration (IPv4-only).
 *
 * @param cfg configuration for the NAT traversal
 * @param is_tcp #GNUNET_YES to test TCP, #GNUNET_NO to test UDP
 * @param bnd_port port to bind to, 0 for connection reversal
 * @param adv_port externally advertised port to use
 * @param timeout delay after which the test should be aborted
 * @param report function to call with the result of the test;
 *               you still must call #GNUNET_NAT_test_stop().
 * @param report_cls closure for @a report
 * @return handle to cancel NAT test
 */
struct GNUNET_NAT_Test *
GNUNET_NAT_test_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       int is_tcp,
                       uint16_t bnd_port,
                       uint16_t adv_port,
                       struct GNUNET_TIME_Relative timeout,
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
 * Signature of a callback that is given an IP address.
 *
 * @param cls closure
 * @param addr the address, NULL on errors
 * @param result GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 */
typedef void (*GNUNET_NAT_IPCallback) (void *cls,
                                       const struct in_addr *addr,
                                       enum GNUNET_NAT_StatusCode result);



/**
 * Opaque handle to cancel #GNUNET_NAT_mini_get_external_ipv4() operation.
 */
struct GNUNET_NAT_ExternalHandle;


/**
 * Try to get the external IPv4 address of this peer.
 *
 * @param timeout when to fail
 * @param cb function to call with result
 * @param cb_cls closure for @a cb
 * @return handle for cancellation (can only be used until @a cb is called), NULL on error
 */
struct GNUNET_NAT_ExternalHandle *
GNUNET_NAT_mini_get_external_ipv4 (struct GNUNET_TIME_Relative timeout,
                                   GNUNET_NAT_IPCallback cb,
                                   void *cb_cls);


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
 * Signature of the callback passed to #GNUNET_NAT_register() for
 * a function to call whenever our set of 'valid' addresses changes.
 *
 * @param cls closure
 * @param add_remove #GNUNET_YES to mean the new public IP address, #GNUNET_NO to mean
 *     the previous (now invalid) one, #GNUNET_SYSERR indicates an error
 * @param addr either the previous or the new public IP address
 * @param addrlen actual length of the @a addr
 * @param result GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
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


/**
 * Handle to auto-configuration in progress.
 */
struct GNUNET_NAT_AutoHandle;


/**
 * Function called with the result from the autoconfiguration.
 *
 * @param cls closure
 * @param diff minimal suggested changes to the original configuration
 *             to make it work (as best as we can)
 * @param result GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 */
typedef void
(*GNUNET_NAT_AutoResultCallback)(void *cls,
                                 const struct GNUNET_CONFIGURATION_Handle *diff,
                                 enum GNUNET_NAT_StatusCode result);


/**
 * Start auto-configuration routine.  The resolver service should
 * be available when this function is called.
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

/* end of gnunet_nat_lib.h */
