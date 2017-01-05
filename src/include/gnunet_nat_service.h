/*
     This file is part of GNUnet.
     Copyright (C) 2007-2016 GNUnet e.V.

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
 * Service for handling UPnP and NAT-PMP port forwarding
 * and external IP address retrieval
 *
 * @defgroup nat  NAT library
 * Service for handling UPnP and NAT-PMP port forwarding
 * and external IP address retrieval
 *
 * @{
 */

#ifndef GNUNET_NAT_SERVICE_H
#define GNUNET_NAT_SERVICE_H

#include "gnunet_util_lib.h"


/**
 * Some addresses contain sensitive information or are
 * not suitable for global distribution.  We use address
 * classes to filter addresses by which domain they make
 * sense to be used in.  These are used in a bitmask.
 *
 * FIXME: might want to define this elsewhere; we have
 * an equivalent enum in gnunet_transport_hello_service.h;
 * might ultimately belong with the new HELLO definition.
 */
enum GNUNET_NAT_AddressClass
{

  /**
   * No address.
   */
  GNUNET_NAT_AC_NONE = 0,

  /**
   * Addresses that fall into no other category
   * (i.e. incoming which we cannot use elsewhere).
   */
  GNUNET_NAT_AC_OTHER = 1,

  /**
   * Flag for addresses that are highly sensitive
   * (i.e. IPv6 with our MAC).
   */
  GNUNET_NAT_AC_PRIVATE = 2,

  /**
   * Addresses that are global (i.e. IPv4).
   */
  GNUNET_NAT_AC_GLOBAL = 4,

  /**
   * Addresses that are global and are sensitive
   * (i.e. IPv6 with our MAC).
   */
  GNUNET_NAT_AC_GLOBAL_PRIVATE = 6,

  /**
   * Addresses useful in the local wired network,
   * i.e. a MAC.  Sensitive, but obvious to people nearby.
   *
   * Useful for broadcasts.
   */
  GNUNET_NAT_AC_LAN = 8,
  
  /**
   * Addresses useful in the local wired network,
   * i.e. a MAC.  Sensitive, but obvious to people nearby.
   * Useful for broadcasts.
   */
  GNUNET_NAT_AC_LAN_PRIVATE = 10,

  /**
   * Addresses useful in the local wireless network,
   * i.e. a MAC.  Sensitive, but obvious to people nearby.
   * Useful for broadcasts.
   */
  GNUNET_NAT_AC_WLAN = 16,

  /**
   * Addresses useful in the local bluetooth network.  Sensitive, but
   * obvious to people nearby.  Useful for broadcasts.
   */
  GNUNET_NAT_AC_BT = 32,

  /**
   * Loopback addresses, only useful under special cirumstances.
   */
  GNUNET_NAT_AC_LOOPBACK = 64,
  
  /**
   * Addresses that should be our external IP address
   * on the outside of a NAT.  Might be incorrectly determined.
   * Used as a bit in combination with #GNUNET_NAT_AC_GLOBAL,
   * or in case of double-NAT with 
   * #GNUNET_NAT_AC_LAN.
   */
  GNUNET_NAT_AC_EXTERN = 128,

  /**
   * Addresses that were manually configured by the user.
   * Used as a bit in combination with #GNUNET_NAT_AC_GLOBAL.
   */
  GNUNET_NAT_AC_MANUAL = 256,

  /**
   * Bitmask for "any" address.
   */
  GNUNET_NAT_AC_ANY = 65535
  
};


/**
 * Signature of the callback passed to #GNUNET_NAT_register() for
 * a function to call whenever our set of 'valid' addresses changes.
 *
 * @param cls closure
 * @param add_remove #GNUNET_YES to add a new public IP address, 
 *                   #GNUNET_NO to remove a previous (now invalid) one
 * @param ac address class the address belongs to
 * @param addr either the previous or the new public IP address
 * @param addrlen actual length of the @a addr
 */
typedef void
(*GNUNET_NAT_AddressCallback) (void *cls,
                               int add_remove,
			       enum GNUNET_NAT_AddressClass ac,
                               const struct sockaddr *addr,
                               socklen_t addrlen);


/**
 * Signature of the callback passed to #GNUNET_NAT_register().
 * for a function to call whenever someone asks us to do connection
 * reversal.
 *
 * @param cls closure
 * @param remote_addr public IP address of the other peer
 * @param remote_addrlen actual length of the @a remote_addr
 */
typedef void
(*GNUNET_NAT_ReversalCallback) (void *cls,
				const struct sockaddr *remote_addr,
                                socklen_t remote_addrlen);


/**
 * Handle for active NAT registrations.
 */
struct GNUNET_NAT_Handle;


/**
 * Attempt to enable port redirection and detect public IP address
 * contacting UPnP or NAT-PMP routers on the local network. Use @a
 * addr to specify to which of the local host's addresses should the
 * external port be mapped. The port is taken from the corresponding
 * sockaddr_in[6] field.  The NAT module should call the given @a
 * address_callback for any 'plausible' external address.
 *
 * @param cfg configuration to use
 * @param config_section name of the configuration section for optionsx
 * @param proto protocol this is about, IPPROTO_TCP or IPPROTO_UDP
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
                     const char *config_section,
                     uint8_t proto,
                     unsigned int num_addrs,
                     const struct sockaddr **addrs,
                     const socklen_t *addrlens,
                     GNUNET_NAT_AddressCallback address_callback,
                     GNUNET_NAT_ReversalCallback reversal_callback,
                     void *callback_cls);


/**
 * Test if the given address is (currently) a plausible IP address for
 * this peer.  Mostly a convenience function so that clients do not
 * have to explicitly track all IPs that the #GNUNET_NAT_AddressCallback
 * has returned so far.
 *
 * @param nh the handle returned by register
 * @param addr IP address to test (IPv4 or IPv6)
 * @param addrlen number of bytes in @a addr
 * @return #GNUNET_YES if the address is plausible,
 *         #GNUNET_NO if the address is not plausible,
 *         #GNUNET_SYSERR if the address is malformed
 */
int
GNUNET_NAT_test_address (struct GNUNET_NAT_Handle *nh,
                         const void *addr,
                         socklen_t addrlen);


/**
 * We learned about a peer (possibly behind NAT) so run the
 * gnunet-nat-client to send dummy ICMP responses to cause
 * that peer to connect to us (connection reversal).
 *
 * @param nh handle (used for configuration)
 * @param local_sa our local address of the peer (IPv4-only)
 * @param remote_sa the remote address of the peer (IPv4-only)
 * @return #GNUNET_SYSERR on error, 
 *         #GNUNET_NO if connection reversal is unavailable,
 *         #GNUNET_OK otherwise (presumably in progress)
 */
int
GNUNET_NAT_request_reversal (struct GNUNET_NAT_Handle *nh,
			     const struct sockaddr_in *local_sa,
			     const struct sockaddr_in *remote_sa);


/**
 * Stop port redirection and public IP address detection for the given
 * handle.  This frees the handle, after having sent the needed
 * commands to close open ports.
 *
 * @param nh the handle to unregister
 */
void
GNUNET_NAT_unregister (struct GNUNET_NAT_Handle *nh);


/**
 * Handle to a NAT test.
 */
struct GNUNET_NAT_Test;


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
  GNUNET_NAT_ERROR_HELPER_NAT_CLIENT_NOT_FOUND
  
};


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
 * What the situation of the NAT connectivity
 */
enum GNUNET_NAT_Type
{
  /**
   * We have a direct connection
   */
  GNUNET_NAT_TYPE_NO_NAT = GNUNET_OK,

  /**
   * We are under a NAT but cannot traverse it
   */
  GNUNET_NAT_TYPE_UNREACHABLE_NAT,

  /**
   * We can traverse using STUN
   */
  GNUNET_NAT_TYPE_STUN_PUNCHED_NAT,

  /**
   * We can traverse using UPNP
   */
  GNUNET_NAT_TYPE_UPNP_NAT,

  /**
   * We know nothing about the NAT.
   */
  GNUNET_NAT_TYPE_UNKNOWN

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

/* end of gnunet_nat_service.h */
