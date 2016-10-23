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
 * @file nat/nat_api.c
 * Service for handling UPnP and NAT-PMP port forwarding
 * and external IP address retrieval
 */
#include "platform.h"
#include "gnunet_nat_service.h"


/**
 * Handle for active NAT registrations.
 */
struct GNUNET_NAT_Handle
{

  /**
   * Configuration we use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  
  /**
   * Message queue for communicating with the NAT service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Our registration message.
   */
  struct GNUNET_MessageHeader *reg;
  
  /**
   * Function to call when our addresses change.
   */
  GNUNET_NAT_AddressCallback address_callback;
  
  /**
   * Function to call when another peer requests connection reversal.
   */
  GNUNET_NAT_ReversalCallback reversal_callback;
  
  /**
   * Closure for the various callbacks.
   */
  void *callback_cls;

};


/**
 * Attempt to enable port redirection and detect public IP address
 * contacting UPnP or NAT-PMP routers on the local network. Use @a
 * addr to specify to which of the local host's addresses should the
 * external port be mapped. The port is taken from the corresponding
 * sockaddr_in[6] field.  The NAT module should call the given @a
 * address_callback for any 'plausible' external address.
 *
 * @param cfg configuration to use
 * @param proto protocol this is about, IPPROTO_TCP or IPPROTO_UDP
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
                     uint8_t proto,
                     uint16_t adv_port,
                     unsigned int num_addrs,
                     const struct sockaddr **addrs,
                     const socklen_t *addrlens,
                     GNUNET_NAT_AddressCallback address_callback,
                     GNUNET_NAT_ReversalCallback reversal_callback,
                     void *callback_cls)
{
  struct GNUNET_NAT_Handle *nh = GNUNET_new (struct GNUNET_NAT_Handle);

  nh->cfg = cfg;
  nh->address_callback = address_callback;
  nh->reversal_callback = reversal_callback;
  nh->callback_cls = callback_cls;
  GNUNET_break (0);
  return nh;
}


/**
 * Handle an incoming STUN message.  This function is useful as
 * some GNUnet service may be listening on a UDP port and might
 * thus receive STUN messages while trying to receive other data.
 * In this case, this function can be used to act as a proper
 * STUN server (if desired).
 *
 * The function does some basic sanity checks on packet size and
 * content, try to extract a bit of information, and possibly replies
 * if this is an actual STUN message.
 * 
 * At the moment this only processes BIND requests, and returns the
 * externally visible address of the request. 
 *
 * @param nh handle to the NAT service
 * @param sender_addr address from which we got @a data
 * @param data the packet
 * @param data_size number of bytes in @a data
 * @return #GNUNET_OK on success
 *         #GNUNET_NO if the packet is not a STUN packet
 *         #GNUNET_SYSERR on internal error handling the packet
 */
int
GNUNET_NAT_stun_handle_packet (struct GNUNET_NAT_Handle *nh,
			       const struct sockaddr *sender_addr,
			       const void *data,
                               size_t data_size)
{
  GNUNET_break (0);
  return GNUNET_SYSERR;
}


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
                         socklen_t addrlen)
{
  GNUNET_break (0);
  return GNUNET_SYSERR;
}


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
			     const struct sockaddr_in *remote_sa)
{
  GNUNET_break (0);
  return GNUNET_SYSERR;
}


/**
 * Stop port redirection and public IP address detection for the given
 * handle.  This frees the handle, after having sent the needed
 * commands to close open ports.
 *
 * @param nh the handle to stop
 */
void
GNUNET_NAT_unregister (struct GNUNET_NAT_Handle *nh)
{
  GNUNET_MQ_destroy (nh->mq);
  GNUNET_free (nh->reg);
  GNUNET_free (nh);
}


/**
 * Handle to a NAT test.
 */
struct GNUNET_NAT_Test
{

  /**
   * Configuration we use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  
  /**
   * Message queue for communicating with the NAT service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Function called to report success or failure for
   * NAT configuration test.
   */
  GNUNET_NAT_TestCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

};


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
                       void *report_cls)
{
  struct GNUNET_NAT_Test *tst = GNUNET_new (struct GNUNET_NAT_Test);

  tst->cb = report;
  tst->cb_cls = report_cls;
  GNUNET_break (0);
  return tst;
}


/**
 * Stop an active NAT test.
 *
 * @param tst test to stop.
 */
void
GNUNET_NAT_test_stop (struct GNUNET_NAT_Test *tst)
{
  GNUNET_break (0);
  GNUNET_MQ_destroy (tst->mq);
  GNUNET_free (tst);
}


/**
 * Handle to auto-configuration in progress.
 */
struct GNUNET_NAT_AutoHandle
{

  /**
   * Configuration we use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  
  /**
   * Message queue for communicating with the NAT service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Function called with the result from the autoconfiguration.
   */
  GNUNET_NAT_AutoResultCallback arc;

  /**
   * Closure for @e arc.
   */
  void *arc_cls;

};


/**
 * Converts `enum GNUNET_NAT_StatusCode` to string
 *
 * @param err error code to resolve to a string
 * @return point to a static string containing the error code
 */
const char *
GNUNET_NAT_status2string (enum GNUNET_NAT_StatusCode err)
{
  GNUNET_break (0);
  return NULL;
}


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
			     void *cb_cls)
{
  struct GNUNET_NAT_AutoHandle *ah = GNUNET_new (struct GNUNET_NAT_AutoHandle);

  ah->cfg = cfg;
  ah->arc = cb;
  ah->arc_cls = cb_cls;
  GNUNET_break (0);
  return ah;
}


/**
 * Abort autoconfiguration.
 *
 * @param ah handle for operation to abort
 */
void
GNUNET_NAT_autoconfig_cancel (struct GNUNET_NAT_AutoHandle *ah)
{
  GNUNET_break (0);
  GNUNET_MQ_destroy (ah->mq);
  GNUNET_free (ah);
}

/* end of nat_api.c */
