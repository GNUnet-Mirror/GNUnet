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
#include "nat.h"
#include "nat_stun.h"


/**
 * Entry in DLL of addresses of this peer.
 */
struct AddrEntry
{

  /**
   * DLL.
   */
  struct AddrEntry *next;

  /**
   * DLL.
   */
  struct AddrEntry *prev;

  /**
   * Number of bytes that follow.
   */
  socklen_t addrlen;
};


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
   * Head of address DLL.
   */
  struct AddrEntry *ae_head;

  /**
   * Tail of address DLL.
   */
  struct AddrEntry *ae_tail;

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

  /**
   * Task scheduled to reconnect to the service.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * How long to wait until we reconnect.
   */
  struct GNUNET_TIME_Relative reconnect_delay;
};


/**
 * Task to connect to the NAT service.
 *
 * @param cls our `struct GNUNET_NAT_Handle *`
 */
static void
do_connect (void *cls);


/**
 * Task to connect to the NAT service.
 *
 * @param nh handle to reconnect
 */
static void
reconnect (struct GNUNET_NAT_Handle *nh)
{
  if (NULL != nh->mq)
  {
    GNUNET_MQ_destroy (nh->mq);
    nh->mq = NULL;
  }
  nh->reconnect_delay
    = GNUNET_TIME_STD_BACKOFF (nh->reconnect_delay);
  nh->reconnect_task
    = GNUNET_SCHEDULER_add_delayed (nh->reconnect_delay,
				    &do_connect,
				    nh);
}


/**
 * Check connection reversal request.
 *
 * @param cls our `struct GNUNET_NAT_Handle`
 * @param crm the message
 * @return #GNUNET_OK if @a crm is well-formed
 */
static int
check_connection_reversal_request (void *cls,
				   const struct GNUNET_NAT_ConnectionReversalRequestedMessage *crm)
{
  if (ntohs (crm->header.size) !=
      sizeof (*crm) +
      ntohs (crm->local_addr_size) +
      ntohs (crm->remote_addr_size) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if ( (sizeof (struct sockaddr_in) != ntohs (crm->local_addr_size)) ||
       (sizeof (struct sockaddr_in) != ntohs (crm->remote_addr_size)) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

  
/**
 * Handle connection reversal request.
 *
 * @param cls our `struct GNUNET_NAT_Handle`
 * @param crm the message
 */
static void
handle_connection_reversal_request (void *cls,
				    const struct GNUNET_NAT_ConnectionReversalRequestedMessage *crm)
{
  struct GNUNET_NAT_Handle *nh = cls;
  const struct sockaddr_in *local_sa = (const struct sockaddr_in *) &crm[1];
  const struct sockaddr_in *remote_sa = &local_sa[1];

  nh->reversal_callback (nh->callback_cls,
			 (const struct sockaddr *) local_sa,
			 sizeof (struct sockaddr_in),
			 (const struct sockaddr *) remote_sa,
			 sizeof (struct sockaddr_in));
}


/**
 * Check address change notification.
 *
 * @param cls our `struct GNUNET_NAT_Handle`
 * @param acn the message
 * @return #GNUNET_OK if @a crm is well-formed
 */
static int
check_address_change_notification (void *cls,
				   const struct GNUNET_NAT_AddressChangeNotificationMessage *acn)
{
  size_t alen = ntohs (acn->header.size) - sizeof (*acn);

  switch (alen)
  {
  case sizeof (struct sockaddr_in):
    {
      const struct sockaddr_in *s4
	= (const struct sockaddr_in *) &acn[1];
      if (AF_INET != s4->sin_family)
      {
	GNUNET_break (0);
	return GNUNET_SYSERR;
      }
    }
    break;
  case sizeof (struct sockaddr_in6):
    {
      const struct sockaddr_in6 *s6
	= (const struct sockaddr_in6 *) &acn[1];
      if (AF_INET6 != s6->sin6_family)
      {
	GNUNET_break (0);
	return GNUNET_SYSERR;
      }
    }
    break;
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

  
/**
 * Handle connection reversal request.
 *
 * @param cls our `struct GNUNET_NAT_Handle`
 * @param acn the message
 */
static void
handle_address_change_notification (void *cls,
				    const struct GNUNET_NAT_AddressChangeNotificationMessage *acn)
{
  struct GNUNET_NAT_Handle *nh = cls;
  size_t alen = ntohs (acn->header.size) - sizeof (*acn);
  const struct sockaddr *sa = (const struct sockaddr *) &acn[1];
  enum GNUNET_NAT_AddressClass ac;
  struct AddrEntry *ae;

  ac = (enum GNUNET_NAT_AddressClass) ntohl (acn->addr_class);
  if (GNUNET_YES == ntohl (acn->add_remove))
  {
    ae = GNUNET_malloc (sizeof (*ae) + alen);
    ae->addrlen = alen;
    GNUNET_memcpy (&ae[1],
		   sa,
		   alen);
    GNUNET_CONTAINER_DLL_insert (nh->ae_head,
				 nh->ae_tail,
				 ae);
  }
  else
  {
    for (ae = nh->ae_head; NULL != ae; ae = ae->next)
      if ( (ae->addrlen == alen) &&
	   (0 == memcmp (&ae[1],
			 sa,
			 alen)) )
	break;
    if (NULL == ae)
    {
      GNUNET_break (0);
      reconnect (nh);
      return;
    }
    GNUNET_CONTAINER_DLL_remove (nh->ae_head,
				 nh->ae_tail,
				 ae);
    GNUNET_free (ae);
  }
  nh->address_callback (nh->callback_cls,
			ntohl (acn->add_remove),
			ac,
			sa,
			alen);
}


/**
 * Handle queue errors by reconnecting to NAT.
 *
 * @param cls the `struct GNUNET_NAT_Handle *`
 * @param error details about the error
 */
static void
mq_error_handler (void *cls,
		  enum GNUNET_MQ_Error error)
{
  struct GNUNET_NAT_Handle *nh = cls;

  reconnect (nh);
}


/**
 * Task to connect to the NAT service.
 *
 * @param cls our `struct GNUNET_NAT_Handle *`
 */
static void
do_connect (void *cls)
{
  struct GNUNET_NAT_Handle *nh = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (connection_reversal_request,
			   GNUNET_MESSAGE_TYPE_NAT_CONNECTION_REVERSAL_REQUESTED,
			   struct GNUNET_NAT_ConnectionReversalRequestedMessage,
			   nh),
    GNUNET_MQ_hd_var_size (address_change_notification,
			   GNUNET_MESSAGE_TYPE_NAT_ADDRESS_CHANGE,
			   struct GNUNET_NAT_AddressChangeNotificationMessage,
			   nh),
    GNUNET_MQ_handler_end ()
  };

  nh->reconnect_task = NULL;
  nh->mq = GNUNET_CLIENT_connecT (nh->cfg,
				  "nat",
				  handlers,
				  &mq_error_handler,
				  nh);
  if (NULL == nh->mq)
    reconnect (nh);
}


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
  struct GNUNET_NAT_Handle *nh;
  struct GNUNET_NAT_RegisterMessage *rm;
  size_t len;
  char *off;
  
  len = 0;
  for (unsigned int i=0;i<num_addrs;i++)
    len += addrlens[i];
  if ( (len > GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (*rm)) ||
       (num_addrs > UINT16_MAX) )
  {
    GNUNET_break (0);
    return NULL;
  }
  rm = GNUNET_malloc (sizeof (*rm) + len);
  rm->header.size = htons (sizeof (*rm) + len);
  rm->header.type = htons (GNUNET_MESSAGE_TYPE_NAT_REGISTER);
  rm->flags = GNUNET_NAT_RF_NONE;
  if (NULL != address_callback)
    rm->flags |= GNUNET_NAT_RF_ADDRESSES;
  if (NULL != reversal_callback)
    rm->flags |= GNUNET_NAT_RF_REVERSAL;
  rm->proto = proto;
  rm->adv_port = htons (adv_port);
  rm->num_addrs = htons ((uint16_t) num_addrs);
  off = (char *) &rm[1];
  for (unsigned int i=0;i<num_addrs;i++)
  {
    GNUNET_memcpy (off,
		   addrs[i],
		   addrlens[i]);
    off += addrlens[i];
  }

  nh = GNUNET_new (struct GNUNET_NAT_Handle);
  nh->reg = &rm->header;
  nh->cfg = cfg;
  nh->address_callback = address_callback;
  nh->reversal_callback = reversal_callback;
  nh->callback_cls = callback_cls;
  do_connect (nh);
  GNUNET_break (0);
  return nh;
}


/**
 * Check if an incoming message is a STUN message.
 *
 * @param data the packet
 * @param len the length of the packet in @a data
 * @return #GNUNET_YES if @a data is a STUN packet,
 *         #GNUNET_NO if the packet is invalid (not a stun packet)
 */
static int
test_stun_packet (const void *data,
		  size_t len)
{
  const struct stun_header *hdr;
  const struct stun_attr *attr;
  uint32_t advertised_message_size;
  uint32_t message_magic_cookie;

  /* On entry, 'len' is the length of the UDP payload. After the
   * initial checks it becomes the size of unprocessed options,
   * while 'data' is advanced accordingly.
   */
  if (len < sizeof(struct stun_header))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"STUN packet too short (only %d, wanting at least %d)\n",
		(int) len,
		(int) sizeof (struct stun_header));
    return GNUNET_NO;
  }
  hdr = (const struct stun_header *) data;
  /* Skip header as it is already in hdr */
  len -= sizeof (struct stun_header);
  data += sizeof (struct stun_header);

  /* len as advertised in the message */
  advertised_message_size = ntohs (hdr->msglen);

  message_magic_cookie = ntohl (hdr->magic);
  /* Compare if the cookie match */
  if (STUN_MAGIC_COOKIE != message_magic_cookie)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Invalid magic cookie for STUN\n");
    return GNUNET_NO;
  }

  if (advertised_message_size > len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Scrambled STUN packet length (got %d, expecting %d)\n",
		advertised_message_size,
		(int)len);
    return GNUNET_NO;
  }
  len = advertised_message_size;
  while (len > 0)
  {
    if (len < sizeof (struct stun_attr))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Attribute too short in STUN packet (got %d, expecting %d)\n",
		  (int) len,
		  (int) sizeof(struct stun_attr));
      return GNUNET_NO;
    }
    attr = (const struct stun_attr *) data;

    /* compute total attribute length */
    advertised_message_size = ntohs (attr->len) + sizeof(struct stun_attr);

    /* Check if we still have space in our buffer */
    if (advertised_message_size > len)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Inconsistent Attribute (length %d exceeds remaining msg len %d)\n",
		  advertised_message_size,
		  (int) len);
      return GNUNET_NO;
    }
    data += advertised_message_size;
    len -= advertised_message_size;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "STUN Packet, msg %04x, length: %d\n",
	      ntohs (hdr->msgtype),
	      advertised_message_size);
  return GNUNET_OK;
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
                               size_t data_size)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_NAT_HandleStunMessage *hsn;
  char *buf;

  if (GNUNET_YES !=
      test_stun_packet (data,
			data_size))
    return GNUNET_NO;
  if (NULL == nh->mq)
    return GNUNET_SYSERR;
  env = GNUNET_MQ_msg_extra (hsn,
			     data_size + sender_addr_len,
			     GNUNET_MESSAGE_TYPE_NAT_HANDLE_STUN);
  hsn->sender_addr_size = htons ((uint16_t) sender_addr_len);
  hsn->payload_size = htons ((uint16_t) data_size);
  buf = (char *) &hsn[1];
  GNUNET_memcpy (buf,
		 sender_addr,
		 sender_addr_len);
  buf += sender_addr_len;
  GNUNET_memcpy (buf,
		 data,
		 data_size);
  GNUNET_MQ_send (nh->mq,
		  env);
  return GNUNET_OK;
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
  struct AddrEntry *ae;

  if ( (addrlen != sizeof (struct sockaddr_in)) &&
       (addrlen != sizeof (struct sockaddr_in6)) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  for (ae = nh->ae_head; NULL != ae; ae = ae->next)
    if ( (addrlen == ae->addrlen) &&
	 (0 == memcmp (addr,
		       &ae[1],
		       addrlen)) )
      return GNUNET_YES;
  return GNUNET_NO;
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
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_NAT_RequestConnectionReversalMessage *req;
  char *buf;

  if (NULL == nh->mq)
    return GNUNET_SYSERR;
  env = GNUNET_MQ_msg_extra (req,
			     2 * sizeof (struct sockaddr_in),
			     GNUNET_MESSAGE_TYPE_NAT_REQUEST_CONNECTION_REVERSAL);
  req->local_addr_size = htons (sizeof (struct sockaddr_in));
  req->remote_addr_size = htons (sizeof (struct sockaddr_in));
  buf = (char *) &req[1];
  GNUNET_memcpy (buf,
		 local_sa,
		 sizeof (struct sockaddr_in));
  buf += sizeof (struct sockaddr_in);
  GNUNET_memcpy (buf,
		 remote_sa,
		 sizeof (struct sockaddr_in));
  GNUNET_MQ_send (nh->mq,
		  env);
  return GNUNET_OK;
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
 * Handle result for a NAT test from the service.
 *
 * @param cls our `struct GNUNET_NAT_Test *`
 * @param rm message with the result of the test
 */
static void
handle_test_result (void *cls,
		    const struct GNUNET_NAT_TestResultMessage *rm)
{
  struct GNUNET_NAT_Test *tst = cls;
  enum GNUNET_NAT_StatusCode sc;

  sc = (enum GNUNET_NAT_StatusCode) ntohl (rm->status_code);
  tst->cb (tst->cb_cls,
	   sc);
  GNUNET_NAT_test_stop (tst);  
}
		    

/**
 * Handle queue errors by reporting test failure.
 *
 * @param cls the `struct GNUNET_NAT_Test *`
 * @param error details about the error
 */
static void
tst_error_handler (void *cls,
		  enum GNUNET_MQ_Error error)
{
  struct GNUNET_NAT_Test *tst = cls;

  tst->cb (tst->cb_cls,
	   GNUNET_NAT_ERROR_IPC_FAILURE);
  GNUNET_NAT_test_stop (tst);
}


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
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (test_result,
			     GNUNET_MESSAGE_TYPE_NAT_TEST_RESULT,
			     struct GNUNET_NAT_TestResultMessage,
			     tst),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_NAT_RequestTestMessage *req;

  tst->cb = report;
  tst->cb_cls = report_cls;
  tst->mq = GNUNET_CLIENT_connecT (cfg,
				   "nat",
				   handlers,
				   &tst_error_handler,
				   tst);
  if (NULL == tst->mq)
  {
    GNUNET_break (0);
    GNUNET_free (tst);
    return NULL;
  }
  env = GNUNET_MQ_msg (req,
		       GNUNET_MESSAGE_TYPE_NAT_REQUEST_TEST);
  req->bind_port = htons (bnd_port);
  req->extern_port = htons (extern_port);
  req->bind_ip = bind_ip;
  req->extern_ip = extern_ip;
  req->proto = proto;
  GNUNET_MQ_send (tst->mq,
		  env);
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
  switch (err)
  {
  case GNUNET_NAT_ERROR_SUCCESS:
    return _ ("Operation Successful");
  case GNUNET_NAT_ERROR_IPC_FAILURE:
    return _ ("Internal Failure (IPC, ...)");
  case GNUNET_NAT_ERROR_INTERNAL_NETWORK_ERROR:
    return _ ("Failure in network subsystem, check permissions.");
  case GNUNET_NAT_ERROR_TIMEOUT:
    return _ ("Encountered timeout while performing operation");
  case GNUNET_NAT_ERROR_NOT_ONLINE:
    return _ ("detected that we are offline");
  case GNUNET_NAT_ERROR_UPNPC_NOT_FOUND:
    return _ ("`upnpc` command not found");
  case GNUNET_NAT_ERROR_UPNPC_FAILED:
    return _ ("Failed to run `upnpc` command");
  case GNUNET_NAT_ERROR_UPNPC_TIMEOUT:
    return _ ("`upnpc' command took too long, process killed");
  case GNUNET_NAT_ERROR_UPNPC_PORTMAP_FAILED:
    return _ ("`upnpc' command failed to establish port mapping");
  case GNUNET_NAT_ERROR_EXTERNAL_IP_UTILITY_NOT_FOUND:
    return _ ("`external-ip' command not found");
  case GNUNET_NAT_ERROR_EXTERNAL_IP_UTILITY_FAILED:
    return _ ("Failed to run `external-ip` command");
  case GNUNET_NAT_ERROR_EXTERNAL_IP_UTILITY_OUTPUT_INVALID:
    return _ ("`external-ip' command output invalid");
  case GNUNET_NAT_ERROR_EXTERNAL_IP_ADDRESS_INVALID:
    return _ ("no valid address was returned by `external-ip'");
  case GNUNET_NAT_ERROR_NO_VALID_IF_IP_COMBO:
    return _ ("Could not determine interface with internal/local network address");
  case GNUNET_NAT_ERROR_HELPER_NAT_SERVER_NOT_FOUND:
    return _ ("No functioning gnunet-helper-nat-server installation found");
  case GNUNET_NAT_ERROR_NAT_TEST_START_FAILED:
    return _ ("NAT test could not be initialized");
  case GNUNET_NAT_ERROR_NAT_TEST_TIMEOUT:
    return _ ("NAT test timeout reached");
  case GNUNET_NAT_ERROR_NAT_REGISTER_FAILED:
    return _ ("could not register NAT");
  case GNUNET_NAT_ERROR_HELPER_NAT_CLIENT_NOT_FOUND:
    return _ ("No working gnunet-helper-nat-client installation found");
  default:
    return "unknown status code";
  }
}


/**
 * Check result from autoconfiguration attempt.
 *
 * @param cls the `struct GNUNET_NAT_AutoHandle`
 * @param res the result
 * @return #GNUNET_OK if @a res is well-formed (always for now)
 */
static int
check_auto_result (void *cls,
		   const struct GNUNET_NAT_AutoconfigResultMessage *res)
{
  return GNUNET_OK;
}


/**
 * Handle result from autoconfiguration attempt.
 *
 * @param cls the `struct GNUNET_NAT_AutoHandle`
 * @param res the result
 */
static void
handle_auto_result (void *cls,
		    const struct GNUNET_NAT_AutoconfigResultMessage *res)
{
  struct GNUNET_NAT_AutoHandle *ah = cls;
  size_t left;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  enum GNUNET_NAT_Type type
    = (enum GNUNET_NAT_Type) ntohl (res->type);
  enum GNUNET_NAT_StatusCode status
    = (enum GNUNET_NAT_StatusCode) ntohl (res->status_code);

  left = ntohs (res->header.size) - sizeof (*res);
  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_deserialize (cfg,
					(const char *) &res[1],
					left,
					GNUNET_NO))
  {
    GNUNET_break (0);
    ah->arc (ah->arc_cls,
	     NULL,
	     GNUNET_NAT_ERROR_IPC_FAILURE,
	     type);
  }
  else
  {
    ah->arc (ah->arc_cls,
	     cfg,
	     status,
	     type);
  }
  GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_NAT_autoconfig_cancel (ah);
}


/**
 * Handle queue errors by reporting autoconfiguration failure.
 *
 * @param cls the `struct GNUNET_NAT_AutoHandle *`
 * @param error details about the error
 */
static void
ah_error_handler (void *cls,
		  enum GNUNET_MQ_Error error)
{
  struct GNUNET_NAT_AutoHandle *ah = cls;

  ah->arc (ah->arc_cls,
	   NULL,
	   GNUNET_NAT_ERROR_IPC_FAILURE,
	   GNUNET_NAT_TYPE_UNKNOWN);
  GNUNET_NAT_autoconfig_cancel (ah);
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
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (auto_result,
			   GNUNET_MESSAGE_TYPE_NAT_AUTO_CFG_RESULT,
			   struct GNUNET_NAT_AutoconfigResultMessage,
			   ah),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_NAT_AutoconfigRequestMessage *req;
  char *buf;
  size_t size;

  buf = GNUNET_CONFIGURATION_serialize (cfg,
					&size);
  if (size > GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (*req))
  {
    GNUNET_break (0);
    GNUNET_free (buf);
    GNUNET_free (ah);
    return NULL;
  }
  ah->arc = cb;
  ah->arc_cls = cb_cls;
  ah->mq = GNUNET_CLIENT_connecT (cfg,
				  "nat",
				  handlers,
				  &ah_error_handler,
				  ah);
  if (NULL == ah->mq)
  {
    GNUNET_break (0);
    GNUNET_free (buf);
    GNUNET_free (ah);
    return NULL;
  }
  env = GNUNET_MQ_msg_extra (req,
			     size,
			     GNUNET_MESSAGE_TYPE_NAT_REQUEST_AUTO_CFG);
  GNUNET_memcpy (&req[1],
		 buf,
		 size);
  GNUNET_free (buf);
  GNUNET_MQ_send (ah->mq,
		  env);
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
  GNUNET_MQ_destroy (ah->mq);
  GNUNET_free (ah);
}

/* end of nat_api.c */
