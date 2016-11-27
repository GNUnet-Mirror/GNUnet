/*
  This file is part of GNUnet.
  Copyright (C) 2016 GNUnet e.V.

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
 * @file nat/gnunet-service-nat.c
 * @brief network address translation traversal service
 * @author Christian Grothoff
 *
 * The purpose of this service is to enable transports to 
 * traverse NAT routers, by providing traversal options and
 * knowledge about the local network topology.
 */
#include "platform.h"
#include <math.h>
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_nat_service.h"
#include "nat.h"
#include <gcrypt.h>


/**
 * How often should we ask the OS about a list of active
 * network interfaces?
 */
#define SCAN_FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)


/**
 * Internal data structure we track for each of our clients.
 */
struct ClientHandle
{

  /**
   * Kept in a DLL.
   */
  struct ClientHandle *next;
  
  /**
   * Kept in a DLL.
   */
  struct ClientHandle *prev;

  /**
   * Underlying handle for this client with the service.
   */ 
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue for communicating with the client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Array of addresses used by the service.
   */
  struct sockaddr **addrs;
  
  /**
   * What does this client care about?
   */
  enum GNUNET_NAT_RegisterFlags flags;

  /**
   * Port we would like as we are configured to use this one for
   * advertising (in addition to the one we are binding to).
   */
  uint16_t adv_port;

  /**
   * Number of addresses that this service is bound to.
   */
  uint16_t num_addrs;
  
  /**
   * Client's IPPROTO, e.g. IPPROTO_UDP or IPPROTO_TCP.
   */
  uint8_t proto;

};


/**
 * List of local addresses this system has.
 */
struct LocalAddressList
{
  /**
   * This is a linked list.
   */
  struct LocalAddressList *next;

  /**
   * Previous entry.
   */
  struct LocalAddressList *prev;

  /**
   * The address itself (i.e. `struct in_addr` or `struct in6_addr`,
   * in the respective byte order).  Allocated at the end of this
   * struct.
   */
  const void *addr;

  /**
   * Address family.
   */
  int af;

  /**
   * What type of address is this?
   */
  enum GNUNET_NAT_AddressClass ac;
  
};




/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Task scheduled to periodically scan our network interfaces.
 */
static struct GNUNET_SCHEDULER_Task *scan_task;

/**
 * Head of client DLL.
 */
static struct ClientHandle *ch_head;
  
/**
 * Tail of client DLL.
 */
static struct ClientHandle *ch_tail;

/**
 * Head of DLL of local addresses.
 */
static struct LocalAddressList *lal_head;

/**
 * Tail of DLL of local addresses.
 */
static struct LocalAddressList *lal_tail;


/**
 * Free the DLL starting at #lal_head.
 */ 
static void
destroy_lal ()
{
  struct LocalAddressList *lal;

  while (NULL != (lal = lal_head))
  {
    GNUNET_CONTAINER_DLL_remove (lal_head,
				 lal_tail,
				 lal);
    GNUNET_free (lal);
  }
}


/**
 * Check validity of #GNUNET_MESSAGE_TYPE_NAT_REGISTER message from
 * client.
 *
 * @param cls client who sent the message
 * @param message the message received
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_register (void *cls,
		const struct GNUNET_NAT_RegisterMessage *message)
{
  uint16_t num_addrs = ntohs (message->num_addrs);
  const char *off = (const char *) &message[1];
  size_t left = ntohs (message->header.size) - sizeof (*message);

  for (unsigned int i=0;i<num_addrs;i++)
  {
    size_t alen;
    const struct sockaddr *sa = (const struct sockaddr *) off;

    if (sizeof (sa_family_t) > left)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    switch (sa->sa_family)
    {
    case AF_INET:
      alen = sizeof (struct sockaddr_in);
      break;
    case AF_INET6:
      alen = sizeof (struct sockaddr_in6);
      break;
#if AF_UNIX
    case AF_UNIX:
      alen = sizeof (struct sockaddr_un);
      break;
#endif
    default:
      GNUNET_break (0);
      return GNUNET_SYSERR;      
    }
    if (alen > left)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;      
    }
  }  
  return GNUNET_OK; 
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_NAT_REGISTER message from client.
 * We remember the client for updates upon future NAT events.
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static void
handle_register (void *cls,
		 const struct GNUNET_NAT_RegisterMessage *message)
{
  struct ClientHandle *ch = cls;
  const char *off;
  size_t left;

  if ( (0 != ch->proto) ||
       (NULL != ch->addrs) )
  {
    /* double registration not allowed */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (ch->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received REGISTER message from client\n");
  ch->flags = message->flags;
  ch->proto = message->proto;
  ch->adv_port = ntohs (message->adv_port);
  ch->num_addrs = ntohs (message->adv_port);
  ch->addrs = GNUNET_new_array (ch->num_addrs,
				struct sockaddr *);
  left = ntohs (message->header.size) - sizeof (*message);
  off = (const char *) &message[1];
  for (unsigned int i=0;i<ch->num_addrs;i++)
  {
    size_t alen;
    const struct sockaddr *sa = (const struct sockaddr *) off;

    if (sizeof (sa_family_t) > left)
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    switch (sa->sa_family)
    {
    case AF_INET:
      alen = sizeof (struct sockaddr_in);
      break;
    case AF_INET6:
      alen = sizeof (struct sockaddr_in6);
      break;
#if AF_UNIX
    case AF_UNIX:
      alen = sizeof (struct sockaddr_un);
      break;
#endif
    default:
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;      
    }
    GNUNET_assert (alen <= left);
    ch->addrs[i] = GNUNET_malloc (alen);
    GNUNET_memcpy (ch->addrs[i],
		   sa,
		   alen);    
    off += alen;
  }  
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Check validity of #GNUNET_MESSAGE_TYPE_NAT_HANDLE_STUN message from
 * client.
 *
 * @param cls client who sent the message
 * @param message the message received
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_stun (void *cls,
	    const struct GNUNET_NAT_HandleStunMessage *message)
{
  size_t sa_len = ntohs (message->sender_addr_size);
  size_t expect = sa_len + ntohs (message->payload_size);
  
  if (ntohs (message->header.size) - sizeof (*message) != expect)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (sa_len < sizeof (sa_family_t))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_NAT_HANDLE_STUN message from
 * client.
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static void
handle_stun (void *cls,
	     const struct GNUNET_NAT_HandleStunMessage *message)
{
  struct ClientHandle *ch = cls;
  const char *buf = (const char *) &message[1];
  const struct sockaddr *sa;
  const void *payload;
  size_t sa_len;
  size_t payload_size;

  sa_len = ntohs (message->sender_addr_size);
  payload_size = ntohs (message->payload_size);
  sa = (const struct sockaddr *) &buf[0];
  payload = (const struct sockaddr *) &buf[sa_len];
  switch (sa->sa_family)
  {
  case AF_INET:
    if (sa_len != sizeof (struct sockaddr_in))
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    break;
  case AF_INET6:
    if (sa_len != sizeof (struct sockaddr_in6))
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    break;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received HANDLE_STUN message from client\n");
  // FIXME: actually handle STUN request!
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Check validity of
 * #GNUNET_MESSAGE_TYPE_NAT_REQUEST_CONNECTION_REVERSAL message from
 * client.
 *
 * @param cls client who sent the message
 * @param message the message received
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_request_connection_reversal (void *cls,
				   const struct GNUNET_NAT_RequestConnectionReversalMessage *message)
{
  size_t expect;

  expect = ntohs (message->local_addr_size)
    + ntohs (message->remote_addr_size);
  if (ntohs (message->header.size) - sizeof (*message) != expect)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_NAT_REQUEST_CONNECTION_REVERSAL
 * message from client.
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static void
handle_request_connection_reversal (void *cls,
				    const struct GNUNET_NAT_RequestConnectionReversalMessage *message)
{
  struct ClientHandle *ch = cls;
  const char *buf = (const char *) &message[1];
  size_t local_sa_len = ntohs (message->local_addr_size);
  size_t remote_sa_len = ntohs (message->remote_addr_size);
  const struct sockaddr *local_sa = (const struct sockaddr *) &buf[0];
  const struct sockaddr *remote_sa = (const struct sockaddr *) &buf[local_sa_len];
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received REQUEST CONNECTION REVERSAL message from client\n");
  switch (local_sa->sa_family)
  {
  case AF_INET:
    if (local_sa_len != sizeof (struct sockaddr_in))
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    break;
  case AF_INET6:
    if (local_sa_len != sizeof (struct sockaddr_in6))
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    break;
  default:
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (ch->client);
    return;
  }
  switch (remote_sa->sa_family)
  {
  case AF_INET:
    if (remote_sa_len != sizeof (struct sockaddr_in))
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    break;
  case AF_INET6:
    if (remote_sa_len != sizeof (struct sockaddr_in6))
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    break;
  default:
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (ch->client);
    return;
  }
  /* FIXME: actually run the logic! */
  
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_NAT_REQUEST_TEST message from
 * client.
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static void
handle_test (void *cls,
	     const struct GNUNET_NAT_RequestTestMessage *message)
{
  struct ClientHandle *ch = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received REQUEST_TEST message from client\n");
  /* FIXME: actually process test request */
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Check validity of #GNUNET_MESSAGE_TYPE_NAT_REQUEST_AUTO_CFG message
 * from client.
 *
 * @param cls client who sent the message
 * @param message the message received
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_autoconfig_request (void *cls,
			  const struct GNUNET_NAT_AutoconfigRequestMessage *message)
{
  return GNUNET_OK;  /* checked later */
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_NAT_REQUEST_AUTO_CFG message from
 * client.
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static void
handle_autoconfig_request (void *cls,
			   const struct GNUNET_NAT_AutoconfigRequestMessage *message)
{
  struct ClientHandle *ch = cls;
  size_t left = ntohs (message->header.size);
  struct GNUNET_CONFIGURATION_Handle *c;

  c = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_deserialize (c,
					(const char *) &message[1],
					left,
					GNUNET_NO))
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (ch->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received REQUEST_AUTO_CONFIG message from client\n");
  // FIXME: actually handle request...
  GNUNET_CONFIGURATION_destroy (c);
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  if (NULL != scan_task)
  {
    GNUNET_SCHEDULER_cancel (scan_task);
    scan_task = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
  destroy_lal ();
}


/**
 * Closure for #ifc_proc.
 */
struct IfcProcContext
{

  /** 
   * Head of DLL of local addresses.
   */
  struct LocalAddressList *lal_head;

  /**
   * Tail of DLL of local addresses.
   */
  struct LocalAddressList *lal_tail;

};


/**
 * Callback function invoked for each interface found.  Adds them
 * to our new address list.
 *
 * @param cls a `struct IfcProcContext *`
 * @param name name of the interface (can be NULL for unknown)
 * @param isDefault is this presumably the default interface
 * @param addr address of this interface (can be NULL for unknown or unassigned)
 * @param broadcast_addr the broadcast address (can be NULL for unknown or unassigned)
 * @param netmask the network mask (can be NULL for unknown or unassigned)
 * @param addrlen length of the address
 * @return #GNUNET_OK to continue iteration, #GNUNET_SYSERR to abort
 */
static int
ifc_proc (void *cls,
	  const char *name,
	  int isDefault,
	  const struct sockaddr *addr,
	  const struct sockaddr *broadcast_addr,
	  const struct sockaddr *netmask,
	  socklen_t addrlen)
{
  struct IfcProcContext *ifc_ctx = cls;
  struct LocalAddressList *lal;
  size_t alen;
  const void *ip;

  switch (addr->sa_family)
  {
  case AF_INET:
    alen = sizeof (struct in_addr);
    ip = &((const struct sockaddr_in *) addr)->sin_addr;
    break;
  case AF_INET6:
    alen = sizeof (struct in6_addr);
    ip = &((const struct sockaddr_in6 *) addr)->sin6_addr;
    break;
#if AF_UNIX
  case AF_UNIX:
    GNUNET_break (0);
    return GNUNET_OK;
#endif
  default:
    GNUNET_break (0);
    return GNUNET_OK;
  }
  lal = GNUNET_malloc (sizeof (*lal) + alen);
  lal->af = addr->sa_family;
  lal->addr = &lal[1];
  GNUNET_memcpy (&lal[1],
		 ip,
		 alen);
  GNUNET_CONTAINER_DLL_insert (ifc_ctx->lal_head,
			       ifc_ctx->lal_tail,
			       lal);
  return GNUNET_OK;
}


/**
 * Notify all clients about a change in the list
 * of addresses this peer has.
 *
 * @param delta the entry in the list that changed
 * @param add #GNUNET_YES to add, #GNUNET_NO to remove
 */
static void
notify_clients (struct LocalAddressList *delta,
		int add)
{
  for (struct ClientHandle *ch = ch_head;
       NULL != ch;
       ch = ch->next)
  {
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_NAT_AddressChangeNotificationMessage *msg;
    void *addr;
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    size_t alen;
    
    if (0 == (ch->flags & GNUNET_NAT_RF_ADDRESSES))
      continue;
    switch (delta->af)
    {
    case AF_INET:
      alen = sizeof (struct sockaddr_in);
      addr = &v4;
      memset (&v4, 0, sizeof (v4));
      v4.sin_family = AF_INET;
      GNUNET_memcpy (&v4.sin_addr,
		     delta->addr,
		     sizeof (struct in_addr));
      /* FIXME: set port */
      break;
    case AF_INET6:
      alen = sizeof (struct sockaddr_in6);
      addr = &v6;
      memset (&v6, 0, sizeof (v6));
      v6.sin6_family = AF_INET6;
      GNUNET_memcpy (&v6.sin6_addr,
		     delta->addr,
		     sizeof (struct in6_addr));
      /* FIXME: set port, and link/interface! */
      break;
    default:
      GNUNET_break (0);
      continue;
    }
    env = GNUNET_MQ_msg_extra (msg,
			       alen,
			       GNUNET_MESSAGE_TYPE_NAT_ADDRESS_CHANGE);
    msg->add_remove = htonl (add);
    msg->addr_class = htonl (delta->ac);
    GNUNET_memcpy (&msg[1],
		   addr,
		   alen);
    GNUNET_MQ_send (ch->mq,
		    env);
  }
}


/**
 * Task we run periodically to scan for network interfaces.
 *
 * @param cls NULL
 */ 
static void
run_scan (void *cls)
{
  struct IfcProcContext ifc_ctx;
  int found;
  
  scan_task = GNUNET_SCHEDULER_add_delayed (SCAN_FREQ,
					    &run_scan,
					    NULL);
  memset (&ifc_ctx,
	  0,
	  sizeof (ifc_ctx));
  GNUNET_OS_network_interfaces_list (&ifc_proc,
				     &ifc_ctx);
  for (struct LocalAddressList *lal = lal_head;
       NULL != lal;
       lal = lal->next)
  {
    found = GNUNET_NO;
    for (struct LocalAddressList *pos = ifc_ctx.lal_head;
	 NULL != pos;
	 pos = pos->next)
    {
      if ( (pos->af == lal->af) &&
	   (0 == memcmp (lal->addr,
			 pos->addr,
			 (AF_INET == lal->af)
			 ? sizeof (struct in_addr)
			 : sizeof (struct in6_addr))) )
	found = GNUNET_YES;
    }
    if (GNUNET_NO == found)
      notify_clients (lal,
		      GNUNET_NO);
  }

  for (struct LocalAddressList *pos = ifc_ctx.lal_head;
       NULL != pos;
       pos = pos->next)
  {
    found = GNUNET_NO;
    for (struct LocalAddressList *lal = lal_head;
	 NULL != lal;
	 lal = lal->next)
    {
      if ( (pos->af == lal->af) &&
	   (0 == memcmp (lal->addr,
			 pos->addr,
			 (AF_INET == lal->af)
			 ? sizeof (struct in_addr)
			 : sizeof (struct in6_addr))) )
	found = GNUNET_YES;
    }
    if (GNUNET_NO == found)
      notify_clients (pos,
		      GNUNET_YES);
  }

  destroy_lal ();
  lal_head = ifc_ctx.lal_head;
  lal_tail = ifc_ctx.lal_tail;
}


/**
 * Handle network size estimate clients.
 *
 * @param cls closure
 * @param c configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  cfg = c;
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 NULL);
  stats = GNUNET_STATISTICS_create ("nat",
				    cfg);
  scan_task = GNUNET_SCHEDULER_add_now (&run_scan,
					NULL);
}


/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return a `struct ClientHandle`
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *c,
		   struct GNUNET_MQ_Handle *mq)
{
  struct ClientHandle *ch;

  ch = GNUNET_new (struct ClientHandle);
  ch->mq = mq;
  ch->client = c;
  GNUNET_CONTAINER_DLL_insert (ch_head,
			       ch_tail,
			       ch);
  return ch;
}


/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls a `struct ClientHandle *`
 */
static void
client_disconnect_cb (void *cls,
		      struct GNUNET_SERVICE_Client *c,
		      void *internal_cls)
{
  struct ClientHandle *ch = internal_cls;

  GNUNET_CONTAINER_DLL_remove (ch_head,
			       ch_tail,
			       ch);
  for (unsigned int i=0;i<ch->num_addrs;i++)
    GNUNET_free_non_null (ch->addrs[i]);
  GNUNET_free_non_null (ch->addrs);
  GNUNET_free (ch);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("nat",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (register,
			GNUNET_MESSAGE_TYPE_NAT_REGISTER,
			struct GNUNET_NAT_RegisterMessage,
			NULL),
 GNUNET_MQ_hd_var_size (stun,
			GNUNET_MESSAGE_TYPE_NAT_HANDLE_STUN,
			struct GNUNET_NAT_HandleStunMessage,
			NULL),
 GNUNET_MQ_hd_var_size (request_connection_reversal,
			GNUNET_MESSAGE_TYPE_NAT_REQUEST_CONNECTION_REVERSAL,
			struct GNUNET_NAT_RequestConnectionReversalMessage,
			NULL),
 GNUNET_MQ_hd_fixed_size (test,
			  GNUNET_MESSAGE_TYPE_NAT_REQUEST_TEST,
			  struct GNUNET_NAT_RequestTestMessage,
			  NULL),
 GNUNET_MQ_hd_var_size (autoconfig_request,
			GNUNET_MESSAGE_TYPE_NAT_REQUEST_AUTO_CFG,
			struct GNUNET_NAT_AutoconfigRequestMessage,
			NULL),
 GNUNET_MQ_handler_end ());


#if defined(LINUX) && defined(__GLIBC__)
#include <malloc.h>

/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor))
GNUNET_ARM_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}
#endif

/* end of gnunet-service-nat.c */
