/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_http.c
 * @brief http transport service plugin
 * @author Matthias Wachs
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_connection_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_resolver_service.h"
#include "gnunet_server_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_transport_plugin.h"
#include "gnunet_os_lib.h"
#include "gnunet_nat_lib.h"
#include "microhttpd.h"
#include <curl/curl.h>

#if BUILD_HTTPS
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_https_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_https_done
#define LIBGNUNET_PLUGIN_TRANSPORT_COMPONENT transport_https
#define PROTOCOL_PREFIX "https"
#else
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_http_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_http_done
#define LIBGNUNET_PLUGIN_TRANSPORT_COMPONENT transport_http
#define PROTOCOL_PREFIX "http"
#endif

#define DEBUG_HTTP GNUNET_NO
#define DEBUG_CURL GNUNET_NO
#define DEBUG_MHD GNUNET_NO
#define DEBUG_CONNECTIONS GNUNET_NO
#define DEBUG_SESSION_SELECTION GNUNET_NO
#define DEBUG_SCHEDULING GNUNET_NO
#define CURL_TCP_NODELAY GNUNET_YES

#define INBOUND GNUNET_NO
#define OUTBOUND GNUNET_YES



/**
 * Text of the response sent back after the last bytes of a PUT
 * request have been received (just to formally obey the HTTP
 * protocol).
 */
#define HTTP_PUT_RESPONSE "Thank you!"

/**
 * After how long do we expire an address that we
 * learned from another peer if it is not reconfirmed
 * by anyone?
 */
#define LEARNED_ADDRESS_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 6)

/**
 * Page returned if request invalid
 */
#define HTTP_ERROR_RESPONSE "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H1>Not Found</H1>The requested URL was not found on this server.<P><HR><ADDRESS></ADDRESS></BODY></HTML>"

/**
 * Timeout for a http connect
 */
#define HTTP_CONNECT_TIMEOUT 30

/**
 * Network format for IPv4 addresses.
 */
struct IPv4HttpAddress
{
  /**
   * IPv4 address, in network byte order.
   */
  uint32_t ipv4_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t port GNUNET_PACKED;
};

/**
 * Wrapper to manage IPv4 addresses
 */
struct IPv4HttpAddressWrapper
{
  /**
   * Linked list next
   */
  struct IPv4HttpAddressWrapper * next;

  /**
   * Linked list previous
   */
  struct IPv4HttpAddressWrapper * prev;

  struct IPv4HttpAddress * addr;
};

/**
 * Network format for IPv6 addresses.
 */
struct IPv6HttpAddress
{
  /**
   * IPv6 address.
   */
  struct in6_addr ipv6_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t port GNUNET_PACKED;

};

/**
 * Wrapper for IPv4 addresses.
 */
struct IPv6HttpAddressWrapper
{
  /**
   * Linked list next
   */
  struct IPv6HttpAddressWrapper * next;

  /**
   * Linked list previous
   */
  struct IPv6HttpAddressWrapper * prev;

  struct IPv6HttpAddress * addr;
};

/**
 *  Message to send using http
 */
struct HTTP_Message
{
  /**
   * next pointer for double linked list
   */
  struct HTTP_Message * next;

  /**
   * previous pointer for double linked list
   */
  struct HTTP_Message * prev;

  /**
   * buffer containing data to send
   */
  char *buf;

  /**
   * amount of data already sent
   */
  size_t pos;

  /**
   * buffer length
   */
  size_t size;

  /**
   * Continuation function to call once the transmission buffer
   * has again space available.  NULL if there is no
   * continuation to call.
   */
  GNUNET_TRANSPORT_TransmitContinuation transmit_cont;

  /**
   * Closure for transmit_cont.
   */
  void *transmit_cont_cls;
};


struct HTTP_PeerContext
{
  /**
   * peer's identity
   */
  struct GNUNET_PeerIdentity identity;

  /**
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

  /**
   * Linked list of connections with this peer
   * head
   */
  struct Session * head;

  /**
   * Linked list of connections with this peer
   * tail
   */
  struct Session * tail;

  /**
   * id for next session
   */
  size_t session_id_counter;

  /**
   * Last session used to send data
   */
  struct Session * last_session;

  /**
   * The task resetting inbound quota delay
   */
  GNUNET_SCHEDULER_TaskIdentifier reset_task;

  /**
   * Delay from transport service inbound quota tracker when to receive data again
   */
  struct GNUNET_TIME_Relative delay;
};


struct Session
{
  /**
   * API requirement.
   */
  struct SessionHeader header;

  /**
   * next session in linked list
   */
  struct Session * next;

  /**
   * previous session in linked list
   */
  struct Session * prev;

  /**
   * address of this session
   */
  void * addr;

  /**
   * address length
   */
  size_t addrlen;

  /**
   * target url
   */
  char * url;

  /**
   * Message queue for outbound messages
   * head of queue
   */
  struct HTTP_Message * pending_msgs_head;

  /**
   * Message queue for outbound messages
   * tail of queue
   */
  struct HTTP_Message * pending_msgs_tail;

  /**
   * partner peer this connection belongs to
   */
  struct HTTP_PeerContext * peercontext;

  /**
   * message stream tokenizer for incoming data
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *msgtok;

  /**
   * session direction
   * outbound: OUTBOUND (GNUNET_YES)
   * inbound : INBOUND (GNUNET_NO)
   */
  unsigned int direction;

  /**
   * is session connected to send data?
   */
  unsigned int send_connected;

  /**
   * is send connection active?
   */
  unsigned int send_active;

  /**
   * connection disconnect forced (e.g. from transport)
   */
  unsigned int send_force_disconnect;

  /**
   * is session connected to receive data?
   */
  unsigned int recv_connected;

  /**
   * is receive connection active?
   */
  unsigned int recv_active;

  /**
   * connection disconnect forced (e.g. from transport)
   */
  unsigned int recv_force_disconnect;


  /**
   * id for next session
   * NOTE: 0 is not an ID, zero is not defined. A correct ID is always > 0
   */
  size_t session_id;

  /**
   * entity managing sending data
   * outbound session: CURL *
   * inbound session: mhd_connection *
   */
  void * send_endpoint;

  /**
   * entity managing recieving data
   * outbound session: CURL *
   * inbound session: mhd_connection *
   */
  void * recv_endpoint;

  /**
   * Current queue size
   */
  size_t queue_length_cur;

  /**
	* Max queue size
	*/
  size_t queue_length_max;

};

/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin
{
  /**
   * Our environment.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment *env;

  /**
   * Handle for reporting statistics.
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Plugin Port
   */
  uint16_t port_inbound;

  struct GNUNET_CONTAINER_MultiHashMap *peers;

  /**
   * Daemon for listening for new IPv4 connections.
   */
  struct MHD_Daemon *http_server_daemon_v4;

  /**
   * Daemon for listening for new IPv6connections.
   */
  struct MHD_Daemon *http_server_daemon_v6;

  /**
   * Our primary task for http daemon handling IPv4 connections
   */
  GNUNET_SCHEDULER_TaskIdentifier http_server_task_v4;

  /**
   * Our primary task for http daemon handling IPv6 connections
   */
  GNUNET_SCHEDULER_TaskIdentifier http_server_task_v6;

  /**
   * The task sending data
   */
  GNUNET_SCHEDULER_TaskIdentifier http_curl_task;

  /**
   * cURL Multihandle
   */
  CURLM * multi_handle;

  /**
   * Our handle to the NAT module.
   */
  struct GNUNET_NAT_Handle *nat;

  /**
   * ipv4 DLL head
   */
  struct IPv4HttpAddressWrapper * ipv4_addr_head;

  /**
   * ipv4 DLL tail
   */
  struct IPv4HttpAddressWrapper * ipv4_addr_tail;

  /**
   * ipv6 DLL head
   */
  struct IPv6HttpAddressWrapper * ipv6_addr_head;

  /**
   * ipv6 DLL tail
   */
  struct IPv6HttpAddressWrapper * ipv6_addr_tail;

  /**
   * Our ASCII encoded, hashed peer identity
   * This string is used to distinguish between connections and is added to the urls
   */
  struct GNUNET_CRYPTO_HashAsciiEncoded my_ascii_hash_ident;

  /**
   * IPv4 Address the plugin binds to
   */
  struct sockaddr_in * bind4_address;

  /**
   * IPv6 Address the plugins binds to
   */
  struct sockaddr_in6 * bind6_address;

  /**
   * Hostname to bind to
   */
  char * bind_hostname;

  /**
   * Is IPv4 enabled?
   */
  int use_ipv6;

  /**
   * Is IPv6 enabled?
   */
  int use_ipv4;

  /**
   * use local addresses?
   */
  int use_localaddresses;

  /**
   * maximum number of connections
   */
  int max_connect_per_transport;

  /**
   * Current number of connections;
   */
  int current_connections;

  /**
   * Closure passed by MHD to the mhd_logger function
   */
  void * mhd_log;

  /* only needed for HTTPS plugin */
#if BUILD_HTTPS
  /* The certificate MHD uses as an \0 terminated string */
  char * cert;

  /* The private key MHD uses as an \0 terminated string */
  char * key;

  /* crypto init string */
  char * crypto_init;
#endif
};

/**
 * Context for address to string conversion.
 */
struct PrettyPrinterContext
{
  /**
   * Function to call with the result.
   */
  GNUNET_TRANSPORT_AddressStringCallback asc;

  /**
   * Clsoure for 'asc'.
   */
  void *asc_cls;

  /**
   * Port to add after the IP address.
   */
  uint16_t port;
};


/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param cls closure
 * @param addr binary address
 * @param addrlen length of the address
 * @return string representing the same address
 */
static const char*
http_plugin_address_to_string (void *cls,
                                   const void *addr,
                                   size_t addrlen);


/**
 * Call MHD to process pending ipv4 requests and then go back
 * and schedule the next run.
 */
static void http_server_daemon_v4_run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);
/**
 * Call MHD to process pending ipv6 requests and then go back
 * and schedule the next run.
 */
static void http_server_daemon_v6_run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Function setting up curl handle and selecting message to send
 *
 * @param plugin plugin
 * @param ps session
 * @return GNUNET_SYSERR on failure, GNUNET_NO if connecting, GNUNET_YES if ok
 */
static int send_check_connections (struct Plugin *plugin, struct Session *ps);

/**
 * Function setting up file descriptors and scheduling task to run
 *
 * @param  plugin plugin as closure
 * @return GNUNET_SYSERR for hard failure, GNUNET_OK for ok
 */
static int curl_schedule (struct Plugin *plugin);

/**
 * Task scheduled to reset the inbound quota delay for a specific peer
 * @param cls plugin as closure
 * @param tc task context
 */
static void reset_inbound_quota_delay (void *cls,
                                       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct HTTP_PeerContext * pc = cls;
  
  GNUNET_assert(cls != NULL);
  pc->reset_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  pc->delay = GNUNET_TIME_relative_get_zero ();
}


/**
 * Creates a valid url from passed address and id
 * @param plugin plugin
 * @param addr address to create url from
 * @param addrlen address lenth
 * @param id session id
 * @return the created url
 */
static char * 
create_url(struct Plugin *plugin, 
	   const void * addr, size_t addrlen, 
	   size_t id)
{
  char *url = NULL;
  char *addr_str = (char *) http_plugin_address_to_string(NULL, addr, addrlen);

  GNUNET_assert ((addr!=NULL) && (addrlen != 0));
  GNUNET_asprintf(&url,
                  "%s://%s/%s;%u", PROTOCOL_PREFIX, addr_str,
                  (char *) (&plugin->my_ascii_hash_ident),id);
  return url;
}


/**
 * Removes a message from the linked list of messages
 * @param ps session
 * @param msg message
 * @return GNUNET_SYSERR if msg not found, GNUNET_OK on success
 */
static int 
remove_http_message (struct Session * ps, 
		     struct HTTP_Message * msg)
{
  GNUNET_CONTAINER_DLL_remove(ps->pending_msgs_head,
			      ps->pending_msgs_tail,
			      msg);
  GNUNET_free(msg);
  return GNUNET_OK;
}

/**
 * Iterator to remove peer context
 * @param cls the plugin
 * @param key the peers public key hashcode
 * @param value the peer context
 * @return GNUNET_YES on success
 */
static int 
remove_peer_context_Iterator (void *cls,
			      const GNUNET_HashCode *key, 
			      void *value)
{
  struct Plugin *plugin = cls;
  struct HTTP_PeerContext * pc = value;
  struct Session * ps = pc->head;
  struct Session * tmp = NULL;
  struct HTTP_Message * msg = NULL;
  struct HTTP_Message * msg_tmp = NULL;

#if DEBUG_HTTP
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Freeing context for peer `%s'\n",
	      GNUNET_i2s(&pc->identity));
#endif
  GNUNET_CONTAINER_multihashmap_remove (plugin->peers, &pc->identity.hashPubKey, pc);
  while (ps!=NULL)
    {
      plugin->env->session_end(plugin, &pc->identity, ps);
      tmp = ps->next;
      
      GNUNET_free_non_null (ps->addr);
      GNUNET_free(ps->url);
      if (ps->msgtok != NULL)
	GNUNET_SERVER_mst_destroy (ps->msgtok);
      
      msg = ps->pending_msgs_head;
      while (msg!=NULL)
	{
	  msg_tmp = msg->next;
	  GNUNET_free(msg);
	  msg = msg_tmp;
	}
      if (ps->direction==OUTBOUND)
	{
	  if (ps->send_endpoint!=NULL)
	    curl_easy_cleanup(ps->send_endpoint);
	  if (ps->recv_endpoint!=NULL)
	    curl_easy_cleanup(ps->recv_endpoint);
	}      
      GNUNET_free(ps);
      ps=tmp;
    }
  GNUNET_free(pc);
  GNUNET_STATISTICS_update (plugin->env->stats,
			    gettext_noop ("# HTTP peers active"),
			    -1,
			    GNUNET_NO);
  return GNUNET_YES;
}


/**
 * Removes a session from the linked list of sessions
 * @param pc peer context
 * @param ps session
 * @param call_msg_cont GNUNET_YES to call pending message continuations, otherwise no
 * @param call_msg_cont_result result to call message continuations with
 * @return GNUNET_SYSERR if msg not found, GNUNET_OK on success
 */
static int 
remove_session (struct HTTP_PeerContext * pc, 
		struct Session * ps,  
		int call_msg_cont, 
		int call_msg_cont_result)
{
  struct HTTP_Message * msg;
  struct Plugin * plugin = ps->peercontext->plugin;

#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Connection %X: removing %s session %X with id %u\n", 
	      ps,
	      (ps->direction == INBOUND) 
	      ? "inbound" 
	      : "outbound", 
	      ps, ps->session_id);
#endif
  plugin->env->session_end(plugin, &pc->identity, ps);
  GNUNET_free_non_null (ps->addr);
  GNUNET_SERVER_mst_destroy (ps->msgtok);
  GNUNET_free(ps->url);
  if (ps->direction==INBOUND)
    {
      if (ps->recv_endpoint != NULL)
	{
	  curl_easy_cleanup(ps->recv_endpoint);
	  ps->recv_endpoint = NULL;
	}
      if (ps->send_endpoint != NULL)
	{
	  curl_easy_cleanup(ps->send_endpoint);
	  ps->send_endpoint = NULL;
	}
    }
  
  msg = ps->pending_msgs_head;
  while (msg!=NULL)
    {
      if ((call_msg_cont == GNUNET_YES) && (msg->transmit_cont!=NULL))
	{
	  msg->transmit_cont (msg->transmit_cont_cls,
			      &pc->identity,
			      call_msg_cont_result);
	}
      GNUNET_CONTAINER_DLL_remove(ps->pending_msgs_head,
				  ps->pending_msgs_head,
				  msg);
      GNUNET_free(msg);
      msg = ps->pending_msgs_head;
    }
  
  GNUNET_CONTAINER_DLL_remove(pc->head,pc->tail,ps);
  GNUNET_free(ps);
  ps = NULL;

  /* no sessions left remove peer */
  if (pc->head==NULL)
    {
#if DEBUG_HTTP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "No sessions left for peer `%s', removing context\n",
		  GNUNET_i2s(&pc->identity));
#endif
      remove_peer_context_Iterator(plugin, &pc->identity.hashPubKey, pc);
    }
  
  return GNUNET_OK;
}


#if 0
static int check_localaddress (const struct sockaddr *addr, socklen_t addrlen)
{
	uint32_t res = 0;
	int local = GNUNET_NO;
	int af = addr->sa_family;
    switch (af)
    {
      case AF_INET:
      {
    	  uint32_t netmask = 0x7F000000;
    	  uint32_t address = ntohl (((struct sockaddr_in *) addr)->sin_addr.s_addr);
    	  res = (address >> 24) ^ (netmask >> 24);
    	  if (res != 0)
    		  local = GNUNET_NO;
    	  else
    		  local = GNUNET_YES;
#if DEBUG_HTTP
    	    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
    			  "Checking IPv4 address `%s': %s\n", GNUNET_a2s (addr, addrlen), (local==GNUNET_YES) ? "local" : "global");
#endif
    	    break;
      }
      case AF_INET6:
      {
    	   if (IN6_IS_ADDR_LOOPBACK  (&((struct sockaddr_in6 *) addr)->sin6_addr) ||
    		   IN6_IS_ADDR_LINKLOCAL (&((struct sockaddr_in6 *) addr)->sin6_addr))
    		   local = GNUNET_YES;
    	   else
    		   local = GNUNET_NO;
#if DEBUG_HTTP
    	   GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
    			  "Checking IPv6 address `%s' : %s\n", GNUNET_a2s (addr, addrlen), (local==GNUNET_YES) ? "local" : "global");
#endif
    	   break;
      }
    }
	return local;
}


/**
 * Add the IP of our network interface to the list of
 * our external IP addresses.
 *
 * @param cls the 'struct Plugin*'
 * @param name name of the interface
 * @param isDefault do we think this may be our default interface
 * @param addr address of the interface
 * @param addrlen number of bytes in addr
 * @return GNUNET_OK to continue iterating
 */
static int
process_interfaces (void *cls,
                    const char *name,
                    int isDefault,
                    const struct sockaddr *addr, socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4HttpAddress * t4;
  struct IPv6HttpAddress * t6;
  int af;

  if (plugin->use_localaddresses == GNUNET_NO)
  {
	  if (GNUNET_YES == check_localaddress (addr, addrlen))
	  {
#if DEBUG_HTTP
          GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
        	   PROTOCOL_PREFIX,
			   "Not notifying transport of address `%s' (local address)\n",
			   GNUNET_a2s (addr, addrlen));
#endif
		  return GNUNET_OK;
	  }
  }


  GNUNET_assert(cls !=NULL);
  af = addr->sa_family;
  if ((af == AF_INET) &&
      (plugin->use_ipv4 == GNUNET_YES) &&
      (plugin->bind6_address == NULL) ) {

	  struct in_addr bnd_cmp = ((struct sockaddr_in *) addr)->sin_addr;
      t4 = GNUNET_malloc(sizeof(struct IPv4HttpAddress));
     // Not skipping loopback addresses


      t4->ipv4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
      t4->port = htons (plugin->port_inbound);
      if (plugin->bind4_address != NULL) {
	if (0 == memcmp(&plugin->bind4_address->sin_addr, &bnd_cmp, sizeof (struct in_addr)))
	  {
	    GNUNET_CONTAINER_DLL_insert(plugin->ipv4_addr_head,
					plugin->ipv4_addr_tail,t4);
	          plugin->env->notify_address(plugin->env->cls,
	                                      GNUNET_YES,
	                                      t4, sizeof (struct IPv4HttpAddress));
	    return GNUNET_OK;
	  }
	GNUNET_free (t4);
	return GNUNET_OK;
      }
      else
	  {
          GNUNET_CONTAINER_DLL_insert (plugin->ipv4_addr_head,
				       plugin->ipv4_addr_tail,
				       t4);
          plugin->env->notify_address(plugin->env->cls,
                                      GNUNET_YES,
                                      t4, sizeof (struct IPv4HttpAddress));
      	  return GNUNET_OK;
	  }
   }
   if ((af == AF_INET6) &&
	    (plugin->use_ipv6 == GNUNET_YES) && 
	    (plugin->bind4_address == NULL) ) {

	  struct in6_addr bnd_cmp6 = ((struct sockaddr_in6 *) addr)->sin6_addr;

      t6 = GNUNET_malloc(sizeof(struct IPv6HttpAddress));
      GNUNET_assert(t6 != NULL);

      if (plugin->bind6_address != NULL) {
    	  if (0 == memcmp(&plugin->bind6_address->sin6_addr,
						  &bnd_cmp6,
						 sizeof (struct in6_addr))) {
    	      memcpy (&t6->ipv6_addr,
    	              &((struct sockaddr_in6 *) addr)->sin6_addr,
    	              sizeof (struct in6_addr));
    	      t6->port = htons (plugin->port_inbound);
    	      plugin->env->notify_address(plugin->env->cls,
    	                                  GNUNET_YES,
    	                                  t6, sizeof (struct IPv6HttpAddress));
    	      GNUNET_CONTAINER_DLL_insert(plugin->ipv6_addr_head,
					  plugin->ipv6_addr_tail,
					  t6);
    	      return GNUNET_OK;
	      }
	  GNUNET_free (t6);
	  return GNUNET_OK;
	  }
      memcpy (&t6->ipv6_addr,
    		  &((struct sockaddr_in6 *) addr)->sin6_addr,
    		  sizeof (struct in6_addr));
      t6->port = htons (plugin->port_inbound);
      GNUNET_CONTAINER_DLL_insert(plugin->ipv6_addr_head,plugin->ipv6_addr_tail,t6);

      plugin->env->notify_address(plugin->env->cls,
                                  GNUNET_YES,
				  t6, sizeof (struct IPv6HttpAddress));
  }
  return GNUNET_OK;
}
#endif

/**
 * External logging function for MHD
 * @param arg arguments
 * @param fmt format string
 * @param ap  list of arguments
 */
static void 
mhd_logger (void * arg, 
	    const char * fmt, 
	    va_list ap)
{
  char text[1024];

  vsnprintf(text, sizeof(text), fmt, ap);
  va_end(ap);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
	      "MHD: %s\n", 
	      text);
}


static void 
mhd_termination_cb (void *cls, 
		    struct MHD_Connection * connection, 
		    void **httpSessionCache)
{
  struct Session * ps = *httpSessionCache;
  if (ps == NULL)
    return;
  struct HTTP_PeerContext * pc = ps->peercontext;
  struct Plugin *plugin = cls;

  GNUNET_assert (cls != NULL);
    plugin->current_connections--;

  if (connection==ps->recv_endpoint)
    {
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection %X: inbound connection from peer `%s' was terminated\n", 
		  ps, 
		  GNUNET_i2s(&pc->identity));
#endif
      ps->recv_active = GNUNET_NO;
      ps->recv_connected = GNUNET_NO;
      ps->recv_endpoint = NULL;
    }
  if (connection==ps->send_endpoint)
    {
      ps->send_active = GNUNET_NO;
      ps->send_connected = GNUNET_NO;
      ps->send_endpoint = NULL;
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection %X: outbound connection from peer `%s' was terminated\n",
		  ps, 
		  GNUNET_i2s(&pc->identity));
#endif
    }

  /* if both connections disconnected, remove session */
  if ( (ps->send_connected == GNUNET_NO) && 
       (ps->recv_connected == GNUNET_NO) )
  {
    GNUNET_STATISTICS_update (pc->plugin->env->stats,
			      gettext_noop ("# HTTP inbound sessions for peers active"),
			      -1,
			      GNUNET_NO);
    remove_session(pc,ps,GNUNET_YES,GNUNET_SYSERR);
  }
}


/**
 * Callback called by MessageStreamTokenizer when a message has arrived
 * @param cls current session as closure
 * @param client clien
 * @param message the message to be forwarded to transport service
 */
static void 
mhd_write_mst_cb (void *cls,
		  void *client,
		  const struct GNUNET_MessageHeader *message)
{
  struct Session *ps  = cls; 
  struct HTTP_PeerContext *pc;
  struct GNUNET_TIME_Relative delay;

  GNUNET_assert(ps != NULL);
  pc = ps->peercontext;
  GNUNET_assert(pc != NULL);
#if DEBUG_HTTP
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Connection %X: Forwarding message to transport service, type %u and size %u from `%s' (`%s')\n",
	      ps,
	      ntohs(message->type),
              ntohs(message->size),
	      GNUNET_i2s(&(ps->peercontext)->identity),
	      http_plugin_address_to_string(NULL,ps->addr,ps->addrlen));
#endif
  struct GNUNET_TRANSPORT_ATS_Information distance[2];
  distance[0].type = htonl (GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE);
  distance[0].value = htonl (1);
  distance[1].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  distance[1].value = htonl (0);
  delay = pc->plugin->env->receive (ps->peercontext->plugin->env->cls,
				    &pc->identity,
				    message,
				    (const struct GNUNET_TRANSPORT_ATS_Information *) &distance,
				    2,
				    ps,
				    NULL,
				    0);
  pc->delay = delay;
  if (pc->reset_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (pc->reset_task);
  
  if (delay.rel_value > 0)
    {
#if DEBUG_HTTP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection %X: Inbound quota management: delay next read for %llu ms \n", 
		  ps,
		  delay.rel_value);
#endif
      pc->reset_task = GNUNET_SCHEDULER_add_delayed (delay, &reset_inbound_quota_delay, pc);
    }
}


/**
 * Check if incoming connection is accepted.
 * NOTE: Here every connection is accepted
 * @param cls plugin as closure
 * @param addr address of incoming connection
 * @param addr_len address length of incoming connection
 * @return MHD_YES if connection is accepted, MHD_NO if connection is rejected
 *
 */
static int
mhd_accept_cb (void *cls,
	       const struct sockaddr *addr, 
	       socklen_t addr_len)
{
  struct Plugin *plugin = cls;
  GNUNET_assert (cls != NULL);

  if (plugin->max_connect_per_transport > plugin->current_connections)
  {
    plugin->current_connections ++;
    return MHD_YES;
  }
  else return MHD_NO;
}


/**
 * Callback called by MHD when it needs data to send
 * @param cls current session
 * @param pos position in buffer
 * @param buf the buffer to write data to
 * @param max max number of bytes available in buffer
 * @return bytes written to buffer
 */
static ssize_t
mhd_send_callback (void *cls, uint64_t pos, char *buf, size_t max)
{
  struct Session * ps = cls;
  struct HTTP_PeerContext * pc;
  struct HTTP_Message * msg;
  int bytes_read = 0;

  GNUNET_assert (ps!=NULL);

  pc = ps->peercontext;
  msg = ps->pending_msgs_tail;
  if (ps->send_force_disconnect==GNUNET_YES)
    {
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection %X: outbound forced to disconnect\n",
		  ps);
#endif
      return -1;
    }
  
  if (msg!=NULL)
    {
      /* sending */
      if ((msg->size-msg->pos) <= max)
	{
	  memcpy(buf,&msg->buf[msg->pos],(msg->size-msg->pos));
	  bytes_read = msg->size-msg->pos;
	  msg->pos+=(msg->size-msg->pos);
	}
      else
	{
	  memcpy(buf,&msg->buf[msg->pos],max);
	  msg->pos+=max;
	  bytes_read = max;
	}
      
      /* removing message */
      if (msg->pos==msg->size)
	{
	  if (NULL!=msg->transmit_cont)
	    msg->transmit_cont (msg->transmit_cont_cls,&pc->identity,GNUNET_OK);
	  ps->queue_length_cur -= msg->size;
	  remove_http_message(ps,msg);
	}
    }
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Connection %X: MHD has sent %u bytes\n", 
	      ps, 
	      bytes_read);
#endif
  return bytes_read;
}


/**
 * Process GET or PUT request received via MHD.  For
 * GET, queue response that will send back our pending
 * messages.  For PUT, process incoming data and send
 * to GNUnet core.  In either case, check if a session
 * already exists and create a new one if not.
 */
static int
mhd_access_cb (void *cls,
	       struct MHD_Connection *mhd_connection,
	       const char *url,
	       const char *method,
	       const char *version,
	       const char *upload_data,
	       size_t * upload_data_size,
	       void **httpSessionCache)
{
  struct Plugin *plugin = cls;
  struct MHD_Response *response;
  const union MHD_ConnectionInfo * conn_info;
  const struct sockaddr *client_addr;
  const struct sockaddr_in  *addrin;
  const struct sockaddr_in6 *addrin6;
  char address[INET6_ADDRSTRLEN+14];
  struct GNUNET_PeerIdentity pi_in;
  size_t id_num = 0;
  struct IPv4HttpAddress ipv4addr;
  struct IPv6HttpAddress ipv6addr;
  struct HTTP_PeerContext *pc = NULL;
  struct Session *ps = NULL;
  struct Session *ps_tmp = NULL;
  int res = GNUNET_NO;
  void * addr = NULL;
  size_t addr_len = 0 ;

  GNUNET_assert(cls !=NULL);

  if (NULL == *httpSessionCache)
    {
      /* check url for peer identity , if invalid send HTTP 404*/
      size_t len = strlen(&url[1]);
      char * peer = GNUNET_malloc(104+1);
      
      if ( (len>104) && (url[104]==';'))
	{
	  char * id = GNUNET_malloc((len-104)+1);
	  strcpy(id,&url[105]);
	  memcpy(peer,&url[1],103);
	  peer[103] = '\0';
        id_num = strtoul ( id, NULL , 10);
        GNUNET_free(id);
    }
    res = GNUNET_CRYPTO_hash_from_string (peer, &(pi_in.hashPubKey));
    GNUNET_free(peer);
    if ( GNUNET_SYSERR == res )
      {
	response = MHD_create_response_from_data (strlen (HTTP_ERROR_RESPONSE),
						  HTTP_ERROR_RESPONSE,
						  MHD_NO, MHD_NO);
	res = MHD_queue_response (mhd_connection, MHD_HTTP_NOT_FOUND, response);
	MHD_destroy_response (response);
#if DEBUG_CONNECTIONS
      if (res == MHD_YES)
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Peer has no valid ident, sent HTTP 1.1/404\n");
      else
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Peer has no valid ident, could not send error\n");
#endif
      return res;
      }
    }
  else
    {
      ps = *httpSessionCache;
      pc = ps->peercontext;
    }
  
  if (NULL == *httpSessionCache)
    {
      /* get peer context */
      pc = GNUNET_CONTAINER_multihashmap_get (plugin->peers, &pi_in.hashPubKey);
      /* Peer unknown */
      if (pc==NULL)
	{
	  pc = GNUNET_malloc(sizeof (struct HTTP_PeerContext));
	  pc->plugin = plugin;
	  pc->session_id_counter=1;
	  pc->last_session = NULL;
	  memcpy(&pc->identity, &pi_in, sizeof(struct GNUNET_PeerIdentity));
	  GNUNET_CONTAINER_multihashmap_put(plugin->peers, 
					    &pc->identity.hashPubKey,
					    pc, 
					    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
	  GNUNET_STATISTICS_update (plugin->env->stats,
				    gettext_noop ("# HTTP peers active"),
				    1,
				    GNUNET_NO);
	}

      conn_info = MHD_get_connection_info(mhd_connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS );
      /* Incoming IPv4 connection */
      /* cast required for legacy MHD API < 0.9.6 */
      client_addr = (const struct sockaddr *) conn_info->client_addr;
      if ( AF_INET == client_addr->sa_family)
	{
	  addrin = (const struct sockaddr_in*) client_addr;
	  inet_ntop(addrin->sin_family, &(addrin->sin_addr),address,INET_ADDRSTRLEN);
	  memcpy(&ipv4addr.ipv4_addr,&(addrin->sin_addr),sizeof(struct in_addr));
	  ipv4addr.port = addrin->sin_port;
	  addr = &ipv4addr;
	  addr_len = sizeof(struct IPv4HttpAddress);
	}
      /* Incoming IPv6 connection */
      if ( AF_INET6 == client_addr->sa_family)
	{
	  addrin6 = (const struct sockaddr_in6 *) client_addr;
	  inet_ntop(addrin6->sin6_family, &(addrin6->sin6_addr),address,INET6_ADDRSTRLEN);
	  memcpy(&ipv6addr.ipv6_addr,&(addrin6->sin6_addr),sizeof(struct in6_addr));
	  ipv6addr.port = addrin6->sin6_port;
	  addr = &ipv6addr;
	  addr_len = sizeof(struct IPv6HttpAddress);
	}
      
      GNUNET_assert (addr != NULL);
      GNUNET_assert (addr_len != 0);
      
      ps = NULL;
      /* only inbound sessions here */
      
      ps_tmp = pc->head;
      while (ps_tmp!=NULL)
	{
	  if ((ps_tmp->direction==INBOUND) && (ps_tmp->session_id == id_num) && (id_num!=0))
	    {
	      if ((ps_tmp->recv_force_disconnect!=GNUNET_YES) && (ps_tmp->send_force_disconnect!=GNUNET_YES))
		ps=ps_tmp;
	      break;
	    }
	  ps_tmp=ps_tmp->next;
	}
      
      if (ps==NULL)
	{
	  ps = GNUNET_malloc(sizeof (struct Session));
	  ps->addr = GNUNET_malloc(addr_len);
	  memcpy(ps->addr,addr,addr_len);
	  ps->addrlen = addr_len;
	  ps->direction=INBOUND;
	  ps->pending_msgs_head = NULL;
	  ps->pending_msgs_tail = NULL;
	  ps->send_connected=GNUNET_NO;
	  ps->send_active=GNUNET_NO;
	  ps->recv_connected=GNUNET_NO;
	  ps->recv_active=GNUNET_NO;
	  ps->peercontext=pc;
	  ps->session_id =id_num;
	  ps->queue_length_cur = 0;
	  ps->queue_length_max = GNUNET_SERVER_MAX_MESSAGE_SIZE;
	  ps->url = create_url (plugin, ps->addr, ps->addrlen, ps->session_id);
	  GNUNET_CONTAINER_DLL_insert(pc->head,pc->tail,ps);
	  GNUNET_STATISTICS_update (plugin->env->stats,
				    gettext_noop ("# HTTP inbound sessions for peers active"),
				    1,
				    GNUNET_NO);
	}
      
      *httpSessionCache = ps;
      if (ps->msgtok==NULL)
	ps->msgtok = GNUNET_SERVER_mst_create (&mhd_write_mst_cb, ps);
#if DEBUG_HTTP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection %X: HTTP Daemon has new an incoming `%s' request from peer `%s' (`%s')\n",
		  ps,
		  method,
		  GNUNET_i2s(&pc->identity),
		  http_plugin_address_to_string(NULL, ps->addr, ps->addrlen));
#endif
    }
  
  /* Is it a PUT or a GET request */
  if (0 == strcmp (MHD_HTTP_METHOD_PUT, method))
    {
      if (ps->recv_force_disconnect == GNUNET_YES)
	{
#if DEBUG_CONNECTIONS
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Connection %X: inbound connection was forced to disconnect\n",ps);
#endif
	  ps->recv_active = GNUNET_NO;
	  return MHD_NO;
	}
      if ((*upload_data_size == 0) && (ps->recv_active==GNUNET_NO))
	{
	  ps->recv_endpoint = mhd_connection;
	  ps->recv_connected = GNUNET_YES;
	  ps->recv_active = GNUNET_YES;
	  ps->recv_force_disconnect = GNUNET_NO;
#if DEBUG_CONNECTIONS
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Connection %X: inbound PUT connection connected\n",ps);
#endif
	  return MHD_YES;
	}
      
      /* Transmission of all data complete */
      if ((*upload_data_size == 0) && (ps->recv_active == GNUNET_YES))
	{
	  response = MHD_create_response_from_data (strlen (HTTP_PUT_RESPONSE),
						    HTTP_PUT_RESPONSE, 
						    MHD_NO, MHD_NO);
	  res = MHD_queue_response (mhd_connection, MHD_HTTP_OK, response);
#if DEBUG_CONNECTIONS
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Connection %X: Sent HTTP/1.1: 200 OK as PUT Response\n",
		      ps);
#endif
	  MHD_destroy_response (response);
	  ps->recv_active=GNUNET_NO;
	  return MHD_YES;
	}
      
      /* Recieving data */
      if ((*upload_data_size > 0) && (ps->recv_active == GNUNET_YES))
	{
	  if (pc->delay.rel_value == 0)
	    {
#if DEBUG_HTTP
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Connection %X: PUT with %u bytes forwarded to MST\n", 
			  ps, *upload_data_size);
#endif
	      res = GNUNET_SERVER_mst_receive(ps->msgtok, ps, 
					      upload_data, *upload_data_size, 
					      GNUNET_NO, GNUNET_NO);
	      (*upload_data_size) = 0;
	    }
	  else
	    {
#if DEBUG_HTTP
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Connection %X: no inbound bandwidth available! Next read was delayed for  %llu ms\n", 
			  ps, 
			  ps->peercontext->delay.rel_value);
#endif
	    }
	  return MHD_YES;
	}
      else
	return MHD_NO;
    }
  if ( 0 == strcmp (MHD_HTTP_METHOD_GET, method) )
    {
      if (ps->send_force_disconnect == GNUNET_YES)
	{
#if DEBUG_CONNECTIONS
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Connection %X: outbound connection was  forced to disconnect\n",
		      ps);
#endif
	  ps->send_active = GNUNET_NO;
	  return MHD_NO;
	}
      ps->send_connected = GNUNET_YES;
      ps->send_active = GNUNET_YES;
      ps->send_endpoint = mhd_connection;
      ps->send_force_disconnect = GNUNET_NO;
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection %X: inbound GET connection connected\n",
		  ps);
#endif
      response = MHD_create_response_from_callback(-1,32 * 1024, &mhd_send_callback, ps, NULL);
      res = MHD_queue_response (mhd_connection, MHD_HTTP_OK, response);
      MHD_destroy_response (response);
      return MHD_YES;
    }
  return MHD_NO;
}


/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 * @param plugin plugin
 * @param daemon_handle the MHD daemon handle
 * @return gnunet task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier
http_server_daemon_prepare (struct Plugin *plugin,
			    struct MHD_Daemon *daemon_handle)
{
  GNUNET_SCHEDULER_TaskIdentifier ret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  struct GNUNET_NETWORK_FDSet *wrs;
  struct GNUNET_NETWORK_FDSet *wws;
  struct GNUNET_NETWORK_FDSet *wes;
  int max;
  unsigned long long timeout;
  int haveto;
  struct GNUNET_TIME_Relative tv;

  ret = GNUNET_SCHEDULER_NO_TASK;
  FD_ZERO(&rs);
  FD_ZERO(&ws);
  FD_ZERO(&es);
  wrs = GNUNET_NETWORK_fdset_create ();
  wes = GNUNET_NETWORK_fdset_create ();
  wws = GNUNET_NETWORK_fdset_create ();
  max = -1;
  GNUNET_assert (MHD_YES ==
                 MHD_get_fdset (daemon_handle,
                                &rs,
                                &ws,
                                &es,
                                &max));
  haveto = MHD_get_timeout (daemon_handle, &timeout);
  if (haveto == MHD_YES)
    tv.rel_value = (uint64_t) timeout;
  else
    tv = GNUNET_TIME_UNIT_SECONDS;
  GNUNET_NETWORK_fdset_copy_native (wrs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (wws, &ws, max + 1);
  GNUNET_NETWORK_fdset_copy_native (wes, &es, max + 1);
  if (daemon_handle == plugin->http_server_daemon_v4)
    {
      if (plugin->http_server_task_v4 != GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel(plugin->http_server_task_v4);
	  plugin->http_server_daemon_v4 = GNUNET_SCHEDULER_NO_TASK;
	}
      
      ret = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
					 GNUNET_SCHEDULER_NO_TASK,
					 tv,
					 wrs,
					 wws,
					 &http_server_daemon_v4_run,
					 plugin);
    }
  if (daemon_handle == plugin->http_server_daemon_v6)
    {
      if (plugin->http_server_task_v6 != GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel(plugin->http_server_task_v6);
	  plugin->http_server_task_v6 = GNUNET_SCHEDULER_NO_TASK;
	}
      
      ret = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
					 GNUNET_SCHEDULER_NO_TASK,
					 tv,
					 wrs,
					 wws,
					 &http_server_daemon_v6_run,
					 plugin);
    }
  GNUNET_NETWORK_fdset_destroy (wrs);
  GNUNET_NETWORK_fdset_destroy (wws);
  GNUNET_NETWORK_fdset_destroy (wes);
  return ret;
}


/**
 * Call MHD IPv4 to process pending requests and then go back
 * and schedule the next run.
 * @param cls plugin as closure
 * @param tc task context
 */
static void 
http_server_daemon_v4_run (void *cls,
			   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

#if DEBUG_SCHEDULING
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY))
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"http_server_daemon_v4_run: GNUNET_SCHEDULER_REASON_READ_READY\n");
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_WRITE_READY)) 
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "http_server_daemon_v4_run: GNUNET_SCHEDULER_REASON_WRITE_READY\n");
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT))
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "http_server_daemon_v4_run: GNUNET_SCHEDULER_REASON_TIMEOUT\n");
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_STARTUP))
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "http_server_daemon_v4_run: GGNUNET_SCHEDULER_REASON_STARTUP\n");
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "http_server_daemon_v4_run: GGNUNET_SCHEDULER_REASON_SHUTDOWN\n");
#endif              
      
  GNUNET_assert(cls !=NULL);
  plugin->http_server_task_v4 = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_assert (MHD_YES == MHD_run (plugin->http_server_daemon_v4));
  plugin->http_server_task_v4 = http_server_daemon_prepare (plugin, plugin->http_server_daemon_v4);
 }


/**
 * Call MHD IPv6 to process pending requests and then go back
 * and schedule the next run.
 * @param cls plugin as closure
 * @param tc task context
 */
static void 
http_server_daemon_v6_run (void *cls,
			   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  
#if DEBUG_SCHEDULING  
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY))
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "http_server_daemon_v6_run: GNUNET_SCHEDULER_REASON_READ_READY\n");
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_WRITE_READY)) 
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "http_server_daemon_v6_run: GNUNET_SCHEDULER_REASON_WRITE_READY\n");
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT))
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "http_server_daemon_v6_run: GNUNET_SCHEDULER_REASON_TIMEOUT\n");
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_STARTUP))  
     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		 "http_server_daemon_v6_run: GGNUNET_SCHEDULER_REASON_STARTUP\n");
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))  
     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		 "http_server_daemon_v6_run: GGNUNET_SCHEDULER_REASON_SHUTDOWN\n");
#endif                                            

  GNUNET_assert(cls !=NULL);
  plugin->http_server_task_v6 = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_assert (MHD_YES == MHD_run (plugin->http_server_daemon_v6));
  plugin->http_server_task_v6 = http_server_daemon_prepare (plugin, plugin->http_server_daemon_v6);
}


static size_t 
curl_get_header_cb( void *ptr, 
		    size_t size, size_t nmemb, 
		    void *stream)
{
  struct Session * ps = stream;

  long http_result = 0;
  int res;
  /* Getting last http result code */
  GNUNET_assert(NULL!=ps);
  if (ps->recv_connected==GNUNET_NO)
    {
      res = curl_easy_getinfo(ps->recv_endpoint, CURLINFO_RESPONSE_CODE, &http_result);
      if (CURLE_OK == res)
	{
	  if (http_result == 200)
	    {
	      ps->recv_connected = GNUNET_YES;
	      ps->recv_active = GNUNET_YES;
#if DEBUG_CONNECTIONS
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: connected to recieve data\n",ps);
#endif
	      // Calling send_check_connections again since receive is established
	      send_check_connections (ps->peercontext->plugin, ps);
	    }
	}
    }
  
#if DEBUG_CURL
  char * tmp;
  size_t len = size * nmemb;
  tmp = NULL;
  if ((size * nmemb) < SIZE_MAX)
    tmp = GNUNET_malloc (len+1);

  if ((tmp != NULL) && (len > 0))
    {
      memcpy(tmp,ptr,len);
      if (len>=2)
	{
	  if (tmp[len-2] == 13)
	    tmp[len-2]= '\0';
	}
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection %X: Header: %s\n",
		  ps, tmp);
    }
  GNUNET_free_non_null (tmp);
#endif
  
  return size * nmemb;
}


/**
 * Callback called by libcurl when new headers arrive
 * Used to get HTTP result for curl operations
 * @param ptr stream to read from
 * @param size size of one char element
 * @param nmemb number of char elements
 * @param stream closure set by user
 * @return bytes read by function
 */
static size_t 
curl_put_header_cb(void *ptr, 
		   size_t size, 
		   size_t nmemb, 
		   void *stream)
{
  struct Session * ps = stream;

  char * tmp;
  size_t len = size * nmemb;
  long http_result = 0;
  int res;

  /* Getting last http result code */
  GNUNET_assert(NULL!=ps);
  res = curl_easy_getinfo (ps->send_endpoint, CURLINFO_RESPONSE_CODE, &http_result);
  if (CURLE_OK == res)
    {
      if ((http_result == 100) && (ps->send_connected==GNUNET_NO))
	{
	  ps->send_connected = GNUNET_YES;
	  ps->send_active = GNUNET_YES;
#if DEBUG_CONNECTIONS
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Connection %X: connected to send data\n",
		      ps);
#endif
	}
      if ((http_result == 200) && (ps->send_connected==GNUNET_YES))
	{
	  ps->send_connected = GNUNET_NO;
	  ps->send_active = GNUNET_NO;
#if DEBUG_CONNECTIONS
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Connection %X: sending disconnected\n",
		      ps);
#endif
	}
    }
  
  tmp = NULL;
  if ((size * nmemb) < SIZE_MAX)
    tmp = GNUNET_malloc (len+1);
  
  if ((tmp != NULL) && (len > 0))
    {
      memcpy(tmp,ptr,len);
      if (len>=2)
	{
	  if (tmp[len-2] == 13)
	    tmp[len-2]= '\0';
	}
    }
  GNUNET_free_non_null (tmp);
  return size * nmemb;
}

/**
 * Callback method used with libcurl
 * Method is called when libcurl needs to read data during sending
 * @param stream pointer where to write data
 * @param size size of an individual element
 * @param nmemb count of elements that can be written to the buffer
 * @param ptr source pointer, passed to the libcurl handle
 * @return bytes written to stream
 */
static size_t 
curl_send_cb(void *stream, 
	     size_t size, size_t nmemb, 
	     void *ptr)
{
  struct Session * ps = ptr;
  struct HTTP_Message * msg = ps->pending_msgs_tail;
  size_t bytes_sent;
  size_t len;

  if (ps->send_active == GNUNET_NO)
    return CURL_READFUNC_PAUSE;
  if ( (ps->pending_msgs_tail == NULL) && 
       (ps->send_active == GNUNET_YES) )
    {
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection %X: No Message to send, pausing connection\n",
		  ps);
#endif
      ps->send_active = GNUNET_NO;
    return CURL_READFUNC_PAUSE;
    }
  
  GNUNET_assert (msg!=NULL);
  
  /* data to send */
  if (msg->pos < msg->size)
    {
      /* data fit in buffer */
      if ((msg->size - msg->pos) <= (size * nmemb))
	{
	  len = (msg->size - msg->pos);
	  memcpy(stream, &msg->buf[msg->pos], len);
	  msg->pos += len;
	  bytes_sent = len;
	}
      else
	{
	  len = size*nmemb;
	  memcpy(stream, &msg->buf[msg->pos], len);
	  msg->pos += len;
	  bytes_sent = len;
	}
    }
  /* no data to send */
  else
    {
      bytes_sent = 0;
    }
  
  if ( msg->pos == msg->size)
    {
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection %X: Message with %u bytes sent, removing message from queue\n",
		  ps, 
		  msg->pos);
#endif
      /* Calling transmit continuation  */
      if (NULL != ps->pending_msgs_tail->transmit_cont)
	msg->transmit_cont (ps->pending_msgs_tail->transmit_cont_cls,
			    &(ps->peercontext)->identity,
			    GNUNET_OK);
      ps->queue_length_cur -= msg->size;
      remove_http_message(ps, msg);
    }
  return bytes_sent;
}


static void 
curl_receive_mst_cb  (void *cls,
		      void *client,
		      const struct GNUNET_MessageHeader *message)
{
  struct Session *ps  = cls;
  struct GNUNET_TIME_Relative delay;
  GNUNET_assert(ps != NULL);

  struct HTTP_PeerContext *pc = ps->peercontext;
  GNUNET_assert(pc != NULL);
#if DEBUG_HTTP
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %X: Forwarding message to transport service, type %u and size %u from `%s' (`%s')\n",
              ps,
              ntohs(message->type),
              ntohs(message->size),
              GNUNET_i2s(&(pc->identity)),
	      http_plugin_address_to_string(NULL,ps->addr,ps->addrlen));
#endif
  struct GNUNET_TRANSPORT_ATS_Information distance[2];
  distance[0].type = htonl (GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE);
  distance[0].value = htonl (1);
  distance[1].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  distance[1].value = htonl (0);

  delay = pc->plugin->env->receive (pc->plugin->env->cls,
				    &pc->identity,
				    message,
				    (const struct GNUNET_TRANSPORT_ATS_Information *) &distance, 2,
				    ps,
				    ps->addr,
				    ps->addrlen);
  pc->delay = delay;
  if (pc->reset_task != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (pc->reset_task);

  if (delay.rel_value > 0)
    {
#if DEBUG_HTTP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection %X: Inbound quota management: delay next read for %llu ms\n", 
		  ps, delay.rel_value);
#endif
      pc->reset_task = GNUNET_SCHEDULER_add_delayed (delay, &reset_inbound_quota_delay, pc);
    }
}


/**
* Callback method used with libcurl
* Method is called when libcurl needs to write data during sending
* @param stream pointer where to write data
* @param size size of an individual element
* @param nmemb count of elements that can be written to the buffer
* @param ptr destination pointer, passed to the libcurl handle
* @return bytes read from stream
*/
static size_t 
curl_receive_cb( void *stream, size_t size, size_t nmemb, void *ptr)
{
  struct Session * ps = ptr;

  if (ps->peercontext->delay.rel_value > 0)
    {
#if DEBUG_HTTP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection %X: no inbound bandwidth available! Next read was delayed for  %llu ms\n",
		  ps, ps->peercontext->delay.rel_value);
#endif
      return 0;
    }  
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Connection %X: %u bytes received\n",
	      ps, size*nmemb);
#endif
  GNUNET_SERVER_mst_receive(ps->msgtok, ps, 
			    stream, size*nmemb, 
			    GNUNET_NO, GNUNET_NO);
  return (size * nmemb);
}


static void 
curl_handle_finished (struct Plugin *plugin)
{
  struct Session *ps = NULL;
  struct HTTP_PeerContext *pc = NULL;
  struct CURLMsg *msg;
  struct HTTP_Message * cur_msg = NULL;
  int msgs_in_queue;
  char * tmp;
  long http_result;
  
  do
    {
      msg = curl_multi_info_read (plugin->multi_handle, &msgs_in_queue);
      if ((msgs_in_queue == 0) || (msg == NULL))
	break;
      /* get session for affected curl handle */
      GNUNET_assert ( msg->easy_handle != NULL );
      curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &tmp);
      ps = (struct Session *) tmp;
      GNUNET_assert ( ps != NULL );
      pc = ps->peercontext;
      GNUNET_assert ( pc != NULL );
      switch (msg->msg)
	{
	case CURLMSG_DONE:
	  if ( (msg->data.result != CURLE_OK) &&
	       (msg->data.result != CURLE_GOT_NOTHING) )
	    {
	      /* sending msg failed*/
	      if (msg->easy_handle == ps->send_endpoint)
		{
#if DEBUG_CONNECTIONS
		  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
			     _("Connection %X: HTTP PUT to peer `%s' (`%s') failed: `%s' `%s'\n"),
			     ps,
			     GNUNET_i2s(&pc->identity),
			     http_plugin_address_to_string(NULL, ps->addr, ps->addrlen),
			     "curl_multi_perform",
			     curl_easy_strerror (msg->data.result));
#endif
		  ps->send_connected = GNUNET_NO;
		  ps->send_active = GNUNET_NO;
		  curl_multi_remove_handle(plugin->multi_handle,ps->send_endpoint);
		  while (ps->pending_msgs_tail != NULL)
		    {
		      cur_msg = ps->pending_msgs_tail;
		      if ( NULL != cur_msg->transmit_cont)
			cur_msg->transmit_cont (cur_msg->transmit_cont_cls,&pc->identity,GNUNET_SYSERR);
		      ps->queue_length_cur -= cur_msg->size;
		      remove_http_message(ps,cur_msg);
		    }
		}
	      /* GET connection failed */
	      if (msg->easy_handle == ps->recv_endpoint)
		{
#if DEBUG_CONNECTIONS
		  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
			     _("Connection %X: HTTP GET to peer `%s' (`%s') failed: `%s' `%s'\n"),
			     ps,
			     GNUNET_i2s(&pc->identity),
			     http_plugin_address_to_string(NULL, ps->addr, ps->addrlen),
			     "curl_multi_perform",
			     curl_easy_strerror (msg->data.result));
#endif
		  ps->recv_connected = GNUNET_NO;
		  ps->recv_active = GNUNET_NO;
		  curl_multi_remove_handle(plugin->multi_handle,ps->recv_endpoint);
		}
	    }
	  else
	    {
	      if (msg->easy_handle == ps->send_endpoint)
		{
		  GNUNET_assert (CURLE_OK == curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &http_result));
#if DEBUG_CONNECTIONS
		  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			      "Connection %X: HTTP PUT connection to peer `%s' (`%s') was closed with HTTP code %u\n",
			      ps,
			      GNUNET_i2s(&pc->identity),
			      http_plugin_address_to_string(NULL, ps->addr, ps->addrlen),
			      http_result);
#endif
		  /* Calling transmit continuation  */
		  while (ps->pending_msgs_tail != NULL)
		    {
		      cur_msg = ps->pending_msgs_tail;
		      if ( NULL != cur_msg->transmit_cont)
			{
			  /* HTTP 1xx : Last message before here was informational */
			  if ((http_result >=100) && (http_result < 200))
			    cur_msg->transmit_cont (cur_msg->transmit_cont_cls,&pc->identity,GNUNET_OK);
			  /* HTTP 2xx: successful operations */
			  if ((http_result >=200) && (http_result < 300))
			    cur_msg->transmit_cont (cur_msg->transmit_cont_cls,&pc->identity,GNUNET_OK);
			  /* HTTP 3xx..5xx: error */
			  if ((http_result >=300) && (http_result < 600))
			    cur_msg->transmit_cont (cur_msg->transmit_cont_cls,&pc->identity,GNUNET_SYSERR);
			}
		      ps->queue_length_cur -= cur_msg->size;
		      remove_http_message(ps,cur_msg);
		    }
		  
		  ps->send_connected = GNUNET_NO;
		  ps->send_active = GNUNET_NO;
		  curl_multi_remove_handle(plugin->multi_handle,ps->send_endpoint);
		}
	      if (msg->easy_handle == ps->recv_endpoint)
		{
#if DEBUG_CONNECTIONS
		  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			      "Connection %X: HTTP GET connection to peer `%s' (`%s') was closed with HTTP code %u\n",
			      ps,
			      GNUNET_i2s(&pc->identity),
			      http_plugin_address_to_string(NULL, ps->addr, ps->addrlen),
			      http_result);
#endif
		  ps->recv_connected = GNUNET_NO;
		  ps->recv_active = GNUNET_NO;
		  curl_multi_remove_handle(plugin->multi_handle,ps->recv_endpoint);
		}
	      plugin->current_connections--;
	    }
	  if ((ps->recv_connected == GNUNET_NO) && (ps->send_connected == GNUNET_NO))
	    remove_session (pc, ps, GNUNET_YES, GNUNET_SYSERR);
	  break;
	default:
	  break;
	}
    }
  while ( (msgs_in_queue > 0) );
}


/**
 * Task performing curl operations
 * @param cls plugin as closure
 * @param tc gnunet scheduler task context
 */
static void curl_perform (void *cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  static unsigned int handles_last_run;
  int running;
  CURLMcode mret;

  GNUNET_assert(cls !=NULL);

  plugin->http_curl_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  do
    {
      running = 0;
      mret = curl_multi_perform (plugin->multi_handle, &running);
      if ((running < handles_last_run) && (running>0))
    	  curl_handle_finished(plugin);
      handles_last_run = running;
    }
  while (mret == CURLM_CALL_MULTI_PERFORM);
  curl_schedule(plugin);
}


/**
 * Function setting up file descriptors and scheduling task to run
 *
 * @param  plugin plugin as closure
 * @return GNUNET_SYSERR for hard failure, GNUNET_OK for ok
 */
static int 
curl_schedule(struct Plugin *plugin)
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct GNUNET_NETWORK_FDSet *grs;
  struct GNUNET_NETWORK_FDSet *gws;
  long to;
  CURLMcode mret;

  /* Cancel previous scheduled task */
  if (plugin->http_curl_task !=  GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel(plugin->http_curl_task);
      plugin->http_curl_task = GNUNET_SCHEDULER_NO_TASK;
    }
  
  max = -1;
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  mret = curl_multi_fdset (plugin->multi_handle, &rs, &ws, &es, &max);
  if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_fdset", __FILE__, __LINE__,
                  curl_multi_strerror (mret));
      return GNUNET_SYSERR;
    }
  mret = curl_multi_timeout (plugin->multi_handle, &to);
  if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_timeout", __FILE__, __LINE__,
                  curl_multi_strerror (mret));
      return GNUNET_SYSERR;
    }

  grs = GNUNET_NETWORK_fdset_create ();
  gws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (grs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (gws, &ws, max + 1);
  plugin->http_curl_task = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
							GNUNET_SCHEDULER_NO_TASK,
							(to == -1) 
							? GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)
							: GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, to),
							grs,
							gws,
							&curl_perform,
							plugin);
  GNUNET_NETWORK_fdset_destroy (gws);
  GNUNET_NETWORK_fdset_destroy (grs);
  return GNUNET_OK;
}


#if DEBUG_CURL
/**
 * Function to log curl debug messages with GNUNET_log
 * @param curl handle
 * @param type curl_infotype
 * @param data data
 * @param size size
 * @param cls  closure
 * @return 0
 */
static int 
curl_logger (CURL * curl,
	     curl_infotype type, 
	     char * data, size_t size, 
	     void * cls)
{
  if (type == CURLINFO_TEXT)
    {
      char text[size+2];
      memcpy(text,data,size);
      if (text[size-1] == '\n')
	text[size] = '\0';
      else
	{
	  text[size] = '\n';
	  text[size+1] = '\0';
	}
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "CURL: Connection %X - %s", 
		  cls, 
		  text);
    }
  return 0;
}
#endif


/**
 * Function setting up curl handle and selecting message to send
 *
 * @param plugin plugin
 * @param ps session
 * @return GNUNET_SYSERR on failure, GNUNET_NO if connecting, GNUNET_YES if ok
 */
static int 
send_check_connections (struct Plugin *plugin, 
			struct Session *ps)
{
  CURLMcode mret;
  struct GNUNET_TIME_Relative timeout = GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT;

  if ((ps->direction == OUTBOUND) && (plugin->current_connections < plugin->max_connect_per_transport))
    {
      /* RECV DIRECTION */
      /* Check if session is connected to receive data, otherwise connect to peer */

      if (ps->recv_connected == GNUNET_NO)
	{
	  int fresh = GNUNET_NO;
	  if (ps->recv_endpoint == NULL)
	    {
	      fresh = GNUNET_YES;
	      ps->recv_endpoint = curl_easy_init();
	    }
#if DEBUG_CURL
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_VERBOSE, 1L);
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_DEBUGFUNCTION , &curl_logger);
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_DEBUGDATA , ps->recv_endpoint);
#endif
#if BUILD_HTTPS
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_SSL_VERIFYPEER, 0);
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_SSL_VERIFYHOST, 0);
#endif
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_URL, ps->url);
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_HEADERFUNCTION, &curl_get_header_cb);
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_WRITEHEADER, ps);
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_READFUNCTION, curl_send_cb);
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_READDATA, ps);
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_WRITEFUNCTION, curl_receive_cb);
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_WRITEDATA, ps);
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_TIMEOUT, (long) timeout.rel_value);
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_PRIVATE, ps);
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_CONNECTTIMEOUT, HTTP_CONNECT_TIMEOUT);
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_BUFFERSIZE, 2*GNUNET_SERVER_MAX_MESSAGE_SIZE);
#if CURL_TCP_NODELAY
	  curl_easy_setopt(ps->recv_endpoint, CURLOPT_TCP_NODELAY, 1);
#endif
	  if (fresh==GNUNET_YES)
	    {
	      mret = curl_multi_add_handle(plugin->multi_handle, ps->recv_endpoint);
	      if (mret != CURLM_OK)
		{
		  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			      _("Connection: %X: %s failed at %s:%d: `%s'\n"),
			      ps,
			      "curl_multi_add_handle", __FILE__, __LINE__,
			      curl_multi_strerror (mret));
		  return GNUNET_SYSERR;
		}
	    }
	  if (plugin->http_curl_task != GNUNET_SCHEDULER_NO_TASK)
	    {
	      GNUNET_SCHEDULER_cancel(plugin->http_curl_task);
	      plugin->http_curl_task = GNUNET_SCHEDULER_NO_TASK;
	    }
	  plugin->current_connections ++;
	  plugin->http_curl_task = GNUNET_SCHEDULER_add_now (&curl_perform, plugin);
	}
      
      /* waiting for receive direction */
      if (ps->recv_connected==GNUNET_NO)
	return GNUNET_NO;
      
      /* SEND DIRECTION */
      /* Check if session is connected to send data, otherwise connect to peer */
      if ((ps->send_connected == GNUNET_YES) && (ps->send_endpoint!= NULL))
	{
	  if (ps->send_active == GNUNET_YES)
	    {
#if DEBUG_CONNECTIONS
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Connection %X: outbound active, enqueueing message\n",
			  ps);
#endif
	      return GNUNET_YES;
	    }
	  if (ps->send_active == GNUNET_NO)
	    {
#if DEBUG_CONNECTIONS
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Connection %X: outbound paused, unpausing existing connection and enqueueing message\n",
			  ps);
#endif
	      if (CURLE_OK == curl_easy_pause(ps->send_endpoint,CURLPAUSE_CONT))
		{
		  ps->send_active=GNUNET_YES;
		  if (plugin->http_curl_task !=  GNUNET_SCHEDULER_NO_TASK)
		    {
		      GNUNET_SCHEDULER_cancel(plugin->http_curl_task);
		      plugin->http_curl_task = GNUNET_SCHEDULER_NO_TASK;
		    }
		  plugin->http_curl_task = GNUNET_SCHEDULER_add_now (&curl_perform, plugin);
		  return GNUNET_YES;
		}
	      else
        	return GNUNET_SYSERR;
	    }
	}
      /* not connected, initiate connection */
      if ((ps->send_connected==GNUNET_NO) && (plugin->current_connections < plugin->max_connect_per_transport))
	{
	  int fresh = GNUNET_NO;
	  if (NULL == ps->send_endpoint)
	    {
	      ps->send_endpoint = curl_easy_init();
	      fresh = GNUNET_YES;
	    }
	  GNUNET_assert (ps->send_endpoint != NULL);
	  GNUNET_assert (NULL != ps->pending_msgs_tail);
#if DEBUG_CONNECTIONS
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Connection %X: outbound not connected, initiating connection\n",
		      ps);
#endif
	  ps->send_active = GNUNET_NO;
	  
#if DEBUG_CURL
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_VERBOSE, 1L);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_DEBUGFUNCTION , &curl_logger);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_DEBUGDATA , ps->send_endpoint);
#endif
#if BUILD_HTTPS
	  curl_easy_setopt (ps->send_endpoint, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_SSL_VERIFYPEER, 0);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_SSL_VERIFYHOST, 0);
#endif
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_URL, ps->url);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_PUT, 1L);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_HEADERFUNCTION, &curl_put_header_cb);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_WRITEHEADER, ps);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_READFUNCTION, curl_send_cb);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_READDATA, ps);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_WRITEFUNCTION, curl_receive_cb);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_READDATA, ps);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_TIMEOUT, (long) timeout.rel_value);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_PRIVATE, ps);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_CONNECTTIMEOUT, HTTP_CONNECT_TIMEOUT);
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_BUFFERSIZE, 2 * GNUNET_SERVER_MAX_MESSAGE_SIZE);
#if CURL_TCP_NODELAY
	  curl_easy_setopt(ps->send_endpoint, CURLOPT_TCP_NODELAY, 1);
#endif
	  if (fresh==GNUNET_YES)
	    {
	      mret = curl_multi_add_handle(plugin->multi_handle, ps->send_endpoint);
	      if (mret != CURLM_OK)
		{
		  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			      _("Connection: %X: %s failed at %s:%d: `%s'\n"),
			      ps,
			      "curl_multi_add_handle", __FILE__, __LINE__,
			      curl_multi_strerror (mret));
		  return GNUNET_SYSERR;
		}
	    }
	}
      if (plugin->http_curl_task !=  GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel(plugin->http_curl_task);
	  plugin->http_curl_task = GNUNET_SCHEDULER_NO_TASK;
	}
      plugin->current_connections++;
      plugin->http_curl_task = GNUNET_SCHEDULER_add_now (&curl_perform, plugin);
      return GNUNET_YES;
    }
  if (ps->direction == INBOUND)
    {
      GNUNET_assert (NULL != ps->pending_msgs_tail);
      if ((ps->recv_connected==GNUNET_YES) && (ps->send_connected==GNUNET_YES) &&
	  (ps->recv_force_disconnect==GNUNET_NO) && (ps->recv_force_disconnect==GNUNET_NO))
    	return GNUNET_YES;
    }
  return GNUNET_SYSERR;
}


/**
 * select best session to transmit data to peer
 *
 * @param pc peer context of target peer
 * @param addr address of target peer
 * @param addrlen address length
 * @param force_address does transport service enforce address?
 * @param session session passed by transport service
 * @return selected session
 *
 */
static struct Session * 
send_select_session (struct HTTP_PeerContext *pc, 
		     const void * addr, size_t addrlen, 
		     int force_address, 
		     struct Session * session)
{
  struct Session * tmp = NULL;
  int addr_given = GNUNET_NO;
  
  if ((addr!=NULL) && (addrlen>0))
    addr_given = GNUNET_YES;
  
  if (force_address == GNUNET_YES)
    {
      /* check session given as argument */
      if ((session != NULL) && (addr_given == GNUNET_YES))
	{
	  if (0 == memcmp(session->addr, addr, addrlen))
	    {
	      /* connection can not be used, since it is disconnected */
	      if ( (session->recv_force_disconnect==GNUNET_NO) && 
		   (session->send_force_disconnect==GNUNET_NO) )
		{
#if DEBUG_SESSION_SELECTION
		  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			      "Session %X selected: Using session passed by transport to send to forced address \n", 
			      session);
#endif
		  return session;
		}
	    }
	}
      /* check last session used */
      if ((pc->last_session != NULL)&& (addr_given == GNUNET_YES))
	{
	  if (0 == memcmp(pc->last_session->addr, addr, addrlen))
	    {
	      /* connection can not be used, since it is disconnected */
	      if ( (pc->last_session->recv_force_disconnect==GNUNET_NO) && 
		   (pc->last_session->send_force_disconnect==GNUNET_NO) )
		{
#if DEBUG_SESSION_SELECTION
		  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			      "Session %X selected: Using last session used to send to forced address \n", 
			      pc->last_session);
#endif
		  return pc->last_session;
		}
	    }
	}
      /* find session in existing sessions */
      tmp = pc->head;
      while ((tmp!=NULL) && (addr_given == GNUNET_YES))
	{
	  if (0 == memcmp(tmp->addr, addr, addrlen))
	    {
	      /* connection can not be used, since it is disconnected */
	      if ( (tmp->recv_force_disconnect==GNUNET_NO) &&
		   (tmp->send_force_disconnect==GNUNET_NO) )
		{
#if DEBUG_SESSION_SELECTION
		  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			      "Session %X selected: Using existing session to send to forced address \n", 
			      session);
#endif
		  return session;
		}	      
	    }
	  tmp=tmp->next;
	}
      /* no session to use */
      return NULL;
    }
  if ((force_address == GNUNET_NO) || (force_address == GNUNET_SYSERR))
    {
      /* check session given as argument */
      if (session != NULL)
	{
	  /* connection can not be used, since it is disconnected */
	  if ( (session->recv_force_disconnect==GNUNET_NO) &&
	       (session->send_force_disconnect==GNUNET_NO) )
	    {
#if DEBUG_SESSION_SELECTION
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Session %X selected: Using session passed by transport to send not-forced address\n", 
			  session);
#endif
	      return session;
	    }	  
	}
      /* check last session used */
      if (pc->last_session != NULL)
	{
	  /* connection can not be used, since it is disconnected */
	  if ( (pc->last_session->recv_force_disconnect==GNUNET_NO) &&
	       (pc->last_session->send_force_disconnect==GNUNET_NO) )
	    {
#if DEBUG_SESSION_SELECTION
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Session %X selected: Using last session to send to not-forced address\n", 
			  pc->last_session);
#endif
	      return pc->last_session;
	    }
	}
      /* find session in existing sessions */
      tmp = pc->head;
      while (tmp!=NULL)
	{
	  /* connection can not be used, since it is disconnected */
	  if ( (tmp->recv_force_disconnect==GNUNET_NO) && 
	       (tmp->send_force_disconnect==GNUNET_NO) )
	    {
#if DEBUG_SESSION_SELECTION
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Session %X selected: Using existing session to send to not-forced address\n",
			  tmp);
#endif
	      return tmp;
	    }
	  tmp=tmp->next;
	}
      return NULL;
    }
  return NULL;
}


/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.   Note that in the case of a
 * peer disconnecting, the continuation MUST be called
 * prior to the disconnect notification itself.  This function
 * will be called with this peer's HELLO message to initiate
 * a fresh connection to another peer.
 *
 * @param cls closure
 * @param target who should receive this message
 * @param msgbuf the message to transmit
 * @param msgbuf_size number of bytes in 'msgbuf'
 * @param priority how important is the message (most plugins will
 *                 ignore message priority and just FIFO)
 * @param to how long to wait at most for the transmission (does not
 *                require plugins to discard the message after the timeout,
 *                just advisory for the desired delay; most plugins will ignore
 *                this as well)
 * @param session which session must be used (or NULL for "any")
 * @param addr the address to use (can be NULL if the plugin
 *                is "on its own" (i.e. re-use existing TCP connection))
 * @param addrlen length of the address in bytes
 * @param force_address GNUNET_YES if the plugin MUST use the given address,
 *                GNUNET_NO means the plugin may use any other address and
 *                GNUNET_SYSERR means that only reliable existing
 *                bi-directional connections should be used (regardless
 *                of address)
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...); can be NULL
 * @param cont_cls closure for cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
http_plugin_send (void *cls,
                  const struct GNUNET_PeerIdentity *target,
                  const char *msgbuf,
                  size_t msgbuf_size,
                  unsigned int priority,
                  struct GNUNET_TIME_Relative to,
                  struct Session *session,
                  const void *addr,
                  size_t addrlen,
                  int force_address,
                  GNUNET_TRANSPORT_TransmitContinuation cont,
                  void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct HTTP_Message *msg;
  struct HTTP_PeerContext * pc;
  struct Session * ps = NULL;

  GNUNET_assert(cls !=NULL);

#if DEBUG_HTTP
  char * force;

  if (force_address == GNUNET_YES)
    GNUNET_asprintf(&force, "forced addr.");
  else if (force_address == GNUNET_NO)
    GNUNET_asprintf(&force, "any addr.");
  else if (force_address == GNUNET_SYSERR)
    GNUNET_asprintf(&force,"reliable bi-direc. address addr.");
  else
    GNUNET_assert (0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transport tells me to send %u bytes to `%s' using %s (%s) and session: %X\n",
	      msgbuf_size,
	      GNUNET_i2s(target),
	      force,
	      http_plugin_address_to_string(NULL, addr, addrlen),
	      session);
  GNUNET_free(force);
#endif

  pc = GNUNET_CONTAINER_multihashmap_get (plugin->peers, &target->hashPubKey);
  /* Peer unknown */
  if (pc==NULL)
    {
      pc = GNUNET_malloc(sizeof (struct HTTP_PeerContext));
      pc->plugin = plugin;
      pc->session_id_counter=1;
      pc->last_session = NULL;
      memcpy(&pc->identity, target, sizeof(struct GNUNET_PeerIdentity));
      GNUNET_CONTAINER_multihashmap_put (plugin->peers, 
					 &pc->identity.hashPubKey, 
					 pc, 
					 GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
      GNUNET_STATISTICS_update (plugin->env->stats,
				gettext_noop ("# HTTP peers active"),
				1,
				GNUNET_NO);
    }
  ps = send_select_session (pc, addr, addrlen, force_address, session);
  /* session not existing, but address forced -> creating new session */
  if (ps==NULL)
    {
      if ((addr!=NULL) && (addrlen!=0))
	{
	  ps = GNUNET_malloc(sizeof (struct Session));
#if DEBUG_SESSION_SELECTION
	  if (force_address == GNUNET_YES)
	    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			"No existing connection & forced address: creating new session %X to peer %s\n", 
			ps, GNUNET_i2s(target));
	  if (force_address != GNUNET_YES)
	    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			"No existing connection: creating new session %X to peer %s\n", 
			ps, GNUNET_i2s(target));
#endif
 	  ps->addr = GNUNET_malloc(addrlen);
	  memcpy(ps->addr,addr,addrlen);
	  ps->addrlen = addrlen;
  	  ps->direction=OUTBOUND;
	  ps->recv_connected = GNUNET_NO;
	  ps->recv_force_disconnect = GNUNET_NO;
	  ps->send_connected = GNUNET_NO;
	  ps->send_force_disconnect = GNUNET_NO;
	  ps->pending_msgs_head = NULL;
	  ps->pending_msgs_tail = NULL;
	  ps->peercontext=pc;
	  ps->session_id = pc->session_id_counter;
	  ps->queue_length_cur = 0;
	  ps->queue_length_max = GNUNET_SERVER_MAX_MESSAGE_SIZE;
	  pc->session_id_counter++;
	  ps->url = create_url (plugin, ps->addr, ps->addrlen, ps->session_id);
	  if (ps->msgtok == NULL)
	    ps->msgtok = GNUNET_SERVER_mst_create (&curl_receive_mst_cb, ps);
	  GNUNET_CONTAINER_DLL_insert(pc->head,pc->tail,ps);
	  GNUNET_STATISTICS_update (plugin->env->stats,
				    gettext_noop ("# HTTP outbound sessions for peers active"),
				    1,
				    GNUNET_NO);
	}
      else
	{
#if DEBUG_HTTP
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "No existing session found & and no address given: no way to send this message to peer `%s'!\n", 
		      GNUNET_i2s(target));
#endif
	  return GNUNET_SYSERR;
	}
    }
  
  if (msgbuf_size >= (ps->queue_length_max - ps->queue_length_cur))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Queue %X full: %u bytes in queue available, message with %u is too big\n", 
		  ps, 
		  (ps->queue_length_max - ps->queue_length_cur), 
		  msgbuf_size);
      //return GNUNET_SYSERR;
    }
  
  /* create msg */
  msg = GNUNET_malloc (sizeof (struct HTTP_Message) + msgbuf_size);
  msg->next = NULL;
  msg->size = msgbuf_size;
  msg->pos = 0;
  msg->buf = (char *) &msg[1];
  msg->transmit_cont = cont;
  msg->transmit_cont_cls = cont_cls;
  memcpy (msg->buf,msgbuf, msgbuf_size);  
  GNUNET_CONTAINER_DLL_insert (ps->pending_msgs_head,
			       ps->pending_msgs_tail,
			       msg);
  ps->queue_length_cur += msgbuf_size;
  if (send_check_connections (plugin, ps) == GNUNET_SYSERR)
    return GNUNET_SYSERR;
  if (force_address != GNUNET_YES)
    pc->last_session = ps;
  if (pc->last_session==NULL)
    pc->last_session = ps;
  return msg->size;
}


/**
 * Function that can be used to force the plugin to disconnect
 * from the given peer and cancel all previous transmissions
 * (and their continuationc).
 *
 * @param cls closure
 * @param target peer from which to disconnect
 */
static void
http_plugin_disconnect (void *cls,
                            const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;
  struct HTTP_PeerContext *pc = NULL;
  struct Session *ps = NULL;

  pc = GNUNET_CONTAINER_multihashmap_get (plugin->peers, &target->hashPubKey);
  if (pc==NULL)
    return;
  ps = pc->head;
  while (ps!=NULL)
    {
      /* Telling transport that session is getting disconnected */
      plugin->env->session_end(plugin, target, ps);
      if (ps->direction==OUTBOUND)
	{
	  if (ps->send_endpoint!=NULL)
	    {
	      //GNUNET_assert(CURLM_OK == curl_multi_remove_handle(plugin->multi_handle,ps->send_endpoint));
	      //curl_easy_cleanup(ps->send_endpoint);
	      //ps->send_endpoint=NULL;
	      ps->send_force_disconnect = GNUNET_YES;
	    }
	  if (ps->recv_endpoint!=NULL)
	    {
	      //GNUNET_assert(CURLM_OK == curl_multi_remove_handle(plugin->multi_handle,ps->recv_endpoint));
	      //curl_easy_cleanup(ps->recv_endpoint);
	      //ps->recv_endpoint=NULL;
	      ps->recv_force_disconnect = GNUNET_YES;
	    }
	}
      if (ps->direction==INBOUND)
	{
	  ps->recv_force_disconnect = GNUNET_YES;
	  ps->send_force_disconnect = GNUNET_YES;
	}      
      while (ps->pending_msgs_head!=NULL)
	remove_http_message(ps, ps->pending_msgs_head);
      ps->recv_active = GNUNET_NO;
      ps->send_active = GNUNET_NO;
      ps=ps->next;
    }
}


/**
 * Append our port and forward the result.
 *
 * @param cls the 'struct PrettyPrinterContext*'
 * @param hostname hostname part of the address
 */
static void
append_port (void *cls, const char *hostname)
{
  struct PrettyPrinterContext *ppc = cls;
  char *ret;

  if (hostname == NULL)
    {
      ppc->asc (ppc->asc_cls, NULL);
      GNUNET_free (ppc);
      return;
    }
  GNUNET_asprintf (&ret, "%s://%s:%d", PROTOCOL_PREFIX, hostname, ppc->port);

  ppc->asc (ppc->asc_cls, ret);
  GNUNET_free (ret);
}



/**
 * Convert the transports address to a nice, human-readable
 * format.
 *
 * @param cls closure
 * @param type name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for asc
 */
static void
http_plugin_address_pretty_printer (void *cls,
                                        const char *type,
                                        const void *addr,
                                        size_t addrlen,
                                        int numeric,
                                        struct GNUNET_TIME_Relative timeout,
                                        GNUNET_TRANSPORT_AddressStringCallback
                                        asc, void *asc_cls)
{
  struct PrettyPrinterContext *ppc;
  const void *sb;
  size_t sbs;
  struct sockaddr_in  a4;
  struct sockaddr_in6 a6;
  const struct IPv4HttpAddress *t4;
  const struct IPv6HttpAddress *t6;
  uint16_t port;

  if (addrlen == sizeof (struct IPv6HttpAddress))
    {
      t6 = addr;
      memset (&a6, 0, sizeof (a6));
      a6.sin6_family = AF_INET6;
      a6.sin6_port = t6->port;
      memcpy (&a6.sin6_addr,
              &t6->ipv6_addr,
              sizeof (struct in6_addr));
      port = ntohs (t6->port);
      sb = &a6;
      sbs = sizeof (a6);
    }
  else if (addrlen == sizeof (struct IPv4HttpAddress))
    {
      t4 = addr;
      memset (&a4, 0, sizeof (a4));
      a4.sin_family = AF_INET;
      a4.sin_port = t4->port;
      a4.sin_addr.s_addr = t4->ipv4_addr;
      port = ntohs (t4->ipv4_addr);
      sb = &a4;
      sbs = sizeof (a4);
    }
  else
    {
      /* invalid address */
      GNUNET_break_op (0);
      asc (asc_cls, NULL);
      return;
    }
  ppc = GNUNET_malloc (sizeof (struct PrettyPrinterContext));
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  ppc->port = port;
  GNUNET_RESOLVER_hostname_get (sb,
                                sbs,
                                !numeric, timeout, &append_port, ppc);
}



/**
 * Another peer has suggested an address for this
 * peer and transport plugin.  Check that this could be a valid
 * address.  If so, consider adding it to the list
 * of addresses.
 *
 * @param cls closure
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport
 */
static int
http_plugin_address_suggested (void *cls,
                               const void *addr, size_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4HttpAddress *v4;
  struct IPv6HttpAddress *v6;
  struct IPv4HttpAddressWrapper *w_tv4 = plugin->ipv4_addr_head;
  struct IPv6HttpAddressWrapper *w_tv6 = plugin->ipv6_addr_head;

  GNUNET_assert(cls !=NULL);
  if ((addrlen != sizeof (struct IPv4HttpAddress)) &&
      (addrlen != sizeof (struct IPv6HttpAddress)))
    return GNUNET_SYSERR;
  if (addrlen == sizeof (struct IPv4HttpAddress))
    {
      v4 = (struct IPv4HttpAddress *) addr;
      if (plugin->bind4_address!=NULL)
	{
    	  if (0 == memcmp (&plugin->bind4_address->sin_addr, &v4->ipv4_addr, sizeof(uint32_t)))
	    return GNUNET_OK;
    	  else
	    return GNUNET_SYSERR;
	}
      while (w_tv4!=NULL)
	{
    	  if (0==memcmp (&w_tv4->addr->ipv4_addr, &v4->ipv4_addr, sizeof(uint32_t)))
	    break;
    	  w_tv4 = w_tv4->next;
	}
      if (w_tv4 != NULL)
        return GNUNET_OK;
      else
	return GNUNET_SYSERR;
    }
  if (addrlen == sizeof (struct IPv6HttpAddress))
    {
      v6 = (struct IPv6HttpAddress *) addr;
      if (plugin->bind6_address!=NULL)
	{
    	  if (0 == memcmp (&plugin->bind6_address->sin6_addr, &v6->ipv6_addr, sizeof(struct in6_addr)))
	    return GNUNET_OK;
    	  else
	    return GNUNET_SYSERR;
	}
      while (w_tv6!=NULL)
	{
    	  if (0 == memcmp (&w_tv6->addr->ipv6_addr, &v6->ipv6_addr, sizeof(struct in6_addr)))
	    break;
    	  w_tv6 = w_tv6->next;
	}
      if (w_tv6 !=NULL)
        return GNUNET_OK;
      else
	return GNUNET_SYSERR;
    }
  return GNUNET_SYSERR;
}


/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param cls closure
 * @param addr binary address
 * @param addrlen length of the address
 * @return string representing the same address
 */
static const char*
http_plugin_address_to_string (void *cls,
                                   const void *addr,
                                   size_t addrlen)
{
  const struct IPv4HttpAddress *t4;
  const struct IPv6HttpAddress *t6;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  char * address;
  static char rbuf[INET6_ADDRSTRLEN + 13];
  uint16_t port;
  int res;

  if (addrlen == sizeof (struct IPv6HttpAddress))
    {
      address = GNUNET_malloc (INET6_ADDRSTRLEN);
      t6 = addr;
      a6.sin6_addr = t6->ipv6_addr;
      inet_ntop(AF_INET6, &(a6.sin6_addr),address,INET6_ADDRSTRLEN);
      port = ntohs(t6->port);
    }
  else if (addrlen == sizeof (struct IPv4HttpAddress))
    {
      address = GNUNET_malloc (INET_ADDRSTRLEN);
      t4 = addr;
      a4.sin_addr.s_addr =  t4->ipv4_addr;
      inet_ntop(AF_INET, &(a4.sin_addr),address,INET_ADDRSTRLEN);
      port = ntohs(t4->port);
    }
  else
    {
      /* invalid address */
      return NULL;
    }

  res = GNUNET_snprintf (rbuf,
                   sizeof (rbuf),
                   "%s:%u",
                   address,
                   port);

  GNUNET_free (address);
  GNUNET_assert(res != 0);
  return rbuf;
}

/**
 * Function called by the NAT subsystem suggesting another peer wants
 * to connect to us via connection reversal.  Try to connect back to the
 * given IP.
 *
 * @param cls closure
 * @param addr address to try
 * @param addrlen number of bytes in addr
 */
static void
try_connection_reversal (void *cls,
                         const struct sockaddr *addr,
                         socklen_t addrlen)
{

}

static void
tcp_nat_cb_add_addr (void *cls,
                         int add_remove,
                         const struct sockaddr *addr,
                         socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4HttpAddress * t4 = NULL;
  struct IPv4HttpAddressWrapper * w_t4 = NULL;
  struct IPv6HttpAddress * t6 = NULL;
  struct IPv6HttpAddressWrapper * w_t6 = NULL;
  int af;

  af = addr->sa_family;
  switch (af)
  {
  case AF_INET:
    w_t4 = plugin->ipv4_addr_head;
    while (w_t4 != NULL)
    {
      int res = memcmp(&w_t4->addr->ipv4_addr,
                       &((struct sockaddr_in *) addr)->sin_addr,
                       sizeof (struct in_addr));
      if (0 == res)
        break;
      w_t4 = w_t4->next;
    }
    if (w_t4 == NULL)
    {
      w_t4 = GNUNET_malloc(sizeof(struct IPv4HttpAddressWrapper));
      t4 = GNUNET_malloc(sizeof(struct IPv4HttpAddress));
      memcpy (&t4->ipv4_addr,
            &((struct sockaddr_in *) addr)->sin_addr,
            sizeof (struct in_addr));
      t4->port = htons (plugin->port_inbound);

      w_t4->addr = t4;

      GNUNET_CONTAINER_DLL_insert(plugin->ipv4_addr_head,
                                  plugin->ipv4_addr_tail,w_t4);
    }
    plugin->env->notify_address(plugin->env->cls,
                                add_remove,
                                w_t4->addr, sizeof (struct IPv4HttpAddress));

    break;
  case AF_INET6:
    w_t6 = plugin->ipv6_addr_head;
    while (w_t6)
    {
      int res = memcmp(&w_t6->addr->ipv6_addr,
                       &((struct sockaddr_in6 *) addr)->sin6_addr,
                       sizeof (struct in6_addr));
      if (0 == res)
        break;
      w_t6 = w_t6->next;
    }
    if (w_t6 == NULL)
    {
    w_t6 = GNUNET_malloc(sizeof(struct IPv6HttpAddressWrapper));
    t6 = GNUNET_malloc(sizeof(struct IPv6HttpAddress));

    memcpy (&t6->ipv6_addr,
            &((struct sockaddr_in6 *) addr)->sin6_addr,
            sizeof (struct in6_addr));
    t6->port = htons (plugin->port_inbound);

    w_t6->addr = t6;

    GNUNET_CONTAINER_DLL_insert(plugin->ipv6_addr_head,
                                plugin->ipv6_addr_tail,w_t6);
    }
    plugin->env->notify_address(plugin->env->cls,
                                add_remove,
                                w_t6->addr, sizeof (struct IPv6HttpAddress));
    break;
  default:
    return;
  }

}

static void
tcp_nat_cb_remove_addr (void *cls,
                         int add_remove,
                         const struct sockaddr *addr,
                         socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4HttpAddressWrapper * w_t4 = NULL;
  struct IPv6HttpAddressWrapper * w_t6 = NULL;
  int af;

  af = addr->sa_family;
  switch (af)
  {
  case AF_INET:
    w_t4 = plugin->ipv4_addr_head;
      while (w_t4 != NULL)
      {
        int res = memcmp(&w_t4->addr->ipv4_addr,
                         &((struct sockaddr_in *) addr)->sin_addr,
                         sizeof (struct in_addr));
        if (0 == res)
          break;
        w_t4 = w_t4->next;
      }
      if (w_t4 == NULL)
        return;
      plugin->env->notify_address(plugin->env->cls,
                                add_remove,
                                w_t4->addr, sizeof (struct IPv4HttpAddress));

      GNUNET_CONTAINER_DLL_remove(plugin->ipv4_addr_head,
                                  plugin->ipv4_addr_tail,w_t4);
      GNUNET_free (w_t4->addr);
      GNUNET_free (w_t4);
    break;
  case AF_INET6:
    w_t6 = plugin->ipv6_addr_head;
    while (w_t6 != NULL)
    {
      int res = memcmp(&w_t6->addr->ipv6_addr,
                       &((struct sockaddr_in6 *) addr)->sin6_addr,
                       sizeof (struct in6_addr));
      if (0 == res)
        break;
      w_t6 = w_t6->next;
    }
    if (w_t6 == NULL)
      return;
    plugin->env->notify_address(plugin->env->cls,
                              add_remove,
                              w_t6->addr, sizeof (struct IPv6HttpAddress));

    GNUNET_CONTAINER_DLL_remove(plugin->ipv6_addr_head,
                                plugin->ipv6_addr_tail,w_t6);
    GNUNET_free (w_t6->addr);
    GNUNET_free (w_t6);
    break;
  default:
    return;
  }

}

/**
 * Our external IP address/port mapping has changed.
 *
 * @param cls closure, the 'struct LocalAddrList'
 * @param add_remove GNUNET_YES to mean the new public IP address, GNUNET_NO to mean
 *     the previous (now invalid) one
 * @param addr either the previous or the new public IP address
 * @param addrlen actual lenght of the address
 */
static void
tcp_nat_port_map_callback (void *cls,
                           int add_remove,
                           const struct sockaddr *addr,
                           socklen_t addrlen)
{
  GNUNET_assert(cls !=NULL );
#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "NPMC called to %s address `%s'\n",
                   (add_remove == GNUNET_YES) ? "remove" : "add",
                   GNUNET_a2s (addr, addrlen));
#endif
  /* convert 'addr' to our internal format */
  switch (add_remove)
  {
  case GNUNET_YES:
    tcp_nat_cb_add_addr (cls, add_remove, addr, addrlen);
    break;
  case GNUNET_NO:
    tcp_nat_cb_remove_addr (cls, add_remove, addr, addrlen);
    break;
  }
}

#if 0
/**
 * Notify transport service about address
 *
 * @param cls the plugin
 * @param tc unused
 */
static void
address_notification (void *cls,
                    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  GNUNET_OS_network_interfaces_list (&process_interfaces, plugin);
}
#endif

/**
 * Exit point from the plugin.
 */
void *
LIBGNUNET_PLUGIN_TRANSPORT_DONE (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  CURLMcode mret;
  struct IPv4HttpAddressWrapper * w_t4;
  struct IPv6HttpAddressWrapper * w_t6;
  GNUNET_assert(cls !=NULL);

  if (plugin->nat != NULL)
    GNUNET_NAT_unregister (plugin->nat);

  if (plugin->http_server_daemon_v4 != NULL)
    {
      MHD_stop_daemon (plugin->http_server_daemon_v4);
      plugin->http_server_daemon_v4 = NULL;
    }
  if (plugin->http_server_daemon_v6 != NULL)
    {
      MHD_stop_daemon (plugin->http_server_daemon_v6);
      plugin->http_server_daemon_v6 = NULL;
    }
  if ( plugin->http_server_task_v4 != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel(plugin->http_server_task_v4);
      plugin->http_server_task_v4 = GNUNET_SCHEDULER_NO_TASK;
    }
  if ( plugin->http_server_task_v6 != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel(plugin->http_server_task_v6);
      plugin->http_server_task_v6 = GNUNET_SCHEDULER_NO_TASK;
    }

  while (plugin->ipv4_addr_head!=NULL)
    {
      w_t4 = plugin->ipv4_addr_head;
      GNUNET_CONTAINER_DLL_remove(plugin->ipv4_addr_head,plugin->ipv4_addr_tail,w_t4);
      GNUNET_free(w_t4->addr);
      GNUNET_free(w_t4);
    }
  
  while (plugin->ipv6_addr_head!=NULL)
    {
      w_t6 = plugin->ipv6_addr_head;
      GNUNET_CONTAINER_DLL_remove(plugin->ipv6_addr_head,plugin->ipv6_addr_tail,w_t6);
      GNUNET_free(w_t6->addr);
      GNUNET_free(w_t6);
    }
  
  /* free all peer information */
  if (plugin->peers!=NULL)
    {
      GNUNET_CONTAINER_multihashmap_iterate (plugin->peers,
					     &remove_peer_context_Iterator,
					     plugin);
      GNUNET_CONTAINER_multihashmap_destroy (plugin->peers);
    }
  if (plugin->multi_handle!=NULL)
    {
      mret = curl_multi_cleanup(plugin->multi_handle);
      if (CURLM_OK != mret)
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    "curl multihandle clean up failed\n");
      plugin->multi_handle = NULL;
    }
  curl_global_cleanup();
  
  if ( plugin->http_curl_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel(plugin->http_curl_task);
      plugin->http_curl_task = GNUNET_SCHEDULER_NO_TASK;
    }
  

  GNUNET_free_non_null (plugin->bind4_address);
  GNUNET_free_non_null (plugin->bind6_address);
  GNUNET_free_non_null (plugin->bind_hostname);
#if BUILD_HTTPS
  GNUNET_free_non_null (plugin->crypto_init);
  GNUNET_free_non_null (plugin->cert);
  GNUNET_free_non_null (plugin->key);
#endif
  GNUNET_free (plugin);
  GNUNET_free (api);
#if DEBUG_HTTP
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Unload %s plugin complete...\n", 
	      PROTOCOL_PREFIX);
#endif
  return NULL;
}

#if BUILD_HTTPS
static char *
load_certificate( const char * file )
{
  struct GNUNET_DISK_FileHandle * gn_file;
  struct stat fstat;
  char * text = NULL;

  if (0 != STAT(file, &fstat))
    return NULL;
  text = GNUNET_malloc (fstat.st_size+1);
  gn_file = GNUNET_DISK_file_open(file, GNUNET_DISK_OPEN_READ, GNUNET_DISK_PERM_USER_READ);
  if (gn_file==NULL)
    {
      GNUNET_free(text);
      return NULL;
    }
  if (GNUNET_SYSERR == GNUNET_DISK_file_read (gn_file, text, fstat.st_size))
    {
      GNUNET_free (text);
      GNUNET_DISK_file_close (gn_file);
      return NULL;
    }
  text[fstat.st_size] = '\0';
  GNUNET_DISK_file_close (gn_file);
  return text;
}
#endif


/**
 * Entry point for the plugin.
 */
void *
LIBGNUNET_PLUGIN_TRANSPORT_INIT (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct Plugin *plugin;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct GNUNET_TIME_Relative gn_timeout;
  long long unsigned int port;
  unsigned long long tneigh;
  struct sockaddr **addrs;
  socklen_t *addrlens;
  int ret;
  char * component_name;
#if BUILD_HTTPS
  char * key_file = NULL;
  char * cert_file = NULL;
#endif

  GNUNET_assert(cls !=NULL);
#if DEBUG_HTTP
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting %s plugin...\n", 
	      PROTOCOL_PREFIX);
#endif
  GNUNET_asprintf(&component_name,
		  "transport-%s",
		  PROTOCOL_PREFIX);

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->stats = env->stats;
  plugin->env = env;
  plugin->peers = NULL;
  plugin->bind4_address = NULL;
  plugin->bind6_address = NULL;
  plugin->use_ipv6  = GNUNET_YES;
  plugin->use_ipv4  = GNUNET_YES;
  plugin->use_localaddresses = GNUNET_NO;

  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &http_plugin_send;
  api->disconnect = &http_plugin_disconnect;
  api->address_pretty_printer = &http_plugin_address_pretty_printer;
  api->check_address = &http_plugin_address_suggested;
  api->address_to_string = &http_plugin_address_to_string;

  /* Hashing our identity to use it in URLs */
  GNUNET_CRYPTO_hash_to_enc (&(plugin->env->my_identity->hashPubKey), 
			     &plugin->my_ascii_hash_ident);


  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg,
					     component_name,
					     "MAX_CONNECTIONS",
					     &tneigh))
    tneigh = 128;
  plugin->max_connect_per_transport = tneigh;


  /* Use IPv6? */
  if (GNUNET_CONFIGURATION_have_value (env->cfg,
				       component_name, "USE_IPv6"))
    {
      plugin->use_ipv6 = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
							       component_name,
							       "USE_IPv6");
    }
  /* Use IPv4? */
  if (GNUNET_CONFIGURATION_have_value (env->cfg,
				       component_name, "USE_IPv4"))
    {
      plugin->use_ipv4 = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
							       component_name,"USE_IPv4");
    }
  /* use local addresses? */

  if (GNUNET_CONFIGURATION_have_value (env->cfg,
				       component_name, "USE_LOCALADDR"))
    {
      plugin->use_localaddresses = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
							       component_name,
							       "USE_LOCALADDR");
    }
  /* Reading port number from config file */
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (env->cfg,
					      component_name,
                                              "PORT",
                                              &port)) ||
      (port > 65535) )
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
		       component_name,
                       _("Require valid port number for transport plugin `%s' in configuration!\n"),
                       PROTOCOL_PREFIX);
      GNUNET_free(component_name);
      LIBGNUNET_PLUGIN_TRANSPORT_DONE (api);
      return NULL;
    }

  /* Reading ipv4 addresse to bind to from config file */
  if ( (plugin->use_ipv4==GNUNET_YES) && 
       (GNUNET_CONFIGURATION_have_value (env->cfg,
					 component_name, "BINDTO4")))
    {
      GNUNET_break (GNUNET_OK ==
		    GNUNET_CONFIGURATION_get_value_string (env->cfg,
							   component_name,
							   "BINDTO4",
							   &plugin->bind_hostname));
      plugin->bind4_address = GNUNET_malloc(sizeof(struct sockaddr_in));
      plugin->bind4_address->sin_family = AF_INET;
      plugin->bind4_address->sin_port = htons (port);
      
      if (plugin->bind_hostname!=NULL)
	{
	  if (inet_pton(AF_INET,plugin->bind_hostname, &plugin->bind4_address->sin_addr)<=0)
	    {
	      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
			       component_name,
			       _("Misconfigured address to bind to in configuration!\n"));
	      GNUNET_free(plugin->bind4_address);
	      GNUNET_free(plugin->bind_hostname);
	      plugin->bind_hostname = NULL;
	      plugin->bind4_address = NULL;
	    }
	}
    }
  
  /* Reading ipv4 addresse to bind to from config file */
  if ( (plugin->use_ipv6==GNUNET_YES) && 
       (GNUNET_CONFIGURATION_have_value (env->cfg,
					 component_name, "BINDTO6")))
    {
      if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (env->cfg,
							      component_name,
							      "BINDTO6",
							      &plugin->bind_hostname))
	{
	  plugin->bind6_address = GNUNET_malloc(sizeof(struct sockaddr_in6));
	  plugin->bind6_address->sin6_family = AF_INET6;
	  plugin->bind6_address->sin6_port = htons (port);
	  if (plugin->bind_hostname!=NULL)
	    {
	      if (inet_pton(AF_INET6,plugin->bind_hostname, &plugin->bind6_address->sin6_addr)<=0)
		{
		  GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
				   component_name,
				   _("Misconfigured address to bind to in configuration!\n"));
		  GNUNET_free(plugin->bind6_address);
		  GNUNET_free(plugin->bind_hostname);
		  plugin->bind_hostname = NULL;
		  plugin->bind6_address = NULL;
		}
	    }
	}
    }
  
#if BUILD_HTTPS
  /* Reading HTTPS crypto related configuration */
  /* Get crypto init string from config */  
  if ( (GNUNET_OK !=
	GNUNET_CONFIGURATION_get_value_string (env->cfg,
					       "transport-https",
					       "CRYPTO_INIT",
					       &plugin->crypto_init)) ||
       (GNUNET_OK !=
	GNUNET_CONFIGURATION_get_value_filename (env->cfg,
						 "transport-https",
						 "KEY_FILE",
						 &key_file)) ||
       (GNUNET_OK !=
	GNUNET_CONFIGURATION_get_value_filename (env->cfg,
						 "transport-https",
						 "CERT_FILE",
						 &cert_file)) )
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
		       "https",
		       _("Required configuration options missing in section `%s'\n"),
		       "transport-https");
      GNUNET_free (component_name);
      GNUNET_free_non_null (key_file);
      GNUNET_free_non_null (cert_file);
      LIBGNUNET_PLUGIN_TRANSPORT_DONE (api);
      return NULL;   
    }
 
  /* read key & certificates from file */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Loading TLS certificate `%s' `%s'\n", 
	      key_file, cert_file);

  plugin->key = load_certificate (key_file);
  plugin->cert = load_certificate (cert_file);

  if ( (plugin->key==NULL) || (plugin->cert==NULL) )
    {
      char * cmd;
      int ret = 0;

      GNUNET_free_non_null (plugin->key);
      plugin->key = NULL;
      GNUNET_free_non_null (plugin->cert);
      plugin->cert = NULL;
      GNUNET_asprintf(&cmd,
		      "gnunet-transport-certificate-creation %s %s", 
		      key_file, cert_file);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "No usable TLS certificate found, creating certificate\n");
      ret = system(cmd);
      if (ret != 0)
	{
	  GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
			   "https",
			   _("Could not create a new TLS certificate, shell script `%s' failed!\n"),
			   cmd);
	  GNUNET_free (key_file);
	  GNUNET_free (cert_file);
	  GNUNET_free (component_name);
	  LIBGNUNET_PLUGIN_TRANSPORT_DONE(api);
	  GNUNET_free (cmd);
	  return NULL;
	}
      GNUNET_free (cmd);      
      plugin->key = load_certificate (key_file);
      plugin->cert = load_certificate (cert_file);
      if ((plugin->key==NULL) || (plugin->cert==NULL))
	{
	  GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
			   "https",
			   _("No usable TLS certificate found and creating one failed!\n"),
			   "transport-https");
	  GNUNET_free (key_file);
	  GNUNET_free (cert_file);
	  GNUNET_free (component_name);	  
	  LIBGNUNET_PLUGIN_TRANSPORT_DONE (api);
	  return NULL;
	}
    }
  GNUNET_free (key_file);
  GNUNET_free (cert_file);
  
  GNUNET_assert((plugin->key!=NULL) && (plugin->cert!=NULL));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "TLS certificate loaded\n");
#endif

  GNUNET_assert ((port > 0) && (port <= 65535));
  plugin->port_inbound = port;
  gn_timeout = GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT;
  unsigned int timeout = (gn_timeout.rel_value) / 1000;
  if ( (plugin->http_server_daemon_v6 == NULL) && 
       (plugin->use_ipv6 == GNUNET_YES) && 
       (port != 0) )
    {
      struct sockaddr * tmp = (struct sockaddr *) plugin->bind6_address;
      plugin->http_server_daemon_v6 = MHD_start_daemon (
#if DEBUG_MHD
							MHD_USE_DEBUG |
#endif
#if BUILD_HTTPS
							MHD_USE_SSL |
#endif
							MHD_USE_IPv6,
							port,
							&mhd_accept_cb, plugin,
							&mhd_access_cb, plugin,
							MHD_OPTION_SOCK_ADDR, tmp,
							MHD_OPTION_CONNECTION_LIMIT, (unsigned int) plugin->max_connect_per_transport,
#if BUILD_HTTPS
							MHD_OPTION_HTTPS_PRIORITIES,  plugin->crypto_init,
							MHD_OPTION_HTTPS_MEM_KEY, plugin->key,
							MHD_OPTION_HTTPS_MEM_CERT, plugin->cert,
#endif
							MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) timeout,
							MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (2 * GNUNET_SERVER_MAX_MESSAGE_SIZE),
							MHD_OPTION_NOTIFY_COMPLETED, &mhd_termination_cb, plugin,
							MHD_OPTION_EXTERNAL_LOGGER, mhd_logger, plugin->mhd_log,
							MHD_OPTION_END);
    }
  if ( (plugin->http_server_daemon_v4 == NULL) && 
       (plugin->use_ipv4 == GNUNET_YES) && 
       (port != 0) )
    {
      plugin->http_server_daemon_v4 = MHD_start_daemon (
#if DEBUG_MHD
							MHD_USE_DEBUG |
#endif
#if BUILD_HTTPS
							MHD_USE_SSL |
#endif
							MHD_NO_FLAG,
							port,
							&mhd_accept_cb, plugin ,
							&mhd_access_cb, plugin,
							MHD_OPTION_SOCK_ADDR, (struct sockaddr_in *) plugin->bind4_address,
                                                        MHD_OPTION_CONNECTION_LIMIT, (unsigned int) plugin->max_connect_per_transport,
#if BUILD_HTTPS
							MHD_OPTION_HTTPS_PRIORITIES,  plugin->crypto_init,

							MHD_OPTION_HTTPS_MEM_KEY, plugin->key,
							MHD_OPTION_HTTPS_MEM_CERT, plugin->cert,
#endif
							MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) timeout,
							MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (2 * GNUNET_SERVER_MAX_MESSAGE_SIZE),
							MHD_OPTION_NOTIFY_COMPLETED, &mhd_termination_cb, plugin,
							MHD_OPTION_EXTERNAL_LOGGER, mhd_logger, plugin->mhd_log,
							MHD_OPTION_END);
    }
  if (plugin->http_server_daemon_v4 != NULL)
    plugin->http_server_task_v4 = http_server_daemon_prepare (plugin, plugin->http_server_daemon_v4);
  if (plugin->http_server_daemon_v6 != NULL)
    plugin->http_server_task_v6 = http_server_daemon_prepare (plugin, plugin->http_server_daemon_v6);
  
  
  if (plugin->http_server_task_v4 != GNUNET_SCHEDULER_NO_TASK)
    {
#if DEBUG_HTTP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Starting MHD with IPv4 bound to %s with port %u\n",
		  (plugin->bind_hostname!=NULL) ? plugin->bind_hostname : "every address",port);
#endif
    }
  else if ( (plugin->http_server_task_v6 != GNUNET_SCHEDULER_NO_TASK) && 
	    (plugin->http_server_task_v4 != GNUNET_SCHEDULER_NO_TASK) )
    {
#if DEBUG_HTTP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Starting MHD with IPv6 bound to %s with port %u\n",
		  (plugin->bind_hostname!=NULL) ? plugin->bind_hostname : "every address", port);
#endif
    }
  else if ( (plugin->http_server_task_v6 != GNUNET_SCHEDULER_NO_TASK) && 
	    (plugin->http_server_task_v4 == GNUNET_SCHEDULER_NO_TASK) )
    {
#if DEBUG_HTTP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Starting MHD with IPv4 and IPv6 bound to %s with port %u\n",
		  (plugin->bind_hostname!=NULL) ? plugin->bind_hostname : "every address", 
		  port);
#endif
    }
  else
    {
      char * tmp = NULL;
      if ((plugin->use_ipv6 == GNUNET_YES) && (plugin->use_ipv4 == GNUNET_YES))
	GNUNET_asprintf(&tmp,"with IPv4 and IPv6 enabled");
      if ((plugin->use_ipv6 == GNUNET_NO) && (plugin->use_ipv4 == GNUNET_YES))
	GNUNET_asprintf(&tmp,"with IPv4 enabled");
      if ((plugin->use_ipv6 == GNUNET_YES) && (plugin->use_ipv4 == GNUNET_NO))
	GNUNET_asprintf(&tmp,"with IPv6 enabled");
      if ((plugin->use_ipv6 == GNUNET_NO) && (plugin->use_ipv4 == GNUNET_NO))
	GNUNET_asprintf(&tmp,"with NO IP PROTOCOL enabled");
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("HTTP Server with %s could not be started on port %u! %s plugin failed!\n"),
		  tmp, port, PROTOCOL_PREFIX);
      GNUNET_free (tmp);
      GNUNET_free (component_name);
      LIBGNUNET_PLUGIN_TRANSPORT_DONE (api);
      return NULL;
    }
  
  /* Initializing cURL */
  curl_global_init(CURL_GLOBAL_ALL);
  plugin->multi_handle = curl_multi_init();
  
  if ( NULL == plugin->multi_handle )
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
		       component_name,
		       _("Could not initialize curl multi handle, failed to start %s plugin!\n"),
		       PROTOCOL_PREFIX);
      GNUNET_free(component_name);
      LIBGNUNET_PLUGIN_TRANSPORT_DONE (api);
      return NULL;
    }
  
  ret = GNUNET_SERVICE_get_server_addresses (component_name,
                          env->cfg,
                          &addrs,
                          &addrlens);

  if (ret != GNUNET_SYSERR)
  {
    plugin->nat = GNUNET_NAT_register (env->cfg,
                                         GNUNET_YES,
                                         port,
                                         (unsigned int) ret,
                                         (const struct sockaddr **) addrs,
                                         addrlens,
                                         &tcp_nat_port_map_callback,
                                         &try_connection_reversal,
                                         plugin);
      while (ret > 0)
      {
        ret--;
        GNUNET_assert (addrs[ret] != NULL);
        GNUNET_free (addrs[ret]);
      }
      GNUNET_free_non_null (addrs);
      GNUNET_free_non_null (addrlens);
  }
  else
  {
    plugin->nat = GNUNET_NAT_register (env->cfg,
         GNUNET_YES,
         0,
         0, NULL, NULL,
         NULL,
         &try_connection_reversal,
         plugin);
  }

  plugin->peers = GNUNET_CONTAINER_multihashmap_create (10);
  
  GNUNET_free(component_name);
  //GNUNET_SCHEDULER_add_now(address_notification, plugin);
  return api;
}

/* end of plugin_transport_http.c */
