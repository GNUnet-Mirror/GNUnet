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
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_connection_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_resolver_service.h"
#include "gnunet_server_lib.h"
#include "gnunet_container_lib.h"
#include "plugin_transport.h"
#include "gnunet_os_lib.h"
#include "microhttpd.h"
#include <curl/curl.h>


#define DEBUG_CURL GNUNET_NO
#define DEBUG_HTTP GNUNET_NO
#define DEBUG_CONNECTIONS GNUNET_YES

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
  uint16_t u_port GNUNET_PACKED;

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
  uint16_t u6_port GNUNET_PACKED;

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

  unsigned int port_inbound;

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
   * Our ASCII encoded, hashed peer identity
   * This string is used to distinguish between connections and is added to the urls
   */
  struct GNUNET_CRYPTO_HashAsciiEncoded my_ascii_hash_ident;
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

static char * create_url(void * cls, const void * addr, size_t addrlen, size_t id)
{
  struct Plugin *plugin = cls;
  char *url = NULL;

  GNUNET_assert ((addr!=NULL) && (addrlen != 0));
  GNUNET_asprintf(&url,
                  "http://%s/%s;%u",
                  http_plugin_address_to_string(NULL, addr, addrlen),
                  (char *) (&plugin->my_ascii_hash_ident),id);

  return url;
}

/**
 * Removes a message from the linked list of messages
 * @param con connection to remove message from
 * @param msg message to remove
 * @return GNUNET_SYSERR if msg not found, GNUNET_OK on success
 */
static int remove_http_message (struct Session * ps, struct HTTP_Message * msg)
{
  GNUNET_CONTAINER_DLL_remove(ps->pending_msgs_head,ps->pending_msgs_tail,msg);
  GNUNET_free(msg);
  return GNUNET_OK;
}

/**
 * Removes a session from the linked list of sessions
 * @param pc peer context
 * @param ps session
 * @param call_msg_cont GNUNET_YES to call pending message continuations, otherwise no
 * @param call_msg_cont_result, result to call message continuations with
 * @return GNUNET_SYSERR if msg not found, GNUNET_OK on success
 */
static int remove_session (struct HTTP_PeerContext * pc, struct Session * ps,  int call_msg_cont, int call_msg_cont_result)
{
  struct HTTP_Message * msg;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: removing %s session with id %u\n", ps, (ps->direction == INBOUND) ? "inbound" : "outbound",ps->session_id);
  GNUNET_free_non_null (ps->addr);
  GNUNET_SERVER_mst_destroy (ps->msgtok);
  GNUNET_free(ps->url);

  msg = ps->pending_msgs_head;
  while (msg!=NULL)
  {
    if ((call_msg_cont == GNUNET_YES) && (msg->transmit_cont!=NULL))
    {
      msg->transmit_cont (msg->transmit_cont_cls,&pc->identity,call_msg_cont_result);
    }
    GNUNET_free(msg);
    GNUNET_CONTAINER_DLL_remove(ps->pending_msgs_head,ps->pending_msgs_head,msg);
    msg = ps->pending_msgs_head;
  }

  GNUNET_CONTAINER_DLL_remove(pc->head,pc->tail,ps);
  GNUNET_free(ps);
  ps = NULL;
  return GNUNET_OK;
}

static struct Session * get_Session (void * cls, struct HTTP_PeerContext *pc, const void * addr, size_t addr_len)
{
  struct Session * cc = pc->head;
  struct Session * con = NULL;
  unsigned int count = 0;

  GNUNET_assert((addr_len == sizeof (struct IPv4HttpAddress)) || (addr_len == sizeof (struct IPv6HttpAddress)));
  while (cc!=NULL)
  {
    if (addr_len == cc->addrlen)
    {
      if (0 == memcmp(cc->addr, addr, addr_len))
      {
        /* connection can not be used, since it is disconnected */
        if ((cc->recv_force_disconnect==GNUNET_NO) && (cc->send_force_disconnect==GNUNET_NO))
          con = cc;
        break;
      }
    }
    count++;
    cc=cc->next;
  }
  return con;
}


/**
 * Callback called by MHD when a connection is terminated
 */
static void mhd_termination_cb (void *cls, struct MHD_Connection * connection, void **httpSessionCache)
{
  struct Session * ps = *httpSessionCache;
  if (ps == NULL)
    return;
  struct HTTP_PeerContext * pc = ps->peercontext;

  if (connection==ps->recv_endpoint)
  {
#if DEBUG_CONNECTIONS
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: inbound connection from peer `%s' was terminated\n", ps, GNUNET_i2s(&pc->identity));
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: outbound connection from peer `%s' was terminated\n", ps, GNUNET_i2s(&pc->identity));
#endif
  }

  /* if both connections disconnected, remove session */
  if ((ps->send_connected == GNUNET_NO) && (ps->recv_connected == GNUNET_NO))
  {
    remove_session(pc,ps,GNUNET_YES,GNUNET_SYSERR);
  }
}

static void mhd_write_mst_cb (void *cls,
                              void *client,
                              const struct GNUNET_MessageHeader *message)
{

  struct Session *ps  = cls;
  struct HTTP_PeerContext *pc = ps->peercontext;
  GNUNET_assert(ps != NULL);
  GNUNET_assert(pc != NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Connection %X: Forwarding message to transport service, type %u and size %u from `%s' (`%s')\n",
	      ps,
	      ntohs(message->type),
              ntohs(message->size),
	      GNUNET_i2s(&(ps->peercontext)->identity),http_plugin_address_to_string(NULL,ps->addr,ps->addrlen));

  pc->plugin->env->receive (ps->peercontext->plugin->env->cls,
			    &pc->identity,
			    message, 1, ps,
			    ps->addr,
			    ps->addrlen);
}

static void curl_receive_mst_cb  (void *cls,
                                void *client,
                                const struct GNUNET_MessageHeader *message)
{
  struct Session *ps  = cls;
  struct HTTP_PeerContext *pc = ps->peercontext;
  GNUNET_assert(ps != NULL);
  GNUNET_assert(pc != NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Forwarding message to transport service, type %u and size %u from `%s' (`%s')\n",
              ntohs(message->type),
              ntohs(message->size),
              GNUNET_i2s(&(pc->identity)),http_plugin_address_to_string(NULL,ps->addr,ps->addrlen));

  pc->plugin->env->receive (pc->plugin->env->cls,
                            &pc->identity,
                            message, 1, ps,
                            ps->addr,
                            ps->addrlen);
}


/**
 * Check if ip is allowed to connect.
 */
static int
mhd_accept_cb (void *cls,
                      const struct sockaddr *addr, socklen_t addr_len)
{
#if 0
  struct Plugin *plugin = cls;
#endif
  /* Every connection is accepted, nothing more to do here */
  return MHD_YES;
}

int mhd_send_callback (void *cls, uint64_t pos, char *buf, int max)
{
  int bytes_read = 0;

  struct Session * ps = cls;
  struct HTTP_PeerContext * pc;
  struct HTTP_Message * msg;
  int res;res=5;

  GNUNET_assert (ps!=NULL);
  pc = ps->peercontext;
  msg = ps->pending_msgs_tail;
  if (ps->send_force_disconnect==GNUNET_YES)
  {
#if DEBUG_CONNECTIONS
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: outbound forced to disconnect\n",ps);
#endif
    return -1;
  }

  if (msg!=NULL)
  {
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

    if (msg->pos==msg->size)
    {
      if (NULL!=msg->transmit_cont)
        msg->transmit_cont (msg->transmit_cont_cls,&pc->identity,GNUNET_OK);
      res = remove_http_message(ps,msg);
    }
  }
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
mdh_access_cb (void *cls,
                       struct MHD_Connection *mhd_connection,
                       const char *url,
                       const char *method,
                       const char *version,
                       const char *upload_data,
                       size_t * upload_data_size, void **httpSessionCache)
{
  struct Plugin *plugin = cls;
  struct MHD_Response *response;
  const union MHD_ConnectionInfo * conn_info;

  struct sockaddr_in  *addrin;
  struct sockaddr_in6 *addrin6;

  char address[INET6_ADDRSTRLEN+14];
  struct GNUNET_PeerIdentity pi_in;
  size_t id_num = 0;

  struct IPv4HttpAddress ipv4addr;
  struct IPv6HttpAddress ipv6addr;

  struct HTTP_PeerContext *pc;
  struct Session *ps;
  struct Session *ps_tmp;

  int res = GNUNET_NO;
  int send_error_to_client;
  void * addr;
  size_t addr_len;

  GNUNET_assert(cls !=NULL);
  send_error_to_client = GNUNET_NO;

  if (NULL == *httpSessionCache)
  {
    /* check url for peer identity , if invalid send HTTP 404*/
    size_t len = strlen(&url[1]);
    char * peer = GNUNET_malloc(104+1);

    if ((len>104) && (url[104]==';'))
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
      response = MHD_create_response_from_data (strlen (HTTP_ERROR_RESPONSE),HTTP_ERROR_RESPONSE, MHD_NO, MHD_NO);
      res = MHD_queue_response (mhd_connection, MHD_HTTP_NOT_FOUND, response);
      MHD_destroy_response (response);
      if (res == MHD_YES)
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Peer has no valid ident, sent HTTP 1.1/404\n");
      else
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Peer has no valid ident, could not send error\n");
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
      memcpy(&pc->identity, &pi_in, sizeof(struct GNUNET_PeerIdentity));
      GNUNET_CONTAINER_multihashmap_put(plugin->peers, &pc->identity.hashPubKey, pc, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    }

    conn_info = MHD_get_connection_info(mhd_connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS );
    /* Incoming IPv4 connection */
    if ( AF_INET == conn_info->client_addr->sin_family)
    {
      addrin = conn_info->client_addr;
      inet_ntop(addrin->sin_family, &(addrin->sin_addr),address,INET_ADDRSTRLEN);
      memcpy(&ipv4addr.ipv4_addr,&(addrin->sin_addr),sizeof(struct in_addr));
      ipv4addr.u_port = addrin->sin_port;
      addr = &ipv4addr;
      addr_len = sizeof(struct IPv4HttpAddress);
    }
    /* Incoming IPv6 connection */
    if ( AF_INET6 == conn_info->client_addr->sin_family)
    {
      addrin6 = (struct sockaddr_in6 *) conn_info->client_addr;
      inet_ntop(addrin6->sin6_family, &(addrin6->sin6_addr),address,INET6_ADDRSTRLEN);
      memcpy(&ipv6addr.ipv6_addr,&(addrin6->sin6_addr),sizeof(struct in6_addr));
      ipv6addr.u6_port = addrin6->sin6_port;
      addr = &ipv6addr;
      addr_len = sizeof(struct IPv6HttpAddress);
    }


    //ps = get_Session(plugin, pc, addr, addr_len);
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
      ps->url = create_url (plugin, ps->addr, ps->addrlen, ps->session_id);
      GNUNET_CONTAINER_DLL_insert(pc->head,pc->tail,ps);
    }

    *httpSessionCache = ps;
    if (ps->msgtok==NULL)
      ps->msgtok = GNUNET_SERVER_mst_create (&mhd_write_mst_cb, ps);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: HTTP Daemon has new an incoming `%s' request from peer `%s' (`%s')\n",
                ps,
                method,
                GNUNET_i2s(&pc->identity),
                http_plugin_address_to_string(NULL, ps->addr, ps->addrlen));
  }

  /* Is it a PUT or a GET request */
  if (0 == strcmp (MHD_HTTP_METHOD_PUT, method))
  {
    if (ps->recv_force_disconnect)
    {
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: inbound connection was forced to disconnect\n",ps);
#endif
      ps->recv_active = GNUNET_NO;
      return MHD_NO;
    }
    if ((*upload_data_size == 0) && (ps->recv_active==GNUNET_NO))
    {
      ps->recv_endpoint = mhd_connection;
      ps->recv_connected = GNUNET_YES;
      ps->recv_active = GNUNET_YES;
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: inbound PUT connection connected\n",ps);
#endif
      return MHD_YES;
    }

    /* Transmission of all data complete */
    if ((*upload_data_size == 0) && (ps->recv_active == GNUNET_YES))
    {
      response = MHD_create_response_from_data (strlen (HTTP_PUT_RESPONSE),HTTP_PUT_RESPONSE, MHD_NO, MHD_NO);
      res = MHD_queue_response (mhd_connection, MHD_HTTP_OK, response);
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: Sent HTTP/1.1: 200 OK as PUT Response\n",ps);
#endif
      MHD_destroy_response (response);
      ps->recv_active=GNUNET_NO;
      return MHD_YES;
    }

    /* Recieving data */
    if ((*upload_data_size > 0) && (ps->recv_active == GNUNET_YES))
    {
      res = GNUNET_SERVER_mst_receive(ps->msgtok, ps, upload_data,*upload_data_size, GNUNET_NO, GNUNET_NO);
      (*upload_data_size) = 0;
      return MHD_YES;
    }
    else
      return MHD_NO;
  }
  if ( 0 == strcmp (MHD_HTTP_METHOD_GET, method) )
  {
    if (ps->send_force_disconnect)
    {
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: outbound connection was  forced to disconnect\n",ps);
#endif
      ps->send_active = GNUNET_NO;
      return MHD_NO;
    }
    ps->send_connected = GNUNET_YES;
    ps->send_active = GNUNET_YES;
    ps->send_endpoint = mhd_connection;
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: inbound GET connection connected\n",ps);
#endif
    response = MHD_create_response_from_callback(-1,32 * 1024, &mhd_send_callback, ps, NULL);
    res = MHD_queue_response (mhd_connection, MHD_HTTP_OK, response);
    MHD_destroy_response (response);
    return MHD_YES;
  }
  return MHD_NO;
}


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
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 */
static GNUNET_SCHEDULER_TaskIdentifier
http_server_daemon_prepare (void * cls, struct MHD_Daemon *daemon_handle)
{
  struct Plugin *plugin = cls;
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

  GNUNET_assert(cls !=NULL);
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
    tv.value = (uint64_t) timeout;
  else
    tv = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_NETWORK_fdset_copy_native (wrs, &rs, max);
  GNUNET_NETWORK_fdset_copy_native (wws, &ws, max);
  GNUNET_NETWORK_fdset_copy_native (wes, &es, max);
  if (daemon_handle == plugin->http_server_daemon_v4)
  {
    ret = GNUNET_SCHEDULER_add_select (plugin->env->sched,
                                       GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                       GNUNET_SCHEDULER_NO_TASK,
                                       tv,
                                       wrs,
                                       wws,
                                       &http_server_daemon_v4_run,
                                       plugin);
  }
  if (daemon_handle == plugin->http_server_daemon_v6)
  {
    ret = GNUNET_SCHEDULER_add_select (plugin->env->sched,
                                       GNUNET_SCHEDULER_PRIORITY_DEFAULT,
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
 * Call MHD to process pending requests and then go back
 * and schedule the next run.
 */
static void http_server_daemon_v4_run (void *cls,
                             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  GNUNET_assert(cls !=NULL);
  if (plugin->http_server_task_v4 != GNUNET_SCHEDULER_NO_TASK)
    plugin->http_server_task_v4 = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_assert (MHD_YES == MHD_run (plugin->http_server_daemon_v4));
  plugin->http_server_task_v4 = http_server_daemon_prepare (plugin, plugin->http_server_daemon_v4);
  return;
}


/**
 * Call MHD to process pending requests and then go back
 * and schedule the next run.
 */
static void http_server_daemon_v6_run (void *cls,
                             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  GNUNET_assert(cls !=NULL);
  if (plugin->http_server_task_v6 != GNUNET_SCHEDULER_NO_TASK)
    plugin->http_server_task_v6 = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_assert (MHD_YES == MHD_run (plugin->http_server_daemon_v6));
  plugin->http_server_task_v6 = http_server_daemon_prepare (plugin, plugin->http_server_daemon_v6);
  return;
}

/**
 * Function setting up curl handle and selecting message to send
 * @param cls plugin
 * @param ses session to send data to
 * @param con connection
 * @return bytes sent to peer
 */
static ssize_t send_check_connections (void *cls, struct Session *ps);

static size_t curl_get_header_function( void *ptr, size_t size, size_t nmemb, void *stream)
{
  struct Session * ps = stream;

  char * tmp;
  size_t len = size * nmemb;
  long http_result = 0;
  int res;
  /* Getting last http result code */
  if (ps->recv_connected==GNUNET_NO)
  {
    GNUNET_assert(NULL!=ps);
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
#if DEBUG_HTTP
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Header: `%s' %u \n",tmp, http_result);
#endif
  }
  if (NULL != tmp)
    GNUNET_free (tmp);

  return size * nmemb;
}

static size_t curl_put_header_function( void *ptr, size_t size, size_t nmemb, void *stream)
{
  struct Session * ps = stream;

  char * tmp;
  size_t len = size * nmemb;
  long http_result = 0;
  int res;

  /* Getting last http result code */
  GNUNET_assert(NULL!=ps);
  res = curl_easy_getinfo(ps->send_endpoint, CURLINFO_RESPONSE_CODE, &http_result);
  if (CURLE_OK == res)
  {
    if ((http_result == 100) && (ps->send_connected==GNUNET_NO))
    {
      ps->send_connected = GNUNET_YES;
      ps->send_active = GNUNET_YES;
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: connected to send data\n",ps);
#endif
    }
    if ((http_result == 200) && (ps->send_connected==GNUNET_YES))
    {
      ps->send_connected = GNUNET_NO;
      ps->send_active = GNUNET_NO;
#if DEBUG_CONNECTIONS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: sending disconnected\n",ps);
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
#if DEBUG_HTTP
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Header: `%s' %u \n",tmp, http_result);
#endif
  }
  if (NULL != tmp)
    GNUNET_free (tmp);

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
static size_t curl_send_cb(void *stream, size_t size, size_t nmemb, void *ptr)
{
  struct Session * ps = ptr;
  struct HTTP_Message * msg = ps->pending_msgs_tail;
  size_t bytes_sent;
  size_t len;

  if ((ps->pending_msgs_tail == NULL) && (ps->send_active == GNUNET_YES))
  {
#if DEBUG_CONNECTIONS
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: No Message to send, pausing connection\n",ps);
#endif
    ps->send_active = GNUNET_NO;
    return CURL_READFUNC_PAUSE;
  }

  msg = ps->pending_msgs_tail;
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: Message with %u bytes sent, removing message from queue \n",ps, msg->pos);
#endif
    /* Calling transmit continuation  */
    if (( NULL != ps->pending_msgs_tail) && (NULL != ps->pending_msgs_tail->transmit_cont))
      msg->transmit_cont (ps->pending_msgs_tail->transmit_cont_cls,&(ps->peercontext)->identity,GNUNET_OK);
    remove_http_message(ps, msg);
  }
  return bytes_sent;
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
static size_t curl_receive_cb( void *stream, size_t size, size_t nmemb, void *ptr)
{
  struct Session * ps = ptr;
#if DEBUG_CONNECTIONS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: %u bytes received\n",ps, size*nmemb);
#endif
  GNUNET_SERVER_mst_receive(ps->msgtok, ps, stream, size*nmemb, GNUNET_NO, GNUNET_NO);
  return (size * nmemb);

}

/**
 * Function setting up file descriptors and scheduling task to run
 * @param cls closure
 * @param ses session to send data to
 * @param
 */
static int curl_schedule(void *cls, struct Session* ses );



/**
 * Function setting up curl handle and selecting message to send
 * @param cls plugin
 * @param ses session to send data to
 * @param con connection
 * @return GNUNET_SYSERR on failure, GNUNET_NO if connecting, GNUNET_YES if ok
 */
static ssize_t send_check_connections (void *cls, struct Session *ps)
{
  struct Plugin *plugin = cls;
  CURLMcode mret;
  struct HTTP_Message * msg;
  struct GNUNET_TIME_Relative timeout = GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT;

  GNUNET_assert(cls !=NULL);

  if (ps->direction == OUTBOUND)
  {
    /* RECV DIRECTION */
    /* Check if session is connected to receive data, otherwise connect to peer */
    if (ps->recv_connected == GNUNET_NO)
    {
        if (ps->recv_endpoint == NULL)
        {
          ps->recv_endpoint = curl_easy_init();
#if DEBUG_CURL
        curl_easy_setopt(ps->recv_endpoint, CURLOPT_VERBOSE, 1L);
#endif
        curl_easy_setopt(ps->recv_endpoint, CURLOPT_URL, ps->url);
        curl_easy_setopt(ps->recv_endpoint, CURLOPT_HEADERFUNCTION, &curl_get_header_function);
        curl_easy_setopt(ps->recv_endpoint, CURLOPT_WRITEHEADER, ps);
        curl_easy_setopt(ps->recv_endpoint, CURLOPT_READFUNCTION, curl_send_cb);
        curl_easy_setopt(ps->recv_endpoint, CURLOPT_READDATA, ps);
        curl_easy_setopt(ps->recv_endpoint, CURLOPT_WRITEFUNCTION, curl_receive_cb);
        curl_easy_setopt(ps->recv_endpoint, CURLOPT_WRITEDATA, ps);
        curl_easy_setopt(ps->recv_endpoint, CURLOPT_TIMEOUT, (long) timeout.value);
        curl_easy_setopt(ps->recv_endpoint, CURLOPT_PRIVATE, ps);
        curl_easy_setopt(ps->recv_endpoint, CURLOPT_CONNECTTIMEOUT, HTTP_CONNECT_TIMEOUT);
        curl_easy_setopt(ps->recv_endpoint, CURLOPT_BUFFERSIZE, GNUNET_SERVER_MAX_MESSAGE_SIZE);

        mret = curl_multi_add_handle(plugin->multi_handle, ps->recv_endpoint);
        if (mret != CURLM_OK)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("%s failed at %s:%d: `%s'\n"),
                      "curl_multi_add_handle", __FILE__, __LINE__,
                      curl_multi_strerror (mret));
          return GNUNET_SYSERR;
        }
        if (curl_schedule (plugin, NULL) == GNUNET_SYSERR)
        	return GNUNET_SYSERR;
#if DEBUG_CONNECTIONS
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: inbound not connected, initiating connection\n",ps);
#endif
      }
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
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: outbound active, enqueueing message\n",ps);
#endif
        return GNUNET_YES;
      }
      if (ps->send_active == GNUNET_NO)
      {
#if DEBUG_CONNECTIONS
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: outbound paused, unpausing existing connection and enqueueing message\n",ps);
#endif
        if (CURLE_OK == curl_easy_pause(ps->send_endpoint,CURLPAUSE_CONT))
        {
			ps->send_active=GNUNET_YES;
			return GNUNET_YES;
        }
        else
        	return GNUNET_SYSERR;
      }
    }
    /* not connected, initiate connection */
    if ((ps->send_connected==GNUNET_NO) && (NULL == ps->send_endpoint))
      ps->send_endpoint = curl_easy_init();
    GNUNET_assert (ps->send_endpoint != NULL);
    GNUNET_assert (NULL != ps->pending_msgs_tail);
#if DEBUG_CONNECTIONS
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection %X: outbound not connected, initiating connection\n",ps);
#endif
    ps->send_active = GNUNET_NO;
    msg = ps->pending_msgs_tail;

  #if DEBUG_CURL
    curl_easy_setopt(ps->send_endpoint, CURLOPT_VERBOSE, 1L);
  #endif
    curl_easy_setopt(ps->send_endpoint, CURLOPT_URL, ps->url);
    curl_easy_setopt(ps->send_endpoint, CURLOPT_PUT, 1L);
    curl_easy_setopt(ps->send_endpoint, CURLOPT_HEADERFUNCTION, &curl_put_header_function);
    curl_easy_setopt(ps->send_endpoint, CURLOPT_WRITEHEADER, ps);
    curl_easy_setopt(ps->send_endpoint, CURLOPT_READFUNCTION, curl_send_cb);
    curl_easy_setopt(ps->send_endpoint, CURLOPT_READDATA, ps);
    curl_easy_setopt(ps->send_endpoint, CURLOPT_WRITEFUNCTION, curl_receive_cb);
    curl_easy_setopt(ps->send_endpoint, CURLOPT_READDATA, ps);
    curl_easy_setopt(ps->send_endpoint, CURLOPT_TIMEOUT, (long) timeout.value);
    curl_easy_setopt(ps->send_endpoint, CURLOPT_PRIVATE, ps);
    curl_easy_setopt(ps->send_endpoint, CURLOPT_CONNECTTIMEOUT, HTTP_CONNECT_TIMEOUT);
    curl_easy_setopt(ps->send_endpoint, CURLOPT_BUFFERSIZE, GNUNET_SERVER_MAX_MESSAGE_SIZE);

    mret = curl_multi_add_handle(plugin->multi_handle, ps->send_endpoint);
    if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_add_handle", __FILE__, __LINE__,
                  curl_multi_strerror (mret));
      return GNUNET_SYSERR;
    }
    if (curl_schedule (plugin, NULL) == GNUNET_SYSERR)
    	return GNUNET_SYSERR;
    return GNUNET_YES;
  }
  if (ps->direction == INBOUND)
  {
    GNUNET_assert (NULL != ps->pending_msgs_tail);
    msg = ps->pending_msgs_tail;
    if ((ps->recv_connected==GNUNET_YES) && (ps->send_connected==GNUNET_YES))
    	return GNUNET_YES;
  }
  return GNUNET_SYSERR;
}

static void curl_perform (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  static unsigned int handles_last_run;
  int running;
  struct CURLMsg *msg;
  CURLMcode mret;
  struct Session *ps = NULL;
  struct HTTP_PeerContext *pc = NULL;
  struct HTTP_Message * cur_msg = NULL;
  long http_result;

  GNUNET_assert(cls !=NULL);

  plugin->http_curl_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  do
    {
      running = 0;
      mret = curl_multi_perform (plugin->multi_handle, &running);
      if ((running < handles_last_run) && (running>0))
        {
          do
            {

              msg = curl_multi_info_read (plugin->multi_handle, &running);
              if (running == 0)
            	  break;
              /* get session for affected curl handle */
              GNUNET_assert ( msg->easy_handle != NULL );
              curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, (char *) &ps);
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
                      curl_easy_cleanup(ps->send_endpoint);
                      ps->send_endpoint=NULL;
                      cur_msg = ps->pending_msgs_tail;
                      if (( NULL != cur_msg) && ( NULL != cur_msg->transmit_cont))
                        cur_msg->transmit_cont (cur_msg->transmit_cont_cls,&pc->identity,GNUNET_SYSERR);
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
                      curl_easy_cleanup(ps->recv_endpoint);
                      ps->recv_endpoint=NULL;
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
                      cur_msg = ps->pending_msgs_tail;
                      if (( NULL != cur_msg) && (NULL != cur_msg->transmit_cont))
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
                      ps->send_connected = GNUNET_NO;
                      ps->send_active = GNUNET_NO;
                      curl_multi_remove_handle(plugin->multi_handle,ps->send_endpoint);
                      curl_easy_cleanup(ps->send_endpoint);
                      ps->send_endpoint =NULL;
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
                      curl_easy_cleanup(ps->recv_endpoint);
                      ps->recv_endpoint=NULL;
                    }
                  }
                  if ((ps->recv_connected == GNUNET_NO) && (ps->send_connected == GNUNET_NO))
                    remove_session (pc, ps, GNUNET_YES, GNUNET_SYSERR);
                  return;
                default:
                  break;
                }

            }
          while ( (running > 0) );
        }
      handles_last_run = running;
    }
  while (mret == CURLM_CALL_MULTI_PERFORM);
  curl_schedule(plugin, cls);
}


/**
 * Function setting up file descriptors and scheduling task to run
 * @param ses session to send data to
 * @return GNUNET_SYSERR for hard failure, GNUNET_OK for ok
 */
static int curl_schedule(void *cls, struct Session* ses )
{
  struct Plugin *plugin = cls;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct GNUNET_NETWORK_FDSet *grs;
  struct GNUNET_NETWORK_FDSet *gws;
  long to;
  CURLMcode mret;

  GNUNET_assert(cls !=NULL);
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
  plugin->http_curl_task = GNUNET_SCHEDULER_add_select (plugin->env->sched,
                                   GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   GNUNET_SCHEDULER_NO_TASK,
                                   GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 0),
                                   grs,
                                   gws,
                                   &curl_perform,
                                   plugin);
  GNUNET_NETWORK_fdset_destroy (gws);
  GNUNET_NETWORK_fdset_destroy (grs);
  return GNUNET_OK;
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
 * @param timeout how long to wait at most for the transmission (does not
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
  struct Session * ps_tmp = NULL;

  GNUNET_assert(cls !=NULL);

  char * force = GNUNET_malloc(40);
  if (force_address == GNUNET_YES)
    strcpy(force,"forced addr.");
  if (force_address == GNUNET_NO)
    strcpy(force,"any addr.");
  if (force_address == GNUNET_SYSERR)
    strcpy(force,"reliable bi-direc. address addr.");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Transport tells me to send %u bytes to `%s' using %s (%s) and session: %X\n",
                                      msgbuf_size,
                                      GNUNET_i2s(target),
                                      force,
                                      http_plugin_address_to_string(NULL, addr, addrlen),
                                      session);
  GNUNET_free(force);

  pc = GNUNET_CONTAINER_multihashmap_get (plugin->peers, &target->hashPubKey);
  /* Peer unknown */
  if (pc==NULL)
  {
    pc = GNUNET_malloc(sizeof (struct HTTP_PeerContext));
    pc->plugin = plugin;
    pc->session_id_counter=1;
    memcpy(&pc->identity, target, sizeof(struct GNUNET_PeerIdentity));
    GNUNET_CONTAINER_multihashmap_put(plugin->peers, &pc->identity.hashPubKey, pc, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }

  /* Search for existing session using the passed address */
  if  ((addr!=NULL) && (addrlen != 0))
  {
    ps = get_Session(plugin, pc, addr, addrlen);
  }
  if (ps != NULL)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Found existing connection to peer %s with given address, using %X\n", GNUNET_i2s(target), ps);

  /* Search for existing session using the passed session */
  if ((ps==NULL) && (force_address != GNUNET_YES))
  {
    ps_tmp = pc->head;
    while (ps_tmp!=NULL)
    {
      if ((ps_tmp==session) && (ps_tmp->recv_force_disconnect==GNUNET_NO) && (ps_tmp->send_force_disconnect==GNUNET_NO) &&
          (ps_tmp->recv_connected==GNUNET_YES) && (ps_tmp->send_connected==GNUNET_YES))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Found existing connection to peer %s with given session, using inbound session %X\n", GNUNET_i2s(target), ps_tmp);
        ps = ps_tmp;
        break;
      }
      ps_tmp=ps_tmp->next;
    }
  }

  /* session not existing, address not forced -> looking for other session */
  if ((ps==NULL) && (force_address != GNUNET_YES))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"No existing connection, but free to choose existing, searching for existing connection to peer %s\n", GNUNET_i2s(target));
    /* Choosing different session to peer when possible */
    struct Session * tmp = pc->head;
    while (tmp!=NULL)
    {
      if ((tmp->recv_connected) && (tmp->send_connected) && (tmp->recv_force_disconnect==GNUNET_NO) && (tmp->send_force_disconnect==GNUNET_NO))
      {
        ps = tmp;
      }
      tmp = tmp->next;
    }
    if (ps != NULL)
     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"No existing connection to peer %s, selected connection %X\n", GNUNET_i2s(target),ps);
    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"No existing connection to peer %s, no connection found\n", GNUNET_i2s(target));
  }

  /* session not existing, but address forced -> creating new session */
  if ((ps==NULL) || ((ps==NULL) && (force_address == GNUNET_YES)))
  {
    if ((addr!=NULL) && (addrlen!=0))
    {
      if (force_address == GNUNET_YES)
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"No existing connection & forced address: creating new connection to peer %s\n", GNUNET_i2s(target));
      if (force_address != GNUNET_YES)
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"No existing connection: creating new connection to peer %s\n", GNUNET_i2s(target));

      ps = GNUNET_malloc(sizeof (struct Session));
      if ((addrlen!=0) && (addr!=NULL))
      {
      ps->addr = GNUNET_malloc(addrlen);
      memcpy(ps->addr,addr,addrlen);
      ps->addrlen = addrlen;
      }
      else
      {
        ps->addr = NULL;
        ps->addrlen = 0;
      }
      ps->direction=OUTBOUND;
      ps->recv_connected = GNUNET_NO;
      ps->recv_force_disconnect = GNUNET_NO;
      ps->send_connected = GNUNET_NO;
      ps->send_force_disconnect = GNUNET_NO;
      ps->pending_msgs_head = NULL;
      ps->pending_msgs_tail = NULL;
      ps->peercontext=pc;
      ps->session_id = pc->session_id_counter;
      pc->session_id_counter++;
      ps->url = create_url (plugin, ps->addr, ps->addrlen, ps->session_id);
      if (ps->msgtok == NULL)
        ps->msgtok = GNUNET_SERVER_mst_create (&curl_receive_mst_cb, ps);
      GNUNET_CONTAINER_DLL_insert(pc->head,pc->tail,ps);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"No existing session & and no address given: no way to send this message to peer `%s'!\n", GNUNET_i2s(target));
      return GNUNET_SYSERR;
    }
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
  GNUNET_CONTAINER_DLL_insert(ps->pending_msgs_head,ps->pending_msgs_tail,msg);

  if (send_check_connections (plugin, ps) != GNUNET_SYSERR)
	  return msg->size;
  else
	  return GNUNET_SYSERR;
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
  //struct Session *tmp = NULL;

  pc = GNUNET_CONTAINER_multihashmap_get (plugin->peers, &target->hashPubKey);
  if (pc==NULL)
    return;
  ps = pc->head;

  while (ps!=NULL)
  {

    if (ps->direction==OUTBOUND)
    {
      if (ps->send_endpoint!=NULL)
      {
        //curl_multi_remove_handle(plugin->multi_handle,ps->send_endpoint);
        //curl_easy_cleanup(ps->send_endpoint);
        //ps->send_endpoint=NULL;
        ps->send_force_disconnect = GNUNET_YES;
      }
      if (ps->recv_endpoint!=NULL)
      {
       //curl_multi_remove_handle(plugin->multi_handle,ps->recv_endpoint);
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
    {
      remove_http_message(ps, ps->pending_msgs_head);
    }
    ps->recv_active = GNUNET_NO;
    ps->send_active = GNUNET_NO;
    ps=ps->next;
  }
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
  const struct IPv4HttpAddress *t4;
  const struct IPv6HttpAddress *t6;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  char * address;
  char * ret;
  unsigned int port;
  unsigned int res;

  GNUNET_assert(cls !=NULL);
  if (addrlen == sizeof (struct IPv6HttpAddress))
  {
    address = GNUNET_malloc (INET6_ADDRSTRLEN);
    t6 = addr;
    a6.sin6_addr = t6->ipv6_addr;
    inet_ntop(AF_INET6, &(a6.sin6_addr),address,INET6_ADDRSTRLEN);
    port = ntohs(t6->u6_port);
  }
  else if (addrlen == sizeof (struct IPv4HttpAddress))
  {
    address = GNUNET_malloc (INET_ADDRSTRLEN);
    t4 = addr;
    a4.sin_addr.s_addr =  t4->ipv4_addr;
    inet_ntop(AF_INET, &(a4.sin_addr),address,INET_ADDRSTRLEN);
    port = ntohs(t4->u_port);
  }
  else
  {
    /* invalid address */
    GNUNET_break_op (0);
    asc (asc_cls, NULL);
    return;
  }
  res = GNUNET_asprintf(&ret,"http://%s:%u/",address,port);
  GNUNET_free (address);
  GNUNET_assert(res != 0);

  asc (asc_cls, ret);
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
  unsigned int port;

  GNUNET_assert(cls !=NULL);
  if ((addrlen != sizeof (struct IPv4HttpAddress)) &&
      (addrlen != sizeof (struct IPv6HttpAddress)))
    {
      return GNUNET_SYSERR;
    }
  if (addrlen == sizeof (struct IPv4HttpAddress))
    {
      v4 = (struct IPv4HttpAddress *) addr;
      if (INADDR_LOOPBACK == ntohl(v4->ipv4_addr))
      {
        return GNUNET_SYSERR;
      }
      port = ntohs (v4->u_port);
      if (port != plugin->port_inbound)
      {
        return GNUNET_SYSERR;
      }
    }
  if (addrlen == sizeof (struct IPv6HttpAddress))
    {
      v6 = (struct IPv6HttpAddress *) addr;
      if (IN6_IS_ADDR_LINKLOCAL (&v6->ipv6_addr))
        {
          return GNUNET_SYSERR;
        }
      port = ntohs (v6->u6_port);
      if (port != plugin->port_inbound)
      {
        return GNUNET_SYSERR;
      }
    }

  return GNUNET_OK;
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
  char * ret;
  uint16_t port;
  unsigned int res;

  if (addrlen == sizeof (struct IPv6HttpAddress))
    {
      address = GNUNET_malloc (INET6_ADDRSTRLEN);
      t6 = addr;
      a6.sin6_addr = t6->ipv6_addr;
      inet_ntop(AF_INET6, &(a6.sin6_addr),address,INET6_ADDRSTRLEN);
      port = ntohs(t6->u6_port);
    }
  else if (addrlen == sizeof (struct IPv4HttpAddress))
    {
      address = GNUNET_malloc (INET_ADDRSTRLEN);
      t4 = addr;
      a4.sin_addr.s_addr =  t4->ipv4_addr;
      inet_ntop(AF_INET, &(a4.sin_addr),address,INET_ADDRSTRLEN);
      port = ntohs(t4->u_port);
    }
  else
    {
      /* invalid address */
      return NULL;
    }
  res = GNUNET_asprintf(&ret,"%s:%u",address,port);
  GNUNET_free (address);
  GNUNET_assert(res != 0);
  return ret;
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

  GNUNET_assert(cls !=NULL);
  af = addr->sa_family;
  if (af == AF_INET)
    {
      t4 = GNUNET_malloc(sizeof(struct IPv4HttpAddress));
      if (INADDR_LOOPBACK == ntohl(((struct sockaddr_in *) addr)->sin_addr.s_addr))
      {
        /* skip loopback addresses */
        return GNUNET_OK;
      }
      t4->ipv4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
      t4->u_port = htons (plugin->port_inbound);
      plugin->env->notify_address(plugin->env->cls,"http",t4, sizeof (struct IPv4HttpAddress), GNUNET_TIME_UNIT_FOREVER_REL);

    }
  else if (af == AF_INET6)
    {
      t6 = GNUNET_malloc(sizeof(struct IPv6HttpAddress));
      if (IN6_IS_ADDR_LINKLOCAL (&((struct sockaddr_in6 *) addr)->sin6_addr))
        {
          /* skip link local addresses */
          return GNUNET_OK;
        }
      if (IN6_IS_ADDR_LOOPBACK (&((struct sockaddr_in6 *) addr)->sin6_addr))
        {
          /* skip loopback addresses */
          return GNUNET_OK;
        }
      memcpy (&t6->ipv6_addr,
              &((struct sockaddr_in6 *) addr)->sin6_addr,
              sizeof (struct in6_addr));
      t6->u6_port = htons (plugin->port_inbound);
      plugin->env->notify_address(plugin->env->cls,"http",t6,sizeof (struct IPv6HttpAddress) , GNUNET_TIME_UNIT_FOREVER_REL);
    }
  return GNUNET_OK;
}

int remove_peer_context_Iterator (void *cls, const GNUNET_HashCode *key, void *value)
{
  struct HTTP_PeerContext * pc = value;
  struct Session * ps = pc->head;
  struct Session * tmp = NULL;
  struct HTTP_Message * msg = NULL;
  struct HTTP_Message * msg_tmp = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Freeing context for peer `%s'\n",GNUNET_i2s(&pc->identity));

  while (ps!=NULL)
  {
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
  return GNUNET_YES;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_transport_http_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  CURLMcode mret;

  GNUNET_assert(cls !=NULL);

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
    GNUNET_SCHEDULER_cancel(plugin->env->sched, plugin->http_server_task_v4);
    plugin->http_server_task_v4 = GNUNET_SCHEDULER_NO_TASK;
  }

  if ( plugin->http_server_task_v6 != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(plugin->env->sched, plugin->http_server_task_v6);
    plugin->http_server_task_v6 = GNUNET_SCHEDULER_NO_TASK;
  }

  if ( plugin->http_curl_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(plugin->env->sched, plugin->http_curl_task);
    plugin->http_curl_task = GNUNET_SCHEDULER_NO_TASK;
  }

  /* free all peer information */
  GNUNET_CONTAINER_multihashmap_iterate (plugin->peers,
                                         &remove_peer_context_Iterator,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (plugin->peers);

  mret = curl_multi_cleanup(plugin->multi_handle);
  if ( CURLM_OK != mret)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"curl multihandle clean up failed");
  plugin->multi_handle = NULL;

  GNUNET_free (plugin);
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Unload http plugin complete...\n");
  return NULL;
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_transport_http_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct Plugin *plugin;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct GNUNET_TIME_Relative gn_timeout;
  long long unsigned int port;

  GNUNET_assert(cls !=NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Starting http plugin...\n");

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  plugin->peers = NULL;

  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &http_plugin_send;
  api->disconnect = &http_plugin_disconnect;
  api->address_pretty_printer = &http_plugin_address_pretty_printer;
  api->check_address = &http_plugin_address_suggested;
  api->address_to_string = &http_plugin_address_to_string;

  /* Hashing our identity to use it in URLs */
  GNUNET_CRYPTO_hash_to_enc ( &(plugin->env->my_identity->hashPubKey), &plugin->my_ascii_hash_ident);

  /* Reading port number from config file */
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                              "transport-http",
                                              "PORT",
                                              &port)) ||
      (port > 65535) )
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "http",
                       _
                       ("Require valid port number for transport plugin `%s' in configuration!\n"),
                       "transport-http");
      libgnunet_plugin_transport_http_done (api);
      return NULL;
    }
  GNUNET_assert ((port > 0) && (port <= 65535));
  plugin->port_inbound = port;
  gn_timeout = GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT;
  if ((plugin->http_server_daemon_v4 == NULL) && (plugin->http_server_daemon_v6 == NULL) && (port != 0))
    {
    plugin->http_server_daemon_v6 = MHD_start_daemon (MHD_USE_IPv6,
                                       port,
                                       &mhd_accept_cb,
                                       plugin , &mdh_access_cb, plugin,
                                       MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 16,
                                       MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int) 1,
                                       MHD_OPTION_CONNECTION_TIMEOUT, (gn_timeout.value / 1000),
                                       MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (16 * 1024),
                                       MHD_OPTION_NOTIFY_COMPLETED, &mhd_termination_cb, NULL,
                                       MHD_OPTION_END);
    plugin->http_server_daemon_v4 = MHD_start_daemon (MHD_NO_FLAG,
                                       port,
                                       &mhd_accept_cb,
                                       plugin , &mdh_access_cb, plugin,
                                       MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 16,
                                       MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int) 1,
                                       MHD_OPTION_CONNECTION_TIMEOUT, (gn_timeout.value / 1000),
                                       MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (16 * 1024),
                                       MHD_OPTION_NOTIFY_COMPLETED, &mhd_termination_cb, NULL,
                                       MHD_OPTION_END);
    }
  if (plugin->http_server_daemon_v4 != NULL)
    plugin->http_server_task_v4 = http_server_daemon_prepare (plugin, plugin->http_server_daemon_v4);
  if (plugin->http_server_daemon_v6 != NULL)
    plugin->http_server_task_v6 = http_server_daemon_prepare (plugin, plugin->http_server_daemon_v6);

  if (plugin->http_server_task_v4 != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Starting MHD with IPv4 on port %u\n",port);
  else if (plugin->http_server_task_v6 != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Starting MHD with IPv4 and IPv6 on port %u\n",port);
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"No MHD was started, transport plugin not functional!\n");
    libgnunet_plugin_transport_http_done (api);
    return NULL;
  }

  /* Initializing cURL */
  curl_global_init(CURL_GLOBAL_ALL);
  plugin->multi_handle = curl_multi_init();

  if ( NULL == plugin->multi_handle )
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                     "http",
                     _("Could not initialize curl multi handle, failed to start http plugin!\n"),
                     "transport-http");
    libgnunet_plugin_transport_http_done (api);
    return NULL;
  }

  plugin->peers = GNUNET_CONTAINER_multihashmap_create (10);
  GNUNET_OS_network_interfaces_list (&process_interfaces, plugin);

  return api;
}

/* end of plugin_transport_http.c */
