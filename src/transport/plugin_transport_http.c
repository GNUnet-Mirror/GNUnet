/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file transport/plugin_transport_template.c
 * @brief template for a new transport service
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_connection_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_resolver_service.h"
#include "plugin_transport.h"
#include "gnunet_os_lib.h"
#include "microhttpd.h"
#include <curl/curl.h>


#define DEBUG_CURL GNUNET_NO
#define DEBUG_HTTP GNUNET_NO

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
 * Timeout for a http connect
 */
#define HTTP_MESSAGE_INITIAL_BUFFERSIZE GNUNET_SERVER_MAX_MESSAGE_SIZE


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin;

/**
 * Network format for IPv4 addresses.
 */
struct IPv4HttpAddress
{
  /**
   * IPv4 address, in network byte order.
   */
  uint32_t ipv4_addr;

  /**
   * Port number, in network byte order.
   */
  uint16_t u_port;

};


/**
 * Network format for IPv6 addresses.
 */
struct IPv6HttpAddress
{
  /**
   * IPv6 address.
   */
  struct in6_addr ipv6_addr;

  /**
   * Port number, in network byte order.
   */
  uint16_t u6_port;

};



/**
 *  Message to send using http
 */
struct HTTP_Message
{
  /**
   * Next field for linked list
   */
  struct HTTP_Message * next;

  /**
   * buffer containing data to send
   */
  char *buf;

  /**
   * amount of data already sent
   */
  size_t pos;

  /**
   * amount of data to sent
   */
  size_t len;

  char * dest_url;

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

  unsigned int http_result_code;
};


/**
 * Session handle for connections.
 */
struct Session
{

  /**
   * Stored in a linked list.
   */
  struct Session *next;

  /**
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Sender's ip address to distinguish between incoming connections
   */
  struct sockaddr_in * addr_inbound;

  /**
   * Sender's ip address recieved by transport
   */
  struct sockaddr_in * addr_outbound;

  /**
   * Did we initiate the connection (GNUNET_YES) or the other peer (GNUNET_NO)?
   */
  unsigned int is_client;

  /**
   * Is the connection active (GNUNET_YES) or terminated (GNUNET_NO)?
   */
  unsigned int is_active;

  /**
   * At what time did we reset last_received last?
   */
  struct GNUNET_TIME_Absolute last_quota_update;

  /**
   * How many bytes have we received since the "last_quota_update"
   * timestamp?
   */
  uint64_t last_received;

  /**
   * Number of bytes per ms that this peer is allowed
   * to send to us.
   */
  uint32_t quota;

  /**
   * Is there a HTTP/PUT in progress?
   */
  unsigned int is_put_in_progress;

  /**
   * Is there a HTTP/PUT in progress?
   */
  unsigned int is_bad_request;

  /**
   * Encoded hash
   */
  struct GNUNET_CRYPTO_HashAsciiEncoded hash;

  struct HTTP_Message * pending_outbound_msg;;

  struct HTTP_Message * pending_inbound_msg;

  CURL *curl_handle;
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

  /**
   * List of open sessions.
   */
  struct Session *sessions;

  /**
   * Number of active sessions
   */

  unsigned int session_count;
};

/**
 * Daemon for listening for new IPv4 connections.
 */
static struct MHD_Daemon *http_daemon_v4;

/**
 * Daemon for listening for new IPv6connections.
 */
static struct MHD_Daemon *http_daemon_v6;

/**
 * Our primary task for http daemon handling IPv4 connections
 */
static GNUNET_SCHEDULER_TaskIdentifier http_task_v4;

/**
 * Our primary task for http daemon handling IPv6 connections
 */
static GNUNET_SCHEDULER_TaskIdentifier http_task_v6;


/**
 * The task sending data
 */
static GNUNET_SCHEDULER_TaskIdentifier http_task_send;


/**
 * Information about this plugin
 */
static struct Plugin *plugin;

/**
 * cURL Multihandle
 */
static CURLM *multi_handle;

/**
 * Our ASCII encoded, hashed peer identity
 * This string is used to distinguish between connections and is added to the urls
 */
static struct GNUNET_CRYPTO_HashAsciiEncoded my_ascii_hash_ident;

struct GNUNET_TIME_Relative timeout;

/**
 * Finds a http session in our linked list using peer identity as a key
 * @param peer peeridentity
 * @return http session corresponding to peer identity
 */
static struct Session * find_session_by_pi( const struct GNUNET_PeerIdentity *peer )
{
  struct Session * cur;
  GNUNET_HashCode hc_peer;
  GNUNET_HashCode hc_current;

  cur = plugin->sessions;
  hc_peer = peer->hashPubKey;
  while (cur != NULL)
  {
    hc_current = cur->sender.hashPubKey;
    if ( 0 == GNUNET_CRYPTO_hash_cmp( &hc_peer, &hc_current))
      return cur;
    cur = plugin->sessions->next;
  }
  return NULL;
}

/**
 * Finds a http session in our linked list using libcurl handle as a key
 * Needed when sending data with libcurl to differentiate between sessions
 * @param handle peeridentity
 * @return http session corresponding to peer identity
 */
static struct Session * find_session_by_curlhandle( CURL* handle )
{
  struct Session * cur;

  cur = plugin->sessions;
  while (cur != NULL)
  {
    if ( handle == cur->curl_handle )
      return cur;
    cur = plugin->sessions->next;
  }
  return NULL;
}

/**
 * Create a new session
 *
 * @param addr_in address the peer is using inbound
 * @param addr_out address the peer is using outbound
 * @param peer identity
 * @return created session object
 */
static struct Session * create_session (struct sockaddr_in *addr_in, struct sockaddr_in *addr_out, const struct GNUNET_PeerIdentity *peer)
{
  struct Session * ses = GNUNET_malloc ( sizeof( struct Session) );

  ses->addr_inbound  = GNUNET_malloc ( sizeof (struct sockaddr_in) );
  ses->addr_outbound  = GNUNET_malloc ( sizeof (struct sockaddr_in) );
  ses->next = NULL;
  ses->plugin = plugin;
  if ((NULL != addr_in) && (( AF_INET == addr_in->sin_family) || ( AF_INET6 == addr_in->sin_family)))
  {
    memcpy(ses->addr_inbound, addr_in, sizeof (struct sockaddr_in));
  }
  if ((NULL != addr_out) && (( AF_INET == addr_out->sin_family) || ( AF_INET6 == addr_out->sin_family)))
  {
    memcpy(ses->addr_outbound, addr_out, sizeof (struct sockaddr_in));
  }
  memcpy(&ses->sender, peer, sizeof (struct GNUNET_PeerIdentity));
  GNUNET_CRYPTO_hash_to_enc(&ses->sender.hashPubKey,&(ses->hash));
  ses->is_active = GNUNET_NO;
  ses->pending_inbound_msg = GNUNET_malloc( sizeof (struct HTTP_Message));
  ses->pending_inbound_msg->buf = GNUNET_malloc(GNUNET_SERVER_MAX_MESSAGE_SIZE);
  ses->pending_inbound_msg->len = GNUNET_SERVER_MAX_MESSAGE_SIZE;
  ses->pending_inbound_msg->pos = 0;
  return ses;
}

/**
 * Callback called by MHD when a connection is terminated
 */
static void requestCompletedCallback (void *cls, struct MHD_Connection * connection, void **httpSessionCache)
{
  struct Session * cs;

  cs = *httpSessionCache;
  if (cs != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection from peer `%s' was terminated\n",GNUNET_i2s(&cs->sender));
    /* session set to inactive */
    cs->is_active = GNUNET_NO;
    cs->is_put_in_progress = GNUNET_NO;
  }
  return;
}

/**
 * Check if we are allowed to connect to the given IP.
 */
static int
acceptPolicyCallback (void *cls,
                      const struct sockaddr *addr, socklen_t addr_len)
{
  /* Every connection is accepted, nothing more to do here */
  return MHD_YES;
}

/**
 * Process GET or PUT request received via MHD.  For
 * GET, queue response that will send back our pending
 * messages.  For PUT, process incoming data and send
 * to GNUnet core.  In either case, check if a session
 * already exists and create a new one if not.
 */
static int
accessHandlerCallback (void *cls,
                       struct MHD_Connection *session,
                       const char *url,
                       const char *method,
                       const char *version,
                       const char *upload_data,
                       size_t * upload_data_size, void **httpSessionCache)
{
  struct MHD_Response *response;
  struct Session * cs;
  struct Session * cs_temp;
  const union MHD_ConnectionInfo * conn_info;
  struct sockaddr_in  *addrin;
  struct sockaddr_in6 *addrin6;
  char address[INET6_ADDRSTRLEN+14];
  struct GNUNET_PeerIdentity pi_in;
  int res = GNUNET_NO;
  struct GNUNET_MessageHeader *gn_msg;
  int send_error_to_client;

  gn_msg = NULL;
  send_error_to_client = GNUNET_NO;

  if ( NULL == *httpSessionCache)
  {
    /* check url for peer identity */
    res = GNUNET_CRYPTO_hash_from_string ( &url[1], &(pi_in.hashPubKey));
    if ( GNUNET_SYSERR == res )
    {
      response = MHD_create_response_from_data (strlen (HTTP_ERROR_RESPONSE),HTTP_ERROR_RESPONSE, MHD_NO, MHD_NO);
      res = MHD_queue_response (session, MHD_HTTP_NOT_FOUND, response);
      MHD_destroy_response (response);
      if (res == MHD_YES)
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Peer has no valid ident, sent HTTP 1.1/404\n");
      else
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Peer has no valid ident, could not send error\n");
      return res;
    }

    conn_info = MHD_get_connection_info(session, MHD_CONNECTION_INFO_CLIENT_ADDRESS );
    /* Incoming IPv4 connection */
    if ( AF_INET == conn_info->client_addr->sin_family)
    {
      addrin = conn_info->client_addr;
      inet_ntop(addrin->sin_family, &(addrin->sin_addr),address,INET_ADDRSTRLEN);
    }
    /* Incoming IPv6 connection */
    if ( AF_INET6 == conn_info->client_addr->sin_family)
    {
      addrin6 = (struct sockaddr_in6 *) conn_info->client_addr;
      inet_ntop(addrin6->sin6_family, &(addrin6->sin6_addr),address,INET6_ADDRSTRLEN);
    }
    /* find existing session for address */
    cs = NULL;
    if (plugin->session_count > 0)
    {
      cs = plugin->sessions;
      while ( NULL != cs)
      {

        /* Comparison based on ip address */
        // res = (0 == memcmp(&(conn_info->client_addr->sin_addr),&(cs->addr->sin_addr), sizeof (struct in_addr))) ? GNUNET_YES : GNUNET_NO;

        /* Comparison based on ip address, port number and address family */
        // res = (0 == memcmp((conn_info->client_addr),(cs->addr), sizeof (struct sockaddr_in))) ? GNUNET_YES : GNUNET_NO;

        /* Comparison based on PeerIdentity */
        res = (0 == memcmp(&pi_in,&(cs->sender), sizeof (struct GNUNET_PeerIdentity))) ? GNUNET_YES : GNUNET_NO;

        if ( GNUNET_YES  == res)
        {
          /* existing session for this address found */
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Session for peer `%s' found\n",GNUNET_i2s(&cs->sender));
          break;
        }
        cs = cs->next;
      }
    }
    /* no existing session, create a new one*/
    if (cs == NULL )
    {
      /* create new session object */
      cs = create_session(conn_info->client_addr, NULL, &pi_in);

      /* Insert session into linked list */
      if ( plugin->sessions == NULL)
      {
        plugin->sessions = cs;
        plugin->session_count = 1;
      }
      cs_temp = plugin->sessions;
      while ( cs_temp->next != NULL )
      {
        cs_temp = cs_temp->next;
      }
      if (cs_temp != cs )
      {
        cs_temp->next = cs;
        plugin->session_count++;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"New Session `%s' inserted, count %u \n", GNUNET_i2s(&cs->sender), plugin->session_count);
    }

    /* Set closure */
    if (*httpSessionCache == NULL)
    {
      *httpSessionCache = cs;
      /* Updating session */
      memcpy(cs->addr_inbound,conn_info->client_addr, sizeof(struct sockaddr_in));
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"HTTP Daemon has new an incoming `%s' request from peer `%s' (`[%s]:%u')\n",method, GNUNET_i2s(&cs->sender),address,ntohs(cs->addr_inbound->sin_port));
  }
  else
  {
    cs = *httpSessionCache;
  }
  /* Is it a PUT or a GET request */
  if ( 0 == strcmp (MHD_HTTP_METHOD_PUT, method) )
  {
    /* New  */
    if ((*upload_data_size == 0) && (cs->is_put_in_progress == GNUNET_NO))
    {
      if (cs->pending_inbound_msg->pos !=0 )
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Incoming message from peer `%s', while existing message with %u bytes was not forwarded to transport'\n"),
                    GNUNET_i2s(&cs->sender), cs->pending_inbound_msg->pos);
        cs->pending_inbound_msg->pos = 0;
      }
      /* not yet ready */
      cs->is_put_in_progress = GNUNET_YES;
      cs->is_bad_request = GNUNET_NO;
      cs->is_active = GNUNET_YES;
      return MHD_YES;
    }

    if ((*upload_data_size > 0) && (cs->is_bad_request != GNUNET_YES))
    {
      if ((*upload_data_size + cs->pending_inbound_msg->pos < cs->pending_inbound_msg->len) && (*upload_data_size + cs->pending_inbound_msg->pos <= GNUNET_SERVER_MAX_MESSAGE_SIZE))
      {
        /* copy uploaded data to buffer */
        memcpy(&cs->pending_inbound_msg->buf[cs->pending_inbound_msg->pos],upload_data,*upload_data_size);
        cs->pending_inbound_msg->pos += *upload_data_size;
        *upload_data_size = 0;
        return MHD_YES;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"%u bytes not added to message of %u bytes, message to big\n",*upload_data_size, cs->pending_inbound_msg->pos);
        cs->is_bad_request = GNUNET_YES;
        /* (*upload_data_size) bytes not processed */
        return MHD_YES;
      }
    }

    if ((cs->is_put_in_progress == GNUNET_YES) && (cs->is_bad_request == GNUNET_YES))
    {
      *upload_data_size = 0;
      response = MHD_create_response_from_data (strlen (HTTP_PUT_RESPONSE),HTTP_PUT_RESPONSE, MHD_NO, MHD_NO);
      res = MHD_queue_response (session, MHD_HTTP_REQUEST_ENTITY_TOO_LARGE, response);
      if (res == MHD_YES)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Sent HTTP/1.1: 413 Request Entity Too Large as PUT Response\n");
        cs->is_bad_request = GNUNET_NO;
        cs->is_put_in_progress =GNUNET_NO;
        cs->pending_inbound_msg->pos = 0;
      }
      MHD_destroy_response (response);
      return MHD_YES;
    }

    if ((*upload_data_size == 0) && (cs->is_put_in_progress == GNUNET_YES) && (cs->is_bad_request == GNUNET_NO))
    {
      send_error_to_client = GNUNET_YES;
      struct GNUNET_MessageHeader * gn_msg = NULL;
      /*check message and forward here */
      /* checking size */
      if (cs->pending_inbound_msg->pos >= sizeof (struct GNUNET_MessageHeader))
      {
        gn_msg = GNUNET_malloc (cs->pending_inbound_msg->pos);
        memcpy (gn_msg,cs->pending_inbound_msg->buf,cs->pending_inbound_msg->pos);

        if ((ntohs(gn_msg->size) == cs->pending_inbound_msg->pos))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Recieved GNUnet message type %u size %u and payload %u \n",ntohs (gn_msg->type), ntohs (gn_msg->size), ntohs (gn_msg->size)-sizeof(struct GNUNET_MessageHeader));
          /* forwarding message to transport */

          char * tmp = NULL;
          if ( AF_INET == cs->addr_inbound->sin_family)
          {
            tmp = GNUNET_malloc (INET_ADDRSTRLEN + 14);
            inet_ntop(AF_INET, &(cs->addr_inbound)->sin_addr,address,INET_ADDRSTRLEN);
            GNUNET_asprintf(&tmp,"%s:%u",address,ntohs(cs->addr_inbound->sin_port));
          }
          /* Incoming IPv6 connection */
          if ( AF_INET6 == cs->addr_inbound->sin_family)
          {
            tmp = GNUNET_malloc (INET6_ADDRSTRLEN + 14);
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *) cs->addr_inbound)->sin6_addr,address,INET6_ADDRSTRLEN);
            GNUNET_asprintf(&tmp,"[%s]:%u",address,ntohs(cs->addr_inbound->sin_port));

          }
          if (NULL != tmp)
          {
            plugin->env->receive(plugin->env, &(cs->sender), gn_msg, 1, cs , tmp, strlen(tmp));
            GNUNET_free_non_null(tmp);
          }
          send_error_to_client = GNUNET_NO;
        }
      }

      if (send_error_to_client == GNUNET_NO)
      {
        response = MHD_create_response_from_data (strlen (HTTP_PUT_RESPONSE),HTTP_PUT_RESPONSE, MHD_NO, MHD_NO);
        res = MHD_queue_response (session, MHD_HTTP_OK, response);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Sent HTTP/1.1: 200 OK as PUT Response\n",HTTP_PUT_RESPONSE, strlen (HTTP_PUT_RESPONSE), res );
        MHD_destroy_response (response);
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Recieved malformed message with %u bytes\n", cs->pending_inbound_msg->pos);
        response = MHD_create_response_from_data (strlen (HTTP_PUT_RESPONSE),HTTP_PUT_RESPONSE, MHD_NO, MHD_NO);
        res = MHD_queue_response (session, MHD_HTTP_BAD_REQUEST, response);
        MHD_destroy_response (response);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Sent HTTP/1.1: 400 BAD REQUEST as PUT Response\n");
      }

      GNUNET_free_non_null (gn_msg);
      cs->is_put_in_progress = GNUNET_NO;
      cs->is_bad_request = GNUNET_NO;
      cs->pending_inbound_msg->pos = 0;
      return res;
    }
  }
  if ( 0 == strcmp (MHD_HTTP_METHOD_GET, method) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Got GET Request\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"URL: `%s'\n",url);
    response = MHD_create_response_from_data (strlen (HTTP_PUT_RESPONSE),HTTP_PUT_RESPONSE, MHD_NO, MHD_NO);
    res = MHD_queue_response (session, MHD_HTTP_OK, response);
    MHD_destroy_response (response);
    return res;
  }
  return MHD_NO;
}


/**
 * Call MHD to process pending requests and then go back
 * and schedule the next run.
 */
static void http_daemon_run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 */
static GNUNET_SCHEDULER_TaskIdentifier
http_daemon_prepare (struct MHD_Daemon *daemon_handle)
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
  ret = GNUNET_SCHEDULER_add_select (plugin->env->sched,
                                     GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                     GNUNET_SCHEDULER_NO_TASK,
                                     tv,
                                     wrs,
                                     wws,
                                     &http_daemon_run,
                                     daemon_handle);
  GNUNET_NETWORK_fdset_destroy (wrs);
  GNUNET_NETWORK_fdset_destroy (wws);
  GNUNET_NETWORK_fdset_destroy (wes);
  return ret;
}

/**
 * Call MHD to process pending requests and then go back
 * and schedule the next run.
 */
static void http_daemon_run (void *cls,
                             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MHD_Daemon *daemon_handle = cls;

  if (daemon_handle == http_daemon_v4)
    http_task_v4 = GNUNET_SCHEDULER_NO_TASK;

  if (daemon_handle == http_daemon_v6)
    http_task_v6 = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_assert (MHD_YES == MHD_run (daemon_handle));
  if (daemon_handle == http_daemon_v4)
    http_task_v4 = http_daemon_prepare (daemon_handle);
  if (daemon_handle == http_daemon_v6)
    http_task_v6 = http_daemon_prepare (daemon_handle);
  return;
}

/**
 * Removes a message from the linked list of messages
 * @param ses session to remove message from
 * @param msg message to remove
 * @return GNUNET_SYSERR if msg not found, GNUNET_OK on success
 */

static int remove_http_message(struct Session * ses, struct HTTP_Message * msg)
{
  struct HTTP_Message * cur;
  struct HTTP_Message * next;

  cur = ses->pending_outbound_msg;
  next = NULL;

  if (cur == NULL)
    return GNUNET_SYSERR;

  if (cur == msg)
  {
    ses->pending_outbound_msg = cur->next;
    GNUNET_free (cur->buf);
    GNUNET_free (cur->dest_url);
    GNUNET_free (cur);
    cur = NULL;
    return GNUNET_OK;
  }

  while (cur->next!=msg)
  {
    if (cur->next != NULL)
      cur = cur->next;
    else
      return GNUNET_SYSERR;
  }

  cur->next = cur->next->next;
  GNUNET_free (cur->next->buf);
  GNUNET_free (cur->next->dest_url);
  GNUNET_free (cur->next);
  cur->next = NULL;
  return GNUNET_OK;
}


static size_t header_function( void *ptr, size_t size, size_t nmemb, void *stream)
{
  char * tmp;
  unsigned int len = size * nmemb;
  struct Session * ses = stream;

  tmp = GNUNET_malloc (  len+1 );
  memcpy(tmp,ptr,len);
  if (tmp[len-2] == 13)
    tmp[len-2]= '\0';
#if DEBUG_CURL
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Header: `%s'\n",tmp);
#endif
  if (0==strcmp (tmp,"HTTP/1.1 100 Continue"))
  {
    ses->pending_outbound_msg->http_result_code=100;
  }
  if (0==strcmp (tmp,"HTTP/1.1 200 OK"))
  {
    ses->pending_outbound_msg->http_result_code=200;
  }
  if (0==strcmp (tmp,"HTTP/1.1 400 Bad Request"))
  {
    ses->pending_outbound_msg->http_result_code=400;
  }
  if (0==strcmp (tmp,"HTTP/1.1 404 Not Found"))
  {
    ses->pending_outbound_msg->http_result_code=404;
  }
  if (0==strcmp (tmp,"HTTP/1.1 413 Request Entity Too Large"))
  {
    ses->pending_outbound_msg->http_result_code=413;
  }
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
static size_t send_read_callback(void *stream, size_t size, size_t nmemb, void *ptr)
{
  struct Session * ses = ptr;
  struct HTTP_Message * msg = ses->pending_outbound_msg;
  unsigned int bytes_sent;
  unsigned int len;
  bytes_sent = 0;

  /* data to send */
  if (( msg->pos < msg->len))
  {
    /* data fit in buffer */
    if ((msg->len - msg->pos) <= (size * nmemb))
    {
      len = (msg->len - msg->pos);
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
static size_t send_write_callback( void *stream, size_t size, size_t nmemb, void *ptr)
{
  char * data = malloc(size*nmemb +1);

  memcpy( data, stream, size*nmemb);
  data[size*nmemb] = '\0';
  /* Just a dummy print for the response recieved for the PUT message */
  /* GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Recieved %u bytes: `%s' \n", size * nmemb, data); */
  free (data);
  return (size * nmemb);

}

/**
 * Function setting up file descriptors and scheduling task to run
 * @param session session to send data to
 * @return bytes sent to peer
 */
static size_t send_prepare(struct Session* ses );

/**
 * Function setting up curl handle and selecting message to send
 * @param ses session to send data to
 * @return bytes sent to peer
 */
static ssize_t send_select_init (struct Session* ses )
{
  int bytes_sent = 0;
  CURLMcode mret;
  struct HTTP_Message * msg;

  if ( NULL == ses->curl_handle)
    ses->curl_handle = curl_easy_init();
  if( NULL == ses->curl_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Getting cURL handle failed\n");
    return -1;
  }
  msg = ses->pending_outbound_msg;



#if DEBUG_CURL
  curl_easy_setopt(ses->curl_handle, CURLOPT_VERBOSE, 1L);
#endif
  curl_easy_setopt(ses->curl_handle, CURLOPT_URL, msg->dest_url);
  curl_easy_setopt(ses->curl_handle, CURLOPT_PUT, 1L);
  curl_easy_setopt(ses->curl_handle, CURLOPT_HEADERFUNCTION, &header_function);
  curl_easy_setopt(ses->curl_handle, CURLOPT_WRITEHEADER, ses);
  curl_easy_setopt(ses->curl_handle, CURLOPT_READFUNCTION, send_read_callback);
  curl_easy_setopt(ses->curl_handle, CURLOPT_READDATA, ses);
  curl_easy_setopt(ses->curl_handle, CURLOPT_WRITEFUNCTION, send_write_callback);
  curl_easy_setopt(ses->curl_handle, CURLOPT_READDATA, ses);
  curl_easy_setopt(ses->curl_handle, CURLOPT_INFILESIZE_LARGE, (curl_off_t) msg->len);
  curl_easy_setopt(ses->curl_handle, CURLOPT_TIMEOUT, (long) (timeout.value / 1000 ));
  curl_easy_setopt(ses->curl_handle, CURLOPT_CONNECTTIMEOUT, HTTP_CONNECT_TIMEOUT);
  curl_easy_setopt(ses->curl_handle, CURLOPT_BUFFERSIZE, GNUNET_SERVER_MAX_MESSAGE_SIZE);

  mret = curl_multi_add_handle(multi_handle, ses->curl_handle);
  if (mret != CURLM_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("%s failed at %s:%d: `%s'\n"),
                "curl_multi_add_handle", __FILE__, __LINE__,
                curl_multi_strerror (mret));
    return -1;
  }
  bytes_sent = send_prepare (ses );
  return bytes_sent;
}

static void send_execute (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static unsigned int handles_last_run;
  int running;
  struct CURLMsg *msg;
  CURLMcode mret;
  struct Session * cs = NULL;

  http_task_send = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  do
    {
      running = 0;
      mret = curl_multi_perform (multi_handle, &running);
      if (running < handles_last_run)
        {
          do
            {

              msg = curl_multi_info_read (multi_handle, &running);
              GNUNET_break (msg != NULL);
              if (msg == NULL)
                break;
              /* get session for affected curl handle */
              GNUNET_assert ( msg->easy_handle != NULL );
              cs = find_session_by_curlhandle (msg->easy_handle);
              GNUNET_assert ( cs != NULL );
              GNUNET_assert ( cs->pending_outbound_msg != NULL );
              switch (msg->msg)
                {

                case CURLMSG_DONE:
                  if ( (msg->data.result != CURLE_OK) &&
                       (msg->data.result != CURLE_GOT_NOTHING) )
                    {

                    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
                               _("%s failed for `%s' at %s:%d: `%s'\n"),
                               "curl_multi_perform",
                               GNUNET_i2s(&cs->sender),
                               __FILE__,
                               __LINE__,
                               curl_easy_strerror (msg->data.result));
                    /* sending msg failed*/
                    if (( NULL != cs->pending_outbound_msg) && ( NULL != cs->pending_outbound_msg->transmit_cont))
                      cs->pending_outbound_msg->transmit_cont (cs->pending_outbound_msg->transmit_cont_cls,&cs->sender,GNUNET_SYSERR);
                    }
                  else
                  {

                    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                                "Send to peer `%s' completed with code %u\n", GNUNET_i2s(&cs->sender),cs->pending_outbound_msg->http_result_code);

                    curl_easy_cleanup(cs->curl_handle);
                    cs->curl_handle=NULL;

                    /* Calling transmit continuation  */
                    if (( NULL != cs->pending_outbound_msg) && (NULL != cs->pending_outbound_msg->transmit_cont))
                    {
                      /* HTTP 1xx : Last message before here was informational */
                      if ((cs->pending_outbound_msg->http_result_code >=100) && (cs->pending_outbound_msg->http_result_code < 200))
                        cs->pending_outbound_msg->transmit_cont (cs->pending_outbound_msg->transmit_cont_cls,&cs->sender,GNUNET_OK);
                      /* HTTP 2xx: successful operations */
                      if ((cs->pending_outbound_msg->http_result_code >=200) && (cs->pending_outbound_msg->http_result_code < 300))
                        cs->pending_outbound_msg->transmit_cont (cs->pending_outbound_msg->transmit_cont_cls,&cs->sender,GNUNET_OK);
                      /* HTTP 3xx..5xx: error */
                      if ((cs->pending_outbound_msg->http_result_code >=300) && (cs->pending_outbound_msg->http_result_code < 600))
                        cs->pending_outbound_msg->transmit_cont (cs->pending_outbound_msg->transmit_cont_cls,&cs->sender,GNUNET_SYSERR);
                    }
                    if (GNUNET_OK != remove_http_message(cs, cs->pending_outbound_msg))
                      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Message could not be removed from session `%s'", GNUNET_i2s(&cs->sender));

                    /* send pending messages */
                    if (cs->pending_outbound_msg != NULL)
                    {
                      send_select_init (cs);
                    }
                  }
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
  send_prepare(cls);
}


/**
 * Function setting up file descriptors and scheduling task to run
 * @param ses session to send data to
 * @return bytes sent to peer
 */
static size_t send_prepare(struct Session* ses )
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct GNUNET_NETWORK_FDSet *grs;
  struct GNUNET_NETWORK_FDSet *gws;
  long to;
  CURLMcode mret;

  max = -1;
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  mret = curl_multi_fdset (multi_handle, &rs, &ws, &es, &max);
  if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_fdset", __FILE__, __LINE__,
                  curl_multi_strerror (mret));
      return -1;
    }
  mret = curl_multi_timeout (multi_handle, &to);
  if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_timeout", __FILE__, __LINE__,
                  curl_multi_strerror (mret));
      return -1;
    }

  grs = GNUNET_NETWORK_fdset_create ();
  gws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (grs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (gws, &ws, max + 1);
  http_task_send = GNUNET_SCHEDULER_add_select (plugin->env->sched,
                                   GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   GNUNET_SCHEDULER_NO_TASK,
                                   GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 0),
                                   grs,
                                   gws,
                                   &send_execute,
                                   ses);
  GNUNET_NETWORK_fdset_destroy (gws);
  GNUNET_NETWORK_fdset_destroy (grs);

  /* FIXME: return bytes REALLY sent */
  return 0;
}

/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.
 *
 * @param cls closure
 * @param target who should receive this message
 * @param priority how important is the message
 * @param msgbuf the message to transmit
 * @param msgbuf_size number of bytes in 'msgbuf'
 * @param to when should we time out
 * @param session which session must be used (or NULL for "any")
 * @param addr the address to use (can be NULL if the plugin
 *                is "on its own" (i.e. re-use existing TCP connection))
 * @param addrlen length of the address in bytes
 * @param force_address GNUNET_YES if the plugin MUST use the given address,
 *                otherwise the plugin may use other addresses or
 *                existing connections (if available)
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
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
  char * address;
  struct Session* ses;
  struct Session* ses_temp;
  struct HTTP_Message * msg;
  struct HTTP_Message * tmp;
  int bytes_sent = 0;


  address = NULL;
  /* find session for peer */
  ses = find_session_by_pi (target);
  if (NULL != ses )
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Existing session for peer `%s' found\n", GNUNET_i2s(target));
  if ( ses == NULL)
  {
    /* create new session object */

    ses = create_session(NULL, (struct sockaddr_in *) addr, target);
    ses->is_active = GNUNET_YES;

    /* Insert session into linked list */
    if ( plugin->sessions == NULL)
    {
      plugin->sessions = ses;
      plugin->session_count = 1;
    }
    ses_temp = plugin->sessions;
    while ( ses_temp->next != NULL )
    {
      ses_temp = ses_temp->next;
    }
    if (ses_temp != ses )
    {
      ses_temp->next = ses;
      plugin->session_count++;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"New Session `%s' inserted, count %u \n", GNUNET_i2s(target), plugin->session_count);
  }

  GNUNET_assert (addr!=NULL);
  unsigned int port;

  /* setting url to send to */
  if (force_address == GNUNET_YES)
  {
    if (addrlen == (sizeof (struct IPv4HttpAddress)))
    {
      address = GNUNET_malloc(INET_ADDRSTRLEN + 14 + strlen ((const char *) (&ses->hash)));
      inet_ntop(AF_INET,&((struct IPv4HttpAddress *) addr)->ipv4_addr,address,INET_ADDRSTRLEN);
      port = ntohs(((struct IPv4HttpAddress *) addr)->u_port);
      GNUNET_asprintf(&address,"http://%s:%u/%s",address,port, (char *) (&ses->hash));
    }
    else if (addrlen == (sizeof (struct IPv6HttpAddress)))
    {
      address = GNUNET_malloc(INET6_ADDRSTRLEN + 14 + strlen ((const char *) (&ses->hash)));
      inet_ntop(AF_INET6, &((struct IPv6HttpAddress *) addr)->ipv6_addr,address,INET6_ADDRSTRLEN);
      port = ntohs(((struct IPv6HttpAddress *) addr)->u6_port);
      GNUNET_asprintf(&address,"http://%s:%u/%s",address,port,(char *) (&ses->hash));
    }
    else
      {
        GNUNET_break (0);
        return -1;
    }
  }

  GNUNET_assert (address != NULL);

  timeout = to;
  /* setting up message */
  msg = GNUNET_malloc (sizeof (struct HTTP_Message));
  msg->next = NULL;
  msg->len = msgbuf_size;
  msg->pos = 0;
  msg->buf = GNUNET_malloc (msgbuf_size);
  msg->dest_url = address;
  msg->transmit_cont = cont;
  msg->transmit_cont_cls = cont_cls;
  memcpy (msg->buf,msgbuf, msgbuf_size);

  /* insert created message in list of pending messages */
  if (ses->pending_outbound_msg == NULL)
  {
    ses->pending_outbound_msg = msg;
  }
  tmp = ses->pending_outbound_msg;
  while ( NULL != tmp->next)
  {
    tmp = tmp->next;
  }
  if ( tmp != msg)
  {
    tmp->next = msg;
  }

  if (msg == ses->pending_outbound_msg)
  {
    bytes_sent = send_select_init (ses);
    return bytes_sent;
  }
  return msgbuf_size;
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"HTTP Plugin: http_plugin_disconnect\n");
  // struct Plugin *plugin = cls;
  // FIXME
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

  ret = GNUNET_malloc(strlen(address) +14);
  GNUNET_asprintf(&ret,"http://%s:%u/",address,port);
  GNUNET_free (address);
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
                                  void *addr, size_t addrlen)
{
  struct IPv4HttpAddress *v4;
  struct IPv6HttpAddress *v6;
  unsigned int port;

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
  else
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
  unsigned int port;

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

  ret = GNUNET_malloc(strlen(address) +6);
  GNUNET_asprintf(&ret,"%s:%u",address,port);
  GNUNET_free (address);
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
  struct IPv4HttpAddress t4;
  struct IPv6HttpAddress t6;
  int af;
  void *arg;
  uint16_t args;

  af = addr->sa_family;
  if (af == AF_INET)
    {
      if (INADDR_LOOPBACK == ntohl(((struct sockaddr_in *) addr)->sin_addr.s_addr))
      {
        /* skip loopback addresses */
        return GNUNET_OK;
      }
      t4.ipv4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
      t4.u_port = htons (plugin->port_inbound);
      arg = &t4;
      args = sizeof (t4);
    }
  else if (af == AF_INET6)
    {
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
      memcpy (&t6.ipv6_addr,
              &((struct sockaddr_in6 *) addr)->sin6_addr,
              sizeof (struct in6_addr));
      t6.u6_port = htons (plugin->port_inbound);
      arg = &t6;
      args = sizeof (t6);
    }
  else
    {
      GNUNET_break (0);
      return GNUNET_OK;
    }
  plugin->env->notify_address(plugin->env->cls,"http",arg, args, GNUNET_TIME_UNIT_FOREVER_REL);
  return GNUNET_OK;
}

/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_transport_http_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct Session * cs;
  struct Session * cs_next;
  CURLMcode mret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Unloading http plugin...\n");

  if ( http_task_v4 != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(plugin->env->sched, http_task_v4);
    http_task_v4 = GNUNET_SCHEDULER_NO_TASK;
  }

  if ( http_task_v6 != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(plugin->env->sched, http_task_v6);
    http_task_v6 = GNUNET_SCHEDULER_NO_TASK;
  }

  if ( http_task_send != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(plugin->env->sched, http_task_send);
    http_task_send = GNUNET_SCHEDULER_NO_TASK;
  }

  if (http_daemon_v4 != NULL)
  {
    MHD_stop_daemon (http_daemon_v4);
    http_daemon_v4 = NULL;
  }
  if (http_daemon_v6 != NULL)
  {
    MHD_stop_daemon (http_daemon_v6);
    http_daemon_v6 = NULL;
  }

  /* free all sessions */
  cs = plugin->sessions;

  while ( NULL != cs)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Freeing session for peer `%s'\n",GNUNET_i2s(&cs->sender));

      cs_next = cs->next;

      /* freeing messages */
      struct HTTP_Message *cur;
      struct HTTP_Message *tmp;
      cur = cs->pending_outbound_msg;

      while (cur != NULL)
      {
         tmp = cur->next;
         if (NULL != cur->buf)
           GNUNET_free (cur->buf);
         GNUNET_free (cur);
         cur = tmp;
      }
      GNUNET_free (cs->pending_inbound_msg->buf);
      GNUNET_free (cs->pending_inbound_msg);
      GNUNET_free_non_null (cs->addr_inbound);
      GNUNET_free_non_null (cs->addr_outbound);
      GNUNET_free (cs);

      plugin->session_count--;
      cs = cs_next;
    }

  mret = curl_multi_cleanup(multi_handle);
  if ( CURLM_OK != mret)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"curl multihandle clean up failed");

  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_transport_http_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  unsigned int timeout;
  struct GNUNET_TIME_Relative gn_timeout;
  long long unsigned int port;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Starting http plugin...\n");

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  plugin->sessions = NULL;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &http_plugin_send;
  api->disconnect = &http_plugin_disconnect;
  api->address_pretty_printer = &http_plugin_address_pretty_printer;
  api->check_address = &http_plugin_address_suggested;
  api->address_to_string = &http_plugin_address_to_string;

  /* Hashing our identity to use it in URLs */
  GNUNET_CRYPTO_hash_to_enc ( &(plugin->env->my_identity->hashPubKey), &my_ascii_hash_ident);

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
  GNUNET_assert (&my_ascii_hash_ident != NULL);

  plugin->port_inbound = port;
  gn_timeout = GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT;
  timeout = ( gn_timeout.value / 1000);
  if ((http_daemon_v4 == NULL) && (http_daemon_v6 == NULL) && (port != 0))
    {
    http_daemon_v6 = MHD_start_daemon (MHD_USE_IPv6,
                                       port,
                                       &acceptPolicyCallback,
                                       NULL , &accessHandlerCallback, NULL,
                                       MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 16,
                                       MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int) 1,
                                       MHD_OPTION_CONNECTION_TIMEOUT, timeout,
                                       /* FIXME: set correct limit */
                                       MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (16 * 1024),
                                       MHD_OPTION_NOTIFY_COMPLETED, &requestCompletedCallback, NULL,
                                       MHD_OPTION_END);
    http_daemon_v4 = MHD_start_daemon (MHD_NO_FLAG,
                                       port,
                                       &acceptPolicyCallback,
                                       NULL , &accessHandlerCallback, NULL,
                                       MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 16,
                                       MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int) 1,
                                       MHD_OPTION_CONNECTION_TIMEOUT, timeout,
                                       /* FIXME: set correct limit */
                                       MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (16 * 1024),
                                       MHD_OPTION_NOTIFY_COMPLETED, &requestCompletedCallback, NULL,
                                       MHD_OPTION_END);
    }
  if (http_daemon_v4 != NULL)
    http_task_v4 = http_daemon_prepare (http_daemon_v4);
  if (http_daemon_v6 != NULL)
    http_task_v6 = http_daemon_prepare (http_daemon_v6);

  if (http_task_v4 != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Starting MHD with IPv4 on port %u\n",port);
  else if (http_task_v6 != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Starting MHD with IPv4 and IPv6 on port %u\n",port);
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"No MHD was started, transport plugin not functional!\n");
    libgnunet_plugin_transport_http_done (api);
    return NULL;
  }

  /* Initializing cURL */
  multi_handle = curl_multi_init();
  if ( NULL == multi_handle )
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                     "http",
                     _("Could not initialize curl multi handle, failed to start http plugin!\n"),
                     "transport-http");
    libgnunet_plugin_transport_http_done (api);
    return NULL;
  }

  GNUNET_OS_network_interfaces_list (&process_interfaces, plugin);

  return api;
}

/* end of plugin_transport_template.c */
