/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file transports/http.c
 * @brief Implementation of the HTTP transport service
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "gnunet_stats_service.h"
#include "gnunet_upnp_service.h"
#include <stdint.h>
#include <microhttpd.h>
#include <curl/curl.h>
#include "ip.h"

#define DEBUG_HTTP GNUNET_NO

/**
 * Disable GET (for debugging only!).  Must be GNUNET_YES
 * in production use!
 */
#define DO_GET GNUNET_YES

/**
 * After how much time of the core not being associated with a http
 * connection anymore do we close it?
 *
 * Needs to be larger than SECONDS_INACTIVE_DROP in
 * core's connection.s
 */
#define HTTP_TIMEOUT (600 * GNUNET_CRON_SECONDS)

/**
 * How often do we re-issue GET requests?
 */
#define HTTP_GET_REFRESH (5 * GNUNET_CRON_SECONDS)

/**
 * Default maximum size of the HTTP read and write buffer.
 */
#define HTTP_BUF_SIZE (64 * 1024)

/**
 * Text of the response sent back after the last bytes of a PUT
 * request have been received (just to formally obey the HTTP
 * protocol).
 */
#define HTTP_PUT_RESPONSE "Thank you!"

#define MY_TRANSPORT_NAME "HTTP"
#include "common.c"

/**
 * Client-side data per PUT request.
 */
struct HTTPPutData
{
  /**
   * This is a linked list.
   */
  struct HTTPPutData *next;

  /**
   * Handle to our CURL request.
   */
  CURL *curl_put;

  /**
   * Last time we made progress with the PUT.
   */
  GNUNET_CronTime last_activity;

  /**
   * The message we are sending.
   */
  char *msg;

  /**
   * Size of msg.
   */
  unsigned int size;

  /**
   * Current position in msg.
   */
  unsigned int pos;

  /**
   * Are we done sending?  Set to 1 after we
   * completed sending and started to receive
   * a response ("Thank you!") or once the
   * timeout has been reached.
   */
  int done;

};

/**
 * Server-side data per PUT request.
 */
struct MHDPutData
{
  /**
   * This is a linked list.
   */
  struct MHDPutData *next;

  /**
   * MHD connection handle for this request.
   */
  struct MHD_Connection *session;

  /**
   * Last time we received data on this PUT
   * connection.
   */
  GNUNET_CronTime last_activity;

  /**
   * Read buffer for the header (from PUT)
   */
  char rbuff1[sizeof (GNUNET_MessageHeader)];

  /**
   * The read buffer (used only receiving PUT data).
   */
  char *rbuff2;

  /**
   * Number of valid bytes in rbuff1
   */
  unsigned int rpos1;

  /**
   * Number of valid bytes in rbuff2
   */
  unsigned int rpos2;


  /**
   * Size of the rbuff2 buffer.
   */
  unsigned int rsize2;

  /**
   * Should we sent a response for this PUT yet?
   */
  int ready;

  /**
   * Have we sent a response for this PUT yet?
   */
  int done;

};

/**
 * Server-side data for a GET request.
 */
struct MHDGetData
{

  /**
   * This is a linked list.
   */
  struct MHDGetData *next;

  /**
   * MHD connection handle for this request.
   */
  struct MHD_Connection *session;

  /**
   * GET session response handle
   */
  struct MHD_Response *get;

  /**
   * My HTTP session.
   */
  struct HTTPSession *httpsession;

  /**
   * The write buffer (for sending GET response)
   */
  char *wbuff;

  /**
   * What was the last time we were able to
   * transmit data using the current get handle?
   */
  GNUNET_CronTime last_get_activity;

  /**
   * Current write position in wbuff
   */
  unsigned int woff;

  /**
   * Number of valid bytes in wbuff (starting at woff)
   */
  unsigned int wpos;

  /**
   * Size of the write buffer.
   */
  unsigned int wsize;

};

/**
 * Transport Session handle.
 */
typedef struct HTTPSession
{

  /**
   * GNUNET_TSession for this session.
   */
  GNUNET_TSession *tsession;

  /**
   * To whom are we talking to.
   */
  GNUNET_PeerIdentity sender;

  /**
   * number of users of this session
   */
  unsigned int users;

  /**
   * Has this session been destroyed?
   */
  int destroyed;

  /**
   * Are we client or server?  Determines which of the
   * structs in the union below is being used for this
   * connection!
   */
  int is_client;

  /**
   * Is MHD still using this session handle?
   */
  int is_mhd_active;

  /**
   * Data maintained for the http client-server connection
   * (depends on if we are client or server).
   */
  union
  {

    struct
    {
      /**
       * Active PUT requests (linked list).
       */
      struct MHDPutData *puts;

#if DO_GET
      /**
       * Active GET requests (linked list; most
       * recent received GET is the head of the list).
       */
      struct MHDGetData *gets;
#endif

    } server;

    struct
    {

      /**
       * Address of the other peer.
       */
      HostAddress address;

#if DO_GET
      /**
       * Last time the GET was active.
       */
      GNUNET_CronTime last_get_activity;

      /**
       * What was the last time we were able to
       * transmit data using the current get handle?
       */
      GNUNET_CronTime last_get_initiated;

      /**
       * GET operation
       */
      CURL *get;

      /**
       * Read buffer for the header (from GET).
       */
      char rbuff1[sizeof (GNUNET_MessageHeader)];

      /**
       * The read buffer (used only receiving GET data).
       */
      char *rbuff2;

      /**
       * Number of valid bytes in rbuff1
       */
      unsigned int rpos1;

      /**
       * Number of valid bytes in rbuff2
       */
      unsigned int rpos2;

      /**
       * Current size of the read buffer rbuff2.
       */
      unsigned int rsize2;
#endif

      /**
       * URL of the get and put operations.
       */
      char *url;

      /**
       * Linked list of PUT operations.
       */
      struct HTTPPutData *puts;

    } client;

  } cs;

} HTTPSession;

/* *********** globals ************* */

static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;

static int stat_get_issued;

static int stat_get_received;

static int stat_put_issued;

static int stat_put_received;

static int stat_select_calls;

static int stat_send_calls;

static int stat_connect_calls;

static int stat_curl_send_callbacks;

static int stat_curl_receive_callbacks;

static int stat_mhd_access_callbacks;

static int stat_mhd_read_callbacks;

static int stat_mhd_close_callbacks;

static int stat_connect_calls;

/**
 * How many requests do we have currently pending
 * (with libcurl)?
 */
static unsigned int http_requests_pending;

static int signal_pipe[2];

static char *proxy;

/**
 * Daemon for listening for new connections.
 */
static struct MHD_Daemon *mhd_daemon;

/**
 * Curl multi for managing client operations.
 */
static CURLM *curl_multi;

/**
 * Set to GNUNET_YES while the transport is running.
 */
static int http_running;

/**
 * Thread running libcurl activities.
 */
static struct GNUNET_ThreadHandle *curl_thread;

/**
 * Array of currently active HTTP sessions.
 */
static GNUNET_TSession **tsessions;

/**
 * Number of valid entries in tsessions.
 */
static unsigned int tsessionCount;

/**
 * Sie of the tsessions array.
 */
static unsigned int tsessionArrayLength;

/**
 * Lock for concurrent access to all structures used
 * by http, including CURL.
 */
static struct GNUNET_Mutex *lock;


/**
 * Signal select thread that its selector
 * set may have changed.
 */
static void
signal_select ()
{
  static char c;
  WRITE (signal_pipe[1], &c, sizeof (c));
}

/**
 * Check if we are allowed to connect to the given IP.
 */
static int
acceptPolicyCallback (void *cls,
                      const struct sockaddr *addr, socklen_t addr_len)
{
  if (GNUNET_NO != is_rejected_tester (addr, addr_len))
    return MHD_NO;
  return MHD_YES;
}

/**
 * Disconnect from a remote node. May only be called
 * on sessions that were acquired by the caller first.
 * For the core, aquiration means to call associate or
 * connect. The number of disconnects must match the
 * number of calls to connect+associate.
 *
 * Sessions are actually discarded in cleanup_connections.
 *
 *
 * @param tsession the session that is closed
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
httpDisconnect (GNUNET_TSession * tsession)
{
  HTTPSession *httpsession = tsession->internal;
  if (httpsession == NULL)
    {
      GNUNET_free (tsession);
      return GNUNET_OK;
    }
  GNUNET_mutex_lock (lock);
  httpsession->users--;
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

static void
destroy_tsession (GNUNET_TSession * tsession)
{
  HTTPSession *httpsession = tsession->internal;
  struct HTTPPutData *pos;
  struct HTTPPutData *next;
#if DO_GET
  struct MHDGetData *gpos;
  struct MHDGetData *gnext;
#endif
  struct MHD_Response *r;
  int i;

  GNUNET_mutex_lock (lock);
  for (i = 0; i < tsessionCount; i++)
    {
      if (tsessions[i] == tsession)
        {
          tsessions[i] = tsessions[--tsessionCount];
          break;
        }
    }
  if (httpsession->is_client)
    {
#if DO_GET
      curl_multi_remove_handle (curl_multi, httpsession->cs.client.get);
      http_requests_pending--;
      signal_select ();
      curl_easy_cleanup (httpsession->cs.client.get);
      GNUNET_array_grow (httpsession->cs.client.rbuff2,
                         httpsession->cs.client.rsize2, 0);
#endif
      GNUNET_free_non_null (httpsession->cs.client.url);
      pos = httpsession->cs.client.puts;
      while (pos != NULL)
        {
          next = pos->next;
          curl_multi_remove_handle (curl_multi, pos->curl_put);
          http_requests_pending--;
          signal_select ();
          curl_easy_cleanup (pos->curl_put);
          GNUNET_free (pos->msg);
          GNUNET_free (pos);
          pos = next;
        }
      GNUNET_free (httpsession);
      GNUNET_free (tsession);
    }
  else
    {
      httpsession->destroyed = GNUNET_YES;
      GNUNET_GE_BREAK (NULL, httpsession->cs.server.puts == NULL);
#if DO_GET
      gpos = httpsession->cs.server.gets;
      while (gpos != NULL)
        {
          GNUNET_array_grow (gpos->wbuff, gpos->wsize, 0);
          r = gpos->get;
          gpos->get = NULL;
          gnext = gpos->next;
          MHD_destroy_response (r);
          gpos = gnext;
        }
      httpsession->cs.server.gets = NULL;
#endif
      GNUNET_free (httpsession->tsession);
      GNUNET_free (httpsession);
    }
  GNUNET_mutex_unlock (lock);
}

/**
 * MHD is done handling a request.  Cleanup
 * the respective transport state.
 */
static void
requestCompletedCallback (void *unused,
                          struct MHD_Connection *session,
                          void **httpSessionCache)
{
  HTTPSession *httpsession = *httpSessionCache;
  struct MHDPutData *pprev;
  struct MHDPutData *ppos;
#if DO_GET
  struct MHDGetData *gprev;
  struct MHDGetData *gpos;
#endif

  if (stats != NULL)
    stats->change (stat_mhd_close_callbacks, 1);
  if (httpsession == NULL)
    return;                     /* oops */
  GNUNET_GE_ASSERT (NULL, !httpsession->is_client);
  pprev = NULL;
  ppos = httpsession->cs.server.puts;
  while (ppos != NULL)
    {
      if (ppos->session == session)
        {
          ppos->last_activity = 0;
          signal_select ();
          return;
        }
      pprev = ppos;
      ppos = ppos->next;
    }
#if DO_GET
  gprev = NULL;
  gpos = httpsession->cs.server.gets;
  while (gpos != NULL)
    {
      if (gpos->session == session)
        {
          gpos->last_get_activity = 0;
          signal_select ();
          return;
        }
      gprev = gpos;
      gpos = gpos->next;
    }
#endif
  httpsession->is_mhd_active--;
}

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed. Associate can also be
 * called to test if it would be possible to associate the session
 * later, in this case the argument session is NULL. This can be used
 * to test if the connection must be closed by the core or if the core
 * can assume that it is going to be self-managed (if associate
 * returns GNUNET_OK and session was NULL, the transport layer is responsible
 * for eventually freeing resources associated with the tesession). If
 * session is not NULL, the core takes responsbility for eventually
 * calling disconnect.
 *
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return GNUNET_OK if the session could be associated,
 *         GNUNET_SYSERR if not.
 */
static int
httpAssociate (GNUNET_TSession * tsession)
{
  HTTPSession *httpSession;

  if (tsession == NULL)
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  httpSession = tsession->internal;
  GNUNET_mutex_lock (lock);
  if (httpSession->destroyed == GNUNET_YES)
    {
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  httpSession->users++;
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * Add a new session to the array watched by the select thread.  Grows
 * the array if needed.  If the caller wants to do anything useful
 * with the return value, it must have the lock before
 * calling.  It is ok to call this function without holding lock if
 * the return value is ignored.
 */
static unsigned int
addTSession (GNUNET_TSession * tsession)
{
  unsigned int i;

  GNUNET_mutex_lock (lock);
  if (tsessionCount == tsessionArrayLength)
    GNUNET_array_grow (tsessions, tsessionArrayLength,
                       tsessionArrayLength * 2);
  i = tsessionCount;
  tsessions[tsessionCount++] = tsession;
  GNUNET_mutex_unlock (lock);
  return i;
}

#if DO_GET
/**
 * Callback for processing GET requests if our side is the
 * MHD HTTP server.
 *
 * @param cls the HTTP session
 * @param pos read-offset in the stream
 * @param buf where to write the data
 * @param max how much data to write (at most)
 * @return number of bytes written, 0 is allowed!
 */
static int
contentReaderCallback (void *cls, uint64_t pos, char *buf, int max)
{
  struct MHDGetData *mgd = cls;

  if (stats != NULL)
    stats->change (stat_mhd_read_callbacks, 1);
  GNUNET_mutex_lock (lock);
  if (mgd->wpos < max)
    max = mgd->wpos;
  memcpy (buf, &mgd->wbuff[mgd->woff], max);
  mgd->wpos -= max;
  mgd->woff += max;
  if (max > 0)
    mgd->last_get_activity = GNUNET_get_time ();
  if (mgd->wpos == 0)
    mgd->woff = 0;
  GNUNET_mutex_unlock (lock);
#if DEBUG_HTTP
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "HTTP returns %u bytes in MHD's GET handler.\n", max);
#endif
  if (stats != NULL)
    stats->change (stat_bytesSent, max);
  if ((max == 0) && (mgd->httpsession->cs.server.gets != mgd))
    return -1;                  /* end of response (another GET replaces this one) */
  return max;
}
#endif

#if DO_GET
/**
 * Notification that libmicrohttpd no longer needs the
 * response object.
 */
static void
contentReaderFreeCallback (void *cls)
{
  struct MHDGetData *mgd = cls;

  GNUNET_GE_ASSERT (NULL, mgd->get == NULL);
  GNUNET_array_grow (mgd->wbuff, mgd->wsize, 0);
  GNUNET_free (mgd);
}
#endif

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
  GNUNET_TSession *tsession;
  struct MHDPutData *put;
  struct MHDGetData *get;
  HTTPSession *httpSession;
  struct MHD_Response *response;
  GNUNET_HashCode client;
  int i;
  unsigned int have;
  GNUNET_MessageHeader *hdr;
  GNUNET_TransportPacket *mp;
  unsigned int cpy;
  unsigned int poff;

  if (stats != NULL)
    stats->change (stat_mhd_access_callbacks, 1);
#if DEBUG_HTTP
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "HTTP/MHD receives `%s' request.\n", method);
#endif
  /* convert URL to sender peer id */
  if ((strlen (url) < 2)
      || (GNUNET_OK != GNUNET_enc_to_hash (&url[1], &client)))
    {
      /* invalid request */
      /* GNUNET_GE_BREAK_OP (NULL, 0); -- this happens a lot, most likely
         somebody scanning for MyDoom.X-opened backdoors */
      return MHD_NO;
    }

  /* check if we already have a session for this */
  httpSession = *httpSessionCache;
  if (httpSession == NULL)
    {
      /* new http connection */
      if (stats != NULL)
        {
          if (0 == strcasecmp (MHD_HTTP_METHOD_PUT, method))
            stats->change (stat_put_received, 1);
          else
            stats->change (stat_get_received, 1);
        }
      GNUNET_mutex_lock (lock);
      for (i = 0; i < tsessionCount; i++)
        {
          tsession = tsessions[i];
          httpSession = tsession->internal;
          if ((0 ==
               memcmp (&httpSession->sender, &client,
                       sizeof (GNUNET_HashCode)))
              && (httpSession->is_client == GNUNET_NO))
            break;
          tsession = NULL;
          httpSession = NULL;
        }
      GNUNET_mutex_unlock (lock);
    }
  /* create new session if necessary */
  if (httpSession == NULL)
    {
#if DEBUG_HTTP
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "HTTP/MHD creates new session for request from `%s'.\n",
                     &url[1]);
#endif
      httpSession = GNUNET_malloc (sizeof (HTTPSession));
      memset (httpSession, 0, sizeof (HTTPSession));
      httpSession->sender.hashPubKey = client;
      httpSession->users = 0;   /* MHD */
      tsession = GNUNET_malloc (sizeof (GNUNET_TSession));
      memset (tsession, 0, sizeof (GNUNET_TSession));
      tsession->ttype = GNUNET_TRANSPORT_PROTOCOL_NUMBER_HTTP;
      tsession->internal = httpSession;
      tsession->peer.hashPubKey = client;
      httpSession->tsession = tsession;
      addTSession (tsession);
    }
  if (*httpSessionCache == NULL)
    {
      httpSession->is_mhd_active++;
      *httpSessionCache = httpSession;
    }
  GNUNET_mutex_lock (lock);
#if DO_GET
  if (0 == strcasecmp (MHD_HTTP_METHOD_GET, method))
    {
#if DEBUG_HTTP
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "HTTP/MHD receives GET request from `%s'.\n", &url[1]);
#endif

      /* handle get; create response object if we do not
         have one already */
      get = GNUNET_malloc (sizeof (struct MHDGetData));
      memset (get, 0, sizeof (struct MHDGetData));
      get->next = httpSession->cs.server.gets;
      httpSession->cs.server.gets = get;
      get->session = session;
      get->httpsession = httpSession;
      get->last_get_activity = GNUNET_get_time ();
      get->get = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN,
                                                    64 * 1024,
                                                    contentReaderCallback,
                                                    get,
                                                    contentReaderFreeCallback);
      MHD_queue_response (session, MHD_HTTP_OK, get->get);
      GNUNET_mutex_unlock (lock);
      return MHD_YES;
    }
#endif
  if (0 == strcasecmp (MHD_HTTP_METHOD_PUT, method))
    {
#if DEBUG_HTTP
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "HTTP/MHD receives PUT request from `%s' with %u bytes.\n",
                     &url[1], *upload_data_size);
#endif
      put = httpSession->cs.server.puts;
      while ((put != NULL) && (put->session != session))
        put = put->next;
      if (put == NULL)
        {
          put = GNUNET_malloc (sizeof (struct MHDPutData));
          memset (put, 0, sizeof (struct MHDPutData));
          put->next = httpSession->cs.server.puts;
          httpSession->cs.server.puts = put;
          put->session = session;
        }
      put->last_activity = GNUNET_get_time ();

      /* handle put (upload_data!) */
      poff = 0;
      have = *upload_data_size;
      if (stats != NULL)
        stats->change (stat_bytesReceived, have);
      *upload_data_size = 0;    /* we will always process everything */
      if ((have == 0) && (put->done == GNUNET_NO)
          && (put->ready == GNUNET_YES))
        {
          put->done = GNUNET_YES;
          /* end of upload, send response! */
#if DEBUG_HTTP
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "HTTP/MHD queues dummy response to completed PUT request.\n");
#endif
          response =
            MHD_create_response_from_data (strlen (HTTP_PUT_RESPONSE),
                                           HTTP_PUT_RESPONSE, MHD_NO, MHD_NO);
          MHD_queue_response (session, MHD_HTTP_OK, response);
          MHD_destroy_response (response);
          GNUNET_mutex_unlock (lock);
          return MHD_YES;
        }
      while (have > 0)
        {
          put->ready = GNUNET_NO;
          if (put->rpos1 < sizeof (GNUNET_MessageHeader))
            {
              cpy = sizeof (GNUNET_MessageHeader) - put->rpos1;
              if (cpy > have)
                cpy = have;
              memcpy (&put->rbuff1[put->rpos1], &upload_data[poff], cpy);
              put->rpos1 += cpy;
              have -= cpy;
              poff += cpy;
              put->rpos2 = 0;
            }
          if (put->rpos1 < sizeof (GNUNET_MessageHeader))
            break;
          hdr = (GNUNET_MessageHeader *) put->rbuff1;
          GNUNET_array_grow (put->rbuff2,
                             put->rsize2,
                             ntohs (hdr->size) -
                             sizeof (GNUNET_MessageHeader));
          if (put->rpos2 < ntohs (hdr->size) - sizeof (GNUNET_MessageHeader))
            {
              cpy =
                ntohs (hdr->size) - sizeof (GNUNET_MessageHeader) -
                put->rpos2;
              if (cpy > have)
                cpy = have;
              memcpy (&put->rbuff2[put->rpos2], &upload_data[poff], cpy);
              have -= cpy;
              poff += cpy;
              put->rpos2 += cpy;
            }
          if (put->rpos2 < ntohs (hdr->size) - sizeof (GNUNET_MessageHeader))
            break;
          mp = GNUNET_malloc (sizeof (GNUNET_TransportPacket));
          mp->msg = put->rbuff2;
          mp->sender = httpSession->sender;
          mp->tsession = httpSession->tsession;
          mp->size = ntohs (hdr->size) - sizeof (GNUNET_MessageHeader);
#if DEBUG_HTTP
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "HTTP/MHD passes %u bytes to core (received via PUT request).\n",
                         mp->size);
#endif
          coreAPI->receive (mp);
          put->rbuff2 = NULL;
          put->rpos2 = 0;
          put->rsize2 = 0;
          put->rpos1 = 0;
          put->ready = GNUNET_YES;
        }
      GNUNET_mutex_unlock (lock);
      return MHD_YES;
    }
  GNUNET_mutex_unlock (lock);
  GNUNET_GE_BREAK_OP (NULL, 0); /* invalid request */
  return MHD_NO;
}

#if DO_GET
/**
 * Process downloaded bits (from GET via CURL).
 */
static size_t
receiveContentCallback (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  HTTPSession *httpSession = ctx;
  const char *inbuf = ptr;
  size_t have = size * nmemb;
  size_t poff = 0;
  size_t cpy;
  GNUNET_MessageHeader *hdr;
  GNUNET_TransportPacket *mp;

  if (stats != NULL)
    stats->change (stat_curl_receive_callbacks, 1);
  httpSession->cs.client.last_get_activity = GNUNET_get_time ();
#if DEBUG_HTTP
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "HTTP/CURL receives %u bytes as response to GET.\n",
                 size * nmemb);
#endif
  while (have > 0)
    {
      if (httpSession->cs.client.rpos1 < sizeof (GNUNET_MessageHeader))
        {
          cpy = sizeof (GNUNET_MessageHeader) - httpSession->cs.client.rpos1;
          if (cpy > have)
            cpy = have;
          memcpy (&httpSession->cs.client.
                  rbuff1[httpSession->cs.client.rpos1], &inbuf[poff], cpy);
          httpSession->cs.client.rpos1 += cpy;
          have -= cpy;
          poff += cpy;
          httpSession->cs.client.rpos2 = 0;
        }
      if (httpSession->cs.client.rpos1 < sizeof (GNUNET_MessageHeader))
        break;
      hdr = (GNUNET_MessageHeader *) httpSession->cs.client.rbuff1;
      GNUNET_array_grow (httpSession->cs.client.rbuff2,
                         httpSession->cs.client.rsize2,
                         ntohs (hdr->size) - sizeof (GNUNET_MessageHeader));
      if (httpSession->cs.client.rpos2 <
          ntohs (hdr->size) - sizeof (GNUNET_MessageHeader))
        {
          cpy =
            ntohs (hdr->size) - sizeof (GNUNET_MessageHeader) -
            httpSession->cs.client.rpos2;
          if (cpy > have)
            cpy = have;
          memcpy (&httpSession->cs.client.
                  rbuff2[httpSession->cs.client.rpos2], &inbuf[poff], cpy);
          have -= cpy;
          poff += cpy;
          httpSession->cs.client.rpos2 += cpy;
        }
      if (httpSession->cs.client.rpos2 <
          ntohs (hdr->size) - sizeof (GNUNET_MessageHeader))
        break;
      mp = GNUNET_malloc (sizeof (GNUNET_TransportPacket));
      mp->msg = httpSession->cs.client.rbuff2;
      mp->sender = httpSession->sender;
      mp->tsession = httpSession->tsession;
      mp->size = ntohs (hdr->size) - sizeof (GNUNET_MessageHeader);
      coreAPI->receive (mp);
      httpSession->cs.client.rbuff2 = NULL;
      httpSession->cs.client.rpos2 = 0;
      httpSession->cs.client.rsize2 = 0;
      httpSession->cs.client.rpos1 = 0;
    }
  if (stats != NULL)
    stats->change (stat_bytesReceived, size * nmemb);
  return size * nmemb;
}
#endif

/**
 * Provide bits for upload: we're using CURL for a PUT request
 * and now need to provide data from the message we are transmitting.
 */
static size_t
sendContentCallback (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  struct HTTPPutData *put = ctx;
  size_t max = size * nmemb;

  if (stats != NULL)
    stats->change (stat_curl_send_callbacks, 1);
  put->last_activity = GNUNET_get_time ();
  if (max > put->size - put->pos)
    max = put->size - put->pos;
  memcpy (ptr, &put->msg[put->pos], max);
  put->pos += max;
#if DEBUG_HTTP
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "HTTP/CURL sends %u bytes in PUT request.\n", max);
#endif
  if (stats != NULL)
    stats->change (stat_bytesSent, max);
  return max;
}

#define CURL_EASY_SETOPT(c, a, b) do { ret = curl_easy_setopt(c, a, b); if (ret != CURLE_OK) GNUNET_GE_LOG(coreAPI->ectx, GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK, _("%s failed at %s:%d: `%s'\n"), "curl_easy_setopt", __FILE__, __LINE__, curl_easy_strerror(ret)); } while (0);
#define IP_BUF_LEN 128

static void
create_session_url (HTTPSession * httpSession)
{
  char buf[IP_BUF_LEN];
  char *url;
  GNUNET_EncName enc;
  unsigned short available;
  const char *obr;
  const char *cbr;
  const HostAddress *haddr =
    (const HostAddress *) &httpSession->cs.client.address;

  url = httpSession->cs.client.url;
  if (url == NULL)
    {
      GNUNET_hash_to_enc (&coreAPI->my_identity->hashPubKey, &enc);
      available = ntohs (haddr->availability) & available_protocols;
      if (available == (VERSION_AVAILABLE_IPV4 | VERSION_AVAILABLE_IPV6))
        {
          if (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 2) == 0)
            available = VERSION_AVAILABLE_IPV4;
          else
            available = VERSION_AVAILABLE_IPV6;
        }
      if ((available & VERSION_AVAILABLE_IPV4) > 0)
        {
          if (NULL == inet_ntop (AF_INET, &haddr->ipv4, buf, IP_BUF_LEN))
            {
              /* log? */
              return;
            }
          obr = "";
          cbr = "";
        }
      else if ((available & VERSION_AVAILABLE_IPV6) > 0)
        {
          if (NULL == inet_ntop (AF_INET6, &haddr->ipv6, buf, IP_BUF_LEN))
            {
              /* log? */
              return;
            }
          obr = "[";
          cbr = "]";
        }
      else
        return;                 /* error */
      url = GNUNET_malloc (64 + sizeof (GNUNET_EncName) + strlen (buf));
      GNUNET_snprintf (url,
                       64 + sizeof (GNUNET_EncName),
                       "http://%s%s%s:%u/%s", obr, buf, cbr,
                       ntohs (haddr->port), &enc);
      httpSession->cs.client.url = url;
    }
}

#if DO_GET
/**
 * Try to do a GET on the other peer of the given
 * http session.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
create_curl_get (HTTPSession * httpSession)
{
  CURL *curl_get;
  CURLcode ret;
  CURLMcode mret;
  GNUNET_CronTime now;

  if (httpSession->cs.client.url == NULL)
    return GNUNET_SYSERR;
  curl_get = httpSession->cs.client.get;
  if (curl_get != NULL)
    {
      GNUNET_mutex_lock (lock);
      curl_multi_remove_handle (curl_multi, curl_get);
      http_requests_pending--;
      signal_select ();
      curl_easy_cleanup (curl_get);
      GNUNET_mutex_unlock (lock);
      httpSession->cs.client.get = NULL;
    }
  curl_get = curl_easy_init ();
  if (curl_get == NULL)
    return GNUNET_SYSERR;
  /* create GET */
  CURL_EASY_SETOPT (curl_get, CURLOPT_FAILONERROR, 1);
  CURL_EASY_SETOPT (curl_get, CURLOPT_URL, httpSession->cs.client.url);
  if (strlen (proxy) > 0)
    CURL_EASY_SETOPT (curl_get, CURLOPT_PROXY, proxy);
  CURL_EASY_SETOPT (curl_get, CURLOPT_BUFFERSIZE, 32 * 1024);
  if (0 == strncmp (httpSession->cs.client.url, "http", 4))
    CURL_EASY_SETOPT (curl_get, CURLOPT_USERAGENT, "GNUnet-http");
#if 0
  CURL_EASY_SETOPT (curl_get, CURLOPT_VERBOSE, 1);
#endif
  CURL_EASY_SETOPT (curl_get, CURLOPT_CONNECTTIMEOUT, 150L);
  /* NOTE: use of CONNECTTIMEOUT without also
     setting NOSIGNAL results in really weird
     crashes on my system! */
  CURL_EASY_SETOPT (curl_get, CURLOPT_NOSIGNAL, 1);
  CURL_EASY_SETOPT (curl_get, CURLOPT_TIMEOUT, 150L);
  CURL_EASY_SETOPT (curl_get, CURLOPT_WRITEFUNCTION, &receiveContentCallback);
  CURL_EASY_SETOPT (curl_get, CURLOPT_WRITEDATA, httpSession);
  CURL_EASY_SETOPT (curl_get, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  if (ret != CURLE_OK)
    {
      curl_easy_cleanup (curl_get);
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_lock (lock);
  mret = curl_multi_add_handle (curl_multi, curl_get);
  http_requests_pending++;
  GNUNET_mutex_unlock (lock);
  if (stats != NULL)
    stats->change (stat_get_issued, 1);
  if (mret != CURLM_OK)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK, _("%s failed at %s:%d: `%s'\n"),
                     "curl_multi_add_handle", __FILE__, __LINE__,
                     curl_multi_strerror (mret));
      curl_easy_cleanup (curl_get);
      return GNUNET_SYSERR;
    }
  signal_select ();
  now = GNUNET_get_time ();
  httpSession->cs.client.last_get_activity = now;
  httpSession->cs.client.get = curl_get;
  httpSession->cs.client.last_get_initiated = now;
#if DEBUG_HTTP
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "HTTP/CURL initiated GET request.\n");
#endif
  return GNUNET_OK;
}
#endif

/**
 * Establish a connection to a remote node.
 *
 * @param hello the hello-Message for the target node
 * @param tsessionPtr the session handle that is set
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
httpConnect (const GNUNET_MessageHello * hello,
             GNUNET_TSession ** tsessionPtr, int may_reuse)
{
  const HostAddress *haddr = (const HostAddress *) &hello[1];
  GNUNET_TSession *tsession;
  HTTPSession *httpSession;
  int i;

  if (stats != NULL)
    stats->change (stat_connect_calls, 1);
  /* check if we have a session pending for this peer */
  tsession = NULL;
  if (may_reuse)
    {
      GNUNET_mutex_lock (lock);
      for (i = 0; i < tsessionCount; i++)
        {
          if (0 == memcmp (&hello->senderIdentity,
                           &tsessions[i]->peer, sizeof (GNUNET_PeerIdentity)))
            {
              tsession = tsessions[i];
              break;
            }
        }
      if ((tsession != NULL) && (GNUNET_OK == httpAssociate (tsession)))
        {
          *tsessionPtr = tsession;
          GNUNET_mutex_unlock (lock);
          return GNUNET_OK;
        }
      GNUNET_mutex_unlock (lock);
    }
  /* no session pending, initiate a new one! */
  httpSession = GNUNET_malloc (sizeof (HTTPSession));
  memset (httpSession, 0, sizeof (HTTPSession));
  httpSession->sender = hello->senderIdentity;
  httpSession->users = 1;       /* us only, core has not seen this tsession! */
  httpSession->is_client = GNUNET_YES;
  httpSession->cs.client.address = *haddr;
  tsession = GNUNET_malloc (sizeof (GNUNET_TSession));
  memset (tsession, 0, sizeof (GNUNET_TSession));
  httpSession->tsession = tsession;
  tsession->ttype = GNUNET_TRANSPORT_PROTOCOL_NUMBER_HTTP;
  tsession->internal = httpSession;
  tsession->peer = hello->senderIdentity;
  create_session_url (httpSession);
#if DO_GET
  if (GNUNET_OK != create_curl_get (httpSession))
    {
      GNUNET_free (tsession);
      GNUNET_free (httpSession);
      return GNUNET_SYSERR;
    }
#endif
  /* PUTs will be created as needed */
  addTSession (tsession);
  *tsessionPtr = tsession;
#if DEBUG_HTTP
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "HTTP/CURL initiated connection to `%s'.\n",
                 httpSession->cs.client.url);
#endif
  return GNUNET_OK;
}

/**
 * We received the "Thank you!" response to a PUT.
 * Discard the data (not useful) and mark the PUT
 * operation as completed.
 */
static size_t
discardContentCallback (void *data, size_t size, size_t nmemb, void *put_cls)
{
  struct HTTPPutData *put = put_cls;
  /* this condition should pretty much always be
     true; just checking here in case the PUT
     response comes early somehow */
  if (put->pos == put->size)
    put->done = GNUNET_YES;
  return size * nmemb;
}

/**
 * Create a new PUT request for the given PUT data.
 */
static int
create_curl_put (HTTPSession * httpSession, struct HTTPPutData *put)
{
  CURL *curl_put;
  CURLcode ret;
  CURLMcode mret;
  long size;

  /* we should have initiated a GET earlier,
     so URL must not be NULL here */
  if (httpSession->cs.client.url == NULL)
    return GNUNET_SYSERR;
  curl_put = curl_easy_init ();
  if (curl_put == NULL)
    return GNUNET_SYSERR;
  CURL_EASY_SETOPT (curl_put, CURLOPT_FAILONERROR, 1);
  CURL_EASY_SETOPT (curl_put, CURLOPT_URL, httpSession->cs.client.url);
  if (strlen (proxy) > 0)
    CURL_EASY_SETOPT (curl_put, CURLOPT_PROXY, proxy);
  CURL_EASY_SETOPT (curl_put, CURLOPT_BUFFERSIZE, put->size);
  if (0 == strncmp (httpSession->cs.client.url, "http", 4))
    CURL_EASY_SETOPT (curl_put, CURLOPT_USERAGENT, "GNUnet-http");
  CURL_EASY_SETOPT (curl_put, CURLOPT_UPLOAD, 1);
#if 0
  CURL_EASY_SETOPT (curl_put, CURLOPT_VERBOSE, 1);
#endif
  CURL_EASY_SETOPT (curl_put, CURLOPT_CONNECTTIMEOUT, 150L);
  /* NOTE: use of CONNECTTIMEOUT without also
     setting NOSIGNAL results in really weird
     crashes on my system! */
  CURL_EASY_SETOPT (curl_put, CURLOPT_NOSIGNAL, 1);
  CURL_EASY_SETOPT (curl_put, CURLOPT_TIMEOUT, 150L);
  size = put->size;
  CURL_EASY_SETOPT (curl_put, CURLOPT_INFILESIZE, size);
  CURL_EASY_SETOPT (curl_put, CURLOPT_READFUNCTION, &sendContentCallback);
  CURL_EASY_SETOPT (curl_put, CURLOPT_READDATA, put);
  CURL_EASY_SETOPT (curl_put, CURLOPT_WRITEFUNCTION, &discardContentCallback);
  CURL_EASY_SETOPT (curl_put, CURLOPT_WRITEDATA, put);
  CURL_EASY_SETOPT (curl_put, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  if (ret != CURLE_OK)
    {
      curl_easy_cleanup (curl_put);
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_lock (lock);
  mret = curl_multi_add_handle (curl_multi, curl_put);
  http_requests_pending++;
  GNUNET_mutex_unlock (lock);
  if (stats != NULL)
    stats->change (stat_put_issued, 1);
  if (mret != CURLM_OK)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK, _("%s failed at %s:%d: `%s'\n"),
                     "curl_multi_add_handle", __FILE__, __LINE__,
                     curl_multi_strerror (mret));
      return GNUNET_SYSERR;
    }
  signal_select ();
  put->curl_put = curl_put;
#if DEBUG_HTTP
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "HTTP/CURL initiated PUT request to `%s'.\n",
                 httpSession->cs.client.url);
#endif
  return GNUNET_OK;
}


/**
 * Test if the transport would even try to send
 * a message of the given size and importance
 * for the given session.<br>
 * This function is used to check if the core should
 * even bother to construct (and encrypt) this kind
 * of message.
 *
 * @return GNUNET_YES if the transport would try (i.e. queue
 *         the message or call the OS to send),
 *         GNUNET_NO if the transport would just drop the message,
 *         GNUNET_SYSERR if the size/session is invalid
 */
static int
httpTestWouldTry (GNUNET_TSession * tsession, const unsigned int size,
                  int important)
{
  HTTPSession *httpSession = tsession->internal;
  struct MHDGetData *get;
  int ret;

  if (size >= GNUNET_MAX_BUFFER_SIZE - sizeof (GNUNET_MessageHeader))
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return GNUNET_SYSERR;
    }
  if (size == 0)
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return GNUNET_SYSERR;
    }
  if (httpSession->is_client)
    {
      /* client */
      if ((important != GNUNET_YES) && (httpSession->cs.client.puts != NULL))
        return GNUNET_NO;
      return GNUNET_YES;
    }
  else
    {
      /* server */
      GNUNET_mutex_lock (lock);
      get = httpSession->cs.server.gets;
      if (get == NULL)
        ret = GNUNET_NO;
      else
        {
          if (get->wsize == 0)
            ret = GNUNET_YES;
          else if ((get->wpos + size > get->wsize)
                   && (important != GNUNET_YES))
            ret = GNUNET_NO;
          else
            ret = GNUNET_YES;
        }
      GNUNET_mutex_unlock (lock);
      return ret;
    }
}


/**
 * Send a message to the specified remote node.
 *
 * @param tsession the GNUNET_MessageHello identifying the remote node
 * @param msg the message
 * @param size the size of the message
 * @return GNUNET_SYSERR on error, GNUNET_OK on success, GNUNET_NO if queue is full
 */
static int
httpSend (GNUNET_TSession * tsession,
          const void *msg, unsigned int size, int important)
{
  HTTPSession *httpSession = tsession->internal;
  struct HTTPPutData *putData;
  GNUNET_MessageHeader *hdr;
#if DO_GET
  struct MHDGetData *getData;
  char *tmp;
#endif

  if (stats != NULL)
    stats->change (stat_send_calls, 1);
  if (httpSession->is_client)
    {
      /* we need to do a PUT (we are the client) */
      if (size >= GNUNET_MAX_BUFFER_SIZE)
        return GNUNET_SYSERR;
      if (size == 0)
        {
          GNUNET_GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
      if (important != GNUNET_YES)
        {
          GNUNET_mutex_lock (lock);
          if (httpSession->cs.client.puts != NULL)
            {
              /* do not queue more than one unimportant PUT at a time */
              signal_select (); /* do clean up now! */
              GNUNET_mutex_unlock (lock);
              if (stats != NULL)
                stats->change (stat_bytesDropped, size);

              return GNUNET_NO;
            }
          GNUNET_mutex_unlock (lock);
        }
      putData = GNUNET_malloc (sizeof (struct HTTPPutData));
      memset (putData, 0, sizeof (struct HTTPPutData));
      putData->msg = GNUNET_malloc (size + sizeof (GNUNET_MessageHeader));
      hdr = (GNUNET_MessageHeader *) putData->msg;
      hdr->size = htons (size + sizeof (GNUNET_MessageHeader));
      hdr->type = htons (0);
      memcpy (&putData->msg[sizeof (GNUNET_MessageHeader)], msg, size);
      putData->size = size + sizeof (GNUNET_MessageHeader);
      putData->last_activity = GNUNET_get_time ();
      if (GNUNET_OK != create_curl_put (httpSession, putData))
        {
          GNUNET_free (putData->msg);
          GNUNET_free (putData);
          return GNUNET_SYSERR;
        }
      GNUNET_mutex_lock (lock);
      putData->next = httpSession->cs.client.puts;
      httpSession->cs.client.puts = putData;
      GNUNET_mutex_unlock (lock);
      return GNUNET_OK;
    }

  /* httpSession->isClient == false, respond to a GET (we
     hopefully have one or will have one soon) */
#if DEBUG_HTTP
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "HTTP/MHD queues %u bytes to be sent as response to GET as soon as possible.\n",
                 size);
#endif
#if DO_GET
  GNUNET_mutex_lock (lock);
  getData = httpSession->cs.server.gets;
  if (getData == NULL)
    {
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if (getData->wsize == 0)
    GNUNET_array_grow (getData->wbuff, getData->wsize, HTTP_BUF_SIZE);
  size += sizeof (GNUNET_MessageHeader);
  if (getData->wpos + size > getData->wsize)
    {
      /* need to grow or discard */
      if (!important)
        {
          GNUNET_mutex_unlock (lock);
          return GNUNET_NO;
        }
      tmp = GNUNET_malloc (getData->wpos + size);
      memcpy (tmp, &getData->wbuff[getData->woff], getData->wpos);
      hdr = (GNUNET_MessageHeader *) & tmp[getData->wpos];
      hdr->type = htons (0);
      hdr->size = htons (size);
      memcpy (&hdr[1], msg, size - sizeof (GNUNET_MessageHeader));
      GNUNET_free (getData->wbuff);
      getData->wbuff = tmp;
      getData->wsize = getData->wpos + size;
      getData->woff = 0;
      getData->wpos = getData->wpos + size;
    }
  else
    {
      /* fits without growing */
      if (getData->wpos + getData->woff + size > getData->wsize)
        {
          /* need to compact first */
          memmove (getData->wbuff,
                   &getData->wbuff[getData->woff], getData->wpos);
          getData->woff = 0;
        }
      /* append */
      hdr =
        (GNUNET_MessageHeader *) & getData->wbuff[getData->woff +
                                                  getData->wpos];
      hdr->size = htons (size);
      hdr->type = htons (0);
      memcpy (&hdr[1], msg, size - sizeof (GNUNET_MessageHeader));
      getData->wpos += size;
    }
  signal_select ();
  GNUNET_mutex_unlock (lock);
#endif
  return GNUNET_OK;
}

/**
 * Function called to cleanup dead connections
 * (completed PUTs, GETs that have timed out,
 * etc.).  Also re-vives GETs that have timed out
 * if we are still interested in the connection.
 */
static void
cleanup_connections ()
{
  int i;
  HTTPSession *s;
  struct HTTPPutData *prev;
  struct HTTPPutData *pos;
  struct MHDPutData *mpos;
  struct MHDPutData *mprev;
#if DO_GET
  struct MHD_Response *r;
  struct MHDGetData *gpos;
  struct MHDGetData *gnext;
#endif
  GNUNET_CronTime now;

  GNUNET_mutex_lock (lock);
  now = GNUNET_get_time ();
  for (i = 0; i < tsessionCount; i++)
    {
      s = tsessions[i]->internal;
      if (s->is_client)
        {
          if ((s->cs.client.puts == NULL) && (s->users == 0)
#if DO_GET
              && (s->cs.client.last_get_activity + HTTP_TIMEOUT < now)
#endif
            )
            {
#if DO_GET
#if DEBUG_HTTP
              GNUNET_GE_LOG (coreAPI->ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                             GNUNET_GE_USER,
                             "HTTP transport destroys old (%llu ms) unused client session\n",
                             now - s->cs.client.last_get_activity);
#endif
#endif
              destroy_tsession (tsessions[i]);
              i--;
              continue;
            }

          prev = NULL;
          pos = s->cs.client.puts;
          while (pos != NULL)
            {
              if (pos->last_activity + HTTP_TIMEOUT < now)
                pos->done = GNUNET_YES;
              if (pos->done)
                {
                  if (prev == NULL)
                    s->cs.client.puts = pos->next;
                  else
                    prev->next = pos->next;
                  GNUNET_free (pos->msg);
                  curl_multi_remove_handle (curl_multi, pos->curl_put);
                  http_requests_pending--;
                  signal_select ();
                  curl_easy_cleanup (pos->curl_put);
                  GNUNET_free (pos);
                  if (prev == NULL)
                    pos = s->cs.client.puts;
                  else
                    pos = prev->next;
                  continue;
                }
              prev = pos;
              pos = pos->next;
            }
#if DO_GET
          if ((s->cs.client.last_get_activity + HTTP_TIMEOUT < now) &&
              ((s->users > 0) || (s->cs.client.puts != NULL)) &&
              ((s->cs.client.last_get_initiated + HTTP_GET_REFRESH > now) ||
               (s->cs.client.get == NULL)) &&
              ((s->cs.client.get == NULL) ||
               (s->cs.client.last_get_activity + HTTP_GET_REFRESH / 2 < now)))
            create_curl_get (s);
#endif
        }
      else
        {
          mpos = s->cs.server.puts;
          mprev = NULL;
          while (mpos != NULL)
            {
              if (mpos->last_activity == 0)
                {
                  if (mprev == NULL)
                    s->cs.server.puts = mpos->next;
                  else
                    mprev->next = mpos->next;
                  GNUNET_array_grow (mpos->rbuff2, mpos->rsize2, 0);
                  GNUNET_free (mpos);
                  if (mprev == NULL)
                    mpos = s->cs.server.puts;
                  else
                    mpos = mprev->next;
                  continue;
                }
              mprev = mpos;
              mpos = mpos->next;
            }

          /* ! s->is_client */
#if DO_GET
          gpos = s->cs.server.gets;
          while (gpos != NULL)
            {
              gnext = gpos->next;
              gpos->next = NULL;
              if ((gpos->last_get_activity + HTTP_TIMEOUT < now) ||
                  (gpos != s->cs.server.gets))
                {
                  if (gpos == s->cs.server.gets)
                    s->cs.server.gets = NULL;
                  r = gpos->get;
                  gpos->get = NULL;
                  MHD_destroy_response (r);
                }
              gpos = gnext;
            }
#endif
          if (
#if DO_GET
               (s->cs.server.gets == NULL) &&
#endif
               (s->is_mhd_active == 0) && (s->users == 0))
            {
#if DO_GET
#if DEBUG_HTTP
              GNUNET_GE_LOG (coreAPI->ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                             GNUNET_GE_USER,
                             "HTTP transport destroys unused server session\n");
#endif
#endif
              destroy_tsession (tsessions[i]);
              i--;
              continue;
            }
        }
    }
  GNUNET_mutex_unlock (lock);
}

/**
 * Thread that runs the CURL and MHD requests.
 */
static void *
curl_runner (void *unused)
{
  CURLMcode mret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct timeval tv;
  int running;
  unsigned long long timeout;
  long ms;
  int have_tv;
  char buf[128];                /* for reading from pipe */
  int ret;

#if DEBUG_HTTP
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "HTTP transport select thread started\n");
#endif
  while (GNUNET_YES == http_running)
    {
      max = 0;
      FD_ZERO (&rs);
      FD_ZERO (&ws);
      FD_ZERO (&es);
      GNUNET_mutex_lock (lock);
      mret = curl_multi_fdset (curl_multi, &rs, &ws, &es, &max);
      GNUNET_mutex_unlock (lock);
      if (mret != CURLM_OK)
        {
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                         GNUNET_GE_BULK, _("%s failed at %s:%d: `%s'\n"),
                         "curl_multi_fdset", __FILE__, __LINE__,
                         curl_multi_strerror (mret));
          break;
        }
      if (mhd_daemon != NULL)
        MHD_get_fdset (mhd_daemon, &rs, &ws, &es, &max);
      timeout = 0;
      have_tv = MHD_NO;
      if (mhd_daemon != NULL)
        have_tv = MHD_get_timeout (mhd_daemon, &timeout);
      GNUNET_mutex_lock (lock);
      if ((CURLM_OK == curl_multi_timeout (curl_multi, &ms)) &&
          (ms != -1) && ((ms < timeout) || (have_tv == MHD_NO)))
        {
          timeout = ms;
          have_tv = MHD_YES;
        }
      GNUNET_mutex_unlock (lock);
      FD_SET (signal_pipe[0], &rs);
      if (max < signal_pipe[0])
        max = signal_pipe[0];
      tv.tv_sec = timeout / 1000;
      tv.tv_usec = (timeout % 1000) * 1000;
      if (stats != NULL)
        stats->change (stat_select_calls, 1);
      ret =
        SELECT (max + 1, &rs, &ws, &es, (have_tv == MHD_YES) ? &tv : NULL);
      if (ret == -1)
        {
          GNUNET_GE_LOG_STRERROR (coreAPI->ectx,
                                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                  GNUNET_GE_DEVELOPER, "select");
        }
      if (GNUNET_YES != http_running)
        break;
      running = 0;
      do
        {
          GNUNET_mutex_lock (lock);
          mret = curl_multi_perform (curl_multi, &running);
          GNUNET_mutex_unlock (lock);
        }
      while ((mret == CURLM_CALL_MULTI_PERFORM)
             && (http_running == GNUNET_YES));
      if (FD_ISSET (signal_pipe[0], &rs))
        read (signal_pipe[0], buf, sizeof (buf));
      if ((mret != CURLM_OK) && (mret != CURLM_CALL_MULTI_PERFORM))
        GNUNET_GE_LOG (coreAPI->ectx,
                       GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                       GNUNET_GE_BULK, _("%s failed at %s:%d: `%s'\n"),
                       "curl_multi_perform", __FILE__, __LINE__,
                       curl_multi_strerror (mret));
      if (mhd_daemon != NULL)
        MHD_run (mhd_daemon);
      cleanup_connections ();
    }
#if DEBUG_HTTP
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "HTTP transport select thread exits.\n");
#endif
  return NULL;
}


/**
 * Start the server process to receive inbound traffic.
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
startTransportServer ()
{
  unsigned short port;

  if ((curl_multi != NULL) || (http_running == GNUNET_YES))
    return GNUNET_SYSERR;
  curl_multi = curl_multi_init ();
  if (curl_multi == NULL)
    return GNUNET_SYSERR;
  port = get_port ();
  if ((mhd_daemon == NULL) && (port != 0))
    {
      if (GNUNET_YES !=
          GNUNET_GC_get_configuration_value_yesno (cfg, "GNUNETD",
                                                   "DISABLE-IPV6",
                                                   GNUNET_YES))
        {
          mhd_daemon = MHD_start_daemon (MHD_USE_IPv6,
                                         port,
                                         &acceptPolicyCallback,
                                         NULL, &accessHandlerCallback, NULL,
                                         MHD_OPTION_CONNECTION_TIMEOUT,
                                         (unsigned int) HTTP_TIMEOUT,
                                         MHD_OPTION_CONNECTION_MEMORY_LIMIT,
                                         (unsigned int) 1024 * 128,
                                         MHD_OPTION_CONNECTION_LIMIT,
                                         (unsigned int) 128,
                                         MHD_OPTION_PER_IP_CONNECTION_LIMIT,
                                         (unsigned int) 8,
                                         MHD_OPTION_NOTIFY_COMPLETED,
                                         &requestCompletedCallback, NULL,
                                         MHD_OPTION_END);
        }
      if (mhd_daemon == NULL)
        {
          /* try without IPv6 */
          mhd_daemon = MHD_start_daemon (MHD_NO_FLAG,
                                         port,
                                         &acceptPolicyCallback,
                                         NULL, &accessHandlerCallback, NULL,
                                         MHD_OPTION_CONNECTION_TIMEOUT,
                                         (unsigned int) HTTP_TIMEOUT,
                                         MHD_OPTION_CONNECTION_MEMORY_LIMIT,
                                         (unsigned int) 1024 * 128,
                                         MHD_OPTION_CONNECTION_LIMIT,
                                         (unsigned int) 128,
                                         MHD_OPTION_PER_IP_CONNECTION_LIMIT,
                                         (unsigned int) 8,
                                         MHD_OPTION_NOTIFY_COMPLETED,
                                         &requestCompletedCallback, NULL,
                                         MHD_OPTION_END);
        }
      else
        {
          available_protocols |= VERSION_AVAILABLE_IPV6;
        }
      if (mhd_daemon != NULL)
        available_protocols |= VERSION_AVAILABLE_IPV4;
    }
  if (port == 0)
    {
      /* NAT */
      available_protocols |= VERSION_AVAILABLE_IPV4;
      if (GNUNET_YES !=
          GNUNET_GC_get_configuration_value_yesno (cfg, "GNUNETD",
                                                   "DISABLE-IPV6",
                                                   GNUNET_YES))
        available_protocols |= VERSION_AVAILABLE_IPV6;
    }
  if (0 != PIPE (signal_pipe))
    {
      MHD_stop_daemon (mhd_daemon);
      curl_multi_cleanup (curl_multi);
      curl_multi = NULL;
      mhd_daemon = NULL;
      return GNUNET_SYSERR;
    }
  GNUNET_pipe_make_nonblocking (coreAPI->ectx, signal_pipe[0]);
  GNUNET_pipe_make_nonblocking (coreAPI->ectx, signal_pipe[1]);
  http_running = GNUNET_YES;
  curl_thread = GNUNET_thread_create (&curl_runner, NULL, 32 * 1024);
  if (curl_thread == NULL)
    GNUNET_GE_DIE_STRERROR (coreAPI->ectx,
                            GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                            GNUNET_GE_IMMEDIATE, "pthread_create");
  return GNUNET_OK;
}

/**
 * Shutdown the server process (stop receiving inbound
 * traffic). May be restarted later!
 */
static int
stopTransportServer ()
{
  void *unused;
  int i;
  HTTPSession *s;

  if ((http_running == GNUNET_NO) || (curl_multi == NULL))
    return GNUNET_SYSERR;
  http_running = GNUNET_NO;
  signal_select ();
  GNUNET_thread_stop_sleep (curl_thread);
  GNUNET_thread_join (curl_thread, &unused);
  CLOSE (signal_pipe[0]);
  CLOSE (signal_pipe[1]);
  if (mhd_daemon != NULL)
    {
      MHD_stop_daemon (mhd_daemon);
      mhd_daemon = NULL;
    }
  cleanup_connections ();
  for (i = 0; i < tsessionCount; i++)
    {
      s = tsessions[i]->internal;
      if (s->users == 0)
        {
          destroy_tsession (tsessions[i]);
          i--;
        }
    }
  curl_multi_cleanup (curl_multi);
  curl_multi = NULL;
  return GNUNET_OK;
}

/* ******************** public API ******************** */

/**
 * The exported method. Makes the core api available
 * via a global and returns the udp transport API.
 */
GNUNET_TransportAPI *
inittransport_http (GNUNET_CoreAPIForTransport * core)
{
  GNUNET_GE_ASSERT (coreAPI->ectx, sizeof (HostAddress) == 24);
  coreAPI = core;
  cfg = coreAPI->cfg;
  lock = GNUNET_mutex_create (GNUNET_YES);
  if (0 != GNUNET_GC_attach_change_listener (coreAPI->cfg,
                                             &reload_configuration, NULL))
    {
      GNUNET_mutex_destroy (lock);
      lock = NULL;
      return NULL;
    }
  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_GC_detach_change_listener (coreAPI->cfg, &reload_configuration,
                                        NULL);
      GNUNET_mutex_destroy (lock);
      lock = NULL;
      return NULL;
    }
  tsessionCount = 0;
  tsessionArrayLength = 0;
  GNUNET_array_grow (tsessions, tsessionArrayLength, 32);
  if (GNUNET_GC_get_configuration_value_yesno (coreAPI->cfg,
                                               "HTTP", "UPNP",
                                               GNUNET_YES) == GNUNET_YES)
    {
      upnp = coreAPI->service_request ("upnp");

      if (upnp == NULL)
        {
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_USER |
                         GNUNET_GE_IMMEDIATE,
                         _
                         ("The UPnP service could not be loaded. To disable UPnP, set the "
                          "configuration option \"UPNP\" in section \"%s\" to \"NO\"\n"),
                         "HTTP");
        }
    }
  stats = coreAPI->service_request ("stats");
  if (stats != NULL)
    {
      stat_bytesReceived
        = stats->create (gettext_noop ("# bytes received via HTTP"));
      stat_bytesSent = stats->create (gettext_noop ("# bytes sent via HTTP"));
      stat_bytesDropped
        = stats->create (gettext_noop ("# bytes dropped by HTTP (outgoing)"));
      stat_get_issued = stats->create (gettext_noop ("# HTTP GET issued"));
      stat_get_received
        = stats->create (gettext_noop ("# HTTP GET received"));
      stat_put_issued = stats->create (gettext_noop ("# HTTP PUT issued"));
      stat_put_received
        = stats->create (gettext_noop ("# HTTP PUT received"));
      stat_select_calls
        = stats->create (gettext_noop ("# HTTP select calls"));

      stat_send_calls = stats->create (gettext_noop ("# HTTP send calls"));

      stat_curl_send_callbacks
        = stats->create (gettext_noop ("# HTTP curl send callbacks"));
      stat_curl_receive_callbacks
        = stats->create (gettext_noop ("# HTTP curl receive callbacks"));
      stat_mhd_access_callbacks
        = stats->create (gettext_noop ("# HTTP mhd access callbacks"));
      stat_mhd_read_callbacks
        = stats->create (gettext_noop ("# HTTP mhd read callbacks"));
      stat_mhd_close_callbacks
        = stats->create (gettext_noop ("# HTTP mhd close callbacks"));
      stat_connect_calls
        = stats->create (gettext_noop ("# HTTP connect calls"));
    }
  GNUNET_GC_get_configuration_value_string (coreAPI->cfg,
                                            "GNUNETD", "HTTP-PROXY", "",
                                            &proxy);

  myAPI.protocol_number = GNUNET_TRANSPORT_PROTOCOL_NUMBER_HTTP;
  myAPI.mtu = 0;
  myAPI.cost = 20000;           /* about equal to udp */
  myAPI.hello_verify = &verify_hello;
  myAPI.hello_create = &create_hello;
  myAPI.connect = &httpConnect;
  myAPI.associate = &httpAssociate;
  myAPI.send = &httpSend;
  myAPI.disconnect = &httpDisconnect;
  myAPI.server_start = &startTransportServer;
  myAPI.server_stop = &stopTransportServer;
  myAPI.hello_to_address = &hello_to_address;
  myAPI.send_now_test = &httpTestWouldTry;

  return &myAPI;
}

void
donetransport_http ()
{
  curl_global_cleanup ();
  GNUNET_free_non_null (proxy);
  proxy = NULL;
  GNUNET_array_grow (tsessions, tsessionArrayLength, 0);
  do_shutdown ();
}

/* end of http.c */
