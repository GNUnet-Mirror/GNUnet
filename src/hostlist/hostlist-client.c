/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file hostlist/hostlist-client.c
 * @brief hostlist support.  Downloads HELLOs via HTTP.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "hostlist-client.h"
#include "gnunet_core_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_transport_service.h"
#include <curl/curl.h>

/**
 * Number of connections that we must have to NOT download
 * hostlists anymore.
 */
#define MIN_CONNECTIONS 4

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Our scheduler.
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * Statistics handle.
 */
struct GNUNET_STATISTICS_Handle *stats; 

/**
 * Transport handle.
 */
struct GNUNET_TRANSPORT_Handle *transport;
                       
/**
 * Proxy that we are using (can be NULL).
 */
static char *proxy;

/**
 * Buffer for data downloaded via HTTP.
 */
static char download_buffer[GNUNET_SERVER_MAX_MESSAGE_SIZE];

/**
 * Number of bytes valid in 'download_buffer'.
 */
static size_t download_pos;

/**
 * Current URL that we are using.
 */
static char *current_url;

/**
 * Current CURL handle.
 */
static CURL *curl;

/**
 * Current multi-CURL handle.
 */
static CURLM *multi;

/**
 * ID of the current task scheduled.
 */
static GNUNET_SCHEDULER_TaskIdentifier current_task;

/**
 * Amount of time we wait between hostlist downloads.
 */
static struct GNUNET_TIME_Relative hostlist_delay;

/**
 * Set to GNUNET_YES if the current URL had some problems.
 */ 
static int bogus_url;

/**
 * Number of active connections (according to core service).
 */
static unsigned int connection_count;


/**
 * Process downloaded bits by calling callback on each HELLO.
 *
 * @param ptr buffer with downloaded data
 * @param size size of a record
 * @param nmemb number of records downloaded
 * @param ctx unused
 * @return number of bytes that were processed (always size*nmemb)
 */
static size_t
download_hostlist_processor (void *ptr, 
			     size_t size, 
			     size_t nmemb, 
			     void *ctx)
{
  const char * cbuf = ptr;
  const struct GNUNET_MessageHeader *msg;
  size_t total;
  size_t cpy;
  size_t left;
  uint16_t msize;

  total = size * nmemb;
  if ( (total == 0) || (bogus_url) )
    return total;  /* ok, no data or bogus data */
  left = total;
  while (left > 0)
    {
      cpy = GNUNET_MIN (total, GNUNET_SERVER_MAX_MESSAGE_SIZE - download_pos);
      GNUNET_assert (cpy > 0);
      memcpy (&download_buffer[download_pos],
	      cbuf,
	      cpy);
      cbuf += cpy;
      download_pos += cpy;
      left -= cpy;
      if (download_pos < sizeof(struct GNUNET_MessageHeader))
	break;
      msg = (const struct GNUNET_MessageHeader *) download_buffer;
      msize = ntohs(msg->size);
      if (msize < sizeof(struct GNUNET_MessageHeader))
	{	 
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("Invalid `%s' message received from hostlist at `%s'\n"),
		      "HELLO",
		      current_url); 
	  bogus_url = 1;
	  return total;
	}
      if (download_pos < msize)
	break;
      if (GNUNET_HELLO_size ((const struct GNUNET_HELLO_Message*)msg) == msize)
	{
	  GNUNET_TRANSPORT_offer_hello (transport, msg);
	}
      else
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("Invalid `%s' message received from hostlist at `%s'\n"),
		      "HELLO",
		      current_url);
	  bogus_url = 1;
	  return total;
	}
      memmove (download_buffer,
	       &download_buffer[msize],
	       download_pos - msize);
      download_pos -= msize;
    }
  return total;
}


/**
 * Obtain a hostlist URL that we should use.
 *
 * @return NULL if there is no URL available
 */
static char *
get_url ()
{
  char *servers;
  char *ret;
  size_t urls;
  size_t pos;

  if (GNUNET_OK != 
      GNUNET_CONFIGURATION_get_value_string (cfg,
					     "HOSTLIST",
					     "SERVERS",
					     &servers))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("No `%s' specified in `%s' configuration, will not bootstrap.\n"),
		  "SERVERS", "HOSTLIST");
      return NULL;
    }

  urls = 0;
  if (strlen (servers) > 0)
    {
      urls++;
      pos = strlen (servers) - 1;
      while (pos > 0)
        {
          if (servers[pos] == ' ')
            urls++;
          pos--;
        }
    }
  if (urls == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("No `%s' specified in `%s' configuration, will not bootstrap.\n"),
		  "SERVERS", "HOSTLIST");
      GNUNET_free (servers);
      return NULL;
    }

  urls = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, urls) + 1;
  pos = strlen (servers) - 1;
  while (pos > 0)
    {
      if (servers[pos] == ' ')
        {
          urls--;
          servers[pos] = '\0';
        }
      if (urls == 0)
        {
          pos++;
          break;
        }
      pos--;    
    }
  ret = GNUNET_strdup (&servers[pos]);
  GNUNET_free (servers);
  return ret;
}


#define CURL_EASY_SETOPT(c, a, b) do { ret = curl_easy_setopt(c, a, b); if (ret != CURLE_OK) GNUNET_log(GNUNET_ERROR_TYPE_WARNING, _("%s failed at %s:%d: `%s'\n"), "curl_easy_setopt", __FILE__, __LINE__, curl_easy_strerror(ret)); } while (0);


/**
 * Schedule the background task that will (possibly)
 * download a hostlist.
 */
static void
schedule_hostlist_task (void);


/**
 * Clean up the state from the task that downloaded the
 * hostlist and schedule the next task.
 */
static void 
clean_up ()
{
  CURLMcode mret;

  if (multi != NULL)
    {
      mret = curl_multi_remove_handle (multi, curl);
      if (mret != CURLM_OK)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("%s failed at %s:%d: `%s'\n"),
		      "curl_multi_remove_handle", __FILE__, __LINE__,
		      curl_multi_strerror (mret));
	}
      mret = curl_multi_cleanup (multi);
      if (mret != CURLM_OK)
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		    _("%s failed at %s:%d: `%s'\n"),
		    "curl_multi_cleanup", __FILE__, __LINE__,
		    curl_multi_strerror (mret));
      multi = NULL;
    }
  if (curl != NULL)
    {
      curl_easy_cleanup (curl);
      curl = NULL;
    }  
  if (transport != NULL)
    {
      GNUNET_TRANSPORT_disconnect (transport);
      transport = NULL;
    }
  GNUNET_free_non_null (current_url);
  current_url = NULL;
  schedule_hostlist_task ();
}


/**
 * Task that is run when we are ready to receive more data from the hostlist
 * server. 
 *
 * @param cls closure, unused
 * @param tc task context, unused
 */
static void
multi_ready (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int running;
  struct CURLMsg *msg;
  CURLMcode mret;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Timeout trying to download hostlist from `%s'\n"),
		  current_url);
      clean_up ();
      return;
    }
  do 
    {
      running = 0;
      mret = curl_multi_perform (multi, &running);
      if (running == 0)
	{
	  do
	    {
	      msg = curl_multi_info_read (multi, &running);
	      GNUNET_break (msg != NULL);
	      if (msg == NULL)
		break;
	      switch (msg->msg)
		{
		case CURLMSG_DONE:
		  if (msg->data.result != CURLE_OK)
		    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
			       _("%s failed at %s:%d: `%s'\n"),
			       "curl_multi_perform", __FILE__,
			       __LINE__,
			       curl_easy_strerror (msg->data.result));
		  break;
		default:
		  break;
		}
	    }
	  while (running > 0);
	}
    }
  while (mret == CURLM_CALL_MULTI_PERFORM);
  if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("%s failed at %s:%d: `%s'\n"),
		  "curl_multi_perform", __FILE__, __LINE__,
		  curl_multi_strerror (mret));
      clean_up ();
      return;
    }
  clean_up ();
}


/**
 * Ask CURL for the select set and then schedule the
 * receiving task with the scheduler.
 */
static void
run_multi () 
{
  CURLMcode mret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct GNUNET_NETWORK_FDSet *grs;
  struct GNUNET_NETWORK_FDSet *gws;
  
  max = 0;
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  mret = curl_multi_fdset (multi, &rs, &ws, &es, &max);
  if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("%s failed at %s:%d: `%s'\n"),
		  "curl_multi_fdset", __FILE__, __LINE__,
		  curl_multi_strerror (mret));
      clean_up ();
      return;
    }
  grs = GNUNET_NETWORK_fdset_create ();
  gws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (grs, &rs, max);
  GNUNET_NETWORK_fdset_copy_native (gws, &ws, max);
  current_task 
    = GNUNET_SCHEDULER_add_select (sched,
				   GNUNET_SCHEDULER_PRIORITY_DEFAULT,
				   GNUNET_SCHEDULER_NO_TASK,
				   GNUNET_TIME_UNIT_MINUTES,
				   grs,
				   gws,
				   &multi_ready,
				   multi);
  GNUNET_NETWORK_fdset_destroy (gws);
  GNUNET_NETWORK_fdset_destroy (grs);
}


/**
 * Main function that will download a hostlist and process its
 * data.
 */
static void
download_hostlist () 
{
  CURLcode ret;
  CURLMcode mret;

  curl = curl_easy_init ();
  multi = NULL;
  if (curl == NULL)
    {
      GNUNET_break (0);
      clean_up ();
      return;
    }
  transport = GNUNET_TRANSPORT_connect (sched, cfg, NULL, NULL, NULL, NULL);
  current_url = get_url ();
  GNUNET_log (GNUNET_ERROR_TYPE_INFO | GNUNET_ERROR_TYPE_BULK,
	      _("Bootstrapping using hostlist at `%s'.\n"), 
	      current_url);

  if (proxy != NULL)
    CURL_EASY_SETOPT (curl, CURLOPT_PROXY, proxy);    
  download_pos = 0;
  bogus_url = 0;
  CURL_EASY_SETOPT (curl,
		    CURLOPT_WRITEFUNCTION, 
		    &download_hostlist_processor);
  if (ret != CURLE_OK)
    {
      clean_up ();
      return;
    }
  CURL_EASY_SETOPT (curl,
		    CURLOPT_WRITEDATA, 
		    NULL);
  if (ret != CURLE_OK)
    {
      clean_up ();
      return;
    }
  CURL_EASY_SETOPT (curl, CURLOPT_FOLLOWLOCATION, 1);
  /* no need to abort if the above failed */
  CURL_EASY_SETOPT (curl, 
		    CURLOPT_URL, 
		    current_url);
  if (ret != CURLE_OK)
    {
      clean_up ();
      return;
    }
  CURL_EASY_SETOPT (curl, 
		    CURLOPT_FAILONERROR, 
		    1);
  CURL_EASY_SETOPT (curl, 
		    CURLOPT_BUFFERSIZE, 
		    GNUNET_SERVER_MAX_MESSAGE_SIZE);
  if (0 == strncmp (current_url, "http", 4))
    CURL_EASY_SETOPT (curl, CURLOPT_USERAGENT, "GNUnet");
  CURL_EASY_SETOPT (curl, 
		    CURLOPT_CONNECTTIMEOUT, 
		    150L);
  CURL_EASY_SETOPT (curl,
		    CURLOPT_NOSIGNAL, 
		    1);
  multi = curl_multi_init ();
  if (multi == NULL)
    {
      GNUNET_break (0);
      clean_up ();
      return;
    }
  mret = curl_multi_add_handle (multi, curl);
  if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("%s failed at %s:%d: `%s'\n"),
		  "curl_multi_add_handle", __FILE__, __LINE__,
		  curl_multi_strerror (mret));
      mret = curl_multi_cleanup (multi);
      if (mret != CURLM_OK)
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		    _("%s failed at %s:%d: `%s'\n"),
		    "curl_multi_cleanup", __FILE__, __LINE__,
		    curl_multi_strerror (mret));
      multi = NULL;
      clean_up ();
      return;
    }
  run_multi (multi);
}  


/**
 * Task that checks if we should try to download a hostlist.
 * If so, we initiate the download, otherwise we schedule
 * this task again for a later time.
 */
static void
check_task (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (connection_count < MIN_CONNECTIONS)
    download_hostlist ();
  else
    schedule_hostlist_task ();
}


/**
 * Compute when we should check the next time about downloading
 * a hostlist; then schedule the task accordingly.
 */
static void
schedule_hostlist_task ()
{
  struct GNUNET_TIME_Relative delay;

  delay = hostlist_delay;
  if (hostlist_delay.value == 0)
    hostlist_delay = GNUNET_TIME_UNIT_SECONDS;
  else
    hostlist_delay = GNUNET_TIME_relative_multiply (hostlist_delay, 2);
  if (hostlist_delay.value > GNUNET_TIME_UNIT_HOURS.value * connection_count)
    hostlist_delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_DAYS,
						    connection_count);
  GNUNET_STATISTICS_set (stats,
			 gettext_noop("Minimum time between hostlist downloads"),
			 hostlist_delay.value,
			 GNUNET_YES);
  current_task = GNUNET_SCHEDULER_add_delayed (sched,
					       delay,
					       &check_task,
					       NULL);
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
connect_handler (void *cls,
		 const struct
		 GNUNET_PeerIdentity * peer)
{
  connection_count++;
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
disconnect_handler (void *cls,
		    const struct
		    GNUNET_PeerIdentity * peer)
{
  connection_count--;
}


/**
 * Continuation called by the statistics code once 
 * we go the stat.  Initiates hostlist download scheduling.
 *
 * @param cls closure
 * @param success GNUNET_OK if statistics were
 *        successfully obtained, GNUNET_SYSERR if not.
 */
static void
primary_task (void *cls, int success)
{
  schedule_hostlist_task ();
}


static int
process_stat (void *cls,
	      const char *subsystem,
	      const char *name,
	      uint64_t value,
	      int is_persistent)
{
  hostlist_delay.value = value;
  return GNUNET_OK;
}


/**
 * Start downloading hostlists from hostlist servers as necessary.
 */
int
GNUNET_HOSTLIST_client_start (const struct GNUNET_CONFIGURATION_Handle *c,
			      struct GNUNET_SCHEDULER_Handle *s,
			      struct GNUNET_STATISTICS_Handle *st,
			      GNUNET_CORE_ClientEventHandler *ch,
			      GNUNET_CORE_ClientEventHandler *dh)
{
  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  cfg = c;
  sched = s;
  stats = st;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
					     "HOSTLIST",
					     "HTTP-PROXY", 
					     &proxy))
    proxy = NULL;
  *ch = &connect_handler;
  *dh = &disconnect_handler;
  GNUNET_STATISTICS_get (stats,
			 "hostlist",
			 gettext_noop("Minimum time between hostlist downloads"),
			 GNUNET_TIME_UNIT_MINUTES,
			 &primary_task,
			 &process_stat,
			 NULL);
  return GNUNET_OK;
}


/**
 * Stop downloading hostlists from hostlist servers as necessary.
 */
void
GNUNET_HOSTLIST_client_stop ()
{
  GNUNET_SCHEDULER_cancel (sched,
			   current_task);
  GNUNET_free_non_null (proxy);
  proxy = NULL;
  if (sched != NULL)
    curl_global_cleanup ();
  cfg = NULL;
  sched = NULL;
}

/* end of hostlist-client.c */
