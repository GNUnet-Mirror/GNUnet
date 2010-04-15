/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @author Matthias Wachs
 */

#include "platform.h"
#include "hostlist-client.h"
#include "gnunet_core_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet-daemon-hostlist.h"
#include <curl/curl.h>
#include "gnunet_common.h"
#include "gnunet_bio_lib.h"

#define DEBUG_HOSTLIST_CLIENT GNUNET_YES

#define MAX_URL_LEN 1000

/**
 * Number of connections that we must have to NOT download
 * hostlists anymore.
 */
#define MIN_CONNECTIONS 4

/**
 * A single hostlist obtained by hostlist advertisements
 */
struct Hostlist
{
  struct Hostlist * prev;

  struct Hostlist * next;

  /**
   * URI where hostlist can be obtained
   */
  const char *hostlist_uri;

  /**
   * Peer offering the hostlist.  TO BE REMOVED.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Value describing the quality of the hostlist, the bigger the better but (should) never < 0
   * used for deciding which hostlist is replaced if MAX_NUMBER_HOSTLISTS in data structure is reached
   * intial value = HOSTLIST_INITIAL
   * increased every successful download by HOSTLIST_SUCCESSFULL_DOWNLOAD
   * increased every successful download by number of obtained HELLO messages
   * decreased every failed download by HOSTLIST_SUCCESSFULL_DOWNLOAD
   */
  uint64_t quality;

  /**
   * Time the hostlist advertisement was recieved and the entry was created
   */
  struct GNUNET_TIME_Absolute   time_creation;

  /**
   * Last time the hostlist was obtained
   */
  struct GNUNET_TIME_Absolute   time_last_usage;

  /**
   * Number of HELLO messages obtained during last download
   */
  uint32_t                 hello_count;

  /**
   * Number of times the hostlist was obtained
   */
  uint32_t                 times_used;

};


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
 * At what time MUST the current hostlist request be done?
 */
static struct GNUNET_TIME_Absolute end_time;

/* DLL_? */
static struct Hostlist * dll_head;

/* DLL_? */
static struct Hostlist * dll_tail;

/* DLL_? */
static unsigned int dll_size;

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
    {
      return total;  /* ok, no data or bogus data */
    }
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# bytes downloaded from hostlist servers"), 
			    (int64_t) total, 
			    GNUNET_NO);  
  left = total;
  while ( (left > 0) ||
	  (download_pos > 0) )
    {
      cpy = GNUNET_MIN (left, GNUNET_SERVER_MAX_MESSAGE_SIZE - download_pos);
      memcpy (&download_buffer[download_pos],
	      cbuf,
	      cpy);      
      cbuf += cpy;
      download_pos += cpy;
      left -= cpy;
      if (download_pos < sizeof(struct GNUNET_MessageHeader))
	{
	  GNUNET_assert (left == 0);
	  break;
	}
      msg = (const struct GNUNET_MessageHeader *) download_buffer;
      msize = ntohs(msg->size);
      if (msize < sizeof(struct GNUNET_MessageHeader))
	{	 
	  GNUNET_STATISTICS_update (stats, 
				    gettext_noop ("# invalid HELLOs downloaded from hostlist servers"), 
				    1, 
				    GNUNET_NO);  
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("Invalid `%s' message received from hostlist at `%s'\n"),
		      "HELLO",
		      current_url); 
	  bogus_url = 1;
	  return total;
	}
      if (download_pos < msize)
	{
	  GNUNET_assert (left == 0);
	  break;
	}
      if (GNUNET_HELLO_size ((const struct GNUNET_HELLO_Message*)msg) == msize)
	{
#if DEBUG_HOSTLIST_CLIENT
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Received valid `%s' message from hostlist server.\n",
		      "HELLO");
#endif
	  GNUNET_STATISTICS_update (stats, 
				    gettext_noop ("# valid HELLOs downloaded from hostlist servers"), 
				    1, 
				    GNUNET_NO);  
	  GNUNET_TRANSPORT_offer_hello (transport, msg);
	}
      else
	{
	  GNUNET_STATISTICS_update (stats, 
				    gettext_noop ("# invalid HELLOs downloaded from hostlist servers"), 
				    1, 
				    GNUNET_NO);  
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("Invalid `%s' message received from hostlist at `%s'\n"),
		      "HELLO",
		      current_url);
	  bogus_url = GNUNET_YES;
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
  GNUNET_free_non_null (current_url);
  current_url = NULL;
  schedule_hostlist_task ();
}


/**
 * Ask CURL for the select set and then schedule the
 * receiving task with the scheduler.
 */
static void
run_multi (void);


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
  
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    {
#if DEBUG_HOSTLIST_CLIENT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Shutdown requested while trying to download hostlist from `%s'\n",
		  current_url);
#endif
      clean_up ();
      return;
    }
  if (GNUNET_TIME_absolute_get_remaining (end_time).value == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Timeout trying to download hostlist from `%s'\n"),
		  current_url);
      clean_up ();
      return;
    }
#if DEBUG_HOSTLIST_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Ready for processing hostlist client request\n");
#endif
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
		  if ( (msg->data.result != CURLE_OK) &&
		       (msg->data.result != CURLE_GOT_NOTHING) )		       
		    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
			       _("%s failed for `%s' at %s:%d: `%s'\n"),
			       "curl_multi_perform", 
			       current_url,
			       __FILE__,
			       __LINE__,
			       curl_easy_strerror (msg->data.result));		  
		  else
		    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
				_("Download of hostlist `%s' completed.\n"),
				current_url);
		  clean_up ();
		  return;
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
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("%s failed at %s:%d: `%s'\n"),
		  "curl_multi_perform", __FILE__, __LINE__,
		  curl_multi_strerror (mret));
      clean_up ();
    }
  run_multi ();
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
  long timeout;
  struct GNUNET_TIME_Relative rtime;
  
  max = -1;
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
  mret = curl_multi_timeout (multi, &timeout);
  if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("%s failed at %s:%d: `%s'\n"),
		  "curl_multi_timeout", __FILE__, __LINE__,
		  curl_multi_strerror (mret));
      clean_up ();
      return;
    }
  rtime = GNUNET_TIME_relative_min (GNUNET_TIME_absolute_get_remaining (end_time),
				    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
								   timeout));
  grs = GNUNET_NETWORK_fdset_create ();
  gws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (grs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (gws, &ws, max + 1);  
#if DEBUG_HOSTLIST_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Scheduling task for hostlist download using cURL\n");
#endif
  current_task 
    = GNUNET_SCHEDULER_add_select (sched,
				   GNUNET_SCHEDULER_PRIORITY_DEFAULT,
				   GNUNET_SCHEDULER_NO_TASK,
				   rtime,
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
  current_url = get_url ();
  GNUNET_log (GNUNET_ERROR_TYPE_INFO | GNUNET_ERROR_TYPE_BULK,
	      _("Bootstrapping using hostlist at `%s'.\n"), 
	      current_url);
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# hostlist downloads initiated"), 
			    1, 
			    GNUNET_NO);  
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
  CURL_EASY_SETOPT (curl, CURLOPT_MAXREDIRS, 4);
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
#if 0
  CURL_EASY_SETOPT (curl, 
		    CURLOPT_VERBOSE, 
		    1);
#endif
  CURL_EASY_SETOPT (curl, 
		    CURLOPT_BUFFERSIZE, 
		    GNUNET_SERVER_MAX_MESSAGE_SIZE);
  if (0 == strncmp (current_url, "http", 4))
    CURL_EASY_SETOPT (curl, CURLOPT_USERAGENT, "GNUnet");
  CURL_EASY_SETOPT (curl, 
		    CURLOPT_CONNECTTIMEOUT, 
		    60L);
  CURL_EASY_SETOPT (curl, 
		    CURLOPT_TIMEOUT, 
		    60L);
#if 0
  /* this should no longer be needed; we're now single-threaded! */
  CURL_EASY_SETOPT (curl,
		    CURLOPT_NOSIGNAL, 
		    1);
#endif
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
  end_time = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES);
  run_multi ();
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
  current_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
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
  static int once;
  struct GNUNET_TIME_Relative delay;

  if (stats == NULL)
    {
      curl_global_cleanup ();
      return; /* in shutdown */
    }
  delay = hostlist_delay;
  if (hostlist_delay.value == 0)
    hostlist_delay = GNUNET_TIME_UNIT_SECONDS;
  else
    hostlist_delay = GNUNET_TIME_relative_multiply (hostlist_delay, 2);
  if (hostlist_delay.value > GNUNET_TIME_UNIT_HOURS.value * (1 + connection_count))
    hostlist_delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS,
						    (1 + connection_count));
  GNUNET_STATISTICS_set (stats,
			 gettext_noop("# seconds between hostlist downloads"),
			 hostlist_delay.value,
			 GNUNET_YES);
  if (0 == once)
    {
      delay = GNUNET_TIME_UNIT_ZERO;
      once = 1;
    }  
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Have %u/%u connections.  Will consider downloading hostlist in %llums\n"),
	      connection_count,
	      MIN_CONNECTIONS,
	      (unsigned long long) delay.value);
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
 * @param latency reported latency of the connection with 'other'
 * @param distance reported distance (DV) to 'other' 
 */
static void
connect_handler (void *cls,
		 const struct
		 GNUNET_PeerIdentity * peer,
		 struct GNUNET_TIME_Relative latency,
		 uint32_t distance)
{
  connection_count++;
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# active connections"), 
			    1, 
			    GNUNET_NO);  
}


/**
 * Method called whenever a given peer disconnects.
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
  GNUNET_STATISTICS_update (stats, 
			    gettext_noop ("# active connections"), 
			    -1, 
			    GNUNET_NO);  
}


/* DLL_? */
static int 
dll_contains (const char * uri)
{
  struct Hostlist * pos;

  pos = dll_head;
  while (pos != NULL)
    {
      if (0 == strcmp(pos->hostlist_uri, uri) ) 
	return GNUNET_YES;
      pos = pos->next;
    }
  return GNUNET_NO;
}


/* DLL_? */
static struct Hostlist *
dll_get_lowest_quality ( )
{
  struct Hostlist * pos;
  struct Hostlist * lowest;

  if (dll_size == 0)
    return NULL;
  lowest = dll_head;
  pos = dll_head->next;
  while (pos != NULL)
    {
      if (pos->quality < lowest->quality) 
	lowest = pos;
      pos = pos->next;
    }
  return lowest;
}


#if DUMMY
/* TO BE REMOVED later */
static void dll_insert ( struct Hostlist *hostlist)
{
  GNUNET_CONTAINER_DLL_insert(dll_head, dll_tail, hostlist);
  dll_size++;
}

static void create_dummy_entries ()
{

  /* test */
  struct Hostlist * hostlist1;
  hostlist1 = GNUNET_malloc ( sizeof (struct Hostlist) );
  char * str = "uri_1";

  GNUNET_CRYPTO_hash_create_random ( GNUNET_CRYPTO_QUALITY_WEAK , &hostlist1->peer.hashPubKey);
  hostlist1->hello_count = 0;
  hostlist1->hostlist_uri = GNUNET_malloc ( strlen(str) +1 );
  strcpy(hostlist1->hostlist_uri,str);
  hostlist1->time_creation = GNUNET_TIME_absolute_get();
  hostlist1->time_last_usage = GNUNET_TIME_absolute_get_zero();
  hostlist1->quality = HOSTLIST_INITIAL - 100;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Adding test peer '%s' with URI %s and quality %u to dll \n", GNUNET_h2s (&hostlist1->peer.hashPubKey) , hostlist1->hostlist_uri, hostlist1->quality);
  dll_insert (hostlist1);

  struct Hostlist * hostlist2;
  hostlist2 = GNUNET_malloc ( sizeof (struct Hostlist) );
  char * str2 = "uri_2";

  GNUNET_CRYPTO_hash_create_random ( GNUNET_CRYPTO_QUALITY_WEAK , &hostlist2->peer.hashPubKey);
  hostlist2->hello_count = 0;
  hostlist2->hostlist_uri = GNUNET_malloc ( strlen(str2) +1 );
  strcpy(hostlist2->hostlist_uri,str2);
  hostlist2->time_creation = GNUNET_TIME_absolute_get();
  hostlist2->time_last_usage = GNUNET_TIME_absolute_get_zero();
  hostlist2->quality = HOSTLIST_INITIAL - 200;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Adding test peer '%s' with URI %s and quality %u to dll \n", GNUNET_h2s (&hostlist2->peer.hashPubKey) , hostlist2->hostlist_uri, hostlist2->quality);
  dll_insert (hostlist2);

  struct Hostlist * hostlist3;
  hostlist3 = GNUNET_malloc ( sizeof (struct Hostlist) );
  char * str3 = "uri_3";

  GNUNET_CRYPTO_hash_create_random ( GNUNET_CRYPTO_QUALITY_WEAK , &hostlist3->peer.hashPubKey);
  hostlist3->hello_count = 0;
  hostlist3->hostlist_uri = GNUNET_malloc ( strlen(str3) +1 );
  strcpy(hostlist3->hostlist_uri,str3);
  hostlist3->time_creation = GNUNET_TIME_absolute_get();
  hostlist3->time_last_usage = GNUNET_TIME_absolute_get_zero();
  hostlist3->quality = HOSTLIST_INITIAL - 300;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
            "Adding test peer '%s' with URI %s and quality %u to dll \n", GNUNET_h2s (&hostlist3->peer.hashPubKey) , hostlist3->hostlist_uri, hostlist3->quality);
  dll_insert (hostlist3);


  struct Hostlist * hostlist4;
  hostlist4 = GNUNET_malloc ( sizeof (struct Hostlist) );
  char * str4 = "uri_4";

  GNUNET_CRYPTO_hash_create_random ( GNUNET_CRYPTO_QUALITY_WEAK , &hostlist4->peer.hashPubKey);
  hostlist4->hello_count = 0;
  hostlist4->hostlist_uri = GNUNET_malloc ( strlen(str4) +1 );
  strcpy(hostlist4->hostlist_uri,str4);
  hostlist4->time_creation = GNUNET_TIME_absolute_get();
  hostlist4->time_last_usage = GNUNET_TIME_absolute_get_zero();
  hostlist4->quality = HOSTLIST_INITIAL - 400;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Adding test peer '%s' with URI %s and quality %u to dll \n", GNUNET_h2s (&hostlist4->peer.hashPubKey) , hostlist4->hostlist_uri, hostlist4->quality);
  dll_insert (hostlist4);
}
#endif

/**
 * Method called whenever an advertisement message arrives.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
advertisement_handler (void *cls,
    const struct GNUNET_PeerIdentity * peer,
    const struct GNUNET_MessageHeader * message,
    struct GNUNET_TIME_Relative latency,
    uint32_t distance)
{
  size_t size;
  size_t uri_size;
  const struct GNUNET_MessageHeader * incoming;
  const char *uri;
  struct Hostlist * hostlist;

  GNUNET_assert (ntohs (message->type) == GNUNET_MESSAGE_TYPE_HOSTLIST_ADVERTISEMENT);
  size = ntohs (message->size);
  if (size <= sizeof(struct GNUNET_MessageHeader))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  incoming = (const struct GNUNET_MessageHeader *) message;
  uri = (const char*) &incoming[1];
  uri_size = size - sizeof (struct GNUNET_MessageHeader);
  if (uri [uri_size - 1] != '\0')
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Hostlist client recieved advertisement from `%s' containing URI `%s'\n", 
	      GNUNET_i2s (peer), 
	      uri);
  if (GNUNET_YES != dll_contains (uri))
    return GNUNET_OK;
  hostlist = GNUNET_malloc (sizeof (struct Hostlist) + uri_size);
  hostlist->peer = *peer;
  hostlist->hostlist_uri = (const char*) &hostlist[1];
  memcpy (&hostlist[1], uri, uri_size);
  hostlist->time_creation = GNUNET_TIME_absolute_get();
  hostlist->time_last_usage = GNUNET_TIME_absolute_get_zero();
  hostlist->quality = HOSTLIST_INITIAL;  
#if DUMMY
  create_dummy_entries(); /* FIXME: remove later... */
#endif
  GNUNET_CONTAINER_DLL_insert(dll_head, dll_tail, hostlist);
  dll_size++;
  
  if (MAX_NUMBER_HOSTLISTS >= dll_size)
    return GNUNET_OK;

  /* No free entries available, replace existing entry  */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Removing lowest quality entry\n" );  
  struct Hostlist * lowest_quality = dll_get_lowest_quality();
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Hostlist with URI `%s' has the worst quality of all with value %llu\n", 
	      lowest_quality->hostlist_uri,
	      (unsigned long long) lowest_quality->quality);
  GNUNET_CONTAINER_DLL_remove (dll_head, dll_tail, lowest_quality);
  dll_size--;
  GNUNET_free (lowest_quality);
  return GNUNET_OK;
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
  if (stats == NULL)
    return; /* in shutdown */
#if DEBUG_HOSTLIST_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Statistics request done, scheduling hostlist download\n");
#endif
  schedule_hostlist_task ();
}


static int
process_stat (void *cls,
	      const char *subsystem,
	      const char *name,
	      uint64_t value,
	      int is_persistent)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Initial time between hostlist downloads is %llums\n"),
	      (unsigned long long) value);
  hostlist_delay.value = value;
  return GNUNET_OK;
}

/**
 * Method to load persistent hostlist file during hostlist client startup
 */
static void 
load_hostlist_file ()
{
  char *filename;
  char *uri;
  char *emsg;
  struct Hostlist * hostlist;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "HOSTLIST",
                                             "HOSTLISTFILE",
                                             &filename))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("No `%s' specified in `%s' configuration, cannot load hostlists from file.\n"),
                  "HOSTLISTFILE", "HOSTLIST");
      return;
    }

  struct GNUNET_BIO_ReadHandle * rh = GNUNET_BIO_read_open (filename);
  if (NULL == rh)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Could not open file `%s' for reading to load hostlists: %s\n"), 
		  filename,
		  STRERROR (errno));
      GNUNET_free (filename);
      return;
    }

  /* add code to read hostlists to file using bio */
  uri = NULL;
  uint32_t times_used;
  uint32_t hellos_returned;
  uint64_t quality;
  uint64_t last_used;
  uint64_t created;

  while ( (GNUNET_OK == GNUNET_BIO_read_string (rh, "url" , &uri, MAX_URL_LEN)) &&
	  (GNUNET_OK == GNUNET_BIO_read_int32 (rh, &times_used)) &&
	  (GNUNET_OK == GNUNET_BIO_read_int64 (rh, &quality)) &&
	  (GNUNET_OK == GNUNET_BIO_read_int64 (rh, &last_used)) &&
	  (GNUNET_OK == GNUNET_BIO_read_int64 (rh, &created)) &&
	  (GNUNET_OK == GNUNET_BIO_read_int32 (rh, &hellos_returned)) )
    {
      hostlist = GNUNET_malloc ( sizeof (struct Hostlist));
      hostlist->hello_count = hellos_returned;
      strcpy(hostlist->hostlist_uri, uri);
      hostlist->quality = quality;
      hostlist->time_creation.value = created;
      hostlist->time_last_usage.value = last_used;
      GNUNET_CONTAINER_DLL_insert(dll_head, dll_tail, hostlist);
      dll_size++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Added hostlist entry eith URI `%s' \n", hostlist->hostlist_uri);
      uri = NULL;
    }
  GNUNET_free_non_null (uri);
  emsg = NULL;
  GNUNET_BIO_read_close (rh, &emsg);
  if (emsg != NULL)
    GNUNET_free (emsg);
  GNUNET_free (filename);
}


/**
 * Method to load persistent hostlist file during hostlist client shutdown
 */
static void save_hostlist_file ()
{
  char *filename;
  struct Hostlist *pos;
  struct GNUNET_BIO_WriteHandle * wh;
  int ok;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "HOSTLIST",
                                             "HOSTLISTFILE",
                                             &filename))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("No `%s' specified in `%s' configuration, cannot save hostlists to file.\n"),
                  "HOSTLISTFILE", "HOSTLIST");
      return;
    }
  wh = GNUNET_BIO_write_open (filename);
  if ( NULL == wh)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Could not open file `%s' for writing to save hostlists: %s\n"),
                  filename,
		  STRERROR (errno));
      return;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Writing hostlist URIs to `%s'\n"),
	      filename);

  /* add code to write hostlists to file using bio */
  ok = GNUNET_YES;
  while (NULL != (pos = dll_head))
    {
      GNUNET_CONTAINER_DLL_remove (dll_head, dll_tail, pos);
      dll_size--;
      if (GNUNET_YES == ok)
	{
	  if ( (GNUNET_OK !=
		GNUNET_BIO_write_string (wh, pos->hostlist_uri)) ||
	       (GNUNET_OK !=
		GNUNET_BIO_write_int32 (wh, pos->times_used)) ||
	       (GNUNET_OK !=
		GNUNET_BIO_write_int64 (wh, pos->quality)) ||
               (GNUNET_OK !=
                GNUNET_BIO_write_int64 (wh, pos->time_last_usage.value)) ||
               (GNUNET_OK !=
                GNUNET_BIO_write_int64 (wh, pos->time_creation.value)) ||
	       (GNUNET_OK !=
	        GNUNET_BIO_write_int32 (wh, pos->hello_count)))
	    {
	      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
			  _("Error writing hostlist URIs to file `%s'\n"),
			  filename);
	      ok = GNUNET_NO;
	    }
	}
      GNUNET_free (pos);
    }  
  if ( GNUNET_OK != GNUNET_BIO_write_close ( wh ) )
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Error writing hostlist URIs to file `%s'\n"),
		filename);
  GNUNET_free (filename);
}

/**
 * Start downloading hostlists from hostlist servers as necessary.
 */
int
GNUNET_HOSTLIST_client_start (const struct GNUNET_CONFIGURATION_Handle *c,
			      struct GNUNET_SCHEDULER_Handle *s,
			      struct GNUNET_STATISTICS_Handle *st,
			      GNUNET_CORE_ConnectEventHandler *ch,
			      GNUNET_CORE_DisconnectEventHandler *dh,
			      GNUNET_CORE_MessageCallback *msgh,
			      int learn)
{
  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  transport = GNUNET_TRANSPORT_connect (s, c, NULL, NULL, NULL, NULL);
  if (NULL == transport)
    {
      curl_global_cleanup ();
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
  if (learn)
    *msgh = &advertisement_handler;
  else
    *msgh = NULL;
  dll_head = NULL;
  dll_tail = NULL;
  load_hostlist_file ();

  GNUNET_STATISTICS_get (stats,
			 "hostlist",
			 gettext_noop("# seconds between hostlist downloads"),
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
#if DEBUG_HOSTLIST_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Hostlist client shutdown\n");
#endif
  save_hostlist_file ();

  if (current_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (sched,
			       current_task);
      curl_global_cleanup ();
    }
  if (transport != NULL)
    {
      GNUNET_TRANSPORT_disconnect (transport);
      transport = NULL;
    }
  GNUNET_assert (NULL == transport);
  GNUNET_free_non_null (proxy);
  proxy = NULL;
  cfg = NULL;
  sched = NULL;
}

/* end of hostlist-client.c */
