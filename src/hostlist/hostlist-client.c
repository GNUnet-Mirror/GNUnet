/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2009, 2010 Christian Grothoff (and other contributing authors)

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


/**
 * Number of connections that we must have to NOT download
 * hostlists anymore.
 */
#define MIN_CONNECTIONS 4

/**
 * Interval between two advertised hostlist tests
 */
#define TESTING_INTERVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * A single hostlist obtained by hostlist advertisements
 */
struct Hostlist
{
  /**
   * previous entry, used to manage entries in a double linked list
   */
  struct Hostlist *prev;

  /**
   * next entry, used to manage entries in a double linked list
   */
  struct Hostlist *next;

  /**
   * URI where hostlist can be obtained
   */
  const char *hostlist_uri;

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
  struct GNUNET_TIME_Absolute time_creation;

  /**
   * Last time the hostlist was obtained
   */
  struct GNUNET_TIME_Absolute time_last_usage;

  /**
   * Number of HELLO messages obtained during last download
   */
  uint32_t hello_count;

  /**
   * Number of times the hostlist was successfully obtained
   */
  uint32_t times_used;

};


/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Statistics handle.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Transport handle.
 */
static struct GNUNET_TRANSPORT_Handle *transport;

/**
 * Proxy that we are using (can be NULL).
 */
static char *proxy;

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
 * How many bytes did we download from the current hostlist URL?
 */
static uint32_t stat_bytes_downloaded;

/**
 * Amount of time we wait between hostlist downloads.
 */
static struct GNUNET_TIME_Relative hostlist_delay;

/**
 * ID of the task, checking if hostlist download should take plate
 */
static GNUNET_SCHEDULER_TaskIdentifier ti_check_download;

/**
 * ID of the task downloading the hostlist
 */
static GNUNET_SCHEDULER_TaskIdentifier ti_download;

/**
 * ID of the task saving the hostlsit in a regular intervall
 */
static GNUNET_SCHEDULER_TaskIdentifier ti_saving_task;

/**
 * ID of the task called to initiate a download
 */
static GNUNET_SCHEDULER_TaskIdentifier ti_download_dispatcher_task;

/**
 * ID of the task controlling the locking between two hostlist tests
 */
static GNUNET_SCHEDULER_TaskIdentifier ti_testing_intervall_task;

/**
 * At what time MUST the current hostlist request be done?
 */
static struct GNUNET_TIME_Absolute end_time;

/**
 * Head of the linked list used to store hostlists
 */
static struct Hostlist *linked_list_head;

/**
 *  Tail of the linked list used to store hostlists
 */
static struct Hostlist *linked_list_tail;

/**
 *  Current hostlist used for downloading
 */
static struct Hostlist *current_hostlist;

/**
 *  Size of the linke list  used to store hostlists
 */
static unsigned int linked_list_size;

/**
 * Head of the linked list used to store hostlists
 */
static struct Hostlist *hostlist_to_test;

/**
 * Handle for our statistics GET operation.
 */
static struct GNUNET_STATISTICS_GetHandle *sget;

/**
 * Set to GNUNET_YES if the current URL had some problems.
 */
static int stat_bogus_url;

/**
 * Value controlling if a hostlist is tested at the moment
 */
static int stat_testing_hostlist;

/**
 * Value controlling if a hostlist testing is allowed at the moment
 */
static int stat_testing_allowed;

/**
 * Value controlling if a hostlist download is running at the moment
 */
static int stat_download_in_progress;

/**
 * Value saying if a preconfigured bootstrap server is used
 */
static unsigned int stat_use_bootstrap;

/**
 * Set if we are allowed to learn new hostlists and use them
 */
static int stat_learning;

/**
 * Value saying if hostlist download was successful
 */
static unsigned int stat_download_successful;

/**
 * Value saying how many valid HELLO messages were obtained during download
 */
static unsigned int stat_hellos_obtained;

/**
 * Number of active connections (according to core service).
 */
static unsigned int stat_connection_count;


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
callback_download (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  static char download_buffer[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  const char *cbuf = ptr;
  const struct GNUNET_MessageHeader *msg;
  size_t total;
  size_t cpy;
  size_t left;
  uint16_t msize;

  total = size * nmemb;
  stat_bytes_downloaded += total;
  if ((total == 0) || (stat_bogus_url))
  {
    return total;               /* ok, no data or bogus data */
  }

  GNUNET_STATISTICS_update (stats,
                            gettext_noop
                            ("# bytes downloaded from hostlist servers"),
                            (int64_t) total, GNUNET_NO);
  left = total;
  while ((left > 0) || (download_pos > 0))
  {
    cpy = GNUNET_MIN (left, GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - download_pos);
    memcpy (&download_buffer[download_pos], cbuf, cpy);
    cbuf += cpy;
    download_pos += cpy;
    left -= cpy;
    if (download_pos < sizeof (struct GNUNET_MessageHeader))
    {
      GNUNET_assert (left == 0);
      break;
    }
    msg = (const struct GNUNET_MessageHeader *) download_buffer;
    msize = ntohs (msg->size);
    if (msize < sizeof (struct GNUNET_MessageHeader))
    {
      GNUNET_STATISTICS_update (stats,
                                gettext_noop
                                ("# invalid HELLOs downloaded from hostlist servers"),
                                1, GNUNET_NO);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Invalid `%s' message received from hostlist at `%s'\n"),
                  "HELLO", current_url);
      stat_hellos_obtained++;
      stat_bogus_url = 1;
      return total;
    }
    if (download_pos < msize)
    {
      GNUNET_assert (left == 0);
      break;
    }
    if (GNUNET_HELLO_size ((const struct GNUNET_HELLO_Message *) msg) == msize)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received valid `%s' message from hostlist server.\n",
                  "HELLO");
      GNUNET_STATISTICS_update (stats,
                                gettext_noop
                                ("# valid HELLOs downloaded from hostlist servers"),
                                1, GNUNET_NO);
      stat_hellos_obtained++;
      GNUNET_TRANSPORT_offer_hello (transport, msg, NULL, NULL);
    }
    else
    {
      GNUNET_STATISTICS_update (stats,
                                gettext_noop
                                ("# invalid HELLOs downloaded from hostlist servers"),
                                1, GNUNET_NO);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Invalid `%s' message received from hostlist at `%s'\n"),
                  "HELLO", current_url);
      stat_bogus_url = GNUNET_YES;
      stat_hellos_obtained++;
      return total;
    }
    memmove (download_buffer, &download_buffer[msize], download_pos - msize);
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
get_bootstrap_server ()
{
  char *servers;
  char *ret;
  size_t urls;
  size_t pos;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "HOSTLIST", "SERVERS",
                                             &servers))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("No `%s' specified in `%s' configuration, will not bootstrap.\n"),
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
                _
                ("No `%s' specified in `%s' configuration, will not bootstrap.\n"),
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

/**
 * Method deciding if a preconfigured or advertisied hostlist is used on a 50:50 ratio
 * @return uri to use, NULL if there is no URL available
 */
static char *
download_get_url ()
{
  uint32_t index;
  unsigned int counter;
  struct Hostlist *pos;

  if (GNUNET_NO == stat_learning)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Using preconfigured bootstrap server\n");
    current_hostlist = NULL;
    return get_bootstrap_server ();
  }

  if ((GNUNET_YES == stat_testing_hostlist) && (NULL != hostlist_to_test))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Testing new advertised hostlist if it is obtainable\n");
    current_hostlist = hostlist_to_test;
    return GNUNET_strdup (hostlist_to_test->hostlist_uri);
  }

  if ((GNUNET_YES == stat_use_bootstrap) || (linked_list_size == 0))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Using preconfigured bootstrap server\n");
    current_hostlist = NULL;
    return get_bootstrap_server ();
  }
  index =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, linked_list_size);
  counter = 0;
  pos = linked_list_head;
  while (counter < index)
  {
    pos = pos->next;
    counter++;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Using learned hostlist `%s'\n",
              pos->hostlist_uri);
  current_hostlist = pos;
  return GNUNET_strdup (pos->hostlist_uri);
}


#define CURL_EASY_SETOPT(c, a, b) do { ret = curl_easy_setopt(c, a, b); if (ret != CURLE_OK) GNUNET_log(GNUNET_ERROR_TYPE_WARNING, _("%s failed at %s:%d: `%s'\n"), "curl_easy_setopt", __FILE__, __LINE__, curl_easy_strerror(ret)); } while (0)


/**
 * Method to save hostlist to a file during hostlist client shutdown
 * @param shutdown set if called because of shutdown, entries in linked list will be destroyed
 */
static void
save_hostlist_file (int shutdown);


/**
 * add val2 to val1 with overflow check
 * @param val1 value 1
 * @param val2 value 2
 * @return result
 */
static uint64_t
checked_add (uint64_t val1, uint64_t val2)
{
  static uint64_t temp;
  static uint64_t maxv;

  maxv = 0;
  maxv--;

  temp = val1 + val2;
  if (temp < val1)
    return maxv;
  else
    return temp;
}

/**
 * Subtract val2 from val1 with underflow check
 * @param val1 value 1
 * @param val2 value 2
 * @return result
 */
static uint64_t
checked_sub (uint64_t val1, uint64_t val2)
{
  if (val1 <= val2)
    return 0;
  else
    return (val1 - val2);
}

/**
 * Method to check if  a URI is in hostlist linked list
 * @param uri uri to check
 * @return GNUNET_YES if existing in linked list, GNUNET_NO if not
 */
static int
linked_list_contains (const char *uri)
{
  struct Hostlist *pos;

  pos = linked_list_head;
  while (pos != NULL)
  {
    if (0 == strcmp (pos->hostlist_uri, uri))
      return GNUNET_YES;
    pos = pos->next;
  }
  return GNUNET_NO;
}


/**
 * Method returning the hostlist element with the lowest quality in the datastore
 * @return hostlist with lowest quality
 */
static struct Hostlist *
linked_list_get_lowest_quality ()
{
  struct Hostlist *pos;
  struct Hostlist *lowest;

  if (linked_list_size == 0)
    return NULL;
  lowest = linked_list_head;
  pos = linked_list_head->next;
  while (pos != NULL)
  {
    if (pos->quality < lowest->quality)
      lowest = pos;
    pos = pos->next;
  }
  return lowest;
}


/**
 * Method to insert a hostlist into the datastore. If datastore
 * contains maximum number of elements, the elements with lowest
 * quality is dismissed
 */
static void
insert_hostlist ()
{
  struct Hostlist *lowest_quality;

  if (MAX_NUMBER_HOSTLISTS <= linked_list_size)
  {
    /* No free entries available, replace existing entry  */
    lowest_quality = linked_list_get_lowest_quality ();
    GNUNET_assert (lowest_quality != NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Removing hostlist with URI `%s' which has the worst quality of all (%llu)\n",
                lowest_quality->hostlist_uri,
                (unsigned long long) lowest_quality->quality);
    GNUNET_CONTAINER_DLL_remove (linked_list_head, linked_list_tail,
                                 lowest_quality);
    linked_list_size--;
    GNUNET_free (lowest_quality);
  }
  GNUNET_CONTAINER_DLL_insert (linked_list_head, linked_list_tail,
                               hostlist_to_test);
  linked_list_size++;
  GNUNET_STATISTICS_set (stats, gettext_noop ("# advertised hostlist URIs"),
                         linked_list_size, GNUNET_NO);
  stat_testing_hostlist = GNUNET_NO;
}


/**
 * Method updating hostlist statistics
 */
static void
update_hostlist ()
{
  char *stat;

  if (((stat_use_bootstrap == GNUNET_NO) && (NULL != current_hostlist)) ||
      ((stat_testing_hostlist == GNUNET_YES) && (NULL != current_hostlist)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Updating hostlist statics for URI `%s'\n",
                current_hostlist->hostlist_uri);
    current_hostlist->hello_count = stat_hellos_obtained;
    current_hostlist->time_last_usage = GNUNET_TIME_absolute_get ();
    current_hostlist->quality =
        checked_add (current_hostlist->quality,
                     (stat_hellos_obtained * HOSTLIST_SUCCESSFUL_HELLO));
    if (GNUNET_YES == stat_download_successful)
    {
      current_hostlist->times_used++;
      current_hostlist->quality =
          checked_add (current_hostlist->quality, HOSTLIST_SUCCESSFUL_DOWNLOAD);
      GNUNET_asprintf (&stat, gettext_noop ("# advertised URI `%s' downloaded"),
                       current_hostlist->hostlist_uri);

      GNUNET_STATISTICS_update (stats, stat, 1, GNUNET_YES);
      GNUNET_free (stat);
    }
    else
      current_hostlist->quality =
          checked_sub (current_hostlist->quality, HOSTLIST_FAILED_DOWNLOAD);
  }
  current_hostlist = NULL;
  /* Alternating the usage of preconfigured and learned hostlists */

  if (stat_testing_hostlist == GNUNET_YES)
    return;

  if (GNUNET_YES == stat_learning)
  {
    if (stat_use_bootstrap == GNUNET_YES)
      stat_use_bootstrap = GNUNET_NO;
    else
      stat_use_bootstrap = GNUNET_YES;
  }
  else
    stat_use_bootstrap = GNUNET_YES;
}

/**
 * Clean up the state from the task that downloaded the
 * hostlist and schedule the next task.
 */
static void
clean_up ()
{
  CURLMcode mret;

  if ((stat_testing_hostlist == GNUNET_YES) &&
      (GNUNET_NO == stat_download_successful) && (NULL != hostlist_to_test))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _
                ("Advertised hostlist with URI `%s' could not be downloaded. Advertised URI gets dismissed.\n"),
                hostlist_to_test->hostlist_uri);
  }

  if (stat_testing_hostlist == GNUNET_YES)
  {
    stat_testing_hostlist = GNUNET_NO;
  }
  if (NULL != hostlist_to_test)
  {
    GNUNET_free (hostlist_to_test);
    hostlist_to_test = NULL;
  }

  if (multi != NULL)
  {
    mret = curl_multi_remove_handle (multi, curl);
    if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_remove_handle", __FILE__, __LINE__,
                  curl_multi_strerror (mret));
    }
    mret = curl_multi_cleanup (multi);
    if (mret != CURLM_OK)
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("%s failed at %s:%d: `%s'\n"),
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
  stat_bytes_downloaded = 0;
  stat_download_in_progress = GNUNET_NO;
}


/**
 * Task that is run when we are ready to receive more data from the hostlist
 * server.
 *
 * @param cls closure, unused
 * @param tc task context, unused
 */
static void
task_download (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Ask CURL for the select set and then schedule the
 * receiving task with the scheduler.
 */
static void
download_prepare ()
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
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("%s failed at %s:%d: `%s'\n"),
                "curl_multi_fdset", __FILE__, __LINE__,
                curl_multi_strerror (mret));
    clean_up ();
    return;
  }
  mret = curl_multi_timeout (multi, &timeout);
  if (mret != CURLM_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("%s failed at %s:%d: `%s'\n"),
                "curl_multi_timeout", __FILE__, __LINE__,
                curl_multi_strerror (mret));
    clean_up ();
    return;
  }
  rtime =
      GNUNET_TIME_relative_min (GNUNET_TIME_absolute_get_remaining (end_time),
                                GNUNET_TIME_relative_multiply
                                (GNUNET_TIME_UNIT_MILLISECONDS, timeout));
  grs = GNUNET_NETWORK_fdset_create ();
  gws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (grs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (gws, &ws, max + 1);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Scheduling task for hostlist download using cURL\n");
  ti_download =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   rtime, grs, gws,
                                   &task_download, multi);
  GNUNET_NETWORK_fdset_destroy (gws);
  GNUNET_NETWORK_fdset_destroy (grs);
}


/**
 * Task that is run when we are ready to receive more data from the hostlist
 * server.
 *
 * @param cls closure, unused
 * @param tc task context, unused
 */
static void
task_download (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int running;
  struct CURLMsg *msg;
  CURLMcode mret;

  ti_download = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Shutdown requested while trying to download hostlist from `%s'\n",
                current_url);
    update_hostlist ();
    clean_up ();
    return;
  }
  if (GNUNET_TIME_absolute_get_remaining (end_time).rel_value == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Timeout trying to download hostlist from `%s'\n"),
                current_url);
    update_hostlist ();
    clean_up ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Ready for processing hostlist client request\n");
  do
  {
    running = 0;
    if (stat_bytes_downloaded > MAX_BYTES_PER_HOSTLISTS)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Download limit of %u bytes exceeded, stopping download\n"),
                  MAX_BYTES_PER_HOSTLISTS);
      clean_up ();
      return;
    }
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
          if ((msg->data.result != CURLE_OK) &&
              (msg->data.result != CURLE_GOT_NOTHING))
            GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                        _("Download of hostlist from `%s' failed: `%s'\n"),
                        current_url,
                        curl_easy_strerror (msg->data.result));
          else
          {
            GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                        _("Download of hostlist `%s' completed.\n"),
                        current_url);
            stat_download_successful = GNUNET_YES;
            update_hostlist ();
            if (GNUNET_YES == stat_testing_hostlist)
            {
              GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                          _
                          ("Adding successfully tested hostlist `%s' datastore.\n"),
                          current_url);
              insert_hostlist ();
              hostlist_to_test = NULL;
              stat_testing_hostlist = GNUNET_NO;
            }
          }
          clean_up ();
          return;
        default:
          break;
        }

      }
      while ((running > 0));
    }
  }
  while (mret == CURLM_CALL_MULTI_PERFORM);

  if (mret != CURLM_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("%s failed at %s:%d: `%s'\n"),
                "curl_multi_perform", __FILE__, __LINE__,
                curl_multi_strerror (mret));
    clean_up ();
  }
  download_prepare ();
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


  current_url = download_get_url ();
  if (current_url == NULL)
    return;
  curl = curl_easy_init ();
  multi = NULL;
  if (curl == NULL)
  {
    GNUNET_break (0);
    clean_up ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO | GNUNET_ERROR_TYPE_BULK,
              _("Bootstrapping using hostlist at `%s'.\n"), current_url);

  stat_download_in_progress = GNUNET_YES;
  stat_download_successful = GNUNET_NO;
  stat_hellos_obtained = 0;
  stat_bytes_downloaded = 0;

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# hostlist downloads initiated"), 1,
                            GNUNET_NO);
  if (proxy != NULL)
    CURL_EASY_SETOPT (curl, CURLOPT_PROXY, proxy);
  download_pos = 0;
  stat_bogus_url = 0;
  CURL_EASY_SETOPT (curl, CURLOPT_WRITEFUNCTION, &callback_download);
  if (ret != CURLE_OK)
  {
    clean_up ();
    return;
  }
  CURL_EASY_SETOPT (curl, CURLOPT_WRITEDATA, NULL);
  if (ret != CURLE_OK)
  {
    clean_up ();
    return;
  }
  CURL_EASY_SETOPT (curl, CURLOPT_FOLLOWLOCATION, 1);
  CURL_EASY_SETOPT (curl, CURLOPT_MAXREDIRS, 4);
  /* no need to abort if the above failed */
  CURL_EASY_SETOPT (curl, CURLOPT_URL, current_url);
  if (ret != CURLE_OK)
  {
    clean_up ();
    return;
  }
  CURL_EASY_SETOPT (curl, CURLOPT_FAILONERROR, 1);
#if 0
  CURL_EASY_SETOPT (curl, CURLOPT_VERBOSE, 1);
#endif
  CURL_EASY_SETOPT (curl, CURLOPT_BUFFERSIZE, GNUNET_SERVER_MAX_MESSAGE_SIZE);
  if (0 == strncmp (current_url, "http", 4))
    CURL_EASY_SETOPT (curl, CURLOPT_USERAGENT, "GNUnet");
  CURL_EASY_SETOPT (curl, CURLOPT_CONNECTTIMEOUT, 60L);
  CURL_EASY_SETOPT (curl, CURLOPT_TIMEOUT, 60L);
#if 0
  /* this should no longer be needed; we're now single-threaded! */
  CURL_EASY_SETOPT (curl, CURLOPT_NOSIGNAL, 1);
#endif
  multi = curl_multi_init ();
  if (multi == NULL)
  {
    GNUNET_break (0);
    /* clean_up (); */
    return;
  }
  mret = curl_multi_add_handle (multi, curl);
  if (mret != CURLM_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("%s failed at %s:%d: `%s'\n"),
                "curl_multi_add_handle", __FILE__, __LINE__,
                curl_multi_strerror (mret));
    mret = curl_multi_cleanup (multi);
    if (mret != CURLM_OK)
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_cleanup", __FILE__, __LINE__,
                  curl_multi_strerror (mret));
    multi = NULL;
    clean_up ();
    return;
  }
  end_time = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES);
  download_prepare ();
}


static void
task_download_dispatcher (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  ti_download_dispatcher_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Download is initiated...\n");
  if (GNUNET_NO == stat_download_in_progress)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Download can start immediately...\n");
    download_hostlist ();
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Download in progess, have to wait...\n");
    ti_download_dispatcher_task =
        GNUNET_SCHEDULER_add_delayed (WAITING_INTERVALL,
                                      &task_download_dispatcher, NULL);
  }
}

/**
 * Task that checks if we should try to download a hostlist.
 * If so, we initiate the download, otherwise we schedule
 * this task again for a later time.
 */
static void
task_check (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static int once;
  struct GNUNET_TIME_Relative delay;

  ti_check_download = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  if (stats == NULL)
  {
    curl_global_cleanup ();
    return;                     /* in shutdown */
  }
  if ( (stat_connection_count < MIN_CONNECTIONS) &&
       (GNUNET_SCHEDULER_NO_TASK == ti_download_dispatcher_task) )
    ti_download_dispatcher_task =
        GNUNET_SCHEDULER_add_now (&task_download_dispatcher, NULL);

  delay = hostlist_delay;
  if (hostlist_delay.rel_value == 0)
    hostlist_delay = GNUNET_TIME_UNIT_SECONDS;
  else
    hostlist_delay = GNUNET_TIME_relative_multiply (hostlist_delay, 2);
  if (hostlist_delay.rel_value >
      GNUNET_TIME_UNIT_HOURS.rel_value * (1 + stat_connection_count))
    hostlist_delay =
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS,
                                       (1 + stat_connection_count));
  GNUNET_STATISTICS_set (stats,
                         gettext_noop
                         ("# milliseconds between hostlist downloads"),
                         hostlist_delay.rel_value, GNUNET_YES);
  if (0 == once)
  {
    delay = GNUNET_TIME_UNIT_ZERO;
    once = 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _
              ("Have %u/%u connections.  Will consider downloading hostlist in %llums\n"),
              stat_connection_count, MIN_CONNECTIONS,
              (unsigned long long) delay.rel_value);
  ti_check_download = GNUNET_SCHEDULER_add_delayed (delay, &task_check, NULL);
}


/**
 * This tasks sets hostlist testing to allowed after intervall between to testings is reached
 *
 * @param cls closure
 * @param tc TaskContext
 */
static void
task_testing_intervall_reset (void *cls,
                              const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  ti_testing_intervall_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  stat_testing_allowed = GNUNET_OK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Testing new hostlist advertisements is allowed again\n");
}


/**
 * Task that writes hostlist entries to a file on a regular base
 *
 * @param cls closure
 * @param tc TaskContext
 */
static void
task_hostlist_saving (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  ti_saving_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Scheduled saving of hostlists\n"));
  save_hostlist_file (GNUNET_NO);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Hostlists will be saved to file again in %llums\n"),
              (unsigned long long) SAVING_INTERVALL.rel_value);
  ti_saving_task =
      GNUNET_SCHEDULER_add_delayed (SAVING_INTERVALL, &task_hostlist_saving,
                                    NULL);
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 */
static void
handler_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
                 const struct GNUNET_ATS_Information *atsi,
                 unsigned int atsi_count)
{
  GNUNET_assert (stat_connection_count < UINT_MAX);
  stat_connection_count++;
  GNUNET_STATISTICS_update (stats, gettext_noop ("# active connections"), 1,
                            GNUNET_NO);
}


/**
 * Method called whenever a given peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
handler_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert (stat_connection_count > 0);
  stat_connection_count--;
  GNUNET_STATISTICS_update (stats, gettext_noop ("# active connections"), -1,
                            GNUNET_NO);
}


/**
 * Method called whenever an advertisement message arrives.
 *
 * @param cls closure (always NULL)
 * @param peer the peer sending the message
 * @param message the actual message
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handler_advertisement (void *cls, const struct GNUNET_PeerIdentity *peer,
                       const struct GNUNET_MessageHeader *message,
                       const struct GNUNET_ATS_Information *atsi,
                       unsigned int atsi_count)
{
  size_t size;
  size_t uri_size;
  const struct GNUNET_MessageHeader *incoming;
  const char *uri;
  struct Hostlist *hostlist;

  GNUNET_assert (ntohs (message->type) ==
                 GNUNET_MESSAGE_TYPE_HOSTLIST_ADVERTISEMENT);
  size = ntohs (message->size);
  if (size <= sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  incoming = (const struct GNUNET_MessageHeader *) message;
  uri = (const char *) &incoming[1];
  uri_size = size - sizeof (struct GNUNET_MessageHeader);
  if (uri[uri_size - 1] != '\0')
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Hostlist client recieved advertisement from `%s' containing URI `%s'\n",
              GNUNET_i2s (peer), uri);
  if (GNUNET_NO != linked_list_contains (uri))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "URI `%s' is already known\n", uri);
    return GNUNET_OK;
  }

  if (GNUNET_NO == stat_testing_allowed)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Currently not accepting new advertisements: interval between to advertisements is not reached\n");
    return GNUNET_SYSERR;
  }
  if (GNUNET_YES == stat_testing_hostlist)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Currently not accepting new advertisements: we are already testing a hostlist\n");
    return GNUNET_SYSERR;
  }

  hostlist = GNUNET_malloc (sizeof (struct Hostlist) + uri_size);
  hostlist->hostlist_uri = (const char *) &hostlist[1];
  memcpy (&hostlist[1], uri, uri_size);
  hostlist->time_creation = GNUNET_TIME_absolute_get ();
  hostlist->quality = HOSTLIST_INITIAL;
  hostlist_to_test = hostlist;

  stat_testing_hostlist = GNUNET_YES;
  stat_testing_allowed = GNUNET_NO;
  ti_testing_intervall_task =
      GNUNET_SCHEDULER_add_delayed (TESTING_INTERVAL,
                                    &task_testing_intervall_reset, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Testing new hostlist advertisements is locked for the next %u ms\n",
              TESTING_INTERVAL.rel_value);

  ti_download_dispatcher_task =
      GNUNET_SCHEDULER_add_now (&task_download_dispatcher, NULL);

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
  sget = NULL;
  GNUNET_assert (stats != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Statistics request done, scheduling hostlist download\n");
  ti_check_download = GNUNET_SCHEDULER_add_now (&task_check, NULL);
}


static int
process_stat (void *cls, const char *subsystem, const char *name,
              uint64_t value, int is_persistent)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Initial time between hostlist downloads is %llums\n"),
              (unsigned long long) value);
  hostlist_delay.rel_value = value;
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
  struct Hostlist *hostlist;

  uri = NULL;
  uint32_t times_used;
  uint32_t hellos_returned;
  uint64_t quality;
  uint64_t last_used;
  uint64_t created;
  uint32_t counter;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "HOSTLIST", "HOSTLISTFILE",
                                               &filename))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("No `%s' specified in `%s' configuration, cannot load hostlists from file.\n"),
                "HOSTLISTFILE", "HOSTLIST");
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Loading saved hostlist entries from file `%s' \n"), filename);
  if (GNUNET_NO == GNUNET_DISK_file_test (filename))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Hostlist file `%s' is not existing\n"), filename);
    GNUNET_free (filename);
    return;
  }

  struct GNUNET_BIO_ReadHandle *rh = GNUNET_BIO_read_open (filename);

  if (NULL == rh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _
                ("Could not open file `%s' for reading to load hostlists: %s\n"),
                filename, STRERROR (errno));
    GNUNET_free (filename);
    return;
  }

  counter = 0;
  while ((GNUNET_OK == GNUNET_BIO_read_string (rh, "url", &uri, MAX_URL_LEN)) &&
         (NULL != uri) && (GNUNET_OK == GNUNET_BIO_read_int32 (rh, &times_used))
         && (GNUNET_OK == GNUNET_BIO_read_int64 (rh, &quality)) &&
         (GNUNET_OK == GNUNET_BIO_read_int64 (rh, &last_used)) &&
         (GNUNET_OK == GNUNET_BIO_read_int64 (rh, &created)) &&
         (GNUNET_OK == GNUNET_BIO_read_int32 (rh, &hellos_returned)))
  {
    hostlist = GNUNET_malloc (sizeof (struct Hostlist) + strlen (uri) + 1);
    hostlist->hello_count = hellos_returned;
    hostlist->hostlist_uri = (const char *) &hostlist[1];
    memcpy (&hostlist[1], uri, strlen (uri) + 1);
    hostlist->quality = quality;
    hostlist->time_creation.abs_value = created;
    hostlist->time_last_usage.abs_value = last_used;
    GNUNET_CONTAINER_DLL_insert (linked_list_head, linked_list_tail, hostlist);
    linked_list_size++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Added hostlist entry eith URI `%s' \n",
                hostlist->hostlist_uri);
    GNUNET_free (uri);
    uri = NULL;
    counter++;
    if (counter >= MAX_NUMBER_HOSTLISTS)
      break;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("%u hostlist URIs loaded from file\n"),
              counter);
  GNUNET_STATISTICS_set (stats, gettext_noop ("# hostlist URIs read from file"),
                         counter, GNUNET_YES);
  GNUNET_STATISTICS_set (stats, gettext_noop ("# advertised hostlist URIs"),
                         linked_list_size, GNUNET_NO);

  GNUNET_free_non_null (uri);
  emsg = NULL;
  GNUNET_BIO_read_close (rh, &emsg);
  if (emsg != NULL)
    GNUNET_free (emsg);
  GNUNET_free (filename);
}


/**
 * Method to save persistent hostlist file during hostlist client shutdown
 * @param shutdown set if called because of shutdown, entries in linked list will be destroyed
 */
static void
save_hostlist_file (int shutdown)
{
  char *filename;
  struct Hostlist *pos;
  struct GNUNET_BIO_WriteHandle *wh;
  int ok;
  uint32_t counter;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "HOSTLIST", "HOSTLISTFILE",
                                               &filename))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("No `%s' specified in `%s' configuration, cannot save hostlists to file.\n"),
                "HOSTLISTFILE", "HOSTLIST");
    return;
  }
  if (GNUNET_SYSERR == GNUNET_DISK_directory_create_for_file (filename))
  {
    GNUNET_free (filename);
    return;
  }
  wh = GNUNET_BIO_write_open (filename);
  if (NULL == wh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Could not open file `%s' for writing to save hostlists: %s\n"),
                filename, STRERROR (errno));
    GNUNET_free (filename);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Writing %u hostlist URIs to `%s'\n"),
              linked_list_size, filename);
  /* add code to write hostlists to file using bio */
  ok = GNUNET_YES;
  counter = 0;
  while (NULL != (pos = linked_list_head))
  {
    if (GNUNET_YES == shutdown)
    {
      GNUNET_CONTAINER_DLL_remove (linked_list_head, linked_list_tail, pos);
      linked_list_size--;
    }
    if (GNUNET_YES == ok)
    {
      if ((GNUNET_OK != GNUNET_BIO_write_string (wh, pos->hostlist_uri)) ||
          (GNUNET_OK != GNUNET_BIO_write_int32 (wh, pos->times_used)) ||
          (GNUNET_OK != GNUNET_BIO_write_int64 (wh, pos->quality)) ||
          (GNUNET_OK !=
           GNUNET_BIO_write_int64 (wh, pos->time_last_usage.abs_value)) ||
          (GNUNET_OK !=
           GNUNET_BIO_write_int64 (wh, pos->time_creation.abs_value)) ||
          (GNUNET_OK != GNUNET_BIO_write_int32 (wh, pos->hello_count)))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _("Error writing hostlist URIs to file `%s'\n"), filename);
        ok = GNUNET_NO;
      }
    }

    if (GNUNET_YES == shutdown)
      GNUNET_free (pos);
    counter++;
    if (counter >= MAX_NUMBER_HOSTLISTS)
      break;
  }
  GNUNET_STATISTICS_set (stats,
                         gettext_noop ("# hostlist URIs written to file"),
                         counter, GNUNET_YES);

  if (GNUNET_OK != GNUNET_BIO_write_close (wh))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Error writing hostlist URIs to file `%s'\n"), filename);
  GNUNET_free (filename);
}

/**
 * Start downloading hostlists from hostlist servers as necessary.
 */
int
GNUNET_HOSTLIST_client_start (const struct GNUNET_CONFIGURATION_Handle *c,
                              struct GNUNET_STATISTICS_Handle *st,
                              GNUNET_CORE_ConnectEventHandler *ch,
                              GNUNET_CORE_DisconnectEventHandler *dh,
                              GNUNET_CORE_MessageCallback *msgh, int learn)
{
  char *filename;
  int result;

  GNUNET_assert (NULL != st);
  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  transport = GNUNET_TRANSPORT_connect (c, NULL, NULL, NULL, NULL, NULL);
  if (NULL == transport)
  {
    curl_global_cleanup ();
    return GNUNET_SYSERR;
  }
  cfg = c;
  stats = st;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "HOSTLIST", "HTTP-PROXY",
                                             &proxy))
    proxy = NULL;
  stat_learning = learn;
  *ch = &handler_connect;
  *dh = &handler_disconnect;
  linked_list_head = NULL;
  linked_list_tail = NULL;
  stat_use_bootstrap = GNUNET_YES;
  stat_testing_hostlist = GNUNET_NO;
  stat_testing_allowed = GNUNET_YES;

  if (GNUNET_YES == stat_learning)
  {
    *msgh = &handler_advertisement;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Learning is enabled on this peer\n"));
    load_hostlist_file ();
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Hostlists will be saved to file again in  %llums\n"),
                (unsigned long long) SAVING_INTERVALL.rel_value);
    ti_saving_task =
        GNUNET_SCHEDULER_add_delayed (SAVING_INTERVALL, &task_hostlist_saving,
                                      NULL);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Learning is not enabled on this peer\n"));
    *msgh = NULL;
    if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_filename (cfg, "HOSTLIST",
                                                 "HOSTLISTFILE", &filename))
    {
      if (GNUNET_YES == GNUNET_DISK_file_test (filename))
      {
        result = remove (filename);
        if (result == 0)
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      _
                      ("Since learning is not enabled on this peer, hostlist file `%s' was removed\n"),
                      filename);
        else
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("Hostlist file `%s' could not be removed\n"), filename);
      }
    }
    GNUNET_free (filename);
  }
  sget = GNUNET_STATISTICS_get (stats, "hostlist",
				gettext_noop
				("# milliseconds between hostlist downloads"),
				GNUNET_TIME_UNIT_MINUTES, &primary_task, &process_stat,
				NULL);
  return GNUNET_OK;
}


/**
 * Stop downloading hostlists from hostlist servers as necessary.
 */
void
GNUNET_HOSTLIST_client_stop ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Hostlist client shutdown\n");
  if (NULL != sget)
  {
    GNUNET_STATISTICS_get_cancel (sget);
    sget = NULL;
  }
  stats = NULL;
  if (GNUNET_YES == stat_learning)
    save_hostlist_file (GNUNET_YES);
  if (ti_saving_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (ti_saving_task);
    ti_saving_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (ti_download_dispatcher_task != GNUNET_SCHEDULER_NO_TASK)
    {
    GNUNET_SCHEDULER_cancel (ti_download_dispatcher_task);
    ti_download_dispatcher_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (ti_testing_intervall_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (ti_testing_intervall_task);
    ti_testing_intervall_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (ti_download != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (ti_download);
    ti_download = GNUNET_SCHEDULER_NO_TASK;
  }
  if (ti_check_download != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (ti_check_download);
    ti_check_download = GNUNET_SCHEDULER_NO_TASK;
    curl_global_cleanup ();
  }
  if (transport != NULL)
  {
    GNUNET_TRANSPORT_disconnect (transport);
    transport = NULL;
  }
  GNUNET_free_non_null (proxy);
  proxy = NULL;
  cfg = NULL;
}

/* end of hostlist-client.c */
