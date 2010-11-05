/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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

/*
 * Code in this file is originally based on the miniupnp library.
 * Copyright (c) 2005-2009, Thomas BERNARD. All rights reserved.
 *
 * Original licence:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   * The name of the author may not be used to endorse or promote products
 * 	   derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file nat/upnp-discover.c
 * @brief Look for UPnP IGD devices
 *
 * @author Milan Bouchet-Valat
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "upnp-discover.h"
#include "upnp-reply-parse.h"
#include "upnp-igd-parse.h"
#include "upnp-minixml.h"

#define DISCOVER_BUFSIZE 512
#define DESCRIPTION_BUFSIZE 2048
#define CURL_EASY_SETOPT(c, a, b) do { ret = curl_easy_setopt(c, a, b); if (ret != CURLE_OK) GNUNET_log(GNUNET_ERROR_TYPE_WARNING, _("%s failed at %s:%d: `%s'\n"), "curl_easy_setopt", __FILE__, __LINE__, curl_easy_strerror(ret)); } while (0)
#define PRINT_SOCKET_ERROR(a) GNUNET_log_from(GNUNET_ERROR_TYPE_WARNING, "UPnP", _("%s failed at %s:%d: '%s'\n"), a, __FILE__, __LINE__, strerror (errno));


/**
 * Callback function called when download is finished.
 *
 * @param data the contents of the downloaded file, or NULL
 * @param cls closure passed via download_device_description()
 */
typedef void (*download_cb) (char *data, void *cls);

/**
 * Private closure used by download_device_description() and it's callbacks.
 */
struct download_cls
{
  /**
   * curl_easy handle.
   */
  CURL *curl;

  /**
   * curl_multi handle.
   */
  CURLM *multi;

  /**
   * URL of the file to download.
   */
  char *url;

  /**
   * Time corresponding to timeout wanted by the caller.
   */
  struct GNUNET_TIME_Absolute end_time;

  /**
   * Buffer to store downloaded content.
   */
  char download_buffer[DESCRIPTION_BUFSIZE];

  /**
   * Size of the already downloaded content.
   */
  size_t download_pos;

  /**
   * User callback to trigger when done.
   */
  download_cb caller_cb;

  /**
   * User closure to pass to caller_cb.
   */
  void *caller_cls;
};

/**
 * Clean up the state of CURL multi handle and that of
 * the only easy handle it uses.
 */
static void
download_clean_up (struct download_cls *cls)
{
  CURLMcode mret;

  mret = curl_multi_cleanup (cls->multi);
  if (mret != CURLM_OK)
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "UPnP",
                     _("%s failed at %s:%d: `%s'\n"),
                     "curl_multi_cleanup", __FILE__, __LINE__,
                     curl_multi_strerror (mret));

  curl_easy_cleanup (cls->curl);
  GNUNET_free (cls);
}

/**
 * Process downloaded bits by calling callback on each HELLO.
 *
 * @param ptr buffer with downloaded data
 * @param size size of a record
 * @param nmemb number of records downloaded
 * @param ctx closure
 * @return number of bytes that were processed (always size*nmemb)
 */
static size_t
callback_download (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  struct download_cls *cls = ctx;
  const char *cbuf = ptr;
  size_t total;
  size_t cpy;

  total = size * nmemb;
  if (total == 0)
    return total;               /* ok, no data */

  cpy = GNUNET_MIN (total, DESCRIPTION_BUFSIZE - cls->download_pos - 1);
  memcpy (&cls->download_buffer[cls->download_pos], cbuf, cpy);
  cbuf += cpy;
  cls->download_pos += cpy;

#if DEBUG_UPNP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UPnP",
                   "Downloaded %d records of size %d, download position: %d\n",
                   size, nmemb, cls->download_pos);
#endif

  return total;
}

static void
task_download (struct download_cls *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Ask CURL for the select set and then schedule the
 * receiving task with the scheduler.
 */
static void
download_prepare (struct download_cls *cls)
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
  mret = curl_multi_fdset (cls->multi, &rs, &ws, &es, &max);
  if (mret != CURLM_OK)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "UPnP",
                       _("%s failed at %s:%d: `%s'\n"),
                       "curl_multi_fdset", __FILE__, __LINE__,
                       curl_multi_strerror (mret));
      download_clean_up (cls);
      cls->caller_cb (NULL, cls->caller_cls);
      return;
    }
  mret = curl_multi_timeout (cls->multi, &timeout);
  if (mret != CURLM_OK)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "UPnP",
                       _("%s failed at %s:%d: `%s'\n"),
                       "curl_multi_timeout", __FILE__, __LINE__,
                       curl_multi_strerror (mret));
      download_clean_up (cls);
      cls->caller_cb (NULL, cls->caller_cls);
      return;
    }
  rtime =
    GNUNET_TIME_relative_min (GNUNET_TIME_absolute_get_remaining
                              (cls->end_time),
                              GNUNET_TIME_relative_multiply
                              (GNUNET_TIME_UNIT_MILLISECONDS, timeout));
  grs = GNUNET_NETWORK_fdset_create ();
  gws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (grs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (gws, &ws, max + 1);

  GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                               GNUNET_SCHEDULER_NO_TASK,
                               rtime,
                               grs,
                               gws,
                               (GNUNET_SCHEDULER_Task) & task_download, cls);
  GNUNET_NETWORK_fdset_destroy (gws);
  GNUNET_NETWORK_fdset_destroy (grs);
}

/**
 * Task that is run when we are ready to receive more data from the device.
 *
 * @param cls closure
 * @param tc task context
 */
static void
task_download (struct download_cls *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  int running;
  struct CURLMsg *msg;
  CURLMcode mret;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    {
#if DEBUG_UPNP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UPnP",
                       "Shutdown requested while trying to download device description from `%s'\n",
                       cls->url);
#endif
      cls->caller_cb (NULL, cls->caller_cls);
      download_clean_up (cls);
      return;
    }
  if (GNUNET_TIME_absolute_get_remaining (cls->end_time).rel_value == 0)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "UPnP",
                       _
                       ("Timeout trying to download UPnP device description from '%s'\n"),
                       cls->url);
      cls->caller_cb (NULL, cls->caller_cls);
      download_clean_up (cls);
      return;
    }

  do
    {
      running = 0;
      mret = curl_multi_perform (cls->multi, &running);

      if (running == 0)
        {
          do
            {
              msg = curl_multi_info_read (cls->multi, &running);
              GNUNET_break (msg != NULL);
              if (msg == NULL)
                break;

              if ((msg->data.result != CURLE_OK) &&
                  (msg->data.result != CURLE_GOT_NOTHING))
                {
                  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                              _("%s failed for `%s' at %s:%d: `%s'\n"),
                              "curl_multi_perform",
                              cls->url,
                              __FILE__,
                              __LINE__,
                              curl_easy_strerror (msg->data.result));
                  cls->caller_cb (NULL, cls->caller_cls);
                }
              else
                {
                  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UPnP",
                                   _
                                   ("Download of device description `%s' completed.\n"),
                                   cls->url);
                  cls->caller_cb (GNUNET_strdup (cls->download_buffer),
                                  cls->caller_cls);
                }

              download_clean_up (cls);
              return;
            }
          while ((running > 0));
        }
    }
  while (mret == CURLM_CALL_MULTI_PERFORM);

  if (mret != CURLM_OK)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "UPnP",
                       _("%s failed at %s:%d: `%s'\n"),
                       "curl_multi_perform", __FILE__, __LINE__,
                       curl_multi_strerror (mret));
      download_clean_up (cls);
      cls->caller_cb (NULL, cls->caller_cls);
    }

  download_prepare (cls);
}


/**
 * Download description from devices.
 *
 * @param url URL of the file to download
 * @param caller_cb user function to call when done
 * @caller_cls closure to pass to caller_cb
 */
void
download_device_description (char *url, download_cb caller_cb,
                             void *caller_cls)
{
  CURL *curl;
  CURLM *multi;
  CURLcode ret;
  CURLMcode mret;
  struct download_cls *cls;

  cls = GNUNET_malloc (sizeof (struct download_cls));

  curl = curl_easy_init ();
  if (curl == NULL)
    goto error;

  CURL_EASY_SETOPT (curl, CURLOPT_WRITEFUNCTION, &callback_download);
  if (ret != CURLE_OK)
    goto error;

  CURL_EASY_SETOPT (curl, CURLOPT_WRITEDATA, cls);
  if (ret != CURLE_OK)
    goto error;

  CURL_EASY_SETOPT (curl, CURLOPT_FOLLOWLOCATION, 1);
  CURL_EASY_SETOPT (curl, CURLOPT_MAXREDIRS, 4);
  /* no need to abort if the above failed */
  CURL_EASY_SETOPT (curl, CURLOPT_URL, url);
  if (ret != CURLE_OK)
    goto error;

  CURL_EASY_SETOPT (curl, CURLOPT_FAILONERROR, 1);
  CURL_EASY_SETOPT (curl, CURLOPT_BUFFERSIZE, DESCRIPTION_BUFSIZE);
  CURL_EASY_SETOPT (curl, CURLOPT_USERAGENT, "GNUnet");
  CURL_EASY_SETOPT (curl, CURLOPT_CONNECTTIMEOUT, 60L);
  CURL_EASY_SETOPT (curl, CURLOPT_TIMEOUT, 60L);

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
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "UPnP",
                       _("%s failed at %s:%d: `%s'\n"),
                       "curl_multi_add_handle", __FILE__, __LINE__,
                       curl_multi_strerror (mret));
      mret = curl_multi_cleanup (multi);
      if (mret != CURLM_OK)
        GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "UPnP",
                         _("%s failed at %s:%d: `%s'\n"),
                         "curl_multi_cleanup", __FILE__, __LINE__,
                         curl_multi_strerror (mret));
      goto error;
      return;
    }

#if DEBUG_UPNP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UPnP",
                   "Preparing to download device description from '%s'\n",
                   url);
#endif

  cls->curl = curl;
  cls->multi = multi;
  cls->url = url;
  cls->end_time = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES);
  memset (cls->download_buffer, 0, DESCRIPTION_BUFSIZE);
  cls->download_pos = 0;
  cls->caller_cb = caller_cb;
  cls->caller_cls = caller_cls;
  download_prepare (cls);
  return;


error:
  GNUNET_break (0);
  GNUNET_free (cls);
  curl_easy_cleanup (curl);
  caller_cb (NULL, caller_cls);
}

/**
 * Parse SSDP packet received in reply to a M-SEARCH message.
 *
 * @param reply contents of the packet
 * @param size length of reply
 * @param location address of a pointer that will be set to the start
 *   of the "location" field
 * @param location_size pointer where to store the length of the "location" field
 * @param st pointer address of a pointer that will be set to the start
 *   of the "st" (search target) field
 * @param st_size pointer where to store the length of the "st" field
 * The strings are NOT null terminated */
static void
parse_msearch_reply (const char *reply, int size,
                     const char **location, int *location_size,
                     const char **st, int *st_size)
{
  int a, b, i;

  i = 0;
  b = 0;
  /* Start of the line */
  a = i;

  while (i < size)
    {
      switch (reply[i])
        {
        case ':':
          if (b == 0)
            /* End of the "header" */
            b = i;
          break;
        case '\x0a':
        case '\x0d':
          if (b != 0)
            {
              do
                {
                  b++;
                }
              while (reply[b] == ' ');

              if (0 == strncasecmp (reply + a, "location", 8))
                {
                  *location = reply + b;
                  *location_size = i - b;
                }
              else if (0 == strncasecmp (reply + a, "st", 2))
                {
                  *st = reply + b;
                  *st_size = i - b;
                }

              b = 0;
            }

          a = i + 1;
          break;
        default:
          break;
        }

      i++;
    }
}

/**
 * Standard port for UPnP discovery (SSDP protocol).
 */
#define PORT 1900

/**
 * Convert a constant integer into a string.
 */
#define XSTR(s) STR(s)
#define STR(s) #s

/**
 * Standard IPv4 multicast adress for UPnP discovery (SSDP protocol).
 */
#define UPNP_MCAST_ADDR "239.255.255.250"

/**
 * Standard IPv6 multicast adress for UPnP discovery (SSDP protocol).
 */
#define UPNP_MCAST_ADDR6 "FF02:0:0:0:0:0:0:F"

/**
 * Size of the buffer needed to store SSDP requests we send.
 */
#define UPNP_DISCOVER_BUFSIZE 1536

/**
 * Description of a UPnP device containing everything
 * we may need to control it.
 *
 * Meant to be member of a chained list.
 */
struct UPNP_Dev_
{
  /**
   * Next device in the list, if any.
   */
  struct UPNP_Dev_ *pNext;

  /**
   * Path to the file describing the device.
   */
  char *desc_url;

  /**
   * UPnP search target.
   */
  char *st;

  /**
   * Service type associated with the control_url for the device.
   */
  char *service_type;

  /**
   * URL to send commands to.
   */
  char *control_url;

  /**
   * Whether the device is currently connected to the WAN.
   */
  int is_connected;

  /**
   * IGD Data associated with the device.
   */
  struct UPNP_IGD_Data_ *data;
};

/**
 * Private closure used by UPNP_discover() and its callbacks.
 */
struct UPNP_discover_cls
{
  /**
   * Remote address used for multicast emission and reception.
   */
  struct sockaddr *multicast_addr;

  /**
   * Network handle used to send and receive discovery messages.
   */
  struct GNUNET_NETWORK_Handle *sudp;

  /**
   * fdset used with sudp.
   */
  struct GNUNET_NETWORK_FDSet *fdset;

  /**
   * Connection handle used to download device description.
   */
  struct GNUNET_CONNECTION_Handle *s;

  /**
   * Transmission handle used with s.
   */
  struct GNUNET_CONNECTION_TransmitHandle *th;

  /**
   * Index of the UPnP device type we're currently sending discovery messages to.
   */
  int type_index;

  /**
   * List of discovered devices.
   */
  struct UPNP_Dev_ *dev_list;

  /**
   * Device we're currently fetching description from.
   */
  struct UPNP_Dev_ *current_dev;

  /**
   * User callback to trigger when done.
   */
  UPNP_discover_cb_ caller_cb;

  /**
   * Closure passed to caller_cb.
   */
  void *caller_cls;
};

/**
 * Check that raw_url is absolute, and if not, use ref_url to resolve it:
 * if is_desc_file is GNUNET_YES, the path to the parent of the file is used;
 * if it is GNUNET_NO, ref_url will be considered as the base URL for raw URL.
 *
 * @param ref_url base URL for the device
 * @param is_desc_file whether ref_url is a path to the description file
 * @param raw_url a possibly relative URL
 * @returns a new string with an absolute URL
 */
static char *
get_absolute_url (const char *ref_url, int is_desc_file, const char *raw_url)
{
  char *final_url;

  if ((raw_url[0] == 'h')
      && (raw_url[1] == 't')
      && (raw_url[2] == 't')
      && (raw_url[3] == 'p')
      && (raw_url[4] == ':') && (raw_url[5] == '/') && (raw_url[6] == '/'))
    {
      final_url = GNUNET_strdup (raw_url);
    }
  else
    {
      int n = strlen (raw_url);
      int l = strlen (ref_url);
      int cpy_len = l;
      char *slash;

      /* If base URL is a path to the description file, go one level higher */
      if (is_desc_file == GNUNET_YES)
        {
          slash = strrchr (ref_url, '/');
          cpy_len = slash - ref_url;
        }

      final_url = GNUNET_malloc (l + n + 1);

      /* Add trailing slash to base URL if needed */
      if (raw_url[0] != '/' && ref_url[cpy_len] != '\0')
        final_url[cpy_len++] = '/';

      strncpy (final_url, ref_url, cpy_len);
      strcpy (final_url + cpy_len, raw_url);
      final_url[cpy_len + n] = '\0';
    }

  return final_url;
}


/**
 * Construct control URL for device from its description URL and
 * UPNP_IGD_Data_ information. This involves resolving relative paths
 * and choosing between Common Interface Config and interface-specific
 * paths.
 *
 * @param desc_url URL to the description file of the device
 * @param data IGD information obtained from the description file
 * @returns a URL to control the IGD device, or the empty string
 *   in case of failure
 */
static char *
format_control_urls (const char *desc_url, struct UPNP_IGD_Data_ *data)
{
  const char *ref_url;
  int is_desc_file;

  if (data->base_url[0] != '\0')
    {
      ref_url = data->base_url;
      is_desc_file = GNUNET_NO;
    }
  else
    {
      ref_url = desc_url;
      is_desc_file = GNUNET_YES;
    }

  if (data->control_url[0] != '\0')
    return get_absolute_url (ref_url, is_desc_file, data->control_url);
  else if (data->control_url_CIF[0] != '\0')
    return get_absolute_url (ref_url, is_desc_file, data->control_url_CIF);
  else
    return GNUNET_strdup ("");
}

static void get_valid_igd (struct UPNP_discover_cls *cls);

/**
 * Called when "GetStatusInfo" command finishes. Check whether IGD device reports
 * to be currently connected or not.
 *
 * @param response content of the UPnP message answered by the device
 * @param received number of received bytes stored in response
 * @param data closure from UPNP_discover()
 */
static void
get_valid_igd_connected_cb (char *response, size_t received, void *data)
{
  struct UPNP_discover_cls *cls = data;
  struct UPNP_REPLY_NameValueList_ pdata;
  char *status;
  char *error;

  UPNP_REPLY_parse_ (response, received, &pdata);

  status = UPNP_REPLY_get_value_ (&pdata, "NewConnectionStatus");
  error = UPNP_REPLY_get_value_ (&pdata, "errorCode");

  if (status)
    cls->current_dev->is_connected = (strcmp ("Connected", status) == 0);
  else
    cls->current_dev->is_connected = GNUNET_NO;

  if (error)
    GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "UPnP",
                     _("Could not get UPnP device status: error %s\n"),
                     error);

  GNUNET_free (response);
  UPNP_REPLY_free_ (&pdata);

  /* Go on to next device, or finish discovery process */
  cls->current_dev = cls->current_dev->pNext;
  get_valid_igd (cls);
}

/**
 * Receive contents of the downloaded UPnP IGD description file,
 * and fill UPNP_Dev_ and UPNP_IGD_Data_ structs with this data.
 * Then, schedule UPnP command to check whether device is connected.
 *
 * @param desc UPnP IGD description (in XML)
 * @data closure from UPNP_discover()
 */
static void
get_valid_igd_receive (char *desc, void *data)
{
  struct UPNP_discover_cls *cls = data;
  struct UPNP_IGD_Data_ *igd_data;
  char *buffer;

  if (!desc || strlen (desc) == 0)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "UPnP",
                       "Error getting IGD XML description at %s:%d\n",
                       __FILE__, __LINE__);

      /* Skip device */
      cls->current_dev->data = NULL;
      cls->current_dev->is_connected = GNUNET_NO;
      get_valid_igd (cls);
    }

  igd_data = GNUNET_malloc (sizeof (struct UPNP_IGD_Data_));
  memset (igd_data, 0, sizeof (struct UPNP_IGD_Data_));
  UPNP_IGD_parse_desc_ (desc, strlen (desc), igd_data);

  cls->current_dev->control_url =
    format_control_urls (cls->current_dev->desc_url, igd_data);

  if (igd_data->service_type != '\0')
    cls->current_dev->service_type = GNUNET_strdup (igd_data->service_type);
  else if (igd_data->service_type_CIF != '\0')
    cls->current_dev->service_type =
      GNUNET_strdup (igd_data->service_type_CIF);
  else
    cls->current_dev->service_type = GNUNET_strdup ("");

  cls->current_dev->data = igd_data;

  /* Check whether device is connected */
  buffer = GNUNET_malloc (UPNP_COMMAND_BUFSIZE);
  UPNP_command_ (cls->current_dev->control_url,
                 cls->current_dev->data->service_type,
                 "GetStatusInfo", NULL, buffer, UPNP_COMMAND_BUFSIZE,
                 get_valid_igd_connected_cb, cls);

  GNUNET_free (desc);
}

/**
 * Free a chained list of UPnP devices.
 */
static void
free_dev_list (struct UPNP_Dev_ *devlist)
{
  struct UPNP_Dev_ *next;

  while (devlist)
    {
      next = devlist->pNext;
      GNUNET_free (devlist->control_url);
      GNUNET_free (devlist->service_type);
      GNUNET_free (devlist->desc_url);
      GNUNET_free (devlist->data);
      GNUNET_free (devlist->st);
      GNUNET_free (devlist);
      devlist = next;
    }
}

/**
 * Walk over the list of found devices looking for a connected IGD,
 * if present, or at least a disconnected one.
 */
static void
get_valid_igd (struct UPNP_discover_cls *cls)
{
  struct UPNP_Dev_ *dev;
  int step;

  /* No device was discovered */
  if (!cls->dev_list)
    {
      cls->caller_cb (NULL, NULL, cls->caller_cls);

      GNUNET_free (cls);
      return;
    }
  /* We already walked over all devices, see what we got,
   * and return the device with the best state we have. */
  else if (cls->current_dev == NULL)
    {
      for (step = 1; step <= 3; step++)
        {
          for (dev = cls->dev_list; dev; dev = dev->pNext)
            {
#if DEBUG_UPNP
              GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UPnP",
                               "Found device: control_url: %s, service_type: %s\n",
                               dev->control_url, dev->service_type);
#endif
              /* Accept connected IGDs on step 1, non-connected IGDs
               * on step 2, and other device types on step 3. */
              if ((step == 1 && dev->is_connected)
                  || (step < 3 && 0 != strcmp (dev->service_type,
                                               "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1")))
                continue;

              cls->caller_cb (dev->control_url,
                              dev->service_type, cls->caller_cls);

              free_dev_list (cls->dev_list);
              GNUNET_free (cls);
              return;
            }
        }

      /* We cannot reach this... */
      GNUNET_assert (GNUNET_NO);
    }

  /* There are still devices to ask, go on */
  download_device_description (cls->current_dev->desc_url,
                               get_valid_igd_receive, cls);
}

static const char *const discover_type_list[] = {
  "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
  "urn:schemas-upnp-org:service:WANIPConnection:1",
  "urn:schemas-upnp-org:service:WANPPPConnection:1",
  "upnp:rootdevice",
  NULL
};

static void
discover_send (void *data, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Handle response from device. Stop when all device types have been tried,
 * and get their descriptions.
 *
 * @param data closure from UPNP_discover()
 * @buf content of the reply
 * @available number of bytes stored in buf
 * @addr address of the sender
 * @addrlen size of addr
 * @param errCode value of errno
 */
static void
discover_recv (void *data, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct UPNP_discover_cls *cls = data;
  GNUNET_SCHEDULER_TaskIdentifier task_w;
  struct UPNP_Dev_ *tmp;
  socklen_t addrlen;
  ssize_t received;
  char buf[DISCOVER_BUFSIZE];
  const char *desc_url = NULL;
  int urlsize = 0;
  const char *st = NULL;
  int stsize = 0;

  /* Free fdset that was used for this sned/receive operation */
  GNUNET_NETWORK_fdset_destroy (cls->fdset);

  if (cls->multicast_addr->sa_family == AF_INET)
    addrlen = sizeof (struct sockaddr_in);
  else
    addrlen = sizeof (struct sockaddr_in6);

  errno = 0;
  received =
    GNUNET_NETWORK_socket_recvfrom (cls->sudp, &buf, DISCOVER_BUFSIZE - 1,
                                    (struct sockaddr *) cls->multicast_addr,
                                    &addrlen);
  if (received == GNUNET_SYSERR)
    {
      if (errno != EAGAIN)
	PRINT_SOCKET_ERROR ("GNUNET_NETWORK_socket_recvfrom");
    }
#if DEBUG_UPNP
  else
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UPnP",
                       "Received %d bytes from %s\n", received,
                       GNUNET_a2s (cls->multicast_addr, addrlen));
    }
#endif

  parse_msearch_reply (buf, received, &desc_url, &urlsize, &st, &stsize);

  if (st && desc_url)
    {
      tmp = (struct UPNP_Dev_ *) GNUNET_malloc (sizeof (struct UPNP_Dev_));
      tmp->pNext = cls->dev_list;

      tmp->desc_url = GNUNET_malloc (urlsize + 1);
      strncpy (tmp->desc_url, desc_url, urlsize);
      tmp->desc_url[urlsize] = '\0';

      tmp->st = GNUNET_malloc (stsize + 1);
      strncpy (tmp->st, st, stsize);
      tmp->st[stsize] = '\0';
      cls->dev_list = tmp;
#if DEBUG_UPNP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UPnP",
                       "Found device %s when looking for type %s\n",
                       tmp->desc_url, tmp->st);
#endif
    }

  /* Continue discovery until all types of devices have been tried */
  if (discover_type_list[cls->type_index])
    {
      /* Send queries for each device type and wait for a possible reply.
       * receiver callback takes care of trying another device type,
       * and eventually calls the caller's callback. */
      cls->fdset = GNUNET_NETWORK_fdset_create ();
      GNUNET_NETWORK_fdset_zero (cls->fdset);
      GNUNET_NETWORK_fdset_set (cls->fdset, cls->sudp);

      task_w = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                            GNUNET_SCHEDULER_NO_TASK,
                                            GNUNET_TIME_relative_multiply
                                            (GNUNET_TIME_UNIT_SECONDS, 15),
                                            NULL, cls->fdset, &discover_send,
                                            cls);

      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   task_w,
                                   GNUNET_TIME_relative_multiply
                                   (GNUNET_TIME_UNIT_SECONDS, 5), cls->fdset,
                                   NULL, &discover_recv, cls);
    }
  else
    {
      GNUNET_NETWORK_socket_close (cls->sudp);
      GNUNET_free (cls->multicast_addr);
      cls->current_dev = cls->dev_list;
      get_valid_igd (cls);
    }
}

/**
 * Send the SSDP M-SEARCH packet.
 *
 * @param data closure from UPNP_discover()
 * @param tc task context
 */
static void
discover_send (void *data, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct UPNP_discover_cls *cls = data;
  socklen_t addrlen;
  ssize_t n, sent;
  char buf[DISCOVER_BUFSIZE];
  static const char msearch_msg[] =
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: " UPNP_MCAST_ADDR ":" XSTR (PORT) "\r\n"
    "ST: %s\r\n" "MAN: \"ssdp:discover\"\r\n" "MX: 3\r\n" "\r\n";

  if (cls->multicast_addr->sa_family == AF_INET)
    addrlen = sizeof (struct sockaddr_in);
  else
    addrlen = sizeof (struct sockaddr_in6);

  n =
    snprintf (buf, DISCOVER_BUFSIZE, msearch_msg,
              discover_type_list[cls->type_index++]);

  errno = 0;
  sent = GNUNET_NETWORK_socket_sendto (cls->sudp, buf, n,
                                       (struct sockaddr *)
                                       cls->multicast_addr, addrlen);
  if (sent == GNUNET_SYSERR)
    {
      PRINT_SOCKET_ERROR ("GNUNET_NETWORK_socket_sendto");
    }
  else if (sent < n)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UPnP",
                       "Could only send %d bytes to %s, needed %d bytes\n",
                       sent, GNUNET_a2s (cls->multicast_addr, addrlen), n);
    }
#if DEBUG_UPNP
  else
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UPnP",
                       "Sent %d bytes to %s\n", sent,
                       GNUNET_a2s (cls->multicast_addr, addrlen));
    }
#endif
}

/**
 * Search for UPnP Internet Gateway Devices (IGD) on a given network interface.
 * If several devices are found, a device that is connected to the WAN
 * is returned first (if any).
 *
 * @param multicastif network interface to send discovery messages, or NULL
 * @param addr address used to send messages on multicastif, or NULL
 * @param caller_cb user function to call when done
 * @param caller_cls closure to pass to caller_cb
 */
void
UPNP_discover_ (const char *multicastif,
                const struct sockaddr *addr,
                UPNP_discover_cb_ caller_cb, void *caller_cls)
{
  int opt = 1;
  int domain = PF_INET;
  int if_index;
  struct in6_addr any_addr = IN6ADDR_ANY_INIT;
  struct sockaddr_in sockudp_r, sockudp_w;
  struct sockaddr_in6 sockudp6_r, sockudp6_w;
  GNUNET_SCHEDULER_TaskIdentifier task_w;
  struct GNUNET_NETWORK_Handle *sudp;
  struct UPNP_discover_cls *cls;


  if (addr && addr->sa_family == AF_INET)
    {
      domain = PF_INET;
    }
  else if (addr && addr->sa_family == AF_INET6)
    {
      domain = PF_INET6;
    }
  else if (addr)
    {
      GNUNET_break (0);
      caller_cb (NULL, NULL, caller_cls);
      return;
    }

  errno = 0;
  sudp = GNUNET_NETWORK_socket_create (domain, SOCK_DGRAM, 0);

  if (sudp == NULL)
    {
      PRINT_SOCKET_ERROR ("GNUNET_NETWORK_socket_create");
      caller_cb (NULL, NULL, caller_cls);
      return;
    }


  cls = GNUNET_malloc (sizeof (struct UPNP_discover_cls));
  cls->sudp = sudp;
  cls->type_index = 0;
  cls->dev_list = NULL;
  cls->current_dev = NULL;
  cls->caller_cb = caller_cb;
  cls->caller_cls = caller_cls;


  if (domain == PF_INET)
    {
      /* receive */
      memset (&sockudp_r, 0, sizeof (struct sockaddr_in));
      sockudp_r.sin_family = AF_INET;
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
      sockudp_r.sin_len = sizeof (struct sockaddr_in);
#endif
      sockudp_r.sin_port = 0;
      sockudp_r.sin_addr.s_addr = INADDR_ANY;

      /* send */
      memset (&sockudp_w, 0, sizeof (struct sockaddr_in));
      sockudp_w.sin_family = AF_INET;
      sockudp_w.sin_port = htons (PORT);
      sockudp_w.sin_addr.s_addr = inet_addr (UPNP_MCAST_ADDR);
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
      sockudp_w.sin_len = sizeof (struct sockaddr_in);
#endif

      cls->multicast_addr = GNUNET_malloc (sizeof (struct sockaddr_in));
      memcpy (cls->multicast_addr, &sockudp_w, sizeof (struct sockaddr_in));
    }
  else
    {
      /* receive */
      memcpy (&sockudp6_r, addr, sizeof (struct sockaddr_in6));
      sockudp6_r.sin6_port = 0;
      sockudp6_r.sin6_addr = any_addr;
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
      sockudp6_r.sin6_len = sizeof (struct sockaddr_in6);
#endif

      /* send */
      memset (&sockudp6_w, 0, sizeof (struct sockaddr_in6));
      sockudp6_w.sin6_family = AF_INET6;
      sockudp6_w.sin6_port = htons (PORT);
      if (inet_pton (AF_INET6, UPNP_MCAST_ADDR6, &sockudp6_w.sin6_addr) != 1)
        {
          PRINT_SOCKET_ERROR ("inet_pton");
          caller_cb (NULL, NULL, caller_cls);
          return;
        }
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
      sockudp6_w.sin6_len = sizeof (struct sockaddr_in6);
#endif

      cls->multicast_addr = GNUNET_malloc (sizeof (struct sockaddr_in6));
      memcpy (cls->multicast_addr, &sockudp6_w, sizeof (struct sockaddr_in6));
    }

  if (GNUNET_NETWORK_socket_setsockopt
      (sudp, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt)) == GNUNET_SYSERR)
    {
      PRINT_SOCKET_ERROR ("GNUNET_NETWORK_socket_setsockopt");
      GNUNET_NETWORK_socket_close (sudp);
      caller_cb (NULL, NULL, caller_cls);
      return;
    }

  if (addr)
    {
      if (domain == PF_INET)
        {
          sockudp_r.sin_addr.s_addr =
            ((struct sockaddr_in *) addr)->sin_addr.s_addr;
          if (GNUNET_NETWORK_socket_setsockopt
              (sudp, IPPROTO_IP, IP_MULTICAST_IF,
               (const char *) &sockudp_r.sin_addr,
               sizeof (struct in_addr)) == GNUNET_SYSERR)
            {
              PRINT_SOCKET_ERROR ("GNUNET_NETWORK_socket_setsockopt");
            }
        }
      else
        {
          if (multicastif)
            {
              if_index = if_nametoindex (multicastif);
              if (!if_index)
                PRINT_SOCKET_ERROR ("if_nametoindex");

              if (GNUNET_NETWORK_socket_setsockopt
                  (sudp, IPPROTO_IPV6, IPV6_MULTICAST_IF, &if_index,
                   sizeof (if_index)) == GNUNET_SYSERR)
                {
                  PRINT_SOCKET_ERROR ("GNUNET_NETWORK_socket_setsockopt");
                }
            }

          memcpy (&sockudp6_r.sin6_addr,
                  &((struct sockaddr_in6 *) addr)->sin6_addr,
                  sizeof (sockudp6_r.sin6_addr));
        }
    }

  if (domain == PF_INET)
    {
      /* Bind to receive response before sending packet */
      if (GNUNET_NETWORK_socket_bind
          (sudp, (struct sockaddr *) &sockudp_r,
           sizeof (struct sockaddr_in)) != GNUNET_OK)
        {
          PRINT_SOCKET_ERROR ("GNUNET_NETWORK_socket_bind");
          GNUNET_NETWORK_socket_close (sudp);
          GNUNET_free (cls->multicast_addr);
          caller_cb (NULL, NULL, caller_cls);
          return;
        }
    }
  else
    {
      /* Bind to receive response before sending packet */
      if (GNUNET_NETWORK_socket_bind
          (sudp, (struct sockaddr *) &sockudp6_r,
           sizeof (struct sockaddr_in6)) != GNUNET_OK)
        {
          PRINT_SOCKET_ERROR ("GNUNET_NETWORK_socket_bind");
          GNUNET_free (cls->multicast_addr);
          GNUNET_NETWORK_socket_close (sudp);
          caller_cb (NULL, NULL, caller_cls);
          return;
        }
    }

  /* Send queries for each device type and wait for a possible reply.
   * receiver callback takes care of trying another device type,
   * and eventually calls the caller's callback. */
  cls->fdset = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_zero (cls->fdset);
  GNUNET_NETWORK_fdset_set (cls->fdset, sudp);

  task_w = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                        GNUNET_SCHEDULER_NO_TASK,
                                        GNUNET_TIME_relative_multiply
                                        (GNUNET_TIME_UNIT_SECONDS, 15), NULL,
                                        cls->fdset, &discover_send, cls);

  GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                               task_w,
                               GNUNET_TIME_relative_multiply
                               (GNUNET_TIME_UNIT_SECONDS, 15), cls->fdset,
                               NULL, &discover_recv, cls);
}
