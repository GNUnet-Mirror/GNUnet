/*
  This file is part of GNUnet
  (C) 2019 GNUnet e.V.

  GNUnet is free software: you can redistribute it and/or modify it
  under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License,
  or (at your option) any later version.

  GNUnet is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/

/**
 * @file json/test_json_mhd.c
 * @brief Tests for JSON MHD integration functions
 * @author Christian Grothoff <christian@grothoff.org>
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_json_lib.h"
#include "gnunet_curl_lib.h"

#define MAX_SIZE 1024 * 1024

static json_t *bigj;

static int global_ret;


static int
access_handler_cb (void *cls,
                   struct MHD_Connection *connection,
                   const char *url,
                   const char *method,
                   const char *version,
                   const char *upload_data,
                   size_t *upload_data_size,
                   void **con_cls)
{
  int ret;
  json_t *json;
  struct MHD_Response *resp;

  json = NULL;
  ret = GNUNET_JSON_post_parser (MAX_SIZE,
                                 connection,
                                 con_cls,
                                 upload_data,
                                 upload_data_size,
                                 &json);
  switch (ret)
  {
  case GNUNET_JSON_PR_SUCCESS:
    if (json_equal (bigj, json))
    {
      global_ret = 0;
    }
    else
    {
      GNUNET_break (0);
      global_ret = 6;
    }
    json_decref (json);
    resp = MHD_create_response_from_buffer (2, "OK", MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response (connection, MHD_HTTP_OK, resp);
    MHD_destroy_response (resp);
    return ret;
  case GNUNET_JSON_PR_CONTINUE:
    return MHD_YES;
  case GNUNET_JSON_PR_OUT_OF_MEMORY:
    GNUNET_break (0);
    global_ret = 3;
    break;
  case GNUNET_JSON_PR_REQUEST_TOO_LARGE:
    GNUNET_break (0);
    global_ret = 4;
    break;
  case GNUNET_JSON_PR_JSON_INVALID:
    GNUNET_break (0);
    global_ret = 5;
    break;
  }
  GNUNET_break (0);
  return MHD_NO;
}


int
main (int argc, const char *const argv[])
{
  struct MHD_Daemon *daemon;
  uint16_t port;
  CURL *easy;
  char *url;
  long post_data_size;
  void *post_data;

  GNUNET_log_setup ("test-json-mhd", "WARNING", NULL);
  global_ret = 2;
  daemon = MHD_start_daemon (MHD_USE_DUAL_STACK | MHD_USE_AUTO_INTERNAL_THREAD,
                             0,
                             NULL,
                             NULL,
                             &access_handler_cb,
                             NULL,
                             MHD_OPTION_END);
  if (NULL == daemon)
    return 77;
  bigj = json_object ();
  json_object_set_new (bigj, "test", json_string ("value"));
  for (unsigned int i = 0; i < 1000; i++)
  {
    char tmp[5];

    GNUNET_snprintf (tmp, sizeof (tmp), "%u", i);
    json_object_set_new (bigj, tmp, json_string (tmp));
  }
  post_data = json_dumps (bigj, JSON_INDENT (2));
  post_data_size = strlen (post_data);

  port = MHD_get_daemon_info (daemon, MHD_DAEMON_INFO_BIND_PORT)->port;
  easy = curl_easy_init ();
  GNUNET_asprintf (&url, "http://localhost:%u/", (unsigned int) port);
  curl_easy_setopt (easy, CURLOPT_VERBOSE, 1);
  curl_easy_setopt (easy, CURLOPT_URL, url);
  curl_easy_setopt (easy, CURLOPT_POST, 1);
  curl_easy_setopt (easy, CURLOPT_POSTFIELDS, post_data);
  curl_easy_setopt (easy, CURLOPT_POSTFIELDSIZE, post_data_size);
  if (0 != curl_easy_perform (easy))
  {
    GNUNET_break (0);
    MHD_stop_daemon (daemon);
    GNUNET_free (url);
    json_decref (bigj);
    return 1;
  }
  MHD_stop_daemon (daemon);
  GNUNET_free (url);
  json_decref (bigj);
  return global_ret;
}

/* end of test_json_mhd.c */
