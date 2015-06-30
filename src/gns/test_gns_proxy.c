/*
     This file is part of GNUnet
     Copyright (C) 2007, 2009, 2011, 2012 Christian Grothoff

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
 * @file test_gns_proxy.c
 * @brief testcase for accessing SOCKS5 GNS proxy
 * @author Martin Schanzenbach
 */
#include "platform.h"
#if HAVE_CURL_CURL_H
#include <curl/curl.h>
#elif HAVE_GNURL_CURL_H
#include <gnurl/curl.h>
#endif
#include <microhttpd.h>
#include "gnunet_namestore_service.h"
#include "gnunet_gns_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_os_lib.h"

#define PORT 8080
#define TEST_DOMAIN "www.gnu"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

/**
 * Return value for 'main'.
 */
static int global_ret;

static struct GNUNET_NAMESTORE_Handle *namestore;

static struct MHD_Daemon *mhd;

static struct GNUNET_SCHEDULER_Task * mhd_task_id;

static struct GNUNET_SCHEDULER_Task * curl_task_id;

static CURL *curl;

static CURLM *multi;

static char *url;

static struct GNUNET_OS_Process *proxy_proc;

static char* tmp_cfgfile;

struct CBC
{
  char buf[1024];
  size_t pos;
};

static struct CBC cbc;


static size_t
copy_buffer (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  struct CBC *cbc = ctx;

  if (cbc->pos + size * nmemb > sizeof(cbc->buf))
    return 0;                   /* overflow */
  memcpy (&cbc->buf[cbc->pos], ptr, size * nmemb);
  cbc->pos += size * nmemb;
  return size * nmemb;
}


static int
mhd_ahc (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data, size_t *upload_data_size,
          void **unused)
{
  static int ptr;
  struct MHD_Response *response;
  int ret;

  if (0 != strcmp ("GET", method))
    return MHD_NO;              /* unexpected method */
  if (&ptr != *unused)
  {
    *unused = &ptr;
    return MHD_YES;
  }
  *unused = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MHD sends respose for request to URL `%s'\n", url);
  response = MHD_create_response_from_buffer (strlen (url),
					      (void *) url,
					      MHD_RESPMEM_MUST_COPY);
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  if (ret == MHD_NO)
    abort ();
  return ret;
}


static void
do_shutdown ()
{
  if (mhd_task_id != NULL)
  {
    GNUNET_SCHEDULER_cancel (mhd_task_id);
    mhd_task_id = NULL;
  }
  if (curl_task_id != NULL)
  {
    GNUNET_SCHEDULER_cancel (curl_task_id);
    curl_task_id = NULL;
  }
  if (NULL != mhd)
  {
    MHD_stop_daemon (mhd);
    mhd = NULL;
  }
  GNUNET_free_non_null (url);

  if (NULL != tmp_cfgfile)
    {
      if (0 != remove (tmp_cfgfile))
	GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "remove", tmp_cfgfile);
      GNUNET_free (tmp_cfgfile);
      tmp_cfgfile = NULL;
    }
  if (NULL != proxy_proc)
    {
      (void) GNUNET_OS_process_kill (proxy_proc, SIGKILL);
      GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (proxy_proc));
      GNUNET_OS_process_destroy (proxy_proc);
      proxy_proc = NULL;
    }
  url = NULL;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Function to run the HTTP client.
 */
static void
curl_main (void);


static void
curl_task (void *cls,
	  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  curl_task_id = NULL;
  curl_main ();
}


static void
curl_main ()
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct GNUNET_NETWORK_FDSet nrs;
  struct GNUNET_NETWORK_FDSet nws;
  struct GNUNET_TIME_Relative delay;
  long timeout;
  int running;
  struct CURLMsg *msg;

  max = 0;
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  curl_multi_perform (multi, &running);
  if (running == 0)
  {
    GNUNET_assert (NULL != (msg = curl_multi_info_read (multi, &running)));
    if (msg->msg == CURLMSG_DONE)
    {
      if (msg->data.result != CURLE_OK)
      {
	fprintf (stderr,
		 "%s failed at %s:%d: `%s'\n",
		 "curl_multi_perform",
		__FILE__,
		__LINE__, curl_easy_strerror (msg->data.result));
	global_ret = 1;
      }
    }
    curl_multi_remove_handle (multi, curl);
    curl_multi_cleanup (multi);
    curl_easy_cleanup (curl);
    curl = NULL;
    multi = NULL;
    if (cbc.pos != strlen ("/hello_world"))
    {
      GNUNET_break (0);
      global_ret = 2;
    }
    if (0 != strncmp ("/hello_world", cbc.buf, strlen ("/hello_world")))
    {
      GNUNET_break (0);
      global_ret = 3;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Download complete, shutting down!\n");
    do_shutdown ();
    return;
  }
  GNUNET_assert (CURLM_OK == curl_multi_fdset (multi, &rs, &ws, &es, &max));
  if ( (CURLM_OK != curl_multi_timeout (multi, &timeout)) ||
       (-1 == timeout) )
    delay = GNUNET_TIME_UNIT_SECONDS;
  else
    delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, (unsigned int) timeout);
  GNUNET_NETWORK_fdset_copy_native (&nrs,
				    &rs,
				    max + 1);
  GNUNET_NETWORK_fdset_copy_native (&nws,
				    &ws,
				    max + 1);
  curl_task_id = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
					      delay,
					      &nrs,
					      &nws,
					      &curl_task,
					      NULL);
}

static void
start_curl (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_asprintf (&url,
		   "http://%s:%d/hello_world",
		   TEST_DOMAIN, PORT);
  curl = curl_easy_init ();
  curl_easy_setopt (curl, CURLOPT_URL, url);
  curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, &copy_buffer);
  curl_easy_setopt (curl, CURLOPT_WRITEDATA, &cbc);
  curl_easy_setopt (curl, CURLOPT_FAILONERROR, 1);
  curl_easy_setopt (curl, CURLOPT_TIMEOUT, 150L);
  curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, 15L);
  curl_easy_setopt (curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt (curl, CURLOPT_PROXY, "socks5h://127.0.0.1:7777");

  multi = curl_multi_init ();
  GNUNET_assert (multi != NULL);
  GNUNET_assert (CURLM_OK == curl_multi_add_handle (multi, curl));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Beginning HTTP download from `%s'\n", url);
  curl_main ();
}

static void
disco_ns (void* cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_NAMESTORE_disconnect (namestore);
}

/**
 * Callback invoked from the namestore service once record is
 * created.
 *
 * @param cls closure
 * @param af address family, AF_INET or AF_INET6; AF_UNSPEC on error;
 *                will match 'result_af' from the request
 * @param address IP address (struct in_addr or struct in_addr6, depending on 'af')
 *                that the VPN allocated for the redirection;
 *                traffic to this IP will now be redirected to the
 *                specified target peer; NULL on error
 */
static void
commence_testing (void *cls, int32_t success, const char *emsg)
{
  GNUNET_SCHEDULER_add_now (&disco_ns, NULL);

  if ((emsg != NULL) && (GNUNET_YES != success))
  {
    fprintf (stderr,
	     "NS failed to create record %s\n", emsg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1), start_curl, NULL);

}




/**
 * Function to keep the HTTP server running.
 */
static void
mhd_main (void);


static void
mhd_task (void *cls,
	  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  mhd_task_id = NULL;
  MHD_run (mhd);
  mhd_main ();
}


static void
mhd_main ()
{
  struct GNUNET_NETWORK_FDSet nrs;
  struct GNUNET_NETWORK_FDSet nws;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max_fd;
  unsigned MHD_LONG_LONG timeout;
  struct GNUNET_TIME_Relative delay;

  GNUNET_assert (NULL == mhd_task_id);
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  max_fd = -1;
  GNUNET_assert (MHD_YES ==
		 MHD_get_fdset (mhd, &rs, &ws, &es, &max_fd));
  if (MHD_YES == MHD_get_timeout (mhd, &timeout))
    delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
					   (unsigned int) timeout);
  else
    delay = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_NETWORK_fdset_copy_native (&nrs,
				    &rs,
				    max_fd + 1);
  GNUNET_NETWORK_fdset_copy_native (&nws,
				    &ws,
				    max_fd + 1);
  mhd_task_id = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
					     delay,
					     &nrs,
					     &nws,
					     &mhd_task,
					     NULL);
}

static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  enum MHD_FLAG flags;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *host_key;
  struct GNUNET_GNSRECORD_Data rd;
  char *zone_keyfile;

  namestore = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_assert (NULL != namestore);
  flags = MHD_USE_DEBUG;
  mhd = MHD_start_daemon (flags,
			  PORT,
			  NULL, NULL,
			  &mhd_ahc, NULL,
			  MHD_OPTION_END);
  GNUNET_assert (NULL != mhd);
  mhd_main ();

  tmp_cfgfile = GNUNET_DISK_mktemp ("test_gns_proxy_tmp.conf");
  if (NULL == tmp_cfgfile)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create tmp cfg!\n");
    do_shutdown ();
    return;
  }

  if (GNUNET_OK != GNUNET_CONFIGURATION_write ((struct GNUNET_CONFIGURATION_Handle *)cfg,
                              tmp_cfgfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to write tmp cfg\n");
    do_shutdown ();
    return;
  }

  proxy_proc = GNUNET_OS_start_process (GNUNET_NO,
                                        GNUNET_OS_INHERIT_STD_ALL,
                                        NULL,
                                        NULL,
                                        NULL,
                                        "gnunet-gns-proxy",
                                        "gnunet-gns-proxy",
                                        "-c", tmp_cfgfile, NULL);

  if (NULL == proxy_proc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to start proxy\n");
    do_shutdown ();
    return;
  }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                            "ZONEKEY",
                                                            &zone_keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    return;
  }

  host_key = GNUNET_CRYPTO_ecdsa_key_create_from_file (zone_keyfile);
  rd.expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_string_to_value (GNUNET_DNSPARSER_TYPE_A,
                                                               "127.0.0.1",
                                                               (void**)&rd.data,
                                                               &rd.data_size));
  rd.record_type = GNUNET_DNSPARSER_TYPE_A;

  GNUNET_NAMESTORE_record_create (namestore,
                                  host_key,
                                  "www",
                                  &rd,
                                  &commence_testing,
                                  NULL);

  GNUNET_free ((void**)rd.data);
  GNUNET_free (zone_keyfile);
  GNUNET_free (host_key);
}

int
main (int argc, char *const *argv)
{
  char *binary;

  if (GNUNET_SYSERR == GNUNET_OS_check_helper_binary ("gnunet-gns-proxy", GNUNET_NO, NULL))
  {
    fprintf (stderr, "Proxy binary not in PATH... skipping!\n");
    return 0;
  }
  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-helper-dns");
  if (GNUNET_YES != GNUNET_OS_check_helper_binary (binary, GNUNET_YES, NULL)) // TODO: once we have a windows-testcase, add test parameters here
  {
    fprintf (stderr, "DNS helper binary has wrong permissions... skipping!\n");
    GNUNET_free (binary);
    return 0;
  }
    GNUNET_free (binary);

  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
  {
    fprintf (stderr, "failed to initialize curl\n");
    return 2;
  }
  if (0 != GNUNET_TESTING_peer_run ("test-gnunet-gns-proxy",
				    "test_gns_proxy.conf",
				    &run, NULL))
    return 1;
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-gns-proxy");
  return global_ret;
}

/* end of test_gns_vpn.c */
