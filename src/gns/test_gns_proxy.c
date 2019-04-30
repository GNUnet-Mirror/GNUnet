/*
     This file is part of GNUnet
     Copyright (C) 2007, 2009, 2011, 2012 Christian Grothoff

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
 * @file test_gns_proxy.c
 * @brief testcase for accessing SOCKS5 GNS proxy
 * @author Martin Schanzenbach
 */
#include "platform.h"
/* Just included for the right curl.h */
#include "gnunet_curl_lib.h"
#include <microhttpd.h>
#include "gnunet_util_lib.h"
#include "gnutls/x509.h"

/**
 * Largest allowed size for a PEM certificate.
 */
#define MAX_PEM_SIZE (10 * 1024)

#define TEST_DOMAIN "www.test"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

/**
 * Return value for 'main'.
 */
static int global_ret;


static struct MHD_Daemon *mhd;

static struct GNUNET_SCHEDULER_Task *mhd_task_id;

static struct GNUNET_SCHEDULER_Task *curl_task_id;

static CURL *curl;

static CURLM *multi;

static char *url;

static struct GNUNET_OS_Process *proxy_proc;

static char* cafile_opt;

static char* cafile_srv;

static uint16_t port;

static gnutls_x509_crt_t proxy_cert;

static gnutls_x509_privkey_t proxy_key;

struct CBC
{
  char buf[1024];
  size_t pos;
};

static struct CBC cbc;

/**
 * Read file in filename
 *
 * @param filename file to read
 * @param size pointer where filesize is stored
 * @return NULL on error
 */
static void*
load_file (const char* filename,
           unsigned int* size)
{
  void *buffer;
  uint64_t fsize;

  if (GNUNET_OK !=
      GNUNET_DISK_file_size (filename,
                             &fsize,
                             GNUNET_YES,
                             GNUNET_YES))
    return NULL;
  if (fsize > MAX_PEM_SIZE)
    return NULL;
  *size = (unsigned int) fsize;
  buffer = GNUNET_malloc (*size);
  if (fsize !=
      GNUNET_DISK_fn_read (filename,
                           buffer,
                           (size_t) fsize))
  {
    GNUNET_free (buffer);
    return NULL;
  }
  return buffer;
}

/**
 * Load PEM key from file
 *
 * @param key where to store the data
 * @param keyfile path to the PEM file
 * @return #GNUNET_OK on success
 */
static int
load_key_from_file (gnutls_x509_privkey_t key,
                    const char* keyfile)
{
  gnutls_datum_t key_data;
  int ret;

  key_data.data = load_file (keyfile,
                             &key_data.size);
  if (NULL == key_data.data)
    return GNUNET_SYSERR;
  ret = gnutls_x509_privkey_import (key, &key_data,
                                    GNUTLS_X509_FMT_PEM);
  if (GNUTLS_E_SUCCESS != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Unable to import private key from file `%s'\n"),
                keyfile);
  }
  GNUNET_free_non_null (key_data.data);
  return (GNUTLS_E_SUCCESS != ret) ? GNUNET_SYSERR : GNUNET_OK;
}

/**
 * Load cert from file
 *
 * @param crt struct to store data in
 * @param certfile path to pem file
 * @return #GNUNET_OK on success
 */
static int
load_cert_from_file (gnutls_x509_crt_t crt,
                     const char* certfile)
{
  gnutls_datum_t cert_data;
  int ret;

  cert_data.data = load_file (certfile,
                              &cert_data.size);
  if (NULL == cert_data.data)
    return GNUNET_SYSERR;
  ret = gnutls_x509_crt_import (crt,
                                &cert_data,
                                GNUTLS_X509_FMT_PEM);
  if (GNUTLS_E_SUCCESS != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Unable to import certificate from `%s'\n"),
                certfile);
  }
  GNUNET_free_non_null (cert_data.data);
  return (GNUTLS_E_SUCCESS != ret) ? GNUNET_SYSERR : GNUNET_OK;
}

static size_t
copy_buffer (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  struct CBC *cbc = ctx;

  if (cbc->pos + size * nmemb > sizeof(cbc->buf))
    return 0;                   /* overflow */
  GNUNET_memcpy (&cbc->buf[cbc->pos], ptr, size * nmemb);
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
  if (ret == MHD_NO) {
    global_ret = 1;
    abort ();
  }
  global_ret = 0;
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
curl_task (void *cls)
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
start_curl (void *cls)
{
  curl_task_id = NULL;
  GNUNET_asprintf (&url,
                   "https://%s:%d/hello_world",
                   TEST_DOMAIN, port);
  curl = curl_easy_init ();
  curl_easy_setopt (curl, CURLOPT_URL, url);
  //curl_easy_setopt (curl, CURLOPT_URL, "https://127.0.0.1:8443/hello_world");
  curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, &copy_buffer);
  curl_easy_setopt (curl, CURLOPT_WRITEDATA, &cbc);
  curl_easy_setopt (curl, CURLOPT_FAILONERROR, 1);
  curl_easy_setopt (curl, CURLOPT_TIMEOUT, 150L);
  curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, 15L);
  curl_easy_setopt (curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt (curl, CURLOPT_CAINFO, cafile_opt);
  //curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0L);
  //curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0L);
  curl_easy_setopt (curl, CURLOPT_PROXY, "socks5h://127.0.0.1:7777");

  multi = curl_multi_init ();
  GNUNET_assert (multi != NULL);
  GNUNET_assert (CURLM_OK == curl_multi_add_handle (multi, curl));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Beginning HTTP download from `%s'\n",
              url);
  curl_main ();
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
commence_testing (void *cls)
{
  curl_task_id =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                  &start_curl,
                                  NULL);
}


/**
 * Function to keep the HTTP server running.
 */
static void
mhd_main (void);


static void
mhd_task (void *cls)
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


/**
 * Main function that will be run
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Using `%s' as CA\n",
              cafile_srv);
  char cert[MAX_PEM_SIZE];
  char key[MAX_PEM_SIZE];
  size_t key_buf_size;
  size_t cert_buf_size;

  gnutls_global_init ();
  gnutls_x509_crt_init (&proxy_cert);
  gnutls_x509_privkey_init (&proxy_key);

  if ( (GNUNET_OK !=
        load_cert_from_file (proxy_cert,
                             cafile_srv)) ||
       (GNUNET_OK !=
        load_key_from_file (proxy_key,
                            cafile_srv)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to load X.509 key and certificate from `%s'\n"),
                cafile_srv);
    gnutls_x509_crt_deinit (proxy_cert);
    gnutls_x509_privkey_deinit (proxy_key);
    gnutls_global_deinit ();
    return;
  }
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  key_buf_size = sizeof (key);
  cert_buf_size = sizeof (cert);
  gnutls_x509_crt_export (proxy_cert,
                          GNUTLS_X509_FMT_PEM,
                          cert,
                          &cert_buf_size);
  gnutls_x509_privkey_export (proxy_key,
                              GNUTLS_X509_FMT_PEM,
                              key,
                              &key_buf_size);
  mhd = MHD_start_daemon (MHD_USE_DEBUG | MHD_USE_SSL | MHD_ALLOW_SUSPEND_RESUME, port,
                          NULL, NULL,
                          &mhd_ahc, NULL,
                          MHD_OPTION_HTTPS_MEM_KEY, key,
                          MHD_OPTION_HTTPS_MEM_CERT, cert,
                          MHD_OPTION_END);
  GNUNET_assert (NULL != mhd);
  mhd_main ();

  GNUNET_SCHEDULER_add_now (&commence_testing,
                            NULL);
}

int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_uint16 ('p',
                                 "port",
                                 NULL,
                                 gettext_noop ("listen on specified port (default: 7777)"),
                                 &port),
    GNUNET_GETOPT_option_string ('A',
                                 "curlcert",
                                 NULL,
                                 gettext_noop ("pem file to use as CA"),
                                 &cafile_opt),
    GNUNET_GETOPT_option_string ('S',
                                 "servercert",
                                 NULL,
                                 gettext_noop ("pem file to use for the server"),
                                 &cafile_srv),

    GNUNET_GETOPT_OPTION_END
  };

  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
  {
    fprintf (stderr, "failed to initialize curl\n");
    return 2;
  }
  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
                                    &argc, &argv))
    return 2;
  GNUNET_log_setup ("gnunet-gns-proxy-test",
                    "WARNING",
                    NULL);
  if (GNUNET_OK != GNUNET_PROGRAM_run (argc, argv,
                                       "gnunet-gns-proxy-test",
                                       _("GNUnet GNS proxy test"),
                                       options,
                                       &run, NULL))
    return 1;
  GNUNET_free_non_null ((char *) argv);
  return global_ret;
}

/* end of test_gns_proxy.c */
