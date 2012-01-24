/*
     This file is part of GNUnet
     (C) 2007, 2009, 2011, 2012 Christian Grothoff

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
 * @file test_gnunet_vpn.c
 * @brief testcase for tunneling HTTP over the GNUnet VPN
 * @author Christian Grothoff
 */
#include "platform.h"
#include <curl/curl.h>
#include <microhttpd.h>
#include "gnunet_vpn_service.h"
#include "gnunet_arm_service.h"

#define PORT 48080

#define START_ARM GNUNET_YES

#define VERBOSE GNUNET_NO

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_PeerIdentity id;
#if START_ARM
  struct GNUNET_OS_Process *arm_proc;
#endif
};

static struct PeerContext p1;

/**
 * Return value for 'main'.
 */
static int global_ret;

static struct GNUNET_VPN_Handle *vpn;

static struct MHD_Daemon *mhd;

static GNUNET_SCHEDULER_TaskIdentifier mhd_task_id;

static GNUNET_SCHEDULER_TaskIdentifier curl_task_id;

static GNUNET_SCHEDULER_TaskIdentifier ctrl_c_task_id;

static struct GNUNET_VPN_RedirectionRequest *rr;

static CURL *curl;

static CURLM *multi;

static char *url;

struct CBC
{
  char *buf;
  size_t pos;
  size_t size;
};

static struct CBC cbc;



static size_t
copyBuffer (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  struct CBC *cbc = ctx;

  if (cbc->pos + size * nmemb > cbc->size)
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
  if (mhd_task_id != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (mhd_task_id);
    mhd_task_id = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != mhd)
  {
    MHD_stop_daemon (mhd);
    mhd = NULL;
  }
  if (NULL != rr)
  {
    GNUNET_VPN_cancel_request (rr);
    rr = NULL;
  }
  if (NULL != vpn)
  {
    GNUNET_VPN_disconnect (vpn);
    vpn = NULL;
  }
  GNUNET_free_non_null (url);
  url = NULL;
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
  curl_task_id = GNUNET_SCHEDULER_NO_TASK;

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
	printf ("%s failed at %s:%d: `%s'\n",
		"curl_multi_perform",
		__FILE__,
		__LINE__, curl_easy_strerror (msg->data.result));
      global_ret = 1;
    }
    curl_multi_remove_handle (multi, curl);
    curl_multi_cleanup (multi);
    curl_easy_cleanup (curl);
    curl = NULL;
    multi = NULL;
    if (cbc.pos != strlen ("/hello_world"))
      global_ret = 2;
    if (0 != strncmp ("/hello_world", cbc.buf, strlen ("/hello_world")))
      global_ret = 3;
    do_shutdown ();
    return;    
  }
  GNUNET_assert (CURLM_OK == curl_multi_fdset (multi, &rs, &ws, &es, &max));
 
  if ( (CURLM_OK != curl_multi_timeout (multi, &timeout)) ||
       (-1 == timeout) )
    delay = GNUNET_TIME_UNIT_FOREVER_REL;
  else
    delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, (unsigned int) timeout);
  GNUNET_NETWORK_fdset_copy_native (&nrs,
				    &rs,
				    max);
  GNUNET_NETWORK_fdset_copy_native (&nws,
				    &ws,
				    max);
  curl_task_id = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
					      GNUNET_SCHEDULER_NO_TASK,
					      delay,
					      &nrs,
					      &nws,
					      &curl_task,
					      NULL);  
}


/**
 * Callback invoked from the VPN service once a redirection is
 * available.  Provides the IP address that can now be used to
 * reach the requested destination (in our case, the MHD server)
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
allocation_cb (void *cls,
	       int af,
	       const void *address)
{
  char ips[INET_ADDRSTRLEN];

  rr = NULL;
  if (AF_INET != af)
  {
    fprintf (stderr, 
	     "VPN failed to allocate appropriate address\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_asprintf (&url, 
		   "http://%s:%u/hello_world",	
		   inet_ntop (af, address, ips, sizeof (ips)),
		   (unsigned int) PORT);
  curl = curl_easy_init ();
  curl_easy_setopt (curl, CURLOPT_URL, url);
  curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, &copyBuffer);
  curl_easy_setopt (curl, CURLOPT_WRITEDATA, &cbc);
  curl_easy_setopt (curl, CURLOPT_FAILONERROR, 1);
  curl_easy_setopt (curl, CURLOPT_TIMEOUT, 150L);
  curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, 15L);
  curl_easy_setopt (curl, CURLOPT_NOSIGNAL, 1);

  multi = curl_multi_init ();
  GNUNET_assert (multi != NULL);
  GNUNET_assert (CURLM_OK == curl_multi_add_handle (multi, curl));

  fprintf (stderr, "Beginning HTTP download from `%s'\n", url);
  curl_main ();
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
  mhd_task_id = GNUNET_SCHEDULER_NO_TASK;
  MHD_run (mhd);
  mhd_main ();
}


static void
ctrl_c_shutdown (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  ctrl_c_task_id = GNUNET_SCHEDULER_NO_TASK;
  do_shutdown ();
  global_ret = 1;
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

  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == mhd_task_id);
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
				    max_fd);
  GNUNET_NETWORK_fdset_copy_native (&nws,
				    &ws,
				    max_fd);
  mhd_task_id = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
					     GNUNET_SCHEDULER_NO_TASK,
					     delay,
					     &nrs,
					     &nws,
					     &mhd_task,
					     NULL);  
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct sockaddr_in v4;

  vpn = GNUNET_VPN_connect (cfg);
  GNUNET_assert (NULL != vpn);
  v4.sin_family = AF_INET;
  v4.sin_port = htons (PORT);
  GNUNET_assert (1 == inet_pton (AF_INET, "127.0.0.1", &v4.sin_addr));
  mhd = MHD_start_daemon (MHD_USE_DEBUG,
			  PORT,
			  NULL, NULL,
			  &mhd_ahc, NULL,
			  MHD_OPTION_SOCK_ADDR, &v4,
			  MHD_OPTION_END);
  GNUNET_assert (NULL != mhd);
  mhd_main ();
  rr = GNUNET_VPN_redirect_to_ip (vpn,
				  AF_INET,
				  AF_INET,
				  &v4,
				  GNUNET_YES,
				  GNUNET_TIME_UNIT_FOREVER_ABS,
				  &allocation_cb, NULL);
  ctrl_c_task_id = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
						 &ctrl_c_shutdown,
						 NULL);
}


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_proc =
      GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm",
#if VERBOSE
                               "-L", "DEBUG",
#endif
                               "-c", cfgname, NULL);
#endif
  GNUNET_assert (NULL != p->arm_proc);
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
}


static void
stop_peer (struct PeerContext *p)
{
#if START_ARM
  if (NULL != p->arm_proc)
  {
    if (0 != GNUNET_OS_process_kill (p->arm_proc, SIGTERM))
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    if (GNUNET_OS_process_wait (p->arm_proc) != GNUNET_OK)
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ARM process %u stopped\n",
                GNUNET_OS_process_get_pid (p->arm_proc));
    GNUNET_OS_process_close (p->arm_proc);
    p->arm_proc = NULL;
  }
#endif
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


int
main (int argc, char *const *argv)
{
  char *const argvx[] = {
    "test_gnunet_vpn",
    "-c",
    "test_gnunet_vpn.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
    return 2;
  setup_peer (&p1, "test_gnunet_vpn.conf");
  GNUNET_log_setup ("test_gnunet_vpn",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  GNUNET_PROGRAM_run ((sizeof (argvx) / sizeof (char *)) - 1, argvx,
                      "test_gnunet_vpn", "nohelp", options, &run, NULL);
  stop_peer (&p1);
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-vpn");
  return global_ret;
}
