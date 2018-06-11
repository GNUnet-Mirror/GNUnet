/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2015 GNUnet e.V.

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
*/

/**
 * Testcase for STUN server resolution
 *
 * @file nat/test_stun.c
 * @brief Testcase for STUN library
 * @author Bruno Souza Cabral
 * @author Christian Grothoff
 */


#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_nat_lib.h"



#define LOG(kind,...) GNUNET_log_from (kind, "test-stun", __VA_ARGS__)

/**
 * Time to wait before stopping NAT, in seconds
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)


/**
 * The port the test service is running on (default 7895)
 */
static unsigned long port = 7895;

static int ret = 1;

static const char *stun_server = "stun.gnunet.org";

static int stun_port = 3478;

/**
 * The listen socket of the service for IPv4
 */
static struct GNUNET_NETWORK_Handle *lsock4;

/**
 * The listen task ID for IPv4
 */
static struct GNUNET_SCHEDULER_Task *ltask4;

/**
 * Handle for the STUN request.
 */
static struct GNUNET_NAT_STUN_Handle *rh;


static void
print_answer(struct sockaddr_in* answer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "External IP is: %s , with port %d\n",
              inet_ntoa (answer->sin_addr),
              ntohs (answer->sin_port));
}


/**
 * Function that terminates the test.
 */
static void
stop ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Stopping NAT and quitting...\n");
  if (NULL != ltask4)
  {
    GNUNET_SCHEDULER_cancel (ltask4);
    ltask4 = NULL;
  }
  if(NULL != lsock4)
  {
    GNUNET_NETWORK_socket_close(lsock4);
    lsock4 = NULL;
  }
  if (NULL != rh)
  {
    GNUNET_NAT_stun_make_request_cancel (rh);
    rh = NULL;
  }
}


/**
 * Activity on our incoming socket.  Read data from the
 * incoming connection.
 *
 * @param cls
 */
static void
do_udp_read (void *cls)
{
  //struct GNUNET_NAT_Test *tst = cls;
  unsigned char reply_buf[1024];
  ssize_t rlen;
  struct sockaddr_in answer;
  const struct GNUNET_SCHEDULER_TaskContext *tc;

  ltask4 = NULL;
  tc = GNUNET_SCHEDULER_get_task_context ();
  if ( (0 == (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY)) ||
       (! GNUNET_NETWORK_fdset_isset (tc->read_ready,
                                      lsock4)) )
  {
    fprintf (stderr,
             "Timeout waiting for STUN response\n");
    stop();
  }
  rlen = GNUNET_NETWORK_socket_recv (lsock4,
                                     reply_buf,
                                     sizeof (reply_buf));
  memset (&answer,
          0,
          sizeof(struct sockaddr_in));
  if (GNUNET_OK !=
      GNUNET_NAT_stun_handle_packet (reply_buf,
                                     rlen,
                                     &answer))
  {
    fprintf (stderr,
             "Unexpected UDP packet, trying to read more\n");
    ltask4 = GNUNET_SCHEDULER_add_read_net (TIMEOUT,
                                            lsock4,
                                            &do_udp_read, NULL);
    return;
  }
  ret = 0;
  print_answer (&answer);
  stop ();
}


/**
 * Create an IPv4 listen socket bound to our port.
 *
 * @return NULL on error
 */
static struct GNUNET_NETWORK_Handle *
bind_v4 ()
{
  struct GNUNET_NETWORK_Handle *ls;
  struct sockaddr_in sa4;
  int eno;

  memset (&sa4, 0, sizeof (sa4));
  sa4.sin_family = AF_INET;
  sa4.sin_port = htons (port);
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa4.sin_len = sizeof (sa4);
#endif
  ls = GNUNET_NETWORK_socket_create (AF_INET,
                                     SOCK_DGRAM,
                                     0);
  if (NULL == ls)
    return NULL;
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_bind (ls,
                                  (const struct sockaddr *) &sa4,
                                  sizeof (sa4)))
  {
    eno = errno;
    GNUNET_NETWORK_socket_close (ls);
    errno = eno;
    return NULL;
  }
  return ls;
}


/**
 * Function called with the result of the STUN request transmission attempt.
 *
 * @param cls unused
 * @param error status code from STUN
 */
static void
request_callback (void *cls,
                  enum GNUNET_NAT_StatusCode error)
{
  rh = NULL;
  if (GNUNET_NAT_ERROR_SUCCESS == error)
  {
    /* all good, start to receive */
    ltask4 = GNUNET_SCHEDULER_add_read_net (TIMEOUT,
                                            lsock4,
                                            &do_udp_read,
                                            NULL);
    return;
  }
  if (error == GNUNET_NAT_ERROR_NOT_ONLINE)
  {
    ret = 77; /* report 'skip' */
    fprintf (stderr,
             "System is offline, cannot test STUN request.\n");
  }
  else
  {
    ret = error;
  }
  stop();
}


/**
 * Main function run with scheduler.
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  //Lets create the socket
  lsock4 = bind_v4 ();
  if (NULL == lsock4)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "bind");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Service listens on port %u\n",
              (unsigned int) port);
  rh = GNUNET_NAT_stun_make_request (stun_server,
                                     stun_port,
                                     lsock4,
                                     &request_callback, NULL);
  GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                &stop, NULL);
}


int
main (int argc, char *const argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
      GNUNET_GETOPT_OPTION_END
  };
  char *const argv_prog[] = {
      "test-stun",
      "-c",
      "test_stun.conf",
      NULL
  };
  char *fn;
  struct GNUNET_OS_Process *proc;

  GNUNET_log_setup ("test-stun",
                    "WARNING",
                    NULL);

  /* Lets start resolver */
  fn = GNUNET_OS_get_libexec_binary_path ("gnunet-service-resolver");
  proc = GNUNET_OS_start_process (GNUNET_YES,
                                  GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                  NULL, NULL, NULL,
                                  fn,
                                  "gnunet-service-resolver",
                                  "-c", "test_stun.conf", NULL);

  if (NULL == proc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "This test was unable to start gnunet-service-resolver, and it is required to run ...\n");
    exit(1);
  }

  GNUNET_PROGRAM_run (3, argv_prog,
                      "test-stun", "nohelp",
                      options,
                      &run, NULL);

  /* Now kill the resolver */
  if (0 != GNUNET_OS_process_kill (proc, GNUNET_TERM_SIG))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  }
  GNUNET_OS_process_wait (proc);
  GNUNET_OS_process_destroy (proc);
  proc = NULL;
  GNUNET_free (fn);

  return ret;
}

/* end of test_stun.c */
