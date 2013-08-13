/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file testing/gnunet-testing-run-service.c
 * @brief tool to start a service for testing
 * @author Florian Dold
 *
 * Start a peer, running only the service specified on the command line.
 * Outputs the path to the temporary configuration file to stdout.
 *
 * The peer will run until this program is killed,
 * or stdin is closed. When reading the character 'r' from stdin,
 * the running service is restarted with the same configuration.
 *
 * This executable is intended to be used by gnunet-java, in order to reliably
 * start and stop services for test cases.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"

#define LOG(kind,...)                                           \
  GNUNET_log_from (kind, "gnunet-testing", __VA_ARGS__)


/**
 * File handle to STDIN, for reading restart/quit commands.
 */
static struct GNUNET_DISK_FileHandle *fh;

/**
 * FIXME
 */
static char *tmpfilename;

/**
 * FIXME
 */
static GNUNET_SCHEDULER_TaskIdentifier tid;

/**
 * FIXME
 */
static struct GNUNET_TESTING_Peer *my_peer;




/**
 * Cleanup called by signal handlers and when stdin is closed.
 * Removes the temporary file.
 *
 * @param cls unused
 * @param tc scheduler context 
 */
static void
cleanup (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != tmpfilename)
  {
    if (0 != UNLINK (tmpfilename))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", tmpfilename);
  }
  if (GNUNET_SCHEDULER_NO_TASK != tid)
  {
    GNUNET_SCHEDULER_cancel (tid);
    tid = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != fh)
  {
    GNUNET_DISK_file_close (fh);
    fh = NULL;
  }
}


/**
 * Called whenever we can read stdin non-blocking 
 *
 * @param cls unused
 * @param tc scheduler context 
 */
static void
stdin_cb (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c;

  tid = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  GNUNET_assert (0 != (GNUNET_SCHEDULER_REASON_READ_READY & tc->reason));
  c = getchar ();
  switch (c)
  {
  case EOF:
  case 'q':
    GNUNET_SCHEDULER_shutdown ();
    return;
  case 'r':
    if (GNUNET_OK != GNUNET_TESTING_peer_stop (my_peer))
      LOG (GNUNET_ERROR_TYPE_ERROR, "Failed to stop the peer\n");
    if (GNUNET_OK != GNUNET_TESTING_peer_start (my_peer))
      LOG (GNUNET_ERROR_TYPE_ERROR, "Failed to start the peer\n");
    printf ("restarted\n");
    fflush (stdout);
    break;
  case '\n':
  case '\r':
    /* ignore whitespace */
    break;
  default:
    fprintf (stderr, _("Unknown command, use 'q' to quit or 'r' to restart peer\n"));
    break;
  }
  tid = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, fh,
                                        &stdin_cb, NULL);    
}


/**
 * Main function called by the testing library.
 * Executed inside a running scheduler.
 *
 * @param cls unused
 * @param cfg configuration of the peer that was started
 * @param peer handle to the peer
 */
static void
testing_main (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
              struct GNUNET_TESTING_Peer *peer)
{
  my_peer = peer;
  if (NULL == (tmpfilename = GNUNET_DISK_mktemp ("gnunet-testing")))
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_SYSERR == 
      GNUNET_CONFIGURATION_write ((struct GNUNET_CONFIGURATION_Handle *) cfg,
                                  tmpfilename))
  {
    GNUNET_break (0);
    return;
  }
  printf("ok\n%s\n", tmpfilename);
  fflush(stdout);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, NULL);
  fh = GNUNET_DISK_get_handle_from_native (stdin);
  tid = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, fh,
                                        &stdin_cb, NULL);
}


/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static char *cfg_name;
  static char *srv_name;
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'c', "config", "FILENAME",
     gettext_noop ("name of the template configuration file to use (optional)"), 1,
     &GNUNET_GETOPT_set_string, &cfg_name},
    {'s', "service", "SERVICE",
     gettext_noop ("name of the service to run"), 1,
     &GNUNET_GETOPT_set_string, &srv_name},
    GNUNET_GETOPT_OPTION_HELP ("tool to start a service for testing"),
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_SYSERR ==
      GNUNET_GETOPT_run("gnunet-testing-run-service", options, argc, argv))
    return 1;
  ret = GNUNET_TESTING_service_run ("gnunet_service_test", srv_name,
				    cfg_name, &testing_main, NULL);
  if (0 != ret)
  {
    printf ("error\n");
  }
  else 
  {
    printf ("bye\n");
  }
  return ret;
}

