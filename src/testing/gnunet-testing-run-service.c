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
 * Start a peer with the service specified on the command line.
 * Outputs the path to the temporary configuration file to stdout.
 *
 * The peer will run until this program is killed,
 * or stdin is closed.
 *
 * This executable is intended to be used by gnunet-java, in order to reliably
 * start and stop services for test cases.
 */

#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_signal_lib.h"
#include "gnunet_testing_lib-new.h"
#include "gnunet_os_lib.h"


static struct GNUNET_DISK_FileHandle fh;
static char *tmpfilename = NULL;
static GNUNET_SCHEDULER_TaskIdentifier tid = GNUNET_SCHEDULER_NO_TASK;
static struct GNUNET_TESTING_Peer *my_peer = NULL;


#define LOG(kind,...)                                           \
  GNUNET_log_from (kind, "gnunettestingnew", __VA_ARGS__)


/**
 * Cleanup called by signal handlers and when stdin is closed.
 * Removes the temporary file with the configuration and shuts down the scheduler.
 */
void
cleanup (void)
{
    if (NULL != tmpfilename)
    {
        remove (tmpfilename);
    }
    GNUNET_SCHEDULER_shutdown ();
}

/**
 * Called whenever we can read stdin non-blocking 
 */
void
stdin_cb (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c;

  if (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason)
  {
      return;
  }
  if (GNUNET_SCHEDULER_REASON_READ_READY & tc->reason)
  {
    c = getchar ();
    if (EOF == c)
    {
      tid = GNUNET_SCHEDULER_NO_TASK;
      cleanup ();
    }
    else
    {
      if (c == 'r')
      {
        GNUNET_TESTING_peer_stop(my_peer); 
        GNUNET_TESTING_peer_start(my_peer); 
        printf("restarted\n");
      }
      tid = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, &fh, &stdin_cb, NULL);
    }
    return;
  }
  GNUNET_break (0);
}

/**
 * Main function called by the testing library.
 * Executed inside a running scheduler.
 */
void
testing_main (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
              const struct GNUNET_TESTING_Peer *peer)
{
    my_peer = peer;
    tmpfilename = tmpnam (NULL);
    if (NULL == tmpfilename)
    {
        GNUNET_break (0);
        cleanup ();
        return;
    }

    if (GNUNET_SYSERR == 
            GNUNET_CONFIGURATION_write((struct GNUNET_CONFIGURATION_Handle *) cfg, tmpfilename))
    {
        GNUNET_break (0);
        return;
    }

    printf("%s\n", tmpfilename);
    fflush(stdout);

    GNUNET_break(NULL != GNUNET_SIGNAL_handler_install(SIGTERM, &cleanup));
    GNUNET_break(NULL != GNUNET_SIGNAL_handler_install(SIGINT, &cleanup));

    fh.fd = 0; /* 0=stdin */
    tid = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, &fh, &stdin_cb, NULL);
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
    static const struct GNUNET_GETOPT_CommandLineOption options[] = {
        GNUNET_GETOPT_OPTION_HELP("tool to start a service for testing"),
        GNUNET_GETOPT_OPTION_END
    };
    int arg_start;
    int ret;

    arg_start = GNUNET_GETOPT_run("gnunet-testing-run-service", options, argc, argv);
    
    if (arg_start == GNUNET_SYSERR) {
        return 1;
    }
    
    if (arg_start != 1 || argc != 2)
    {
        fprintf (stderr, "Invalid number of arguments\n");
        return 1;
    }

    ret =  GNUNET_TESTING_service_run_restartable ("gnunet_service_test", argv[1],
                                                   NULL, &testing_main, NULL);

    printf ("bye\n");

    return ret;
}
