/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file testing/test_testing_connect.c
 * @brief testcase for functions to connect two peers in testing.c
 */
#include "platform.h"
#include "gnunet_testing_lib.h"

#define VERBOSE GNUNET_YES


/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)


static int ok;

static struct GNUNET_TESTING_Daemon *d1;

static struct GNUNET_TESTING_Daemon *d2;

static struct GNUNET_CONFIGURATION_Handle *c1;

static struct GNUNET_CONFIGURATION_Handle *c2;

static struct GNUNET_SCHEDULER_Handle *sched;

static void end2_cb(void *cls,
		   const char *emsg)
{
  GNUNET_assert (emsg == NULL); 
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Both daemons terminated, will now exit.\n");
#endif
 ok = 0;
}

static void end1_cb(void *cls,
		    const char *emsg)
{
  GNUNET_assert (emsg == NULL); 
  GNUNET_TESTING_daemon_stop (d2, &end2_cb, NULL);
  d2 = NULL;
}


static void
my_connect_complete (void *cls,
		     const char *emsg)
{
  GNUNET_TESTING_daemon_stop (d1, &end1_cb, NULL);
  d1 = NULL;
}


static void my_cb2(void *cls,
		   const struct GNUNET_PeerIdentity *id,
		   const struct GNUNET_CONFIGURATION_Handle *cfg,
		   struct GNUNET_TESTING_Daemon *d,
		   const char *emsg)
{
  GNUNET_assert (id != NULL);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Daemon `%s' started.\n",
	      GNUNET_i2s (id));
#endif
  GNUNET_TESTING_daemons_connect (d1, d2,
				  TIMEOUT,
				  &my_connect_complete,
				  NULL);
}


static void my_cb1(void *cls,
		   const struct GNUNET_PeerIdentity *id,
		   const struct GNUNET_CONFIGURATION_Handle *cfg,
		   struct GNUNET_TESTING_Daemon *d,
		   const char *emsg)
{
  GNUNET_assert (id != NULL);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Daemon `%s' started.\n",
	      GNUNET_i2s (id));
#endif
  d2 = GNUNET_TESTING_daemon_start (sched,
				    c2,
				    NULL,
				    &my_cb2,
				    NULL);
  GNUNET_assert (d2 != NULL);

}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  sched = s;
  ok = 1;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting daemon.\n");
#endif
  c1 = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_parse (c1,
			      "test_testing_connect_peer1.conf");
  c2 = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_parse (c2,
			      "test_testing_connect_peer2.conf");
  d1 = GNUNET_TESTING_daemon_start (sched,
				    c1,
				    NULL,
				    &my_cb1,
				    NULL);
  GNUNET_assert (d1 != NULL);
}

static int
check ()
{
  char *const argv[] = { "test-testing",
    "-c",
    "test_testing_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-testing-connect", "nohelp",
                      options, &run, &ok);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-testing-connect",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  sleep (1);
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-testing");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-testing-connect-peer1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-testing-connect-peer2");
  return ret;
}

/* end of test_testing_connect.c */
