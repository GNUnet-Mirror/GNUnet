/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file testing/test_testing_group_remote.c
 * @brief testcase for testing remote and local starting and connecting
 *        of hosts from the testing library.  The test_testing_data_remote.conf
 *        file should be modified if this testcase is intended to be used.
 */
#include "platform.h"
#include "gnunet_testing_lib.h"

#define VERBOSE GNUNET_YES


/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

#define DEFAULT_NUM_PEERS 8;

static int ok;

static int peers_left;

static int peers_failed;

static struct GNUNET_TESTING_PeerGroup *pg;

static unsigned long long num_peers;


/**
 * Check whether peers successfully shut down.
 */
void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Shutdown of peers failed (error %s)!\n", emsg);
#endif
    if (ok == 0)
      ok = 666;
  }
  else
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All peers successfully shut down!\n");
#endif
  }
}


static void
my_cb (void *cls, const struct GNUNET_PeerIdentity *id,
       const struct GNUNET_CONFIGURATION_Handle *cfg,
       struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (emsg != NULL)
  {
    peers_failed++;
  }

  peers_left--;
  if (peers_left == 0)
  {
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
    ok = 0;
  }
  else if (peers_failed == peers_left)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Too many peers failed, ending test!\n");
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
  }
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_TESTING_Host *hosts;
  struct GNUNET_TESTING_Host *hostpos;
  struct GNUNET_TESTING_Host *temphost;
  char *hostfile;
  struct stat frstat;
  char *buf;
  char *data;
  int count;
  int ret;

  ok = 1;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting daemons.\n");
#endif

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;

  GNUNET_assert (num_peers > 0 && num_peers < (unsigned long long) -1);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "hostfile",
                                             &hostfile))
    hostfile = NULL;

  hosts = NULL;
  data = NULL;
  if (hostfile != NULL)
  {
    if (GNUNET_OK != GNUNET_DISK_file_test (hostfile))
      GNUNET_DISK_fn_write (hostfile, NULL, 0,
                            GNUNET_DISK_PERM_USER_READ |
                            GNUNET_DISK_PERM_USER_WRITE);
    if ((0 != STAT (hostfile, &frstat)) || (frstat.st_size == 0))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not open file specified for host list, ending test!");
      ok = 1119;
      GNUNET_free (hostfile);
      return;
    }

    data = GNUNET_malloc_large (frstat.st_size);
    GNUNET_assert (data != NULL);
    if (frstat.st_size != GNUNET_DISK_fn_read (hostfile, data, frstat.st_size))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not read file %s specified for host list, ending test!",
                  hostfile);
      GNUNET_free (hostfile);
      GNUNET_free (data);
      return;
    }

    GNUNET_free_non_null (hostfile);

    buf = data;
    count = 0;
    while (count < frstat.st_size)
    {
      count++;
      if (count >= frstat.st_size)
        break;

      /* if (((data[count] == '\n') || (data[count] == '\0')) && (buf != &data[count])) */
      if (((data[count] == '\n')) && (buf != &data[count]))
      {
        data[count] = '\0';
        temphost = GNUNET_malloc (sizeof (struct GNUNET_TESTING_Host));
        ret =
            sscanf (buf, "%a[a-zA-Z0-9]@%a[a-zA-Z0-9.]:%hd",
                    &temphost->username, &temphost->hostname, &temphost->port);
        if (3 == ret)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "Successfully read host %s, port %d and user %s from file\n",
                      temphost->hostname, temphost->port, temphost->username);
        }
        else
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "Error reading line `%s' in hostfile\n", buf);
          GNUNET_free (temphost);
          buf = &data[count + 1];
          continue;
        }
        /* temphost->hostname = buf; */
        temphost->next = hosts;
        hosts = temphost;
        buf = &data[count + 1];
      }
      else if ((data[count] == '\n') || (data[count] == '\0'))
        buf = &data[count + 1];
    }
  }

  peers_left = num_peers;
  pg = GNUNET_TESTING_daemons_start (cfg, peers_left,   /* Total number of peers */
                                     peers_left,        /* Number of outstanding connections */
                                     peers_left,        /* Number of parallel ssh connections, or peers being started at once */
                                     TIMEOUT, NULL, NULL, &my_cb, NULL, NULL,
                                     NULL, hosts);
  hostpos = hosts;
  while (hostpos != NULL)
  {
    temphost = hostpos->next;
    GNUNET_free (hostpos->hostname);
    GNUNET_free (hostpos->username);
    GNUNET_free (hostpos);
    hostpos = temphost;
  }
  GNUNET_free_non_null (data);
  GNUNET_assert (pg != NULL);

}

static int
check ()
{
  char *const argv[] = { "test-testing",
    "-c",
    "test_testing_data_remote.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test-testing-group", "nohelp", options, &run, &ok);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-testing-group",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  /**
   * Still need to remove the base testing directory here,
   * because group starts will create subdirectories under this
   * main dir.  However, we no longer need to sleep, as the
   * shutdown sequence won't return until everything is cleaned
   * up.
   */
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-testing");
  return ret;
}

/* end of test_testing_group.c */
