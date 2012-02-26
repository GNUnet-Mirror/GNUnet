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
 * @file dht/test_dht_twopeer_path_tracking.c
 * @brief testcase for testing DHT service with
 *        two running peers, logging the path of the dht requests.
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_dht_service.h"

/* DEFINES */
#define VERBOSE GNUNET_NO

/* Timeout for entire testcase */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5)

/* Timeout for waiting for replies to get requests */
#define GET_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 30)

/* If number of peers not in config file, use this number */
#define DEFAULT_NUM_PEERS 2

/* Globals */

/**
 * Directory to store temp data in, defined in config file
 */
static char *test_directory;

/**
 * Variable used to store the number of connections we should wait for.
 */
static unsigned int expected_connections;

/**
 * Variable used to keep track of how many peers aren't yet started.
 */
static unsigned long long peers_left;

/**
 * Handle to the set of all peers run for this test.
 */
static struct GNUNET_TESTING_PeerGroup *pg;

/**
 * Global handle we will use for GET requests.
 */
struct GNUNET_DHT_GetHandle *global_get_handle;


/**
 * Total number of peers to run, set based on config file.
 */
static unsigned long long num_peers;

/**
 * Global used to count how many connections we have currently
 * been notified about (how many times has topology_callback been called
 * with success?)
 */
static unsigned int total_connections;

/**
 * Global used to count how many failed connections we have
 * been notified about (how many times has topology_callback
 * been called with failure?)
 */
static unsigned int failed_connections;

/**
 * Task handle to use to schedule test failure
 */
GNUNET_SCHEDULER_TaskIdentifier die_task;

/**
 * Global return value (0 for success, anything else for failure)
 */
static int ok;

/**
 * Peer identity of the first peer started.
 */
static struct GNUNET_PeerIdentity peer1id;

/**
 * Peer identity of the second peer started.
 */
static struct GNUNET_PeerIdentity peer2id;

/**
 * Handle to the first peers DHT service (via the API)
 */
static struct GNUNET_DHT_Handle *peer1dht;

/**
 * Handle to the second peers DHT service (via the API)
 */
static struct GNUNET_DHT_Handle *peer2dht;

/**
 * Check whether peers successfully shut down.
 */
void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
    if (ok == 0)
      ok = 2;
  }
}

/**
 * Function scheduled to be run on the successful completion of this
 * testcase.  Specifically, called when our get request completes.
 */
static void
finish_testing (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (pg != NULL);
  GNUNET_assert (peer1dht != NULL);
  GNUNET_assert (peer2dht != NULL);
  GNUNET_DHT_disconnect (peer1dht);
  GNUNET_DHT_disconnect (peer2dht);
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
  ok = 0;
}

/**
 * Continuation for the GNUNET_DHT_get_stop call, so that we don't shut
 * down the peers without freeing memory associated with GET request.
 */
static void
end_badly_cont (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (peer1dht != NULL)
    GNUNET_DHT_disconnect (peer1dht);

  if (peer2dht != NULL)
    GNUNET_DHT_disconnect (peer2dht);

  if (pg != NULL)
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
}

/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failing test with error: `%s'!\n",
              (char *) cls);
  if (global_get_handle != NULL)
  {
    GNUNET_DHT_get_stop (global_get_handle);
    global_get_handle = NULL;
  }
  GNUNET_SCHEDULER_add_now (&end_badly_cont, NULL);
  ok = 1;
}

/**
 * Iterator called if the GET request initiated returns a response.
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
static void
get_result_iterator (void *cls, struct GNUNET_TIME_Absolute exp,
                     const GNUNET_HashCode * key,
                     const struct GNUNET_PeerIdentity *get_path,
                     unsigned int get_path_length,
                     const struct GNUNET_PeerIdentity *put_path,
                     unsigned int put_path_length, enum GNUNET_BLOCK_Type type,
                     size_t size, const void *data)
{
  GNUNET_HashCode original_key; /* Key data was stored data under */
  char original_data[4];        /* Made up data that was stored */

  memset (&original_key, 42, sizeof (GNUNET_HashCode)); /* Set the key to what it was set to previously */
  memset (original_data, 43, sizeof (original_data));
#if VERBOSE
  unsigned int i;
#endif

  if ((0 != memcmp (&original_key, key, sizeof (GNUNET_HashCode))) ||
      (0 != memcmp (original_data, data, sizeof (original_data))))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Key or data is not the same as was inserted!\n");
    GNUNET_SCHEDULER_cancel (die_task);
    GNUNET_SCHEDULER_add_now (&end_badly,
                              "key or data mismatch in get response!\n");
    return;
  }

#if VERBOSE
  if (put_path != NULL)
  {
    FPRINTF (stderr, "%s",  "PUT Path: ");
    for (i = 0; i < put_path_length; i++)
      FPRINTF (stderr, "%s%s", i == 0 ? "" : "->", GNUNET_i2s (&put_path[i]));
    FPRINTF (stderr, "%s",  "\n");
  }
  if (get_path != NULL)
  {
    FPRINTF (stderr, "%s",  "GET Path: ");
    for (i = 0; i < get_path_length; i++)
      FPRINTF (stderr, "%s%s", i == 0 ? "" : "->", GNUNET_i2s (&get_path[i]));
    FPRINTF (stderr, "%s",  "\n");
  }
#endif

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received correct GET response!\n");
  GNUNET_SCHEDULER_cancel (die_task);
  GNUNET_DHT_get_stop (global_get_handle);
  GNUNET_SCHEDULER_add_now (&finish_testing, NULL);
}


/**
 * Called when the PUT request has been transmitted to the DHT service.
 * Schedule the GET request for some time in the future.
 */
static void
put_finished (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_HashCode key;          /* Key for data lookup */

  GNUNET_SCHEDULER_cancel (die_task);
  die_task =
      GNUNET_SCHEDULER_add_delayed (GET_TIMEOUT, &end_badly,
                                    "waiting for get response (data not found)");
  memset (&key, 42, sizeof (GNUNET_HashCode));  /* Set the key to the same thing as when data was inserted */
  global_get_handle =
      GNUNET_DHT_get_start (peer2dht, GNUNET_TIME_relative_get_forever (),
                            GNUNET_BLOCK_TYPE_TEST, &key, 1,
                            GNUNET_DHT_RO_RECORD_ROUTE, NULL, 0,
                            &get_result_iterator, NULL);
}

/**
 * Set up some data, and call API PUT function
 */
static void
do_put (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_HashCode key;          /* Made up key to store data under */
  char data[4];                 /* Made up data to store */

  memset (&key, 42, sizeof (GNUNET_HashCode));  /* Set the key to something simple so we can issue GET request */
  memset (data, 43, sizeof (data));

  /* Insert the data at the first peer */
  GNUNET_DHT_put (peer1dht, &key, 1, GNUNET_DHT_RO_RECORD_ROUTE,
                  GNUNET_BLOCK_TYPE_TEST, sizeof (data), data,
                  GNUNET_TIME_UNIT_FOREVER_ABS, GNUNET_TIME_UNIT_FOREVER_REL,
                  &put_finished, NULL);
}

/**
 * This function is called whenever a connection attempt is finished between two of
 * the started peers (started with GNUNET_TESTING_daemons_start).  The total
 * number of times this function is called should equal the number returned
 * from the GNUNET_TESTING_connect_topology call.
 *
 * The emsg variable is NULL on success (peers connected), and non-NULL on
 * failure (peers failed to connect).
 */
static void
topology_callback (void *cls, const struct GNUNET_PeerIdentity *first,
                   const struct GNUNET_PeerIdentity *second, uint32_t distance,
                   const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                   const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                   struct GNUNET_TESTING_Daemon *first_daemon,
                   struct GNUNET_TESTING_Daemon *second_daemon,
                   const char *emsg)
{
  if (emsg == NULL)
  {
    total_connections++;
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "connected peer %s to peer %s, distance %u\n",
                first_daemon->shortname, second_daemon->shortname, distance);
#endif
  }
#if VERBOSE
  else
  {
    failed_connections++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to connect peer %s to peer %s with error :\n%s\n",
                first_daemon->shortname, second_daemon->shortname, emsg);
  }
#endif

  if (total_connections == expected_connections)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Created %d total connections, which is our target number!  Starting next phase of testing.\n",
                total_connections);
#endif
    GNUNET_SCHEDULER_cancel (die_task);
    die_task =
        GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, "from test gets");

    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 2), &do_put, NULL);
  }
  else if (total_connections + failed_connections == expected_connections)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task =
        GNUNET_SCHEDULER_add_now (&end_badly,
                                  "from topology_callback (too many failed connections)");
  }
}


/**
 * Callback which is called whenever a peer is started (as a result of the
 * GNUNET_TESTING_daemons_start call.
 *
 * @param cls closure argument given to GNUNET_TESTING_daemons_start
 * @param id the GNUNET_PeerIdentity of the started peer
 * @param cfg the configuration for this specific peer (needed to connect
 *            to the DHT)
 * @param d the handle to the daemon started
 * @param emsg NULL if peer started, non-NULL on error
 */
static void
peers_started_callback (void *cls, const struct GNUNET_PeerIdentity *id,
                        const struct GNUNET_CONFIGURATION_Handle *cfg,
                        struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to start daemon with error: `%s'\n", emsg);
    return;
  }
  GNUNET_assert (id != NULL);

  /* This is the first peer started */
  if (peers_left == num_peers)
  {
    memcpy (&peer1id, id, sizeof (struct GNUNET_PeerIdentity)); /* Save the peer id */
    peer1dht = GNUNET_DHT_connect (cfg, 100);   /* Connect to the first peers DHT service */
    if (peer1dht == NULL)       /* If DHT connect failed */
    {
      GNUNET_SCHEDULER_cancel (die_task);
      GNUNET_SCHEDULER_add_now (&end_badly, "Failed to get dht handle!\n");
    }
  }
  else                          /* This is the second peer started */
  {
    memcpy (&peer2id, id, sizeof (struct GNUNET_PeerIdentity)); /* Same as for first peer... */
    peer2dht = GNUNET_DHT_connect (cfg, 100);
    if (peer2dht == NULL)
    {
      GNUNET_SCHEDULER_cancel (die_task);
      GNUNET_SCHEDULER_add_now (&end_badly, "Failed to get dht handle!\n");
    }
  }

  /* Decrement number of peers left to start */
  peers_left--;

  if (peers_left == 0)          /* Indicates all peers started */
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All %d daemons started, now connecting peers!\n", num_peers);
#endif
    expected_connections = -1;
    if ((pg != NULL))           /* Sanity check */
    {
      /* Connect peers in a "straight line" topology, return the number of expected connections */
      expected_connections =
          GNUNET_TESTING_connect_topology (pg, GNUNET_TESTING_TOPOLOGY_LINE,
                                           GNUNET_TESTING_TOPOLOGY_OPTION_ALL,
                                           0.0, TIMEOUT, 2, NULL, NULL);
    }

    /* Cancel current timeout fail task */
    GNUNET_SCHEDULER_cancel (die_task);
    if (expected_connections == GNUNET_SYSERR)  /* Some error happened */
      die_task =
          GNUNET_SCHEDULER_add_now (&end_badly,
                                    "from connect topology (bad return)");

    /* Schedule timeout on failure task */
    die_task =
        GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly,
                                      "from connect topology (timeout)");
    ok = 0;
  }
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{

  /* Get path from configuration file */
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "paths", "servicehome",
                                             &test_directory))
  {
    ok = 404;
    return;
  }

  /* Get number of peers to start from configuration (should be two) */
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;

  /* Set peers_left so we know when all peers started */
  peers_left = num_peers;

  /* Set up a task to end testing if peer start fails */
  die_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly,
                                    "didn't start all daemons in reasonable amount of time!!!");

  /* Start num_peers peers, call peers_started_callback on peer start, topology_callback on peer connect */
  /* Read the API documentation for other parameters! */
  pg = GNUNET_TESTING_daemons_start (cfg, peers_left,   /* Total number of peers */
                                     peers_left,        /* Number of outstanding connections */
                                     peers_left,        /* Number of parallel ssh connections, or peers being started at once */
                                     TIMEOUT, NULL, NULL,
                                     &peers_started_callback, NULL,
                                     &topology_callback, NULL, NULL);

}

static int
check ()
{
  int ret;

  /* Arguments for GNUNET_PROGRAM_run */
  char *const argv[] = { "test-dht-twopeer-put-get",    /* Name to give running binary */
    "-c",
    "test_dht_twopeer_data.conf",       /* Config file to use */
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  /* Run the run function as a new program */
  ret =
      GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                          "test-dht-twopeer-put-get", "nohelp", options, &run,
                          &ok);
  if (ret != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "`test-dht-twopeer': Failed with error code %d\n", ret);
  }
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-dht-twopeer",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  /**
   * Need to remove base directory, subdirectories taken care
   * of by the testing framework.
   */
  if (GNUNET_DISK_directory_remove (test_directory) != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to remove testing directory %s\n", test_directory);
  }
  return ret;
}

/* end of test_dht_twopeer_put_get.c */
