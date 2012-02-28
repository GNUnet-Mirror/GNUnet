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
 * @file dht/test_dht_twopeer.c
 * @brief base testcase for testing DHT service with
 *        two running peers
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_dht_service.h"

/* DEFINES */
#define VERBOSE GNUNET_NO

#define MAX_GET_ATTEMPTS 10

#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5)

#define DEFAULT_NUM_PEERS 2

/* Structs */

struct PeerGetContext
{
  struct GNUNET_PeerIdentity *peer;

  struct GNUNET_DHT_Handle *dht_handle;

  struct GNUNET_DHT_GetHandle *get_handle;

  unsigned int get_attempts;

  GNUNET_SCHEDULER_TaskIdentifier retry_task;
};

/* Globals */
static char *test_directory;

static struct PeerGetContext curr_get_ctx;

static unsigned int expected_connections;

static unsigned long long peers_left;

static struct GNUNET_TESTING_PeerGroup *pg;

static unsigned long long num_peers;

static unsigned int total_gets;

static unsigned int gets_succeeded;

static unsigned int total_connections;

static unsigned int failed_connections;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static int ok;

static struct GNUNET_PeerIdentity peer1id;

static struct GNUNET_PeerIdentity peer2id;

static struct GNUNET_DHT_Handle *peer1dht;

static struct GNUNET_DHT_Handle *peer2dht;

/**
 * Check whether peers successfully shut down.
 */
static void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
    if (ok == 0)
      ok = 2;
  }
}

static void
finish_testing (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (pg != NULL);
  GNUNET_assert (peer1dht != NULL);
  GNUNET_assert (peer2dht != NULL);
  GNUNET_DHT_disconnect (peer1dht);
  GNUNET_DHT_disconnect (peer2dht);
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
  pg = NULL;
  ok = 0;
}

static void
end_badly_cont (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (peer1dht != NULL)
    GNUNET_DHT_disconnect (peer1dht);

  if (peer2dht != NULL)
    GNUNET_DHT_disconnect (peer2dht);

  if (pg != NULL)
  {
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
    pg = NULL;
  }

  if (curr_get_ctx.retry_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (curr_get_ctx.retry_task);
    curr_get_ctx.retry_task = GNUNET_SCHEDULER_NO_TASK;
  }
}


static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  const char *emsg = cls;

  FPRINTF (stderr, "Error: %s\n", emsg);
  if (curr_get_ctx.retry_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (curr_get_ctx.retry_task);
    curr_get_ctx.retry_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (curr_get_ctx.get_handle != NULL)
  {
    GNUNET_DHT_get_stop (curr_get_ctx.get_handle);
  }

  GNUNET_SCHEDULER_add_now (&end_badly_cont, NULL);
  ok = 1;
}


/* Forward declaration */
static void
do_get (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Iterator called on each result obtained for a DHT
 * operation that expects a reply
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
  struct PeerGetContext *get_context = cls;

  if (0 !=
      memcmp (&get_context->peer->hashPubKey, key, sizeof (GNUNET_HashCode)))
  {
    FPRINTF (stderr, "%s",  "??\n");
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Key returned is not the same key as was searched for!\n");
    GNUNET_SCHEDULER_cancel (die_task);
    die_task =
        GNUNET_SCHEDULER_add_now (&end_badly,
                                  "key mismatch in get response!\n");
    return;
  }
  if (get_context->retry_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (get_context->retry_task);
    get_context->retry_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (get_context->peer == &peer2id)
  {
    get_context->peer = &peer1id;
    get_context->dht_handle = peer2dht;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received first correct GET request response!\n");
    GNUNET_DHT_get_stop (get_context->get_handle);
    GNUNET_SCHEDULER_add_now (&do_get, get_context);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received second correct GET request response!\n");
    GNUNET_SCHEDULER_cancel (die_task);
    GNUNET_DHT_get_stop (get_context->get_handle);
    die_task = GNUNET_SCHEDULER_add_now (&finish_testing, NULL);
  }

}

static void
stop_retry_get (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
get_stop_finished (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerGetContext *get_context = cls;

  if (get_context->get_attempts >= MAX_GET_ATTEMPTS)
  {
    FPRINTF (stderr, "%s",  "?\n");
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Too many attempts failed, ending test!\n",
                get_context->get_attempts);
    GNUNET_SCHEDULER_cancel (die_task);
    die_task =
        GNUNET_SCHEDULER_add_now (&end_badly,
                                  "GET attempt failed, ending test!\n");
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Get attempt %u failed, retrying request!\n",
              get_context->get_attempts);
  FPRINTF (stderr, "%s",  ".");
  get_context->get_attempts++;
  get_context->retry_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 60),
                                    &stop_retry_get, get_context);
  get_context->get_handle =
      GNUNET_DHT_get_start (get_context->dht_handle,
                            GNUNET_TIME_relative_multiply
                            (GNUNET_TIME_UNIT_SECONDS, 5),
                            GNUNET_BLOCK_TYPE_DHT_HELLO,
                            &get_context->peer->hashPubKey, 1,
                            GNUNET_DHT_RO_NONE, NULL, 0, &get_result_iterator,
                            get_context);
}


static void
stop_retry_get (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerGetContext *get_context = cls;

  get_context->retry_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Get attempt %u failed, canceling request!\n",
              get_context->get_attempts);
  GNUNET_DHT_get_stop (get_context->get_handle);
  get_context->get_handle = NULL;
  GNUNET_SCHEDULER_add_now (&get_stop_finished, get_context);
}


static void
do_get (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerGetContext *get_context = cls;

  get_context->retry_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 10),
                                    &stop_retry_get, get_context);
  get_context->get_handle =
      GNUNET_DHT_get_start (get_context->dht_handle,
                            GNUNET_TIME_relative_multiply
                            (GNUNET_TIME_UNIT_SECONDS, 5),
                            GNUNET_BLOCK_TYPE_DHT_HELLO,
                            &get_context->peer->hashPubKey, 1,
                            GNUNET_DHT_RO_FIND_PEER, NULL, 0,
                            &get_result_iterator, get_context);
}


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
  }
  else
  {
    failed_connections++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to connect peer %s to peer %s with error :\n%s\n",
                first_daemon->shortname, second_daemon->shortname, emsg);
#endif
  }

  if (total_connections == expected_connections)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Created %d total connections, which is our target number!  Starting next phase of testing.\n",
                total_connections);
#endif
    GNUNET_SCHEDULER_cancel (die_task);
    die_task =
        GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly,
                                      "Timeout trying to GET");

    curr_get_ctx.dht_handle = peer1dht;
    curr_get_ctx.peer = &peer2id;
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 2), &do_get,
                                  &curr_get_ctx);
  }
  else if (total_connections + failed_connections == expected_connections)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task =
        GNUNET_SCHEDULER_add_now (&end_badly,
                                  "from topology_callback (too many failed connections)");
  }
}


static void
connect_topology (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  expected_connections = -1;
  if ((pg != NULL) && (peers_left == 0))
    expected_connections =
        GNUNET_TESTING_connect_topology (pg, GNUNET_TESTING_TOPOLOGY_CLIQUE,
                                         GNUNET_TESTING_TOPOLOGY_OPTION_ALL,
                                         0.0, TIMEOUT, 12, NULL, NULL);

  GNUNET_SCHEDULER_cancel (die_task);
  if (expected_connections == GNUNET_SYSERR)
    die_task =
        GNUNET_SCHEDULER_add_now (&end_badly,
                                  "from connect topology (bad return)");
  else
    die_task =
        GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly,
                                      "from connect topology (timeout)");
}


static void
peers_started_callback (void *cls, const struct GNUNET_PeerIdentity *id,
                        const struct GNUNET_CONFIGURATION_Handle *cfg,
                        struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (emsg != NULL)
  {
    FPRINTF (stderr, "Failed to start daemon: `%s'\n", emsg);
    return;
  }
  GNUNET_assert (id != NULL);
  if (peers_left == num_peers)
  {
    memcpy (&peer1id, id, sizeof (struct GNUNET_PeerIdentity));
    peer1dht = GNUNET_DHT_connect (cfg, 100);
    if (peer1dht == NULL)
    {
      GNUNET_SCHEDULER_cancel (die_task);
      die_task =
          GNUNET_SCHEDULER_add_now (&end_badly, "Failed to get dht handle!\n");
    }
  }
  else
  {
    memcpy (&peer2id, id, sizeof (struct GNUNET_PeerIdentity));
    peer2dht = GNUNET_DHT_connect (cfg, 100);
    if (peer2dht == NULL)
    {
      GNUNET_SCHEDULER_cancel (die_task);
      die_task =
          GNUNET_SCHEDULER_add_now (&end_badly, "Failed to get dht handle!\n");
    }
  }


  peers_left--;

  if (peers_left == 0)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All %d daemons started, now connecting peers!\n", num_peers);
#endif
    GNUNET_SCHEDULER_cancel (die_task);
    /* Set up task in case topology creation doesn't finish
     * within a reasonable amount of time */
    die_task =
        GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly,
                                      "from peers_started_callback");

    GNUNET_SCHEDULER_add_now (&connect_topology, NULL);
    ok = 0;
  }
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "paths", "servicehome",
                                             &test_directory))
  {
    ok = 404;
    return;
  }

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;

  peers_left = num_peers;
  total_gets = num_peers;
  gets_succeeded = 0;
  /* Set up a task to end testing if peer start fails */
  die_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly,
                                    "didn't start all daemons in reasonable amount of time!!!");

  pg = GNUNET_TESTING_daemons_start (cfg, num_peers, 10, num_peers, TIMEOUT,
                                     NULL, NULL, &peers_started_callback, NULL,
                                     &topology_callback, NULL, NULL);

}

static int
check ()
{
  int ret;

  char *const argv[] = { "test-dht-twopeer",
    "-c",
    "test_dht_twopeer_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  ret =
      GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                          "test-dht-twopeer", "nohelp", options, &run, &ok);
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

/* end of test_dht_twopeer.c */
