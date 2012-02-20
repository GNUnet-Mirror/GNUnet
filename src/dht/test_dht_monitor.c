/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file dht/test_dht_monitor.c
 *
 * @brief Test for the dht service: store, retrieve and monitor in a line.
 * TODO: update this description
 * Each peer stores it own ID in the DHT and then a different peer tries to
 * retrieve that key from it. The GET starts after a first round of PUTS has
 * been made. Periodically, each peer stores its ID into the DHT. If after
 * a timeout no result has been returned, the test fails.
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_dht_service.h"

#define VERBOSE GNUNET_YES

#define REMOVE_DIR GNUNET_YES


/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1500)

#define GET_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

#define PUT_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static int ok;

/**
 * Be verbose
 */
static int verbose;

/**
 * Total number of peers in the test.
 */
static unsigned long long num_peers;

/**
 * Global configuration file
 */
static struct GNUNET_CONFIGURATION_Handle *testing_cfg;

/**
 * Total number of currently running peers.
 */
static unsigned long long peers_running;

/**
 * Total number of connections in the whole network.
 */
static unsigned int total_connections;

/**
 * The currently running peer group.
 */
static struct GNUNET_TESTING_PeerGroup *pg;

/**
 * File to report results to.
 */
static struct GNUNET_DISK_FileHandle *output_file;

/**
 * File to log connection info, statistics to.
 */
static struct GNUNET_DISK_FileHandle *data_file;

/**
 * Task called to disconnect peers.
 */
static GNUNET_SCHEDULER_TaskIdentifier disconnect_task;

/**
 * Task To perform tests
 */
static GNUNET_SCHEDULER_TaskIdentifier test_task;

/**
 * Task to do DHT_puts
 */
static GNUNET_SCHEDULER_TaskIdentifier put_task;

/**
 * Task called to shutdown test.
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_handle;

static char *topology_file;

struct GNUNET_TESTING_Daemon *d1;

struct GNUNET_TESTING_Daemon *d2;

struct GNUNET_DHT_Handle **hs;

struct GNUNET_DHT_MonitorHandle **mhs;

struct GNUNET_DHT_GetHandle *get_h_far;

const char *id_origin = "FC74";
const char *id_far = "2UVH";

struct GNUNET_TESTING_Daemon *d_far;
struct GNUNET_TESTING_Daemon *o;

unsigned int monitor_counter;

int in_test;

/**
 * Check whether peers successfully shut down.
 */
static void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Shutdown of peers failed!\n");
#endif
    ok++;
  }
  else
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "test: All peers successfully shut down!\n");
#endif
  }
  GNUNET_CONFIGURATION_destroy (testing_cfg);
}


static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Ending test.\n");
#endif

  if (disconnect_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (data_file != NULL)
    GNUNET_DISK_file_close (data_file);
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
}


static void
disconnect_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: disconnecting peers\n");
  disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_SCHEDULER_cancel (put_task);
  if (NULL != get_h_far)
    GNUNET_DHT_get_stop (get_h_far);
  for (i = 0; i < num_peers; i++)
  {
    GNUNET_DHT_disconnect (hs[i]);
  }
  GNUNET_SCHEDULER_cancel (shutdown_handle);
  shutdown_handle = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
}

static void
dht_get_id_handler (void *cls, struct GNUNET_TIME_Absolute exp,
                    const GNUNET_HashCode * key,
                    const struct GNUNET_PeerIdentity *get_path,
                    unsigned int get_path_length,
                    const struct GNUNET_PeerIdentity *put_path,
                    unsigned int put_path_length, enum GNUNET_BLOCK_Type type,
                    size_t size, const void *data)
{
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "test: ************* FOUND!!! ***********\n");
  if (sizeof (GNUNET_HashCode) == size)
  {
    const GNUNET_HashCode *h = data;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test:   Contents: %s\n",
                GNUNET_h2s_full (h));

  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: PATH: (get %u, put %u)\n",
              get_path_length, put_path_length);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test:   LOCAL\n");
  for (i = get_path_length - 1; i >= 0; i--)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test:   %s\n",
                GNUNET_i2s (&get_path[i]));
  }
  for (i = put_path_length - 1; i >= 0; i--)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test:   %s\n",
                GNUNET_i2s (&put_path[i]));
  }
  if (monitor_counter >= get_path_length + put_path_length)
  {
    ok = 0;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "expected at least %u hops, got %u\n",
                get_path_length + put_path_length, monitor_counter);
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "expected at least %u hops, got %u\n",
                get_path_length + put_path_length, monitor_counter);
  GNUNET_SCHEDULER_cancel (disconnect_task);
  disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_peers, NULL);
}

/**
 * Start test: start GET request from the first node in the line looking for
 * the ID of the last node in the line.
 * 
 * @param cls Closure (not used).
 * @param tc Task context.
 */
static void
do_test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
  {
    return;
  }
  
  in_test = GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: test_task\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: looking for %s\n",
              GNUNET_h2s_full (&d_far->id.hashPubKey));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test:        from %s\n",
              GNUNET_h2s_full (&o->id.hashPubKey));
  get_h_far = GNUNET_DHT_get_start (hs[0], GNUNET_TIME_UNIT_FOREVER_REL,        /* timeout */
                                    GNUNET_BLOCK_TYPE_TEST,     /* type */
                                    &d_far->id.hashPubKey,      /*key to search */
                                    4U, /* replication level */
                                    GNUNET_DHT_RO_RECORD_ROUTE | GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE, NULL,    /* xquery */
                                    0,  /* xquery bits */
                                    &dht_get_id_handler, NULL);
  GNUNET_SCHEDULER_cancel (disconnect_task);
  disconnect_task =
      GNUNET_SCHEDULER_add_delayed (GET_TIMEOUT, &disconnect_peers, NULL);
}


/**
 * Periodic function used to put the ID of the far peer in the DHT.
 * 
 * @param cls Closure (not used).
 * @param tc Task context.
 */
static void
put_id (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTING_Daemon *d;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
  {
    put_task = GNUNET_SCHEDULER_NO_TASK;
    return;
  }

  d = GNUNET_TESTING_daemon_get (pg, 4);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: putting into DHT: %s\n",
              GNUNET_h2s_full (&d->id.hashPubKey));
  GNUNET_DHT_put (hs[4], &d->id.hashPubKey, 10U,
                  GNUNET_DHT_RO_RECORD_ROUTE |
                  GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                  GNUNET_BLOCK_TYPE_TEST, sizeof (struct GNUNET_PeerIdentity),
                  (const char *) &d->id, GNUNET_TIME_UNIT_FOREVER_ABS,
                  GNUNET_TIME_UNIT_FOREVER_REL, NULL, NULL);

  put_task = GNUNET_SCHEDULER_add_delayed (PUT_FREQUENCY, &put_id, NULL);
}

/**
 * Callback called on each request going through the DHT.
 * Prints the info about the intercepted packet and increments a counter.
 *
 * @param cls Closure (long) # of daemon that got the monitor event.
 * @param mtype Type of the DHT message monitored.
 * @param exp When will this value expire.
 * @param key Key of the result/request.
 * @param get_path Peers on reply path (or NULL if not recorded).
 * @param get_path_length number of entries in get_path.
 * @param put_path peers on the PUT path (or NULL if not recorded).
 * @param put_path_length number of entries in get_path.
 * @param desired_replication_level Desired replication level.
 * @param type Type of the result/request.
 * @param data Pointer to the result data.
 * @param size Number of bytes in data.
 */
void
monitor_dht_cb (void *cls,
                uint16_t mtype,
                struct GNUNET_TIME_Absolute exp,
                const GNUNET_HashCode * key,
                const struct GNUNET_PeerIdentity * get_path,
                unsigned int get_path_length,
                const struct GNUNET_PeerIdentity * put_path,
                unsigned int put_path_length,
                uint32_t desired_replication_level,
                enum GNUNET_DHT_RouteOption options,
                enum GNUNET_BLOCK_Type type,
                const void *data,
                size_t size)
{
  const char *s_key;
  const char *mtype_s;
  unsigned int i;

  i = (unsigned int) (long) cls;
  s_key = GNUNET_h2s(key);
  switch (mtype)
  {
    case 149:
      mtype_s = "GET   ";
      break;
    case 150:
      mtype_s = "RESULT";
      break;
    case 151:
      mtype_s = "PUT   ";
      break;
    default:
      GNUNET_break (0);
      mtype_s = "UNKNOWN!!!";
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "%u got a message of type %s for key %s\n",
              i, mtype_s, s_key);

  if ((mtype == GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET ||
       mtype == GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT) &&
      strncmp (s_key, id_far, 4) == 0 && in_test == GNUNET_YES)
    monitor_counter++;
}


/**
 * peergroup_ready: start test when all peers are connected
 *
 * @param cls closure
 * @param emsg error message
 */
static void
peergroup_ready (void *cls, const char *emsg)
{
  struct GNUNET_TESTING_Daemon *d;
  char *buf;
  int buf_len;
  unsigned int i;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "test: Peergroup callback called with error, aborting test!\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Error from testing: `%s'\n",
                emsg);
    ok++;
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
    return;
  }
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "************************************************************\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "test: Peer Group started successfully!\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Have %u connections\n",
              total_connections);
#endif

  if (data_file != NULL)
  {
    buf = NULL;
    buf_len = GNUNET_asprintf (&buf, "CONNECTIONS_0: %u\n", total_connections);
    if (buf_len > 0)
      GNUNET_DISK_file_write (data_file, buf, buf_len);
    GNUNET_free (buf);
  }
  peers_running = GNUNET_TESTING_daemons_running (pg);

  GNUNET_assert (peers_running == num_peers);
  hs = GNUNET_malloc (num_peers * sizeof (struct GNUNET_DHT_Handle *));
  mhs = GNUNET_malloc (num_peers * sizeof (struct GNUNET_DHT_MonitorHandle *));
  d_far = o = NULL;
  o = GNUNET_TESTING_daemon_get (pg, 0);
  d_far = GNUNET_TESTING_daemon_get (pg, 4);

  for (i = 0; i < num_peers; i++)
  {
    d = GNUNET_TESTING_daemon_get (pg, i);
    hs[i] = GNUNET_DHT_connect (d->cfg, 32);
    mhs[i] = GNUNET_DHT_monitor_start(hs[i], GNUNET_BLOCK_TYPE_ANY, NULL,
                                      &monitor_dht_cb, (void *)(long)i);
  }

  if ((NULL == o) || (NULL == d_far))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "test: Error getting daemons from pg\n");
    GNUNET_SCHEDULER_cancel (disconnect_task);
    disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_peers, NULL);
    return;
  }
  monitor_counter = 0;
  put_task = GNUNET_SCHEDULER_add_now (&put_id, NULL);
  test_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 2), &do_test,
                                    NULL);
  disconnect_task =
      GNUNET_SCHEDULER_add_delayed (GET_TIMEOUT, &disconnect_peers, NULL);

}


/**
 * Function that will be called whenever two daemons are connected by
 * the testing library.
 *
 * @param cls closure
 * @param first peer id for first daemon
 * @param second peer id for the second daemon
 * @param distance distance between the connected peers
 * @param first_cfg config for the first daemon
 * @param second_cfg config for the second daemon
 * @param first_daemon handle for the first daemon
 * @param second_daemon handle for the second daemon
 * @param emsg error message (NULL on success)
 */
static void
connect_cb (void *cls, const struct GNUNET_PeerIdentity *first,
            const struct GNUNET_PeerIdentity *second, uint32_t distance,
            const struct GNUNET_CONFIGURATION_Handle *first_cfg,
            const struct GNUNET_CONFIGURATION_Handle *second_cfg,
            struct GNUNET_TESTING_Daemon *first_daemon,
            struct GNUNET_TESTING_Daemon *second_daemon, const char *emsg)
{

  if (emsg == NULL)
  {
    total_connections++;
    GNUNET_PEER_intern (first);
    GNUNET_PEER_intern (second);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "test: Problem with new connection (%s)\n", emsg);
  }

}


/**
 * run: load configuration options and schedule test to run (start peergroup)
 * @param cls closure
 * @param args argv
 * @param cfgfile configuration file name (can be NULL)
 * @param cfg configuration handle
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *temp_str;
  struct GNUNET_TESTING_Host *hosts;
  char *data_filename;

  ok = 1;
  testing_cfg = GNUNET_CONFIGURATION_dup (cfg);

  GNUNET_log_setup ("test_dht_monitor",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Starting daemons.\n");
  GNUNET_CONFIGURATION_set_value_string (testing_cfg, "testing",
                                         "use_progressbars", "YES");
#endif

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (testing_cfg, "testing",
                                             "num_peers", &num_peers))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Option TESTING:NUM_PEERS is required!\n");
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (testing_cfg, "testing",
                                             "topology_output_file",
                                             &topology_file))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Option test_dht_monitor:topology_output_file is required!\n");
    return;
  }

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (testing_cfg, "test_dht_topo",
                                             "data_output_file",
                                             &data_filename))
  {
    data_file =
        GNUNET_DISK_file_open (data_filename,
                               GNUNET_DISK_OPEN_READWRITE |
                               GNUNET_DISK_OPEN_CREATE,
                               GNUNET_DISK_PERM_USER_READ |
                               GNUNET_DISK_PERM_USER_WRITE);
    if (data_file == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Failed to open %s for output!\n",
                  data_filename);
      GNUNET_free (data_filename);
    }
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "test_dht_topo",
                                             "output_file", &temp_str))
  {
    output_file =
        GNUNET_DISK_file_open (temp_str,
                               GNUNET_DISK_OPEN_READWRITE |
                               GNUNET_DISK_OPEN_CREATE,
                               GNUNET_DISK_PERM_USER_READ |
                               GNUNET_DISK_PERM_USER_WRITE);
    if (output_file == NULL)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Failed to open %s for output!\n",
                  temp_str);
  }
  GNUNET_free_non_null (temp_str);

  hosts = GNUNET_TESTING_hosts_load (testing_cfg);

  pg = GNUNET_TESTING_peergroup_start (testing_cfg, num_peers, TIMEOUT,
                                       &connect_cb, &peergroup_ready, NULL,
                                       hosts);
  GNUNET_assert (pg != NULL);
  shutdown_handle =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                    &shutdown_task, NULL);
}



/**
 * test_dht_monitor command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'V', "verbose", NULL,
   gettext_noop ("be verbose (print progress information)"),
   0, &GNUNET_GETOPT_set_one, &verbose},
  GNUNET_GETOPT_OPTION_END
};


/**
 * Main: start test
 */
int
main (int xargc, char *xargv[])
{
  char *const argv[] = { "test-dht-monitor",
    "-c",
    "test_dht_line.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };

  in_test = GNUNET_NO;
  GNUNET_PROGRAM_run (sizeof (argv) / sizeof (char *) - 1, argv,
                      "test_dht_monitor",
                      gettext_noop ("Test dht monitoring in a line."),
                      options, &run, NULL);
#if REMOVE_DIR
  GNUNET_DISK_directory_remove ("/tmp/test_dht_monitor");
#endif
  if (0 != ok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "test: FAILED!\n");
  }
  return ok;
}

/* end of test_dht_monitor.c */
