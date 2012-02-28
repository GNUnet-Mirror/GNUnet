/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file dht/test_dht_topo.c
 *
 * @brief Test for the dht service: store and retrieve in various topologies.
 * Each peer stores it own ID in the DHT and then a different peer tries to
 * retrieve that key from it. The GET starts after a first round of PUTS has
 * been made. Periodically, each peer stores its ID into the DHT. If after
 * a timeout no result has been returned, the test fails.
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_dht_service.h"

#define VERBOSE GNUNET_NO

#define REMOVE_DIR GNUNET_YES

/**
 * DIFFERENT TESTS TO RUN
 */
#define LINE 0
#define TORUS 1

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1500)

#define GET_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

#define PUT_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Result of the test.
 */
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

struct GNUNET_DHT_GetHandle *get_h;

struct GNUNET_DHT_GetHandle *get_h_2;

struct GNUNET_DHT_GetHandle *get_h_far;

int found_1;
int found_2;
int found_far;

/**
 * Which topology are we to run
 */
static int test_topology;

/**
 * Check whether peers successfully shut down.
 */
static void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown of peers failed!\n");
#endif
    ok++;
  }
  else
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All peers successfully shut down!\n");
#endif
  }
  GNUNET_CONFIGURATION_destroy (testing_cfg);
}


static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ending test.\n");
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "disconnecting peers\n");
  disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_SCHEDULER_cancel (put_task);
  if (NULL != get_h)
    GNUNET_DHT_get_stop (get_h);
  if (NULL != get_h_2)
    GNUNET_DHT_get_stop (get_h_2);
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

  if (sizeof (GNUNET_HashCode) == size)
  {
    const GNUNET_HashCode *h = data;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Contents: %s\n",
                GNUNET_h2s_full (h));

  }
  else
  {
    GNUNET_break(0);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "PATH: (get %u, put %u)\n",
              get_path_length, put_path_length);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  LOCAL\n");
  for (i = get_path_length - 1; i >= 0; i--)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  %s\n",
                GNUNET_i2s (&get_path[i]));
  }
  for (i = put_path_length - 1; i >= 0; i--)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  %s\n",
                GNUNET_i2s (&put_path[i]));
  }
  switch ((long)cls)
  {
    case 1:
      found_1++;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "FOUND 1!\n");
      break;
    case 2:
      found_2++;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "FOUND 2!\n");
      break;
    case 3:
      found_far++;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "FOUND FAR!\n");
      break;
    default:
      GNUNET_break(0);
  }
  if (TORUS == test_topology &&
      (found_1 == 0 || found_2 == 0 || found_far == 0))
    return;
  ok = 0;
  GNUNET_SCHEDULER_cancel (disconnect_task);
  disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_peers, NULL);
}

static void
do_test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTING_Daemon *d;
  struct GNUNET_TESTING_Daemon *d2;
  struct GNUNET_TESTING_Daemon *d_far;
  struct GNUNET_TESTING_Daemon *o;
  struct GNUNET_TESTING_Daemon *aux;
  const char *id_aux;
  const char *id_origin = "FC74";
  const char *id_near = "9P6V";
  const char *id_near2 = "2GDS";
  const char *id_far = "KPST";
  unsigned int i;

  d = d2 = d_far = o = NULL;
  found_1 = found_2 = found_far = 0;
  if (LINE == test_topology)
  {
    o = GNUNET_TESTING_daemon_get (pg, 0);
    d = GNUNET_TESTING_daemon_get (pg, 4);
  }
  else if (TORUS == test_topology)
  {
    for (i = 0; i < num_peers; i++)
    {
      aux = GNUNET_TESTING_daemon_get (pg, i);
      id_aux = GNUNET_i2s (&aux->id);
      if (strcmp (id_aux, id_origin) == 0)
        o = aux;
      if (strcmp (id_aux, id_far) == 0)
        d_far = aux;
      if (strcmp (id_aux, id_near) == 0)
        d = aux;
      if (strcmp (id_aux, id_near2) == 0)
        d2 = aux;
    }
    if ((NULL == o) || (NULL == d) || (NULL == d2) || (NULL == d_far))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Peers not found (hostkey file changed?)\n");
      GNUNET_SCHEDULER_cancel (disconnect_task);
      disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_peers, NULL);
      return;
    }
  }
  else
  {
    GNUNET_assert (0);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test_task\ntest:   from %s\n",
              GNUNET_h2s_full (&o->id.hashPubKey));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  looking for %s\n",
              GNUNET_h2s_full (&d->id.hashPubKey));
  get_h = GNUNET_DHT_get_start (hs[0], GNUNET_TIME_UNIT_FOREVER_REL,    /* timeout */
                                GNUNET_BLOCK_TYPE_TEST, /* type */
                                &d->id.hashPubKey,      /*key to search */
                                4U,     /* replication level */
                                GNUNET_DHT_RO_RECORD_ROUTE | GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE, NULL,        /* xquery */
                                0,      /* xquery bits */
                                &dht_get_id_handler, (void *)1);
  if (TORUS == test_topology)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  looking for %s\n",
                GNUNET_h2s_full (&d2->id.hashPubKey));
    get_h_2 = GNUNET_DHT_get_start (hs[0], GNUNET_TIME_UNIT_FOREVER_REL,  /* timeout */
                                    GNUNET_BLOCK_TYPE_TEST,       /* type */
                                    &d2->id.hashPubKey,   /*key to search */
                                    4U,   /* replication level */
                                    GNUNET_DHT_RO_RECORD_ROUTE | GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE, NULL,      /* xquery */
                                    0,    /* xquery bits */
                                    &dht_get_id_handler, (void *)2);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  looking for %s\n",
                GNUNET_h2s_full (&d_far->id.hashPubKey));
    get_h_far = GNUNET_DHT_get_start (hs[0], GNUNET_TIME_UNIT_FOREVER_REL,        /* timeout */
                                      GNUNET_BLOCK_TYPE_TEST,     /* type */
                                      &d_far->id.hashPubKey,      /*key to search */
                                      4U, /* replication level */
                                      GNUNET_DHT_RO_RECORD_ROUTE | GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE, NULL,    /* xquery */
                                      0,  /* xquery bits */
                                      &dht_get_id_handler, (void *)3);
  }
  GNUNET_SCHEDULER_cancel (disconnect_task);
  disconnect_task =
      GNUNET_SCHEDULER_add_delayed (GET_TIMEOUT, &disconnect_peers, NULL);
}

/**
 * Task to put the id of each peer into teh DHT.
 * 
 * @param cls Closure (unused)
 * @param tc Task context
 * 
 */
static void
put_id (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTING_Daemon *d;
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "putting id's in DHT\n");
  for (i = 0; i < num_peers; i++)
  {
    d = GNUNET_TESTING_daemon_get (pg, i);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   putting into DHT: %s\n",
                GNUNET_h2s_full (&d->id.hashPubKey));
    GNUNET_DHT_put (hs[i], &d->id.hashPubKey, 10U,
                    GNUNET_DHT_RO_RECORD_ROUTE |
                    GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                    GNUNET_BLOCK_TYPE_TEST, sizeof (struct GNUNET_PeerIdentity),
                    (const char *) &d->id, GNUNET_TIME_UNIT_FOREVER_ABS,
                    GNUNET_TIME_UNIT_FOREVER_REL, NULL, NULL);

  }
  put_task = GNUNET_SCHEDULER_add_delayed (PUT_FREQUENCY, &put_id, NULL);
  if (GNUNET_SCHEDULER_NO_TASK == test_task)
    test_task = GNUNET_SCHEDULER_add_now (&do_test, NULL);
}


/**
 * peergroup_ready: start test when all peers are connected
 * 
 * @param cls closure
 * @param emsg error message
 * 
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
                "Peergroup callback called with error, aborting test!\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Error from testing: `%s'\n",
                emsg);
    ok++;
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
    return;
  }
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "************************************************************\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer Group started successfully!\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Have %u connections\n",
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
  for (i = 0; i < num_peers; i++)
  {
    d = GNUNET_TESTING_daemon_get (pg, i);
    hs[i] = GNUNET_DHT_connect (d->cfg, 32);
  }

  test_task = GNUNET_SCHEDULER_NO_TASK;
  put_task = GNUNET_SCHEDULER_add_now (&put_id, NULL);
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
                "Problem with new connection (%s)\n", emsg);
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

  GNUNET_log_setup ("test_dht_topo",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting daemons.\n");
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
                "Option test_dht_topo:topology_output_file is required!\n");
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
 * test_dht_2d command line options
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
  char *const argv_torus[] = { "test-dht-2dtorus",
    "-c",
    "test_dht_2dtorus.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  char *const argv_line[] = { "test-dht-line",
    "-c",
    "test_dht_line.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  char *const *argv;
  int argc;
  
  if (strstr (xargv[0], "test_dht_2dtorus") != NULL)
  {
    argv = argv_torus;
    argc = sizeof (argv_torus) / sizeof (char *);
    test_topology = TORUS;
  }
  else if (strstr (xargv[0], "test_dht_line") != NULL)
  {
    argv = argv_line;
    argc = sizeof (argv_line) / sizeof (char *);
    test_topology = LINE;
  }
  else
  {
    GNUNET_break (0);
    return 1;
  }
  GNUNET_PROGRAM_run (argc - 1, argv,
                      xargv[0],
                      gettext_noop ("Test dht in different topologies."),
                      options,
                      &run, NULL);
#if REMOVE_DIR
  GNUNET_DISK_directory_remove ("/tmp/test_dht_topo");
#endif
  if (found_1 == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "ID 1 not found!\n");
  }
  if (TORUS == test_topology)
  {
    if (found_2 == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "ID 2 not found!\n");
    }
    if (found_far == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "ID far not found!\n");
    }
  }
  return ok;
}

/* end of test_dht_topo.c */
