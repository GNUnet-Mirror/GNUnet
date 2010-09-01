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
 * @file testing/test_testing_topology.c
 * @brief base testcase for testing all the topologies provided
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_os_lib.h"

#define VERBOSE GNUNET_YES

#define DELAY_FOR_LOGGING GNUNET_NO

/**
 * How long until we fail the whole testcase?
 */
#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 240)

/**
 * How long until we give up on starting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 500)

#define SECONDS_PER_PEER_START 45

#define DEFAULT_NUM_PEERS 4

#define MAX_OUTSTANDING_CONNECTIONS 100

static float fail_percentage = 0.05;

static int ok;

static unsigned long long num_peers;

static unsigned int topology_connections;

static unsigned int total_connections;

static unsigned int failed_connections;

static unsigned int total_server_connections;

static unsigned int total_messages_received;

static unsigned int expected_messages;

static unsigned int expected_connections;

static unsigned long long peers_left;

static struct GNUNET_TESTING_PeerGroup *pg;

static struct GNUNET_SCHEDULER_Handle *sched;

const struct GNUNET_CONFIGURATION_Handle *main_cfg;

GNUNET_SCHEDULER_TaskIdentifier die_task;

static char *dotOutFileName;

static struct GNUNET_TIME_Relative settle_time;

static FILE *dotOutFile;

static char *topology_string;

static char *blacklist_transports;

static int transmit_ready_scheduled;

static int transmit_ready_failed;

static int transmit_ready_called;

static unsigned int modnum;

static unsigned int dotnum;

static enum GNUNET_TESTING_Topology topology;

static enum GNUNET_TESTING_Topology blacklist_topology = GNUNET_TESTING_TOPOLOGY_NONE; /* Don't do any blacklisting */

static enum GNUNET_TESTING_Topology connection_topology = GNUNET_TESTING_TOPOLOGY_NONE; /* NONE actually means connect all allowed peers */

static enum GNUNET_TESTING_TopologyOption connect_topology_option = GNUNET_TESTING_TOPOLOGY_OPTION_ALL;

static double connect_topology_option_modifier = 0.0;

static char *test_directory;

#define MTYPE 12345

struct GNUNET_TestMessage
{
  /**
   * Header of the message
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this message.
   */
  uint32_t uid;
};

struct TestMessageContext
{
  /* This is a linked list */
  struct TestMessageContext *next;

  /* Handle to the sending peer core */
  struct GNUNET_CORE_Handle *peer1handle;

  /* Handle to the receiving peer core */
  struct GNUNET_CORE_Handle *peer2handle;

  /* Handle to the sending peer daemon */
  struct GNUNET_TESTING_Daemon *peer1;

  /* Handle to the receiving peer daemon */
  struct GNUNET_TESTING_Daemon *peer2;

  /* Identifier for this message, so we don't disconnect other peers! */
  uint32_t uid;

  /* Task for disconnecting cores, allow task to be cancelled on shutdown */
  GNUNET_SCHEDULER_TaskIdentifier disconnect_task;

};

static struct TestMessageContext *test_messages;

/**
 * Check whether peers successfully shut down.
 */
void shutdown_callback (void *cls,
                        const char *emsg)
{
  if (emsg != NULL)
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Shutdown of peers failed!\n");
#endif
      if (ok == 0)
        ok = 666;
    }
  else
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "All peers successfully shut down!\n");
#endif
    }
}

#if DELAY_FOR_LOGGING
static void gather_log_data ()
{
  char *peer_number;
  char *connect_number;
  pid_t mem_process;
  GNUNET_asprintf(&peer_number, "%llu", num_peers);
  GNUNET_asprintf(&connect_number, "%llu", expected_connections);
  mem_process = GNUNET_OS_start_process (NULL, NULL, "./memsize.pl",
                           "memsize.pl", "totals.txt", peer_number, connect_number, NULL);
  GNUNET_OS_process_wait(mem_process);
}

#endif

static void
finish_testing ()
{
  GNUNET_assert (pg != NULL);
  struct TestMessageContext *pos;
  struct TestMessageContext *free_pos;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Called finish testing, stopping daemons.\n");
#endif

  pos = test_messages;
  while (pos != NULL)
    {
      if (pos->peer1handle != NULL)
        {
          GNUNET_CORE_disconnect(pos->peer1handle);
          pos->peer1handle = NULL;
        }
      if (pos->peer2handle != NULL)
        {
          GNUNET_CORE_disconnect(pos->peer2handle);
          pos->peer2handle = NULL;
        }
      free_pos = pos;
      pos = pos->next;
      if (free_pos->disconnect_task != GNUNET_SCHEDULER_NO_TASK)
        {
          GNUNET_SCHEDULER_cancel(sched, free_pos->disconnect_task);
        }
      GNUNET_free(free_pos);
    }
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmit_ready's scheduled %d, failed %d, transmit_ready's called %d\n", transmit_ready_scheduled, transmit_ready_failed, transmit_ready_called);
#endif

#if VERBOSE
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Calling daemons_stop\n");
#endif
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);

  if (dotOutFile != NULL)
    {
      fprintf(dotOutFile, "}");
      fclose(dotOutFile);
    }

  ok = 0;
}


static void
disconnect_cores (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct TestMessageContext *pos = cls;

  /* Disconnect from the respective cores */
#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting from peer 1 `%4s'\n", GNUNET_i2s (&pos->peer1->id));
#endif
  if (pos->peer1handle != NULL)
    GNUNET_CORE_disconnect(pos->peer1handle);
#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting from peer 2 `%4s'\n", GNUNET_i2s (&pos->peer2->id));
#endif
  if (pos->peer2handle != NULL)
    GNUNET_CORE_disconnect(pos->peer2handle);
  /* Set handles to NULL so test case can be ended properly */
  pos->peer1handle = NULL;
  pos->peer2handle = NULL;
  pos->disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  /* Decrement total connections so new can be established */
  total_server_connections -= 2;
}

static void stats_finished (void *cls, int result)
{
  fprintf(stderr, "Finished getting all peers statistics!\n");
  GNUNET_SCHEDULER_add_now (sched, &finish_testing, NULL);
}

/**
 * Callback function to process statistic values.
 *
 * @param cls closure
 * @param peer the peer the statistics belong to
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int stats_print  (void *cls,
                         const struct GNUNET_PeerIdentity *peer,
                         const char *subsystem,
                         const char *name,
                         uint64_t value,
                         int is_persistent)
{
  GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "%s:%s:%s -- %llu\n", GNUNET_i2s(peer), subsystem, name, value);
  return GNUNET_OK;
}

static void topology_cb (void *cls,
                  const struct GNUNET_PeerIdentity *first,
                  const struct GNUNET_PeerIdentity *second,
                  struct GNUNET_TIME_Relative latency,
                  uint32_t distance,
                  const char *emsg)
{
  FILE *outfile;
  outfile = cls;
  if (first != NULL)
  {
    if (outfile != NULL)
    {
      fprintf(outfile, "\t\"%s\" -- ", GNUNET_i2s(first));
      fprintf(outfile, "\"%s\";\n", GNUNET_i2s(second));
    }
    topology_connections++;
  }
  else
    {
      fprintf(stderr, "Finished iterating over topology, %d total connections!\n", topology_connections);
      if (outfile != NULL)
      {
        fprintf(outfile, "}\n");
        fclose(outfile);
        GNUNET_TESTING_get_statistics(pg, &stats_finished, &stats_print, NULL);
        //GNUNET_SCHEDULER_add_now (sched, &finish_testing, NULL);
      }
    }
}

static int
process_mtype (void *cls,
               const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_MessageHeader *message,
               struct GNUNET_TIME_Relative latency,
               uint32_t distance)
{
  char *dotOutFileNameFinished;
  FILE *dotOutFileFinished;
  struct TestMessageContext *pos = cls;
  struct GNUNET_TestMessage *msg = (struct GNUNET_TestMessage *)message;
  if (pos->uid != ntohl(msg->uid))
    return GNUNET_OK;

#if VERBOSE
    if ((total_messages_received) % modnum == 0)
      {
        if (total_messages_received == 0)
          fprintf (stdout, "0%%");
        else
          fprintf (stdout, "%d%%",
                   (int) (((float) total_messages_received /
                           expected_messages) * 100));

      }
    else if (total_messages_received % dotnum == 0)
      {
        fprintf (stdout, ".");
      }
    fflush (stdout);
#endif

  total_messages_received++;
#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message from `%4s', type %d.\n", GNUNET_i2s (peer), ntohs(message->type));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Total messages received %d, expected %d.\n", total_messages_received, expected_messages);
#endif

  if (total_messages_received == expected_messages)
    {
#if VERBOSE
      fprintf(stdout, "100%%]\n");
#endif
      GNUNET_SCHEDULER_cancel (sched, die_task);
      GNUNET_asprintf(&dotOutFileNameFinished, "%s.dot", "final_topology");
      dotOutFileFinished = fopen (dotOutFileNameFinished, "w");
      GNUNET_free(dotOutFileNameFinished);
      if (dotOutFileFinished != NULL)
      {
        fprintf(dotOutFileFinished, "strict graph G {\n");
      }
      topology_connections = 0;
      GNUNET_TESTING_get_topology (pg, &topology_cb, dotOutFileFinished);
      //GNUNET_SCHEDULER_add_now (sched, &finish_testing, NULL);
    }
  else
    {
      pos->disconnect_task = GNUNET_SCHEDULER_add_now(sched, &disconnect_cores, pos);
    }

  return GNUNET_OK;
}

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  char *msg = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "End badly was called (%s)... stopping daemons.\n", msg);
  struct TestMessageContext *pos;
  struct TestMessageContext *free_pos;

  pos = test_messages;
  while (pos != NULL)
    {
      if (pos->peer1handle != NULL)
        {
          GNUNET_CORE_disconnect(pos->peer1handle);
          pos->peer1handle = NULL;
        }
      if (pos->peer2handle != NULL)
        {
          GNUNET_CORE_disconnect(pos->peer2handle);
          pos->peer2handle = NULL;
        }
      free_pos = pos;
      pos = pos->next;
      GNUNET_free(free_pos);
    }

#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmit_ready's scheduled %d, failed %d, transmit_ready's called %d\n", transmit_ready_scheduled, transmit_ready_failed, transmit_ready_called);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Total messages received %d, expected %d.\n", total_messages_received, expected_messages);
#endif

  if (pg != NULL)
    {
      GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
      ok = 7331;                /* Opposite of leet */
    }
  else
    ok = 401;                   /* Never got peers started */

  if (dotOutFile != NULL)
    {
      fprintf(dotOutFile, "}");
      fclose(dotOutFile);
    }
}

static size_t
transmit_ready (void *cls, size_t size, void *buf)
{
  struct GNUNET_TestMessage *m;
  struct TestMessageContext *pos = cls;

  GNUNET_assert (buf != NULL);
  m = (struct GNUNET_TestMessage *) buf;
  m->header.type = htons (MTYPE);
  m->header.size = htons (sizeof (struct GNUNET_TestMessage));
  m->uid = htonl(pos->uid);
  transmit_ready_called++;
#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "transmit ready for peer %s\ntransmit_ready's scheduled %d, transmit_ready's called %d\n", GNUNET_i2s(&pos->peer1->id), transmit_ready_scheduled, transmit_ready_called);
#endif
  return sizeof (struct GNUNET_TestMessage);
}


static struct GNUNET_CORE_MessageHandler no_handlers[] = {
  {NULL, 0, 0}
};

static struct GNUNET_CORE_MessageHandler handlers[] = {
  {&process_mtype, MTYPE, sizeof (struct GNUNET_TestMessage)},
  {NULL, 0, 0}
};

static void
init_notify_peer2 (void *cls,
             struct GNUNET_CORE_Handle *server,
             const struct GNUNET_PeerIdentity *my_identity,
             const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
  struct TestMessageContext *pos = cls;

#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core connection to `%4s' established, scheduling message send\n",
              GNUNET_i2s (my_identity));
#endif
  total_server_connections++;

  if (NULL == GNUNET_CORE_notify_transmit_ready (pos->peer1handle,
                                                 0,
                                                 TIMEOUT,
                                                 &pos->peer2->id,
                                                 sizeof (struct GNUNET_TestMessage),
                                                 &transmit_ready, pos))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "RECEIVED NULL when asking core (1) for transmission to peer `%4s'\n",
                  GNUNET_i2s (&pos->peer2->id));
      transmit_ready_failed++;
    }
  else
    {
      transmit_ready_scheduled++;
    }
}


static void
init_notify_peer1 (void *cls,
             struct GNUNET_CORE_Handle *server,
             const struct GNUNET_PeerIdentity *my_identity,
             const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
  struct TestMessageContext *pos = cls;
  total_server_connections++;

#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core connection to `%4s' established, setting up handles\n",
              GNUNET_i2s (my_identity));
#endif

  /*
   * Connect to the receiving peer
   */
  pos->peer2handle = GNUNET_CORE_connect (sched,
					  pos->peer2->cfg,
					  TIMEOUT,
					  pos,
					  &init_notify_peer2,
					  NULL,
					  NULL, 
					  NULL, NULL,
					  GNUNET_YES, NULL, GNUNET_YES, handlers);

}


static void
send_test_messages (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct TestMessageContext *pos = cls;

  if ((pos == test_messages) && (settle_time.value > 0))
    {
      topology_connections = 0;
      GNUNET_TESTING_get_topology (pg, &topology_cb, NULL);
    }
  if ((tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN) || (cls == NULL))
    return;

  if (die_task == GNUNET_SCHEDULER_NO_TASK)
    {
      die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                               TEST_TIMEOUT,
                                               &end_badly, "from send test messages (timeout)");
    }

  if (total_server_connections >= MAX_OUTSTANDING_CONNECTIONS)
    {
      GNUNET_SCHEDULER_add_delayed (sched, GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1),
                                    &send_test_messages, pos);
      return; /* Otherwise we'll double schedule messages here! */
    }

  /*
   * Connect to the sending peer
   */
  pos->peer1handle = GNUNET_CORE_connect (sched,
                                          pos->peer1->cfg,
                                          TIMEOUT,
                                          pos,
                                          &init_notify_peer1,
                                          NULL, NULL,
                                          NULL,
                                          NULL,
                                          GNUNET_NO, NULL, GNUNET_NO, no_handlers);

  GNUNET_assert(pos->peer1handle != NULL);

  if (total_server_connections < MAX_OUTSTANDING_CONNECTIONS)
    {
      GNUNET_SCHEDULER_add_now (sched,
                                &send_test_messages, pos->next);
    }
  else
    {
      GNUNET_SCHEDULER_add_delayed (sched, GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1),
                                    &send_test_messages, pos->next);
    }
}


void
topology_callback (void *cls,
                   const struct GNUNET_PeerIdentity *first,
                   const struct GNUNET_PeerIdentity *second,
                   uint32_t distance,
                   const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                   const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                   struct GNUNET_TESTING_Daemon *first_daemon,
                   struct GNUNET_TESTING_Daemon *second_daemon,
                   const char *emsg)
{
  struct TestMessageContext *temp_context;
  if (emsg == NULL)
    {
#if VERBOSE
    if ((total_connections) % modnum == 0)
      {
        if (total_connections == 0)
          fprintf (stdout, "0%%");
        else
          fprintf (stdout, "%d%%",
                   (int) (((float) total_connections /
                           expected_connections) * 100));

      }
    else if (total_connections % dotnum == 0)
      {
        fprintf (stdout, ".");
      }
    fflush (stdout);
#endif
      total_connections++;
#if VERBOSE > 1
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "connected peer %s to peer %s\n",
                 first_daemon->shortname,
                 second_daemon->shortname);
#endif
      temp_context = GNUNET_malloc(sizeof(struct TestMessageContext));
      temp_context->peer1 = first_daemon;
      temp_context->peer2 = second_daemon;
      temp_context->next = test_messages;
      temp_context->uid = total_connections;
      temp_context->disconnect_task = GNUNET_SCHEDULER_NO_TASK;
      test_messages = temp_context;

      expected_messages++;
      if (dotOutFile != NULL)
        fprintf(dotOutFile, "\tn%s -- n%s;\n", first_daemon->shortname, second_daemon->shortname);
    }
#if VERBOSE
  else
    {
      failed_connections++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to connect peer %s to peer %s with error :\n%s\n",
               first_daemon->shortname,
               second_daemon->shortname, emsg);
    }
#endif

  if (total_connections == expected_connections)
    {
#if VERBOSE
      fprintf(stdout, "100%%]\n");
#endif
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Created %d total connections, which is our target number!  Calling send messages.\n",
                  total_connections);
#endif
      modnum = expected_messages / 4;
      dotnum = (expected_messages / 50) + 1;
      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_NO_TASK;
#if DELAY_FOR_LOGGING
      fprintf(stdout, "Sending test messages in 10 seconds.\n");
      GNUNET_SCHEDULER_add_delayed (sched,
                                    GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 10),
                                    &send_test_messages, test_messages);
      gather_log_data();
#else
      if (settle_time.value > 0)
        {
          GNUNET_TESTING_get_topology (pg, &topology_cb, NULL);
        }
      GNUNET_SCHEDULER_add_delayed (sched, settle_time, &send_test_messages, test_messages);
#endif
#if VERBOSE
      fprintf(stdout, "Test message progress: [");
#endif

    }
  else if (total_connections + failed_connections == expected_connections)
    {
      if (failed_connections < (unsigned int)(fail_percentage * total_connections))
        {
          GNUNET_SCHEDULER_cancel (sched, die_task);
          die_task = GNUNET_SCHEDULER_NO_TASK;
          GNUNET_SCHEDULER_add_now (sched, &send_test_messages, test_messages);
        }
      else
        {
          GNUNET_SCHEDULER_cancel (sched, die_task);
          die_task = GNUNET_SCHEDULER_add_now (sched,
                                               &end_badly, "from topology_callback (too many failed connections)");
        }
    }
  else
    {
#if VERBOSE > 1
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Have %d total connections, %d failed connections, Want %d (at least %d)\n",
                  total_connections, failed_connections, expected_connections, expected_connections - (unsigned int)(fail_percentage * expected_connections));
#endif
    }
}

static void
connect_topology ()
{
  expected_connections = -1;
  if ((pg != NULL) && (peers_left == 0))
    {
      expected_connections = GNUNET_TESTING_connect_topology (pg, connection_topology, connect_topology_option, connect_topology_option_modifier);
#if VERBOSE > 1
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Have %d expected connections\n", expected_connections);
#endif
    }

  GNUNET_SCHEDULER_cancel (sched, die_task);
  if (expected_connections == GNUNET_SYSERR)
    {
      die_task = GNUNET_SCHEDULER_add_now (sched,
                                           &end_badly, "from connect topology (bad return)");
    }

  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           TEST_TIMEOUT,
                                           &end_badly, "from connect topology (timeout)");
  modnum = expected_connections / 4;
  dotnum = (expected_connections / 50) + 1;
#if VERBOSE
  fprintf(stdout, "Peer connection progress: [");
#endif
}

static void
create_topology ()
{
  peers_left = num_peers; /* Reset counter */
  if (GNUNET_TESTING_create_topology (pg, topology, blacklist_topology, blacklist_transports) != GNUNET_SYSERR)
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Topology set up, now starting peers!\n");
      fprintf(stdout, "Daemon start progress [");
#endif
      GNUNET_TESTING_daemons_continue_startup(pg);
    }
  else
    {
      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_add_now (sched,
                                           &end_badly, "from create topology (bad return)");
    }
  GNUNET_SCHEDULER_cancel (sched, die_task);
  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           TEST_TIMEOUT,
                                           &end_badly, "from continue startup (timeout)");
}


static void
peers_started_callback (void *cls,
       const struct GNUNET_PeerIdentity *id,
       const struct GNUNET_CONFIGURATION_Handle *cfg,
       struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (emsg != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to start daemon with error: `%s'\n",
                  emsg);
      return;
    }
  GNUNET_assert (id != NULL);
#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Started daemon %llu out of %llu\n",
              (num_peers - peers_left) + 1, num_peers);
#endif
#if VERBOSE
    if ((num_peers - peers_left) % modnum == 0)
      {
        if (num_peers - peers_left == 0)
          fprintf (stdout, "0%%");
        else
          fprintf (stdout, "%d%%",
                   (int) (((float) (num_peers - peers_left) /
                           num_peers) * 100));

      }
    else if ((num_peers - peers_left) % dotnum == 0)
      {
        fprintf (stdout, ".");
      }
    fflush (stdout);
#endif
  peers_left--;
  if (peers_left == 0)
    {
#if VERBOSE
      fprintf(stdout, "100%%]\n");
#endif
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "All %d daemons started, now connecting peers!\n",
                  num_peers);
#endif
      GNUNET_SCHEDULER_cancel (sched, die_task);
      /* Set up task in case topology creation doesn't finish
       * within a reasonable amount of time */
      die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                               GNUNET_TIME_relative_multiply
                                               (GNUNET_TIME_UNIT_MINUTES, 8),
                                               &end_badly, "from peers_started_callback");
#if DELAY_FOR_LOGGING
      fprintf(stdout, "Connecting topology in 10 seconds\n");
      gather_log_data();
      GNUNET_SCHEDULER_add_delayed (sched,
                                    GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 10),
                                    &connect_topology, NULL);
#else
      connect_topology ();
#endif
      ok = 0;
    }
}

/**
 * Callback indicating that the hostkey was created for a peer.
 *
 * @param cls NULL
 * @param id the peer identity
 * @param d the daemon handle (pretty useless at this point, remove?)
 * @param emsg non-null on failure
 */
void hostkey_callback (void *cls,
                       const struct GNUNET_PeerIdentity *id,
                       struct GNUNET_TESTING_Daemon *d,
                       const char *emsg)
{
  if (emsg != NULL)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Hostkey callback received error: %s\n", emsg);
    }

#if VERBOSE > 1
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Hostkey (%d/%d) created for peer `%s'\n",
                num_peers - peers_left, num_peers, GNUNET_i2s(id));
#endif

#if VERBOSE
    if ((num_peers - peers_left) % modnum == 0)
      {
        if (num_peers - peers_left == 0)
          fprintf (stdout, "0%%");
        else
          fprintf (stdout, "%d%%",
                   (int) (((float) (num_peers - peers_left) /
                           num_peers) * 100));

      }
    else if ((num_peers - peers_left) % dotnum == 0)
      {
        fprintf (stdout, ".");
      }
    fflush (stdout);
#endif
    peers_left--;
    if (peers_left == 0)
      {
#if VERBOSE
        fprintf(stdout, "100%%]\n");
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "All %d hostkeys created, now creating topology!\n",
                    num_peers);
#endif
        GNUNET_SCHEDULER_cancel (sched, die_task);
        /* Set up task in case topology creation doesn't finish
         * within a reasonable amount of time */
        die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                                 TIMEOUT,
                                                 &end_badly, "from create_topology");
        GNUNET_SCHEDULER_add_now(sched, &create_topology, NULL);
        ok = 0;
      }
}

static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char * topology_str;
  char * connect_topology_str;
  char * blacklist_topology_str;
  char * connect_topology_option_str;
  char * connect_topology_option_modifier_string;
  unsigned long long temp_settle;
  sched = s;
  ok = 1;

  dotOutFile = fopen (dotOutFileName, "w");
  if (dotOutFile != NULL)
    {
      fprintf (dotOutFile, "strict graph G {\n");
    }

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting daemons based on config file %s\n", cfgfile);
#endif

  if (GNUNET_YES != GNUNET_CONFIGURATION_get_value_string(cfg, "paths", "servicehome", &test_directory))
    {
      ok = 404;
      return;
    }

  if ((GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string(cfg, "testing", "topology",
                                            &topology_str)) && (GNUNET_NO == GNUNET_TESTING_topology_get(&topology, topology_str)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Invalid topology `%s' given for section %s option %s\n", topology_str, "TESTING", "TOPOLOGY");
      topology = GNUNET_TESTING_TOPOLOGY_CLIQUE; /* Defaults to NONE, so set better default here */
    }

  if ((GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string(cfg, "testing", "connect_topology",
                                            &connect_topology_str)) && (GNUNET_NO == GNUNET_TESTING_topology_get(&connection_topology, connect_topology_str)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Invalid connect topology `%s' given for section %s option %s\n", connect_topology_str, "TESTING", "CONNECT_TOPOLOGY");
    }
  GNUNET_free_non_null(connect_topology_str);
  if ((GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string(cfg, "testing", "connect_topology_option",
                                            &connect_topology_option_str)) && (GNUNET_NO == GNUNET_TESTING_topology_option_get(&connect_topology_option, connect_topology_option_str)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Invalid connect topology option `%s' given for section %s option %s\n", connect_topology_option_str, "TESTING", "CONNECT_TOPOLOGY_OPTION");
      connect_topology_option = GNUNET_TESTING_TOPOLOGY_OPTION_ALL; /* Defaults to NONE, set to ALL */
    }
  GNUNET_free_non_null(connect_topology_option_str);
  if (GNUNET_YES ==
        GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "connect_topology_option_modifier",
                                               &connect_topology_option_modifier_string))
    {
      if (sscanf(connect_topology_option_modifier_string, "%lf", &connect_topology_option_modifier) != 1)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
        _("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
        connect_topology_option_modifier_string,
        "connect_topology_option_modifier",
        "TESTING");
      }
      GNUNET_free (connect_topology_option_modifier_string);
    }

  if (GNUNET_YES != GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "blacklist_transports",
                                         &blacklist_transports))
    blacklist_transports = NULL;

  if ((GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string(cfg, "testing", "blacklist_topology",
                                            &blacklist_topology_str)) && (GNUNET_NO == GNUNET_TESTING_topology_get(&blacklist_topology, blacklist_topology_str)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Invalid topology `%s' given for section %s option %s\n", topology_str, "TESTING", "BLACKLIST_TOPOLOGY");
    }
  GNUNET_free_non_null(topology_str);
  GNUNET_free_non_null(blacklist_topology_str);

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "settle_time",
                                             &temp_settle))
    settle_time = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, temp_settle);

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;

  main_cfg = cfg;

  peers_left = num_peers;
  modnum = num_peers / 4;
  dotnum = (num_peers / 50) + 1;
#if VERBOSE
  fprintf (stdout, "Hostkey generation progress: \[");
#endif
  /* Set up a task to end testing if peer start fails */
  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, SECONDS_PER_PEER_START * num_peers),
                                           &end_badly, "didn't generate all hostkeys within a reasonable amount of time!!!");

  GNUNET_assert(num_peers > 0 && num_peers < (unsigned int)-1);
  pg = GNUNET_TESTING_daemons_start (sched, cfg,
                                     peers_left, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, SECONDS_PER_PEER_START * num_peers), &hostkey_callback, NULL, &peers_started_callback, NULL,
                                     &topology_callback, NULL, NULL);

}

static int
check ()
{
  char *binary_name;
  char *config_file_name;
  GNUNET_asprintf(&binary_name, "test-testing-topology-%s", topology_string);
  GNUNET_asprintf(&config_file_name, "test_testing_data_topology_%s.conf", topology_string);
  int ret;
  char *const argv[] = {binary_name,
    "-c",
    config_file_name,
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  ret = GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, binary_name, "nohelp",
                      options, &run, &ok);
  if (ret != GNUNET_OK)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "`test-testing-topology-%s': Failed with error code %d\n", topology_string, ret);
    }
  GNUNET_free(binary_name);
  GNUNET_free(config_file_name);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;
  char *binary_start_pos;
  char *our_binary_name;

  binary_start_pos = rindex(argv[0], '/');
  GNUNET_assert(binary_start_pos != NULL);
  topology_string = strstr (binary_start_pos,
			    "_topology");
  GNUNET_assert (topology_string != NULL);
  topology_string++;
  topology_string = strstr (topology_string, "_");
  GNUNET_assert (topology_string != NULL);
  topology_string++;

  GNUNET_asprintf(&our_binary_name, "test-testing-topology_%s", topology_string);
  GNUNET_asprintf(&dotOutFileName, "topology_%s.dot", topology_string);

  GNUNET_log_setup (our_binary_name,
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
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Failed to remove testing directory %s\n", test_directory);
    }
  GNUNET_free(our_binary_name);
  return ret;
}

/* end of test_testing_topology.c */
