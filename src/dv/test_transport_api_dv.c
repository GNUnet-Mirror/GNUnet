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
 * @file dv/test_transport_api_dv.c
 * @brief base testcase for testing distance vector transport
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"

#define VERBOSE 1

#define TEST_ALL GNUNET_NO

/**
 * How long until we fail the whole testcase?
 */
#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 600)

/**
 * How long until we give up on starting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 500)

#define DEFAULT_NUM_PEERS 4

#define DEFAULT_ADDITIONAL_MESSAGES 2

#define MAX_OUTSTANDING_CONNECTIONS 100

static float fail_percentage = 0.00;

static int ok;

static unsigned long long num_additional_messages;

static unsigned long long num_peers;

static unsigned int total_connections;

static unsigned int failed_connections;

static unsigned int total_server_connections;

static unsigned int total_messages_received;

static unsigned int total_other_expected_messages;

static unsigned int temp_total_other_messages;

static unsigned int total_other_messages;

static unsigned int expected_messages;

static unsigned int expected_connections;

static unsigned long long peers_left;

static struct GNUNET_TESTING_PeerGroup *pg;

const struct GNUNET_CONFIGURATION_Handle *main_cfg;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static char *dotOutFileName = "topology.dot";

static FILE *dotOutFile;

static char *blacklist_transports;

static int transmit_ready_scheduled;

static int transmit_ready_failed;

static int transmit_ready_called;

static enum GNUNET_TESTING_Topology topology;

static enum GNUNET_TESTING_Topology blacklist_topology = GNUNET_TESTING_TOPOLOGY_NONE;  /* Don't do any blacklisting */

static enum GNUNET_TESTING_Topology connection_topology = GNUNET_TESTING_TOPOLOGY_NONE; /* NONE actually means connect all allowed peers */

static enum GNUNET_TESTING_TopologyOption connect_topology_option =
    GNUNET_TESTING_TOPOLOGY_OPTION_ALL;

static double connect_topology_option_modifier = 0.0;

static char *test_directory;

struct GNUNET_CONTAINER_MultiHashMap *peer_daemon_hash;

#define MTYPE 12345

GNUNET_NETWORK_STRUCT_BEGIN

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
GNUNET_NETWORK_STRUCT_END

struct PeerContext
{
  /* This is a linked list */
  struct PeerContext *next;

  /**
   * Handle to the daemon
   */
  struct GNUNET_TESTING_Daemon *daemon;

  /* Handle to the peer core */
  struct GNUNET_CORE_Handle *peer_handle;
};

static struct PeerContext *all_peers;

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

static struct TestMessageContext *other_test_messages;

/**
 * Check whether peers successfully shut down.
 */
void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown of peers failed!\n");
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
finish_testing (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (pg != NULL);
  struct PeerContext *peer_pos;
  struct PeerContext *free_peer_pos;
  struct TestMessageContext *pos;
  struct TestMessageContext *free_pos;

  die_task = GNUNET_SCHEDULER_NO_TASK;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Called finish testing, stopping daemons.\n");
#endif
  peer_pos = all_peers;
  while (peer_pos != NULL)
  {
    if (peer_pos->peer_handle != NULL)
      GNUNET_CORE_disconnect (peer_pos->peer_handle);
    free_peer_pos = peer_pos;
    peer_pos = peer_pos->next;
    GNUNET_free (free_peer_pos);
  }
  all_peers = NULL;

  pos = test_messages;
  while (pos != NULL)
  {
    if (pos->peer1handle != NULL)
    {
      GNUNET_CORE_disconnect (pos->peer1handle);
      pos->peer1handle = NULL;
    }
    if (pos->peer2handle != NULL)
    {
      GNUNET_CORE_disconnect (pos->peer2handle);
      pos->peer2handle = NULL;
    }
    free_pos = pos;
    pos = pos->next;
    if (free_pos->disconnect_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (free_pos->disconnect_task);
    }
    GNUNET_free (free_pos);
  }

  pos = other_test_messages;
  while (pos != NULL)
  {
    if (pos->peer1handle != NULL)
    {
      GNUNET_CORE_disconnect (pos->peer1handle);
      pos->peer1handle = NULL;
    }
    if (pos->peer2handle != NULL)
    {
      GNUNET_CORE_disconnect (pos->peer2handle);
      pos->peer2handle = NULL;
    }
    free_pos = pos;
    pos = pos->next;
    if (free_pos->disconnect_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (free_pos->disconnect_task);
    }
    GNUNET_free (free_pos);
  }
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "transmit_ready's scheduled %d, failed %d, transmit_ready's called %d\n",
              transmit_ready_scheduled, transmit_ready_failed,
              transmit_ready_called);
#endif

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Calling daemons_stop\n");
#endif
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "daemons_stop finished\n");
#endif
  if (dotOutFile != NULL)
  {
    FPRINTF (dotOutFile, "%s",  "}");
    FCLOSE (dotOutFile);
  }

  ok = 0;
}


static void
disconnect_cores (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestMessageContext *pos = cls;

  /* Disconnect from the respective cores */
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from peer 1 `%4s'\n",
              GNUNET_i2s (&pos->peer1->id));
#endif
  if (pos->peer1handle != NULL)
    GNUNET_CORE_disconnect (pos->peer1handle);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from peer 2 `%4s'\n",
              GNUNET_i2s (&pos->peer2->id));
#endif
  if (pos->peer2handle != NULL)
    GNUNET_CORE_disconnect (pos->peer2handle);
  /* Set handles to NULL so test case can be ended properly */
  pos->peer1handle = NULL;
  pos->peer2handle = NULL;
  pos->disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  /* Decrement total connections so new can be established */
  total_server_connections -= 2;
}

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char *msg = cls;
  struct TestMessageContext *pos;
  struct TestMessageContext *free_pos;
  struct PeerContext *peer_pos;
  struct PeerContext *free_peer_pos;

  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "End badly was called (%s)... stopping daemons.\n", msg);

  peer_pos = all_peers;
  while (peer_pos != NULL)
  {
    if (peer_pos->peer_handle != NULL)
      GNUNET_CORE_disconnect (peer_pos->peer_handle);
    free_peer_pos = peer_pos;
    peer_pos = peer_pos->next;
    GNUNET_free (free_peer_pos);
  }
  all_peers = NULL;

  pos = test_messages;
  while (pos != NULL)
  {
    if (pos->peer1handle != NULL)
    {
      GNUNET_CORE_disconnect (pos->peer1handle);
      pos->peer1handle = NULL;
    }
    if (pos->peer2handle != NULL)
    {
      GNUNET_CORE_disconnect (pos->peer2handle);
      pos->peer2handle = NULL;
    }
    free_pos = pos;
    pos = pos->next;
    GNUNET_free (free_pos);
  }

  pos = other_test_messages;
  while (pos != NULL)
  {
    if (pos->peer1handle != NULL)
    {
      GNUNET_CORE_disconnect (pos->peer1handle);
      pos->peer1handle = NULL;
    }
    if (pos->peer2handle != NULL)
    {
      GNUNET_CORE_disconnect (pos->peer2handle);
      pos->peer2handle = NULL;
    }
    free_pos = pos;
    pos = pos->next;
    if (free_pos->disconnect_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (free_pos->disconnect_task);
    }
    GNUNET_free (free_pos);
  }

  if (pg != NULL)
  {
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
    ok = 7331;                  /* Opposite of leet */
  }
  else
    ok = 401;                   /* Never got peers started */

  if (dotOutFile != NULL)
  {
    FPRINTF (dotOutFile, "%s",  "}");
    FCLOSE (dotOutFile);
  }
}

static void
send_other_messages (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Get distance information from 'atsi'.
 *
 * @param atsi performance data
 * @return connected transport distance
 */
static uint32_t
get_atsi_distance (const struct GNUNET_ATS_Information *atsi,
                   unsigned int atsi_count)
{
  unsigned int i;

  for (i = 0; i < atsi_count; i++)
  {
    if (ntohl (atsi->type) == GNUNET_ATS_QUALITY_NET_DISTANCE)
      return ntohl (atsi->value);
  }

  GNUNET_break (0);
  /* FIXME: we do not have distance data? Assume direct neighbor. */
  return 1;
}


static int
process_mtype (void *cls, const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_MessageHeader *message,
               const struct GNUNET_ATS_Information *atsi,
               unsigned int atsi_count)
{
  struct TestMessageContext *pos = cls;
  struct GNUNET_TestMessage *msg = (struct GNUNET_TestMessage *) message;

#if VERBOSE
  uint32_t distance;
#endif
  if (pos->uid != ntohl (msg->uid))
    return GNUNET_OK;

#if VERBOSE
  distance = get_atsi_distance (atsi, atsi_count);
#endif
  GNUNET_assert (0 ==
                 memcmp (peer, &pos->peer1->id,
                         sizeof (struct GNUNET_PeerIdentity)));
  if (total_other_expected_messages == 0)
  {
    total_messages_received++;
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received message from `%4s', type %d, uid %u, distance %u.\n",
                GNUNET_i2s (peer), ntohs (message->type), ntohl (msg->uid),
                distance);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Total messages received %d, expected %d.\n",
                total_messages_received, expected_messages);
#endif
  }
  else
  {
    total_other_messages++;
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received message from `%4s', type %d, uid %u, distance %u.\n",
                GNUNET_i2s (peer), ntohs (message->type), ntohl (msg->uid),
                distance);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Total OTHER messages received %d, expected %d.\n",
                total_other_messages, total_other_expected_messages);
#endif
  }

  if ((total_messages_received == expected_messages) &&
      (total_other_messages == 0))
  {
    GNUNET_SCHEDULER_cancel (die_task);
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Scheduling timeout from DV connections.\n");
#endif
    die_task =
        GNUNET_SCHEDULER_add_delayed (TEST_TIMEOUT, &end_badly,
                                      "waiting for DV peers to connect!");
  }
  else if ((total_other_expected_messages > 0) &&
           (total_other_messages == total_other_expected_messages))
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&finish_testing, NULL);
  }
  else
  {
    pos->disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_cores, pos);
  }

  return GNUNET_OK;
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
  m->uid = htonl (pos->uid);
  transmit_ready_called++;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "transmit ready for peer %s\ntransmit_ready's scheduled %d, transmit_ready's called %d\n",
              GNUNET_i2s (&pos->peer1->id), transmit_ready_scheduled,
              transmit_ready_called);
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

/**
 * Notify of all peer1's peers, once peer 2 is found, schedule connect
 * to peer two for message send.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data for the connection
 * @param atsi_count number of ATS information included
 */
static void
connect_notify_peer2 (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_ATS_Information *atsi,
                      unsigned int atsi_count)
{
  struct TestMessageContext *pos = cls;

  if (0 == memcmp (&pos->peer1->id, peer, sizeof (struct GNUNET_PeerIdentity)))
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Core connection from `%s' to `%4s' verfied, sending message!\n",
                GNUNET_i2s (&pos->peer2->id), GNUNET_h2s (&peer->hashPubKey));
#endif
    if (NULL ==
        GNUNET_CORE_notify_transmit_ready (pos->peer1handle, GNUNET_YES, 0,
                                           TIMEOUT, &pos->peer2->id,
                                           sizeof (struct GNUNET_TestMessage),
                                           &transmit_ready, pos))
    {
      /* This probably shouldn't happen, but it does (timing issue?) */
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "RECEIVED NULL when asking core (1) for transmission to peer `%4s'\n",
                  GNUNET_i2s (&pos->peer2->id));
      transmit_ready_failed++;
      total_other_expected_messages--;
    }
    else
    {
      transmit_ready_scheduled++;
    }
  }
}

static void
init_notify_peer2 (void *cls, struct GNUNET_CORE_Handle *server,
                   const struct GNUNET_PeerIdentity *my_identity)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core connection to `%4s' established, awaiting connections.\n",
              GNUNET_i2s (my_identity));
#endif
  total_server_connections++;
}

/**
 * Notify of all peer1's peers, once peer 2 is found, schedule connect
 * to peer two for message send.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data for the connection
 * @param atsi_count number of atsi datums
 */
static void
connect_notify_peer1 (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_ATS_Information *atsi,
                      unsigned int atsi_count)
{
  struct TestMessageContext *pos = cls;

  if (0 == memcmp (&pos->peer2->id, peer, sizeof (struct GNUNET_PeerIdentity)))
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Core connection from `%s' to `%4s' verified.\n",
                GNUNET_i2s (&pos->peer1->id), GNUNET_h2s (&peer->hashPubKey));
#endif
    /*
     * Connect to the receiving peer
     */
    pos->peer2handle =
        GNUNET_CORE_connect (pos->peer2->cfg, 1, pos, &init_notify_peer2,
                             &connect_notify_peer2, NULL, NULL, GNUNET_YES,
                             NULL, GNUNET_YES, handlers);
  }
}

static void
init_notify_peer1 (void *cls, struct GNUNET_CORE_Handle *server,
                   const struct GNUNET_PeerIdentity *my_identity)
{
  total_server_connections++;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core connection to `%4s' established, awaiting connections...\n",
              GNUNET_i2s (my_identity));
#endif
}


static void
send_test_messages (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestMessageContext *pos = cls;

  if (((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0) || (cls == NULL))
    return;

  if (die_task == GNUNET_SCHEDULER_NO_TASK)
  {
    die_task =
        GNUNET_SCHEDULER_add_delayed (TEST_TIMEOUT, &end_badly,
                                      "from create topology (timeout)");
  }

  if (total_server_connections >= MAX_OUTSTANDING_CONNECTIONS)
  {
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 1),
                                  &send_test_messages, pos);
    return;                     /* Otherwise we'll double schedule messages here! */
  }
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Attempting to send test message from %s to %s\n",
              pos->peer1->shortname, pos->peer2->shortname);
#endif
  /*
   * Connect to the sending peer
   */
  pos->peer1handle =
      GNUNET_CORE_connect (pos->peer1->cfg, 1, pos, &init_notify_peer1,
                           &connect_notify_peer1, NULL, NULL, GNUNET_NO, NULL,
                           GNUNET_NO, no_handlers);

  GNUNET_assert (pos->peer1handle != NULL);

  if (total_server_connections < MAX_OUTSTANDING_CONNECTIONS)
  {
    GNUNET_SCHEDULER_add_now (&send_test_messages, pos->next);
  }
  else
  {
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 1),
                                  &send_test_messages, pos->next);
  }
}

static void
send_other_messages (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestMessageContext *pos;
  struct TestMessageContext *free_pos;
  struct PeerContext *peer_pos;

#if TEST_ALL
  struct PeerContext *inner_peer_pos;
  struct TestMessageContext *temp_context;
#endif
  peer_pos = all_peers;
  while (peer_pos != NULL)
  {
    if (peer_pos->peer_handle != NULL)
    {
      GNUNET_CORE_disconnect (peer_pos->peer_handle);
      peer_pos->peer_handle = NULL;
    }
#if TEST_ALL
    inner_peer_pos = all_peers;
    while (inner_peer_pos != NULL)
    {
      if (inner_peer_pos != peer_pos)
      {
        temp_total_other_messages++;
        temp_context = GNUNET_malloc (sizeof (struct TestMessageContext));
        temp_context->peer1 = peer_pos->daemon;
        temp_context->peer2 = inner_peer_pos->daemon;
        temp_context->next = other_test_messages;
        temp_context->uid = total_connections + temp_total_other_messages;
        temp_context->disconnect_task = GNUNET_SCHEDULER_NO_TASK;
        other_test_messages = temp_context;
      }
      inner_peer_pos = inner_peer_pos->next;
    }
#endif
    peer_pos = peer_pos->next;
  }
  all_peers = NULL;

  pos = test_messages;
  while (pos != NULL)
  {
    if (pos->peer1handle != NULL)
    {
      GNUNET_CORE_disconnect (pos->peer1handle);
      pos->peer1handle = NULL;
    }
    if (pos->peer2handle != NULL)
    {
      GNUNET_CORE_disconnect (pos->peer2handle);
      pos->peer2handle = NULL;
    }
    free_pos = pos;
    pos = pos->next;
    if (free_pos->disconnect_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (free_pos->disconnect_task);
    }
    GNUNET_free (free_pos);
  }
  test_messages = NULL;

  total_other_expected_messages = temp_total_other_messages;
  if (total_other_expected_messages == 0)
  {
    GNUNET_SCHEDULER_add_now (&end_badly,
                              "send_other_messages had 0 messages to send, no DV connections made!");
  }
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Preparing to send %d other test messages\n",
              total_other_expected_messages);
#endif

  GNUNET_SCHEDULER_add_now (&send_test_messages, other_test_messages);
  if (GNUNET_SCHEDULER_NO_TASK != die_task)
    GNUNET_SCHEDULER_cancel (die_task);
  die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 250), &end_badly,
                                    "from send_other_messages");
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
  struct TestMessageContext *temp_context;

  if (emsg == NULL)
  {
    total_connections++;
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "connected peer %s to peer %s, distance %u\n",
                first_daemon->shortname, second_daemon->shortname, distance);
#endif
    temp_context = GNUNET_malloc (sizeof (struct TestMessageContext));
    temp_context->peer1 = first_daemon;
    temp_context->peer2 = second_daemon;
    temp_context->next = test_messages;
    temp_context->uid = total_connections;
    temp_context->disconnect_task = GNUNET_SCHEDULER_NO_TASK;
    test_messages = temp_context;
    expected_messages++;
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
                "Created %u total connections, which is our target number!  Calling send messages.\n",
                total_connections);
#endif
    if (GNUNET_SCHEDULER_NO_TASK != die_task)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_SCHEDULER_add_now (&send_test_messages, test_messages);
  }
  else if (total_connections + failed_connections == expected_connections)
  {
    if (failed_connections <
        (unsigned int) (fail_percentage * total_connections))
    {
      GNUNET_SCHEDULER_cancel (die_task);
      die_task = GNUNET_SCHEDULER_NO_TASK;
      /* FIXME: ret value!? */ GNUNET_SCHEDULER_add_now (&send_test_messages,
                                                         test_messages);
    }
    else
    {
      if (die_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (die_task);
      die_task =
          GNUNET_SCHEDULER_add_now (&end_badly,
                                    "from topology_callback (too many failed connections)");
    }
  }
  else
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Have %d total connections, %d failed connections, Want %d (at least %d)\n",
                total_connections, failed_connections, expected_connections,
                expected_connections -
                (unsigned int) (fail_percentage * expected_connections));
#endif
  }
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data about this peer's connection
 * @param atsi_count number of atsi datums
 *
 */
static void
all_connect_handler (void *cls, const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_ATS_Information *atsi,
                     unsigned int atsi_count)
{
  struct GNUNET_TESTING_Daemon *d = cls;
  struct GNUNET_TESTING_Daemon *second_daemon;
  char *second_shortname;

#if !TEST_ALL
  struct TestMessageContext *temp_context;
#endif
  uint32_t distance;

  if (0 == memcmp (&d->id, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  second_shortname = GNUNET_strdup (GNUNET_i2s (peer));
  distance = get_atsi_distance (atsi, atsi_count);

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "connected peer %s to peer %s, distance %u\n", d->shortname,
              second_shortname, distance);
#endif

  second_daemon =
      GNUNET_CONTAINER_multihashmap_get (peer_daemon_hash, &peer->hashPubKey);

  if (second_daemon == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Couldn't find second peer!\n");
    GNUNET_free (second_shortname);
    return;
  }
#if !TEST_ALL
  if (distance > 1)
  {
    temp_total_other_messages++;
    temp_context = GNUNET_malloc (sizeof (struct TestMessageContext));
    temp_context->peer1 = d;
    temp_context->peer2 = second_daemon;
    temp_context->next = other_test_messages;
    temp_context->uid = total_connections + temp_total_other_messages;
    temp_context->disconnect_task = GNUNET_SCHEDULER_NO_TASK;
    other_test_messages = temp_context;
  }
#endif

  if (dotOutFile != NULL)
  {
    if (distance == 1)
      FPRINTF (dotOutFile, "\tn%s -- n%s;\n", d->shortname, second_shortname);
    else if (distance == 2)
      FPRINTF (dotOutFile, "\tn%s -- n%s [color=blue];\n", d->shortname,
               second_shortname);
    else if (distance == 3)
      FPRINTF (dotOutFile, "\tn%s -- n%s [color=red];\n", d->shortname,
               second_shortname);
    else if (distance == 4)
      FPRINTF (dotOutFile, "\tn%s -- n%s [color=green];\n", d->shortname,
               second_shortname);
    else
      FPRINTF (dotOutFile, "\tn%s -- n%s [color=brown];\n", d->shortname,
               second_shortname);
  }
  GNUNET_free (second_shortname);

  if (temp_total_other_messages == num_additional_messages)
  {
    /* FIXME: ret value!? */ GNUNET_SCHEDULER_add_now (&send_other_messages,
                                                       NULL);
  }
}

static void
peers_started_callback (void *cls, const struct GNUNET_PeerIdentity *id,
                        const struct GNUNET_CONFIGURATION_Handle *cfg,
                        struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  struct PeerContext *new_peer;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to start daemon with error: `%s'\n", emsg);
    return;
  }
  GNUNET_assert (id != NULL);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Started daemon %llu out of %llu\n",
              (num_peers - peers_left) + 1, num_peers);
#endif
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CONTAINER_multihashmap_put (peer_daemon_hash,
                                                    &id->hashPubKey, d,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  new_peer = GNUNET_malloc (sizeof (struct PeerContext));
  new_peer->peer_handle =
      GNUNET_CORE_connect (cfg, 1, d, NULL, &all_connect_handler, NULL, NULL,
                           GNUNET_NO, NULL, GNUNET_NO, no_handlers);
  new_peer->daemon = d;
  new_peer->next = all_peers;
  all_peers = new_peer;
  peers_left--;

  if (peers_left == 0)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All %d daemons started, now creating topology!\n", num_peers);
#endif
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
    expected_connections = -1;
    if ((pg != NULL) && (peers_left == 0))
    {
      expected_connections =
          GNUNET_TESTING_connect_topology (pg, connection_topology,
                                           connect_topology_option,
                                           connect_topology_option_modifier,
                                           TIMEOUT, 12, NULL, NULL);
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Have %d expected connections\n",
                  expected_connections);
#endif
    }

    if (expected_connections == GNUNET_SYSERR)
    {
      die_task =
          GNUNET_SCHEDULER_add_now (&end_badly,
                                    "from connect topology (bad return)");
    }
    else
    {
      /* Set up task in case topology creation doesn't finish
       * within a reasonable amount of time */
      die_task =
          GNUNET_SCHEDULER_add_delayed (TEST_TIMEOUT, &end_badly,
                                        "from connect topology (timeout)");
    }
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
static void
hostkey_callback (void *cls, const struct GNUNET_PeerIdentity *id,
                  struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Hostkey callback received error: %s\n", emsg);
  }

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Hostkey created for peer `%s'\n",
              GNUNET_i2s (id));
#endif
  peers_left--;
  if (peers_left == 0)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All %d hostkeys created, now creating topology!\n", num_peers);
#endif
    if (GNUNET_SCHEDULER_NO_TASK != die_task)
    {
      GNUNET_SCHEDULER_cancel (die_task);
      die_task = GNUNET_SCHEDULER_NO_TASK;
    }
    /* create topology */
    peers_left = num_peers;     /* Reset counter */
    if (GNUNET_TESTING_create_topology
        (pg, topology, blacklist_topology,
         blacklist_transports) != GNUNET_SYSERR)
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Topology set up, now starting peers!\n");
#endif
      GNUNET_TESTING_daemons_continue_startup (pg);
      /* Set up task in case topology creation doesn't finish
       * within a reasonable amount of time */
      die_task =
          GNUNET_SCHEDULER_add_delayed (TEST_TIMEOUT, &end_badly,
                                        "from continue startup (timeout)");
    }
    else
    {
      die_task =
          GNUNET_SCHEDULER_add_now (&end_badly,
                                    "from create topology (bad return)");
    }
    ok = 0;
  }
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *topology_str;
  char *connect_topology_str;
  char *blacklist_topology_str;
  char *connect_topology_option_str;
  char *connect_topology_option_modifier_string;

  ok = 1;

  dotOutFile = fopen (dotOutFileName, "w");
  if (dotOutFile != NULL)
  {
    FPRINTF (dotOutFile, "%s",  "strict graph G {\n");
  }

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting daemons based on config file %s\n", cfgfile);
#endif

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "paths", "servicehome",
                                             &test_directory))
  {
    ok = 404;
    return;
  }

  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "topology",
                                              &topology_str)) &&
      (GNUNET_NO == GNUNET_TESTING_topology_get (&topology, topology_str)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid topology `%s' given for section %s option %s\n",
                topology_str, "TESTING", "TOPOLOGY");
    topology = GNUNET_TESTING_TOPOLOGY_CLIQUE;  /* Defaults to NONE, so set better default here */
  }

  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                              "connect_topology",
                                              &connect_topology_str)) &&
      (GNUNET_NO ==
       GNUNET_TESTING_topology_get (&connection_topology,
                                    connect_topology_str)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid connect topology `%s' given for section %s option %s\n",
                connect_topology_str, "TESTING", "CONNECT_TOPOLOGY");
  }
  GNUNET_free_non_null (connect_topology_str);
  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                              "connect_topology_option",
                                              &connect_topology_option_str)) &&
      (GNUNET_NO ==
       GNUNET_TESTING_topology_option_get (&connect_topology_option,
                                           connect_topology_option_str)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid connect topology option `%s' given for section %s option %s\n",
                connect_topology_option_str, "TESTING",
                "CONNECT_TOPOLOGY_OPTION");
    connect_topology_option = GNUNET_TESTING_TOPOLOGY_OPTION_ALL;       /* Defaults to NONE, set to ALL */
  }
  GNUNET_free_non_null (connect_topology_option_str);
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                             "connect_topology_option_modifier",
                                             &connect_topology_option_modifier_string))
  {
    if (sscanf
        (connect_topology_option_modifier_string, "%lf",
         &connect_topology_option_modifier) != 1)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
                  connect_topology_option_modifier_string,
                  "connect_topology_option_modifier", "TESTING");
    }
    GNUNET_free (connect_topology_option_modifier_string);
  }

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                             "blacklist_transports",
                                             &blacklist_transports))
    blacklist_transports = NULL;

  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                              "blacklist_topology",
                                              &blacklist_topology_str)) &&
      (GNUNET_NO ==
       GNUNET_TESTING_topology_get (&blacklist_topology,
                                    blacklist_topology_str)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid topology `%s' given for section %s option %s\n",
                topology_str, "TESTING", "BLACKLIST_TOPOLOGY");
  }
  GNUNET_free_non_null (topology_str);
  GNUNET_free_non_null (blacklist_topology_str);
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing",
                                             "additional_messages",
                                             &num_additional_messages))
    num_additional_messages = DEFAULT_ADDITIONAL_MESSAGES;

  main_cfg = cfg;

  GNUNET_assert (num_peers > 0 && num_peers < (unsigned int) -1);
  peers_left = num_peers;

  /* Set up a task to end testing if peer start fails */
  die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES, 5), &end_badly,
                                    "didn't start all daemons in reasonable amount of time!!!");

  peer_daemon_hash = GNUNET_CONTAINER_multihashmap_create (peers_left);
  pg = GNUNET_TESTING_daemons_start (cfg, peers_left,   /* Total number of peers */
                                     peers_left,        /* Number of outstanding connections */
                                     peers_left,        /* Number of parallel ssh connections, or peers being started at once */
                                     TIMEOUT, &hostkey_callback, NULL,
                                     &peers_started_callback, NULL,
                                     &topology_callback, NULL, NULL);

}

static int
check ()
{
  int ret;

  char *const argv[] = { "test-transport-dv",
    "-c",
    "test_transport_dv_data.conf",
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
                          "test-transport-dv", "nohelp", options, &run, &ok);
  if (ret != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "`test-transport-dv': Failed with error code %d\n", ret);
  }
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-transport-dv",
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

/* end of test_transport_api_dv.c */
