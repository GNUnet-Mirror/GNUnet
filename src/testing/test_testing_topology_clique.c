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
 * @file testing/test_testing_group.c
 * @brief testcase for functions to connect two peers in testing.c
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"

#define VERBOSE GNUNET_NO

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

#define DEFAULT_NUM_PEERS 4;

static int ok;

static unsigned long long num_peers;

static unsigned int total_connections;

static unsigned int expected_connections;

static int peers_left;

static struct GNUNET_TESTING_PeerGroup *pg;

static struct GNUNET_SCHEDULER_Handle *sched;

const struct GNUNET_CONFIGURATION_Handle *main_cfg;

GNUNET_SCHEDULER_TaskIdentifier die_task;

static struct GNUNET_CORE_Handle *peer1handle;

static struct GNUNET_CORE_Handle *peer2handle;

#define MTYPE 12345

static void
finish_testing ()
{
  GNUNET_assert (pg != NULL);

  if (peer1handle != NULL)
    GNUNET_CORE_disconnect(peer1handle);
  if (peer2handle != NULL)
    GNUNET_CORE_disconnect(peer2handle);

  GNUNET_TESTING_daemons_stop (pg);
  ok = 0;
}

static int
process_mtype (void *cls,
               const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_MessageHeader *message,
               struct GNUNET_TIME_Relative latency,
               uint32_t distance)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Receiving message from `%4s'.\n", GNUNET_i2s (peer));
#endif
  GNUNET_SCHEDULER_cancel (sched, die_task);
  GNUNET_SCHEDULER_add_now (sched, &finish_testing, NULL);
  return GNUNET_OK;
}


static void
connect_notify (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                struct GNUNET_TIME_Relative latency,
                uint32_t distance)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted connection established to peer `%4s' with latency %llu\n",
              GNUNET_i2s (peer), latency.value);
#endif
}


static void
disconnect_notify (void *cls,
                   const struct GNUNET_PeerIdentity *peer)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted connection to `%4s' cut\n", GNUNET_i2s (peer));
#endif
}


static int
inbound_notify (void *cls,
                const struct GNUNET_PeerIdentity *other,
                const struct GNUNET_MessageHeader *message,
                struct GNUNET_TIME_Relative latency,
                uint32_t distance)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core provides inbound data from `%4s'.\n", GNUNET_i2s (other));
#endif
  return GNUNET_OK;
}


static int
outbound_notify (void *cls,
                 const struct GNUNET_PeerIdentity *other,
                 const struct GNUNET_MessageHeader *message,
                 struct GNUNET_TIME_Relative latency,
                 uint32_t distance)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core notifies about outbound data for `%4s'.\n",
              GNUNET_i2s (other));
#endif
  return GNUNET_OK;
}

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "End badly was called... stopping daemons.\n");
#endif

  if (peer1handle != NULL)
    {
      GNUNET_CORE_disconnect(peer1handle);
      peer1handle = NULL;
    }
  if (peer2handle != NULL)
    {
      GNUNET_CORE_disconnect(peer2handle);
      peer2handle = NULL;
    }

  if (pg != NULL)
    {
      GNUNET_TESTING_daemons_stop (pg);
      ok = 7331;                /* Opposite of leet */
    }
  else
    ok = 401;                   /* Never got peers started */
}

static size_t
transmit_ready (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *m;

  GNUNET_assert (buf != NULL);
  m = (struct GNUNET_MessageHeader *) buf;
  m->type = htons (MTYPE);
  m->size = htons (sizeof (struct GNUNET_MessageHeader));
  GNUNET_SCHEDULER_cancel(sched, die_task);
  die_task =
    GNUNET_SCHEDULER_add_delayed (sched,
        TIMEOUT, &end_badly, "from transmit ready");

  return sizeof (struct GNUNET_MessageHeader);
}


static struct GNUNET_CORE_MessageHandler handlers[] = {
  {&process_mtype, MTYPE, sizeof (struct GNUNET_MessageHeader)},
  {NULL, 0, 0}
};


static void
init_notify (void *cls,
             struct GNUNET_CORE_Handle *server,
             const struct GNUNET_PeerIdentity *my_identity,
             const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
  struct GNUNET_TESTING_Daemon *connected_peer = cls;
  struct GNUNET_TESTING_Daemon *peer1;
  struct GNUNET_TESTING_Daemon *peer2;

  peer1 = GNUNET_TESTING_daemon_get(pg, 0);
  peer2 = GNUNET_TESTING_daemon_get(pg, 1);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core connection to `%4s' established, setting up handles\n",
              GNUNET_i2s (my_identity));
#endif

  if (connected_peer == peer1)
    {
      peer1handle = server;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting core to peer 2\n");
#endif
      /* connect p2 */
      GNUNET_CORE_connect (sched,
                           peer2->cfg,
                           TIMEOUT,
                           peer2,
                           &init_notify,
                           NULL,
                           &connect_notify,
                           &disconnect_notify,
                           &inbound_notify,
                           GNUNET_YES,
                           &outbound_notify, GNUNET_YES, handlers);
    }
  else
    {
      GNUNET_assert(connected_peer == peer2);
      peer2handle = server;
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Asking core (1) for transmission to peer `%4s'\n",
                  GNUNET_i2s (&peer2->id));
#endif

      if (NULL == GNUNET_CORE_notify_transmit_ready (peer1->server,
                                                     0,
                                                     TIMEOUT,
                                                     &peer2->id,
                                                     sizeof (struct GNUNET_MessageHeader),
                                                     &transmit_ready, &peer1))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "RECEIVED NULL when asking core (1) for transmission to peer `%4s'\n",
                      GNUNET_i2s (&peer2->id));
        }

    }
}


static void
send_test_messages ()
{
  struct GNUNET_TESTING_Daemon *peer1;
  struct GNUNET_TESTING_Daemon *peer2;

  peer1 = GNUNET_TESTING_daemon_get(pg, 0);
  peer2 = GNUNET_TESTING_daemon_get(pg, 1);

  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           TIMEOUT,
                                           &end_badly, "from send test messages");

  /* Send a message from peer 1 to peer 2 */
  GNUNET_CORE_connect (sched,
                       peer1->cfg,
                       TIMEOUT,
                       peer1,
                       &init_notify,
                       NULL,
                       &connect_notify,
                       &disconnect_notify,
                       &inbound_notify,
                       GNUNET_YES, &outbound_notify, GNUNET_YES, handlers);
}

void
topology_callback (void *cls,
                   const struct GNUNET_PeerIdentity *first,
                   const struct GNUNET_PeerIdentity *second,
                   const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                   const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                   struct GNUNET_TESTING_Daemon *first_daemon,
                   struct GNUNET_TESTING_Daemon *second_daemon,
                   const char *emsg)
{
  /* Keep track of connections here if the client needs to know?
   * Still, we have no real handle to say the i'th peer of the peer group
   * even though we know that X peers exist in i...  But we may want to
   * know about the peer for logging purposes here (I'm sure we will actually
   * so the API may need changed).  Question, should the API expose what
   * a peer group is, or provide convenience/accessor functions?
   *
   * For now, I've added accessor functions, which seems like a software
   * engineering kind of solution, but who knows/cares. */
  if (emsg == NULL)
    {
      total_connections++;
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "connected peer %s to peer %s\n",
               first_daemon->shortname,
               second_daemon->shortname);
#endif
    }
#if VERBOSE
  else
    {

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to connect peer %s to peer %s with error %s\n",
               first_daemon->shortname,
               second_daemon->shortname, emsg);
    }
#endif

  if (total_connections == expected_connections)
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Created %d total connections, which is our target number!  Ending test.\n",
                  total_connections);
#endif

      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_add_now (sched, &send_test_messages, NULL);
    }
  else
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Have %d total connections, Need %d\n",
                  total_connections, expected_connections);
#endif
    }
}


static void
create_topology ()
{
  expected_connections = -1;
  if ((pg != NULL) && (peers_left == 0))
    {
      /* create_topology will read the topology information from
         the config already contained in the peer group, so should
         we have create_topology called from start peers?  I think
         maybe this way is best so that the client can know both
         when peers are started, and when they are connected.
       */
      expected_connections = GNUNET_TESTING_create_topology (pg);
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Have %d expected connections\n", expected_connections);
#endif
    }

  GNUNET_SCHEDULER_cancel (sched, die_task);
  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           TIMEOUT,
                                           &end_badly, NULL);
}


static void
my_cb (void *cls,
       const struct GNUNET_PeerIdentity *id,
       const struct GNUNET_CONFIGURATION_Handle *cfg,
       struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  GNUNET_assert (id != NULL);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Started daemon %d out of %d\n",
              (num_peers - peers_left) + 1, num_peers);
#endif
  peers_left--;
  if (peers_left == 0)
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "All %d daemons started, now creating topology!\n",
                  num_peers);
#endif
      GNUNET_SCHEDULER_cancel (sched, die_task);
      /* Set up task in case topology creation doesn't finish
       * within a reasonable amount of time */
      die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                               GNUNET_TIME_relative_multiply
                                               (GNUNET_TIME_UNIT_MINUTES, 5),
                                               &end_badly, NULL);
      create_topology ();
      ok = 0;
    }
}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  sched = s;
  ok = 1;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting daemons based on config file %s\n", cfgfile);
#endif
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;

  main_cfg = cfg;

  peers_left = num_peers;

  /* Set up a task to end testing if peer start fails */
  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           GNUNET_TIME_relative_multiply
                                           (GNUNET_TIME_UNIT_MINUTES, 5),
                                           &end_badly, NULL);

  pg = GNUNET_TESTING_daemons_start (sched, cfg,
                                     peers_left, &my_cb, NULL,
                                     &topology_callback, NULL, NULL);

  /*
     if (ret != GNUNET_SYSERR)
     ret = send_test_messages (pg);
   */

}

static int
check ()
{
  char *const argv[] = { "test-testing-topology-clique",
    "-c",
    "test_testing_data_topology_clique.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-testing-topology-clique", "nohelp",
                      options, &run, &ok);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-testing-topology_clique",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  sleep (1);
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-testing");
  return ret;
}

/* end of test_testing_group.c */
