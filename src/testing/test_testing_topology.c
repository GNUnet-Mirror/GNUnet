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
 * @file testing/test_testing_topology.c
 * @brief base testcase for testing all the topologies provided
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"

#define VERBOSE GNUNET_YES

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

#define DEFAULT_NUM_PEERS 4;

static int ok;

static unsigned long long num_peers;

static unsigned int total_connections;

static unsigned int total_server_connections;

static unsigned int total_messages_received;

static unsigned int expected_messages;

static unsigned int expected_connections;

static int peers_left;

static struct GNUNET_TESTING_PeerGroup *pg;

static struct GNUNET_SCHEDULER_Handle *sched;

const struct GNUNET_CONFIGURATION_Handle *main_cfg;

GNUNET_SCHEDULER_TaskIdentifier die_task;

static char *dotOutFileName = "topology.dot";

static FILE *dotOutFile;

static char *topology_string;

static int transmit_ready_scheduled;

static int transmit_ready_called;

struct TestMessageContext *global_pos;

#define MTYPE 12345

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

  /* Maintain some state */
  int first_step_done;

};

struct Connection
{
  struct Connection *next;
  struct GNUNET_TESTING_Daemon *peer;
  struct GNUNET_CORE_Handle *server;
};

static struct Connection *global_connections;

static struct TestMessageContext *test_messages;

static void
finish_testing ()
{
  GNUNET_assert (pg != NULL);
  struct Connection *pos;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Called finish testing, stopping daemons.\n");
#endif
  int count;
  count = 0;
  pos = global_connections;
  while (pos != NULL)
    {
      if (pos->server != NULL)
        {
          GNUNET_CORE_disconnect(pos->server);
          pos->server = NULL;
        }
      pos = pos->next;
    }
#if VERBOSE
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "transmit_ready's scheduled %d, transmit_ready's called %d\n", transmit_ready_scheduled, transmit_ready_called);
#endif
  sleep(1);
#if VERBOSE
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Calling daemons_stop\n");
#endif
  GNUNET_TESTING_daemons_stop (pg);
#if VERBOSE
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "daemons_stop finished\n");
#endif
  if (dotOutFile != NULL)
    {
      fprintf(dotOutFile, "}");
      fclose(dotOutFile);
    }

  ok = 0;
}

static int
process_mtype (void *cls,
               const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_MessageHeader *message,
               struct GNUNET_TIME_Relative latency,
               uint32_t distance)
{
  total_messages_received++;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message from `%4s', type %d.\n", GNUNET_i2s (peer), ntohs(message->type));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Total messages received %d, expected %d.\n", total_messages_received, expected_messages);
#endif

  if (total_messages_received == expected_messages)
    {
      GNUNET_SCHEDULER_cancel (sched, die_task);
      GNUNET_SCHEDULER_add_now (sched, &finish_testing, NULL);
    }
  return GNUNET_OK;
}

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "End badly was called... stopping daemons.\n");
#endif
  struct Connection *pos;

  pos = global_connections;
  while (pos != NULL)
    {
      if (pos->server != NULL)
        {
          GNUNET_CORE_disconnect(pos->server);
          pos->server = NULL;
        }
      pos = pos->next;
    }

  if (pg != NULL)
    {
      GNUNET_TESTING_daemons_stop (pg);
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


/**
 * Forward declaration.
 */
static size_t
transmit_ready (void *cls, size_t size, void *buf);

static void
schedule_transmission (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{

  if (global_pos != NULL)
  {
    if (NULL == GNUNET_CORE_notify_transmit_ready (global_pos->peer1handle,
                                                 0,
                                                 TIMEOUT,
                                                 &global_pos->peer2->id,
                                                 sizeof (struct GNUNET_MessageHeader),
                                                 &transmit_ready, &global_pos->peer1->id))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "RECEIVED NULL when asking core (1) for transmission to peer `%4s'\n",
                    GNUNET_i2s (&global_pos->peer2->id));
      }
    else
      {
        transmit_ready_scheduled++;
      }
    global_pos = global_pos->next;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmit ready scheduled on %d messages\n",
                transmit_ready_scheduled);
  }

}

static size_t
transmit_ready (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *m;
  struct GNUNET_PeerIdentity *peer = cls;
  GNUNET_assert (buf != NULL);
  m = (struct GNUNET_MessageHeader *) buf;
  m->type = htons (MTYPE);
  m->size = htons (sizeof (struct GNUNET_MessageHeader));

  transmit_ready_called++;
#if VERBOSE
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "transmit ready for peer %s\ntransmit_ready's scheduled %d, transmit_ready's called %d\n", GNUNET_i2s(peer), transmit_ready_scheduled, transmit_ready_called);
#endif
  GNUNET_SCHEDULER_add_now(sched, &schedule_transmission, NULL);
  return sizeof (struct GNUNET_MessageHeader);
}


static struct GNUNET_CORE_MessageHandler handlers[] = {
  {&process_mtype, MTYPE, sizeof (struct GNUNET_MessageHeader)},
  {NULL, 0, 0}
};



static void
send_test_messages ()
{
  struct TestMessageContext *pos;
  struct Connection *conn_pos;
  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           TIMEOUT,
                                           &end_badly, "from send test messages");

  int count = 0;
  int conn_count = 0;
  pos = test_messages;
  while (pos != NULL)
    {
      conn_pos = global_connections;
      conn_count = 0;
      while (conn_pos != NULL)
        {
          if (conn_pos->peer == pos->peer1)
            {
              pos->peer1handle = conn_pos->server;
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                                "Peer matched conn_count %d\n",
                                conn_count);
              break;
            }
          conn_count++;
          conn_pos = conn_pos->next;
        }
      GNUNET_assert(pos->peer1handle != NULL);

      /*
      if (NULL == GNUNET_CORE_notify_transmit_ready (pos->peer1handle,
                                                   0,
                                                   TIMEOUT,
                                                   &pos->peer2->id,
                                                   sizeof (struct GNUNET_MessageHeader),
                                                   &transmit_ready, &pos->peer1->id))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "RECEIVED NULL when asking core (1) for transmission to peer `%4s'\n",
                      GNUNET_i2s (&pos->peer2->id));
        }
      else
        {
          transmit_ready_scheduled++;
        }
      */
      pos = pos->next;
      count++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Prepared %d messages\n",
                  count);
    }

  global_pos = test_messages;

  GNUNET_SCHEDULER_add_now(sched, &schedule_transmission, NULL);
}



static void
init_notify (void *cls,
             struct GNUNET_CORE_Handle *server,
             const struct GNUNET_PeerIdentity *my_identity,
             const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
  struct Connection *connection = cls;

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core connection to `%4s' established, setting up handles\n",
              GNUNET_i2s (my_identity));
#endif
  connection->server = server;
  total_server_connections++;

  if (total_server_connections == num_peers)
    {
      GNUNET_SCHEDULER_cancel(sched, die_task);
      GNUNET_SCHEDULER_add_now(sched, &send_test_messages, NULL);
    }
#if OLD
  if (context->first_step_done == GNUNET_NO)
    {
      context->peer1handle = server;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting core to peer 2\n");
#endif
      context->first_step_done = GNUNET_YES;
      /* connect p2 */
      GNUNET_CORE_connect (sched,
                           context->peer2->cfg,
                           TIMEOUT,
                           context,
                           &init_notify,
                           NULL,
                           NULL,
                           NULL,
                           NULL,
                           GNUNET_YES,
                           NULL, GNUNET_YES, handlers);

    }
  else
    {
      context->peer2handle = server;
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Asking core (1) for transmission to peer `%4s'\n",
                  GNUNET_i2s (&context->peer2->id));
#endif
      transmit_ready_scheduled++;
      if (NULL == GNUNET_CORE_notify_transmit_ready (context->peer1->server,
                                                     0,
                                                     TIMEOUT,
                                                     &context->peer2->id,
                                                     sizeof (struct GNUNET_MessageHeader),
                                                     &transmit_ready, NULL))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "RECEIVED NULL when asking core (1) for transmission to peer `%4s'\n",
                      GNUNET_i2s (&context->peer2->id));
        }
    }
#endif
}


static void
setup_handlers ()
{
  int i;
  struct Connection *new_connection;

  struct GNUNET_TESTING_Daemon *temp_daemon;
  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           TIMEOUT,
                                           &end_badly, "from setup_handlers");


  /**
   * Set up a single handler for each peer
   */
  for (i = 0; i < num_peers; i++)
    {
      new_connection = GNUNET_malloc(sizeof(struct Connection));
      temp_daemon = GNUNET_TESTING_daemon_get(pg, i);
      new_connection->peer = temp_daemon;
      new_connection->server = NULL;
      new_connection->next = global_connections;
      global_connections = new_connection;

      GNUNET_CORE_connect (sched,
                           temp_daemon->cfg,
                           TIMEOUT,
                           new_connection,
                           &init_notify,
                           NULL,
                           NULL,
                           NULL,
                           NULL,
                           GNUNET_YES, NULL, GNUNET_YES, handlers);
    }
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
  struct TestMessageContext *temp_context;
  if (emsg == NULL)
    {
      total_connections++;
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "connected peer %s to peer %s\n",
               first_daemon->shortname,
               second_daemon->shortname);
#endif
      temp_context = GNUNET_malloc(sizeof(struct TestMessageContext));
      temp_context->first_step_done = 0;
      temp_context->peer1handle = NULL;
      temp_context->peer1 = first_daemon;
      temp_context->peer2 = second_daemon;
      temp_context->peer2handle = NULL;
      temp_context->next = test_messages;
      test_messages = temp_context;

      expected_messages++;
      if (dotOutFile != NULL)
        fprintf(dotOutFile, "\tn%s -- n%s;\n", first_daemon->shortname, second_daemon->shortname);
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
                  "Created %d total connections, which is our target number!  Calling send messages.\n",
                  total_connections);
#endif

      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_add_now (sched, &setup_handlers, NULL);
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
  if (expected_connections == GNUNET_SYSERR)
    {
      die_task = GNUNET_SCHEDULER_add_now (sched,
                                           &end_badly, NULL);
    }
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

  dotOutFile = fopen (dotOutFileName, "w");
  if (dotOutFile != NULL)
    {
      fprintf (dotOutFile, "strict graph G {\n");
    }

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

}

static int
check ()
{
  char *binary_name;
  char *config_file_name;
  GNUNET_asprintf(&binary_name, "test-testing-topology-%s", topology_string);
  GNUNET_asprintf(&config_file_name, "test_testing_data_topology_%s.conf", topology_string);
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
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, binary_name, "nohelp",
                      options, &run, &ok);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;
  char *binary_start_pos;
  char *our_binary_name;
  binary_start_pos = rindex(argv[0], '/');
  if (strstr(binary_start_pos, "test_testing_topology_") == NULL)
    {
      return GNUNET_SYSERR;
    }

  topology_string = &binary_start_pos[23];

  GNUNET_asprintf(&our_binary_name, "test-testing-topology_%s", topology_string);
  GNUNET_log_setup (our_binary_name,
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
