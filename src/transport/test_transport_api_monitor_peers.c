/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file transport/test_transport_api_monitor_peers.c
 * @brief base test case for transport peer monitor API
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

#define TEST_MESSAGE_SIZE 2600

#define TEST_MESSAGE_TYPE 12345

static char *test_source;

static char *test_plugin;

static char *test_name;

static int ok;

static int s_started;

static int s_connected;

static int s_sending;

static struct GNUNET_SCHEDULER_Task * die_task;

static struct GNUNET_SCHEDULER_Task * send_task;

static struct PeerContext *p1;

static struct PeerContext *p2;

static GNUNET_TRANSPORT_TESTING_ConnectRequest cc;

static struct GNUNET_TRANSPORT_TransmitHandle *th;

static struct GNUNET_TRANSPORT_TESTING_handle *tth;

static char *cfg_file_p1;

static char *cfg_file_p2;

static struct GNUNET_TRANSPORT_PeerMonitoringContext *pmc_p1;

static struct GNUNET_TRANSPORT_PeerMonitoringContext *pmc_p2;

static int p1_c = GNUNET_NO;

static int p2_c = GNUNET_NO;

static int p1_c_notify = GNUNET_NO;

static int p2_c_notify = GNUNET_NO;


static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Stopping peers\n");

  if (send_task != NULL)
    GNUNET_SCHEDULER_cancel (send_task);

  if (die_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = NULL;
  }

  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;

  if (NULL != p1)
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
  p1 = NULL;
  if (NULL != p2)
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);
  p2 = NULL;

  if (NULL != pmc_p1)
  {
    GNUNET_TRANSPORT_monitor_peers_cancel (pmc_p1);
    pmc_p1 = NULL;
  }
  if (NULL != pmc_p2)
  {
    GNUNET_TRANSPORT_monitor_peers_cancel (pmc_p2);
    pmc_p2 = NULL;
  }



  ok = 0;
}


static void
end_badly (void *cls,
           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Fail! Stopping peers\n");


  if (send_task != NULL)
    GNUNET_SCHEDULER_cancel (send_task);

  if (cc != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Fail! Could not connect peers\n"));
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);
    cc = NULL;
  }

  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Peer were not ready to send data\n"));

  if (s_started == GNUNET_NO)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Peers were not started \n"));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Peers were started \n"));

  if (s_connected == GNUNET_NO)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Peer were not connected\n"));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Peer were connected\n"));

  if (s_sending == GNUNET_NO)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Peer were not ready to send data\n"));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Peer were ready to send data\n"));

  th = NULL;

  if (NULL != pmc_p1)
  {
    GNUNET_TRANSPORT_monitor_peers_cancel (pmc_p1);
    pmc_p1 = NULL;
  }
  if (NULL != pmc_p2)
  {
    GNUNET_TRANSPORT_monitor_peers_cancel (pmc_p2);
    pmc_p2 = NULL;
  }

  if (p1 != NULL)
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Peer 1 was not started\n"));
  if (p2 != NULL)
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Peer 2 was not started\n"));

  ok = GNUNET_SYSERR;
}


static void
notify_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cls;
  struct PeerContext *t = NULL;

  if (0 == memcmp (peer, &p1->id, sizeof (struct GNUNET_PeerIdentity)))
    t = p1;
  if (0 == memcmp (peer, &p2->id, sizeof (struct GNUNET_PeerIdentity)))
    t = p2;
  GNUNET_assert (t != NULL);

  char *ps = GNUNET_strdup (GNUNET_i2s (&p->id));

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer %u (`%4s') received message of type %d and size %u size from peer %u (`%4s')!\n",
              p->no, ps, ntohs (message->type), ntohs (message->size), t->no,
              GNUNET_i2s (&t->id));
  GNUNET_free (ps);
}


static size_t
notify_ready (void *cls, size_t size, void *buf)
{
  struct PeerContext *p = cls;
  struct GNUNET_MessageHeader *hdr;

  th = NULL;

  if (buf == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout occurred while waiting for transmit_ready\n");
    if (NULL != die_task)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    ok = 42;
    return 0;
  }

  GNUNET_assert (size >= TEST_MESSAGE_SIZE);
  if (buf != NULL)
  {
    memset (buf, '\0', TEST_MESSAGE_SIZE);
    hdr = buf;
    hdr->size = htons (TEST_MESSAGE_SIZE);
    hdr->type = htons (TEST_MESSAGE_TYPE);
  }

  char *ps = GNUNET_strdup (GNUNET_i2s (&p2->id));
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer %u (`%4s') sending message with type %u and size %u bytes to peer %u (`%4s')\n",
              p2->no, ps, ntohs (hdr->type), ntohs (hdr->size), p->no,
              GNUNET_i2s (&p->id));
  GNUNET_free (ps);

  return TEST_MESSAGE_SIZE;
}


static void
sendtask (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  send_task = NULL;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  char *receiver_s = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Sending message from peer %u (`%4s') -> peer %u (`%s') !\n",
              p2->no, GNUNET_i2s (&p2->id), p1->no, receiver_s);
  GNUNET_free (receiver_s);
  s_sending = GNUNET_YES;
  th = GNUNET_TRANSPORT_notify_transmit_ready (p2->th, &p1->id, TEST_MESSAGE_SIZE,
                                               TIMEOUT_TRANSMIT, &notify_ready,
                                               p1);
}


static void
done ()
{
  if ((GNUNET_YES == p1_c) && (GNUNET_YES == p2_c) && p1_c_notify && p2_c_notify)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Both peers state to be connected\n");
    ok = 0;
    end();
  }
}


static void
notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  static int c;

  c++;
  struct PeerContext *p = cls;
  struct PeerContext *t = NULL;

  if (0 == memcmp (peer, &p1->id, sizeof (struct GNUNET_PeerIdentity)))
  {
    p1_c_notify = GNUNET_YES;
    t = p1;
  }
  if (0 == memcmp (peer, &p2->id, sizeof (struct GNUNET_PeerIdentity)))
  {
    p2_c_notify = GNUNET_YES;
    t = p2;
  }
  GNUNET_assert (t != NULL);

  char *ps = GNUNET_strdup (GNUNET_i2s (&p->id));

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer %u (`%4s'): peer %u (`%s') connected to me!\n", p->no, ps,
              t->no, GNUNET_i2s (peer));
  if (p1_c_notify && p2_c_notify)
    GNUNET_SCHEDULER_add_now(&done, NULL);
  GNUNET_free (ps);
}


static void
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *p = cls;
  char *ps = GNUNET_strdup (GNUNET_i2s (&p->id));

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer %u (`%4s'): peer (`%s') disconnected from me!\n", p->no, ps,
              GNUNET_i2s (peer));

  GNUNET_free (ps);

  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;
}


static void
testing_connect_cb (struct PeerContext *p1,
                    struct PeerContext *p2,
                    void *cls)
{
  cc = NULL;
  char *p1_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peers connected: %u (%s) <-> %u (%s)\n",
              p1->no, p1_c, p2->no, GNUNET_i2s (&p2->id));
  GNUNET_free (p1_c);

  s_connected = GNUNET_YES;
  send_task = GNUNET_SCHEDULER_add_now (&sendtask, NULL);
}


static void
start_cb (struct PeerContext *p, void *cls)
{
  static int started;

  started++;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer %u (`%s') started\n", p->no,
              GNUNET_i2s (&p->id));

  if (started != 2)
    return;
  else
    s_started = GNUNET_YES;
  char *sender_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test tries to connect peer %u (`%s') -> peer %u (`%s')\n",
              p1->no, sender_c, p2->no, GNUNET_i2s (&p2->id));
  GNUNET_free (sender_c);

  cc = GNUNET_TRANSPORT_TESTING_connect_peers (tth, p1, p2, &testing_connect_cb,
                                               NULL);

}


static void
monitor1_cb (void *cls,
             const struct GNUNET_PeerIdentity *peer,
             const struct GNUNET_HELLO_Address *address,
             enum GNUNET_TRANSPORT_PeerState state,
             struct GNUNET_TIME_Absolute state_timeout)
{
  if ((NULL == peer) || (NULL == p1))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Monitor 1: %s %s %s\n",
              GNUNET_i2s (peer),
              GNUNET_TRANSPORT_ps2s (state),
              GNUNET_STRINGS_absolute_time_to_string(state_timeout));
  if ((0 == memcmp (peer, &p2->id, sizeof (p2->id)) &&
      (GNUNET_YES == GNUNET_TRANSPORT_is_connected(state)) &&
      GNUNET_NO == p1_c) )
  {
    p1_c = GNUNET_YES;
    GNUNET_SCHEDULER_add_now (&done, NULL);
  }

}


static void
monitor2_cb (void *cls,
             const struct GNUNET_PeerIdentity *peer,
             const struct GNUNET_HELLO_Address *address,
             enum GNUNET_TRANSPORT_PeerState state,
             struct GNUNET_TIME_Absolute state_timeout)
{
  if ((NULL == peer) || (NULL == p2))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Monitor 2: %s %s %s\n",
              GNUNET_i2s (peer),
              GNUNET_TRANSPORT_ps2s (state),
              GNUNET_STRINGS_absolute_time_to_string(state_timeout));
  if ((0 == memcmp (peer, &p1->id, sizeof (p1->id)) &&
      (GNUNET_YES == GNUNET_TRANSPORT_is_connected(state)) &&
      GNUNET_NO == p2_c) )
  {
    p2_c = GNUNET_YES;
    GNUNET_SCHEDULER_add_now (&done, NULL);
  }
}



static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  s_started = GNUNET_NO;
  s_connected = GNUNET_NO;
  s_sending = GNUNET_NO;

  p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth, cfg_file_p1, 1,
                                            &notify_receive, &notify_connect,
                                            &notify_disconnect, &start_cb,
                                            NULL);
  pmc_p1 = GNUNET_TRANSPORT_monitor_peers (p1->cfg, NULL, GNUNET_NO, GNUNET_TIME_UNIT_FOREVER_REL, &monitor1_cb, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer 1 started\n");

  p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth, cfg_file_p2, 2,
                                            &notify_receive, &notify_connect,
                                            &notify_disconnect, &start_cb,
                                            NULL);
  pmc_p2 = GNUNET_TRANSPORT_monitor_peers (p2->cfg, NULL, GNUNET_NO, GNUNET_TIME_UNIT_FOREVER_REL, &monitor2_cb, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer 1 started\n");
  if ((p1 == NULL) || (p2 == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Fail! Could not start peers!\n");
    if (die_task != NULL)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }
}


static int
check ()
{
  static char *const argv[] = { "test-transport-api",
    "-c",
    "test_transport_api_data.conf",
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  send_task = NULL;

  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv, test_name,
                      "nohelp", options, &run, &ok);

  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;

  ok = 1;

  GNUNET_TRANSPORT_TESTING_get_test_name (argv[0], &test_name);
  GNUNET_TRANSPORT_TESTING_get_test_source_name (__FILE__, &test_source);
  GNUNET_TRANSPORT_TESTING_get_test_plugin_name (argv[0], test_source,
                                                 &test_plugin);

  GNUNET_log_setup (test_name,
                    "WARNING",
                    NULL);
  tth = GNUNET_TRANSPORT_TESTING_init ();

  GNUNET_TRANSPORT_TESTING_get_config_name (argv[0], &cfg_file_p1, 1);
  GNUNET_TRANSPORT_TESTING_get_config_name (argv[0], &cfg_file_p2, 2);

  ret = check ();

  GNUNET_free (cfg_file_p1);
  GNUNET_free (cfg_file_p2);

  GNUNET_free (test_source);
  GNUNET_free (test_plugin);
  GNUNET_free (test_name);

  GNUNET_TRANSPORT_TESTING_done (tth);

  if (0 != ret)
    return ret;
  else
    return ok;
}

/* end of test_transport_api_monitor_peers.c */
