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
 * @file transport/test_transport_api_manipulation_recv_tcp.c
 * @brief base test case for transport traffic manipulation implementation
 *
 * This test case will setup 2 peers and connect them, the first message
 * will be sent without manipulation, then a receive delay of 1 second will
 * be configured and 2 more message will be sent. Time will be measured
 *
 * In addition the distance on receiver side will be manipulated to be 10
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

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static GNUNET_SCHEDULER_TaskIdentifier send_task;

static struct PeerContext *p1;

static struct PeerContext *p2;

static GNUNET_TRANSPORT_TESTING_ConnectRequest cc;

static struct GNUNET_TRANSPORT_TransmitHandle *th;

static struct GNUNET_TRANSPORT_TESTING_handle *tth;

static char *cfg_file_p1;

static char *cfg_file_p2;

static int messages_recv;

static struct GNUNET_TIME_Absolute start_normal;
static struct GNUNET_TIME_Relative dur_normal;

static struct GNUNET_TIME_Absolute start_delayed;
static struct GNUNET_TIME_Relative dur_delayed;

static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping peers\n");

  if (send_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (send_task);

  if (die_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (die_task);

  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;

  GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
  GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);
}

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Fail! Stopping peers\n");


  if (send_task != GNUNET_SCHEDULER_NO_TASK)
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
sendtask (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u (`%4s') received message of type %d and size %u size from peer %u (`%4s')!\n",
              p->no, ps, ntohs (message->type), ntohs (message->size), t->no,
              GNUNET_i2s (&t->id));
  GNUNET_free (ps);

  if ((TEST_MESSAGE_TYPE == ntohs (message->type)) &&
      (TEST_MESSAGE_SIZE == ntohs (message->size)))
  {
    ok = 0;

  }
  else
  {
    GNUNET_break (0);
    ok = 1;
    end ();
    return;
  }

  if (messages_recv <= 1)
  {
  	/* Received non-delayed message */
  	dur_normal = GNUNET_TIME_absolute_get_duration(start_normal);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received non-delayed message %u after %llu\n",
                messages_recv,
                (long long unsigned int) dur_normal.rel_value);

    struct GNUNET_ATS_Information ats[2];
  	ats[0].type = htonl (GNUNET_ATS_QUALITY_NET_DELAY);
  	ats[0].value = htonl (1000);
  	ats[1].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  	ats[1].value = htonl (10);

    GNUNET_TRANSPORT_set_traffic_metric (p1->th, &p2->id, GNUNET_YES, GNUNET_NO, ats, 2);
    send_task = GNUNET_SCHEDULER_add_now (&sendtask, NULL);
  }
  if (2 == messages_recv)
  {
  	/* Received manipulated message */
    	dur_delayed = GNUNET_TIME_absolute_get_duration(start_delayed);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received delayed message %u after %llu\n",
                  messages_recv,
                  (long long unsigned int) dur_delayed.rel_value);
      if (dur_delayed.rel_value < 1000)
      {
				GNUNET_break (0);
				ok += 1;
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Delayed message was not delayed correctly: took only %llu\n",
                    (long long unsigned int) dur_delayed.rel_value);
      }
      /* shutdown */
      end ();
  }

  messages_recv ++;
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
    if (GNUNET_SCHEDULER_NO_TASK != die_task)
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u (`%4s') sending message with type %u and size %u bytes to peer %u (`%4s')\n",
              p2->no, ps, ntohs (hdr->type), ntohs (hdr->size), p->no,
              GNUNET_i2s (&p->id));
  GNUNET_free (ps);

  return TEST_MESSAGE_SIZE;
}


static void
sendtask (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  send_task = GNUNET_SCHEDULER_NO_TASK;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  char *receiver_s = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending message from peer %u (`%4s') -> peer %u (`%s') !\n",
              p2->no, GNUNET_i2s (&p2->id), p1->no, receiver_s);
  GNUNET_free (receiver_s);


  if (0 == messages_recv)
  {
  	start_normal = GNUNET_TIME_absolute_get();
  }
  if (1 == messages_recv)
  {
		start_delayed = GNUNET_TIME_absolute_get();
  }

  s_sending = GNUNET_YES;
  th = GNUNET_TRANSPORT_notify_transmit_ready (p2->th, &p1->id, TEST_MESSAGE_SIZE, 0,
                                               TIMEOUT_TRANSMIT, &notify_ready,
                                               p1);
}


static void
notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  static int c;

  c++;
  struct PeerContext *p = cls;
  struct PeerContext *t = NULL;

  if (0 == memcmp (peer, &p1->id, sizeof (struct GNUNET_PeerIdentity)))
    t = p1;
  if (0 == memcmp (peer, &p2->id, sizeof (struct GNUNET_PeerIdentity)))
    t = p2;
  GNUNET_assert (t != NULL);

  char *ps = GNUNET_strdup (GNUNET_i2s (&p->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u (`%4s'): peer %u (`%s') connected to me!\n", p->no, ps,
              t->no, GNUNET_i2s (peer));
  GNUNET_free (ps);
}


static void
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *p = cls;
  char *ps = GNUNET_strdup (GNUNET_i2s (&p->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u (`%4s'): peer (`%s') disconnected from me!\n", p->no, ps,
              GNUNET_i2s (peer));

  GNUNET_free (ps);

  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;
}


static void
testing_connect_cb (struct PeerContext *p1, struct PeerContext *p2, void *cls)
{
  cc = NULL;
  char *p1_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peers connected: %u (%s) <-> %u (%s)\n",
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer %u (`%s') started\n", p->no,
              GNUNET_i2s (&p->id));

  if (started != 2)
    return;
  else
    s_started = GNUNET_YES;
  char *sender_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Test tries to connect peer %u (`%s') -> peer %u (`%s')\n",
              p1->no, sender_c, p2->no, GNUNET_i2s (&p2->id));
  GNUNET_free (sender_c);

  cc = GNUNET_TRANSPORT_TESTING_connect_peers (tth, p1, p2, &testing_connect_cb,
                                               NULL);

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

  p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth, cfg_file_p2, 2,
                                            &notify_receive, &notify_connect,
                                            &notify_disconnect, &start_cb,
                                            NULL);

  if ((p1 == NULL) || (p2 == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Fail! Could not start peers!\n");
    if (die_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }
}


static int
check ()
{
  static char *const argv[] = { "test-transport-api-manipulation",
    "-c",
    "test_transport_api_data.conf",
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  send_task = GNUNET_SCHEDULER_NO_TASK;

  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv, test_name,
                      "nohelp", options, &run, &ok);

  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

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

  return ret;
}

/* end of test_transport_api_manipulation_recv_tcp.c */
