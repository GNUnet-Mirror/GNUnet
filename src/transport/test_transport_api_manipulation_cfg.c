/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file transport/test_transport_api_manipulation_send_tcp.c
 * @brief base test case for transport traffic manipulation implementation
 * based onf cfg
 *
 * Peer 1 has inbound and outbound delay of 100ms
 * Peer 2 has no inbound and outbound delay
 *
 * We send a request from P1 to P2 and expect delay of >= TEST_DELAY us
 * Then we send response from P2 to P1 and expect delay of >= TEST_DELAY us
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

#define TEST_REQUEST_MESSAGE_TYPE 12345

#define TEST_RESPONSE_MESSAGE_TYPE 12346

/**
 * Test delay, in microseconds.
 */
#define TEST_DELAY 100 * 1000LL

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

static struct GNUNET_TRANSPORT_TESTING_ConnectRequest * cc;

static struct GNUNET_TRANSPORT_TransmitHandle *th;

static struct GNUNET_TRANSPORT_TESTING_handle *tth;

static char *cfg_file_p1;

static char *cfg_file_p2;

static struct GNUNET_TIME_Absolute start_request;
static struct GNUNET_TIME_Absolute start_response;

static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping peers\n");

  if (send_task != NULL)
    GNUNET_SCHEDULER_cancel (send_task);

  if (die_task != NULL)
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
  die_task = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Fail! Stopping peers\n");


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


static size_t
notify_request_ready (void *cls, size_t size, void *buf)
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
  memset (buf, '\0', TEST_MESSAGE_SIZE);
  hdr = buf;
  hdr->size = htons (TEST_MESSAGE_SIZE);
  hdr->type = htons (TEST_REQUEST_MESSAGE_TYPE);

  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&p1->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending request message from peer %u (`%4s') with type %u and size %u bytes to peer %u (`%4s')\n",
                p1->no, ps,
                ntohs (hdr->type),
                ntohs (hdr->size),
                p->no,
                GNUNET_i2s (&p->id));
    GNUNET_free (ps);
  }

  return TEST_MESSAGE_SIZE;
}


static void
sendtask_request_task (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  send_task = NULL;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  char *receiver_s = GNUNET_strdup (GNUNET_i2s (&p2->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending message from peer %u (`%4s') -> peer %u (`%s') !\n",
              p1->no, GNUNET_i2s (&p1->id), p2->no, receiver_s);
  GNUNET_free (receiver_s);

  s_sending = GNUNET_YES;
 	start_request = GNUNET_TIME_absolute_get();
  th = GNUNET_TRANSPORT_notify_transmit_ready (p1->th, &p2->id, TEST_MESSAGE_SIZE,
                                               TIMEOUT_TRANSMIT, &notify_request_ready,
                                               p2);
}


static size_t
notify_response_ready (void *cls, size_t size, void *buf)
{
  struct PeerContext *p = cls;
  struct GNUNET_MessageHeader *hdr;

  th = NULL;

  if (buf == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Timeout occurred while waiting for transmit_ready\n");
    if (NULL != die_task)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    ok = 42;
    return 0;
  }

  GNUNET_assert (size >= TEST_MESSAGE_SIZE);
  memset (buf, '\0', TEST_MESSAGE_SIZE);
  hdr = buf;
  hdr->size = htons (TEST_MESSAGE_SIZE);
  hdr->type = htons (TEST_RESPONSE_MESSAGE_TYPE);

  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&p1->id));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending response message from peer %u (`%4s') with type %u and size %u bytes to peer %u (`%4s')\n",
                p1->no,
                ps,
                ntohs (hdr->type),
                ntohs (hdr->size),
                p->no,
                GNUNET_i2s (&p->id));
    GNUNET_free (ps);
  }

  return TEST_MESSAGE_SIZE;
}


static void
sendtask_response_task (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  send_task = NULL;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  {
    char *receiver_s = GNUNET_strdup (GNUNET_i2s (&p1->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending message from peer %u (`%4s') -> peer %u (`%s') !\n",
                p2->no,
                GNUNET_i2s (&p2->id),
                p1->no,
                receiver_s);
    GNUNET_free (receiver_s);
  }

  s_sending = GNUNET_YES;
  start_response = GNUNET_TIME_absolute_get();
  th = GNUNET_TRANSPORT_notify_transmit_ready (p2->th,
                                               &p1->id,
                                               TEST_MESSAGE_SIZE,
                                               TIMEOUT_TRANSMIT,
                                               &notify_response_ready,
                                               p1);
}



static void
notify_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cls;
  struct PeerContext *t = NULL;
  struct GNUNET_TIME_Relative duration;

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

  switch (ntohs (message->type)) {
		case TEST_REQUEST_MESSAGE_TYPE:
			duration = GNUNET_TIME_absolute_get_difference(start_request,
					GNUNET_TIME_absolute_get());
			if (duration.rel_value_us >= TEST_DELAY)
				GNUNET_log (GNUNET_ERROR_TYPE_INFO,
					    "Request message was delayed for %s\n",
					    GNUNET_STRINGS_relative_time_to_string (duration,
										    GNUNET_YES));
			else
			  {
			    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
					"Request message was delayed for unexpected duration %s\n",
					GNUNET_STRINGS_relative_time_to_string (duration,
										GNUNET_YES));
			    ok = 1;
			}

		  /* Send response */
		  send_task = GNUNET_SCHEDULER_add_now (&sendtask_response_task, NULL);
		  return;
			break;
		case TEST_RESPONSE_MESSAGE_TYPE:
			duration = GNUNET_TIME_absolute_get_difference(start_response,
					GNUNET_TIME_absolute_get());
			if (duration.rel_value_us >= TEST_DELAY)
			  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
				      "Response message was delayed for %s\n",
				      GNUNET_STRINGS_relative_time_to_string (duration,
									      GNUNET_YES));
			else
			  {
			    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
					"Response message was delayed for unexpected duration %s\n",
					GNUNET_STRINGS_relative_time_to_string (duration,
										GNUNET_YES));
			    ok = 1;
			}
		  /* Done */
			ok = 0;
		  end();
			break;
		default:
			break;
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
  send_task = GNUNET_SCHEDULER_add_now (&sendtask_request_task, NULL);
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
    if (die_task != NULL)
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

/* end of test_transport_api.c */
