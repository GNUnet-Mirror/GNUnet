/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/transport_api_blacklisting.c
 * @brief test for the blacklisting API
 * @author Matthias Wachs
 *
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_hello_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_transport_service.h"
#include "transport.h"
#include "transport-testing.h"

#define VERBOSE GNUNET_NO
#define VERBOSE_ARM GNUNET_NO

#define START_ARM GNUNET_YES


struct PeerContext *p1;

struct PeerContext *p2;

static GNUNET_TRANSPORT_TESTING_ConnectRequest cc;

struct GNUNET_TRANSPORT_TransmitHandle *th;

struct GNUNET_TRANSPORT_TESTING_handle *tth;

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

#define TEST_MESSAGE_SIZE 2600

#define TEST_MESSAGE_TYPE 12345


static int ok;
static int connected;
static int blacklist_request_p1;
static int blacklist_request_p2;

struct GNUNET_TRANSPORT_Blacklist * blacklist_p1;

struct GNUNET_TRANSPORT_Blacklist * blacklist_p2;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static GNUNET_SCHEDULER_TaskIdentifier send_task;

static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

#if VERBOSE
#define OKPP do { ok++; FPRINTF (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping\n");

  if (send_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (send_task);

  if (die_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (cc != NULL)
  {
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel(tth, cc);
    cc = NULL;
  }

  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;

  if (blacklist_p1 != NULL)
  {
    GNUNET_TRANSPORT_blacklist_cancel (blacklist_p1);
    blacklist_p1 = NULL;
  }

  if (blacklist_p2 != NULL)
  {
    GNUNET_TRANSPORT_blacklist_cancel (blacklist_p2);
    blacklist_p2 = NULL;
  }

  if (p1 != NULL)
  {
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
    p1 = NULL;
  }
  if (p2 != NULL)
  {
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);
    p2 = NULL;
  }

  if ((blacklist_request_p1 == GNUNET_YES) &&
      (blacklist_request_p2 == GNUNET_YES) &&
      (connected == GNUNET_NO))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Peers were not connected, success\n"));
    ok = 0;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Peers were not connected, fail\n"));
    ok = 1;
  }
}

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (send_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (send_task);
    send_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (shutdown_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (cc != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Fail! Could not connect peers\n"));
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);
    cc = NULL;
  }

  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;

  if (blacklist_p1 != NULL)
    GNUNET_TRANSPORT_blacklist_cancel (blacklist_p1);

  if (blacklist_p2 != NULL)
    GNUNET_TRANSPORT_blacklist_cancel (blacklist_p2);

  if (p1 != NULL)
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
  if (p2 != NULL)
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);

  ok = GNUNET_SYSERR;
}


static void
notify_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message,
                const struct GNUNET_ATS_Information *ats, uint32_t ats_count)
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
    shutdown_task = GNUNET_SCHEDULER_add_now(&end, NULL);
  }
  else
  {
    GNUNET_break (0);
    ok = 1;
    shutdown_task = GNUNET_SCHEDULER_add_now(&end, NULL);
  }
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
    {
      GNUNET_SCHEDULER_cancel (die_task);
      die_task = GNUNET_SCHEDULER_NO_TASK;
    }
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    ok = 42;
    return 0;
  }

  GNUNET_assert (size >= TEST_MESSAGE_SIZE);

  if (buf != NULL)
  {
    hdr = buf;
    hdr->size = htons (TEST_MESSAGE_SIZE);
    hdr->type = htons (TEST_MESSAGE_TYPE);
  }

  char *ps = GNUNET_strdup (GNUNET_i2s (&p2->id));
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
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

  th = GNUNET_TRANSPORT_notify_transmit_ready (p2->th, &p1->id, TEST_MESSAGE_SIZE, 0,
                                               TIMEOUT_TRANSMIT, &notify_ready,
                                               p1);
}

static void
notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_ATS_Information *ats, uint32_t ats_count)
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



  send_task = GNUNET_SCHEDULER_add_now (&sendtask, NULL);
}


int blacklist_cb (void *cls,
                 const struct
                 GNUNET_PeerIdentity * pid)
{
  struct PeerContext * p = cls;
  int res = GNUNET_SYSERR;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer  %u : Blacklist request for peer `%s'\n", p->no, GNUNET_i2s (pid));

  if (p == p1)
  {
    blacklist_request_p1 = GNUNET_YES;
    res = GNUNET_OK;
  }
  else if (p == p2)
  {
    blacklist_request_p2 = GNUNET_YES;
    res = GNUNET_SYSERR;
  }

  if (((blacklist_request_p2 == GNUNET_YES) && (blacklist_request_p1 == GNUNET_YES)) && (shutdown_task == GNUNET_SCHEDULER_NO_TASK))
  {
    shutdown_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 3), &end, NULL);
  }

  return res;
}

void
start_cb (struct PeerContext *p, void *cls)
{
  static int started;

  started++;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer %u (`%s') started\n", p->no,
              GNUNET_i2s (&p->id));

  if (started != 2)
    return;

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
  connected = GNUNET_NO;
  blacklist_request_p1 = GNUNET_NO;
  blacklist_request_p2 = GNUNET_NO;

  p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth, "test_transport_api_tcp_peer1.conf", 1,
                                            &notify_receive, &notify_connect,
                                            &notify_disconnect, &start_cb,
                                            NULL);

  p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth, "test_transport_api_tcp_peer2.conf", 2,
                                            &notify_receive, &notify_connect,
                                            &notify_disconnect, &start_cb,
                                            NULL);

  blacklist_p1 = GNUNET_TRANSPORT_blacklist (p1->cfg,
                              &blacklist_cb,
                              p1);

  blacklist_p2 = GNUNET_TRANSPORT_blacklist (p2->cfg,
                              &blacklist_cb,
                              p2);

  GNUNET_assert (blacklist_p1 != NULL);
  GNUNET_assert (blacklist_p2 != NULL);
}


static int
check ()
{
  static char *const argv[] = { "test-transport-api-blacklisting",
    "-c",
    "test_transport_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

#if WRITECONFIG
  setTransportOptions ("test_transport_api_data.conf");
#endif

  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv, "test-transport-api-blacklisting",
                      "nohelp", options, &run, &ok);

  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-transport-api-blacklisting",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  tth = GNUNET_TRANSPORT_TESTING_init ();

  ret = check ();

  GNUNET_TRANSPORT_TESTING_done (tth);

  return ret;
}

/* end of transport_api_blacklisting.c */
