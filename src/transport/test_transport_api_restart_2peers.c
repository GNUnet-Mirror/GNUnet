/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2015 Christian Grothoff (and other contributing authors)

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
 * @file transport/test_transport_api_restart_2peers.c
 * @brief base test case for transport implementations
 *
 * This test case starts 2 peers, connects and exchanges a message
 * boths peer are restarted and tested if peers reconnect
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 900)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

#define MTYPE 12345

static char *test_name;

static int ok;

static struct GNUNET_SCHEDULER_Task *die_task;

static struct GNUNET_SCHEDULER_Task *send_task;

static struct GNUNET_ATS_ConnectivitySuggestHandle *ats_sh;

static struct PeerContext *p1;

static struct PeerContext *p2;

static struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc;

static struct GNUNET_TRANSPORT_TransmitHandle *th;

static struct GNUNET_TRANSPORT_TESTING_handle *tth;

static char *cfg_file_p1;

static char *cfg_file_p2;

static int restarted;


static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping peers\n");
  if (NULL != send_task)
  {
    GNUNET_SCHEDULER_cancel (send_task);
    send_task = NULL;
  }
  if (NULL != ats_sh)
  {
    GNUNET_ATS_connectivity_suggest_cancel (ats_sh);
    ats_sh = NULL;
  }
  if (NULL != die_task)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = NULL;
  }
  if (NULL != th)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
  if (NULL != p1)
  {
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
    p1 = NULL;
  }
  if (NULL != p2)
  {
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);
    p2 = NULL;
  }
}


static void
end_badly (void *cls,
           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = NULL;

  if (restarted == GNUNET_YES)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Peer was restarted, but communication did not resume\n");

  if (restarted == GNUNET_NO)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Peer was NOT (even) restarted\n");
  if (cc != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Fail! Could not connect peers\n"));
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);
    cc = NULL;
  }
  end ();
  ok = GNUNET_SYSERR;
}


static void
restart_cb (struct PeerContext *p,
            void *cls)
{
  static int c;

  c++;
  if (c != 2)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Restarted peer %u (`%4s'), issuing reconnect\n",
              p->no,
              GNUNET_i2s (&p->id));
  ats_sh = GNUNET_ATS_connectivity_suggest (p->ats,
                                            &p2->id,
                                            1);
}


static void
restart (struct PeerContext *p,
         const char *cfg_file)
{
  GNUNET_assert (NULL != p);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Restarting peer %u (`%4s')\n",
              p->no,
              GNUNET_i2s (&p->id));
  GNUNET_TRANSPORT_TESTING_restart_peer (p,
                                         cfg_file,
                                         &restart_cb,
                                         p);
}


static void
notify_receive (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cls;
  struct PeerContext *t = NULL;

  if (0 == memcmp (peer, &p1->id, sizeof (struct GNUNET_PeerIdentity)))
    t = p1;
  if (0 == memcmp (peer, &p2->id, sizeof (struct GNUNET_PeerIdentity)))
    t = p2;
  GNUNET_assert (t != NULL);

  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&p->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer %u (`%4s') received message of type %d and size %u size from peer %u (`%4s')!\n",
                p->no,
                ps,
                ntohs (message->type),
                ntohs (message->size),
                t->no,
                GNUNET_i2s (&t->id));
    GNUNET_free (ps);
  }

  if ((MTYPE == ntohs (message->type)) &&
      (sizeof (struct GNUNET_MessageHeader) == ntohs (message->size)))
  {
    if (restarted == GNUNET_NO)
    {
      restarted = GNUNET_YES;
      restart (p1, cfg_file_p1);
      restart (p2, cfg_file_p2);
      return;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Restarted peers connected, stopping test...\n");
      ok = 0;
      end ();
    }
  }
  else
  {
    GNUNET_break (0);
    ok = 1;
    if (die_task != NULL)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
  }
}


static size_t
notify_ready (void *cls,
              size_t size,
              void *buf)
{
  struct PeerContext *p = cls;
  struct GNUNET_MessageHeader *hdr;

  th = NULL;
  if (NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout occurred while waiting for transmit_ready\n");
    if (NULL != die_task)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    ok = 42;
    return 0;
  }

  GNUNET_assert (size >= 256);
  hdr = buf;
  hdr->size = htons (sizeof (struct GNUNET_MessageHeader));
  hdr->type = htons (MTYPE);

  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&p2->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer %u (`%4s') sending message with type %u and size %u bytes to peer %u (`%4s')\n",
                p2->no,
                ps,
                ntohs (hdr->type),
                ntohs (hdr->size),
                p->no,
                GNUNET_i2s (&p->id));
    GNUNET_free (ps);
  }

  return sizeof (struct GNUNET_MessageHeader);
}


static void
sendtask (void *cls,
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

  th = GNUNET_TRANSPORT_notify_transmit_ready (p2->th,
                                               &p1->id,
                                               256,
                                               TIMEOUT_TRANSMIT,
                                               &notify_ready,
                                               p1);
}


static void
notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  static int c;
  struct PeerContext *p = cls;
  struct PeerContext *t = NULL;

  c++;
  if (0 == memcmp (peer,
                   &p1->id,
                   sizeof (struct GNUNET_PeerIdentity)))
    t = p1;
  if (0 == memcmp (peer,
                   &p2->id,
                   sizeof (struct GNUNET_PeerIdentity)))
    t = p2;
  GNUNET_assert (t != NULL);

  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&p->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer %u (`%4s'): peer %u (`%s') connected to me!\n",
                p->no,
                ps,
                t->no,
                GNUNET_i2s (peer));
    GNUNET_free (ps);
  }

  if ((restarted == GNUNET_YES) && (c == 4))
  {
    send_task = GNUNET_SCHEDULER_add_now (&sendtask,
                                          NULL);
  }
}


static void
notify_disconnect (void *cls,
                   const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *p = cls;

  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&p->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer %u (`%4s'): peer (`%s') disconnected from me!\n",
                p->no,
                ps,
                GNUNET_i2s (peer));
    GNUNET_free (ps);
  }

  if (th != NULL)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
  if (NULL != send_task)
  {
    GNUNET_SCHEDULER_cancel (send_task);
    send_task = NULL;
  }
}


static void
testing_connect_cb (struct PeerContext *p1,
                    struct PeerContext *p2,
                    void *cls)
{
  cc = NULL;

  {
    char *p1_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peers connected: %u (%s) <-> %u (%s)\n",
                p1->no,
                p1_c,
                p2->no,
                GNUNET_i2s (&p2->id));
    GNUNET_free (p1_c);
  }
  send_task = GNUNET_SCHEDULER_add_now (&sendtask,
                                        NULL);
}


static void
start_cb (struct PeerContext *p, void *cls)
{
  static int started;

  started++;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u (`%s') started\n",
              p->no,
              GNUNET_i2s (&p->id));
  if (started != 2)
    return;

  {
    char *sender_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Test tries to connect peer %u (`%s') -> peer %u (`%s')\n",
                p1->no,
                sender_c,
                p2->no,
                GNUNET_i2s (&p2->id));
    GNUNET_free (sender_c);
  }

  cc = GNUNET_TRANSPORT_TESTING_connect_peers (tth,
                                               p1,
                                               p2,
                                               &testing_connect_cb,
                                               NULL);
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                           &end_badly,
                                           NULL);
  p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth,
                                            cfg_file_p1,
                                            1,
                                            &notify_receive,
                                            &notify_connect,
                                            &notify_disconnect,
                                            &start_cb,
                                            NULL);

  p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth,
                                            cfg_file_p2,
                                            2,
                                            &notify_receive,
                                            &notify_connect,
                                            &notify_disconnect,
                                            &start_cb,
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
                      "nohelp", options, &run, NULL);

  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_TRANSPORT_TESTING_get_test_name (argv[0], &test_name);
  GNUNET_log_setup (test_name,
                    "WARNING",
                    NULL);
  tth = GNUNET_TRANSPORT_TESTING_init ();
  GNUNET_asprintf (&cfg_file_p1, "test_transport_api_tcp_peer1.conf");
  GNUNET_asprintf (&cfg_file_p2, "test_transport_api_tcp_peer2.conf");
  ret = check ();
  GNUNET_free (cfg_file_p1);
  GNUNET_free (cfg_file_p2);
  GNUNET_free (test_name);
  GNUNET_TRANSPORT_TESTING_done (tth);
  return ret;
}

/* end of test_transport_api_restart_2peers.c */
