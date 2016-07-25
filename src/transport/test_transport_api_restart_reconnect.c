/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2015, 2016 GNUnet e.V.

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
 * @file transport/test_transport_api_restart_reconnect.c
 * @brief base test case for transport implementations
 *
 * This test case starts 2 peers, connects and exchanges a message.
 * Then, 1 or 2 peers are restarted and it is tested if peers reconnect.
 * How many peers are restarted is determined by the name of the binary.
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

static struct GNUNET_ATS_ConnectivitySuggestHandle *ats_sh;

static int p1_connected;

static int p2_connected;

static int restarted;


static void
custom_shutdown (void *cls)
{
  if (NULL != ats_sh)
  {
    GNUNET_ATS_connectivity_suggest_cancel (ats_sh);
    ats_sh = NULL;
  }
}


static void
restart_cb (void *cls)
{
  static unsigned int c;
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p = cls;
  
  c++;
  if ( (2 != c) &&
       (NULL != strstr (ccc->test_name,
			"2peers")) )
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Restarted peer %u (`%s'), issuing reconnect\n",
              p->no,
              GNUNET_i2s (&p->id));
  ats_sh = GNUNET_ATS_connectivity_suggest (p->ats,
                                            &ccc->p[1]->id,
                                            1);
}


static void
restart (struct GNUNET_TRANSPORT_TESTING_PeerContext *p)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Restarting peer %u (`%s')\n",
              p->no,
              GNUNET_i2s (&p->id));
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_TRANSPORT_TESTING_restart_peer (p,
							&restart_cb,
							p));
}


static void
notify_receive (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&receiver->id));

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Peer %u (`%s') received message of type %d and size %u size from peer %s!\n",
                receiver->no,
                ps,
                ntohs (message->header.type),
                ntohs (message->header.size),
                GNUNET_i2s (sender));
    GNUNET_free (ps);
  }
  if ( (GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE == ntohs (message->header.type)) &&
       (sizeof (struct GNUNET_TRANSPORT_TESTING_TestMessage) == ntohs (message->header.size)) )
  {
    if (GNUNET_NO == restarted)
    {
      restarted = GNUNET_YES;
      fprintf (stderr, "TN: %s\n", ccc->test_name);
      restart (ccc->p[0]);
      if (NULL != strstr (ccc->test_name,
			  "2peers"))
	restart (ccc->p[1]);
      return;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Restarted peers connected and message was sent, stopping test...\n");
      ccc->global_ret = GNUNET_OK;
      GNUNET_SCHEDULER_shutdown ();
    }
  }
  else
  {
    GNUNET_break (0);
    ccc->global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();    
  }
}


static void
notify_connect (void *cls,
		struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
		const struct GNUNET_PeerIdentity *other)
{
  static struct GNUNET_TRANSPORT_TESTING_SendClosure sc = {
    .num_messages = 1
  };

  sc.ccc = ccc;
  GNUNET_TRANSPORT_TESTING_log_connect (cls,
					me,
					other);
  if (me == ccc->p[0])
    p1_connected = GNUNET_YES;
  if (me == ccc->p[1])
    p2_connected = GNUNET_YES;

  if ( (GNUNET_YES == restarted) &&
       (GNUNET_YES == p1_connected) &&
       (GNUNET_YES == p2_connected) )
  {
    /* Peer was restarted and we received 3 connect messages (2 from first connect, 1 from reconnect) */
    GNUNET_SCHEDULER_add_now (&GNUNET_TRANSPORT_TESTING_simple_send,
			      &sc);
  }
}


static void
notify_disconnect (void *cls,
                   struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                   const struct GNUNET_PeerIdentity *other)
{
  GNUNET_TRANSPORT_TESTING_log_disconnect (cls,
                                           me,
                                           other);
  if (me == ccc->p[0])
    p1_connected = GNUNET_NO;
  if (me == ccc->p[1])
    p2_connected = GNUNET_NO;
}


int
main (int argc,
      char *argv[])
{
  struct GNUNET_TRANSPORT_TESTING_SendClosure sc = {
    .num_messages = 1
  };
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .connect_continuation = &GNUNET_TRANSPORT_TESTING_simple_send,
    .connect_continuation_cls = &sc,
    .config_file = "test_transport_api_data.conf",
    .rec = &notify_receive,
    .nc = &notify_connect,
    .nd = &notify_disconnect,
    .shutdown_task = &custom_shutdown,
    .timeout = TIMEOUT
  };

  ccc = &my_ccc;
  sc.ccc = ccc;
  if (GNUNET_OK !=
      GNUNET_TRANSPORT_TESTING_main (2,
                                     &GNUNET_TRANSPORT_TESTING_connect_check,
                                     ccc))
    return 1;
  return 0;
}

/* end of test_transport_api_restart_1peer.c */
