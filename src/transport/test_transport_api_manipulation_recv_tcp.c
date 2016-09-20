/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2016 GNUnet e.V.

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


static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

static int messages_recv;

static struct GNUNET_TIME_Absolute start_normal;

static struct GNUNET_TIME_Relative dur_normal;

static struct GNUNET_TIME_Absolute start_delayed;

static struct GNUNET_TIME_Relative dur_delayed;


static void
do_free (void *cls)
{
  struct GNUNET_TRANSPORT_TESTING_SendClosure *sc = cls;
  
  GNUNET_free (sc);
}


static void
delayed_transmit (void *cls)
{
  struct GNUNET_TRANSPORT_TESTING_SendClosure *sc = cls;
  
  start_delayed = GNUNET_TIME_absolute_get ();
  GNUNET_TRANSPORT_TESTING_large_send (sc);
}


static void
sendtask (void *cls)
{
  struct GNUNET_TRANSPORT_TESTING_SendClosure *sc;
  struct GNUNET_ATS_Properties prop;
  struct GNUNET_TIME_Relative delay;

  sc = GNUNET_new (struct GNUNET_TRANSPORT_TESTING_SendClosure);
  sc->num_messages = 1;
  sc->ccc = ccc;
  sc->cont = &do_free;
  sc->cont_cls = sc;
  if (0 == messages_recv)
  {
    start_normal = GNUNET_TIME_absolute_get();
  }
  if (0 < messages_recv)
  {
    memset (&prop, 0, sizeof (prop));
    delay = GNUNET_TIME_UNIT_SECONDS;
    GNUNET_TRANSPORT_manipulation_set (ccc->p[1]->tmh,
				       &ccc->p[0]->id,
				       &prop,
				       delay,
				       GNUNET_TIME_UNIT_ZERO);
    /* wait 1s to allow manipulation to go into effect */
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				  &delayed_transmit,
				  sc);
    return;
  }
  GNUNET_TRANSPORT_TESTING_large_send (sc);
}


static void
notify_receive (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&receiver->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer %u (`%s') received message of type %d and size %u size from peer %s)!\n",
                receiver->no,
                ps,
                ntohs (message->header.type),
                ntohs (message->header.size),
                GNUNET_i2s (sender));
    GNUNET_free (ps);
  }
  if ( (GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE != ntohs (message->header.type)) ||
       (GNUNET_TRANSPORT_TESTING_LARGE_MESSAGE_SIZE != ntohs (message->header.size)) )
  {
    GNUNET_break (0);
    ccc->global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (messages_recv <= 1)
  {
    /* Received non-delayed message */
    dur_normal = GNUNET_TIME_absolute_get_duration (start_normal);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received non-delayed message %u after %s\n",
                messages_recv,
                GNUNET_STRINGS_relative_time_to_string (dur_normal,
							GNUNET_YES));
    GNUNET_SCHEDULER_add_now (&sendtask,
			      NULL);
    messages_recv++;
    return;
  }
  /* Received manipulated message */
  dur_delayed = GNUNET_TIME_absolute_get_duration(start_delayed);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received delayed message %u after %s\n",
	      messages_recv,
	      GNUNET_STRINGS_relative_time_to_string (dur_delayed,
						      GNUNET_YES));
  if (dur_delayed.rel_value_us < GNUNET_TIME_UNIT_SECONDS.rel_value_us)
  {
    GNUNET_break (0);
    ccc->global_ret = GNUNET_SYSERR;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Delayed message was not delayed correctly: took only %s\n",
		GNUNET_STRINGS_relative_time_to_string (dur_delayed,
							GNUNET_YES));
  }
  else
  { 
    ccc->global_ret = GNUNET_OK;
  }
  /* shutdown */
  GNUNET_SCHEDULER_shutdown ();
}


int
main (int argc,
      char *argv[])
{
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .connect_continuation = &sendtask,
    .config_file = "test_transport_api_data.conf",
    .rec = &notify_receive,
    .nc = &GNUNET_TRANSPORT_TESTING_log_connect,
    .nd = &GNUNET_TRANSPORT_TESTING_log_disconnect,
    .timeout = TIMEOUT,
    .global_ret = GNUNET_NO
  };

  ccc = &my_ccc;
  if (GNUNET_OK !=
      GNUNET_TRANSPORT_TESTING_main (2,
                                     &GNUNET_TRANSPORT_TESTING_connect_check,
                                     ccc))
    return 1;
  return 0;
}

/* end of test_transport_api_manipulation_recv_tcp.c */
