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
 * @file transport/test_transport_api.c
 * @brief base test case for transport implementations
 * @author Christian Grothoff
 *
 * This test case serves as a base for tcp, udp, and udp-nat
 * transport test cases.  Based on the executable being run
 * the correct test case will be performed.  Conservation of
 * C code apparently.
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;


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

  if ((GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE == ntohs (message->header.type)) &&
      (GNUNET_TRANSPORT_TESTING_LARGE_MESSAGE_SIZE == ntohs (message->header.size)))
  {
    ccc->global_ret = GNUNET_OK;
    GNUNET_SCHEDULER_shutdown ();
  }
  else
  {
    GNUNET_break (0);
    ccc->global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * Runs the test.
 *
 * @param argv the argv argument from main()
 * @param bi_directional should we try to establish connections
 *        in both directions simultaneously?
 */
static int
test (char *argv[],
      int bi_directional)
{
  struct GNUNET_TRANSPORT_TESTING_SendClosure sc = {
    .num_messages = 1
  };
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .connect_continuation = &GNUNET_TRANSPORT_TESTING_large_send,
    .connect_continuation_cls = &sc,
    .config_file = "test_transport_api_data.conf",
    .rec = &notify_receive,
    .nc = &GNUNET_TRANSPORT_TESTING_log_connect,
    .nd = &GNUNET_TRANSPORT_TESTING_log_disconnect,
    .timeout = TIMEOUT,
    .bi_directional = bi_directional
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


int
main (int argc,
      char *argv[])
{
  if ( (0 != test (argv,
                   GNUNET_NO)) ||
       (0 != test (argv,
                   GNUNET_YES) ) )
    return 1;
  return 0;
}

/* end of test_transport_api.c */
