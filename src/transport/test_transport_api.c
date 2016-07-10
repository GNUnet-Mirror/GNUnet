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

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

#define TEST_MESSAGE_SIZE 2600

#define TEST_MESSAGE_TYPE 12345


static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

static struct GNUNET_TRANSPORT_TransmitHandle *th;


static void
custom_shutdown (void *cls)
{
  if (NULL != th)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
}


static void
notify_receive (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_MessageHeader *message)
{
  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&receiver->id));

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Peer %u (`%4s') received message of type %d and size %u size from peer %s!\n",
                receiver->no,
                ps,
                ntohs (message->type),
                ntohs (message->size),
                GNUNET_i2s (sender));
    GNUNET_free (ps);
  }

  if ((TEST_MESSAGE_TYPE == ntohs (message->type)) &&
      (TEST_MESSAGE_SIZE == ntohs (message->size)))
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


static size_t
notify_ready (void *cls,
              size_t size,
              void *buf)
{
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p = cls;
  struct GNUNET_MessageHeader *hdr;

  th = NULL;
  if (buf == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout occurred while waiting for transmit_ready\n");
    GNUNET_SCHEDULER_shutdown ();
    ccc->global_ret = 42;
    return 0;
  }

  GNUNET_assert (size >= TEST_MESSAGE_SIZE);
  if (NULL != buf)
  {
    memset (buf, '\0', TEST_MESSAGE_SIZE);
    hdr = buf;
    hdr->size = htons (TEST_MESSAGE_SIZE);
    hdr->type = htons (TEST_MESSAGE_TYPE);
  }

  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&ccc->p[1]->id));
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Peer %u (`%4s') sending message with type %u and size %u bytes to peer %u (`%4s')\n",
                ccc->p[1]->no,
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
sendtask (void *cls)
{
  {
    char *receiver_s = GNUNET_strdup (GNUNET_i2s (&ccc->p[0]->id));

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Sending message from peer %u (`%s') -> peer %u (`%s') !\n",
                ccc->p[1]->no,
                GNUNET_i2s (&ccc->p[1]->id),
                ccc->p[0]->no,
                receiver_s);
    GNUNET_free (receiver_s);
  }
  ccc->global_ret = GNUNET_SYSERR;
  th = GNUNET_TRANSPORT_notify_transmit_ready (ccc->p[1]->th,
                                               &ccc->p[0]->id,
                                               TEST_MESSAGE_SIZE,
                                               TIMEOUT_TRANSMIT,
                                               &notify_ready,
                                               ccc->p[0]);
  GNUNET_assert (NULL != th);
}


static void
notify_disconnect (void *cls,
                   struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                   const struct GNUNET_PeerIdentity *other)
{
  GNUNET_TRANSPORT_TESTING_log_disconnect (cls,
                                           me,
                                           other);
  if (NULL != th)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
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
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .connect_continuation = &sendtask,
    .config_file = "test_transport_api_data.conf",
    .rec = &notify_receive,
    .nc = &GNUNET_TRANSPORT_TESTING_log_connect,
    .nd = &notify_disconnect,
    .shutdown_task = &custom_shutdown,
    .timeout = TIMEOUT,
    .bi_directional = bi_directional
  };

  ccc = &my_ccc;
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
