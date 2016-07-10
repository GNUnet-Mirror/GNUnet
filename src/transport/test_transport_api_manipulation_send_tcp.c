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
 * @file transport/test_transport_api_manipulation_send_tcp.c
 * @brief base test case for transport traffic manipulation implementation
 *
 * This test case will setup 2 peers and connect them, the first message
 * will be sent without manipulation, then a send delay of 1 second will
 * be configured and 1 more message will be sent. Time will be measured.
 *
 * In addition the distance on receiver side will be manipulated to be 10
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
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

#define TEST_MESSAGE_SIZE 2600

#define TEST_MESSAGE_TYPE 12345


static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

static struct GNUNET_TRANSPORT_TransmitHandle *th;

static struct GNUNET_SCHEDULER_Task *send_task;

static int messages_recv;

static struct GNUNET_TIME_Absolute start_normal;

static struct GNUNET_TIME_Relative dur_normal;

static struct GNUNET_TIME_Absolute start_delayed;

static struct GNUNET_TIME_Relative dur_delayed;


static void
custom_shutdown (void *cls)
{
  if (NULL != th)
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
sendtask (void *cls);


static void
notify_receive (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_MessageHeader *message)
{
  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&receiver->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer %u (`%s') received message of type %d and size %u size from peer %s)!\n",
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
    if (GNUNET_NO == ccc->global_ret)
      ccc->global_ret = GNUNET_OK;
  }
  else
  {
    GNUNET_break (0);
    ccc->global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (0 == messages_recv)
  {
    /* Received non-delayed message */
    dur_normal = GNUNET_TIME_absolute_get_duration(start_normal);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received non-delayed message %u after %s\n",
                messages_recv,
                GNUNET_STRINGS_relative_time_to_string (dur_normal,
							GNUNET_YES));
    send_task = GNUNET_SCHEDULER_add_now (&sendtask,
                                          NULL);
  }
  if (1 == messages_recv)
  {
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
    GNUNET_SCHEDULER_shutdown ();
  }
  messages_recv++;
}


static size_t
notify_ready (void *cls, size_t size, void *buf)
{
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p = cls;
  struct GNUNET_MessageHeader *hdr;

  th = NULL;
  if (NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout occurred while waiting for transmit_ready\n");
    GNUNET_SCHEDULER_shutdown ();
    ccc->global_ret = 42;
    return 0;
  }

  GNUNET_assert (size >= TEST_MESSAGE_SIZE);
  memset (buf, '\0', TEST_MESSAGE_SIZE);
  hdr = buf;
  hdr->size = htons (TEST_MESSAGE_SIZE);
  hdr->type = htons (TEST_MESSAGE_TYPE);

  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&ccc->p[1]->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer %u (`%s') sending message with type %u and size %u bytes to peer %u (`%s')\n",
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
  struct GNUNET_TIME_Relative delay;
  struct GNUNET_ATS_Properties prop;

  if (NULL == send_task)
    ccc->global_ret = GNUNET_NO; /* first call! */
  send_task = NULL;
  {
    char *receiver_s = GNUNET_strdup (GNUNET_i2s (&ccc->p[0]->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending message from peer %u (`%s') -> peer %u (`%s') !\n",
                ccc->p[1]->no,
                GNUNET_i2s (&ccc->p[1]->id),
                ccc->p[0]->no,
                receiver_s);
    GNUNET_free (receiver_s);
  }

  if (0 == messages_recv)
  {
    start_normal = GNUNET_TIME_absolute_get ();
  }
  if (1 == messages_recv)
  {
    memset (&prop, 0, sizeof (prop));
    delay = GNUNET_TIME_UNIT_SECONDS;
    GNUNET_TRANSPORT_set_traffic_metric (ccc->p[1]->th,
                                         &ccc->p[0]->id,
                                         &prop,
                                         GNUNET_TIME_UNIT_ZERO,
                                         delay);
    prop.distance = 10;
    GNUNET_TRANSPORT_set_traffic_metric (ccc->p[0]->th,
                                         &ccc->p[1]->id,
                                         &prop,
                                         delay,
                                         delay);
    start_delayed = GNUNET_TIME_absolute_get();
  }
  th = GNUNET_TRANSPORT_notify_transmit_ready (ccc->p[1]->th,
                                               &ccc->p[0]->id,
                                               TEST_MESSAGE_SIZE,
                                               TIMEOUT_TRANSMIT,
                                               &notify_ready,
                                               ccc->p[0]);
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


int
main (int argc, char *argv[])
{
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .connect_continuation = &sendtask,
    .config_file = "test_transport_api_data.conf",
    .rec = &notify_receive,
    .nc = &GNUNET_TRANSPORT_TESTING_log_connect,
    .nd = &notify_disconnect,
    .shutdown_task = &custom_shutdown,
    .timeout = TIMEOUT
  };

  ccc = &my_ccc;
  if (GNUNET_OK !=
      GNUNET_TRANSPORT_TESTING_main (2,
                                     &GNUNET_TRANSPORT_TESTING_connect_check,
                                     ccc))
    return 1;
  return 0;
}

/* end of test_transport_api_manipulation_send_tcp.c */
