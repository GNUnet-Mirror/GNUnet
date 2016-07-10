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
 * @file transport/test_transport_api_manipulation_cfg.c
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


static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

static struct GNUNET_TRANSPORT_TransmitHandle *th;

static struct GNUNET_SCHEDULER_Task *send_task;

static struct GNUNET_TIME_Absolute start_request;

static struct GNUNET_TIME_Absolute start_response;


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


static size_t
notify_request_ready (void *cls, size_t size, void *buf)
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
  hdr->type = htons (TEST_REQUEST_MESSAGE_TYPE);

  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&ccc->p[0]->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending request message from peer %u (`%4s') with type %u and size %u bytes to peer %u (`%4s')\n",
                ccc->p[0]->no, ps,
                ntohs (hdr->type),
                ntohs (hdr->size),
                p->no,
                GNUNET_i2s (&p->id));
    GNUNET_free (ps);
  }

  return TEST_MESSAGE_SIZE;
}


static void
sendtask_request_task (void *cls)
{
  send_task = NULL;
  {
    char *receiver_s = GNUNET_strdup (GNUNET_i2s (&ccc->p[1]->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending message from peer %u (`%s') -> peer %u (`%s') !\n",
                ccc->p[0]->no,
                GNUNET_i2s (&ccc->p[0]->id),
                ccc->p[1]->no,
                receiver_s);
    GNUNET_free (receiver_s);
  }

  start_request = GNUNET_TIME_absolute_get();
  th = GNUNET_TRANSPORT_notify_transmit_ready (ccc->p[0]->th,
                                               &ccc->p[1]->id,
                                               TEST_MESSAGE_SIZE,
                                               TIMEOUT_TRANSMIT,
                                               &notify_request_ready,
                                               ccc->p[1]);
}


static size_t
notify_response_ready (void *cls, size_t size, void *buf)
{
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p = cls;
  struct GNUNET_MessageHeader *hdr;

  th = NULL;
  if (NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Timeout occurred while waiting for transmit_ready\n");
    GNUNET_SCHEDULER_shutdown ();
    ccc->global_ret = 42;
    return 0;
  }

  GNUNET_assert (size >= TEST_MESSAGE_SIZE);
  memset (buf, '\0', TEST_MESSAGE_SIZE);
  hdr = buf;
  hdr->size = htons (TEST_MESSAGE_SIZE);
  hdr->type = htons (TEST_RESPONSE_MESSAGE_TYPE);

  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&ccc->p[0]->id));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending response message from peer %u (`%4s') with type %u and size %u bytes to peer %u (`%4s')\n",
                ccc->p[0]->no,
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
sendtask_response_task (void *cls)
{
  send_task = NULL;
  {
    char *receiver_s = GNUNET_strdup (GNUNET_i2s (&ccc->p[0]->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending message from peer %u (`%4s') -> peer %u (`%s') !\n",
                ccc->p[1]->no,
                GNUNET_i2s (&ccc->p[1]->id),
                ccc->p[0]->no,
                receiver_s);
    GNUNET_free (receiver_s);
  }
  start_response = GNUNET_TIME_absolute_get();
  th = GNUNET_TRANSPORT_notify_transmit_ready (ccc->p[1]->th,
                                               &ccc->p[0]->id,
                                               TEST_MESSAGE_SIZE,
                                               TIMEOUT_TRANSMIT,
                                               &notify_response_ready,
                                               ccc->p[0]);
}


static void
notify_receive (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_TIME_Relative duration;

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
      ccc->global_ret = GNUNET_SYSERR;
      GNUNET_SCHEDULER_shutdown ();
    }
    /* Send response */
    send_task = GNUNET_SCHEDULER_add_now (&sendtask_response_task,
                                          NULL);
    return;
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
      ccc->global_ret = GNUNET_SYSERR;
      GNUNET_SCHEDULER_shutdown ();
      break;
    }
    ccc->global_ret = GNUNET_OK;
    GNUNET_SCHEDULER_shutdown ();
    break;
  default:
    break;
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
    .connect_continuation = &sendtask_request_task,
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


/* end of test_transport_api_manipulation_cfg.c */
