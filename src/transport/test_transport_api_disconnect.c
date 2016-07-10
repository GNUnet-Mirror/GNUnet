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
 * @file transport/test_transport_api_disconnect.c
 * @brief base test case for transport implementations
 *
 * This test case tests disconnect notifications in peer shutdown
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
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

#define MTYPE 12345

static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

static struct GNUNET_TRANSPORT_TransmitHandle *th;

static int shutdown_;


static void
custom_shutdown (void *cls)
{
  if (th != NULL)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
}


static void
notify_disconnect (void *cls,
                   struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                   const struct GNUNET_PeerIdentity *other)
{
  if (me != ccc->p[0])
    return;
  GNUNET_TRANSPORT_TESTING_log_disconnect (cls,
                                           me,
                                           other);
  if (th != NULL)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
  if (shutdown_ == GNUNET_YES)
  {
    ccc->global_ret = GNUNET_OK;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Test good, shutting down...\n");
    GNUNET_SCHEDULER_shutdown ();
  }
}


static void
stop_peer (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Shutting down peer %u (`%s')\n",
              ccc->p[1]->no,
              GNUNET_i2s (&ccc->p[1]->id));
  shutdown_ = GNUNET_YES;
  GNUNET_TRANSPORT_TESTING_stop_peer (ccc->p[1]);
  ccc->p[1] = NULL;
}


static void
notify_receive (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_MessageHeader *message)
{
  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&receiver->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer %u (`%4s') received message of type %d and size %u size from peer %s!\n",
                receiver->no,
                ps,
                ntohs (message->type),
                ntohs (message->size),
                GNUNET_i2s (sender));
    GNUNET_free (ps);
  }
  if ((MTYPE == ntohs (message->type)) &&
      (sizeof (struct GNUNET_MessageHeader) == ntohs (message->size)))
  {
    GNUNET_SCHEDULER_add_now (&stop_peer,
                              NULL);
    return;
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
                "Transmission error occurred in transmit_ready\n");
    GNUNET_SCHEDULER_shutdown ();
    return 0;
  }

  GNUNET_assert (size >= 256);

  if (NULL != buf)
  {
    hdr = buf;
    hdr->size = htons (sizeof (struct GNUNET_MessageHeader));
    hdr->type = htons (MTYPE);
  }
  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&ccc->p[1]->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer %u (`%4s') sending message with type %u and size %u bytes to peer %u (`%4s')\n",
                ccc->p[1]->no,
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
sendtask (void *cls)
{
  ccc->global_ret = GNUNET_SYSERR;
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
  th = GNUNET_TRANSPORT_notify_transmit_ready (ccc->p[1]->th,
                                               &ccc->p[0]->id, 256,
                                               TIMEOUT_TRANSMIT,
                                               &notify_ready,
                                               ccc->p[0]);
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

/* end of test_transport_api_disconnect.c */
