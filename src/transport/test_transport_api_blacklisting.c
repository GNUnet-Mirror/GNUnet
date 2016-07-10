/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2016 GNUnet e.V.

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
 * @file transport/test_transport_api_blacklisting.c
 * @brief test for the blacklisting API
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

#define TEST_MESSAGE_SIZE 2600

#define TEST_MESSAGE_TYPE 12345


static struct GNUNET_TRANSPORT_TransmitHandle *th;

static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

static int connected;

static int blacklist_request_p1;

static int blacklist_request_p2;

static struct GNUNET_TRANSPORT_Blacklist *blacklist_p1;

static struct GNUNET_TRANSPORT_Blacklist *blacklist_p2;

static struct GNUNET_SCHEDULER_Task *send_task;

static struct GNUNET_SCHEDULER_Task *shutdown_task;


static void
end (void *cls)
{
  shutdown_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Stopping\n");
  if ((GNUNET_YES == blacklist_request_p1) &&
      (GNUNET_YES == blacklist_request_p2) &&
      (GNUNET_NO == connected) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peers were never connected, success\n");
    ccc->global_ret = GNUNET_OK;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Peers were not connected, fail\n");
    ccc->global_ret = GNUNET_SYSERR;
  }
  GNUNET_SCHEDULER_shutdown ();
}


static void
custom_shutdown (void *cls)
{
  if (NULL != send_task)
  {
    GNUNET_SCHEDULER_cancel (send_task);
    send_task = NULL;
  }
  if (NULL != shutdown_task)
  {
    GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = NULL;
  }
  if (NULL != th)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
  if (NULL != blacklist_p1)
  {
    GNUNET_TRANSPORT_blacklist_cancel (blacklist_p1);
    blacklist_p1 = NULL;
  }
  if (NULL != blacklist_p2)
  {
    GNUNET_TRANSPORT_blacklist_cancel (blacklist_p2);
    blacklist_p2 = NULL;
  }
}


static void
notify_receive (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Unexpectedly even received the message despite blacklist\n");
  GNUNET_SCHEDULER_shutdown ();
}


static size_t
notify_ready (void *cls,
              size_t size,
              void *buf)
{
  struct GNUNET_MessageHeader *hdr;

  th = NULL;
  if (NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout occurred while waiting for transmit_ready\n");
    GNUNET_SCHEDULER_shutdown ();
    return 0;
  }
  GNUNET_assert (size >= TEST_MESSAGE_SIZE);
  hdr = buf;
  hdr->size = htons (TEST_MESSAGE_SIZE);
  hdr->type = htons (TEST_MESSAGE_TYPE);
  return TEST_MESSAGE_SIZE;
}


static void
sendtask (void *cls)
{
  th = GNUNET_TRANSPORT_notify_transmit_ready (ccc->p[1]->th,
                                               &ccc->p[0]->id,
                                               TEST_MESSAGE_SIZE,
                                               TIMEOUT,
                                               &notify_ready,
                                               ccc->p[0]);
}


static void
notify_connect (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                const struct GNUNET_PeerIdentity *other)
{
  GNUNET_TRANSPORT_TESTING_log_connect (cls,
                                        me,
                                        other);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Peers connected despite blacklist!\n");
  connected = GNUNET_YES; /* this test now failed */
  GNUNET_SCHEDULER_cancel (shutdown_task);
  end (NULL);
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


static int
blacklist_cb (void *cls,
              const struct GNUNET_PeerIdentity *pid)
{
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p = cls;
  int res = GNUNET_SYSERR;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u: Blacklist request for peer `%s'\n",
              p->no,
              GNUNET_i2s (pid));

  if (p == ccc->p[0])
  {
    blacklist_request_p1 = GNUNET_YES;
    res = GNUNET_OK;
  }
  if (p == ccc->p[1])
  {
    blacklist_request_p2 = GNUNET_YES;
    res = GNUNET_SYSERR;
  }

  if ( (GNUNET_YES == blacklist_request_p2) &&
       (GNUNET_YES == blacklist_request_p1) &&
       (NULL == shutdown_task) )
  {
    shutdown_task
      = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3),
                                      &end,
                                      NULL);
  }
  return res;
}


static void
start_blacklist (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting blacklists\n");
  blacklist_p1 = GNUNET_TRANSPORT_blacklist (ccc->p[0]->cfg,
                                             &blacklist_cb,
                                             ccc->p[0]);
  GNUNET_assert (NULL != blacklist_p1);
  blacklist_p2 = GNUNET_TRANSPORT_blacklist (ccc->p[1]->cfg,
                                             &blacklist_cb,
                                             ccc->p[1]);
  GNUNET_assert (NULL != blacklist_p2);
}


int
main (int argc,
      char *argv[])
{
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .pre_connect_task = &start_blacklist,
    .connect_continuation = &sendtask,
    .config_file = "test_transport_api_data.conf",
    .rec = &notify_receive,
    .nc = &notify_connect,
    .nd = &notify_disconnect,
    .shutdown_task = &custom_shutdown,
    .timeout = TIMEOUT,
    .bi_directional = GNUNET_YES
  };

  ccc = &my_ccc;
  if (GNUNET_OK !=
      GNUNET_TRANSPORT_TESTING_main (2,
                                     &GNUNET_TRANSPORT_TESTING_connect_check,
                                     ccc))
    return 1;
  return 0;
}


/* end of transport_api_blacklisting.c */
