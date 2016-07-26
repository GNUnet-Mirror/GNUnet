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
 * @file transport/test_transport_api_monitor_peers.c
 * @brief base test case for transport peer monitor API
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

#define TEST_MESSAGE_TYPE 12345

static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

static struct GNUNET_TRANSPORT_PeerMonitoringContext *pmc_p1;

static struct GNUNET_TRANSPORT_PeerMonitoringContext *pmc_p2;

static int p1_c;

static int p2_c;

static int p1_c_notify;

static int p2_c_notify;


static void
custom_shutdown (void *cls)
{
  if (NULL != pmc_p1)
  {
    GNUNET_TRANSPORT_monitor_peers_cancel (pmc_p1);
    pmc_p1 = NULL;
  }
  if (NULL != pmc_p2)
  {
    GNUNET_TRANSPORT_monitor_peers_cancel (pmc_p2);
    pmc_p2 = NULL;
  }
}


static void
notify_receive (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  char *ps = GNUNET_strdup (GNUNET_i2s (&receiver->id));

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Peer %u (`%s') received message of type %d and size %u size from peer %s!\n",
              receiver->no,
              ps,
              ntohs (message->header.type),
              ntohs (message->header.size),
              GNUNET_i2s (sender));
  GNUNET_free (ps);
}


static void
sendtask (void *cls)
{
  /* intentionally empty */
}


static void
check_done ()
{
  if ( (GNUNET_YES == p1_c) &&
       (GNUNET_YES == p2_c) &&
       p1_c_notify &&
       p2_c_notify)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Both peers state to be connected\n");
    ccc->global_ret = GNUNET_OK;
    GNUNET_SCHEDULER_shutdown ();
  }
}


static void
notify_connect (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                const struct GNUNET_PeerIdentity *other)
{
  GNUNET_TRANSPORT_TESTING_log_connect (cls,
                                        me,
                                        other);
  if (0 == memcmp (other, &ccc->p[0]->id, sizeof (struct GNUNET_PeerIdentity)))
  {
    p1_c_notify = GNUNET_YES;
  }
  if (0 == memcmp (other, &ccc->p[1]->id, sizeof (struct GNUNET_PeerIdentity)))
  {
    p2_c_notify = GNUNET_YES;
  }
  check_done ();
}


static void
monitor1_cb (void *cls,
             const struct GNUNET_PeerIdentity *peer,
             const struct GNUNET_HELLO_Address *address,
             enum GNUNET_TRANSPORT_PeerState state,
             struct GNUNET_TIME_Absolute state_timeout)
{
  if ((NULL == address) || (NULL == ccc->p[0]))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Monitor 1: %s %s %s\n",
              GNUNET_i2s (&address->peer),
              GNUNET_TRANSPORT_ps2s (state),
              GNUNET_STRINGS_absolute_time_to_string(state_timeout));
  if ( (0 == memcmp (&address->peer, &ccc->p[1]->id, sizeof (ccc->p[1]->id))) &&
       (GNUNET_YES == GNUNET_TRANSPORT_is_connected(state)) &&
       (GNUNET_NO == p1_c) )
  {
    p1_c = GNUNET_YES;
    check_done ();
  }
}


static void
monitor2_cb (void *cls,
             const struct GNUNET_PeerIdentity *peer,
             const struct GNUNET_HELLO_Address *address,
             enum GNUNET_TRANSPORT_PeerState state,
             struct GNUNET_TIME_Absolute state_timeout)
{
  if ((NULL == address) || (NULL == ccc->p[1]))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Monitor 2: %s %s %s\n",
              GNUNET_i2s (&address->peer),
              GNUNET_TRANSPORT_ps2s (state),
              GNUNET_STRINGS_absolute_time_to_string(state_timeout));
  if ( (0 == memcmp (&address->peer, &ccc->p[0]->id, sizeof (ccc->p[0]->id))) &&
       (GNUNET_YES == GNUNET_TRANSPORT_is_connected(state)) &&
       (GNUNET_NO == p2_c) )
  {
    p2_c = GNUNET_YES;
    check_done ();
  }
}


static void
start_monitors (void *cls)
{
  pmc_p1 = GNUNET_TRANSPORT_monitor_peers (ccc->p[0]->cfg,
                                           NULL,
                                           GNUNET_NO,
                                           &monitor1_cb,
                                           NULL);
  pmc_p2 = GNUNET_TRANSPORT_monitor_peers (ccc->p[1]->cfg,
                                           NULL,
                                           GNUNET_NO,
                                           &monitor2_cb,
                                           NULL);
}


int
main (int argc, char *argv[])
{
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .pre_connect_task = &start_monitors,
    .connect_continuation = &sendtask,
    .config_file = "test_transport_api_data.conf",
    .rec = &notify_receive,
    .nc = &notify_connect,
    .nd = &GNUNET_TRANSPORT_TESTING_log_disconnect,
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

/* end of test_transport_api_monitor_peers.c */
