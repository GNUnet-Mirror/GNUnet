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
 * @file transport/test_transport_address_switch.c
 * @brief base test case for transport implementations
 *
 * This test case tests if peers can successfully switch addresses when
 * connected for plugins supporting multiple addresses by monitoring transport's
 * statistic values.
 *
 * This test starts 2 peers and connects them. When connected test messages
 * are transmitted from peer 2 to peer 1. The test monitors transport's
 * statistics values for information about address switch attempts.
 *
 * The test passes with success if one of the peers could successfully switch
 * addresses in connected state and a test message was successfully transmitted
 * after this switch.
 *
 * Since it is not possible to trigger an address switch from outside,
 * the test returns "77" (skipped) when no address switching attempt
 * takes place. It fails if an address switch attempt fails.
 *
 * NOTE: The test seems largely useless right now, as we simply NEVER
 * switch addresses under the test conditions.  However, it may be a
 * good starting point for a future test.  For now, it always times
 * out and returns "77" (skipped), so we set the timeout suitably low.
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "gnunet_ats_service.h"
#include "transport-testing.h"


/**
 * Testcase timeout
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

static struct GNUNET_SCHEDULER_Task *measure_task;


/**
 * Statistics we track per peer.
 */
struct PeerStats
{
  struct GNUNET_STATISTICS_Handle *stat;

  unsigned int addresses_avail;

  unsigned int switch_attempts;

  unsigned int switch_success;

  unsigned int switch_fail;
};

static struct PeerStats stats[2];

/* Amount of data transfered since last switch attempt */
static unsigned long long bytes_sent_after_switch;

static unsigned long long bytes_recv_after_switch;


static int
stat_start_attempt_cb (void *cls,
                       const char *subsystem,
                       const char *name,
                       uint64_t value,
                       int is_persistent)
{
  struct PeerStats *stat = cls;

  stat->switch_attempts++;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Switch attempted (%p)",
              stat);
  bytes_recv_after_switch = 0;
  bytes_sent_after_switch = 0;

  return GNUNET_OK;
}


static int
stat_success_attempt_cb (void *cls,
                         const char *subsystem,
                         const char *name,
                         uint64_t value,
                         int is_persistent)
{
  struct PeerStats *stat = cls;

  stat->switch_success++;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Switch succeeded (%p)",
              stat);
  return GNUNET_OK;
}


static int
stat_fail_attempt_cb (void *cls,
                      const char *subsystem,
                      const char *name,
                      uint64_t value,
                      int is_persistent)
{
  struct PeerStats *stat = cls;

  if (value == 0)
    return GNUNET_OK;

  stat->switch_fail++;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Switch failed (%p)",
              stat);
  return GNUNET_OK;
}


static int
stat_addresses_available (void *cls,
                          const char *subsystem,
                          const char *name,
                          uint64_t value,
                          int is_persistent)
{
  struct PeerStats *stat = cls;

  stat->addresses_avail++;
  return GNUNET_OK;
}


/**
 * List of statistics entries we care about.
 */
static struct WatchEntry {

  /**
   * Name of the statistic we watch.
   */
  const char *stat_name;

  /**
   * Handler to register;
   */
  GNUNET_STATISTICS_Iterator stat_handler;
} watches[] = {
  { "# Attempts to switch addresses", &stat_start_attempt_cb },
  { "# Successful attempts to switch addresses", &stat_success_attempt_cb },
  { "# Failed attempts to switch addresses (failed to send CONNECT CONT)", &stat_fail_attempt_cb },
  { "# Failed attempts to switch addresses (failed to send CONNECT)", &stat_fail_attempt_cb },
  { "# Failed attempts to switch addresses (no response)", &stat_fail_attempt_cb },
  { "# transport addresses", &stat_addresses_available },
  { NULL, NULL }
};


static void
custom_shutdown (void *cls)
{
  int result;

  if (NULL != measure_task)
  {
    GNUNET_SCHEDULER_cancel (measure_task);
    measure_task = NULL;
  }
  if (0 == stats[0].switch_attempts + stats[1].switch_attempts)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Test did not work, as peers didn't switch (flawed testcase)!\n");
    ccc->global_ret = 77;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Fail (timeout)! No transmission after switch! Stopping peers\n");
    ccc->global_ret = GNUNET_SYSERR;
  }

  /* stop statistics */
  for (unsigned int i=0;i<2;i++)
  {
    if (NULL != stats[i].stat)
    {
      for (unsigned int j=0;NULL != watches[j].stat_name; j++)
        GNUNET_STATISTICS_watch_cancel (stats[i].stat,
                                        "transport",
                                        watches[j].stat_name,
                                        watches[j].stat_handler,
                                        &stats[i]);

      GNUNET_STATISTICS_destroy (stats[i].stat,
                                 GNUNET_NO);
      stats[i].stat = NULL;
    }
  }

  result = 0;
  FPRINTF (stderr, "\n");
  if (stats[0].switch_attempts > 0)
  {
    FPRINTF (stderr,
             "Peer 1 tried %u times to switch and succeeded %u times, failed %u times\n",
             stats[0].switch_attempts,
             stats[0].switch_success,
             stats[0].switch_fail);
    if (stats[0].switch_success != stats[0].switch_attempts)
    {
      GNUNET_break (0);
      result ++;
    }
  }
  else if (stats[0].addresses_avail > 1)
  {
    FPRINTF (stderr,
             "Peer 1 had %u addresses available, but did not try to switch\n",
             stats[0].addresses_avail);
  }
  if (stats[1].switch_attempts > 0)
  {
    FPRINTF (stderr,
             "Peer 2 tried %u times to switch and succeeded %u times, failed %u times\n",
             stats[1].switch_attempts,
             stats[1].switch_success,
             stats[1].switch_fail);
    if (stats[1].switch_success != stats[1].switch_attempts)
    {
      GNUNET_break (0);
      result++;
    }
  }
  else if (stats[1].addresses_avail > 1)
  {
    FPRINTF (stderr,
             "Peer 2 had %u addresses available, but did not try to switch\n",
             stats[1].addresses_avail);
  }

  if ( ((stats[0].switch_attempts > 0) || (stats[1].switch_attempts > 0)) &&
       (bytes_sent_after_switch == 0) )
  {
    FPRINTF (stderr,
	     "No data sent after switching!\n");
    GNUNET_break (0);
    result++;
  }
  if ( ((stats[0].switch_attempts > 0) || (stats[1].switch_attempts > 0)) &&
       (bytes_recv_after_switch == 0) )
  {
    FPRINTF (stderr,
	     "No data received after switching!\n");
    GNUNET_break (0);
    result++;
  }
  if (0 != result)
    ccc->global_ret = GNUNET_SYSERR;
}


static void
notify_receive (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_TRANSPORT_TESTING_TestMessage *hdr)
{
  if (GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE != ntohs (hdr->header.type))
    return;

  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&receiver->id));

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Peer %u (`%s') got message %u of size %u from peer (`%s')\n",
                receiver->no,
                ps,
                ntohl (hdr->num),
                ntohs (hdr->header.size),
                GNUNET_i2s (sender));
    GNUNET_free (ps);
  }
  if ( ((stats[0].switch_attempts >= 1) || (stats[1].switch_attempts >= 1)) &&
        (stats[0].switch_attempts == stats[0].switch_fail + stats[0].switch_success) &&
        (stats[1].switch_attempts == stats[1].switch_fail + stats[1].switch_success) )
  {
    bytes_recv_after_switch += ntohs(hdr->header.size);
    if ( (bytes_sent_after_switch > 0) &&
	 (bytes_recv_after_switch > 0) )
    {
      /* A peer switched addresses and sent and received data after the
       * switch operations */
      GNUNET_SCHEDULER_shutdown ();
    }
  }
}


static void
notify_send (void *cls)
{
  static uint32_t cnt;

  GNUNET_assert (GNUNET_OK ==
		 GNUNET_TRANSPORT_TESTING_send (ccc->p[1],
						ccc->p[0],
						GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE,
						GNUNET_TRANSPORT_TESTING_LARGE_MESSAGE_SIZE,
						++cnt,
						&notify_send,
						NULL));
  if ( ( (stats[0].switch_attempts >= 1) ||
         (stats[1].switch_attempts >= 1) ) &&
       (stats[0].switch_attempts == stats[0].switch_fail + stats[0].switch_success) &&
       (stats[1].switch_attempts == stats[1].switch_fail + stats[1].switch_success) )
  {
    bytes_sent_after_switch
      += GNUNET_TRANSPORT_TESTING_LARGE_MESSAGE_SIZE;
  }
}


static void
progress_indicator (void *cls)
{
  static int counter;

  measure_task = NULL;
  counter++;
  if ((TIMEOUT.rel_value_us / 1000 / 1000LL) < counter)
  {
    FPRINTF (stderr, "%s", ".\n");
  }
  else
  {
    FPRINTF (stderr, "%s", ".");
    measure_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                                 &progress_indicator,
                                                 NULL);
  }
}


static void
connected_cb (void *cls)
{
  for (unsigned int i=0;i<2;i++)
  {
    stats[i].stat = GNUNET_STATISTICS_create ("transport",
                                              ccc->p[i]->cfg);
    if (NULL == stats[i].stat)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Fail! Could not create statistics for peers!\n");
      ccc->global_ret = GNUNET_SYSERR;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    for (unsigned int j=0;NULL != watches[j].stat_name; j++)
    {
      GNUNET_STATISTICS_watch (stats[i].stat,
                               "transport",
                               watches[j].stat_name,
                               watches[j].stat_handler,
                               &stats[i]);
    }
  }
  /* Show progress */
  ccc->global_ret = GNUNET_OK;
  measure_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                               &progress_indicator,
                                               NULL);
  /* Peers are connected, start transmit test messages */
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_TRANSPORT_TESTING_send (ccc->p[1],
						ccc->p[0],
						GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE,
						GNUNET_TRANSPORT_TESTING_LARGE_MESSAGE_SIZE,
						0,
						&notify_send,
						NULL));
}


int
main (int argc,
      char *argv[])
{
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .connect_continuation = &connected_cb,
    .config_file = "test_transport_api_data.conf",
    .rec = &notify_receive,
    .nc = &GNUNET_TRANSPORT_TESTING_log_connect,
    .shutdown_task = &custom_shutdown,
    .timeout = TIMEOUT
  };
  ccc = &my_ccc;
  int ret;

  ret = GNUNET_TRANSPORT_TESTING_main (2,
                                       &GNUNET_TRANSPORT_TESTING_connect_check,
                                       ccc);
  if (77 == ret)
    return 77;
  if (GNUNET_OK != ret)
    return 1;
  return 0;
}
/* end of test_transport_address_switch.c */
