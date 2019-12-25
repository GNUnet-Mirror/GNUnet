/*
    This file is part of GNUnet.
    Copyright (C) 2019 GNUnet e.V.

    GNUnet is free software: you can redistribute it and/or modify it
    under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License,
    or (at your option) any later version.

    GNUnet is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    SPDX-License-Identifier: AGPL3.0-or-later
*/

/**
* @file transport/test_communicator_basic.c
* @brief test the communicators
* @author Julius Bünger
* @author Martin Schanzenbach
*/
#include "platform.h"
#include "gnunet_util_lib.h"
#include "transport-testing2.h"
#include "gnunet_ats_transport_service.h"
#include "gnunet_signatures.h"
#include "gnunet_testing_lib.h"
#include "transport.h"

#include <inttypes.h>


#define LOG(kind, ...) GNUNET_log_from (kind, \
                                        "test_transport_communicator", \
                                        __VA_ARGS__)

#define NUM_PEERS 2

static struct GNUNET_SCHEDULER_Task *to_task;

static int queue_est = GNUNET_NO;

static struct GNUNET_PeerIdentity peer_id[NUM_PEERS];

static char *communicator_binary;

static struct
GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_hs[NUM_PEERS];

static struct GNUNET_CONFIGURATION_Handle *cfg_peers[NUM_PEERS];

static char **cfg_peers_name;

static int ret;

static struct GNUNET_TIME_Absolute start_short;

static struct GNUNET_TIME_Absolute start_long;

static struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *my_tc;

#define SHORT_MESSAGE_SIZE 128

#define LONG_MESSAGE_SIZE 32000

#define BURST_PACKETS 5000

#define BURST_RUNS 1

#define SHORT_BURST_WINDOW \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,2)

#define LONG_BURST_WINDOW \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,2)

#define BURST_SHORT 0

#define BURST_LONG 1

#define SIZE_CHECK 2


static size_t num_sent = 0;

static uint32_t ack = 0;

static int phase;

static size_t num_received = 0;

static uint64_t avg_latency = 0;

static struct GNUNET_TIME_Relative duration;

static void
communicator_available_cb (void *cls,
                           struct
                           GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle
                           *tc_h,
                           enum GNUNET_TRANSPORT_CommunicatorCharacteristics cc,
                           char *address_prefix)
{
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Communicator available. (cc: %u, prefix: %s)\n",
       cc,
       address_prefix);
}


static void
add_address_cb (void *cls,
                struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *
                tc_h,
                const char *address,
                struct GNUNET_TIME_Relative expiration,
                uint32_t aid,
                enum GNUNET_NetworkType nt)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "New address. (addr: %s, expir: %" PRIu32 ", ID: %" PRIu32 ", nt: %u\n",
       address,
       expiration.rel_value_us,
       aid,
       nt);
  // addresses[1] = GNUNET_strdup (address);
  if ((0 == strcmp ((char*) cls, cfg_peers_name[NUM_PEERS - 1])) &&
      (GNUNET_NO == queue_est))
  {
    queue_est = GNUNET_YES;
    GNUNET_TRANSPORT_TESTING_transport_communicator_open_queue (tc_hs[0],
                                                                &peer_id[
                                                                  NUM_PEERS
                                                                  - 1],
                                                                address);
  }
}


/**
 * @brief Callback that informs whether the requested queue will be
 * established
 *
 * Implements #GNUNET_TRANSPORT_TESTING_QueueCreateReplyCallback.
 *
 * @param cls Closure - unused
 * @param tc_h Communicator handle - unused
 * @param will_try #GNUNET_YES if queue will be established
 *                #GNUNET_NO if queue will not be established (bogous address)
 */
static void
queue_create_reply_cb (void *cls,
                       struct
                       GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *
                       tc_h,
                       int will_try)
{
  if (GNUNET_YES == will_try)
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Queue will be established!\n");
  else
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Queue won't be established (bougus address?)!\n");
}


static char*
make_payload (size_t payload_size)
{
  char *payload = GNUNET_malloc (payload_size);
  struct GNUNET_TIME_Absolute ts;
  struct GNUNET_TIME_AbsoluteNBO ts_n;
  GNUNET_assert (payload_size >= 8); // So that out timestamp fits
  ts = GNUNET_TIME_absolute_get ();
  ts_n = GNUNET_TIME_absolute_hton (ts);
  memset (payload, 0, payload_size);
  memcpy (payload, &ts_n, sizeof (struct GNUNET_TIME_AbsoluteNBO));
  return payload;
}


static void
latency_timeout (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Latency too high. Test failed. (Phase: %d. Received: %lu\n",
              phase, num_received);
  ret = 2;
  to_task = NULL;
  GNUNET_SCHEDULER_shutdown ();
}


static void
size_test (void *cls)
{
  char *payload;
  phase = SIZE_CHECK;

  if (ack < 64000) // Leave some room for our protocol.
  {
    payload = make_payload (ack);
    GNUNET_TRANSPORT_TESTING_transport_communicator_send (my_tc,
                                                          payload,
                                                          ack);
    GNUNET_free (payload);
    ack += 5;
    num_sent++;
    if (NULL == to_task)
      to_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                              &latency_timeout,
                                              NULL);
    if (ack < 64000)
      GNUNET_SCHEDULER_add_now (&size_test, NULL);
  }
}


static void
long_test (void *cls)
{
  char *payload;
  if (num_sent < BURST_PACKETS)
  {
    payload = make_payload (LONG_MESSAGE_SIZE);
    GNUNET_TRANSPORT_TESTING_transport_communicator_send (my_tc,
                                                          payload,
                                                          LONG_MESSAGE_SIZE);
    num_sent++;
    GNUNET_free (payload);
    if (NULL == to_task)
      to_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                              &latency_timeout,
                                              NULL);

    GNUNET_SCHEDULER_add_now (&long_test, NULL);
    //if (num_sent == BURST_PACKETS)
    //  GNUNET_SCHEDULER_add_delayed (LONG_BURST_WINDOW,
    //                                &long_test, NULL);
    return;
  }
}


static void
short_test (void *cls)
{
  char *payload;
  if (num_sent < BURST_PACKETS)
  {
    payload = make_payload (SHORT_MESSAGE_SIZE);
    GNUNET_TRANSPORT_TESTING_transport_communicator_send (my_tc,
                                                          payload,
                                                          SHORT_MESSAGE_SIZE);
    num_sent++;
    GNUNET_free (payload);
    if (NULL == to_task)
      to_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                              &latency_timeout,
                                              NULL);

    GNUNET_SCHEDULER_add_now (&short_test, NULL);
    /*if (num_sent == BURST_PACKETS)
    {
      GNUNET_SCHEDULER_add_delayed (SHORT_BURST_WINDOW,
                                    &short_test, NULL);
      return;
    }*/
  }
}



/**
 * @brief Handle opening of queue
 *
 * Issues sending of test data
 *
 * Implements #GNUNET_TRANSPORT_TESTING_AddQueueCallback
 *
 * @param cls Closure
 * @param tc_h Communicator handle
 * @param tc_queue Handle to newly opened queue
 */
static void
add_queue_cb (void *cls,
              struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
              struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *
              tc_queue)
{
  if (0 != strcmp ((char*) cls, cfg_peers_name[0]))
    return; // TODO?
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queue established, starting test...\n");
  start_short = GNUNET_TIME_absolute_get ();
  my_tc = tc_queue;
  phase = BURST_SHORT;
  GNUNET_SCHEDULER_add_now (&short_test, tc_queue);
}


static void
update_avg_latency (const char*payload)
{
  struct GNUNET_TIME_AbsoluteNBO *ts_n;
  struct GNUNET_TIME_Absolute ts;
  struct GNUNET_TIME_Relative latency;

  ts_n = (struct GNUNET_TIME_AbsoluteNBO *) payload;
  ts = GNUNET_TIME_absolute_ntoh (*ts_n);
  latency = GNUNET_TIME_absolute_get_duration (ts);
  if (1 == num_received)
    avg_latency = latency.rel_value_us;
  else
    avg_latency = ((avg_latency * (num_received - 1)) + latency.rel_value_us)
                  / num_received;

}


/**
 * @brief Handle an incoming message
 *
 * Implements #GNUNET_TRANSPORT_TESTING_IncomingMessageCallback

 * @param cls Closure
 * @param tc_h Handle to the receiving communicator
 * @param msg Received message
 */
void
incoming_message_cb (void *cls,
                     struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle
                     *tc_h,
                     const char*payload,
                     size_t payload_len)
{
  if (0 != strcmp ((char*) cls, cfg_peers_name[NUM_PEERS - 1]))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "unexpected receiver...\n");
    return;
  }
  if (phase == BURST_SHORT)
  {
    GNUNET_assert (SHORT_MESSAGE_SIZE == payload_len);
    num_received++;
    duration = GNUNET_TIME_absolute_get_duration (start_short);
    update_avg_latency (payload);
    if (num_received == BURST_PACKETS)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                  "Short size packet test done.\n");
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                  "%lu/%lu packets in %llu us (%llu kb/s) -- avg latency: %llu us\n",
                  num_received,
                  num_sent,
                  duration.rel_value_us,
                  (SHORT_MESSAGE_SIZE * num_received) / (duration.rel_value_us
                                                         / 1000),
                  avg_latency);
      start_long = GNUNET_TIME_absolute_get ();
      phase = BURST_LONG;
      num_sent = 0;
      avg_latency = 0;
      num_received = 0;
      GNUNET_SCHEDULER_cancel (to_task);
      to_task = NULL;
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &long_test, NULL);
    }

  }
  else if (phase == BURST_LONG)
  {
    if (LONG_MESSAGE_SIZE != payload_len)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Ignoring packet with wrong length\n");
      return; // Ignore
    }
    num_received++;
    duration = GNUNET_TIME_absolute_get_duration (start_long);
    update_avg_latency (payload);
    if (num_received == BURST_PACKETS)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                  "Long size packet test done.\n");
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                  "%lu/%lu packets in %llu us (%llu kb/s) -- avg latency: %llu us\n",
                  num_received,
                  num_sent,
                  duration.rel_value_us,
                  (LONG_MESSAGE_SIZE * num_received) / (duration.rel_value_us
                                                        / 1000),
                  avg_latency);
      ack = 10;
      phase = SIZE_CHECK;
      num_received = 0;
      num_sent = 0;
      avg_latency = 0;
      GNUNET_SCHEDULER_cancel (to_task);
      to_task = NULL;
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &size_test, NULL);

    }
  }
  else         // if (phase == SIZE_CHECK) {
  {
    num_received++;
    update_avg_latency (payload);
    if (num_received >= (64000 - 10) / 5)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                  "Size packet test done.\n");
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                  "%lu/%lu packets -- avg latency: %llu us\n",
                  num_received,
                  num_sent,
                  avg_latency);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Finished\n");
      GNUNET_SCHEDULER_cancel (to_task);
      to_task = NULL;
      GNUNET_SCHEDULER_shutdown ();
      // Finished!
      // }
    }
  }
  // Reset timeout
  if (to_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (to_task);
    to_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                            &latency_timeout,
                                            NULL);
  }
}


/**
 * @brief Main function called by the scheduler
 *
 * @param cls Closure - Handle to configuration
 */
static void
run (void *cls)
{
  ret = 0;
  num_received = 0;
  num_sent = 0;
  for (int i = 0; i < NUM_PEERS; i++)
  {
    tc_hs[i] = GNUNET_TRANSPORT_TESTING_transport_communicator_service_start (
      "transport",
      communicator_binary,
      cfg_peers_name[i],
      &communicator_available_cb,
      &add_address_cb,
      &queue_create_reply_cb,
      &add_queue_cb,
      &incoming_message_cb,
      cfg_peers_name[i]);   /* cls */
  }
}


int
main (int argc,
      char *const *argv)
{
  struct GNUNET_CRYPTO_EddsaPrivateKey *private_key;
  char *communicator_name;
  char *cfg_peer;
  ret = 1;

  communicator_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);
  GNUNET_asprintf (&communicator_binary, "gnunet-communicator-%s",
                   communicator_name);
  cfg_peers_name = GNUNET_malloc (sizeof(char*) * NUM_PEERS);
  if (GNUNET_OK != GNUNET_log_setup ("test_communicator_basic",
                                     "DEBUG",
                                     "test_communicator_basic.log"))
  {
    fprintf (stderr, "Unable to setup log\n");
    GNUNET_break (0);
    return 2;
  }
  for (int i = 0; i < NUM_PEERS; i++)
  {
    GNUNET_asprintf ((&cfg_peer),
                     "test_communicator_%s_peer%u.conf",
                     communicator_name, i + 1);
    cfg_peers_name[i] = cfg_peer;
    cfg_peers[i] = GNUNET_CONFIGURATION_create ();
    if (GNUNET_YES ==
        GNUNET_DISK_file_test (cfg_peers_name[i]))
    {
      if (GNUNET_SYSERR ==
          GNUNET_CONFIGURATION_load (cfg_peers[i],
                                     cfg_peers_name[i]))
      {
        fprintf (stderr,
                 "Malformed configuration file `%s', exiting ...\n",
                 cfg_peers_name[i]);
        return 1;
      }
    }
    else
    {
      if (GNUNET_SYSERR ==
          GNUNET_CONFIGURATION_load (cfg_peers[i],
                                     NULL))
      {
        fprintf (stderr,
                 "Configuration file %s does not exist, exiting ...\n",
                 cfg_peers_name[i]);
        return 1;
      }
    }
    private_key =
      GNUNET_CRYPTO_eddsa_key_create_from_configuration (cfg_peers[i]);
    if (NULL == private_key)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Unable to get peer ID\n");
      return 1;
    }
    GNUNET_CRYPTO_eddsa_key_get_public (private_key,
                                        &peer_id[i].public_key);
    GNUNET_free (private_key);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Identity of peer %u is %s\n",
                i, GNUNET_i2s_full (&peer_id[i]));
  }
  fprintf (stderr, "Starting test...\n");
  GNUNET_SCHEDULER_run (&run,
                        NULL);
  return ret;
}
