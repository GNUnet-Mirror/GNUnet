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
* @file transport/test_communicator.c
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

static struct GNUNET_PeerIdentity peer_id[NUM_PEERS];

static char *communicator_binary;

static struct
GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_hs[NUM_PEERS];

static struct GNUNET_CONFIGURATION_Handle *cfg_peers[NUM_PEERS];

static char **cfg_peers_name;

static int ret;

// static char *addresses[NUM_PEERS];


#define PAYLOAD_SIZE 256

// static char payload[PAYLOAD_SIZE] = "TEST PAYLOAD";
// static char payload[] = "TEST PAYLOAD";
static uint32_t payload = 42;

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
  if (0 == strcmp ((char*) cls, cfg_peers_name[NUM_PEERS - 1]))
    GNUNET_TRANSPORT_TESTING_transport_communicator_open_queue (tc_hs[0],
                                                                &peer_id[
                                                                  NUM_PEERS
                                                                  - 1],
                                                                address);
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got Queue!\n");
  GNUNET_TRANSPORT_TESTING_transport_communicator_send (tc_queue,
                                                        &payload,
                                                        sizeof(payload));
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
                     const struct GNUNET_TRANSPORT_IncomingMessage *msg)
{
  char *payload_ptr;
  if (0 != strcmp ((char*) cls, cfg_peers_name[NUM_PEERS - 1]))
    return; // TODO?
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s received data (%lu bytes payload)\n",
              (char*) cls,
              ntohs (msg->header.size) - sizeof (struct GNUNET_TRANSPORT_IncomingMessage));
  payload_ptr = (char*)&msg[1] + sizeof (struct GNUNET_MessageHeader);
  ret = memcmp (payload_ptr, &payload, sizeof (payload));
  GNUNET_SCHEDULER_shutdown ();
}

/**
 * @brief Main function called by the scheduler
 *
 * @param cls Closure - Handle to configuration
 */
static void
run (void *cls)
{
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
      cfg_peers_name[i]); /* cls */
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
  if (GNUNET_OK != GNUNET_log_setup ("test_communicator",
                                     "DEBUG",
                                     "test_communicator.log"))
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
