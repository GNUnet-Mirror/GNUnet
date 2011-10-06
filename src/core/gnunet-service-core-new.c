/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file core/gnunet-service-core.c
 * @brief high-level P2P messaging
 * @author Christian Grothoff
 *
 * Type map implementation:
 * - track type maps for neighbours (can wait)
 * - only notify clients about peers with matching type maps (can wait)
 *
 * Considerations for later:
 * - check that hostkey used by transport (for HELLOs) is the
 *   same as the hostkey that we are using!
 */
#include "platform.h"
#include <zlib.h>
#include "gnunet_constants.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "core.h"


#define DEBUG_HANDSHAKE GNUNET_EXTRA_LOGGING

#define DEBUG_CORE_QUOTA GNUNET_EXTRA_LOGGING

/**
 * Receive and send buffer windows grow over time.  For
 * how long can 'unused' bandwidth accumulate before we
 * need to cap it?  (specified in seconds).
 */
#define MAX_WINDOW_TIME_S (5 * 60)

/**
 * How many messages do we queue up at most for optional
 * notifications to a client?  (this can cause notifications
 * about outgoing messages to be dropped).
 */
#define MAX_NOTIFY_QUEUE 1024

/**
 * Minimum bandwidth (out) to assign to any connected peer.
 * Should be rather low; values larger than DEFAULT_BW_IN_OUT make no
 * sense.
 */
#define MIN_BANDWIDTH_PER_PEER GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT

/**
 * After how much time past the "official" expiration time do
 * we discard messages?  Should not be zero since we may
 * intentionally defer transmission until close to the deadline
 * and then may be slightly past the deadline due to inaccuracy
 * in sleep and our own CPU consumption.
 */
#define PAST_EXPIRATION_DISCARD_TIME GNUNET_TIME_UNIT_SECONDS

/**
 * What is the maximum delay for a SET_KEY message?
 */
#define MAX_SET_KEY_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

/**
 * How long do we wait for SET_KEY confirmation initially?
 */
#define INITIAL_SET_KEY_RETRY_FREQUENCY GNUNET_TIME_relative_multiply (MAX_SET_KEY_DELAY, 1)

/**
 * What is the maximum delay for a PING message?
 */
#define MAX_PING_DELAY GNUNET_TIME_relative_multiply (MAX_SET_KEY_DELAY, 2)

/**
 * What is the maximum delay for a PONG message?
 */
#define MAX_PONG_DELAY GNUNET_TIME_relative_multiply (MAX_PING_DELAY, 2)

/**
 * What is the minimum frequency for a PING message?
 */
#define MIN_PING_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * How often do we recalculate bandwidth quotas?
 */
#define QUOTA_UPDATE_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * What is the priority for a SET_KEY message?
 */
#define SET_KEY_PRIORITY 0xFFFFFF

/**
 * What is the priority for a PING message?
 */
#define PING_PRIORITY 0xFFFFFF

/**
 * What is the priority for a PONG message?
 */
#define PONG_PRIORITY 0xFFFFFF

/**
 * How many messages do we queue per peer at most?  Must be at
 * least two.
 */
#define MAX_PEER_QUEUE_SIZE 16

/**
 * How many non-mandatory messages do we queue per client at most?
 */
#define MAX_CLIENT_QUEUE_SIZE 32

/**
 * What is the maximum age of a message for us to consider
 * processing it?  Note that this looks at the timestamp used
 * by the other peer, so clock skew between machines does
 * come into play here.  So this should be picked high enough
 * so that a little bit of clock skew does not prevent peers
 * from connecting to us.
 */
#define MAX_MESSAGE_AGE GNUNET_TIME_UNIT_DAYS



/**
 * Number of bytes (at the beginning) of "struct EncryptedMessage"
 * that are NOT encrypted.
 */
#define ENCRYPTED_HEADER_SIZE (offsetof(struct EncryptedMessage, sequence_number))


/**
 * Our identity.
 */
struct GNUNET_PeerIdentity GSC_my_identity;

/**
 * Our configuration.
 */
const struct GNUNET_CONFIGURATION_Handle *GSC_cfg;

/**
 * For creating statistics.
 */
struct GNUNET_STATISTICS_Handle *GSC_stats;

/**
 * Our message stream tokenizer (for encrypted payload).
 */
struct GNUNET_SERVER_MessageStreamTokenizer *GSC_mst;


/**
 * Last task run during shutdown.  Disconnects us from
 * the transport.
 */
static void
cleaning_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Core service shutting down.\n");
#endif
  GSC_CLIENTS_done ();

  if (GSC_mst != NULL)
  {
    GNUNET_SERVER_mst_destroy (GSC_mst);
    GSC_mst = NULL;
  }
  if (GSC_stats != NULL)
  {
    GNUNET_STATISTICS_destroy (GSC_stats, GNUNET_NO);
    GSC_stats = NULL;
  }
  GSC_cfg = NULL;
}


/**
 * Initiate core service.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  GSC_cfg = c;  
  GSC_mst = GNUNET_SERVER_mst_create (&deliver_message, NULL);
  GSC_stats = GNUNET_STATISTICS_create ("core", cfg);

  GSC_CLIENTS_init (server);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleaning_task,
                                NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Core service of `%4s' ready.\n"),
              GNUNET_i2s (&my_identity));
}



/**
 * The main function for the transport service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "core", GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-core.c */
