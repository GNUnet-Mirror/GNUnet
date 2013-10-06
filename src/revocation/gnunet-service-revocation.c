/*
  This file is part of GNUnet.
  (C) 2013 Christian Grothoff (and other contributing authors)

  GNUnet is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public Licerevocation as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  GNUnet is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public Licerevocation for more details.

  You should have received a copy of the GNU General Public Licerevocation
  along with GNUnet; see the file COPYING.  If not, write to the
  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
  Boston, MA 02111-1307, USA.
 */

/**
 * @file revocation/gnunet-service-revocation.c
 * @brief key revocation service
 * @author Christian Grothoff
 *
 * The purpose of this service is to allow users to permanently revoke
 * (compromised) keys.  This is done by flooding the network with the
 * revocation requests.  To reduce the attack potential offered by such
 * flooding, revocations must include a proof of work.  We use the
 * set service for efficiently computing the union of revocations of
 * peers that connect.
 *
 * TODO:
 * - load revocations from disk
 * - store revocations to disk
 * - handle p2p revocations
 * - handle p2p connect (trigger SET union)
 * - handle client revoke message
 * - handle client query message
 */
#include "platform.h"
#include <math.h>
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_core_service.h"
#include "gnunet_revocation_service.h"
#include "gnunet_set_service.h"
#include "revocation.h"
#include <gcrypt.h>


/**
 * Per-peer information.
 */
struct PeerEntry
{

  /**
   * Core handle for sending messages to this peer.
   */
  struct GNUNET_CORE_TransmitHandle *th;

  /**
   * What is the identity of the peer?
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Task scheduled to send message to this peer.
   */
  GNUNET_SCHEDULER_TaskIdentifier transmit_task;

};


/**
 * Set from all revocations known to us.
 */
static struct GNUNET_SET_Handle *revocation_set;

/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to the core service (for flooding)
 */
static struct GNUNET_CORE_Handle *coreAPI;

/**
 * Map of all connected peers.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *peers;

/**
 * The peer identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Handle to this serivce's server.
 */
static struct GNUNET_SERVER_Handle *srv;

/**
 * Amount of work required (W-bit collisions) for REVOCATION proofs, in collision-bits.
 */
static unsigned long long revocation_work_required;


/**
 * An revoke message has been received, check that it is well-formed.
 *
 * @param rm the message to verify
 * @return #GNUNET_YES if the message is verified
 *         #GNUNET_NO if the key/signature don't verify
 */
static int
verify_revoke_message (const struct RevokeMessage *rm)
{
  if (GNUNET_YES !=
      GNUNET_REVOCATION_check_pow (&rm->public_key,
				   rm->proof_of_work,
				   (unsigned int) revocation_work_required))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Proof of work invalid: %llu!\n",
                (unsigned long long)
                GNUNET_ntohll (rm->proof_of_work));
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecc_verify (GNUNET_SIGNATURE_PURPOSE_REVOCATION,
				&rm->purpose,
				&rm->signature,
				&rm->public_key))
  {
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Handle QUERY message from client.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_query_message (void *cls, 
		      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received QUERY message from client\n");
  GNUNET_break (0);
  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
}


/**
 * Handle REVOKE message from client.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_revoke_message (void *cls, 
		      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  const struct RevokeMessage *rm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received REVOKE message from client\n");
  rm = (const struct RevokeMessage *) message;
  if (GNUNET_OK != 
      verify_revoke_message (rm))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
  }
  GNUNET_break (0); // FIXME: TBD
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Core handler for flooded revocation messages.
 *
 * @param cls closure unused
 * @param message message
 * @param peer peer identity this message is from (ignored)
 */
static int
handle_p2p_revoke_message (void *cls, 
			   const struct GNUNET_PeerIdentity *peer,
			   const struct GNUNET_MessageHeader *message)
{
  const struct RevokeMessage *rm;


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received REVOKE message from peer\n");
  rm = (const struct RevokeMessage *) message;
  if (GNUNET_OK != 
      verify_revoke_message (rm))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_break (0); // FIXME: TBD

#if 0
  /* flood to rest */
  GNUNET_CONTAINER_multipeermap_iterate (peers, 
					 &do_flood,
                                         &ctx);
#endif
  return GNUNET_OK;
}


/**
 * Method called whenever a peer connects. Sets up the PeerEntry and
 * schedules the initial revocation set exchange with this peer.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
handle_core_connect (void *cls,
		     const struct GNUNET_PeerIdentity *peer)
{
  struct PeerEntry *peer_entry;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%s' connected to us\n",
              GNUNET_i2s (peer));
  peer_entry = GNUNET_new (struct PeerEntry);
  peer_entry->id = *peer;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (peers, peer,
                                                    peer_entry,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
#if 0
  peer_entry->transmit_task =
      GNUNET_SCHEDULER_add_delayed (get_transmit_delay (-1), &transmit_task_cb,
                                    peer_entry);
#endif
  GNUNET_STATISTICS_update (stats, "# peers connected", 1, GNUNET_NO);
}


/**
 * Method called whenever a peer disconnects. Deletes the PeerEntry and cancels
 * any pending transmission requests to that peer.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
handle_core_disconnect (void *cls, 
			const struct GNUNET_PeerIdentity *peer)
{
  struct PeerEntry *pos;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Peer `%s' disconnected from us\n",
              GNUNET_i2s (peer));
  pos = GNUNET_CONTAINER_multipeermap_get (peers, peer);
  if (NULL == pos)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (peers, peer,
                                                       pos));
#if 0
  if (pos->transmit_task != GNUNET_SCHEDULER_NO_TASK) 
  {
    GNUNET_SCHEDULER_cancel (pos->transmit_task);
    pos->transmit_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != pos->th)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (pos->th);
    pos->th = NULL;
  }
#endif
  GNUNET_free (pos);
  GNUNET_STATISTICS_update (stats, "# peers connected", -1, GNUNET_NO);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != revocation_set)
  {
    GNUNET_SET_destroy (revocation_set);
    revocation_set = NULL;
  }
  if (NULL != coreAPI)
  {
    GNUNET_CORE_disconnect (coreAPI);
    coreAPI = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
  if (NULL != peers)
  {
    GNUNET_CONTAINER_multipeermap_destroy (peers);
    peers = NULL;
  }
}


/**
 * Called on core init/fail.
 *
 * @param cls service closure
 * @param identity the public identity of this peer
 */
static void
core_init (void *cls, 
           const struct GNUNET_PeerIdentity *identity)
{
  if (NULL == identity)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		"Connection to core FAILED!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  my_identity = *identity;
}


/**
 * Handle network size estimate clients.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, 
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_query_message, NULL, GNUNET_MESSAGE_TYPE_REVOCATION_QUERY,
     sizeof (struct QueryMessage)},
    {&handle_revoke_message, NULL, GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE,
     sizeof (struct RevokeMessage)},
    {NULL, NULL, 0, 0}
  };
  static const struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {&handle_p2p_revoke_message, GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE,
     sizeof (struct RevokeMessage)},
    {NULL, 0, 0}
  };

  cfg = c;
  srv = server;  
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "REVOCATION", "WORKBITS",
					     &revocation_work_required))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "REVOCATION",
			       "WORKBITS");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (revocation_work_required >= sizeof (struct GNUNET_HashCode) * 8)
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
			       "REVOCATION",
			       "WORKBITS",
			       _("Value is too large.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  revocation_set = GNUNET_SET_create (cfg,
				      GNUNET_SET_OPERATION_UNION);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  peers = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_NO);
  GNUNET_SERVER_add_handlers (srv, handlers);
   /* Connect to core service and register core handlers */
  coreAPI = GNUNET_CORE_connect (cfg,   /* Main configuration */
                                 NULL,       /* Closure passed to functions */
                                 &core_init,    /* Call core_init once connected */
                                 &handle_core_connect,  /* Handle connects */
                                 &handle_core_disconnect,       /* Handle disconnects */
                                 NULL,  /* Don't want notified about all incoming messages */
                                 GNUNET_NO,     /* For header only inbound notification */
                                 NULL,  /* Don't want notified about all outbound messages */
                                 GNUNET_NO,     /* For header only outbound notification */
                                 core_handlers);        /* Register these handlers */
  if (NULL == coreAPI)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  stats = GNUNET_STATISTICS_create ("revocation", cfg);
}


/**
 * The main function for the network size estimation service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, 
      char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "revocation", GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}


#ifdef LINUX
#include <malloc.h>

/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor)) 
GNUNET_ARM_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}
#endif



/* end of gnunet-service-revocation.c */
