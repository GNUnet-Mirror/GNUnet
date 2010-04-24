/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file migration/gnunet-daemon-migration.c
 * @brief migrating (file-sharing) content through the network; this 
 *        daemon is only responsible for pushing content out (not for
 *        processing inbound messages)
 * @author Christian Grothoff
 */
#include <stdlib.h>
#include "platform.h"
#include "../fs/fs.h"
#include "gnunet_constants.h"
#include "gnunet_core_service.h"
#include "gnunet_datastore_service.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_util_lib.h"


#define DEBUG_MIGRATION GNUNET_YES

/**
 * Information we keep per peer.
 */
struct Peer
{
  /**
   * Last time we migrated data to this peer.
   */
  struct GNUNET_TIME_Absolute last_migration;

};


/**
 * Our scheduler.
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the core API.
 */
static struct GNUNET_CORE_Handle *handle;

/**
 * Handle for reporting statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle for the core service.
*/
static struct GNUNET_CORE_Handle *handle;

/**
 * Handle to the datastore.
 */
static struct GNUNET_DATASTORE_Handle *datastore;

/**
 * Anonymity level for the current block.
 */
static unsigned int current_anonymity;

/**
 * Type of the current block.
 */
static enum GNUNET_BLOCK_Type current_type;

/**
 * Data of the current block (already encrypted).
 */
static char current_block[GNUNET_SERVER_MAX_MESSAGE_SIZE];

/**
 * Size of the current block.
 */
static size_t current_block_size;

/**
 * Key of the current block.
 */
static GNUNET_HashCode current_key;

/**
 * Task scheduled to receive content from the datastore (with some delay).
 */
static GNUNET_SCHEDULER_TaskIdentifier get_task;


/**
 * Select a peer for transmitting the current block to.
 */
static void
select_peer ()
{
  /* FIXME: select a peer for transmission... */
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param latency reported latency of the connection with 'other'
 * @param distance reported distance (DV) to 'other' 
 */
static void 
connect_notify (void *cls,
		const struct
		GNUNET_PeerIdentity * peer,
		struct GNUNET_TIME_Relative latency,
		uint32_t distance)
{
  /* FIXME: track peer */
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void 
disconnect_notify (void *cls,
		   const struct
		   GNUNET_PeerIdentity * peer)
{
  /* FIXME: untrack peer */
}


/**
 * Ask datastore for more content.
 * @param cls closure
 * @param tc scheduler context 
 */
static void
get_content (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * An iterator over a set of items stored in the datastore.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
static void 
content_processor (void *cls,
		   const GNUNET_HashCode * key,
		   uint32_t size,
		   const void *data,
		   enum GNUNET_BLOCK_Type type,
		   uint32_t priority,
		   uint32_t anonymity,
		   struct GNUNET_TIME_Absolute
		   expiration, uint64_t uid)
{
  if (key != NULL)
    {
      memcpy (current_block, data, size);
      current_block_size = size;
      current_type = type;
      current_anonymity = anonymity;
      current_key = *key;
      return;
    }
  if (current_block_size == 0)
    {
      get_task = GNUNET_SCHEDULER_add_delayed (sched,
					       GNUNET_TIME_UNIT_MINUTES,
					       &get_content,
					       NULL);
      return;
    }
  if (current_type == GNUNET_BLOCK_TYPE_ONDEMAND)
    {	  
      /* FIXME: do on-demand encoding... */
      return;
    }
  select_peer ();
}


/**
 * Ask datastore for more content.
 * @param cls closure
 * @param tc scheduler context 
 */
static void
get_content (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  get_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_DATASTORE_get_random (datastore,
			       &content_processor,
			       NULL,
			       GNUNET_CONSTANTS_SERVICE_TIMEOUT);
}


/**
 * Function called after GNUNET_CORE_connect has succeeded
 * (or failed for good).
 *
 * @param cls closure
 * @param server handle to the server, NULL if we failed
 * @param my_id ID of this peer, NULL if we failed
 * @param publicKey public key of this peer, NULL if we failed
 */
static void
core_init (void *cls,
	   struct GNUNET_CORE_Handle * server,
	   const struct GNUNET_PeerIdentity *
	   my_id,
	   const struct
	   GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *
	   publicKey)
{
  handle = server;
  if (datastore != NULL)
    get_task = GNUNET_SCHEDULER_add_now (sched,
					 &get_content,
					 NULL);
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the core.
 *
 * @param cls unused, NULL
 * @param tc scheduler context
 */
static void
cleaning_task (void *cls, 
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (get_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (sched,
			       get_task);
      get_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (handle != NULL)
    {
      GNUNET_CORE_disconnect (handle);
      handle = NULL;
    }
  if (datastore != NULL)
    {
      GNUNET_DATASTORE_disconnect (datastore, GNUNET_NO);
      datastore = NULL;
    }
  if (stats != NULL)
    {
      GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
      stats = NULL;
    }
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param s the scheduler to use
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle * s,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle * c)
{
  struct GNUNET_CORE_MessageHandler handlers[] =
    {
      { NULL, 0, 0 }
    };
  sched = s;
  cfg = c;
  stats = GNUNET_STATISTICS_create (sched, "topology", cfg);
  handle = GNUNET_CORE_connect (sched,
				cfg,
				GNUNET_TIME_UNIT_FOREVER_REL,
				NULL,
				&core_init,
				&connect_notify,
				&disconnect_notify,
				NULL, GNUNET_NO,
				NULL, GNUNET_NO,
				handlers);
  datastore = GNUNET_DATASTORE_connect (cfg, sched);
  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &cleaning_task, NULL);
  if ( (NULL == handle) ||
       (NULL == datastore) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to `%s' service.\n"),
		  (NULL == handle) ? "core" : "datastore");
      GNUNET_SCHEDULER_shutdown (sched);
      return;
    }
}


/**
 * gnunet-daemon-topology command line options.
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  GNUNET_GETOPT_OPTION_END
};


/**
 * The main function for the topology daemon.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int ret;

  ret = (GNUNET_OK ==
         GNUNET_PROGRAM_run (argc,
                             argv,
                             "migration",
			     _("Content migration for anonymous file-sharing"),
			     options,
			     &run, NULL)) ? 0 : 1;
  return ret;
}

/* end of gnunet-daemon-migration.c */
