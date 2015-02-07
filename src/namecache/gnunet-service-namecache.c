/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file namecache/gnunet-service-namecache.c
 * @brief namecache for the GNUnet naming system
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_namecache_service.h"
#include "gnunet_namecache_plugin.h"
#include "gnunet_signatures.h"
#include "namecache.h"

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)


/**
 * A namecache client
 */
struct NamecacheClient;


/**
 * A namecache client
 */
struct NamecacheClient
{
  /**
   * Next element in the DLL
   */
  struct NamecacheClient *next;

  /**
   * Previous element in the DLL
   */
  struct NamecacheClient *prev;

  /**
   * The client
   */
  struct GNUNET_SERVER_Client *client;

};


/**
 * Configuration handle.
 */
static const struct GNUNET_CONFIGURATION_Handle *GSN_cfg;

/**
 * Database handle
 */
static struct GNUNET_NAMECACHE_PluginFunctions *GSN_database;

/**
 * Name of the database plugin
 */
static char *db_lib_name;

/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *snc;

/**
 * Head of the Client DLL
 */
static struct NamecacheClient *client_head;

/**
 * Tail of the Client DLL
 */
static struct NamecacheClient *client_tail;

/**
 * Notification context shared by all monitors.
 */
static struct GNUNET_SERVER_NotificationContext *monitor_nc;



/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NamecacheClient *nc;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Stopping namecache service\n");
  if (NULL != snc)
  {
    GNUNET_SERVER_notification_context_destroy (snc);
    snc = NULL;
  }
  while (NULL != (nc = client_head))
  {
    GNUNET_CONTAINER_DLL_remove (client_head, client_tail, nc);
    GNUNET_SERVER_client_set_user_context (nc->client, NULL);
    GNUNET_free (nc);
  }
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name, GSN_database));
  GNUNET_free (db_lib_name);
  db_lib_name = NULL;
  if (NULL != monitor_nc)
  {
    GNUNET_SERVER_notification_context_destroy (monitor_nc);
    monitor_nc = NULL;
  }
}


/**
 * Called whenever a client is disconnected.
 * Frees our resources associated with that client.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
client_disconnect_notification (void *cls,
				struct GNUNET_SERVER_Client *client)
{
  struct NamecacheClient *nc;

  if (NULL == client)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Client %p disconnected\n",
	      client);
  if (NULL == (nc = GNUNET_SERVER_client_get_user_context (client, struct NamecacheClient)))
    return;
  GNUNET_CONTAINER_DLL_remove (client_head, client_tail, nc);
  GNUNET_free (nc);
}


/**
 * Add a client to our list of active clients, if it is not yet
 * in there.
 *
 * @param client client to add
 * @return internal namecache client structure for this client
 */
static struct NamecacheClient *
client_lookup (struct GNUNET_SERVER_Client *client)
{
  struct NamecacheClient *nc;

  nc = GNUNET_SERVER_client_get_user_context (client, struct NamecacheClient);
  if (NULL != nc)
    return nc;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Client %p connected\n",
	      client);
  nc = GNUNET_new (struct NamecacheClient);
  nc->client = client;
  GNUNET_SERVER_notification_context_add (snc, client);
  GNUNET_CONTAINER_DLL_insert (client_head, client_tail, nc);
  GNUNET_SERVER_client_set_user_context (client, nc);
  return nc;
}


/**
 * Context for name lookups passed from #handle_lookup_block to
 * #handle_lookup_block_it as closure
 */
struct LookupBlockContext
{
  /**
   * The client to send the response to
   */
  struct NamecacheClient *nc;

  /**
   * Operation id for the name lookup
   */
  uint32_t request_id;

};


/**
 * A #GNUNET_NAMECACHE_BlockCallback for name lookups in #handle_lookup_block
 *
 * @param cls a `struct LookupNameContext *` with information about the request
 * @param block the block
 */
static void
handle_lookup_block_it (void *cls,
			const struct GNUNET_GNSRECORD_Block *block)
{
  struct LookupBlockContext *lnc = cls;
  struct LookupBlockResponseMessage *r;
  size_t esize;

  esize = ntohl (block->purpose.size)
    - sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose)
    - sizeof (struct GNUNET_TIME_AbsoluteNBO);
  r = GNUNET_malloc (sizeof (struct LookupBlockResponseMessage) + esize);
  r->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK_RESPONSE);
  r->gns_header.header.size = htons (sizeof (struct LookupBlockResponseMessage) + esize);
  r->gns_header.r_id = htonl (lnc->request_id);
  r->expire = block->expiration_time;
  r->signature = block->signature;
  r->derived_key = block->derived_key;
  memcpy (&r[1], &block[1], esize);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending `%s' message with expiration time %s\n",
	      "NAMECACHE_LOOKUP_BLOCK_RESPONSE",
              GNUNET_STRINGS_absolute_time_to_string (GNUNET_TIME_absolute_ntoh (r->expire)));
  GNUNET_SERVER_notification_context_unicast (snc,
					      lnc->nc->client,
					      &r->gns_header.header,
					      GNUNET_NO);
  GNUNET_free (r);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK message
 *
 * @param cls unused
 * @param client client sending the message
 * @param message message of type 'struct LookupNameMessage'
 */
static void
handle_lookup_block (void *cls,
                    struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  const struct LookupBlockMessage *ln_msg;
  struct LookupBlockContext lnc;
  struct NamecacheClient *nc;
  struct LookupBlockResponseMessage zir_end;
  int ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received `%s' message\n",
	      "NAMECACHE_LOOKUP_BLOCK");
  nc = client_lookup(client);
  ln_msg = (const struct LookupBlockMessage *) message;
  lnc.request_id = ntohl (ln_msg->gns_header.r_id);
  lnc.nc = nc;
  if (GNUNET_SYSERR ==
      (ret = GSN_database->lookup_block (GSN_database->cls,
					 &ln_msg->query,
					 &handle_lookup_block_it, &lnc)))
  {
    /* internal error (in database plugin); might be best to just hang up on
       plugin rather than to signal that there are 'no' results, which
       might also be false... */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (0 == ret)
  {
    /* no records match at all, generate empty response */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Sending empty `%s' message\n",
		"NAMECACHE_LOOKUP_BLOCK_RESPONSE");
    memset (&zir_end, 0, sizeof (zir_end));
    zir_end.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK_RESPONSE);
    zir_end.gns_header.header.size = htons (sizeof (struct LookupBlockResponseMessage));
    zir_end.gns_header.r_id = ln_msg->gns_header.r_id;
    GNUNET_SERVER_notification_context_unicast (snc,
						client,
						&zir_end.gns_header.header,
						GNUNET_NO);

  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE message
 *
 * @param cls unused
 * @param client client sending the message
 * @param message message of type 'struct BlockCacheMessage'
 */
static void
handle_block_cache (void *cls,
		     struct GNUNET_SERVER_Client *client,
		     const struct GNUNET_MessageHeader *message)
{
  struct NamecacheClient *nc;
  const struct BlockCacheMessage *rp_msg;
  struct BlockCacheResponseMessage rpr_msg;
  struct GNUNET_GNSRECORD_Block *block;
  size_t esize;
  int res;

  nc = client_lookup (client);
  if (ntohs (message->size) < sizeof (struct BlockCacheMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  rp_msg = (const struct BlockCacheMessage *) message;
  esize = ntohs (rp_msg->gns_header.header.size) - sizeof (struct BlockCacheMessage);
  block = GNUNET_malloc (sizeof (struct GNUNET_GNSRECORD_Block) + esize);
  block->signature = rp_msg->signature;
  block->derived_key = rp_msg->derived_key;
  block->purpose.size = htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
			       sizeof (struct GNUNET_TIME_AbsoluteNBO) +
			       esize);
  block->expiration_time = rp_msg->expire;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received `%s' message with expiration time %s\n",
	      "NAMECACHE_BLOCK_CACHE",
              GNUNET_STRINGS_absolute_time_to_string (GNUNET_TIME_absolute_ntoh (block->expiration_time)));
  memcpy (&block[1], &rp_msg[1], esize);
  res = GSN_database->cache_block (GSN_database->cls,
				   block);
  GNUNET_free (block);

  rpr_msg.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE_RESPONSE);
  rpr_msg.gns_header.header.size = htons (sizeof (struct BlockCacheResponseMessage));
  rpr_msg.gns_header.r_id = rp_msg->gns_header.r_id;
  rpr_msg.op_result = htonl (res);
  GNUNET_SERVER_notification_context_unicast (snc,
					      nc->client,
					      &rpr_msg.gns_header.header,
					      GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Process namecache requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_lookup_block, NULL,
     GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK, sizeof (struct LookupBlockMessage)},
    {&handle_block_cache, NULL,
    GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE, 0},
    {NULL, NULL, 0, 0}
  };
  char *database;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting namecache service\n");
  GSN_cfg = cfg;
  monitor_nc = GNUNET_SERVER_notification_context_create (server, 1);

  /* Loading database plugin */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "namecache", "database",
                                             &database))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No database backend configured\n");

  GNUNET_asprintf (&db_lib_name, "libgnunet_plugin_namecache_%s", database);
  GSN_database = GNUNET_PLUGIN_load (db_lib_name, (void *) GSN_cfg);
  GNUNET_free (database);
  if (NULL == GSN_database)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Could not load database backend `%s'\n",
		db_lib_name);
    GNUNET_SCHEDULER_add_now (&cleanup_task, NULL);
    return;
  }

  /* Configuring server handles */
  GNUNET_SERVER_add_handlers (server, handlers);
  snc = GNUNET_SERVER_notification_context_create (server, 16);
  GNUNET_SERVER_disconnect_notify (server,
                                   &client_disconnect_notification,
                                   NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);
}


/**
 * The main function for the template service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "namecache",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-namecache.c */

