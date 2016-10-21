/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013 GNUnet e.V.

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
struct NamecacheClient
{

  /**
   * The client
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * The message queue to talk to @e client.
   */
  struct GNUNET_MQ_Handle *mq;
  
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
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
cleanup_task (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Stopping namecache service\n");
  GNUNET_break (NULL ==
		GNUNET_PLUGIN_unload (db_lib_name,
				      GSN_database));
  GNUNET_free (db_lib_name);
  db_lib_name = NULL;
}


/**
 * Called whenever a client is disconnected.
 * Frees our resources associated with that client.
 *
 * @param cls closure
 * @param client identification of the client
 * @param app_ctx the `struct NamecacheClient` for this @a client
 */
static void
client_disconnect_cb (void *cls,
		      struct GNUNET_SERVICE_Client *client,
		      void *app_ctx)
{
  struct NamecacheClient *nc = app_ctx;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Client %p disconnected\n",
	      client);
  GNUNET_free (nc);
}


/**
 * Add a client to our list of active clients.
 *
 * @param cls NULL
 * @param client client to add
 * @param mq queue to talk to @a client
 * @return internal namecache client structure for this client
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *client,
		   struct GNUNET_MQ_Handle *mq)
{
  struct NamecacheClient *nc;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Client %p connected\n",
	      client);
  nc = GNUNET_new (struct NamecacheClient);
  nc->client = client;
  nc->mq = mq;
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
  struct GNUNET_MQ_Envelope *env;
  struct LookupBlockResponseMessage *r;
  size_t esize;

  esize = ntohl (block->purpose.size)
    - sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose)
    - sizeof (struct GNUNET_TIME_AbsoluteNBO);
  env = GNUNET_MQ_msg_extra (r,
			     esize,
			     GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK_RESPONSE);
  r->gns_header.r_id = htonl (lnc->request_id);
  r->expire = block->expiration_time;
  r->signature = block->signature;
  r->derived_key = block->derived_key;
  GNUNET_memcpy (&r[1],
		 &block[1],
		 esize);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending NAMECACHE_LOOKUP_BLOCK_RESPONSE message with expiration time %s\n",
              GNUNET_STRINGS_absolute_time_to_string (GNUNET_TIME_absolute_ntoh (r->expire)));
  GNUNET_MQ_send (lnc->nc->mq,
		  env);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK message
 *
 * @param cls a `struct NamecacheClient *`
 * @param the inbound message
 */
static void
handle_lookup_block (void *cls,
		     const struct LookupBlockMessage *ln_msg)
{
  struct NamecacheClient *nc = cls;
  struct GNUNET_MQ_Envelope *env;
  struct LookupBlockContext lnc;
  struct LookupBlockResponseMessage *zir_end;
  int ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received NAMECACHE_LOOKUP_BLOCK message\n");
  
  lnc.request_id = ntohl (ln_msg->gns_header.r_id);
  lnc.nc = nc;
  if (GNUNET_SYSERR ==
      (ret = GSN_database->lookup_block (GSN_database->cls,
					 &ln_msg->query,
					 &handle_lookup_block_it,
					 &lnc)))
  {
    /* internal error (in database plugin); might be best to just hang up on
       plugin rather than to signal that there are 'no' results, which
       might also be false... */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  if (0 == ret)
  {
    /* no records match at all, generate empty response */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Sending empty NAMECACHE_LOOKUP_BLOCK_RESPONSE message\n");
    env = GNUNET_MQ_msg (zir_end,
			 GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK_RESPONSE);
    zir_end->gns_header.r_id = ln_msg->gns_header.r_id;
    GNUNET_MQ_send (nc->mq,
		    env);
  }
  GNUNET_SERVICE_client_continue (nc->client);
}


/**
 * Check a #GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE message
 *
 * @param cls our `struct NamecacheClient`
 * @param rp_msg message to process
 * @return #GNUNET_OK (always fine)
 */
static int
check_block_cache (void *cls,
		   const struct BlockCacheMessage *rp_msg)
{
  return GNUNET_OK;
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE message
 *
 * @param cls our `struct NamecacheClient`
 * @param rp_msg message to process
 */
static void
handle_block_cache (void *cls,
		    const struct BlockCacheMessage *rp_msg)
{
  struct NamecacheClient *nc = cls;
  struct GNUNET_MQ_Envelope *env;
  struct BlockCacheResponseMessage *rpr_msg;
  struct GNUNET_GNSRECORD_Block *block;
  size_t esize;
  int res;

  esize = ntohs (rp_msg->gns_header.header.size) - sizeof (struct BlockCacheMessage);
  block = GNUNET_malloc (sizeof (struct GNUNET_GNSRECORD_Block) + esize);
  block->signature = rp_msg->signature;
  block->derived_key = rp_msg->derived_key;
  block->purpose.size = htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
			       sizeof (struct GNUNET_TIME_AbsoluteNBO) +
			       esize);
  block->expiration_time = rp_msg->expire;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received NAMECACHE_BLOCK_CACHE message with expiration time %s\n",
              GNUNET_STRINGS_absolute_time_to_string (GNUNET_TIME_absolute_ntoh (block->expiration_time)));
  GNUNET_memcpy (&block[1],
		 &rp_msg[1],
		 esize);
  res = GSN_database->cache_block (GSN_database->cls,
				   block);
  GNUNET_free (block);
  env = GNUNET_MQ_msg (rpr_msg,
		       GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE_RESPONSE);
  rpr_msg->gns_header.r_id = rp_msg->gns_header.r_id;
  rpr_msg->op_result = htonl (res);
  GNUNET_MQ_send (nc->mq,
		  env);
  GNUNET_SERVICE_client_continue (nc->client);
}


/**
 * Process namecache requests.
 *
 * @param cls closure
 * @param cfg configuration to use
 * @param service the initialized service
 */
static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_SERVICE_Handle *service)
{
  char *database;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting namecache service\n");
  GSN_cfg = cfg;

  /* Loading database plugin */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
					     "namecache",
					     "database",
                                             &database))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"No database backend configured\n");

  GNUNET_asprintf (&db_lib_name,
		   "libgnunet_plugin_namecache_%s",
		   database);
  GSN_database = GNUNET_PLUGIN_load (db_lib_name,
				     (void *) GSN_cfg);
  GNUNET_free (database);
  if (NULL == GSN_database)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Could not load database backend `%s'\n",
		db_lib_name);
    GNUNET_SCHEDULER_add_now (&cleanup_task,
			      NULL);
    return;
  }

  /* Configuring server handles */
  GNUNET_SCHEDULER_add_shutdown (&cleanup_task,
				 NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("namecache",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_fixed_size (lookup_block,
			  GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK,
			  struct LookupBlockMessage,
			  NULL),
 GNUNET_MQ_hd_var_size (block_cache,
			GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE,
			struct BlockCacheMessage,
			NULL),
 GNUNET_MQ_handler_end ());


/* end of gnunet-service-namecache.c */
