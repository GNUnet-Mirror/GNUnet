/*
     This file is part of GNUnet.
     Copyright (C) 2011-2013 GNUnet e.V.

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
 * @file gns/gnunet-service-gns.c
 * @brief GNU Name System (main service)
 * @author Martin Schanzenbach
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dns_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_namecache_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_gns_service.h"
#include "gnunet_statistics_service.h"
#include "gns.h"
#include "gnunet-service-gns_resolver.h"
#include "gnunet-service-gns_reverser.h"
#include "gnunet-service-gns_shorten.h"
#include "gnunet-service-gns_interceptor.h"
#include "gnunet_protocols.h"


/**
 * GnsClient prototype
 */
struct GnsClient;

/**
 * Handle to a lookup operation from api
 */
struct ClientLookupHandle
{

  /**
   * We keep these in a DLL.
   */
  struct ClientLookupHandle *next;

  /**
   * We keep these in a DLL.
   */
  struct ClientLookupHandle *prev;

  /**
   * Client handle
   */
  struct GnsClient *gc;

  /**
   * Active handle for the lookup.
   */
  struct GNS_ResolverHandle *lookup;

  /**
   * request id
   */
  uint32_t request_id;

};

struct GnsClient
{
  /**
   * The client
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * The MQ
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of the DLL.
   */
  struct ClientLookupHandle *clh_head;

  /**
   * Tail of the DLL.
   */
  struct ClientLookupHandle *clh_tail;
};


/**
 * Our handle to the DHT
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Our handle to the namecache service
 */
static struct GNUNET_NAMECACHE_Handle *namecache_handle;

/**
 * Our handle to the namestore service
 */
static struct GNUNET_NAMESTORE_Handle *namestore_handle;

/**
 * Our handle to the identity service
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * Our handle to the identity operation to find the master zone
 * for intercepted queries.
 */
static struct GNUNET_IDENTITY_Operation *identity_op;

/**
 * #GNUNET_YES if ipv6 is supported
 */
static int v6_enabled;

/**
 * #GNUNET_YES if ipv4 is supported
 */
static int v4_enabled;

/**
 * Handle to the statistics service
 */
static struct GNUNET_STATISTICS_Handle *statistics;


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Shutting down!\n");
  GNS_interceptor_done ();
  if (NULL != identity_op)
  {
    GNUNET_IDENTITY_cancel (identity_op);
    identity_op = NULL;
  }
  if (NULL != identity_handle)
  {
    GNUNET_IDENTITY_disconnect (identity_handle);
    identity_handle = NULL;
  }
  GNS_resolver_done ();
  if (NULL != statistics)
  {
    GNUNET_STATISTICS_destroy (statistics,
                               GNUNET_NO);
    statistics = NULL;
  }
  if (NULL != namestore_handle)
  {
    GNUNET_NAMESTORE_disconnect (namestore_handle);
    namestore_handle = NULL;
  }
  if (NULL != namecache_handle)
  {
    GNUNET_NAMECACHE_disconnect (namecache_handle);
    namecache_handle = NULL;
  }
  if (NULL != dht_handle)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }
}


/**
 * Called whenever a client is disconnected.
 *
 * @param cls closure
 * @param client identification of the client
 * @param app_ctx @a client
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *app_ctx)
{
  struct ClientLookupHandle *clh;
  struct GnsClient *gc = app_ctx;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p disconnected\n",
              client);
  while (NULL != (clh = gc->clh_head))
  {
    if (NULL != clh->lookup)
      GNS_resolver_lookup_cancel (clh->lookup);
    GNUNET_CONTAINER_DLL_remove (gc->clh_head,
                                 gc->clh_tail,
                                 clh);
    GNUNET_free (clh);
  }

  GNUNET_free (gc);
}


/**
 * Add a client to our list of active clients.
 *
 * @param cls NULL
 * @param client client to add
 * @param mq message queue for @a client
 * @return internal namestore client structure for this client
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  struct GnsClient *gc;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p connected\n",
              client);
  gc = GNUNET_new (struct GnsClient);
  gc->client = client;
  gc->mq = mq;
  return gc;
}


/**
 * Reply to client with the result from our lookup.
 *
 * @param cls the closure (our client lookup handle)
 * @param rd_count the number of records in @a rd
 * @param rd the record data
 */
static void
send_lookup_response (void* cls,
                      uint32_t rd_count,
                      const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ClientLookupHandle *clh = cls;
  struct GNUNET_MQ_Envelope *env;
  struct LookupResultMessage *rmsg;
  size_t len;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending LOOKUP_RESULT message with %u results\n",
              (unsigned int) rd_count);

  len = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
  env = GNUNET_MQ_msg_extra (rmsg,
                             len,
                             GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT);
  rmsg->id = clh->request_id;
  rmsg->rd_count = htonl (rd_count);
  GNUNET_GNSRECORD_records_serialize (rd_count, rd, len,
                                      (char*) &rmsg[1]);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq(clh->gc->client),
                  env);
  GNUNET_CONTAINER_DLL_remove (clh->gc->clh_head,
                               clh->gc->clh_tail,
                               clh);
  GNUNET_free (clh);
  GNUNET_STATISTICS_update (statistics,
                            "Completed lookups", 1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (statistics,
                            "Records resolved",
                            rd_count,
                            GNUNET_NO);
}


/**
 * Checks a #GNUNET_MESSAGE_TYPE_GNS_LOOKUP message
 *
 * @param cls client sending the message
 * @param l_msg message of type `struct LookupMessage`
 * @return #GNUNET_OK if @a l_msg is well-formed
 */
static int
check_lookup (void *cls,
              const struct LookupMessage *l_msg)
{
  size_t msg_size;
  const char* name;

  msg_size = ntohs (l_msg->header.size);
  if (msg_size < sizeof (struct LookupMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name = (const char *) &l_msg[1];
  if ( ('\0' != name[msg_size - sizeof (struct LookupMessage) - 1]) ||
       (strlen (name) > GNUNET_DNSPARSER_MAX_NAME_LENGTH) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle lookup requests from client
 *
 * @param cls the closure
 * @param client the client
 * @param message the message
 */
static void
handle_lookup (void *cls,
               const struct LookupMessage *sh_msg)
{
  struct GnsClient *gc = cls;
  char name[GNUNET_DNSPARSER_MAX_NAME_LENGTH + 1];
  struct ClientLookupHandle *clh;
  char *nameptr = name;
  const char *utf_in;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received LOOKUP message\n");
  GNUNET_SERVICE_client_continue (gc->client);
  utf_in = (const char *) &sh_msg[1];
  GNUNET_STRINGS_utf8_tolower (utf_in, nameptr);

  clh = GNUNET_new (struct ClientLookupHandle);
  GNUNET_CONTAINER_DLL_insert (gc->clh_head,
                               gc->clh_tail,
                               clh);
  clh->gc = gc;
  clh->request_id = sh_msg->id;
  if ( (GNUNET_DNSPARSER_TYPE_A == ntohl (sh_msg->type)) &&
       (GNUNET_OK != v4_enabled) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "LOOKUP: Query for A record but AF_INET not supported!");
    send_lookup_response (clh, 0, NULL);
    return;
  }
  if ( (GNUNET_DNSPARSER_TYPE_AAAA == ntohl (sh_msg->type)) &&
       (GNUNET_OK != v6_enabled) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "LOOKUP: Query for AAAA record but AF_INET6 not supported!");
    send_lookup_response (clh, 0, NULL);
    return;
  }
  clh->lookup = GNS_resolver_lookup (&sh_msg->zone,
                                     ntohl (sh_msg->type),
                                     name,
                                     (enum GNUNET_GNS_LocalOptions) ntohs (sh_msg->options),
                                     &send_lookup_response, clh);
  GNUNET_STATISTICS_update (statistics,
                            "Lookup attempts",
                            1, GNUNET_NO);
}


/**
 * Method called to inform about the ego to be used for the master zone
 * for DNS interceptions.
 *
 * This function is only called ONCE, and 'NULL' being passed in
 * @a ego does indicate that interception is not configured.
 * If @a ego is non-NULL, we should start to intercept DNS queries
 * and resolve ".gnu" queries using the given ego as the master zone.
 *
 * @param cls closure, our `const struct GNUNET_CONFIGURATION_Handle *c`
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_intercept_cb (void *cls,
                       struct GNUNET_IDENTITY_Ego *ego,
                       void **ctx,
                       const char *name)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_CRYPTO_EcdsaPublicKey dns_root;

  identity_op = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Looking for gns-intercept ego\n");
  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("No ego configured for `%s`\n"),
                "gns-intercept");

    return;
  }
  GNUNET_IDENTITY_ego_get_public_key (ego,
                                      &dns_root);
  if (GNUNET_SYSERR ==
      GNS_interceptor_init (&dns_root,
                            cfg))
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_add_now (&shutdown_task,
                              NULL);
    return;
  }
}


/**
 * Process GNS requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  unsigned long long max_parallel_bg_queries = 16;

  v6_enabled = GNUNET_NETWORK_test_pf (PF_INET6);
  v4_enabled = GNUNET_NETWORK_test_pf (PF_INET);
  namestore_handle = GNUNET_NAMESTORE_connect (c);
  if (NULL == namestore_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to the namestore!\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
 namecache_handle = GNUNET_NAMECACHE_connect (c);
  if (NULL == namecache_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to the namecache!\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (c,
					     "gns",
                                             "MAX_PARALLEL_BACKGROUND_QUERIES",
                                             &max_parallel_bg_queries))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Number of allowed parallel background queries: %llu\n",
                max_parallel_bg_queries);
  }
  dht_handle = GNUNET_DHT_connect (c,
                                   (unsigned int) max_parallel_bg_queries);
  if (NULL == dht_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not connect to DHT!\n"));
    GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
    return;
  }

  identity_handle = GNUNET_IDENTITY_connect (c,
                                             NULL,
                                             NULL);
  if (NULL == identity_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Could not connect to identity service!\n");
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Looking for gns-intercept ego\n");
    identity_op = GNUNET_IDENTITY_get (identity_handle,
                                       "gns-intercept",
                                       &identity_intercept_cb,
                                       (void *) c);
  }
  GNS_resolver_init (namecache_handle,
                     dht_handle,
                     c,
                     max_parallel_bg_queries);
  statistics = GNUNET_STATISTICS_create ("gns", c);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("gns",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (lookup,
                        GNUNET_MESSAGE_TYPE_GNS_LOOKUP,
                        struct LookupMessage,
                        NULL),
 GNUNET_MQ_handler_end());


/* end of gnunet-service-gns.c */
