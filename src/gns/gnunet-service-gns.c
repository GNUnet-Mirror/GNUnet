/*
     This file is part of GNUnet.
     Copyright (C) 2011-2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
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
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_gns_service.h"
#include "gnunet_statistics_service.h"
#include "gns.h"
#include "gnunet-service-gns_resolver.h"
#include "gnunet-service-gns_interceptor.h"
#include "gnunet_protocols.h"


/**
 * GnsClient prototype
 */
struct GnsClient;

/**
 * Handle to a lookup operation from client via API.
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


/**
 * Information we track per connected client.
 */
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
 * Representation of a TLD, mapping the respective TLD string
 * (i.e. ".gnu") to the respective public key of the zone.
 */
struct GNS_TopLevelDomain
{

  /**
   * Kept in a DLL, as there are unlikely enough of these to
   * warrant a hash map.
   */
  struct GNS_TopLevelDomain *next;

  /**
   * Kept in a DLL, as there are unlikely enough of these to
   * warrant a hash map.
   */
  struct GNS_TopLevelDomain *prev;

  /**
   * Public key associated with the @a tld.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

  /**
   * Top-level domain as a string, including leading ".".
   */
  char *tld;

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
 * Head of DLL of TLDs we map to GNS zones.
 */
static struct GNS_TopLevelDomain *tld_head;

/**
 * Tail of DLL of TLDs we map to GNS zones.
 */
static struct GNS_TopLevelDomain *tld_tail;


/**
 * Find GNS zone belonging to TLD @a tld.
 *
 * @param tld_str top-level domain to look up
 * @param[out] pkey public key to set
 * @return #GNUNET_YES if @a tld was found #GNUNET_NO if not
 */
int
GNS_find_tld (const char *tld_str,
              struct GNUNET_CRYPTO_EcdsaPublicKey *pkey)
{
  if ('\0' == *tld_str)
    return GNUNET_NO;
  for (struct GNS_TopLevelDomain *tld = tld_head;
       NULL != tld;
       tld = tld->next)
  {
    if (0 == strcasecmp (tld_str,
                         tld->tld))
    {
      *pkey = tld->pkey;
      return GNUNET_YES;
    }
  }
  if (GNUNET_OK ==
      GNUNET_GNSRECORD_zkey_to_pkey (tld_str + 1,
                                     pkey))
    return GNUNET_YES; /* TLD string *was* the public key */
  return GNUNET_NO;
}


/**
 * Obtain the TLD of the given @a name.
 *
 * @param name a name
 * @return the part of @a name after the last ".",
 *         or @a name if @a name does not contain a "."
 */
const char *
GNS_get_tld (const char *name)
{
  const char *tld;

  tld = strrchr (name,
                 (unsigned char) '.');
  if (NULL == tld)
    tld = name;
  else
    tld++; /* skip the '.' */
  return tld;
}


/**
 * Task run during shutdown.
 *
 * @param cls unused, NULL
 */
static void
shutdown_task (void *cls)
{
  struct GNS_TopLevelDomain *tld;

  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Shutting down!\n");
  GNS_interceptor_done ();
  GNS_resolver_done ();
  if (NULL != statistics)
  {
    GNUNET_STATISTICS_destroy (statistics,
                               GNUNET_NO);
    statistics = NULL;
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
  while (NULL != (tld = tld_head))
  {
    GNUNET_CONTAINER_DLL_remove (tld_head,
                                 tld_tail,
                                 tld);
    GNUNET_free (tld->tld);
    GNUNET_free (tld);
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

  (void) cls;
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

  (void) cls;
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
send_lookup_response (void *cls,
                      uint32_t rd_count,
                      const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ClientLookupHandle *clh = cls;
  struct GnsClient *gc = clh->gc;
  struct GNUNET_MQ_Envelope *env;
  struct LookupResultMessage *rmsg;
  ssize_t len;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending LOOKUP_RESULT message with %u results\n",
              (unsigned int) rd_count);
  len = GNUNET_GNSRECORD_records_get_size (rd_count,
                                           rd);
  if (len < 0)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (gc->client);
    return;
  }
  if (len > UINT16_MAX - sizeof (*rmsg))
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (gc->client);
    return;
  }
  env = GNUNET_MQ_msg_extra (rmsg,
                             len,
                             GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT);
  rmsg->id = clh->request_id;
  rmsg->rd_count = htonl (rd_count);
  GNUNET_assert (len ==
                 GNUNET_GNSRECORD_records_serialize (rd_count,
                                                     rd,
                                                     len,
                                                     (char*) &rmsg[1]));
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (gc->client),
                  env);
  GNUNET_CONTAINER_DLL_remove (gc->clh_head,
                               gc->clh_tail,
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

  (void) cls;
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

  GNUNET_SERVICE_client_continue (gc->client);
  utf_in = (const char *) &sh_msg[1];
  GNUNET_STRINGS_utf8_tolower (utf_in,
                               nameptr);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received LOOKUP `%s' message\n",
              name);
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
    send_lookup_response (clh,
                          0,
                          NULL);
    return;
  }
  if ( (GNUNET_DNSPARSER_TYPE_AAAA == ntohl (sh_msg->type)) &&
       (GNUNET_OK != v6_enabled) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "LOOKUP: Query for AAAA record but AF_INET6 not supported!");
    send_lookup_response (clh,
                          0,
                          NULL);
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
 * Reads the configuration and populates TLDs
 *
 * @param cls unused
 * @param section name of section in config, always "gns"
 * @param option name of the option, TLDs start with "."
 * @param value value for the option, public key for TLDs
 */
static void
read_service_conf (void *cls,
                   const char *section,
                   const char *option,
                   const char *value)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pk;
  struct GNS_TopLevelDomain *tld;

  (void) cls;
  (void) section;
  if (option[0] != '.')
    return;
  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (value,
                                     strlen (value),
                                     &pk,
                                     sizeof (pk)))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               section,
                               option,
                               _("Properly base32-encoded public key required"));
    return;
  }
  tld = GNUNET_new (struct GNS_TopLevelDomain);
  tld->tld = GNUNET_strdup (&option[1]);
  tld->pkey = pk;
  GNUNET_CONTAINER_DLL_insert (tld_head,
                               tld_tail,
                               tld);
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

  GNUNET_CONFIGURATION_iterate_section_values (c,
                                               "gns",
                                               &read_service_conf,
                                               NULL);
  v6_enabled = GNUNET_NETWORK_test_pf (PF_INET6);
  v4_enabled = GNUNET_NETWORK_test_pf (PF_INET);
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
    GNUNET_SCHEDULER_add_now (&shutdown_task,
                              NULL);
    return;
  }
  GNS_resolver_init (namecache_handle,
                     dht_handle,
                     c,
                     max_parallel_bg_queries);
  if ( (GNUNET_YES ==
        GNUNET_CONFIGURATION_get_value_yesno (c,
                                              "gns",
                                              "INTERCEPT_DNS")) &&
       (GNUNET_SYSERR ==
        GNS_interceptor_init (c)) )
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_add_now (&shutdown_task,
                              NULL);
    return;
  }
  statistics = GNUNET_STATISTICS_create ("gns",
                                         c);
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
