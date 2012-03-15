/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 *
 * TODO:
 *    - Write xquery and block plugin
 *    - The smaller FIXME issues all around
 *
 * @file gns/gnunet-service-gns.c
 * @brief GNUnet GNS service
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_dns_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_gns_service.h"
#include "block_gns.h"
#include "gns.h"
#include "gnunet-service-gns_resolver.h"
#include "gnunet-service-gns_interceptor.h"

/* FIXME move to proper header in include */
#define GNUNET_MESSAGE_TYPE_GNS_LOOKUP 23
#define GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT 24
#define GNUNET_MESSAGE_TYPE_GNS_SHORTEN 25
#define GNUNET_MESSAGE_TYPE_GNS_SHORTEN_RESULT 26
#define GNUNET_MESSAGE_TYPE_GNS_GET_AUTH 27
#define GNUNET_MESSAGE_TYPE_GNS_GET_AUTH_RESULT 28


/**
 * Handle to a shorten operation from api
 */
struct ClientShortenHandle
{
  /* the requesting client that */
  struct GNUNET_SERVER_Client *client;

  /* request id */
  uint64_t unique_id;

  /* request type */
  enum GNUNET_GNS_RecordType type;

  /* name to shorten */
  char* name;

};


/**
 * Handle to a get auhtority operation from api
 */
struct ClientGetAuthHandle
{
  /* the requesting client that */
  struct GNUNET_SERVER_Client *client;

  /* request id */
  uint64_t unique_id;

  /* name to lookup authority */
  char* name;

};


/**
 * Handle to a lookup operation from api
 */
struct ClientLookupHandle
{
  /* the requesting client that */
  struct GNUNET_SERVER_Client *client;

  /* request id */
  uint64_t unique_id;

  /* request type */
  enum GNUNET_GNS_RecordType type;

  /* the name to look up */
  char* name; //Needed?
};

/**
 * Our handle to the DHT
 */
struct GNUNET_DHT_Handle *dht_handle;

/**
 * Our zone's private key
 */
struct GNUNET_CRYPTO_RsaPrivateKey *zone_key;

/**
 * Our handle to the namestore service
 * FIXME maybe need a second handle for iteration
 */
struct GNUNET_NAMESTORE_Handle *namestore_handle;

/**
 * Handle to iterate over our authoritative zone in namestore
 */
struct GNUNET_NAMESTORE_ZoneIterator *namestore_iter;

/**
 * The configuration the GNS service is running with
 */
const struct GNUNET_CONFIGURATION_Handle *GNS_cfg;

/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Our zone hash
 */
GNUNET_HashCode zone_hash;

/**
 * Useful for zone update for DHT put
 */
static int num_public_records =  3600;

/* dht update interval FIXME define? */
static struct GNUNET_TIME_Relative dht_update_interval;

/* zone update task */
GNUNET_SCHEDULER_TaskIdentifier zone_update_taskid = GNUNET_SCHEDULER_NO_TASK;

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Shutting down!");
  /* Kill zone task for it may make the scheduler hang */
  if (zone_update_taskid)
    GNUNET_SCHEDULER_cancel(zone_update_taskid);
  
  GNUNET_SERVER_notification_context_destroy (nc);
  
  gns_interceptor_stop();

  GNUNET_NAMESTORE_disconnect(namestore_handle, 1);
  GNUNET_DHT_disconnect(dht_handle);
}


/**
 * Method called periodicattluy that triggers
 * iteration over root zone
 *
 * @param cls closure
 * @param tc task context
 */
static void
update_zone_dht_next(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_NAMESTORE_zone_iterator_next(namestore_iter);
}

/**
 * Continuation for DHT put
 *
 * @param cls closure
 * @param tc task context
 */
static void
record_dht_put(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "put request transmitted\n");
}

/* prototype */
static void
update_zone_dht_start(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Function used to put all records successively into the DHT.
 *
 * @param cls the closure (NULL)
 * @param key the public key of the authority (ours)
 * @param expiration lifetime of the namestore entry
 * @param name the name of the records
 * @param rd_count the number of records in data
 * @param rd the record data
 * @param signature the signature for the record data
 */
static void
put_gns_record(void *cls,
                const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                struct GNUNET_TIME_Absolute expiration,
                const char *name,
                unsigned int rd_count,
                const struct GNUNET_NAMESTORE_RecordData *rd,
                const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  
  struct GNSNameRecordBlock *nrb;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode xor_hash;
  struct GNUNET_CRYPTO_HashAsciiEncoded xor_hash_string;
  uint32_t rd_payload_length;
  char* nrb_data = NULL;
  size_t namelen;

  /* we're done */
  if (NULL == name)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Zone iteration finished. Rescheduling put in %ds\n",
               GNUNET_GNS_DHT_MAX_UPDATE_INTERVAL);
    zone_update_taskid = GNUNET_SCHEDULER_add_delayed (
                                        GNUNET_TIME_relative_multiply(
                                            GNUNET_TIME_UNIT_SECONDS,
                                            GNUNET_GNS_DHT_MAX_UPDATE_INTERVAL
                                            ),
                                            &update_zone_dht_start,
                                            NULL);
    return;
  }
  
  namelen = strlen(name) + 1;
  
  if (signature == NULL)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "No signature for %s record data provided! Skipping...\n",
               name);
    zone_update_taskid = GNUNET_SCHEDULER_add_now (&update_zone_dht_next,
                                                   NULL);
    return;

  }
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Putting records for %s into the DHT\n", name);
  
  rd_payload_length = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  
  nrb = GNUNET_malloc(rd_payload_length + namelen
                      + sizeof(struct GNSNameRecordBlock));
  
  nrb->signature = *signature;
  
  nrb->public_key = *key;

  nrb->rd_count = htonl(rd_count);
  
  memcpy(&nrb[1], name, namelen);

  nrb_data = (char*)&nrb[1];
  nrb_data += namelen;

  rd_payload_length += sizeof(struct GNSNameRecordBlock) + namelen;

  if (-1 == GNUNET_NAMESTORE_records_serialize (rd_count,
                                                rd,
                                                rd_payload_length,
                                                nrb_data))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Record serialization failed! Skipping...\n");
    GNUNET_free(nrb);
    zone_update_taskid = GNUNET_SCHEDULER_add_now (&update_zone_dht_next,
                                                   NULL);
    return;
  }


  /*
   * calculate DHT key: H(name) xor H(pubkey)
   */
  GNUNET_CRYPTO_hash(name, strlen(name), &name_hash);
  GNUNET_CRYPTO_hash_xor(&zone_hash, &name_hash, &xor_hash);
  GNUNET_CRYPTO_hash_to_enc (&xor_hash, &xor_hash_string);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "putting records for %s under key: %s with size %d\n",
             name, (char*)&xor_hash_string, rd_payload_length);

  GNUNET_DHT_put (dht_handle, &xor_hash,
                  DHT_GNS_REPLICATION_LEVEL,
                  GNUNET_DHT_RO_NONE,
                  GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                  rd_payload_length,
                  (char*)nrb,
                  expiration,
                  DHT_OPERATION_TIMEOUT,
                  &record_dht_put,
                  NULL); //cls for cont
  
  num_public_records++;

  /**
   * Reschedule periodic put
   */
  zone_update_taskid = GNUNET_SCHEDULER_add_delayed (dht_update_interval,
                                &update_zone_dht_next,
                                NULL);

  GNUNET_free(nrb);

}

/**
 * Periodically iterate over our zone and store everything in dht
 *
 * @param cls NULL
 * @param tc task context
 */
static void
update_zone_dht_start(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Scheduling DHT zone update!\n");
  if (0 == num_public_records)
  {
    dht_update_interval = GNUNET_TIME_relative_multiply(
                                            GNUNET_TIME_UNIT_SECONDS,
                                            GNUNET_GNS_DHT_MAX_UPDATE_INTERVAL);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "No records in db. Adjusted DHT update interval to %ds\n",
               GNUNET_GNS_DHT_MAX_UPDATE_INTERVAL);
  }
  else
  {
    
    dht_update_interval = GNUNET_TIME_relative_multiply(
                                                      GNUNET_TIME_UNIT_SECONDS,
                                                     (3600/num_public_records));
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Adjusted DHT update interval to %ds!\n",
               (3600/num_public_records));
  }

  /* start counting again */
  num_public_records = 0;
  namestore_iter = GNUNET_NAMESTORE_zone_iteration_start (namestore_handle,
                                                 &zone_hash,
                                                 GNUNET_NAMESTORE_RF_AUTHORITY,
                                                 GNUNET_NAMESTORE_RF_PRIVATE,
                                                 &put_gns_record,
                                                 NULL);
}


/* END DHT ZONE PROPAGATION */

/**
 * Send shorten response back to client
 * 
 * @param name the shortened name result or NULL if cannot be shortened
 * @param csh the handle to the shorten request
 */
static void
send_shorten_response(void* cls, const char* name)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message with %s\n",
              "SHORTEN_RESULT", name);
  struct GNUNET_GNS_ClientShortenResultMessage *rmsg;
  struct ClientShortenHandle *csh = (struct ClientShortenHandle *)cls;
  
  if (name == NULL)
  {
    name = "";
  }

  rmsg = GNUNET_malloc(sizeof(struct GNUNET_GNS_ClientShortenResultMessage)
                       + strlen(name) + 1);
  
  rmsg->id = csh->unique_id;
  rmsg->header.type = htons(GNUNET_MESSAGE_TYPE_GNS_SHORTEN_RESULT);
  rmsg->header.size = 
    htons(sizeof(struct GNUNET_GNS_ClientShortenResultMessage) +
          strlen(name) + 1);

  strcpy((char*)&rmsg[1], name);

  GNUNET_SERVER_notification_context_unicast (nc, csh->client,
                              (const struct GNUNET_MessageHeader *) rmsg,
                              GNUNET_NO);
  GNUNET_SERVER_receive_done (csh->client, GNUNET_OK);
  
  GNUNET_free(rmsg);
  GNUNET_free_non_null(csh->name);
  GNUNET_free(csh);

}

/**
 * Handle a shorten message from the api
 *
 * @param cls the closure
 * @param client the client
 * @param message the message
 */
static void handle_shorten(void *cls,
                           struct GNUNET_SERVER_Client * client,
                           const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "SHORTEN");

  size_t msg_size = 0;
  struct ClientShortenHandle *csh;
  const char* name;

  if (ntohs (message->size) < sizeof (struct GNUNET_GNS_ClientShortenMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  GNUNET_SERVER_notification_context_add (nc, client);

  struct GNUNET_GNS_ClientShortenMessage *sh_msg =
    (struct GNUNET_GNS_ClientShortenMessage *) message;
  
  msg_size = ntohs(message->size);

  if (msg_size > GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  csh = GNUNET_malloc(sizeof(struct ClientShortenHandle));
  csh->client = client;
  csh->unique_id = sh_msg->id;
  
  name = (char*)&sh_msg[1];

  if (strlen (name) < strlen(GNUNET_GNS_TLD)) {
    csh->name = NULL;
    send_shorten_response(csh, name);
    return;
  }
  
  if (strcmp(name+strlen(name)-strlen(GNUNET_GNS_TLD),
             GNUNET_GNS_TLD) != 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s is not our domain. Returning\n", name);
    csh->name = NULL;
    send_shorten_response(csh, name);
    return;
  }
  
  csh->name = GNUNET_malloc(strlen(name)
                            - strlen(GNUNET_GNS_TLD) + 1);
  memset(csh->name, 0,
         strlen(name)-strlen(GNUNET_GNS_TLD) + 1);
  memcpy(csh->name, name,
         strlen(name)-strlen(GNUNET_GNS_TLD));

  /* Start shortening */
  gns_resolver_shorten_name(zone_hash, name, &send_shorten_response, csh);
}


/**
 * Send get authority response back to client
 * 
 * @param name the shortened name result or NULL if cannot be shortened
 * @param cah the handle to the get authority request
 */
static void
send_get_auth_response(void *cls, const char* name)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message with %s\n",
              "GET_AUTH_RESULT", name);
  struct GNUNET_GNS_ClientGetAuthResultMessage *rmsg;
  struct ClientGetAuthHandle *cah = (struct ClientGetAuthHandle *)cls;
  
  if (name == NULL)
  {
    name = "";
  }

  rmsg = GNUNET_malloc(sizeof(struct GNUNET_GNS_ClientGetAuthResultMessage)
                       + strlen(name) + 1);
  
  rmsg->id = cah->unique_id;
  rmsg->header.type = htons(GNUNET_MESSAGE_TYPE_GNS_GET_AUTH_RESULT);
  rmsg->header.size = 
    htons(sizeof(struct GNUNET_GNS_ClientGetAuthResultMessage) +
          strlen(name) + 1);

  strcpy((char*)&rmsg[1], name);

  GNUNET_SERVER_notification_context_unicast (nc, cah->client,
                              (const struct GNUNET_MessageHeader *) rmsg,
                              GNUNET_NO);
  GNUNET_SERVER_receive_done (cah->client, GNUNET_OK);
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up handles...\n");

  GNUNET_free(rmsg);
  GNUNET_free_non_null(cah->name);
  GNUNET_free(cah);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "done.\n");

}


/**
 * Handle a get authority message from the api
 *
 * @param cls the closure
 * @param client the client
 * @param message the message
 */
static void handle_get_authority(void *cls,
                           struct GNUNET_SERVER_Client * client,
                           const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "GET_AUTH");

  size_t msg_size = 0;
  struct ClientGetAuthHandle *cah;
  const char* name;

  if (ntohs (message->size) < sizeof (struct GNUNET_GNS_ClientGetAuthMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  GNUNET_SERVER_notification_context_add (nc, client);

  struct GNUNET_GNS_ClientGetAuthMessage *sh_msg =
    (struct GNUNET_GNS_ClientGetAuthMessage *) message;
  
  msg_size = ntohs(message->size);

  if (msg_size > GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  
  name = (char*)&sh_msg[1];

  cah = GNUNET_malloc(sizeof(struct ClientGetAuthHandle));
  cah->client = client;
  cah->unique_id = sh_msg->id;

  if (strlen(name) < strlen(GNUNET_GNS_TLD))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s is too short. Returning\n", name);
    cah->name = NULL;
    send_get_auth_response(cah, name);
    return;
  }

  if (strcmp(name+strlen(name)-strlen(GNUNET_GNS_TLD),
             GNUNET_GNS_TLD) != 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s is not our domain. Returning\n", name);
    cah->name = NULL;
    send_get_auth_response(cah, name);
    return;
  }

  if (strcmp(name, GNUNET_GNS_TLD) == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s is us. Returning\n", name);
    cah->name = NULL;
    send_get_auth_response(cah, name);
    return;
  }
  
  cah->name = GNUNET_malloc(strlen(name)
                            - strlen(GNUNET_GNS_TLD) + 1);
  memset(cah->name, 0,
         strlen(name)-strlen(GNUNET_GNS_TLD) + 1);
  memcpy(cah->name, name,
         strlen(name)-strlen(GNUNET_GNS_TLD));

  /* Start delegation resolution in our namestore */
  gns_resolver_get_authority(zone_hash, name, &send_get_auth_response, cah);
}


/**
 * Reply to client with the result from our lookup.
 *
 * @param cls the closure (our client lookup handle)
 * @param rh the request handle of the lookup
 * @param rd_count the number of records
 * @param rd the record data
 */
static void
send_lookup_response(void* cls,
                     uint32_t rd_count,
                     const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct ClientLookupHandle* clh = (struct ClientLookupHandle*)cls;
  struct GNUNET_GNS_ClientLookupResultMessage *rmsg;
  size_t len;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message with %d results\n",
              "LOOKUP_RESULT", rd_count);
  
  len = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  rmsg = GNUNET_malloc(len+sizeof(struct GNUNET_GNS_ClientLookupResultMessage));
  
  rmsg->id = clh->unique_id;
  rmsg->rd_count = htonl(rd_count);
  rmsg->header.type = htons(GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT);
  rmsg->header.size = 
    htons(len+sizeof(struct GNUNET_GNS_ClientLookupResultMessage));

  GNUNET_NAMESTORE_records_serialize (rd_count, rd, len, (char*)&rmsg[1]);
  
  GNUNET_SERVER_notification_context_unicast (nc, clh->client,
                                (const struct GNUNET_MessageHeader *) rmsg,
                                GNUNET_NO);
  GNUNET_SERVER_receive_done (clh->client, GNUNET_OK);
  
  GNUNET_free(rmsg);
  GNUNET_free(clh->name);
  GNUNET_free(clh);

}


/**
 * Handle lookup requests from client
 *
 * @param cls the closure
 * @param client the client
 * @param message the message
 */
static void
handle_lookup(void *cls,
              struct GNUNET_SERVER_Client * client,
              const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "LOOKUP");

  size_t msg_size = 0;
  size_t namelen;
  char* name;
  struct ClientLookupHandle *clh;

  if (ntohs (message->size) < sizeof (struct GNUNET_GNS_ClientLookupMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  GNUNET_SERVER_notification_context_add (nc, client);

  struct GNUNET_GNS_ClientLookupMessage *sh_msg =
    (struct GNUNET_GNS_ClientLookupMessage *) message;
  
  msg_size = ntohs(message->size);

  if (msg_size > GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  
  name = (char*)&sh_msg[1];
  namelen = strlen(name)+1;
  clh = GNUNET_malloc(sizeof(struct ClientLookupHandle));
  clh->client = client;
  clh->name = GNUNET_malloc(namelen);
  strcpy(clh->name, name);
  clh->unique_id = sh_msg->id;
  clh->type = ntohl(sh_msg->type);
  
  gns_resolver_lookup_record(zone_hash, clh->type, name,
                             &send_lookup_response, clh);
}



/**
 * Process GNS requests.
 *
 * @param cls closure)
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Initializing GNS\n");
  
  char* keyfile;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;

  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_shorten, NULL, GNUNET_MESSAGE_TYPE_GNS_SHORTEN, 0},
    {&handle_lookup, NULL, GNUNET_MESSAGE_TYPE_GNS_LOOKUP, 0},
    {&handle_get_authority, NULL, GNUNET_MESSAGE_TYPE_GNS_GET_AUTH, 0}
  };

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (c, "gns",
                                             "ZONEKEY", &keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No private key for root zone specified!\n");
    GNUNET_SCHEDULER_shutdown(0);
    return;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Using keyfile %s for root zone.\n", keyfile);

  zone_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_CRYPTO_rsa_key_get_public (zone_key, &pkey);

  GNUNET_CRYPTO_hash(&pkey, sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &zone_hash);
  GNUNET_free(keyfile);
  

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (c, "gns",
                                            "HIJACK_DNS"))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
               "DNS hijacking enabled... connecting to service.\n");

    if (gns_interceptor_init(zone_hash, c) == GNUNET_SYSERR)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Failed to enable the dns interceptor!\n");
    }
  }

  

  /**
   * handle to our local namestore
   */
  namestore_handle = GNUNET_NAMESTORE_connect(c);

  if (NULL == namestore_handle)
  {
    //FIXME do error handling;
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Failed to connect to the namestore!\n");
    GNUNET_SCHEDULER_shutdown(0);
    return;
  }
  
  /**
   * handle to the dht
   */
  dht_handle = GNUNET_DHT_connect(c, 1); //FIXME get ht_len from cfg

  if (NULL == dht_handle)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Could not connect to DHT!\n");
  }

  //put_some_records(); //FIXME for testing
  
  /**
   * Schedule periodic put
   * for our records
   * We have roughly an hour for all records;
   */
  dht_update_interval = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,
                                                      1);
  zone_update_taskid = GNUNET_SCHEDULER_add_now (&update_zone_dht_start, NULL);

  GNUNET_SERVER_add_handlers (server, handlers);
  
  //FIXME
  //GNUNET_SERVER_disconnect_notify (server,
  //                                 &client_disconnect_notification,
  //                                 NULL);

  nc = GNUNET_SERVER_notification_context_create (server, 1);

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
}


/**
 * The main function for the GNS service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int ret;

  ret =
      (GNUNET_OK ==
       GNUNET_SERVICE_run (argc, argv, "gns", GNUNET_SERVICE_OPTION_NONE, &run,
                           NULL)) ? 0 : 1;
  return ret;
}

/* end of gnunet-service-gns.c */
