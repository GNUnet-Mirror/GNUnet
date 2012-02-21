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
#include "gns.h"


/* TODO into gnunet_protocols */
#define GNUNET_MESSAGE_TYPE_GNS_CLIENT_LOOKUP 23
#define GNUNET_MESSAGE_TYPE_GNS_CLIENT_RESULT 24

struct GNUNET_GNS_QueryRecordList
{
  /**
   * DLL
   */
  struct GNUNET_GNS_QueryRecordList * next;
  struct GNUNET_GNS_QueryRecordList * prev;

  struct GNUNET_DNSPARSER_Record * record;
};

/**
 * A result list for namestore queries
 */
struct GNUNET_GNS_PendingQuery
{
  /* the answer packet */
  struct GNUNET_DNSPARSER_Packet *answer;

  /* records to put into answer packet */
  struct GNUNET_GNS_QueryRecordList * records_head;
  struct GNUNET_GNS_QueryRecordList * records_tail;

  int num_records;
  int num_authority_records; //FIXME are all of our replies auth?
  
  char *name;
  uint16_t type;
  /* the dns request id */
  int id; // FIXME can handle->request_id also be used here?

  /* the request handle to reply to */
  struct GNUNET_DNS_RequestHandle *request_handle;

  /* hast this query been answered? */
  int answered;
};


/**
 * Our handle to the DNS handler library
 */
struct GNUNET_DNS_Handle *dns_handle;

/**
 * Our handle to the DHT
 */
struct GNUNET_DHT_Handle *dht_handle;

/**
 * Our handle to the namestore service
 */
struct GNUNET_NAMESTORE_Handle *namestore_handle;

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
const GNUNET_HashCode *my_zone;

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_DNS_disconnect(dns_handle);
  GNUNET_NAMESTORE_disconnect(namestore_handle, 0);
}

/**
 * Phase 2 of resolution.
 */
void
lookup_dht(struct GNUNET_GNS_PendingQuery *answer)
{
}

void
reply_to_dns(struct GNUNET_GNS_PendingQuery *answer)
{
  struct GNUNET_GNS_QueryRecordList *i;
  struct GNUNET_DNSPARSER_Packet *packet;
  struct GNUNET_DNSPARSER_Flags dnsflags;
  int j;
  size_t len;
  int ret;
  char *buf;
  
  packet = GNUNET_malloc(sizeof(struct GNUNET_DNSPARSER_Packet));
  packet->answers =
    GNUNET_malloc(sizeof(struct GNUNET_DNSPARSER_Record) * answer->num_records);
  
  len = sizeof(struct GNUNET_DNSPARSER_Record*);
  j = 0;
  for (i=answer->records_head; i != NULL; i=i->next)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
               "Adding %s to DNS response\n", i->record->name);
    memcpy(&packet->answers[j], 
           i->record,
           sizeof (struct GNUNET_DNSPARSER_Record));
    GNUNET_free(i->record);
    j++;
  }
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "after memcpy\n");
  /* FIXME how to handle auth, additional etc */
  packet->num_answers = answer->num_records;
  packet->num_authority_records = answer->num_authority_records;

  dnsflags.authoritative_answer = 1;
  dnsflags.opcode = GNUNET_DNSPARSER_OPCODE_QUERY;
  dnsflags.return_code = GNUNET_DNSPARSER_RETURN_CODE_NO_ERROR; //not sure
  dnsflags.query_or_response = 1;
  packet->flags = dnsflags;

  packet->id = answer->id;
  ret = GNUNET_DNSPARSER_pack (packet,
                               1024, /* FIXME magic from dns redirector */
                               &buf,
                               &len);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
             "Built DNS response! (ret=%d)\n", ret);
  if (ret == GNUNET_OK)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
               "Answering DNS request\n");
    GNUNET_DNS_request_answer(answer->request_handle,
                              len,
                              buf);
    GNUNET_free(answer);
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Answered DNS request\n");
    //FIXME return code, free datastructures
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Error building DNS response! (ret=%d)", ret);
  }
}

static void
process_ns_result(void* cls, const GNUNET_HashCode *zone,
                  const char *name, uint32_t record_type,
                  struct GNUNET_TIME_Absolute expiration,
                  enum GNUNET_NAMESTORE_RecordFlags flags,
                  const struct GNUNET_NAMESTORE_SignatureLocation *sig_loc,
                  size_t size, const void *data)
{
  struct GNUNET_GNS_PendingQuery *query;
  struct GNUNET_GNS_QueryRecordList *qrecord;
  struct GNUNET_DNSPARSER_Record *record;
  query = (struct GNUNET_GNS_PendingQuery *) cls;


  if (NULL == data)
  {
    /**
     * Last result received (or none)
     * Do we have what we need to answer?
     * If not -> DHT Phase
     * FIXME free memory
     */
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
               "Namestore lookup terminated. (answered=%d)", query->answered);

    if (query->answered)
      reply_to_dns(query);
    else
      lookup_dht(query); //TODO

  }
  else
  {
    /**
     * New result
     */
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
               "Processing additional result %s from namestore\n", name);

    qrecord = GNUNET_malloc(sizeof(struct GNUNET_GNS_QueryRecordList));
    record = GNUNET_malloc(sizeof(struct GNUNET_DNSPARSER_Record));
    qrecord->record = record;

    record->name = (char*)name;
    /* FIXME for gns records this requires the dnsparser to be modified!
     * or use RAW
     * maybe store record data appropriately in namestore to avoid this
     * huge switch?
     **/
    if (record_type == GNUNET_DNSPARSER_TYPE_A)
    {
      record->data.raw.data = (char*)data;
      record->data.raw.data_len = size;
    }
    record->expiration_time = expiration;
    record->type = record_type;
    record->class = GNUNET_DNSPARSER_CLASS_INTERNET; /* srsly? */

    if (flags == GNUNET_NAMESTORE_RF_AUTHORITY)
    {
      //query->num_authority_records++;
    }

    if ((0 == strcmp(query->name , name)) &&
        (query->type == record_type))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Found answer to query!\n");
      query->answered = 1;
    }

    query->num_records++;

    //FIXME watch for leaks
    GNUNET_CONTAINER_DLL_insert(query->records_head,
                                query->records_tail,
                                qrecord);
  }
}


/**
 * Phase 1 of name resolution: Lookup local namestore
 *
 * @param name the name to look up
 * @param id the id of the dns request (for the reply)
 * @param type the record type to look for
 */
void
lookup_namestore(struct GNUNET_DNS_RequestHandle *rh,
                 char* name, uint16_t id, uint16_t type)
{
  struct GNUNET_GNS_PendingQuery *answer;
  
  /**
   * Do db lookup here. Make dht lookup if necessary 
   * FIXME for now only local lookups for our zone!
   */
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "This is .gnunet (%s)!\n", name);
  answer = GNUNET_malloc(sizeof (struct GNUNET_GNS_PendingQuery));
  answer->id = id;
  answer->name = name;
  answer->type =type;
  answer->request_handle = rh;
  
  GNUNET_NAMESTORE_lookup_name(namestore_handle,
                               my_zone,
                               name,
                               type,
                               &process_ns_result,
                               answer);
}

/**
 * The DNS request handler
 *
 * @param cls closure
 * @param rh request handle to user for reply
 * @param request_length number of bytes in request
 * @param request udp payload of the DNS request
 */
void
handle_dns_request(void *cls,
                   struct GNUNET_DNS_RequestHandle *rh,
                   size_t request_length,
                   const char *request)
{
  /**
   * parse request for tld
   */
  struct GNUNET_DNSPARSER_Packet *p;
  int namelen;
  int i;
  char *tail;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "hijacked a request...processing\n");
  p = GNUNET_DNSPARSER_parse (request, request_length);
  
  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Received malformed DNS packet, leaving it untouched\n");
    GNUNET_DNS_request_forward (rh);
    return;
  }
  
  /**
   * Check tld and decide if we or
   * legacy dns is responsible
   */
  for (i=0;i<p->num_queries;i++)
  {
    namelen = strlen(p->queries[i].name);
    
    if (namelen < 7) /* this can't be .gnunet */
      continue;
    /**
     * Move our tld/root to config file
     * Generate fake DNS reply that replaces .gnunet with .org for testing?
     */
    tail = p->queries[i].name+(namelen-7);
    if (0 == strcmp(tail, ".gnunet"))
    {
      /* FIXME we need to answer to ALL queries in ONE response...
       * What happens if some requests should be handles by us and
       * others by DNS?
       * Like this we only answer one...
       */
      lookup_namestore(rh, p->queries[i].name, p->id, p->queries[i].type);
    }
    else
    {
      /**
       * This request does not concern us. Forward to real DNS.
       */
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
                 "Request for %s is forwarded to DNS\n", p->queries[i].name);
      GNUNET_DNS_request_forward (rh);
    }
  }
}

/*TODO*/
static void
handle_client_record_lookup(void *cls,
                            struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
}

/**
 * test function
 */
void
put_some_records(void)
{
  /* put a few records into namestore */
  char* ipA = "1.2.3.4";
  char* ipB = "5.6.7.8";
  struct in_addr *alice = GNUNET_malloc(sizeof(struct in_addr));
  struct in_addr *bob = GNUNET_malloc(sizeof(struct in_addr));
  GNUNET_assert(1 == inet_pton (AF_INET, ipA, alice));
  GNUNET_assert(1 == inet_pton (AF_INET, ipB, bob));
  GNUNET_NAMESTORE_record_put (namestore_handle,
                               my_zone,
                               "alice.gnunet",
                               GNUNET_GNS_RECORD_TYPE_A,
                               GNUNET_TIME_absolute_get_forever(),
                               GNUNET_NAMESTORE_RF_AUTHORITY,
                               NULL, //sig loc
                               sizeof(struct in_addr),
                               alice,
                               NULL,
                               NULL);
  GNUNET_NAMESTORE_record_put (namestore_handle,
                               my_zone,
                               "bob.gnunet",
                               GNUNET_GNS_RECORD_TYPE_A,
                               GNUNET_TIME_absolute_get_forever(),
                               GNUNET_NAMESTORE_RF_AUTHORITY,
                               NULL, //sig loc
                               sizeof(struct in_addr),
                               bob,
                               NULL,
                               NULL);
}

/**
 * Process GNS requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  /* The IPC message types */
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    /* callback, cls, type, size */
    {&handle_client_record_lookup, NULL, GNUNET_MESSAGE_TYPE_GNS_CLIENT_LOOKUP,
      0},
    {NULL, NULL, 0, 0}
  };
  
  nc = GNUNET_SERVER_notification_context_create (server, 1);

  /* FIXME - do some config parsing 
   *       - Maybe only hijack dns if option is set (HIJACK_DNS=1)
   */

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  /**
   * Do gnunet dns init here
   */
  dns_handle = GNUNET_DNS_connect(c,
                                  GNUNET_DNS_FLAG_PRE_RESOLUTION,
                                  &handle_dns_request, /* rh */
                                  NULL); /* Closure */

  if (NULL == dns_handle)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Failed to connect to the dnsservice!\n");
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
  }

  /**
   * handle to the dht
   */
  dht_handle = GNUNET_DHT_connect(c, 1); //FIXME get ht_len from cfg

  if (NULL == dht_handle)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Could not connect to DHT!\n");
  }
  
  put_some_records();

  GNUNET_SERVER_add_handlers (server, handlers);
  /**
   * Esp the lookup would require to keep track of the clients' context
   * See dht.
   * GNUNET_SERVER_disconnect_notify (server, &client_disconnect, NULL);
   **/
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
