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
 *    - Think about mixed dns queries (.gnunet and .org)
 *    - (de-)serialisation of records/signature trees
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
#include "gns.h"

/* Ignore for now not used anyway and probably never will */
#define GNUNET_MESSAGE_TYPE_GNS_CLIENT_LOOKUP 23
#define GNUNET_MESSAGE_TYPE_GNS_CLIENT_RESULT 24

struct GNUNET_GNS_QueryRecordList
{
  /**
   * DLL
   */
  struct GNUNET_GNS_QueryRecordList * next;
  struct GNUNET_GNS_QueryRecordList * prev;

  GNUNET_GNS_Record * record;
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
  
  char *original_name;
  char *name;

  uint16_t type;
  /* the dns request id */
  int id; // FIXME can handle->request_id also be used here?

  /* the request handle to reply to */
  struct GNUNET_DNS_RequestHandle *request_handle;

  /* hast this query been answered? */
  int answered;

  /* the authoritative zone to query */
  GNUNET_HashCode *authority;

  /* we have an authority in namestore that
   * may be able to resolve
   */
  int authority_found;
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
 * Our zone's private key
 */
struct GNUNET_CRYPTO_RsaPrivateKey *zone_key;

/**
 * Our handle to the namestore service
 */
struct GNUNET_NAMESTORE_Handle *namestore_handle;

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
 * Our tld. Maybe get from config file
 */
const char* gnunet_tld = ".gnunet";

/**
 * Useful for zone update for DHT put
 */
static int num_public_records =  3600;
struct GNUNET_TIME_Relative dht_update_interval;

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
  GNUNET_DHT_disconnect(dht_handle);
}

/**
 * Function called when we get a result from the dht
 * for our query
 *
 * @param cls the query handle
 * @param exp lifetime
 * @param key the key the record was stored under
 * @param get_path get path
 * @param get_path_length get path length
 * @param put_path put path
 * @param put_path_length put path length
 * @param type the block type
 * @param size the size of the record
 * @param data the record data
 */
void
process_authority_dht_result(void* cls,
                 struct GNUNET_TIME_Absolute exp,
                 const GNUNET_HashCode * key,
                 const struct GNUNET_PeerIdentity *get_path,
                 unsigned int get_path_length,
                 const struct GNUNET_PeerIdentity *put_path,
                 unsigned int put_path_length,
                 enum GNUNET_BLOCK_Type type,
                 size_t size, const void *data)
{
  if (data == NULL)
    return;

  /**
   * data is a serialized PKEY record (probably)
   * parse, put into namestore
   * namestore zone hash is in query.
   * Then adjust query->name and call resolve_name
   * with new zone (the one just received)
   *
   * query->authority = new_authority
   * resolve_name(query, new_authority);
   */
}

/**
 * Start DHT lookup for a name -> PKEY (compare NS) record in
 * query->authority's zone
 *
 * @param query the pending gns query
 * @param name the name of the PKEY record
 */
void
resolve_authority_dht(struct GNUNET_GNS_PendingQuery *query, const char* name)
{
  enum GNUNET_GNS_RecordType rtype = GNUNET_GNS_RECORD_PKEY;
  struct GNUNET_TIME_Relative timeout;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode lookup_key;

  GNUNET_CRYPTO_hash(name, strlen(name), &name_hash);
  GNUNET_CRYPTO_hash_xor(&name_hash, query->authority, &lookup_key);

  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 20);
  
  //FIXME how long to wait for results?
  GNUNET_DHT_get_start(dht_handle, timeout,
                       GNUNET_BLOCK_TYPE_TEST, //FIXME todo
                       &lookup_key,
                       5, //Replication level FIXME
                       GNUNET_DHT_RO_NONE,
                       &rtype, //xquery FIXME this is bad
                       sizeof(GNUNET_GNS_RECORD_PKEY),
                       &process_authority_dht_result,
                       query);

}

/**
 * Function called when we get a result from the dht
 * for our query
 *
 * @param cls the query handle
 * @param exp lifetime
 * @param key the key the record was stored under
 * @param get_path get path
 * @param get_path_length get path length
 * @param put_path put path
 * @param put_path_length put path length
 * @param type the block type
 * @param size the size of the record
 * @param data the record data
 */
void
process_name_dht_result(void* cls,
                 struct GNUNET_TIME_Absolute exp,
                 const GNUNET_HashCode * key,
                 const struct GNUNET_PeerIdentity *get_path,
                 unsigned int get_path_length,
                 const struct GNUNET_PeerIdentity *put_path,
                 unsigned int put_path_length,
                 enum GNUNET_BLOCK_Type type,
                 size_t size, const void *data)
{
  if (data == NULL)
    return;

  /**
   * data is a serialized GNS record of type
   * query->record_type. Parse and put into namestore
   * namestore zone hash is in query.
   * Check if record type and name match in query and reply
   * to dns!
   */
}

/**
 * Start DHT lookup for a (name -> query->record_type) record in
 * query->authority's zone
 *
 * @param query the pending gns query
 * @param name the name to query record
 */
void
resolve_name_dht(struct GNUNET_GNS_PendingQuery *query, const char* name)
{
  struct GNUNET_TIME_Relative timeout;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode lookup_key;

  GNUNET_CRYPTO_hash(name, strlen(name), &name_hash);
  GNUNET_CRYPTO_hash_xor(&name_hash, query->authority, &lookup_key);

  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 20);
  
  //FIXME how long to wait for results?
  GNUNET_DHT_get_start(dht_handle, timeout,
                       GNUNET_BLOCK_TYPE_TEST, //FIXME todo
                       &lookup_key,
                       5, //Replication level FIXME
                       GNUNET_DHT_RO_NONE,
                       &query->type, //xquery
                       sizeof(query->type),
                       &process_name_dht_result,
                       query);

}

//Prototype
void
resolve_name(struct GNUNET_GNS_PendingQuery *query, GNUNET_HashCode *zone);

/**
 * This is a callback function that should give us only PKEY
 * records. Used to query the namestore for the authority (PKEY)
 * for 'name'
 *
 * @param cls the pending query
 * @param zone our zone hash
 * @param name the name for which we need an authority
 * @param record_type the type of record (PKEY)
 * @param expiration expiration date of the record
 * @param flags namestore record flags
 * @param sig_loc the location of the record in the signature tree
 * @param size the size of the record
 * @param data the record data
 */
void
process_authority_lookup(void* cls,
                   const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                   struct GNUNET_TIME_Absolute expiration,
                   const char *name,
                   unsigned int rd_count,
                   const struct GNUNET_NAMESTORE_RecordData *rd,
                   const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct GNUNET_GNS_PendingQuery *query;
  GNUNET_HashCode zone;

  query = (struct GNUNET_GNS_PendingQuery *)cls;
  GNUNET_CRYPTO_hash(key, GNUNET_CRYPTO_RSA_KEY_LENGTH, &zone);
  
  /**
   * No authority found in namestore.
   */
  if (rd_count == 0)
  {
    if (query->authority_found)
    {
      query->authority_found = 0;
      resolve_name(query, query->authority);
      return;
    }

    /**
     * We did not find an authority in the namestore
     * _IF_ the current authoritative zone is us we cannot resolve
     * _ELSE_ we can still check the dht
     */
    if (GNUNET_CRYPTO_hash_cmp(&zone, &zone_hash))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Authority unknown\n");
      //FIXME return NX answer
      return;
    }

    resolve_authority_dht(query, name);
    return;
  }

  //Note only 1 pkey should have been returned.. anything else would be strange
  /**
   * We found an authority that may be able to help us
   * move on with query
   */
  GNUNET_GNS_Record *record 
    = GNUNET_malloc(sizeof(GNUNET_GNS_Record));
  
  
  //FIXME todo
  //parse_record(rd[0]->data, rd[0]->data_size, 0, record);
  //FIXME this cast will not work we have to define how a PKEY record looks like
  //In reality this also returns a pubkey not a hash
  GNUNET_HashCode *k = (GNUNET_HashCode*)record->data.raw.data;
  query->authority = k;
  resolve_name(query, query->authority);
  
}


/**
 * Reply to client with the result from our lookup.
 *
 * @param answer the pending query used in the lookup
 */
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
  
  //FIXME this is silently discarded
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
    //GNUNET_free(answer);
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Answered DNS request\n");
    //FIXME return code, free datastructures
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Error building DNS response! (ret=%d)", ret);
  }
}


/**
 * Namestore calls this function if we have an entry for this name.
 * (or data=null to indicate the lookup has finished)
 *
 * @param cls the pending query
 * @param zone the zone of the lookup
 * @param name the name looked up
 * @param record_type the record type
 * @param expiration lifetime of the record
 * @param flags record flags
 * @param sig_loc location of the record in the signature tree
 * @param size the size of the record
 * @param data the record data
 */
static void
process_authoritative_result(void* cls,
                  const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                  struct GNUNET_TIME_Absolute expiration,
                  const char *name, unsigned int rd_count,
                  const struct GNUNET_NAMESTORE_RecordData *rd,
                  const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct GNUNET_GNS_PendingQuery *query;
  struct GNUNET_GNS_QueryRecordList *qrecord;
  struct GNUNET_DNSPARSER_Record *record;
  GNUNET_HashCode zone;
  query = (struct GNUNET_GNS_PendingQuery *) cls;
  GNUNET_CRYPTO_hash(key, GNUNET_CRYPTO_RSA_KEY_LENGTH, &zone);

  //FIXME Handle results in rd

  if (rd_count == 0)
  {
    /**
     * FIXME
     * Lookup terminated and no results
     * -> DHT Phase unless data is recent
     * if full_name == next_name and not anwered we cannot resolve
     */
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
               "Namestore lookup terminated. without results\n");
    
    /**
     * if this is not our zone we cannot rely on the namestore to be
     * complete. -> Query DHT
     */
    if (!GNUNET_CRYPTO_hash_cmp(&zone, &zone_hash))
    {
      //FIXME todo
      resolve_name_dht(query, name);
      return;
    }

    /**
     * Our zone and no result? Cannot resolve TT
     * FIXME modify query to say NX
     */
    return;

  }
  else
  {
    /**
     * Record found
     *
     * FIXME Check record expiration and dht expiration
     * consult dht if necessary
     */
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
               "Processing additional result for %s from namestore\n", name);
    int i;
    for (i=0; i<rd_count;i++)
    {
      // A time will come when this has to be freed
      qrecord = GNUNET_malloc(sizeof(struct GNUNET_GNS_QueryRecordList));
      record = GNUNET_malloc(sizeof(struct GNUNET_DNSPARSER_Record));
      qrecord->record = record;
      
      //fixme into gns_util
      //parse_record(rd[i]->data, rd[i]->data_size, 0, record);
      GNUNET_CONTAINER_DLL_insert(query->records_head,
                                  query->records_tail,
                                  qrecord);
      query->num_records++;

      //TODO really?
      //we need to resolve to the original name in the end though...
      //record->name = (char*)query->original_name;
    }

    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Found answer to query!\n");
    query->answered = 1;

    reply_to_dns(query);
  }
}

/**
 * Determine if this name is canonical.
 * i.e.
 * a.b.gnunet  = not canonical
 * a           = canonical
 *
 * @param name the name to test
 * @return 1 if canonical
 */
int
is_canonical(char* name)
{
  uint32_t len = strlen(name);
  int i;

  for (i=0; i<len; i++)
  {
    if (*(name+i) == '.')
      return 0;
  }
  return 1;
}

/**
 * Move one level up in the domain hierarchy and return the
 * passed top level domain.
 * FIXME this needs a better name
 *
 * @param name the domain
 * @return the tld
 */
char* move_up(char* name)
{
  uint32_t len;

  if (is_canonical(name))
    return NULL;

  for (len = strlen(name); len > 0; len--)
  {
    if (*(name+len) == '.')
      break;
  }

  if (len == 0)
    return NULL; //Error

  name[len] = '\0'; //terminate string

  return (name+len+1);
}


/**
 * The first phase of resolution.
 * First check if the name is canonical.
 * If it is then try to resolve directly.
 * If not then first have to resolve the authoritative entities.
 *
 * @param query the pending lookup
 * @param zone the zone we are currently resolving in
 */
void
resolve_name(struct GNUNET_GNS_PendingQuery *query, GNUNET_HashCode *zone)
{
  if (is_canonical(query->name))
  {
    //We only need to check this zone's ns
    GNUNET_NAMESTORE_lookup_record(namestore_handle,
                               zone,
                               query->name,
                               query->type,
                               &process_authoritative_result,
                               query);
  }
  else
  {
    //We have to resolve the authoritative entity
    char *new_authority = move_up(query->name);
    GNUNET_NAMESTORE_lookup_record(namestore_handle,
                                 zone,
                                 new_authority,
                                 GNUNET_GNS_RECORD_PKEY,
                                 &process_authority_lookup,
                                 query);
  }
}

/**
 * Entry point for name resolution
 * Lookup local namestore of our zone.
 *
 * Setup a new query and try to resolve
 *
 * @param rh the request handle of the DNS request from a client
 * @param name the name to look up
 * @param id the id of the dns request (for the reply)
 * @param type the record type to look for
 */
void
start_resolution(struct GNUNET_DNS_RequestHandle *rh,
                 char* name, uint16_t id, uint16_t type)
{
  struct GNUNET_GNS_PendingQuery *query;
  
  //FIXME remove .gnunet here from name
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "This is .gnunet (%s)!\n", name);
  query = GNUNET_malloc(sizeof (struct GNUNET_GNS_PendingQuery));
  query->id = id;
  query->original_name = name; //Full name of original query
  
  //FIXME do not forget to free!!
  query->name = GNUNET_malloc(strlen(name)-strlen(gnunet_tld) + 1);
  memset(query->name, 0, strlen(name)-strlen(gnunet_tld) + 1);
  memcpy(query->name, name, strlen(name)-strlen(gnunet_tld));

  query->type = type;
  query->request_handle = rh;

  //Start resolution in our zone
  resolve_name(query, &zone_hash);
}

/**
 * The DNS request handler
 * Called for every incoming DNS request.
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
  struct GNUNET_DNSPARSER_Packet *p;
  int i;
  char *tldoffset;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Hijacked a DNS request...processing\n");
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
   *
   * FIXME now in theory there could be more than 1 query in the request
   * but if this is case we get into trouble:
   * either we query the GNS or the DNS. We cannot do both!
   * So I suggest to either only allow a single query per request or
   * only allow GNS or DNS requests.
   * The way it is implemented here now is buggy and will lead to erratic
   * behaviour (if multiple queries are present).
   */
  for (i=0;i<p->num_queries;i++)
  {
    tldoffset = p->queries[i].name + strlen(p->queries[i].name);

    while ((*tldoffset) != '.')
      tldoffset--;
    
    if (0 == strcmp(tldoffset, gnunet_tld))
    {
      start_resolution(rh, p->queries[i].name, p->id, p->queries[i].type);
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

/**
 * test function that stores some data in the namestore
 */
void
put_some_records(void)
{
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Populating namestore\n");
  /* put a few records into namestore */
  char* ipA = "1.2.3.4";
  char* ipB = "5.6.7.8";
  GNUNET_GNS_Record *alice = GNUNET_malloc(sizeof(GNUNET_GNS_Record));
  GNUNET_GNS_Record *bob = GNUNET_malloc(sizeof(GNUNET_GNS_Record));
  struct GNUNET_NAMESTORE_RecordData *rda = NULL;
  struct GNUNET_NAMESTORE_RecordData *rdb = NULL;
  rda = GNUNET_malloc(sizeof(struct GNUNET_NAMESTORE_RecordData));
  
  //FIXME here we would have to parse the gns record and put it into
  //the rd struct

  //FIXME this is not enough! but too mucht atm
  GNUNET_assert(1 == inet_pton (AF_INET, ipA, alice->data.raw.data));
  GNUNET_assert(1 == inet_pton (AF_INET, ipB, bob->data.raw.data));

  GNUNET_NAMESTORE_record_create (namestore_handle,
                               zone_key,
                               "alice",
                               rda,
                               NULL,
                               NULL);
  GNUNET_NAMESTORE_record_create (namestore_handle,
                               zone_key,
                               "bob",
                               rdb,
                               NULL,
                               NULL);
}

void
update_zone_dht_next(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_NAMESTORE_zone_iterator_next(namestore_iter);
}

/**
 * Function used to put all records successively into the DHT.
 *
 * @param cls the closure (NULL)
 * @param zone our root zone hash
 * @param name the name of the record
 * @param record_type the type of the record
 * @param expiration lifetime of the record
 * @param flags flags of the record
 * @param sig_loc location of record in signature tree
 * @param size size of the record
 * @param record_data the record data
 */
void
put_gns_record(void *cls,
                const const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *key,
                struct GNUNET_TIME_Absolute expiration,
                const char *name,
                unsigned int rd_count,
                const struct GNUNET_NAMESTORE_RecordData *rd,
                const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Putting records into the DHT\n");
  struct GNUNET_TIME_Relative timeout;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode xor_hash;

  if (NULL == name) //We're done
  {
    GNUNET_NAMESTORE_zone_iteration_stop (namestore_iter);
    return;
  }
  /**
   * FIXME magic number 20 move to config file
   */
  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 20);
  GNUNET_CRYPTO_hash(name, strlen(name), &name_hash);
  GNUNET_CRYPTO_hash_xor(&zone_hash, &name_hash, &xor_hash);
  GNUNET_DHT_put (dht_handle, &xor_hash,
                  5, //replication level
                  GNUNET_DHT_RO_NONE,
                  GNUNET_BLOCK_TYPE_TEST, //FIXME todo block plugin
                  rd->data_size,
                  rd->data,
                  expiration,
                  timeout,
                  NULL, //FIXME continuation needed? success check? yes ofc
                  NULL); //cls for cont

  /**
   * Reschedule periodic put
   */
  GNUNET_SCHEDULER_add_delayed (dht_update_interval,
                                &update_zone_dht_next,
                                NULL);

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
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Update zone!\n");
  dht_update_interval = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,
                                                     (3600/num_public_records));
  namestore_iter = GNUNET_NAMESTORE_zone_iteration_start (namestore_handle,
                                                          &zone_hash,
                                                          GNUNET_NAMESTORE_RF_AUTHORITY,
                                                          GNUNET_NAMESTORE_RF_PRIVATE,
                                                          &put_gns_record,
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
  
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Init GNS\n");
  zone_key = GNUNET_CRYPTO_rsa_key_create ();

  GNUNET_CRYPTO_hash(zone_key, GNUNET_CRYPTO_RSA_KEY_LENGTH,//FIXME is this ok?
                     &zone_hash);
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

  put_some_records(); //FIXME for testing
  
  /**
   * Schedule periodic put
   * for our records
   * We have roughly an hour for all records;
   */
  dht_update_interval = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,
                                                      60); //FIXME from cfg
  GNUNET_SCHEDULER_add_delayed (dht_update_interval,
                                &update_zone_dht_start,
                                NULL);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "GNS Init done!\n");

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
