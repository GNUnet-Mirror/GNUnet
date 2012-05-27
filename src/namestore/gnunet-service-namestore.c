/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file namestore/gnunet-service-namestore.c
 * @brief namestore for the GNUnet naming system
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_namestore_plugin.h"
#include "gnunet_signatures.h"
#include "namestore.h"

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

/**
 * A namestore operation.
 */
struct GNUNET_NAMESTORE_ZoneIteration
{
  struct GNUNET_NAMESTORE_ZoneIteration *next;
  struct GNUNET_NAMESTORE_ZoneIteration *prev;

  struct GNUNET_NAMESTORE_Client * client;

  int has_zone;

  struct GNUNET_CRYPTO_ShortHashCode zone;

  uint64_t request_id;
  uint32_t offset;

  /**
   * Which flags must be included
   */
  uint16_t must_have_flags;

  /**
   * Which flags must not be included
   */
  uint16_t must_not_have_flags;
};


/**
 * A namestore client
 */
struct GNUNET_NAMESTORE_Client
{
  struct GNUNET_NAMESTORE_Client *next;
  struct GNUNET_NAMESTORE_Client *prev;

  struct GNUNET_SERVER_Client * client;

  struct GNUNET_NAMESTORE_ZoneIteration *op_head;
  struct GNUNET_NAMESTORE_ZoneIteration *op_tail;
};

struct GNUNET_NAMESTORE_CryptoContainer
{
  char * filename;

  struct GNUNET_CRYPTO_ShortHashCode zone;
  struct GNUNET_CRYPTO_RsaPrivateKey *privkey;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pubkey;
};


/**
* Configuration handle.
*/
const struct GNUNET_CONFIGURATION_Handle *GSN_cfg;

/**
* Database handle
*/
struct GNUNET_NAMESTORE_PluginFunctions *GSN_database;

/**
* Zonefile directory
*/
static char *zonefile_directory;

static char *db_lib_name;


/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *snc;

static struct GNUNET_NAMESTORE_Client *client_head;
static struct GNUNET_NAMESTORE_Client *client_tail;

struct GNUNET_CONTAINER_MultiHashMap *zonekeys;


/**
 * Write zonefile to disk
 * @param filename where to write
 * @param c the crypto container
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on fail
 */

int
write_key_to_file (const char *filename, struct GNUNET_NAMESTORE_CryptoContainer *c)
{
  struct GNUNET_CRYPTO_RsaPrivateKey *ret = c->privkey;
  struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded *enc;
  struct GNUNET_DISK_FileHandle *fd;

  if (GNUNET_YES == GNUNET_DISK_file_test (filename))
  {
    struct GNUNET_CRYPTO_ShortHashCode zone;
    struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pubkey;
    struct GNUNET_CRYPTO_RsaPrivateKey * privkey;

    privkey = GNUNET_CRYPTO_rsa_key_create_from_file(filename);
    if (privkey == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           _("File zone `%s' but corrupt content already exists, failed to write! \n"), GNUNET_short_h2s (&zone));
      return GNUNET_SYSERR;
    }

    GNUNET_CRYPTO_rsa_key_get_public (privkey, &pubkey);
    GNUNET_CRYPTO_short_hash (&pubkey, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), &zone);
    GNUNET_CRYPTO_rsa_key_free (privkey);

    if (0 == memcmp (&zone, &c->zone, sizeof(zone)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
           _("File zone `%s' containing this key already exists\n"), GNUNET_short_h2s (&zone));
      return GNUNET_OK;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           _("File zone `%s' but different zone key already exists, failed to write! \n"), GNUNET_short_h2s (&zone));
      return GNUNET_OK;
    }
  }
  fd = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE | GNUNET_DISK_OPEN_FAILIFEXISTS, GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
  if (NULL == fd)
  {
    if (errno == EEXIST)
    {
      if (GNUNET_YES != GNUNET_DISK_file_test (filename))
      {
        /* must exist but not be accessible, fail for good! */
        if (0 != ACCESS (filename, R_OK))
          LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "access", filename);
        else
          GNUNET_break (0);   /* what is going on!? */
        return GNUNET_SYSERR;
      }
    }
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "open", filename);
    return GNUNET_SYSERR;
  }

  if (GNUNET_YES != GNUNET_DISK_file_lock (fd, 0, sizeof (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded), GNUNET_YES))
  {
    GNUNET_assert (GNUNET_YES == GNUNET_DISK_file_close (fd));
    return GNUNET_SYSERR;
  }
  enc = GNUNET_CRYPTO_rsa_encode_key (ret);
  GNUNET_assert (enc != NULL);
  GNUNET_assert (ntohs (enc->len) == GNUNET_DISK_file_write (fd, enc, ntohs (enc->len)));
  GNUNET_free (enc);
  GNUNET_DISK_file_sync (fd);
  if (GNUNET_YES != GNUNET_DISK_file_unlock (fd, 0, sizeof (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded)))
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "fcntl", filename);
  GNUNET_assert (GNUNET_YES == GNUNET_DISK_file_close (fd));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
       _("Stored zonekey for zone `%s' in file `%s'\n"), GNUNET_short_h2s(&c->zone), c->filename);
  return GNUNET_OK;
}

int zone_to_disk_it (void *cls,
                     const GNUNET_HashCode *key,
                     void *value)
{
  struct GNUNET_NAMESTORE_CryptoContainer * c = value;
  if (c->filename != NULL)
    write_key_to_file(c->filename, c);
  else
  {
    GNUNET_asprintf(&c->filename, "%s/%s.zkey", zonefile_directory, GNUNET_short_h2s (&c->zone));
    write_key_to_file(c->filename, c);
  }


  GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_remove (zonekeys, key, value));
  GNUNET_CRYPTO_rsa_key_free (c->privkey);
  GNUNET_free (c->pubkey);
  GNUNET_free (c->filename);
  GNUNET_free (c);

  return GNUNET_OK;
}


struct GNUNET_TIME_Absolute
get_block_expiration_time (unsigned int rd_count, const struct GNUNET_NAMESTORE_RecordData *rd)
{
  unsigned int c;
  struct GNUNET_TIME_Absolute expire = GNUNET_TIME_UNIT_FOREVER_ABS;

  if (NULL == rd)
    return GNUNET_TIME_UNIT_ZERO_ABS;
  for (c = 0; c < rd_count; c++)  
    expire = GNUNET_TIME_absolute_min (rd[c].expiration, expire);  
  return expire;
}

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping namestore service\n");
  struct GNUNET_NAMESTORE_ZoneIteration * no;
  struct GNUNET_NAMESTORE_ZoneIteration * tmp;
  struct GNUNET_NAMESTORE_Client * nc;
  struct GNUNET_NAMESTORE_Client * next;

  GNUNET_SERVER_notification_context_destroy (snc);
  snc = NULL;
  GNUNET_CONTAINER_multihashmap_iterate(zonekeys, &zone_to_disk_it, NULL);
  GNUNET_CONTAINER_multihashmap_destroy(zonekeys);

  for (nc = client_head; nc != NULL; nc = next)
  {
    next = nc->next;
    for (no = nc->op_head; no != NULL; no = tmp)
    {
      GNUNET_CONTAINER_DLL_remove (nc->op_head, nc->op_tail, no);
      tmp = no->next;
      GNUNET_free (no);
    }
    GNUNET_SERVER_client_drop(nc->client);
    GNUNET_CONTAINER_DLL_remove (client_head, client_tail, nc);
    GNUNET_free (nc);
  }

  GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name, GSN_database));
  GNUNET_free (db_lib_name);
  GNUNET_free_non_null(zonefile_directory);
}

static struct GNUNET_NAMESTORE_Client *
client_lookup (struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_NAMESTORE_Client * nc;

  GNUNET_assert (NULL != client);

  for (nc = client_head; nc != NULL; nc = nc->next)
  {
    if (client == nc->client)
      break;
  }
  return nc;
}

/**
 * Called whenever a client is disconnected.  Frees our
 * resources associated with that client.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
client_disconnect_notification (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_NAMESTORE_ZoneIteration * no;
  struct GNUNET_NAMESTORE_Client * nc;
  if (NULL == client)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p disconnected \n", client);

  nc = client_lookup (client);

  if ((NULL == client) || (NULL == nc))
    return;

  no = nc->op_head;
  while (NULL != no)
  {
    GNUNET_CONTAINER_DLL_remove (nc->op_head, nc->op_tail, no);
    GNUNET_free (no);
    no = nc->op_head;
  }

  GNUNET_SERVER_client_drop(nc->client);
  GNUNET_CONTAINER_DLL_remove (client_head, client_tail, nc);
  GNUNET_free (nc);
  nc = NULL;
}



static void handle_start (void *cls,
                          struct GNUNET_SERVER_Client * client,
                          const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p connected\n", client);

  struct GNUNET_NAMESTORE_Client * nc = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_Client));
  nc->client = client;
  GNUNET_SERVER_notification_context_add (snc, client);
  GNUNET_CONTAINER_DLL_insert(client_head, client_tail, nc);
  GNUNET_SERVER_client_keep (client);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

struct LookupNameContext
{
  struct GNUNET_NAMESTORE_Client *nc;
  uint32_t request_id;
  uint32_t record_type;
  struct GNUNET_CRYPTO_ShortHashCode *zone;
  char * name;
};

void drop_iterator (void *cls,
                   const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                   struct GNUNET_TIME_Absolute expire,
                   const char *name,
                   unsigned int rd_len,
                   const struct GNUNET_NAMESTORE_RecordData *rd,
                   const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct GNUNET_CRYPTO_ShortHashCode zone_hash;
  int * stop = cls;
  if (NULL != zone_key)
  {
    GNUNET_CRYPTO_short_hash(zone_key, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), &zone_hash);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deleting zone `%s'\n", GNUNET_short_h2s (&zone_hash));
    GSN_database->delete_zone (GSN_database->cls, &zone_hash);
  }
  else
  {
    (*stop) = GNUNET_YES;
  }
}


static void
handle_lookup_name_it (void *cls,
    const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
    struct GNUNET_TIME_Absolute expire,
    const char *name,
    unsigned int rd_count,
    const struct GNUNET_NAMESTORE_RecordData *rd,
    const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  /* send response */
  struct LookupNameContext *lnc = cls;
  struct LookupNameResponseMessage *lnr_msg;
  struct GNUNET_NAMESTORE_RecordData *rd_selected = NULL;
  struct GNUNET_NAMESTORE_CryptoContainer *cc;
  struct GNUNET_CRYPTO_RsaSignature *signature_new = NULL;
  struct GNUNET_TIME_Absolute e;
  struct GNUNET_CRYPTO_ShortHashCode zone_key_hash;
  GNUNET_HashCode long_hash;
  char *rd_tmp;
  char *name_tmp;
  size_t rd_ser_len;
  size_t r_size = 0;
  size_t name_len = 0;

  int copied_elements = 0;
  int contains_signature = GNUNET_NO;
  int authoritative = GNUNET_NO;
  int c;

  if (NULL != name)
    name_len = strlen(name) + 1;

  /* count records to copy */
  if (rd_count != 0)
  {
    if (lnc->record_type != 0)
    {
      /* special record type needed */
      for (c = 0; c < rd_count; c ++)
        if (rd[c].record_type == lnc->record_type)
          copied_elements++; /* found matching record */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found %u records with type %u for name `%s' in zone `%s'\n",
          copied_elements, lnc->record_type, lnc->name, GNUNET_short_h2s(lnc->zone));
      rd_selected = GNUNET_malloc (copied_elements * sizeof (struct GNUNET_NAMESTORE_RecordData));
      copied_elements = 0;
      for (c = 0; c < rd_count; c ++)
      {
        if (rd[c].record_type == lnc->record_type)
        {
          /* found matching record */
          memcpy (&rd_selected[copied_elements], &rd[c], sizeof (struct GNUNET_NAMESTORE_RecordData));
          copied_elements++;
        }
      }
    }
    else
    {
      copied_elements = rd_count;
      rd_selected = (struct GNUNET_NAMESTORE_RecordData *) rd;
    }
  }
  else
  {
    /* No results */
    copied_elements = 0;
    rd_selected = NULL;
    expire = GNUNET_TIME_UNIT_ZERO_ABS;
  }

  rd_ser_len = GNUNET_NAMESTORE_records_get_size(copied_elements, rd_selected);
  char rd_ser[rd_ser_len];
  GNUNET_NAMESTORE_records_serialize(copied_elements, rd_selected, rd_ser_len, rd_ser);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found %u records for name `%s' in zone `%s'\n",
      copied_elements, lnc->name, GNUNET_short_h2s(lnc->zone));

  if ((copied_elements == rd_count) && (NULL != signature))
    contains_signature = GNUNET_YES; /* returning all records, so include signature */
  else
    contains_signature = GNUNET_NO; /* returning not all records, so do not include signature */


  if ((NULL != zone_key) && (copied_elements == rd_count))
  {
    GNUNET_CRYPTO_short_hash(zone_key, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), &zone_key_hash);
    GNUNET_CRYPTO_short_hash_double (&zone_key_hash, &long_hash);
    if (GNUNET_CONTAINER_multihashmap_contains(zonekeys, &long_hash))
    {
      cc = GNUNET_CONTAINER_multihashmap_get(zonekeys, &long_hash);
      e = get_block_expiration_time(rd_count, rd);
      signature_new = GNUNET_NAMESTORE_create_signature(cc->privkey, e, name, rd, rd_count);
      GNUNET_assert (signature_new != NULL);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating signature for name `%s' with %u records in zone `%s'\n",name, copied_elements, GNUNET_short_h2s(&zone_key_hash));
      authoritative = GNUNET_YES;
    }
    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "I am not authoritative for name `%s' in zone `%s'\n",name, GNUNET_short_h2s(&zone_key_hash));
  }

  r_size = sizeof (struct LookupNameResponseMessage) +
           sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) +
           name_len +
           rd_ser_len;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message\n", "NAMESTORE_LOOKUP_NAME_RESPONSE");
  lnr_msg = GNUNET_malloc (r_size);
  lnr_msg->gns_header.header.type = ntohs (GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME_RESPONSE);
  lnr_msg->gns_header.header.size = ntohs (r_size);
  lnr_msg->gns_header.r_id = htonl (lnc->request_id);
  lnr_msg->rd_count = htons (copied_elements);
  lnr_msg->rd_len = htons (rd_ser_len);
  lnr_msg->name_len = htons (name_len);
  lnr_msg->expire = GNUNET_TIME_absolute_hton(get_block_expiration_time(copied_elements, rd_selected));

  if (rd_selected != rd)
    GNUNET_free (rd_selected);

  if (zone_key != NULL)
    lnr_msg->public_key = (*zone_key);
  else
    memset(&lnr_msg->public_key, '\0', sizeof (lnr_msg->public_key));

  if (GNUNET_YES == authoritative)
  { /* use new created signature */
    lnr_msg->contains_sig = htons (GNUNET_YES);
    GNUNET_assert (signature_new != NULL);
    lnr_msg->signature = *signature_new;
    GNUNET_free (signature_new);
  }
  else if (GNUNET_YES == contains_signature)
  {
    /* use existing signature */
    lnr_msg->contains_sig = htons (GNUNET_YES);
    GNUNET_assert (signature != NULL);
    lnr_msg->signature = *signature;
  }
  else
  {
    /* use no signature */
    memset (&lnr_msg->signature, '\0', sizeof (lnr_msg->signature));
  }

  name_tmp = (char *) &lnr_msg[1];
  rd_tmp = &name_tmp[name_len];

  memcpy (name_tmp, name, name_len);
  memcpy (rd_tmp, rd_ser, rd_ser_len);

  GNUNET_SERVER_notification_context_unicast (snc, lnc->nc->client, (const struct GNUNET_MessageHeader *) lnr_msg, GNUNET_NO);
  GNUNET_free (lnr_msg);
}

static void handle_lookup_name (void *cls,
                          struct GNUNET_SERVER_Client * client,
                          const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "NAMESTORE_LOOKUP_NAME");
  struct LookupNameContext lnc;
  struct GNUNET_NAMESTORE_Client *nc;
  size_t name_len;
  char * name;
  uint32_t rid = 0;
  uint32_t type = 0;

  if (ntohs (message->size) < sizeof (struct LookupNameMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  nc = client_lookup(client);
  if (nc == NULL)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  struct LookupNameMessage * ln_msg = (struct LookupNameMessage *) message;
  rid = ntohl (ln_msg->gns_header.r_id);
  name_len = ntohl (ln_msg->name_len);
  type = ntohl (ln_msg->record_type);

  if ((name_len == 0) || (name_len > 256))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  name = (char *) &ln_msg[1];
  if (name[name_len -1] != '\0')
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  if (0 == type)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Looking up all records for name `%s' in zone `%s'\n", name, GNUNET_short_h2s(&ln_msg->zone));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Looking up records with type %u for name `%s' in zone `%s'\n", type, name, GNUNET_short_h2s(&ln_msg->zone));

  /* do the actual lookup */
  lnc.request_id = rid;
  lnc.nc = nc;
  lnc.record_type = type;
  lnc.name = name;
  lnc.zone = &ln_msg->zone;
  GSN_database->iterate_records(GSN_database->cls, &ln_msg->zone, name, 0, &handle_lookup_name_it, &lnc);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

static void handle_record_put (void *cls,
                          struct GNUNET_SERVER_Client * client,
                          const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "NAMESTORE_RECORD_PUT");
  struct GNUNET_NAMESTORE_Client *nc;
  struct GNUNET_TIME_Absolute expire;
  struct GNUNET_CRYPTO_RsaSignature *signature;
  struct RecordPutResponseMessage rpr_msg;
  size_t name_len;
  size_t msg_size;
  size_t msg_size_exp;
  char * name;
  char * rd_ser;
  uint32_t rid = 0;
  uint32_t rd_ser_len;
  uint32_t rd_count;
  int res = GNUNET_SYSERR;

  if (ntohs (message->size) < sizeof (struct RecordPutMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  nc = client_lookup (client);
  if (nc == NULL)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  struct RecordPutMessage * rp_msg = (struct RecordPutMessage *) message;

  rid = ntohl (rp_msg->gns_header.r_id);
  msg_size = ntohs (rp_msg->gns_header.header.size);
  name_len = ntohs (rp_msg->name_len);
  rd_count = ntohs (rp_msg->rd_count);
  rd_ser_len = ntohs(rp_msg->rd_len);

  if (msg_size > GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  if ((rd_count < 1) || (rd_ser_len < 1) || (name_len >=256) || (name_len == 0))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  msg_size_exp = sizeof (struct RecordPutMessage) +  name_len  + rd_ser_len;
  if (msg_size != msg_size_exp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Expected message %u size but message size is %u \n", msg_size_exp, msg_size);
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if ((name_len == 0) || (name_len > 256))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  name = (char *) &rp_msg[1];

  if (name[name_len -1] != '\0')
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  expire = GNUNET_TIME_absolute_ntoh(rp_msg->expire);
  signature = (struct GNUNET_CRYPTO_RsaSignature *) &rp_msg->signature;

  rd_ser = &name[name_len];
  struct GNUNET_NAMESTORE_RecordData rd[rd_count];
  res = GNUNET_NAMESTORE_records_deserialize(rd_ser_len, rd_ser, rd_count, rd);
  if (res != GNUNET_OK)
  {
    GNUNET_break_op (0);
    goto send;
  }

  struct GNUNET_CRYPTO_ShortHashCode zone_hash;
  GNUNET_CRYPTO_short_hash (&rp_msg->public_key, sizeof (rp_msg->public_key), &zone_hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Putting %u record for name `%s' in zone `%s'\n", rd_count, name, GNUNET_short_h2s(&zone_hash));

  /* Database operation */
  res = GSN_database->put_records(GSN_database->cls,
                                &rp_msg->public_key,
                                expire,
                                name,
                                rd_count, rd,
                                signature);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Putting record for name `%s': %s\n",
      name, (res == GNUNET_OK) ? "OK" : "FAIL");

  /* Send response */
send:
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message\n", "RECORD_PUT_RESPONSE");
  rpr_msg.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_PUT_RESPONSE);
  rpr_msg.gns_header.header.size = htons (sizeof (struct RecordPutResponseMessage));
  rpr_msg.gns_header.r_id = htonl (rid);
  rpr_msg.op_result = htonl (res);
  GNUNET_SERVER_notification_context_unicast (snc, nc->client, (const struct GNUNET_MessageHeader *) &rpr_msg, GNUNET_NO);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

struct CreateRecordContext
{
  struct GNUNET_NAMESTORE_RecordData *rd;
  struct GNUNET_CRYPTO_RsaPrivateKey *pkey;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pubkey;
  struct GNUNET_TIME_Absolute expire;
  char *name;
  int res;
};


static void
handle_create_record_it (void *cls,
    const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pubkey,
    struct GNUNET_TIME_Absolute expire,
    const char *name,
    unsigned int rd_count,
    const struct GNUNET_NAMESTORE_RecordData *rd,
    const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct CreateRecordContext * crc = cls;
  struct GNUNET_NAMESTORE_RecordData *rd_new = NULL;
  struct GNUNET_CRYPTO_RsaSignature dummy_signature;
  struct GNUNET_TIME_Absolute block_expiration;
  int res;
  int exist = GNUNET_SYSERR;
  int update = GNUNET_NO;
  int c;
  int rd_count_new = 0;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found %u existing records for `%s'\n", rd_count, crc->name);
  for (c = 0; c < rd_count; c++)
  {
    if ((crc->rd->record_type == GNUNET_NAMESTORE_TYPE_PKEY) && (rd[c].record_type == GNUNET_NAMESTORE_TYPE_PKEY))
    {
      /* Update unique PKEY */
      exist = c;
      update = GNUNET_YES;
     break;
    }
    else if ((crc->rd->record_type == GNUNET_NAMESTORE_TYPE_PSEU) && (rd[c].record_type == GNUNET_NAMESTORE_TYPE_PSEU))
    {
      /* Update unique PSEU */
      exist = c;
      update = GNUNET_YES;
     break;
    }
    else if ((crc->rd->record_type == rd[c].record_type) &&
        (crc->rd->data_size == rd[c].data_size) &&
        (0 == memcmp (crc->rd->data, rd[c].data, rd[c].data_size)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found existing records for `%s' to update expiration date!\n", crc->name);
      exist = c;
      if (crc->rd->expiration.abs_value != rd[c].expiration.abs_value)
        update = GNUNET_YES;
       break;
    }
  }

  if (exist == GNUNET_SYSERR)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "New record does not exist for name `%s'!\n", crc->name);

  if (exist == GNUNET_SYSERR)
  {
    rd_new = GNUNET_malloc ((rd_count+1) * sizeof (struct GNUNET_NAMESTORE_RecordData));
    memcpy (rd_new, rd, rd_count * sizeof (struct GNUNET_NAMESTORE_RecordData));
    rd_count_new = rd_count + 1;
    rd_new[rd_count] = *(crc->rd);
  }
  else if (update == GNUNET_NO)
  {
    /* Exact same record already exists */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No update for %s' record required!\n", crc->name);
    res = GNUNET_NO;
    goto end;
  }
  else if (update == GNUNET_YES)
  {
    /* Update record */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating existing records for `%s'!\n", crc->name);
    rd_new = GNUNET_malloc ((rd_count) * sizeof (struct GNUNET_NAMESTORE_RecordData));
    memcpy (rd_new, rd, rd_count * sizeof (struct GNUNET_NAMESTORE_RecordData));
    rd_count_new = rd_count;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating expiration from %llu to %llu!\n", rd_new[exist].expiration.abs_value, crc->rd->expiration.abs_value);
    rd_new[exist] = *(crc->rd);
  }

  block_expiration = GNUNET_TIME_absolute_max(crc->expire, expire);
  if (block_expiration.abs_value != expire.abs_value)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updated block expiration time\n");

  memset (&dummy_signature, '\0', sizeof (dummy_signature));

  /* Database operation */
  GNUNET_assert ((rd_new != NULL) && (rd_count_new > 0));
  res = GSN_database->put_records(GSN_database->cls,
                                (const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *) crc->pubkey,
                                block_expiration,
                                crc->name,
                                rd_count_new, rd_new,
                                &dummy_signature);
  GNUNET_break (GNUNET_OK == res);
  if (res == GNUNET_OK)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Successfully put record for `%s' in database \n", crc->name);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to put record for `%s' in database \n", crc->name);
  res = GNUNET_YES;

end:
  GNUNET_free_non_null (rd_new);

  switch (res) {
    case GNUNET_SYSERR:
       /* failed to create the record */
       crc->res = GNUNET_SYSERR;
      break;
    case GNUNET_YES:
      /* database operations OK */
      if (GNUNET_YES == update)
      {
        /* we updated an existing record */
        crc->res = GNUNET_NO;
      }
      else
      {
        /* we created a new record */
        crc->res = GNUNET_YES;
      }
      break;
    case GNUNET_NO:
        /* identical entry existed, so we did nothing */
        crc->res = GNUNET_NO;
      break;
    default:
      break;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Update result for name `%s' %u\n", crc->name, res);

}

static void handle_record_create (void *cls,
                          struct GNUNET_SERVER_Client * client,
                          const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "NAMESTORE_RECORD_CREATE");
  struct GNUNET_NAMESTORE_Client *nc;
  struct GNUNET_NAMESTORE_CryptoContainer *cc;
  struct CreateRecordContext crc;
  struct GNUNET_CRYPTO_RsaPrivateKey *pkey;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;
  struct RecordCreateResponseMessage rcr_msg;
  struct GNUNET_CRYPTO_ShortHashCode pubkey_hash;
  GNUNET_HashCode long_hash;
  size_t name_len;
  size_t msg_size;
  size_t msg_size_exp;
  size_t rd_ser_len;
  size_t key_len;
  uint32_t rid = 0;
  char *pkey_tmp;
  char *name_tmp;
  char *rd_ser;
  int rd_count;

  int res = GNUNET_SYSERR;
  crc.res = GNUNET_SYSERR;

  if (ntohs (message->size) < sizeof (struct RecordCreateMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  nc = client_lookup(client);
  if (nc == NULL)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  struct RecordCreateMessage * rp_msg = (struct RecordCreateMessage *) message;
  rid = ntohl (rp_msg->gns_header.r_id);
  name_len = ntohs (rp_msg->name_len);
  msg_size = ntohs (message->size);
  rd_count = ntohs (rp_msg->rd_count);
  rd_ser_len = ntohs (rp_msg->rd_len);
  key_len = ntohs (rp_msg->pkey_len);
  msg_size_exp = sizeof (struct RecordCreateMessage) + key_len + name_len + rd_ser_len;

  if (msg_size != msg_size_exp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Expected message %u size but message size is %u \n", msg_size_exp, msg_size);
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  if ((name_len == 0) || (name_len > 256))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  pkey_tmp = (char *) &rp_msg[1];
  name_tmp = &pkey_tmp[key_len];
  rd_ser = &name_tmp[name_len];

  if (name_tmp[name_len -1] != '\0')
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  struct GNUNET_NAMESTORE_RecordData rd[rd_count];

  res = GNUNET_NAMESTORE_records_deserialize(rd_ser_len, rd_ser, rd_count, rd);
  if ((res != GNUNET_OK) || (rd_count != 1))
  {
    GNUNET_break_op (0);
    goto send;
  }
  /* Extracting and converting private key */
  pkey = GNUNET_CRYPTO_rsa_decode_key((char *) pkey_tmp, key_len);
  GNUNET_assert (pkey != NULL);
  GNUNET_CRYPTO_rsa_key_get_public(pkey, &pub);
  GNUNET_CRYPTO_short_hash (&pub, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), &pubkey_hash);
  GNUNET_CRYPTO_short_hash_double (&pubkey_hash, &long_hash);

  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(zonekeys, &long_hash))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received new private key for zone `%s'\n",GNUNET_short_h2s(&pubkey_hash));

    cc = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_CryptoContainer));
    cc->privkey = GNUNET_CRYPTO_rsa_decode_key((char *) pkey_tmp, key_len);
    cc->pubkey = GNUNET_malloc(sizeof (pub));
    memcpy (cc->pubkey, &pub, sizeof(pub));
    cc->zone = pubkey_hash;
    GNUNET_CONTAINER_multihashmap_put(zonekeys, &long_hash, cc, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }

  crc.expire = GNUNET_TIME_absolute_ntoh(rp_msg->expire);
  crc.res = GNUNET_SYSERR;
  crc.pkey = pkey;
  crc.pubkey = &pub;
  crc.rd = rd;
  crc.name = name_tmp;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating record for name `%s' in zone `%s'\n", name_tmp, GNUNET_short_h2s(&pubkey_hash));

  /* Get existing records for name */
  res = GSN_database->iterate_records(GSN_database->cls, &pubkey_hash, name_tmp, 0, &handle_create_record_it, &crc);
  if (res != GNUNET_SYSERR)
    res = GNUNET_OK;
  GNUNET_CRYPTO_rsa_key_free(pkey);
  pkey = NULL;

  /* Send response */
send:
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message\n", "RECORD_CREATE_RESPONSE");
  rcr_msg.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE_RESPONSE);
  rcr_msg.gns_header.header.size = htons (sizeof (struct RecordCreateResponseMessage));
  rcr_msg.gns_header.r_id = htonl (rid);
  if ((GNUNET_OK == res) && (crc.res == GNUNET_YES))
    rcr_msg.op_result = htonl (GNUNET_YES);
  else if ((GNUNET_OK == res) && (crc.res == GNUNET_NO))
    rcr_msg.op_result = htonl (GNUNET_NO);
  else
    rcr_msg.op_result = htonl (GNUNET_SYSERR);
  GNUNET_SERVER_notification_context_unicast (snc, nc->client, (const struct GNUNET_MessageHeader *) &rcr_msg, GNUNET_NO);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


struct RemoveRecordContext
{
  struct GNUNET_NAMESTORE_RecordData *rd;
  struct GNUNET_CRYPTO_RsaPrivateKey *pkey;
  int remove_name;
  uint16_t op_res;
};

static void
handle_record_remove_it (void *cls,
    const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
    struct GNUNET_TIME_Absolute expire,
    const char *name,
    unsigned int rd_count,
    const struct GNUNET_NAMESTORE_RecordData *rd,
    const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct RemoveRecordContext *rrc = cls;
  unsigned int c;
  int res;
  int found;
  unsigned int rd_count_new;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Name `%s 'currently has %u records\n", name, rd_count);

  if (rd_count == 0)
  {
    /* Could not find record to remove */
    rrc->op_res = 1;
    return;
  }

  /* Find record to remove */
  found = GNUNET_SYSERR;
  for (c = 0; c < rd_count; c++)
  {
    /*
    if (rd[c].flags != rrc->rd->flags)
       continue;*/
    if (rd[c].record_type != rrc->rd->record_type)
       continue;
    /*
    if (rd[c].data_size != rrc->rd->data_size)
       continue;
    GNUNET_break(0);
    if (0 != memcmp (rd[c].data, rrc->rd->data, rrc->rd->data_size))
        continue;
    GNUNET_break(0); */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found record to remove!\n", rd_count);
    found = c;
    break;
  }
  if (GNUNET_SYSERR == found)
  {
    /* Could not find record to remove */
    rrc->op_res = 2;
    return;
  }

  if (rd_count-1 == 0)
  {
    struct GNUNET_CRYPTO_ShortHashCode pubkey_hash;
    GNUNET_CRYPTO_short_hash (zone_key, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), &pubkey_hash);
    res = GSN_database->remove_records (GSN_database->cls,
                                        &pubkey_hash,
                                        name);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No records left for name `%s', removing name\n",
                name, res);
    if (GNUNET_OK != res)
    {
      /* Could put records into database */
      rrc->op_res = 4;
      return;
    }
    rrc->op_res = 0;
    return;
  }

  rd_count_new = rd_count -1;
  struct GNUNET_NAMESTORE_RecordData rd_new[rd_count_new];

  unsigned int c2 = 0;
  for (c = 0; c < rd_count; c++)
  {
    if (c != found)
    {
      GNUNET_assert (c2 < rd_count_new);
      rd_new[c2] = rd[c];
      c2++;
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Name `%s' now has %u records\n", name, rd_count_new);

  /* Create dummy signature */
  struct GNUNET_CRYPTO_RsaSignature dummy_signature;
  memset (&dummy_signature, '\0', sizeof (dummy_signature));


  /* Put records */
  res = GSN_database->put_records(GSN_database->cls,
                                  zone_key,
                                  expire,
                                  name,
                                  rd_count_new, rd_new,
                                  &dummy_signature);
  if (GNUNET_OK != res)
  {
    /* Could put records into database */
    rrc->op_res = 4;
    return;
  }

  rrc->op_res = 0;
}

static void handle_record_remove (void *cls,
                          struct GNUNET_SERVER_Client * client,
                          const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "NAMESTORE_RECORD_REMOVE");
  struct GNUNET_NAMESTORE_Client *nc;
  struct RecordRemoveResponseMessage rrr_msg;
  struct GNUNET_CRYPTO_RsaPrivateKey *pkey;
  struct GNUNET_NAMESTORE_CryptoContainer *cc = NULL;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;
  struct GNUNET_CRYPTO_ShortHashCode pubkey_hash;
  GNUNET_HashCode long_hash;
  char * pkey_tmp = NULL;
  char * name_tmp = NULL;
  char * rd_ser = NULL;
  size_t key_len = 0;
  size_t name_len = 0;
  size_t rd_ser_len = 0;
  size_t msg_size = 0;
  size_t msg_size_exp = 0;
  uint32_t rd_count;
  uint32_t rid = 0;

  int res = GNUNET_SYSERR;

  if (ntohs (message->size) < sizeof (struct RecordRemoveMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  nc = client_lookup(client);
  if (nc == NULL)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  struct RecordRemoveMessage * rr_msg = (struct RecordRemoveMessage *) message;
  rid = ntohl (rr_msg->gns_header.r_id);
  name_len = ntohs (rr_msg->name_len);
  rd_ser_len = ntohs (rr_msg->rd_len);
  rd_count = ntohs (rr_msg->rd_count);
  key_len = ntohs (rr_msg->pkey_len);
  msg_size = ntohs (message->size);

  if (msg_size > GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  if ((name_len >=256) || (name_len == 0))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  msg_size_exp = sizeof (struct RecordRemoveMessage) + key_len + name_len + rd_ser_len;
  if (msg_size != msg_size_exp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Expected message %u size but message size is %u \n", msg_size_exp, msg_size);
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  pkey_tmp = (char *) &rr_msg[1];
  name_tmp = &pkey_tmp[key_len];
  rd_ser = &name_tmp[name_len];


  if ((name_len == 0) || (name_len > 256))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  if (name_tmp[name_len -1] != '\0')
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  /* Extracting and converting private key */
  pkey = GNUNET_CRYPTO_rsa_decode_key((char *) pkey_tmp, key_len);
  GNUNET_assert (pkey != NULL);
  GNUNET_CRYPTO_rsa_key_get_public(pkey, &pub);
  GNUNET_CRYPTO_short_hash (&pub, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), &pubkey_hash);
  GNUNET_CRYPTO_short_hash_double (&pubkey_hash, &long_hash);

  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(zonekeys, &long_hash))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received new private key for zone `%s'\n",GNUNET_short_h2s(&pubkey_hash));
    cc = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_CryptoContainer));
    cc->privkey = GNUNET_CRYPTO_rsa_decode_key((char *) pkey_tmp, key_len);
    cc->pubkey = GNUNET_malloc(sizeof (pub));
    memcpy (cc->pubkey, &pub, sizeof(pub));
    cc->zone = pubkey_hash;

    GNUNET_CONTAINER_multihashmap_put(zonekeys, &long_hash, cc, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }


  struct GNUNET_NAMESTORE_RecordData rd[rd_count];
  res = GNUNET_NAMESTORE_records_deserialize(rd_ser_len, rd_ser, rd_count, rd);
  if ((res != GNUNET_OK) || (rd_count > 1))
  {
    GNUNET_break_op (0);
    goto send;
  }

  if (0 == rd_count)
  {
    /* remove the whole name and all records */
    /* Database operation */
    res = GSN_database->remove_records (GSN_database->cls,
                                         &pubkey_hash,
                                         name_tmp);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Removing name `%s': %s\n",
        name_tmp, (GNUNET_OK == res) ? "OK" : "FAIL");

    if (GNUNET_OK != res)
      /* Could not remove entry from database */
      res = 4;
    else
      res = 0;
  }
  else
  {
    /* remove a single record */
    struct RemoveRecordContext rrc;
    rrc.rd = rd;
    rrc.pkey = pkey;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Removing record for name `%s' in zone `%s'\n", name_tmp, GNUNET_short_h2s(&pubkey_hash));

    /* Database operation */
    res = GSN_database->iterate_records (GSN_database->cls,
                                         &pubkey_hash,
                                         name_tmp,
                                         0,
                                         handle_record_remove_it, &rrc);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Removing record for name `%s': %s\n",
        name_tmp, (rrc.op_res == 0) ? "OK" : "FAIL");
    res = rrc.op_res;
  }
  /* Send response */
send:
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message\n", "RECORD_REMOVE_RESPONSE");
  rrr_msg.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_REMOVE_RESPONSE);
  rrr_msg.gns_header.header.size = htons (sizeof (struct RecordRemoveResponseMessage));
  rrr_msg.gns_header.r_id = htonl (rid);
  rrr_msg.op_result = htonl (res);
  GNUNET_SERVER_notification_context_unicast (snc, nc->client, (const struct GNUNET_MessageHeader *) &rrr_msg, GNUNET_NO);

  GNUNET_CRYPTO_rsa_key_free (pkey);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


struct ZoneToNameCtx
{
  struct GNUNET_NAMESTORE_Client *nc;
  uint32_t rid;
};

static void
handle_zone_to_name_it (void *cls,
    const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
    struct GNUNET_TIME_Absolute expire,
    const char *name,
    unsigned int rd_count,
    const struct GNUNET_NAMESTORE_RecordData *rd,
    const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ZoneToNameCtx * ztn_ctx = cls;
  struct ZoneToNameResponseMessage *ztnr_msg;
  int16_t res = GNUNET_SYSERR;
  uint16_t name_len = 0;
  uint16_t rd_ser_len = 0 ;
  int32_t contains_sig = 0;
  size_t msg_size = 0;

  char *rd_ser = NULL;
  char *name_tmp;
  char *rd_tmp;
  char *sig_tmp;

  if ((zone_key != NULL) && (name != NULL))
  {
    /* found result */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found results: name is `%s', has %u records\n", name, rd_count);
    res = GNUNET_YES;
    name_len = strlen (name) +1;
  }
  else
  {
    /* no result found */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found no results\n");
    res = GNUNET_NO;
    name_len = 0;
  }

  if (rd_count > 0)
  {
    rd_ser_len = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
    rd_ser = GNUNET_malloc (rd_ser_len);
    GNUNET_NAMESTORE_records_serialize(rd_count, rd, rd_ser_len, rd_ser);
  }
  else
    rd_ser_len = 0;

  if (signature != NULL)
    contains_sig = GNUNET_YES;
  else
    contains_sig = GNUNET_NO;



  msg_size = sizeof (struct ZoneToNameResponseMessage) + name_len + rd_ser_len + contains_sig * sizeof (struct GNUNET_CRYPTO_RsaSignature);
  ztnr_msg = GNUNET_malloc (msg_size);

  name_tmp = (char *) &ztnr_msg[1];
  rd_tmp = &name_tmp[name_len];
  sig_tmp = &rd_tmp[rd_ser_len];

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message\n", "ZONE_TO_NAME_RESPONSE");
  ztnr_msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE);
  ztnr_msg->gns_header.header.size = htons (msg_size);
  ztnr_msg->gns_header.r_id = htonl (ztn_ctx->rid);
  ztnr_msg->res = htons (res);
  ztnr_msg->rd_len = htons (rd_ser_len);
  ztnr_msg->rd_count = htons (rd_count);
  ztnr_msg->name_len = htons (name_len);
  ztnr_msg->expire = GNUNET_TIME_absolute_hton(expire);
  if (zone_key != NULL)
    ztnr_msg->zone_key = *zone_key;
  else
    memset (&ztnr_msg->zone_key, '\0', sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));

  if ((name_len > 0) && (name != NULL))
    memcpy (name_tmp, name, name_len);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Name is `%s', has %u records, rd ser len %u msg_size %u\n", name, rd_count, rd_ser_len, msg_size);
  if ((rd_ser_len > 0) && (rd_ser != NULL))
    memcpy (rd_tmp, rd_ser, rd_ser_len);
  if ((GNUNET_YES == contains_sig) && (signature != NULL))
    memcpy (sig_tmp, signature, contains_sig * sizeof (struct GNUNET_CRYPTO_RsaSignature));

  GNUNET_SERVER_notification_context_unicast (snc, ztn_ctx->nc->client, (const struct GNUNET_MessageHeader *) ztnr_msg, GNUNET_NO);
  GNUNET_free (ztnr_msg);
  GNUNET_free_non_null (rd_ser);
}


static void handle_zone_to_name (void *cls,
                          struct GNUNET_SERVER_Client * client,
                          const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "ZONE_TO_NAME");
  struct GNUNET_NAMESTORE_Client *nc;
  struct ZoneToNameCtx ztn_ctx;
  size_t msg_size = 0;
  uint32_t rid = 0;

  if (ntohs (message->size) != sizeof (struct ZoneToNameMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  nc = client_lookup(client);
  if (nc == NULL)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  struct ZoneToNameMessage *ztn_msg = (struct ZoneToNameMessage *) message;

  if (msg_size > GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  rid = ntohl (ztn_msg->gns_header.r_id);

  ztn_ctx.rid = rid;
  ztn_ctx.nc = nc;

  struct GNUNET_CRYPTO_ShortHashAsciiEncoded z_tmp;
  GNUNET_CRYPTO_short_hash_to_enc(&ztn_msg->zone, &z_tmp);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Looking up name for zone `%s' in zone `%s'\n",
      (char *) &z_tmp,
      GNUNET_short_h2s (&ztn_msg->value_zone));

  GSN_database->zone_to_name (GSN_database->cls, &ztn_msg->zone, &ztn_msg->value_zone, &handle_zone_to_name_it, &ztn_ctx);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Copy record, data has to be free separetely
 */
void
copy_record (const struct GNUNET_NAMESTORE_RecordData *src, struct GNUNET_NAMESTORE_RecordData *dest)
{

  memcpy (dest, src, sizeof (struct GNUNET_NAMESTORE_RecordData));
  dest->data = GNUNET_malloc (src->data_size);
  memcpy ((void *) dest->data, src->data, src->data_size);
}

struct ZoneIterationProcResult
{
  struct GNUNET_NAMESTORE_ZoneIteration *zi;

  int res_iteration_finished;
  int records_included;
  int has_signature;

  char *name;
  struct GNUNET_CRYPTO_ShortHashCode zone_hash;
  struct GNUNET_NAMESTORE_RecordData *rd;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded zone_key;
  struct GNUNET_CRYPTO_RsaSignature signature;
  struct GNUNET_TIME_Absolute expire;
};


void zone_iteraterate_proc (void *cls,
                         const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                         struct GNUNET_TIME_Absolute expire,
                         const char *name,
                         unsigned int rd_count,
                         const struct GNUNET_NAMESTORE_RecordData *rd,
                         const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ZoneIterationProcResult *proc = cls;
  struct GNUNET_NAMESTORE_RecordData *rd_filtered;
  struct GNUNET_CRYPTO_RsaSignature * new_signature;
  struct GNUNET_NAMESTORE_CryptoContainer *cc;
  struct GNUNET_CRYPTO_ShortHashCode hash;
  GNUNET_HashCode long_hash;
  struct GNUNET_TIME_Absolute e;
  unsigned int rd_count_filtered  = 0;
  int include;
  int c;

  proc->res_iteration_finished = GNUNET_NO;
  proc->records_included = 0;

  if ((zone_key == NULL) && (name == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Iteration done\n");
    proc->res_iteration_finished = GNUNET_YES;
    proc->rd = NULL;
    proc->name = NULL;
  }
  else if ((zone_key != NULL) && (name != NULL)) /* just a safety check */
  {
    rd_filtered = GNUNET_malloc (rd_count * sizeof (struct GNUNET_NAMESTORE_RecordData));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received result for zone iteration: `%s'\n", name);
    for (c = 0; c < rd_count; c++)
    {
      include = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Record %i has flags: 0x%x must have 0x%x \n",
          c, rd[c].flags, proc->zi->must_have_flags);
      /* Checking must have flags */
      if ((rd[c].flags & proc->zi->must_have_flags) == proc->zi->must_have_flags)
      {
        /* Include */
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Record %i has flags: Include \n", c);
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Record %i has flags: Not include \n", c);
        include = GNUNET_NO;
      }

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Record %i has flags: 0x%x must not have 0x%x\n",
          c, rd[c].flags, proc->zi->must_not_have_flags);
      if ((rd[c].flags & proc->zi->must_not_have_flags) != 0)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Record %i has flags: Not include \n", c);
        include = GNUNET_NO;
      }
      else
      {
        /* Include */
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Record %i has flags: Include \n", c);
      }
      if (GNUNET_YES == include)
      {
        copy_record (&rd[c], &rd_filtered[rd_count_filtered]);
        rd_count_filtered++;
      }

    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Included %i of %i records \n", rd_count_filtered, rd_count);

    proc->records_included = rd_count_filtered;
    if (0 == rd_count_filtered)
    {
      GNUNET_free (rd_filtered);
      rd_filtered = NULL;
    }
    proc->rd = rd_filtered;
    proc->name = GNUNET_strdup(name);
    memcpy (&proc->zone_key, zone_key, sizeof (proc->zone_key));

    /* Signature */
    proc->has_signature = GNUNET_NO;
    GNUNET_CRYPTO_short_hash (zone_key, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), &hash);
    GNUNET_CRYPTO_short_hash_double(&hash, &long_hash);
    proc->zone_hash = hash;

    if (GNUNET_CONTAINER_multihashmap_contains(zonekeys, &long_hash))
    {
      cc = GNUNET_CONTAINER_multihashmap_get(zonekeys, &long_hash);
      e = get_block_expiration_time(rd_count_filtered, rd_filtered);
      proc->expire = e;
      new_signature = GNUNET_NAMESTORE_create_signature(cc->privkey, e, name, rd_filtered, rd_count_filtered);
      GNUNET_assert (signature != NULL);
      proc->signature = (*new_signature);
      GNUNET_free (new_signature);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating signature for `%s' in zone `%s' with %u records and expiration %llu\n",
          name, GNUNET_short_h2s(&hash), rd_count_filtered, e.abs_value);
      proc->has_signature = GNUNET_YES;
    }
    else if (rd_count_filtered == rd_count)
    {
      proc->expire = expire;
      if (NULL != signature)
      {
        proc->signature = (*signature);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Using provided signature for `%s' in zone `%s' with %u records and expiration %llu\n",
            name, GNUNET_short_h2s(&hash), rd_count_filtered, expire.abs_value);
        proc->has_signature = GNUNET_YES;
      }
      else
      {
        memset (&proc->signature, '\0', sizeof (proc->signature));
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No signature provided for `%s'\n", name);
      }
    }
  }
  else
  {
    GNUNET_break (0);
    return;
  }

}

void find_next_zone_iteration_result (struct ZoneIterationProcResult *proc)
{

  struct GNUNET_CRYPTO_ShortHashCode *zone;

  if (GNUNET_YES == proc->zi->has_zone)
    zone = &proc->zi->zone;
  else
    zone = NULL;

  do
  {
    GSN_database->iterate_records (GSN_database->cls, zone , NULL, proc->zi->offset, &zone_iteraterate_proc, proc);
    proc->zi->offset++;
  }
  while ((proc->records_included == 0) && (GNUNET_NO == proc->res_iteration_finished));
}


void send_zone_iteration_result (struct ZoneIterationProcResult *proc)
{
  struct GNUNET_NAMESTORE_ZoneIteration *zi = proc->zi;

  if (GNUNET_YES == proc->res_iteration_finished)
  {
    struct ZoneIterationResponseMessage zir_msg;
    if (zi->has_zone == GNUNET_YES)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No more results for zone `%s'\n", GNUNET_short_h2s(&zi->zone));
    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No more results for all zones\n");

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending empty `%s' message\n", "ZONE_ITERATION_RESPONSE");
    zir_msg.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_RESPONSE);
    zir_msg.gns_header.header.size = htons (sizeof (struct ZoneIterationResponseMessage));
    zir_msg.gns_header.r_id = htonl(zi->request_id);
    zir_msg.expire = GNUNET_TIME_absolute_hton(GNUNET_TIME_UNIT_ZERO_ABS);
    zir_msg.name_len = htons (0);
    zir_msg.reserved = htons (0);
    zir_msg.rd_count = htons (0);
    zir_msg.rd_len = htons (0);
    memset (&zir_msg.public_key, '\0', sizeof (zir_msg.public_key));
    memset (&zir_msg.signature, '\0', sizeof (zir_msg.signature));
    GNUNET_SERVER_notification_context_unicast (snc, zi->client->client, (const struct GNUNET_MessageHeader *) &zir_msg, GNUNET_NO);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Removing zone iterator\n");
    GNUNET_CONTAINER_DLL_remove (zi->client->op_head, zi->client->op_tail, zi);
    GNUNET_free (zi);
    return;
  }
  else
  {
    GNUNET_assert (proc->records_included > 0);

    struct ZoneIterationResponseMessage *zir_msg;
    if (zi->has_zone == GNUNET_YES)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending name `%s' for iteration over zone `%s'\n",
          proc->name, GNUNET_short_h2s(&zi->zone));
    if (zi->has_zone == GNUNET_NO)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending name `%s' for iteration over all zones\n",
          proc->name);

    size_t name_len;
    size_t rd_ser_len;
    size_t msg_size;
    char *name_tmp;
    char *rd_tmp;
    name_len = strlen (proc->name) +1;

    rd_ser_len = GNUNET_NAMESTORE_records_get_size(proc->records_included, proc->rd);
    char rd_ser[rd_ser_len];
    GNUNET_NAMESTORE_records_serialize(proc->records_included, proc->rd, rd_ser_len, rd_ser);
    msg_size = sizeof (struct ZoneIterationResponseMessage) + name_len + rd_ser_len;
    zir_msg = GNUNET_malloc(msg_size);

    name_tmp = (char *) &zir_msg[1];
    rd_tmp = &name_tmp[name_len];

    zir_msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_RESPONSE);
    zir_msg->gns_header.header.size = htons (msg_size);
    zir_msg->gns_header.r_id = htonl(zi->request_id);
    zir_msg->expire = GNUNET_TIME_absolute_hton(proc->expire);
    zir_msg->reserved = htons (0);
    zir_msg->name_len = htons (name_len);
    zir_msg->rd_count = htons (proc->records_included);
    zir_msg->rd_len = htons (rd_ser_len);
    zir_msg->signature = proc->signature;
    zir_msg->public_key = proc->zone_key;
    memcpy (name_tmp, proc->name, name_len);
    memcpy (rd_tmp, rd_ser, rd_ser_len);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message with size %u\n", "ZONE_ITERATION_RESPONSE", msg_size);
    GNUNET_SERVER_notification_context_unicast (snc, zi->client->client, (const struct GNUNET_MessageHeader *) zir_msg, GNUNET_NO);
    GNUNET_free (zir_msg);
  }
}

void clean_up_zone_iteration_result (struct ZoneIterationProcResult *proc)
{
  int c;
  GNUNET_free_non_null (proc->name);
  for (c = 0; c < proc->records_included; c++)
  {
    GNUNET_free ((void *) proc->rd[c].data);
  }
  GNUNET_free_non_null (proc->rd);
  proc->name = NULL;
  proc->rd = NULL;
}

static void handle_iteration_start (void *cls,
                          struct GNUNET_SERVER_Client * client,
                          const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "ZONE_ITERATION_START");

  struct ZoneIterationStartMessage * zis_msg = (struct ZoneIterationStartMessage *) message;
  struct GNUNET_NAMESTORE_Client *nc;
  struct GNUNET_NAMESTORE_ZoneIteration *zi;

  nc = client_lookup(client);
  if (nc == NULL)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  zi = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_ZoneIteration));
  zi->request_id = ntohl (zis_msg->gns_header.r_id);
  zi->offset = 0;
  zi->client = nc;
  zi->must_have_flags = ntohs (zis_msg->must_have_flags);
  zi->must_not_have_flags = ntohs (zis_msg->must_not_have_flags);

  struct GNUNET_CRYPTO_ShortHashCode dummy;
  memset (&dummy, '\0', sizeof (dummy));
  if (0 == memcmp (&dummy, &zis_msg->zone, sizeof (dummy)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting to iterate over all zones\n");
    zi->zone = zis_msg->zone;
    zi->has_zone = GNUNET_NO;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting to iterate over zone  `%s'\n", GNUNET_short_h2s (&zis_msg->zone));
    zi->zone = zis_msg->zone;
    zi->has_zone = GNUNET_YES;
  }

  GNUNET_CONTAINER_DLL_insert (nc->op_head, nc->op_tail, zi);

  struct ZoneIterationProcResult proc;
  proc.zi = zi;

  find_next_zone_iteration_result (&proc);
  if (GNUNET_YES == proc.res_iteration_finished)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Zone iteration done\n");
  }
  else if (proc.records_included != 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Zone iteration return %u records\n", proc.records_included);
  }
  send_zone_iteration_result (&proc);
  clean_up_zone_iteration_result (&proc);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

static void handle_iteration_stop (void *cls,
                          struct GNUNET_SERVER_Client * client,
                          const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "ZONE_ITERATION_STOP");

  struct GNUNET_NAMESTORE_Client *nc;
  struct GNUNET_NAMESTORE_ZoneIteration *zi;
  struct ZoneIterationStopMessage * zis_msg = (struct ZoneIterationStopMessage *) message;
  uint32_t rid;

  nc = client_lookup(client);
  if (nc == NULL)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  rid = ntohl (zis_msg->gns_header.r_id);
  for (zi = nc->op_head; zi != NULL; zi = zi->next)
  {
    if (zi->request_id == rid)
      break;
  }
  if (zi == NULL)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  GNUNET_CONTAINER_DLL_remove(nc->op_head, nc->op_tail, zi);
  if (GNUNET_YES == zi->has_zone)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopped zone iteration for zone `%s'\n", GNUNET_short_h2s (&zi->zone));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopped zone iteration all zones\n");
  GNUNET_free (zi);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

static void handle_iteration_next (void *cls,
                          struct GNUNET_SERVER_Client * client,
                          const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "ZONE_ITERATION_NEXT");

  struct GNUNET_NAMESTORE_Client *nc;
  struct GNUNET_NAMESTORE_ZoneIteration *zi;
  struct ZoneIterationStopMessage * zis_msg = (struct ZoneIterationStopMessage *) message;
  uint32_t rid;

  nc = client_lookup(client);
  if (nc == NULL)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  rid = ntohl (zis_msg->gns_header.r_id);
  for (zi = nc->op_head; zi != NULL; zi = zi->next)
  {
    if (zi->request_id == rid)
      break;
  }
  if (zi == NULL)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  struct ZoneIterationProcResult proc;
  proc.zi = zi;

  find_next_zone_iteration_result (&proc);
  if (GNUNET_YES == proc.res_iteration_finished)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Zone iteration done\n");
  }
  else if (proc.records_included != 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Zone iteration return %u records\n", proc.records_included);
  }
  send_zone_iteration_result (&proc);
  clean_up_zone_iteration_result (&proc);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

int zonekey_file_it (void *cls, const char *filename)
{
  GNUNET_HashCode long_hash;
  int *counter = cls;
   if ((filename != NULL) && (NULL != strstr(filename, ".zkey")))
   {
     struct GNUNET_CRYPTO_RsaPrivateKey * privkey;
     struct GNUNET_NAMESTORE_CryptoContainer *c;
     privkey = GNUNET_CRYPTO_rsa_key_create_from_file(filename);
     if (privkey == NULL)
       return GNUNET_OK;

     c = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_CryptoContainer));
     c->pubkey = GNUNET_malloc(sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
     c->privkey = privkey;
     GNUNET_CRYPTO_rsa_key_get_public(privkey, c->pubkey);
     GNUNET_CRYPTO_short_hash(c->pubkey, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), &c->zone);

     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found zonefile for zone `%s'\n", GNUNET_short_h2s (&c->zone));
     GNUNET_CRYPTO_short_hash_double (&c->zone, &long_hash);
     GNUNET_CONTAINER_multihashmap_put(zonekeys, &long_hash, c, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
     (*counter) ++;
   }
   return GNUNET_OK;
}


/**
 * Process template requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char * database;
  int counter = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting namestore service\n");

  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_start, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_START, sizeof (struct StartMessage)},
    {&handle_lookup_name, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME, 0},
    {&handle_record_put, NULL,
    GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_PUT, 0},
    {&handle_record_create, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE, 0},
    {&handle_record_remove, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_REMOVE, 0},
    {&handle_zone_to_name, NULL,
      GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME, 0},
    {&handle_iteration_start, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START, sizeof (struct ZoneIterationStartMessage)},
    {&handle_iteration_next, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT, 0},
     {&handle_iteration_stop, NULL,
      GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP, 0},
    {NULL, NULL, 0, 0}
  };

  GSN_cfg = cfg;

  /* Load private keys from disk */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "namestore", "zonefile_directory",
                                             &zonefile_directory))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("No directory to load zonefiles specified in configuration\n"));
    GNUNET_SCHEDULER_add_now (&cleanup_task, NULL);
    return;
  }

  if (GNUNET_NO == GNUNET_DISK_file_test (zonefile_directory))
  {
    if (GNUNET_SYSERR == GNUNET_DISK_directory_create (zonefile_directory))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Creating directory `%s' for zone files failed!\n"), zonefile_directory);
      GNUNET_SCHEDULER_add_now (&cleanup_task, NULL);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created directory `%s' for zone files\n", zonefile_directory);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Scanning directory `%s' for zone files\n", zonefile_directory);
  zonekeys = GNUNET_CONTAINER_multihashmap_create (10);
  GNUNET_DISK_directory_scan (zonefile_directory, zonekey_file_it, &counter);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found %u zone files\n", counter);

  /* Loading database plugin */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "namestore", "database",
                                             &database))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No database backend configured\n");

  GNUNET_asprintf (&db_lib_name, "libgnunet_plugin_namestore_%s", database);
  GSN_database = GNUNET_PLUGIN_load (db_lib_name, (void *) GSN_cfg);
  GNUNET_free (database);
  if (GSN_database == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not load database backend `%s'\n",
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
          GNUNET_SERVICE_run (argc, argv, "namestore",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-namestore.c */

