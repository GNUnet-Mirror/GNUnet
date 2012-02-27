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
#include "namestore.h"



/**
 * A namestore operation.
 */
struct GNUNET_NAMESTORE_Operation
{
  struct GNUNET_NAMESTORE_Operation *next;
  struct GNUNET_NAMESTORE_Operation *prev;

  uint64_t op_id;

  char *data; /*stub data pointer*/
};


/**
 * A namestore client
 */
struct GNUNET_NAMESTORE_Client
{
  struct GNUNET_NAMESTORE_Client *next;
  struct GNUNET_NAMESTORE_Client *prev;

  struct GNUNET_SERVER_Client * client;

  struct GNUNET_NAMESTORE_Operation *op_head;
  struct GNUNET_NAMESTORE_Operation *op_tail;
};



/**
 * Configuration handle.
 */
const struct GNUNET_CONFIGURATION_Handle *GSN_cfg;

static struct GNUNET_NAMESTORE_PluginFunctions *GSN_database;

/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *snc;

static char *db_lib_name;

static struct GNUNET_NAMESTORE_Client *client_head;
static struct GNUNET_NAMESTORE_Client *client_tail;


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

  struct GNUNET_NAMESTORE_Operation * no;
  struct GNUNET_NAMESTORE_Operation * tmp;
  struct GNUNET_NAMESTORE_Client * nc;
  struct GNUNET_NAMESTORE_Client * next;

  for (nc = client_head; nc != NULL; nc = next)
  {
    next = nc->next;
    for (no = nc->op_head; no != NULL; no = tmp)
    {
      GNUNET_CONTAINER_DLL_remove (nc->op_head, nc->op_tail, no);
      tmp = no->next;
      GNUNET_free (no);
    }

    GNUNET_CONTAINER_DLL_remove (client_head, client_tail, nc);
    GNUNET_free (nc);

  }

  GNUNET_SERVER_notification_context_destroy (snc);
  snc = NULL;

  GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name, GSN_database));
  GNUNET_free (db_lib_name);
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
  struct GNUNET_NAMESTORE_Operation * no;
  struct GNUNET_NAMESTORE_Client * nc;
  if (NULL == client)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p disconnected \n", client);

  nc = client_lookup (client);

  if ((NULL == client) || (NULL == nc))
    return;

  for (no = nc->op_head; no != NULL; no = no->next)
  {
    GNUNET_CONTAINER_DLL_remove (nc->op_head, nc->op_tail, no);
    GNUNET_free (no);
  }

  GNUNET_CONTAINER_DLL_remove (client_head, client_tail, nc);
  GNUNET_free (nc);
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

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

struct LookupNameContext
{
  struct GNUNET_NAMESTORE_Client *nc;
  uint32_t id;
  uint32_t record_type;
};


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

  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key_tmp;
  struct GNUNET_NAMESTORE_RecordData * rd_tmp;
  char *name_tmp;
  struct GNUNET_CRYPTO_RsaSignature *signature_tmp;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message\n", "NAMESTORE_LOOKUP_NAME_RESPONSE");

  size_t r_size = 0;

  size_t name_len = 0;
  if (NULL != name)
    name_len = strlen(name) + 1;

  int copied_elements = 0;
  int contains_signature = 0;
  int c;

  /* count records to copy */
  if (rd_count != 0)
  {
    if (lnc->record_type != 0)
    {
      /* special record type needed */
      for (c = 0; c < rd_count; c ++)
        if (rd[c].record_type == lnc->record_type)
          copied_elements++; /* found matching record */
    }
    else
      copied_elements = rd_count;
  }

  if ((copied_elements == rd_count) && (signature != NULL))
      contains_signature = GNUNET_YES;

  r_size = sizeof (struct LookupNameResponseMessage) +
           sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) +
           name_len +
           copied_elements * sizeof (struct GNUNET_NAMESTORE_RecordData) +
           contains_signature * sizeof (struct GNUNET_CRYPTO_RsaSignature);

  lnr_msg = GNUNET_malloc (r_size);

  lnr_msg->header.type = ntohs (GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME_RESPONSE);
  lnr_msg->header.size = ntohs (r_size);
  lnr_msg->op_id = htonl (lnc->id);
  lnr_msg->rc_count = htonl (copied_elements);
  lnr_msg->name_len = htons (name_len);
  lnr_msg->expire = GNUNET_TIME_absolute_hton(expire);
  lnr_msg->contains_sig = htons (contains_signature);


  zone_key_tmp =  (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *) &lnr_msg[1];
  name_tmp = (char *) &zone_key_tmp[1];
  rd_tmp = (struct GNUNET_NAMESTORE_RecordData *) &name_tmp[name_len];
  signature_tmp = (struct GNUNET_CRYPTO_RsaSignature *) &rd_tmp[copied_elements];

  if (zone_key != NULL)
    memcpy (zone_key_tmp, zone_key, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  else
  {
    struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded dummy;
    memset (&dummy, '0', sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
    memcpy (zone_key_tmp, &dummy, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  }
  memcpy (name_tmp, name, name_len);
  /* copy records */
  copied_elements = 0;
  if (rd_count != 0)
  {
    if (lnc->record_type != 0)
    {
      /* special record type needed */
      for (c = 0; c < rd_count; c ++)
        if (rd[c].record_type == lnc->record_type)
        {
          /* found matching record */
          memcpy (&rd_tmp[copied_elements], &rd[c], rd_count * sizeof (struct GNUNET_NAMESTORE_RecordData));
          copied_elements++;
        }
    }
    else
      memcpy (rd_tmp, rd, rd_count * sizeof (struct GNUNET_NAMESTORE_RecordData));
  }

  if (GNUNET_YES == contains_signature)
    memcpy (signature_tmp, signature, sizeof (struct GNUNET_CRYPTO_RsaSignature));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "DONE `%s' message\n", "NAMESTORE_LOOKUP_NAME_RESPONSE");
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
  GNUNET_HashCode name_hash;
  size_t name_len;
  char * name;
  uint32_t id = 0;
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
  id = ntohl (ln_msg->op_id);
  name_len = ntohl (ln_msg->name_len);
  type = ntohl (ln_msg->record_type);

  if ((name_len == 0) || (name_len > 256))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  name = GNUNET_malloc (name_len);
  memcpy (name, &ln_msg[1], name_len);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Looking up record for name `%s'\n", name);
  GNUNET_CRYPTO_hash(name, name_len-1, &name_hash);
  GNUNET_free (name);

  /* do the actual lookup */
  lnc.id = id;
  lnc.nc = nc;
  lnc.record_type = type;
  GSN_database->iterate_records(GSN_database->cls, &ln_msg->zone, &ln_msg->zone, 0, &handle_lookup_name_it, &lnc);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting namestore service\n");

  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_start, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_START, sizeof (struct StartMessage)},
    {&handle_lookup_name, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME, 0},
    {NULL, NULL, 0, 0}
  };

  GSN_cfg = cfg;

  /* Loading database plugin */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "namestore", "database",
                                             &database))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No database backend configured\n");

  GNUNET_asprintf (&db_lib_name, "libgnunet_plugin_namestore_%s", database);
  GSN_database = GNUNET_PLUGIN_load (db_lib_name, (void *) GSN_cfg);
  if (GSN_database == NULL)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not load database backend `%s'\n",
        db_lib_name);
  GNUNET_free (database);

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
