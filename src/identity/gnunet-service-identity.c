/*
  This file is part of GNUnet.
  Copyright (C) 2013 GNUnet e.V.

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
 * @file identity/gnunet-service-identity.c
 * @brief identity management service
 * @author Christian Grothoff
 *
 * The purpose of this service is to manage private keys that
 * represent the various egos/pseudonyms/identities of a GNUnet user.
 *
 * Todo:
 * - auto-initialze default egos; maybe trigger default
 *   initializations (such as gnunet-gns-import.sh?)
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_identity_service.h"
#include "identity.h"


/**
 * Information we keep about each ego.
 */
struct Ego
{

  /**
   * We keep egos in a DLL.
   */
  struct Ego *next;

  /**
   * We keep egos in a DLL.
   */
  struct Ego *prev;

  /**
   * Private key of the ego.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;

  /**
   * String identifier for the ego.
   */
  char *identifier;

};


/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to subsystem configuration which for each subsystem contains
 * the name of the default ego.
 */
static struct GNUNET_CONFIGURATION_Handle *subsystem_cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Notification context, simplifies client broadcasts.
 */
static struct GNUNET_NotificationContext *nc;

/**
 * Directory where we store the identities.
 */
static char *ego_directory;

/**
 * Configuration file name where subsystem information is kept.
 */
static char *subsystem_cfg_file;

/**
 * Head of DLL of all egos.
 */
static struct Ego *ego_head;

/**
 * Tail of DLL of all egos.
 */
static struct Ego *ego_tail;


/**
 * Get the name of the file we use to store a given ego.
 *
 * @param ego ego for which we need the filename
 * @return full filename for the given ego
 */
static char *
get_ego_filename (struct Ego *ego)
{
  char *filename;

  GNUNET_asprintf (&filename,
		   "%s%s%s",
		   ego_directory,
		   DIR_SEPARATOR_STR,
		   ego->identifier);
  return filename;
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p disconnected\n",
              client);
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
  return client;
}

/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  struct Ego *e;

  if (NULL != nc)
  {
    GNUNET_notification_context_destroy (nc);
    nc = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
  GNUNET_CONFIGURATION_destroy (subsystem_cfg);
  subsystem_cfg = NULL;
  GNUNET_free (subsystem_cfg_file);
  subsystem_cfg_file = NULL;
  GNUNET_free (ego_directory);
  ego_directory = NULL;
  while (NULL != (e = ego_head))
  {
    GNUNET_CONTAINER_DLL_remove (ego_head, ego_tail, e);
    GNUNET_free (e->pk);
    GNUNET_free (e->identifier);
    GNUNET_free (e);
  }
}


/**
 * Send a result code back to the client.
 *
 * @param client client that should receive the result code
 * @param result_code code to transmit
 * @param emsg error message to include (or NULL for none)
 */
static void
send_result_code (struct GNUNET_SERVICE_Client *client,
		  uint32_t result_code,
		  const char *emsg)
{
  struct ResultCodeMessage *rcm;
  struct GNUNET_MQ_Envelope *env;
  size_t elen;

  if (NULL == emsg)
    elen = 0;
  else
    elen = strlen (emsg) + 1;
  env = GNUNET_MQ_msg_extra (rcm,
                             elen,
                             GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE);
  rcm->result_code = htonl (result_code);
  if (0 < elen)
    GNUNET_memcpy (&rcm[1], emsg, elen);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending result %d (%s) to client\n",
              (int) result_code,
              emsg);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client), env);
}


/**
 * Create an update message with information about the current state of an ego.
 *
 * @param ego ego to create message for
 * @return corresponding update message
 */
static struct GNUNET_MQ_Envelope *
create_update_message (struct Ego *ego)
{
  struct UpdateMessage *um;
  struct GNUNET_MQ_Envelope *env;
  size_t name_len;

  name_len = (NULL == ego->identifier) ? 0 : (strlen (ego->identifier) + 1);
  env = GNUNET_MQ_msg_extra (um,
                             name_len,
                             GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE);
  um->name_len = htons (name_len);
  um->end_of_list = htons (GNUNET_NO);
  um->private_key = *ego->pk;
  GNUNET_memcpy (&um[1], ego->identifier, name_len);
  return env;
}


/**
 * Create a set default message with information about the current state of an ego.
 *
 * @param ego ego to create message for
 * @param servicename name of the service to provide in the message
 * @return corresponding set default message
 */
static struct GNUNET_MQ_Envelope *
create_set_default_message (struct Ego *ego,
                            const char *servicename)
{
  struct SetDefaultMessage *sdm;
  struct GNUNET_MQ_Envelope *env;
  size_t name_len;

  name_len = (NULL == servicename) ? 0 : (strlen (servicename) + 1);
  env = GNUNET_MQ_msg_extra (sdm,
                             name_len,
                             GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT);
  sdm->name_len = htons (name_len);
  sdm->reserved = htons (0);
  sdm->private_key = *ego->pk;
  GNUNET_memcpy (&sdm[1], servicename, name_len);
  return env;
}


/**
 * Handler for START message from client, sends information
 * about all identities to the client immediately and
 * adds the client to the notification context for future
 * updates.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_start_message (void *cls,
                      const struct GNUNET_MessageHeader *message)
{
  struct UpdateMessage *ume;
  struct GNUNET_SERVICE_Client *client = cls;
  struct GNUNET_MQ_Envelope *env;
  struct Ego *ego;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received START message from client\n");
  GNUNET_SERVICE_client_mark_monitor (client);
  GNUNET_SERVICE_client_disable_continue_warning (client);
  GNUNET_notification_context_add (nc,
                                   GNUNET_SERVICE_client_get_mq(client));
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    env = create_update_message (ego);
    GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq(client), env);
  }
  env = GNUNET_MQ_msg_extra (ume,
                             0,
                             GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE);
  ume->end_of_list = htons (GNUNET_YES);
  ume->name_len = htons (0);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq(client), env);
  GNUNET_SERVICE_client_continue (client);
}

/**
 * Checks a #GNUNET_MESSAGE_TYPE_IDENTITY_GET_DEFAULT message
 *
 * @param cls client sending the message
 * @param msg message of type `struct GetDefaultMessage`
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_get_default_message (void *cls,
                           const struct GetDefaultMessage *msg)
{
  uint16_t size;
  uint16_t name_len;
  const char *name;

  size = ntohs (msg->header.size);
  if (size <= sizeof (struct GetDefaultMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name = (const char *) &msg[1];
  name_len = ntohs (msg->name_len);
  if ( (name_len + sizeof (struct GetDefaultMessage) != size) ||
       (0 != ntohs (msg->reserved)) ||
       ('\0' != name[name_len - 1]) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for GET_DEFAULT message from client, returns
 * default identity for some service.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_get_default_message (void *cls,
                            const struct GetDefaultMessage *gdm)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_SERVICE_Client *client = cls;
  struct Ego *ego;
  const char *name;
  char *identifier;


  name = (const char *) &gdm[1];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received GET_DEFAULT for service `%s' from client\n",
              name);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (subsystem_cfg,
                                             name,
                                             "DEFAULT_IDENTIFIER",
                                             &identifier))
  {
    send_result_code (client, 1, gettext_noop ("no default known"));
    GNUNET_SERVICE_client_continue (client);
    return;
  }
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == strcmp (ego->identifier,
                     identifier))
    {
      env = create_set_default_message (ego,
                                        name);
      GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client), env);
      GNUNET_SERVICE_client_continue (client);
      GNUNET_free (identifier);
      return;
    }
  }
  GNUNET_free (identifier);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Failed to find ego `%s'\n",
              name);
  send_result_code (client, 1,
                    gettext_noop ("default configured, but ego unknown (internal error)"));
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Compare the given two private keys for equality.
 *
 * @param pk1 one private key
 * @param pk2 another private key
 * @return 0 if the keys are equal
 */
static int
key_cmp (const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk1,
         const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk2)
{
  return memcmp (pk1, pk2, sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
}

/**
 * Checks a #GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT message
 *
 * @param cls client sending the message
 * @param msg message of type `struct SetDefaultMessage`
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_set_default_message (void *cls,
                           const struct SetDefaultMessage *msg)
{
  uint16_t size;
  uint16_t name_len;
  const char *str;

  size = ntohs (msg->header.size);
  if (size <= sizeof (struct SetDefaultMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name_len = ntohs (msg->name_len);
  GNUNET_break (0 == ntohs (msg->reserved));
  if (name_len + sizeof (struct SetDefaultMessage) != size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  str = (const char *) &msg[1];
  if ('\0' != str[name_len - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

/**
 * Handler for SET_DEFAULT message from client, updates
 * default identity for some service.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_set_default_message (void *cls,
                            const struct SetDefaultMessage *sdm)
{
  struct Ego *ego;
  struct GNUNET_SERVICE_Client *client = cls;
  const char *str;

  str = (const char *) &sdm[1];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received SET_DEFAULT for service `%s' from client\n",
              str);
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == key_cmp (ego->pk,
                      &sdm->private_key))
    {
      GNUNET_CONFIGURATION_set_value_string (subsystem_cfg,
                                             str,
                                             "DEFAULT_IDENTIFIER",
                                             ego->identifier);
      if (GNUNET_OK !=
          GNUNET_CONFIGURATION_write (subsystem_cfg,
                                      subsystem_cfg_file))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Failed to write subsystem default identifier map to `%s'.\n"),
                    subsystem_cfg_file);
      send_result_code (client, 0, NULL);
      GNUNET_SERVICE_client_continue (client);
      return;
    }
  }
  send_result_code (client, 1, _("Unknown ego specified for service (internal error)"));
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Send an updated message for the given ego to all listeners.
 *
 * @param ego ego to send the update for
 */
static void
notify_listeners (struct Ego *ego)
{
  struct UpdateMessage *um;
  size_t name_len;

  name_len = (NULL == ego->identifier) ? 0 : (strlen (ego->identifier) + 1);
  um = GNUNET_malloc (sizeof (struct UpdateMessage) + name_len);
  um->header.type = htons (GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE);
  um->header.size = htons (sizeof (struct UpdateMessage) + name_len);
  um->name_len = htons (name_len);
  um->end_of_list = htons (GNUNET_NO);
  um->private_key = *ego->pk;
  GNUNET_memcpy (&um[1], ego->identifier, name_len);
  GNUNET_notification_context_broadcast (nc,
                                         &um->header,
                                         GNUNET_NO);
  GNUNET_free (um);
}

/**
 * Checks a #GNUNET_MESSAGE_TYPE_IDENTITY_CREATE message
 *
 * @param cls client sending the message
 * @param msg message of type `struct CreateRequestMessage`
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_create_message (void *cls,
                      const struct CreateRequestMessage *msg)
{
  
  uint16_t size;
  uint16_t name_len;
  const char *str;

  size = ntohs (msg->header.size);
  if (size <= sizeof (struct CreateRequestMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name_len = ntohs (msg->name_len);
  GNUNET_break (0 == ntohs (msg->reserved));
  if (name_len + sizeof (struct CreateRequestMessage) != size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  str = (const char *) &msg[1];
  if ('\0' != str[name_len - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
} 

/**
 * Handler for CREATE message from client, creates
 * new identity.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_create_message (void *cls,
                       const struct CreateRequestMessage *crm)
{
  struct GNUNET_SERVICE_Client *client = cls;
  struct Ego *ego;
  const char *str;
  char *fn;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received CREATE message from client\n");
  str = (const char *) &crm[1];
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == strcmp (ego->identifier,
                     str))
    {
      send_result_code (client, 1, gettext_noop ("identifier already in use for another ego"));
      GNUNET_SERVICE_client_continue (client);
      return;
    }
  }
  ego = GNUNET_new (struct Ego);
  ego->pk = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPrivateKey);
  *ego->pk = crm->private_key;
  ego->identifier = GNUNET_strdup (str);
  GNUNET_CONTAINER_DLL_insert (ego_head,
                               ego_tail,
                               ego);
  send_result_code (client, 0, NULL);
  fn = get_ego_filename (ego);
  (void) GNUNET_DISK_directory_create_for_file (fn);
  if (sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey) !=
      GNUNET_DISK_fn_write (fn,
                            &crm->private_key,
                            sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey),
                            GNUNET_DISK_PERM_USER_READ |
                            GNUNET_DISK_PERM_USER_WRITE))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "write", fn);
  GNUNET_free (fn);
  notify_listeners (ego);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Closure for 'handle_ego_rename'.
 */
struct RenameContext
{
  /**
   * Old name.
   */
  const char *old_name;

  /**
   * New name.
   */
  const char *new_name;
};

/**
 * An ego was renamed; rename it in all subsystems where it is
 * currently set as the default.
 *
 * @param cls the 'struct RenameContext'
 * @param section a section in the configuration to process
 */
static void
handle_ego_rename (void *cls,
                   const char *section)
{
  struct RenameContext *rc = cls;
  char *id;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (subsystem_cfg,
                                             section,
                                             "DEFAULT_IDENTIFIER",
                                             &id))
    return;
  if (0 != strcmp (id, rc->old_name))
  {
    GNUNET_free (id);
    return;
  }
  GNUNET_CONFIGURATION_set_value_string (subsystem_cfg,
                                         section,
                                         "DEFAULT_IDENTIFIER",
                                         rc->new_name);
  GNUNET_free (id);
}

/**
 * Checks a #GNUNET_MESSAGE_TYPE_IDENTITY_RENAME message
 *
 * @param cls client sending the message
 * @param msg message of type `struct RenameMessage`
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_rename_message (void *cls,
                      const struct RenameMessage *msg)
{
  uint16_t size;
  uint16_t old_name_len;
  uint16_t new_name_len;
  const char *old_name;
  const char *new_name;

  size = ntohs (msg->header.size);
  if (size <= sizeof (struct RenameMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  old_name_len = ntohs (msg->old_name_len);
  new_name_len = ntohs (msg->new_name_len);
  old_name = (const char *) &msg[1];
  new_name = &old_name[old_name_len];
  if ( (old_name_len + new_name_len + sizeof (struct RenameMessage) != size) ||
       ('\0' != old_name[old_name_len - 1]) ||
       ('\0' != new_name[new_name_len - 1]) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}
 

/**
 * Handler for RENAME message from client, creates
 * new identity.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_rename_message (void *cls,
                       const struct RenameMessage *rm)
{
  uint16_t old_name_len;
  struct Ego *ego;
  const char *old_name;
  const char *new_name;
  struct RenameContext rename_ctx;
  struct GNUNET_SERVICE_Client *client = cls;
  char *fn_old;
  char *fn_new;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received RENAME message from client\n");
  old_name_len = ntohs (rm->old_name_len);
  old_name = (const char *) &rm[1];
  new_name = &old_name[old_name_len];

  /* check if new name is already in use */
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == strcmp (ego->identifier,
                     new_name))
    {
      send_result_code (client, 1, gettext_noop ("target name already exists"));
      GNUNET_SERVICE_client_continue (client);
      return;
    }
  }

  /* locate old name and, if found, perform rename */
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == strcmp (ego->identifier,
                     old_name))
    {
      fn_old = get_ego_filename (ego);
      GNUNET_free (ego->identifier);
      rename_ctx.old_name = old_name;
      rename_ctx.new_name = new_name;
      GNUNET_CONFIGURATION_iterate_sections (subsystem_cfg,
                                             &handle_ego_rename,
                                             &rename_ctx);
      if (GNUNET_OK !=
          GNUNET_CONFIGURATION_write (subsystem_cfg,
                                      subsystem_cfg_file))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Failed to write subsystem default identifier map to `%s'.\n"),
                    subsystem_cfg_file);
      ego->identifier = GNUNET_strdup (new_name);
      fn_new = get_ego_filename (ego);
      if (0 != RENAME (fn_old, fn_new))
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "rename", fn_old);
      GNUNET_free (fn_old);
      GNUNET_free (fn_new);
      notify_listeners (ego);
      send_result_code (client, 0, NULL);
      GNUNET_SERVICE_client_continue (client);
      return;
    }
  }

  /* failed to locate old name */
  send_result_code (client, 1, gettext_noop ("no matching ego found"));
  GNUNET_SERVICE_client_continue (client);
}


/**
 * An ego was removed, remove it from all subsystems where it is
 * currently set as the default.
 *
 * @param cls name of the removed ego (const char *)
 * @param section a section in the configuration to process
 */
static void
handle_ego_delete (void *cls,
                   const char *section)
{
  const char *identifier = cls;
  char *id;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (subsystem_cfg,
                                             section,
                                             "DEFAULT_IDENTIFIER",
                                             &id))
    return;
  if (0 != strcmp (id, identifier))
  {
    GNUNET_free (id);
    return;
  }
  GNUNET_CONFIGURATION_set_value_string (subsystem_cfg,
                                         section,
                                         "DEFAULT_IDENTIFIER",
                                         NULL);
  GNUNET_free (id);
}

/**
 * Checks a #GNUNET_MESSAGE_TYPE_IDENTITY_DELETE message
 *
 * @param cls client sending the message
 * @param msg message of type `struct DeleteMessage`
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_delete_message (void *cls,
                      const struct DeleteMessage *msg)
{
  uint16_t size;
  uint16_t name_len;
  const char *name;

  size = ntohs (msg->header.size);
  if (size <= sizeof (struct DeleteMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name = (const char *) &msg[1];
  name_len = ntohs (msg->name_len);
  if ( (name_len + sizeof (struct DeleteMessage) != size) ||
       (0 != ntohs (msg->reserved)) ||
       ('\0' != name[name_len - 1]) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for DELETE message from client, creates
 * new identity.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_delete_message (void *cls,
                       const struct DeleteMessage *dm)
{
  struct Ego *ego;
  const char *name;
  char *fn;
  struct GNUNET_SERVICE_Client *client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received DELETE message from client\n");
  name = (const char *) &dm[1];
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == strcmp (ego->identifier,
                     name))
    {
      GNUNET_CONTAINER_DLL_remove (ego_head,
                                   ego_tail,
                                   ego);
      GNUNET_CONFIGURATION_iterate_sections (subsystem_cfg,
                                             &handle_ego_delete,
                                             ego->identifier);
      if (GNUNET_OK !=
          GNUNET_CONFIGURATION_write (subsystem_cfg,
                                      subsystem_cfg_file))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Failed to write subsystem default identifier map to `%s'.\n"),
                    subsystem_cfg_file);
      fn = get_ego_filename (ego);
      if (0 != UNLINK (fn))
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
      GNUNET_free (fn);
      GNUNET_free (ego->identifier);
      ego->identifier = NULL;
      notify_listeners (ego);
      GNUNET_free (ego->pk);
      GNUNET_free (ego);
      send_result_code (client, 0, NULL);
      GNUNET_SERVICE_client_continue (client);
      return;
    }
  }

  send_result_code (client, 1, gettext_noop ("no matching ego found"));
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Process the given file from the "EGODIR".  Parses the file
 * and creates the respective 'struct Ego' in memory.
 *
 * @param cls NULL
 * @param filename name of the file to parse
 * @return #GNUNET_OK to continue to iterate,
 *  #GNUNET_NO to stop iteration with no error,
 *  #GNUNET_SYSERR to abort iteration with error!
 */
static int
process_ego_file (void *cls,
                  const char *filename)
{
  struct Ego *ego;
  const char *fn;

  fn = strrchr (filename, (int) DIR_SEPARATOR);
  if (NULL == fn)
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  ego = GNUNET_new (struct Ego);
  ego->pk = GNUNET_CRYPTO_ecdsa_key_create_from_file (filename);
  if (NULL == ego->pk)
  {
    GNUNET_free (ego);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to parse ego information in `%s'\n"),
                filename);
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loaded ego `%s'\n",
              fn + 1);
  ego->identifier = GNUNET_strdup (fn + 1);
  GNUNET_CONTAINER_DLL_insert (ego_head,
                               ego_tail,
                               ego);
  return GNUNET_OK;
}


/**
 * Handle network size estimate clients.
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
  cfg = c;
  nc = GNUNET_notification_context_create (1);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "identity",
                                               "EGODIR",
                                               &ego_directory))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "identity", "EGODIR");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "identity",
                                               "SUBSYSTEM_CFG",
                                               &subsystem_cfg_file))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "identity", "SUBSYSTEM_CFG");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loading subsystem configuration `%s'\n",
              subsystem_cfg_file);
  subsystem_cfg = GNUNET_CONFIGURATION_create ();
  if ( (GNUNET_YES ==
        GNUNET_DISK_file_test (subsystem_cfg_file)) &&
       (GNUNET_OK !=
        GNUNET_CONFIGURATION_parse (subsystem_cfg,
                                    subsystem_cfg_file)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to parse subsystem identity configuration file `%s'\n"),
                subsystem_cfg_file);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  stats = GNUNET_STATISTICS_create ("identity", cfg);
  if (GNUNET_OK !=
      GNUNET_DISK_directory_create (ego_directory))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to create directory `%s' for storing egos\n"),
                ego_directory);
  }
  GNUNET_DISK_directory_scan (ego_directory,
                              &process_ego_file,
                              NULL);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("identity",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_fixed_size (start_message,
                          GNUNET_MESSAGE_TYPE_IDENTITY_START,
                          struct GNUNET_MessageHeader,
                          NULL),
 GNUNET_MQ_hd_var_size (get_default_message,
                        GNUNET_MESSAGE_TYPE_IDENTITY_GET_DEFAULT,
                        struct GetDefaultMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (set_default_message,
                        GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT,
                        struct SetDefaultMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (create_message,
                        GNUNET_MESSAGE_TYPE_IDENTITY_CREATE,
                        struct CreateRequestMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (rename_message,
                        GNUNET_MESSAGE_TYPE_IDENTITY_RENAME,
                        struct RenameMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (delete_message,
                        GNUNET_MESSAGE_TYPE_IDENTITY_DELETE,
                        struct DeleteMessage,
                        NULL),
 GNUNET_MQ_handler_end());



/* end of gnunet-service-identity.c */
