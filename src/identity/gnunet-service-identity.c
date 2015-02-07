/*
  This file is part of GNUnet.
  Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
static struct GNUNET_SERVER_NotificationContext *nc;

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
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Ego *e;

  if (NULL != nc)
  {
    GNUNET_SERVER_notification_context_destroy (nc);
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
send_result_code (struct GNUNET_SERVER_Client *client,
		  uint32_t result_code,
		  const char *emsg)
{
  struct GNUNET_IDENTITY_ResultCodeMessage *rcm;
  size_t elen;

  if (NULL == emsg)
    elen = 0;
  else
    elen = strlen (emsg) + 1;
  rcm = GNUNET_malloc (sizeof (struct GNUNET_IDENTITY_ResultCodeMessage) + elen);
  rcm->header.type = htons (GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE);
  rcm->header.size = htons (sizeof (struct GNUNET_IDENTITY_ResultCodeMessage) + elen);
  rcm->result_code = htonl (result_code);
  if (0 < elen)
    memcpy (&rcm[1], emsg, elen);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending result %d (%s) to client\n",
	      (int) result_code,
	      emsg);
  GNUNET_SERVER_notification_context_unicast (nc, client, &rcm->header, GNUNET_NO);
  GNUNET_free (rcm);
}


/**
 * Create an update message with information about the current state of an ego.
 *
 * @param ego ego to create message for
 * @return corresponding update message
 */
static struct GNUNET_IDENTITY_UpdateMessage *
create_update_message (struct Ego *ego)
{
  struct GNUNET_IDENTITY_UpdateMessage *um;
  size_t name_len;

  name_len = (NULL == ego->identifier) ? 0 : (strlen (ego->identifier) + 1);
  um = GNUNET_malloc (sizeof (struct GNUNET_IDENTITY_UpdateMessage) + name_len);
  um->header.type = htons (GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE);
  um->header.size = htons (sizeof (struct GNUNET_IDENTITY_UpdateMessage) + name_len);
  um->name_len = htons (name_len);
  um->end_of_list = htons (GNUNET_NO);
  um->private_key = *ego->pk;
  memcpy (&um[1], ego->identifier, name_len);
  return um;
}


/**
 * Create a set default message with information about the current state of an ego.
 *
 * @param ego ego to create message for
 * @param servicename name of the service to provide in the message
 * @return corresponding set default message
 */
static struct GNUNET_IDENTITY_SetDefaultMessage *
create_set_default_message (struct Ego *ego,
			    const char *servicename)
{
  struct GNUNET_IDENTITY_SetDefaultMessage *sdm;
  size_t name_len;

  name_len = (NULL == servicename) ? 0 : (strlen (servicename) + 1);
  sdm = GNUNET_malloc (sizeof (struct GNUNET_IDENTITY_SetDefaultMessage) + name_len);
  sdm->header.type = htons (GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT);
  sdm->header.size = htons (sizeof (struct GNUNET_IDENTITY_SetDefaultMessage) + name_len);
  sdm->name_len = htons (name_len);
  sdm->reserved = htons (0);
  sdm->private_key = *ego->pk;
  memcpy (&sdm[1], servicename, name_len);
  return sdm;
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
handle_start_message (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_IDENTITY_UpdateMessage *um;
  struct GNUNET_IDENTITY_UpdateMessage ume;
  struct Ego *ego;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received START message from client\n");
  GNUNET_SERVER_notification_context_add (nc, client);
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    um = create_update_message (ego);
    GNUNET_SERVER_notification_context_unicast (nc, client, &um->header, GNUNET_NO);
    GNUNET_free (um);
  }
  memset (&ume, 0, sizeof (ume));
  ume.header.type = htons (GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE);
  ume.header.size = htons (sizeof (struct GNUNET_IDENTITY_UpdateMessage));
  ume.end_of_list = htons (GNUNET_YES);
  ume.name_len = htons (0);
  GNUNET_SERVER_notification_context_unicast (nc, client, &ume.header, GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
handle_get_default_message (void *cls, struct GNUNET_SERVER_Client *client,
			    const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_IDENTITY_GetDefaultMessage *gdm;
  struct GNUNET_IDENTITY_SetDefaultMessage *sdm;
  uint16_t size;
  uint16_t name_len;
  struct Ego *ego;
  const char *name;
  char *identifier;

  size = ntohs (message->size);
  if (size <= sizeof (struct GNUNET_IDENTITY_GetDefaultMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  gdm = (const struct GNUNET_IDENTITY_GetDefaultMessage *) message;
  name = (const char *) &gdm[1];
  name_len = ntohs (gdm->name_len);
  if ( (name_len + sizeof (struct GNUNET_IDENTITY_GetDefaultMessage) != size) ||
       (0 != ntohs (gdm->reserved)) ||
       ('\0' != name[name_len - 1]) )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
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
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == strcmp (ego->identifier,
		     identifier))
    {
      sdm = create_set_default_message (ego,
					name);
      GNUNET_SERVER_notification_context_unicast (nc, client,
                                                  &sdm->header, GNUNET_NO);
      GNUNET_free (sdm);
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
 * Handler for SET_DEFAULT message from client, updates
 * default identity for some service.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_set_default_message (void *cls, struct GNUNET_SERVER_Client *client,
			    const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_IDENTITY_SetDefaultMessage *sdm;
  uint16_t size;
  uint16_t name_len;
  struct Ego *ego;
  const char *str;

  size = ntohs (message->size);
  if (size <= sizeof (struct GNUNET_IDENTITY_SetDefaultMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  sdm = (const struct GNUNET_IDENTITY_SetDefaultMessage *) message;
  name_len = ntohs (sdm->name_len);
  GNUNET_break (0 == ntohs (sdm->reserved));
  if (name_len + sizeof (struct GNUNET_IDENTITY_SetDefaultMessage) != size)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  str = (const char *) &sdm[1];
  if ('\0' != str[name_len - 1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
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
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
  }
  send_result_code (client, 1, _("Unknown ego specified for service (internal error)"));
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Send an updated message for the given ego to all listeners.
 *
 * @param ego ego to send the update for
 */
static void
notify_listeners (struct Ego *ego)
{
  struct GNUNET_IDENTITY_UpdateMessage *um;

  um = create_update_message (ego);
  GNUNET_SERVER_notification_context_broadcast (nc, &um->header, GNUNET_NO);
  GNUNET_free (um);
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
handle_create_message (void *cls, struct GNUNET_SERVER_Client *client,
		       const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_IDENTITY_CreateRequestMessage *crm;
  uint16_t size;
  uint16_t name_len;
  struct Ego *ego;
  const char *str;
  char *fn;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received CREATE message from client\n");
  size = ntohs (message->size);
  if (size <= sizeof (struct GNUNET_IDENTITY_CreateRequestMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  crm = (const struct GNUNET_IDENTITY_CreateRequestMessage *) message;
  name_len = ntohs (crm->name_len);
  GNUNET_break (0 == ntohs (crm->reserved));
  if (name_len + sizeof (struct GNUNET_IDENTITY_CreateRequestMessage) != size)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  str = (const char *) &crm[1];
  if ('\0' != str[name_len - 1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == strcmp (ego->identifier,
		     str))
    {
      send_result_code (client, 1, gettext_noop ("identifier already in use for another ego"));
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
 * Handler for RENAME message from client, creates
 * new identity.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_rename_message (void *cls, struct GNUNET_SERVER_Client *client,
		       const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_IDENTITY_RenameMessage *rm;
  uint16_t size;
  uint16_t old_name_len;
  uint16_t new_name_len;
  struct Ego *ego;
  const char *old_name;
  const char *new_name;
  struct RenameContext rename_ctx;
  char *fn_old;
  char *fn_new;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received RENAME message from client\n");
  size = ntohs (message->size);
  if (size <= sizeof (struct GNUNET_IDENTITY_RenameMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  rm = (const struct GNUNET_IDENTITY_RenameMessage *) message;
  old_name_len = ntohs (rm->old_name_len);
  new_name_len = ntohs (rm->new_name_len);
  old_name = (const char *) &rm[1];
  new_name = &old_name[old_name_len];
  if ( (old_name_len + new_name_len + sizeof (struct GNUNET_IDENTITY_RenameMessage) != size) ||
       ('\0' != old_name[old_name_len - 1]) ||
       ('\0' != new_name[new_name_len - 1]) )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* check if new name is already in use */
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == strcmp (ego->identifier,
		     new_name))
    {
      send_result_code (client, 1, gettext_noop ("target name already exists"));
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
  }

  /* failed to locate old name */
  send_result_code (client, 1, gettext_noop ("no matching ego found"));
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
 * Handler for DELETE message from client, creates
 * new identity.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_delete_message (void *cls, struct GNUNET_SERVER_Client *client,
		       const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_IDENTITY_DeleteMessage *dm;
  uint16_t size;
  uint16_t name_len;
  struct Ego *ego;
  const char *name;
  char *fn;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received DELETE message from client\n");
  size = ntohs (message->size);
  if (size <= sizeof (struct GNUNET_IDENTITY_DeleteMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  dm = (const struct GNUNET_IDENTITY_DeleteMessage *) message;
  name = (const char *) &dm[1];
  name_len = ntohs (dm->name_len);
  if ( (name_len + sizeof (struct GNUNET_IDENTITY_DeleteMessage) != size) ||
       (0 != ntohs (dm->reserved)) ||
       ('\0' != name[name_len - 1]) )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
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
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
  }

  send_result_code (client, 1, gettext_noop ("no matching ego found"));
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_start_message, NULL,
     GNUNET_MESSAGE_TYPE_IDENTITY_START, sizeof (struct GNUNET_MessageHeader)},
    {&handle_get_default_message, NULL,
     GNUNET_MESSAGE_TYPE_IDENTITY_GET_DEFAULT, 0},
    {&handle_set_default_message, NULL,
     GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT, 0},
    {&handle_create_message, NULL,
     GNUNET_MESSAGE_TYPE_IDENTITY_CREATE, 0},
    {&handle_rename_message, NULL,
     GNUNET_MESSAGE_TYPE_IDENTITY_RENAME, 0},
    {&handle_delete_message, NULL,
     GNUNET_MESSAGE_TYPE_IDENTITY_DELETE, 0},
    {NULL, NULL, 0, 0}
  };

  cfg = c;
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
  GNUNET_SERVER_add_handlers (server, handlers);
  nc = GNUNET_SERVER_notification_context_create (server, 1);
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
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
}


/**
 * The main function for the network size estimation service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "identity",
			      GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}


/* end of gnunet-service-identity.c */
