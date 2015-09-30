 /*
 * This file is part of GNUnet
 * Copyright (C) 2013 Christian Grothoff (and other contributing authors)
 *
 * GNUnet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUnet; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

/**
 * @file social/social_api.c
 * @brief Social service; implements social interactions using the PSYC service.
 * @author Gabor X Toth
 */

#include <inttypes.h>
#include <string.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_env_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_gns_service.h"
#include "gnunet_psyc_service.h"
#include "gnunet_psyc_util_lib.h"
#include "gnunet_social_service.h"
#include "social.h"

#define LOG(kind,...) GNUNET_log_from (kind, "social-api",__VA_ARGS__)


static struct GNUNET_CORE_Handle *core;
static struct GNUNET_GNS_Handle *gns;
static struct GNUNET_NAMESTORE_Handle *namestore;
static struct GNUNET_PeerIdentity this_peer;


/**
 * Handle for a pseudonym of another user in the network.
 */
struct GNUNET_SOCIAL_Nym
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pub_key;
  struct GNUNET_HashCode pub_key_hash;
};


/**
 * Handle for a place where social interactions happen.
 */
struct GNUNET_SOCIAL_Place
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Client connection to the service.
   */
  struct GNUNET_CLIENT_MANAGER_Connection *client;

  /**
   * Transmission handle.
   */
  struct GNUNET_PSYC_TransmitHandle *tmit;

  /**
   * Receipt handle.
   */
  struct GNUNET_PSYC_ReceiveHandle *recv;

  /**
   * Slicer for processing incoming methods.
   */
  struct GNUNET_SOCIAL_Slicer *slicer;

  /**
   * Message to send on reconnect.
   */
  struct GNUNET_MessageHeader *connect_msg;

  /**
   * Function called after disconnected from the service.
   */
  GNUNET_ContinuationCallback disconnect_cb;

  /**
   * Closure for @a disconnect_cb.
   */
  void *disconnect_cls;

  /**
   * Public key of the place.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;

  /**
   * Private key of the ego.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey ego_key;

  /**
   * Does this place belong to a host (#GNUNET_YES) or guest (#GNUNET_NO)?
   */
  uint8_t is_host;

  /**
   * Is this place in the process of disconnecting from the service?
   * #GNUNET_YES or #GNUNET_NO
   */
  uint8_t is_disconnecting;
};


/**
 * Host handle for a place that we entered.
 */
struct GNUNET_SOCIAL_Host
{
  struct GNUNET_SOCIAL_Place plc;

  struct GNUNET_CRYPTO_EddsaPrivateKey place_key;

  /**
   * Receipt handle.
   */
  struct GNUNET_PSYC_ReceiveHandle *recv;

  /**
   * Slicer for processing incoming methods.
   */
  struct GNUNET_SOCIAL_Slicer *slicer;

  GNUNET_SOCIAL_HostEnterCallback enter_cb;

  GNUNET_SOCIAL_AnswerDoorCallback answer_door_cb;

  GNUNET_SOCIAL_FarewellCallback farewell_cb;

  /**
   * Closure for callbacks.
   */
  void *cb_cls;

  struct GNUNET_SOCIAL_Nym *notice_place_leave_nym;
  struct GNUNET_ENV_Environment *notice_place_leave_env;
};


/**
 * Guest handle for place that we entered.
 */
struct GNUNET_SOCIAL_Guest
{
  struct GNUNET_SOCIAL_Place plc;

  /**
   * Receipt handle.
   */
  struct GNUNET_PSYC_ReceiveHandle *recv;

  /**
   * Slicer for processing incoming methods.
   */
  struct GNUNET_SOCIAL_Slicer *slicer;

  GNUNET_SOCIAL_GuestEnterCallback enter_cb;

  GNUNET_SOCIAL_EntryDecisionCallback entry_dcsn_cb;

  /**
   * Closure for callbacks.
   */
  void *cb_cls;
};


/**
 * Hash map of all nyms.
 * pub_key_hash -> struct GNUNET_SOCIAL_Nym *
 */
struct GNUNET_CONTAINER_MultiHashMap *nyms;


/**
 * Handle for a try-and-slice instance.
 */
struct GNUNET_SOCIAL_Slicer
{
  /**
   * Method handlers: method_name -> SlicerMethodCallbacks
   */
  struct GNUNET_CONTAINER_MultiHashMap *method_handlers;

  /**
   * Modifier handlers: modifier name -> SlicerModifierCallbacks
   */
  struct GNUNET_CONTAINER_MultiHashMap *modifier_handlers;

  /**
   * Currently being processed message part.
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * ID of currently being received message.
   */
  uint64_t message_id;

  /**
   * Method name of currently being received message.
   */
  char *method_name;

  /**
   * Name of currently processed modifier.
   */
  char *mod_name;

  /**
   * Value of currently processed modifier.
   */
  char *mod_value;

  /**
   * Public key of the nym the current message originates from.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey nym_key;

  /**
   * Size of @a method_name (including terminating \0).
   */
  uint16_t method_name_size;

  /**
   * Size of @a modifier_name (including terminating \0).
   */
  uint16_t mod_name_size;

  /**
   * Size of modifier value fragment.
   */
  uint16_t mod_value_size;

  /**
   * Full size of modifier value.
   */
  uint16_t mod_full_value_size;

  /**
   * Remaining bytes from the value of the current modifier.
   */
  uint16_t mod_value_remaining;

  /**
   * Operator of currently processed modifier.
   */
  uint8_t mod_oper;
};


/**
 * Callbacks for a slicer method handler.
 */
struct SlicerMethodCallbacks
{
  GNUNET_SOCIAL_MethodCallback method_cb;
  GNUNET_SOCIAL_ModifierCallback modifier_cb;
  GNUNET_SOCIAL_DataCallback data_cb;
  GNUNET_SOCIAL_EndOfMessageCallback eom_cb;
  void *cls;
};


struct SlicerMethodRemoveClosure
{
  struct GNUNET_SOCIAL_Slicer *slicer;
  struct SlicerMethodCallbacks rm_cbs;
};


/**
 * Callbacks for a slicer method handler.
 */
struct SlicerModifierCallbacks
{
  GNUNET_SOCIAL_ModifierCallback modifier_cb;
  void *cls;
};


struct SlicerModifierRemoveClosure
{
  struct GNUNET_SOCIAL_Slicer *slicer;
  struct SlicerModifierCallbacks rm_cbs;
};


/**
 * Handle for an announcement request.
 */
struct GNUNET_SOCIAL_Announcement
{

};


/**
 * A talk request.
 */
struct GNUNET_SOCIAL_TalkRequest
{

};


/**
 * A history lesson.
 */
struct GNUNET_SOCIAL_HistoryRequest
{
  /**
   * Place.
   */
  struct GNUNET_SOCIAL_Place *plc;

  /**
   * Operation ID.
   */
  uint64_t op_id;

  /**
   * Message handler.
   */
  struct GNUNET_PSYC_ReceiveHandle *recv;

  /**
   * Function to call when the operation finished.
   */
  GNUNET_ResultCallback result_cb;

  /**
   * Closure for @a result_cb.
   */
  void *cls;
};


struct GNUNET_SOCIAL_LookHandle
{
  /**
   * Place.
   */
  struct GNUNET_SOCIAL_Place *plc;

  /**
   * Operation ID.
   */
  uint64_t op_id;

  /**
   * State variable result callback.
   */
  GNUNET_PSYC_StateVarCallback var_cb;

  /**
   * Function to call when the operation finished.
   */
  GNUNET_ResultCallback result_cb;

  /**
   * Name of current modifier being received.
   */
  char *mod_name;

  /**
   * Size of current modifier value being received.
   */
  size_t mod_value_size;

  /**
   * Remaining size of current modifier value still to be received.
   */
  size_t mod_value_remaining;

  /**
   * Closure for @a result_cb.
   */
  void *cls;
};


/*** NYM ***/

static struct GNUNET_SOCIAL_Nym *
nym_get_or_create (const struct GNUNET_CRYPTO_EcdsaPublicKey *pub_key)
{
  struct GNUNET_SOCIAL_Nym *nym = NULL;
  struct GNUNET_HashCode pub_key_hash;

  if (NULL == pub_key)
    return NULL;

  GNUNET_CRYPTO_hash (pub_key, sizeof (*pub_key), &pub_key_hash);

  if (NULL == nyms)
    nyms = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  else
    nym = GNUNET_CONTAINER_multihashmap_get (nyms, &pub_key_hash);

  if (NULL == nym)
  {
    nym = GNUNET_new (struct GNUNET_SOCIAL_Nym);
    nym->pub_key = *pub_key;
    nym->pub_key_hash = pub_key_hash;
    GNUNET_CONTAINER_multihashmap_put (nyms, &nym->pub_key_hash, nym,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  return nym;
}


static void
nym_destroy (struct GNUNET_SOCIAL_Nym *nym)
{
  GNUNET_CONTAINER_multihashmap_remove (nyms, &nym->pub_key_hash, nym);
  GNUNET_free (nym);
}


/*** MESSAGE HANDLERS ***/

/** _notice_place_leave from guests */

static void
host_recv_notice_place_leave_method (void *cls,
                                     const struct GNUNET_PSYC_MessageMethod *meth,
                                     uint64_t message_id,
                                     uint32_t flags,
                                     const struct GNUNET_SOCIAL_Nym *nym,
                                     const char *method_name)
{
  struct GNUNET_SOCIAL_Host *hst = cls;
  if (0 == memcmp (&(struct GNUNET_CRYPTO_EcdsaPublicKey) {},
                   &nym->pub_key, sizeof (nym->pub_key)))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Host received method for message ID %" PRIu64 " from nym %s: %s\n",
              message_id, GNUNET_h2s (&nym->pub_key_hash), method_name);

  hst->notice_place_leave_nym = (struct GNUNET_SOCIAL_Nym *) nym;
  hst->notice_place_leave_env = GNUNET_ENV_environment_create ();

  char *str = GNUNET_CRYPTO_ecdsa_public_key_to_string (&hst->notice_place_leave_nym->pub_key);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "_notice_place_leave: got method from nym %s (%s).\n",
              GNUNET_h2s (&hst->notice_place_leave_nym->pub_key_hash), str);
}


static void
host_recv_notice_place_leave_modifier (void *cls,
                                       const struct GNUNET_MessageHeader *msg,
                                       uint64_t message_id,
                                       enum GNUNET_ENV_Operator oper,
                                       const char *name,
                                       const void *value,
                                       uint16_t value_size,
                                       uint16_t full_value_size)
{
  struct GNUNET_SOCIAL_Host *hst = cls;
  if (NULL == hst->notice_place_leave_env)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Host received modifier for _notice_place_leave message with ID %" PRIu64 ":\n"
              "%c%s: %.*s\n",
              message_id, oper, name, value_size, value);

  /* skip _nym, it's added later in eom() */
  if (0 == memcmp (name, "_nym", sizeof ("_nym"))
      || 0 == memcmp (name, "_nym_", sizeof ("_nym_") - 1))
    return;

  GNUNET_ENV_environment_add (hst->notice_place_leave_env,
                              GNUNET_ENV_OP_SET, name, value, value_size);
}


static void
host_recv_notice_place_leave_eom (void *cls,
                                  const struct GNUNET_MessageHeader *msg,
                                  uint64_t message_id,
                                  uint8_t cancelled)
{
  struct GNUNET_SOCIAL_Host *hst = cls;
  if (NULL == hst->notice_place_leave_env)
    return;

  char *str = GNUNET_CRYPTO_ecdsa_public_key_to_string (&hst->notice_place_leave_nym->pub_key);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "_notice_place_leave: got EOM from nym %s (%s).\n",
              GNUNET_h2s (&hst->notice_place_leave_nym->pub_key_hash), str);

  if (GNUNET_YES != cancelled)
  {
    if (NULL != hst->farewell_cb)
      hst->farewell_cb (hst->cb_cls, hst->notice_place_leave_nym,
                        hst->notice_place_leave_env);
    /* announce leaving guest to place */
    GNUNET_ENV_environment_add (hst->notice_place_leave_env, GNUNET_ENV_OP_SET,
                                "_nym", hst->notice_place_leave_nym,
                                sizeof (*hst->notice_place_leave_nym));
    GNUNET_SOCIAL_host_announce (hst, "_notice_place_leave",
                                 hst->notice_place_leave_env,
                                 NULL, NULL, GNUNET_SOCIAL_ANNOUNCE_NONE);
    nym_destroy (hst->notice_place_leave_nym);
  }
  GNUNET_ENV_environment_destroy (hst->notice_place_leave_env);
  hst->notice_place_leave_env = NULL;
}


/*** SLICER ***/

/**
 * Call a method handler for an incoming message part.
 */
int
slicer_method_handler_notify (void *cls, const struct GNUNET_HashCode *key,
                              void *value)
{
  struct GNUNET_SOCIAL_Slicer *slicer = cls;
  const struct GNUNET_MessageHeader *msg = slicer->msg;
  struct SlicerMethodCallbacks *cbs = value;
  uint16_t ptype = ntohs (msg->type);

  switch (ptype)
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD:
  {
    if (NULL == cbs->method_cb)
      break;
    struct GNUNET_PSYC_MessageMethod *
      meth = (struct GNUNET_PSYC_MessageMethod *) msg;
    cbs->method_cb (cbs->cls, meth, slicer->message_id,
                    ntohl (meth->flags),
                    nym_get_or_create (&slicer->nym_key),
                    slicer->method_name);
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
  {
    if (NULL == cbs->modifier_cb)
      break;
    struct GNUNET_PSYC_MessageModifier *
      mod = (struct GNUNET_PSYC_MessageModifier *) msg;
    cbs->modifier_cb (cbs->cls, &mod->header, slicer->message_id,
                      mod->oper, (const char *) &mod[1],
                      (const void *) &mod[1] + ntohs (mod->name_size),
                      ntohs (mod->header.size) - sizeof (*mod) - ntohs (mod->name_size),
                      ntohs (mod->value_size));
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT:
  {
    if (NULL == cbs->modifier_cb)
      break;
    cbs->modifier_cb (cbs->cls, msg, slicer->message_id,
                      slicer->mod_oper, slicer->mod_name, &msg[1],
                      ntohs (msg->size) - sizeof (*msg),
                      slicer->mod_full_value_size);
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA:
  {
    if (NULL == cbs->data_cb)
      break;
    uint64_t data_offset = 0; // FIXME
    cbs->data_cb (cbs->cls, msg, slicer->message_id,
                  data_offset, &msg[1], ntohs (msg->size) - sizeof (*msg));
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END:
    if (NULL == cbs->eom_cb)
      break;
    cbs->eom_cb (cbs->cls, msg, slicer->message_id, GNUNET_NO);
    break;

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL:
    if (NULL == cbs->eom_cb)
      break;
    cbs->eom_cb (cbs->cls, msg, slicer->message_id, GNUNET_YES);
    break;
  }
  return GNUNET_YES;
}


/**
 * Call a method handler for an incoming message part.
 */
int
slicer_modifier_handler_notify (void *cls, const struct GNUNET_HashCode *key,
                                void *value)
{
  struct GNUNET_SOCIAL_Slicer *slicer = cls;
  struct SlicerModifierCallbacks *cbs = value;

  cbs->modifier_cb (cbs->cls, slicer->msg, slicer->message_id, slicer->mod_oper,
                    slicer->mod_name, slicer->mod_value,
                    slicer->mod_value_size, slicer->mod_full_value_size);
  return GNUNET_YES;
}


/**
 * Process an incoming message part and call matching handlers.
 *
 * @param cls
 *        Closure.
 * @param message_id
 *        ID of the message.
 * @param flags
 *        Flags for the message.
 *        @see enum GNUNET_PSYC_MessageFlags
 * @param msg
 *        The message part. as it arrived from the network.
 */
static void
slicer_message (void *cls, const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                uint64_t message_id, uint32_t flags, uint64_t fragment_offset,
                const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Slicer *slicer = cls;
  slicer->nym_key = *slave_key;

  uint16_t ptype = ntohs (msg->type);
  if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD == ptype)
  {
    struct GNUNET_PSYC_MessageMethod *
      meth = (struct GNUNET_PSYC_MessageMethod *) msg;
    slicer->method_name_size = ntohs (meth->header.size) - sizeof (*meth);
    slicer->method_name = GNUNET_malloc (slicer->method_name_size);
    memcpy (slicer->method_name, &meth[1], slicer->method_name_size);
    slicer->message_id = message_id;
  }
  else
  {
    GNUNET_assert (message_id == slicer->message_id);
  }

  char *nym_str = GNUNET_CRYPTO_ecdsa_public_key_to_string (slave_key);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Slicer received message of type %u and size %u, "
       "with ID %" PRIu64 " and method %s from %s\n",
       ptype, ntohs (msg->size), message_id, slicer->method_name, nym_str);
  GNUNET_free (nym_str);

  slicer->msg = msg;

  /* try-and-slice modifier */

  switch (ptype)
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
  {
    struct GNUNET_PSYC_MessageModifier *
      mod = (struct GNUNET_PSYC_MessageModifier *) msg;
    slicer->mod_oper = mod->oper;
    slicer->mod_name_size = ntohs (mod->name_size);
    slicer->mod_name = GNUNET_malloc (slicer->mod_name_size);
    memcpy (slicer->mod_name, &mod[1], slicer->mod_name_size);
    slicer->mod_value = (char *) &mod[1] + slicer->mod_name_size;
    slicer->mod_full_value_size = ntohs (mod->value_size);
    slicer->mod_value_remaining = slicer->mod_full_value_size;
    slicer->mod_value_size
      = ntohs (mod->header.size) - sizeof (*mod) - slicer->mod_name_size;
  }
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT:
    if (ptype == GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT)
    {
      slicer->mod_value = (char *) &msg[1];
      slicer->mod_value_size = ntohs (msg->size) - sizeof (*msg);
    }
    slicer->mod_value_remaining -= slicer->mod_value_size;
    char *name = GNUNET_malloc (slicer->mod_name_size);
    memcpy (name, slicer->mod_name, slicer->mod_name_size);
    do
    {
      struct GNUNET_HashCode key;
      uint16_t name_len = strlen (name);
      GNUNET_CRYPTO_hash (name, name_len, &key);
      GNUNET_CONTAINER_multihashmap_get_multiple (slicer->modifier_handlers, &key,
                                                  slicer_modifier_handler_notify,
                                                  slicer);
      char *p = strrchr (name, '_');
      if (NULL == p)
        break;
      *p = '\0';
    } while (1);
    GNUNET_free (name);
  }

  /* try-and-slice method */

  char *name = GNUNET_malloc (slicer->method_name_size);
  memcpy (name, slicer->method_name, slicer->method_name_size);
  do
  {
    struct GNUNET_HashCode key;
    uint16_t name_len = strlen (name);
    GNUNET_CRYPTO_hash (name, name_len, &key);
    GNUNET_CONTAINER_multihashmap_get_multiple (slicer->method_handlers, &key,
                                                slicer_method_handler_notify,
                                                slicer);
    char *p = strrchr (name, '_');
    if (NULL == p)
      break;
    *p = '\0';
  } while (1);
  GNUNET_free (name);

  if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END <= ptype)
    GNUNET_free (slicer->method_name);

  if (0 == slicer->mod_value_remaining && NULL != slicer->mod_name)
  {
    GNUNET_free (slicer->mod_name);
    slicer->mod_name = NULL;
    slicer->mod_name_size = 0;
    slicer->mod_value_size = 0;
    slicer->mod_full_value_size = 0;
    slicer->mod_oper = 0;
  }

  slicer->msg = NULL;
}


/**
 * Create a try-and-slice instance.
 *
 * A slicer processes incoming messages and notifies callbacks about matching
 * methods or modifiers encountered.
 *
 * @return A new try-and-slice construct.
 */
struct GNUNET_SOCIAL_Slicer *
GNUNET_SOCIAL_slicer_create (void)
{
  struct GNUNET_SOCIAL_Slicer *slicer = GNUNET_malloc (sizeof (*slicer));
  slicer->method_handlers = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  slicer->modifier_handlers = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  return slicer;
}


/**
 * Add a method to the try-and-slice instance.
 *
 * The callbacks are called for messages with a matching @a method_name prefix.
 *
 * @param slicer
 *        The try-and-slice instance to extend.
 * @param method_name
 *        Name of the given method, use empty string to match all.
 * @param method_cb
 *        Method handler invoked upon a matching message.
 * @param modifier_cb
 *        Modifier handler, invoked after @a method_cb
 *        for each modifier in the message.
 * @param data_cb
 *        Data handler, invoked after @a modifier_cb for each data fragment.
 * @param eom_cb
 *        Invoked upon reaching the end of a matching message.
 * @param cls
 *        Closure for the callbacks.
 */
void
GNUNET_SOCIAL_slicer_method_add (struct GNUNET_SOCIAL_Slicer *slicer,
                                 const char *method_name,
                                 GNUNET_SOCIAL_MethodCallback method_cb,
                                 GNUNET_SOCIAL_ModifierCallback modifier_cb,
                                 GNUNET_SOCIAL_DataCallback data_cb,
                                 GNUNET_SOCIAL_EndOfMessageCallback eom_cb,
                                 void *cls)
{
  struct GNUNET_HashCode key;
  GNUNET_CRYPTO_hash (method_name, strlen (method_name), &key);

  struct SlicerMethodCallbacks *cbs = GNUNET_malloc (sizeof (*cbs));
  cbs->method_cb = method_cb;
  cbs->modifier_cb = modifier_cb;
  cbs->data_cb = data_cb;
  cbs->eom_cb = eom_cb;
  cbs->cls = cls;

  GNUNET_CONTAINER_multihashmap_put (slicer->method_handlers, &key, cbs,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
}


int
slicer_method_remove (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct SlicerMethodRemoveClosure *rm_cls = cls;
  struct GNUNET_SOCIAL_Slicer *slicer = rm_cls->slicer;
  struct SlicerMethodCallbacks *rm_cbs = &rm_cls->rm_cbs;
  struct SlicerMethodCallbacks *cbs = value;

  if (cbs->method_cb == rm_cbs->method_cb
      && cbs->modifier_cb == rm_cbs->modifier_cb
      && cbs->data_cb == rm_cbs->data_cb
      && cbs->eom_cb == rm_cbs->eom_cb)
  {
    GNUNET_CONTAINER_multihashmap_remove (slicer->method_handlers, key, cbs);
    GNUNET_free (cbs);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Remove a registered method from the try-and-slice instance.
 *
 * Removes one matching handler registered with the given
 * @a method_name and  callbacks.
 *
 * @param slicer
 *        The try-and-slice instance.
 * @param method_name
 *        Name of the method to remove.
 * @param method_cb
 *        Method handler.
 * @param modifier_cb
 *        Modifier handler.
 * @param data_cb
 *        Data handler.
 * @param eom_cb
 *        End of message handler.
 *
 * @return #GNUNET_OK if a method handler was removed,
 *         #GNUNET_NO if no handler matched the given method name and callbacks.
 */
int
GNUNET_SOCIAL_slicer_method_remove (struct GNUNET_SOCIAL_Slicer *slicer,
                                    const char *method_name,
                                    GNUNET_SOCIAL_MethodCallback method_cb,
                                    GNUNET_SOCIAL_ModifierCallback modifier_cb,
                                    GNUNET_SOCIAL_DataCallback data_cb,
                                    GNUNET_SOCIAL_EndOfMessageCallback eom_cb)
{
  struct GNUNET_HashCode key;
  GNUNET_CRYPTO_hash (method_name, strlen (method_name), &key);

  struct SlicerMethodRemoveClosure rm_cls;
  rm_cls.slicer = slicer;
  struct SlicerMethodCallbacks *rm_cbs = &rm_cls.rm_cbs;
  rm_cbs->method_cb = method_cb;
  rm_cbs->modifier_cb = modifier_cb;
  rm_cbs->data_cb = data_cb;
  rm_cbs->eom_cb = eom_cb;

  return
    (GNUNET_SYSERR
     == GNUNET_CONTAINER_multihashmap_get_multiple (slicer->method_handlers, &key,
                                                    slicer_method_remove,
                                                    &rm_cls))
    ? GNUNET_NO
    : GNUNET_OK;
}


/**
 * Watch a place for changed objects.
 *
 * @param slicer
 *        The try-and-slice instance.
 * @param object_filter
 *        Object prefix to match.
 * @param modifier_cb
 *        Function to call when encountering a state modifier.
 * @param cls
 *        Closure for callback.
 */
void
GNUNET_SOCIAL_slicer_modifier_add (struct GNUNET_SOCIAL_Slicer *slicer,
                                   const char *object_filter,
                                   GNUNET_SOCIAL_ModifierCallback modifier_cb,
                                   void *cls)
{
  struct SlicerModifierCallbacks *cbs = GNUNET_malloc (sizeof *cbs);
  cbs->modifier_cb = modifier_cb;
  cbs->cls = cls;

  struct GNUNET_HashCode key;
  GNUNET_CRYPTO_hash (object_filter, strlen (object_filter), &key);
  GNUNET_CONTAINER_multihashmap_put (slicer->modifier_handlers, &key, cbs,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
}


int
slicer_modifier_remove (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct SlicerModifierRemoveClosure *rm_cls = cls;
  struct GNUNET_SOCIAL_Slicer *slicer = rm_cls->slicer;
  struct SlicerModifierCallbacks *rm_cbs = &rm_cls->rm_cbs;
  struct SlicerModifierCallbacks *cbs = value;

  if (cbs->modifier_cb == rm_cbs->modifier_cb)
  {
    GNUNET_CONTAINER_multihashmap_remove (slicer->modifier_handlers, key, cbs);
    GNUNET_free (cbs);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Remove a registered modifier from the try-and-slice instance.
 *
 * Removes one matching handler registered with the given
 * @a object_filter and @a modifier_cb.
 *
 * @param slicer
 *        The try-and-slice instance.
 * @param object_filter
 *        Object prefix to match.
 * @param modifier_cb
 *        Function to call when encountering a state modifier changes.
 */
int
GNUNET_SOCIAL_slicer_modifier_remove (struct GNUNET_SOCIAL_Slicer *slicer,
                                      const char *object_filter,
                                      GNUNET_SOCIAL_ModifierCallback modifier_cb)
{
  struct GNUNET_HashCode key;
  GNUNET_CRYPTO_hash (object_filter, strlen (object_filter), &key);

  struct SlicerModifierRemoveClosure rm_cls;
  rm_cls.slicer = slicer;
  struct SlicerModifierCallbacks *rm_cbs = &rm_cls.rm_cbs;
  rm_cbs->modifier_cb = modifier_cb;

  return
    (GNUNET_SYSERR
     == GNUNET_CONTAINER_multihashmap_get_multiple (slicer->modifier_handlers, &key,
                                                    slicer_modifier_remove,
                                                    &rm_cls))
    ? GNUNET_NO
    : GNUNET_OK;
 }


int
slicer_method_free (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct SlicerMethodCallbacks *cbs = value;
  GNUNET_free (cbs);
  return GNUNET_YES;
}


/**
 * Destroy a given try-and-slice instance.
 *
 * @param slicer
 *        Slicer to destroy
 */
void
GNUNET_SOCIAL_slicer_destroy (struct GNUNET_SOCIAL_Slicer *slicer)
{
  GNUNET_CONTAINER_multihashmap_iterate (slicer->method_handlers,
                                         slicer_method_free, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (slicer->method_handlers);
  GNUNET_free (slicer);
}


/*** PLACE ***/


static void
place_send_connect_msg (struct GNUNET_SOCIAL_Place *plc)
{
  uint16_t cmsg_size = ntohs (plc->connect_msg->size);
  struct GNUNET_MessageHeader * cmsg = GNUNET_malloc (cmsg_size);
  memcpy (cmsg, plc->connect_msg, cmsg_size);
  GNUNET_CLIENT_MANAGER_transmit_now (plc->client, cmsg);
}


static void
place_recv_disconnect (void *cls,
                       struct GNUNET_CLIENT_MANAGER_Connection *client,
                       const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Place *
    plc = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*plc));

  GNUNET_CLIENT_MANAGER_reconnect (client);
  place_send_connect_msg (plc);
}


static void
place_recv_result (void *cls,
                   struct GNUNET_CLIENT_MANAGER_Connection *client,
                   const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Place *
    plc = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*plc));

  const struct GNUNET_OperationResultMessage *
    res = (const struct GNUNET_OperationResultMessage *) msg;

  uint16_t size = ntohs (msg->size);
  if (size < sizeof (*res))
  { /* Error, message too small. */
    GNUNET_break (0);
    return;
  }

  uint16_t data_size = size - sizeof (*res);
  const char *data = (0 < data_size) ? (const char *) &res[1] : NULL;
  GNUNET_CLIENT_MANAGER_op_result (plc->client, GNUNET_ntohll (res->op_id),
                                   GNUNET_ntohll (res->result_code),
                                   data, data_size);
}


static void
op_recv_history_result (void *cls, int64_t result,
                        const void *err_msg, uint16_t err_msg_size)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received history replay result: %" PRId64 ".\n", result);

  struct GNUNET_SOCIAL_HistoryRequest *hist = cls;

  if (NULL != hist->result_cb)
    hist->result_cb (hist->cls, result, err_msg, err_msg_size);

  GNUNET_PSYC_receive_destroy (hist->recv);
  GNUNET_free (hist);
}


static void
op_recv_state_result (void *cls, int64_t result,
                      const void *err_msg, uint16_t err_msg_size)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received state request result: %" PRId64 ".\n", result);

  struct GNUNET_SOCIAL_LookHandle *look = cls;

  if (NULL != look->result_cb)
    look->result_cb (look->cls, result, err_msg, err_msg_size);

  GNUNET_free (look);
}


static void
place_recv_history_result (void *cls,
                           struct GNUNET_CLIENT_MANAGER_Connection *client,
                           const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Place *
    plc = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*plc));

  const struct GNUNET_OperationResultMessage *
    res = (const struct GNUNET_OperationResultMessage *) msg;
  struct GNUNET_PSYC_MessageHeader *
    pmsg = (struct GNUNET_PSYC_MessageHeader *) &res[1];

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%p Received historic fragment for message #%" PRIu64 ".\n",
       plc, GNUNET_ntohll (pmsg->message_id));

  GNUNET_ResultCallback result_cb = NULL;
  struct GNUNET_SOCIAL_HistoryRequest *hist = NULL;

  if (GNUNET_YES != GNUNET_CLIENT_MANAGER_op_find (plc->client,
                                                   GNUNET_ntohll (res->op_id),
                                                   &result_cb, (void *) &hist))
  { /* Operation not found. */
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "%p Replay operation not found for historic fragment of message #%"
         PRIu64 ".\n",
         plc, GNUNET_ntohll (pmsg->message_id));
    return;
  }

  uint16_t size = ntohs (msg->size);
  if (size < sizeof (*res) + sizeof (*pmsg))
  { /* Error, message too small. */
    GNUNET_break (0);
    return;
  }

  GNUNET_PSYC_receive_message (hist->recv,
                               (const struct GNUNET_PSYC_MessageHeader *) pmsg);
}


static void
place_recv_state_result (void *cls,
                         struct GNUNET_CLIENT_MANAGER_Connection *client,
                         const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Place *
    plc = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*plc));

  const struct GNUNET_OperationResultMessage *
    res = (const struct GNUNET_OperationResultMessage *) msg;

  GNUNET_ResultCallback result_cb = NULL;
  struct GNUNET_SOCIAL_LookHandle *look = NULL;

  if (GNUNET_YES != GNUNET_CLIENT_MANAGER_op_find (plc->client,
                                                   GNUNET_ntohll (res->op_id),
                                                   &result_cb, (void *) &look))
  { /* Operation not found. */
    return;
  }

  const struct GNUNET_MessageHeader *
    mod = (struct GNUNET_MessageHeader *) &res[1];
  uint16_t mod_size = ntohs (mod->size);
  if (ntohs (msg->size) - sizeof (*res) != mod_size)
  {
    GNUNET_break_op (0);
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Invalid modifier size in state result: %u - %u != %u\n",
         ntohs (msg->size), sizeof (*res), mod_size);
    return;
  }
  switch (ntohs (mod->type))
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
  {
    const struct GNUNET_PSYC_MessageModifier *
      pmod = (const struct GNUNET_PSYC_MessageModifier *) mod;

    const char *name = (const char *) &pmod[1];
    uint16_t name_size = ntohs (pmod->name_size);
    if ('\0' != name[name_size - 1])
    {
      GNUNET_break_op (0);
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Invalid modifier name in state result\n");
      return;
    }
    look->mod_value_size = ntohs (pmod->value_size);
    look->var_cb (look->cls, mod, name, name + name_size,
                  mod_size - sizeof (*mod) - name_size,
                  look->mod_value_size);
    if (look->mod_value_size > mod_size - sizeof (*mod) - name_size)
    {
        look->mod_value_remaining = look->mod_value_size;
        look->mod_name = GNUNET_malloc (name_size);
        memcpy (look->mod_name, name, name_size);
    }
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT:
    look->var_cb (look->cls, mod, look->mod_name, (const char *) &mod[1],
                  mod_size - sizeof (*mod), look->mod_value_size);
    look->mod_value_remaining -= mod_size - sizeof (*mod);
    if (0 == look->mod_value_remaining)
    {
        GNUNET_free (look->mod_name);
    }
    break;
  }
}


static void
place_recv_message_ack (void *cls,
                        struct GNUNET_CLIENT_MANAGER_Connection *client,
                        const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Place *
    plc = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*plc));
  GNUNET_PSYC_transmit_got_ack (plc->tmit);
}


static void
place_recv_message (void *cls,
                    struct GNUNET_CLIENT_MANAGER_Connection *client,
                    const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Place *
    plc = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*plc));
  GNUNET_PSYC_receive_message (plc->recv,
                               (const struct GNUNET_PSYC_MessageHeader *) msg);
}


static void
host_recv_message (void *cls,
                   struct GNUNET_CLIENT_MANAGER_Connection *client,
                   const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Host *
    hst = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (hst->plc));
  GNUNET_PSYC_receive_message (hst->recv,
                               (const struct GNUNET_PSYC_MessageHeader *) msg);
  GNUNET_PSYC_receive_message (hst->plc.recv,
                               (const struct GNUNET_PSYC_MessageHeader *) msg);
}


static void
host_recv_enter_ack (void *cls,
                     struct GNUNET_CLIENT_MANAGER_Connection *client,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Host *
    hst = GNUNET_CLIENT_MANAGER_get_user_context_ (client,
                                                   sizeof (struct GNUNET_SOCIAL_Place));

  struct GNUNET_PSYC_CountersResultMessage *
    cres = (struct GNUNET_PSYC_CountersResultMessage *) msg;
  int32_t result = ntohl (cres->result_code);
  if (NULL != hst->enter_cb)
    hst->enter_cb (hst->cb_cls, result, GNUNET_ntohll (cres->max_message_id));
}


static void
host_recv_enter_request (void *cls,
                         struct GNUNET_CLIENT_MANAGER_Connection *client,
                         const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Host *
    hst = GNUNET_CLIENT_MANAGER_get_user_context_ (client,
                                                   sizeof (struct GNUNET_SOCIAL_Place));
  if (NULL == hst->answer_door_cb)
     return;

  const char *method_name = NULL;
  struct GNUNET_ENV_Environment *env = NULL;
  struct GNUNET_PSYC_MessageHeader *entry_pmsg = NULL;
  const void *data = NULL;
  uint16_t data_size = 0;
  char *str;
  const struct GNUNET_PSYC_JoinRequestMessage *
    req = (const struct GNUNET_PSYC_JoinRequestMessage *) msg;
  const struct GNUNET_PSYC_Message *entry_msg = NULL;

  do
  {
    if (sizeof (*req) + sizeof (*entry_msg) <= ntohs (req->header.size))
    {
      entry_msg = (struct GNUNET_PSYC_Message *) &req[1];
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Received entry_msg of type %u and size %u.\n",
           ntohs (entry_msg->header.type), ntohs (entry_msg->header.size));

      env = GNUNET_ENV_environment_create ();
      entry_pmsg = GNUNET_PSYC_message_header_create_from_psyc (entry_msg);
      if (GNUNET_OK != GNUNET_PSYC_message_parse (entry_pmsg, &method_name, env,
                                                  &data, &data_size))
      {
        GNUNET_break_op (0);
        str = GNUNET_CRYPTO_ecdsa_public_key_to_string (&req->slave_key);
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Ignoring invalid entry request from nym %s.\n",
             str);
        GNUNET_free (str);
        break;
      }
    }

    struct GNUNET_SOCIAL_Nym *nym = nym_get_or_create (&req->slave_key);
    hst->answer_door_cb (hst->cb_cls, nym, method_name, env,
                         data_size, data);
  } while (0);

  if (NULL != env)
    GNUNET_ENV_environment_destroy (env);
  if (NULL != entry_pmsg)
    GNUNET_free (entry_pmsg);
}


static void
guest_recv_enter_ack (void *cls,
                     struct GNUNET_CLIENT_MANAGER_Connection *client,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Guest *
    gst = GNUNET_CLIENT_MANAGER_get_user_context_ (client,
                                                   sizeof (struct GNUNET_SOCIAL_Place));

  struct GNUNET_PSYC_CountersResultMessage *
    cres = (struct GNUNET_PSYC_CountersResultMessage *) msg;
  int32_t result = ntohl (cres->result_code);
  if (NULL != gst->enter_cb)
    gst->enter_cb (gst->cb_cls, result, GNUNET_ntohll (cres->max_message_id));
}


static void
guest_recv_join_decision (void *cls,
                          struct GNUNET_CLIENT_MANAGER_Connection *client,
                          const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Guest *
    gst = GNUNET_CLIENT_MANAGER_get_user_context_ (client,
                                                   sizeof (struct GNUNET_SOCIAL_Place));
  const struct GNUNET_PSYC_JoinDecisionMessage *
    dcsn = (const struct GNUNET_PSYC_JoinDecisionMessage *) msg;

  struct GNUNET_PSYC_Message *pmsg = NULL;
  if (ntohs (dcsn->header.size) <= sizeof (*dcsn) + sizeof (*pmsg))
    pmsg = (struct GNUNET_PSYC_Message *) &dcsn[1];

  if (NULL != gst->entry_dcsn_cb)
    gst->entry_dcsn_cb (gst->cb_cls, ntohl (dcsn->is_admitted), pmsg);
}


static struct GNUNET_CLIENT_MANAGER_MessageHandler host_handlers[] =
{
  { host_recv_enter_ack, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER_ACK,
    sizeof (struct GNUNET_PSYC_CountersResultMessage), GNUNET_NO },

  { host_recv_enter_request, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_JOIN_REQUEST,
    sizeof (struct GNUNET_PSYC_JoinRequestMessage), GNUNET_YES },

  { host_recv_message, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MESSAGE,
    sizeof (struct GNUNET_PSYC_MessageHeader), GNUNET_YES },

  { place_recv_message_ack, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_ACK,
    sizeof (struct GNUNET_MessageHeader), GNUNET_NO },

  { place_recv_history_result, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_HISTORY_RESULT,
    sizeof (struct GNUNET_OperationResultMessage), GNUNET_YES },

  { place_recv_state_result, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_STATE_RESULT,
    sizeof (struct GNUNET_OperationResultMessage), GNUNET_YES },

  { place_recv_result, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_RESULT_CODE,
    sizeof (struct GNUNET_OperationResultMessage), GNUNET_YES },

  { place_recv_disconnect, NULL, 0, 0, GNUNET_NO },

  { NULL, NULL, 0, 0, GNUNET_NO }
};


static struct GNUNET_CLIENT_MANAGER_MessageHandler guest_handlers[] =
{
  { guest_recv_enter_ack, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER_ACK,
    sizeof (struct GNUNET_PSYC_CountersResultMessage), GNUNET_NO },

  { host_recv_enter_request, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_JOIN_REQUEST,
    sizeof (struct GNUNET_PSYC_JoinRequestMessage), GNUNET_YES },

  { place_recv_message, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MESSAGE,
    sizeof (struct GNUNET_PSYC_MessageHeader), GNUNET_YES },

  { place_recv_message_ack, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_ACK,
    sizeof (struct GNUNET_MessageHeader), GNUNET_NO },

  { guest_recv_join_decision, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_JOIN_DECISION,
    sizeof (struct GNUNET_PSYC_JoinDecisionMessage), GNUNET_YES },

  { place_recv_history_result, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_HISTORY_RESULT,
    sizeof (struct GNUNET_OperationResultMessage), GNUNET_YES },

  { place_recv_state_result, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_STATE_RESULT,
    sizeof (struct GNUNET_OperationResultMessage), GNUNET_YES },

  { place_recv_result, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_RESULT_CODE,
    sizeof (struct GNUNET_OperationResultMessage), GNUNET_YES },

  { place_recv_disconnect, NULL, 0, 0, GNUNET_NO },

  { NULL, NULL, 0, 0, GNUNET_NO }
};


static void
place_cleanup (struct GNUNET_SOCIAL_Place *plc)
{
  if (NULL != plc->tmit)
    GNUNET_PSYC_transmit_destroy (plc->tmit);
  if (NULL != plc->recv)
    GNUNET_PSYC_receive_destroy (plc->recv);
  if (NULL != plc->connect_msg)
    GNUNET_free (plc->connect_msg);
  if (NULL != plc->disconnect_cb)
    plc->disconnect_cb (plc->disconnect_cls);

  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
  if (NULL != namestore)
  {
    GNUNET_NAMESTORE_disconnect (namestore);
    namestore = NULL;
  }
  if (NULL != gns)
  {
    GNUNET_GNS_disconnect (gns);
    gns = NULL;
  }
}


static void
host_cleanup (void *cls)
{
  struct GNUNET_SOCIAL_Host *hst = cls;
  place_cleanup (&hst->plc);
  GNUNET_PSYC_receive_destroy (hst->recv);
  GNUNET_SOCIAL_slicer_destroy (hst->slicer);
  GNUNET_free (hst);
}


static void
guest_cleanup (void *cls)
{
  struct GNUNET_SOCIAL_Guest *gst = cls;
  place_cleanup (&gst->plc);
  GNUNET_free (gst);
}


/*** HOST ***/

/**
 * Enter a place as host.
 *
 * A place is created upon first entering, and it is active until permanently
 * left using GNUNET_SOCIAL_host_leave().
 *
 * @param cfg
 *        Configuration to contact the social service.
 * @param ego
 *        Identity of the host.
 * @param place_key
 *        Private-public key pair of the place.
 *        NULL for ephemeral places.
 * @param policy
 *        Policy specifying entry and history restrictions for the place.
 * @param slicer
 *        Slicer to handle incoming messages.
 * @param answer_door_cb
 *        Function to handle new nyms that want to enter.
 * @param farewell_cb
 *        Function to handle departing nyms.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle for the host.
 */
struct GNUNET_SOCIAL_Host *
GNUNET_SOCIAL_host_enter (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const struct GNUNET_IDENTITY_Ego *ego,
                          const struct GNUNET_CRYPTO_EddsaPrivateKey *place_key,
                          enum GNUNET_PSYC_Policy policy,
                          struct GNUNET_SOCIAL_Slicer *slicer,
                          GNUNET_SOCIAL_HostEnterCallback enter_cb,
                          GNUNET_SOCIAL_AnswerDoorCallback answer_door_cb,
                          GNUNET_SOCIAL_FarewellCallback farewell_cb,
                          void *cls)
{
  struct GNUNET_SOCIAL_Host *hst = GNUNET_malloc (sizeof (*hst));
  struct GNUNET_SOCIAL_Place *plc = &hst->plc;
  struct HostEnterRequest *req = GNUNET_malloc (sizeof (*req));

  if (NULL != place_key)
  {
    hst->place_key = *place_key;
  }
  else
  {
    struct GNUNET_CRYPTO_EddsaPrivateKey *
      ephemeral_key = GNUNET_CRYPTO_eddsa_key_create ();
    hst->place_key = *ephemeral_key;
    GNUNET_CRYPTO_eddsa_key_get_public (&hst->place_key, &plc->pub_key);
    GNUNET_CRYPTO_eddsa_key_clear (ephemeral_key);
    GNUNET_free (ephemeral_key);
  }

  req->header.size = htons (sizeof (*req));
  req->header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER);
  req->policy = policy;
  req->place_key = hst->place_key;
  req->host_key = plc->ego_key;

  plc->connect_msg = (struct GNUNET_MessageHeader *) req;
  plc->cfg = cfg;
  plc->is_host = GNUNET_YES;
  plc->slicer = slicer;

  plc->ego_key = *GNUNET_IDENTITY_ego_get_private_key (ego);
  GNUNET_CRYPTO_eddsa_key_get_public (place_key, &plc->pub_key);

  hst->enter_cb = enter_cb;
  hst->answer_door_cb = answer_door_cb;
  hst->farewell_cb = farewell_cb;
  hst->cb_cls = cls;

  plc->client = GNUNET_CLIENT_MANAGER_connect (cfg, "social", host_handlers);
  GNUNET_CLIENT_MANAGER_set_user_context_ (plc->client, hst, sizeof (*plc));

  plc->tmit = GNUNET_PSYC_transmit_create (plc->client);
  plc->recv = GNUNET_PSYC_receive_create (NULL, slicer_message, plc->slicer);

  hst->slicer = GNUNET_SOCIAL_slicer_create ();
  GNUNET_SOCIAL_slicer_method_add (hst->slicer, "_notice_place_leave",
                                   host_recv_notice_place_leave_method,
                                   host_recv_notice_place_leave_modifier,
                                   NULL, host_recv_notice_place_leave_eom, hst);
  hst->recv = GNUNET_PSYC_receive_create (NULL, slicer_message, hst->slicer);

  place_send_connect_msg (plc);
  return hst;
}


/**
 * Enter a place as host.
 *
 * A place is created upon first entering, and it is active until permanently
 * left using GNUNET_SOCIAL_host_leave().
 *
 * @param cfg
 *        Configuration to contact the social service.
 * @param ego
 *        Identity of the host.
 * @param gns_name
 *        GNS name in the zone of the @a ego that contains the
 *        public key of the place in a PLACE record.
 * @param policy
 *        Policy specifying entry and history restrictions for the place.
 * @param slicer
 *        Slicer to handle incoming messages.
 * @param answer_door_cb
 *        Function to handle new nyms that want to enter.
 * @param farewell_cb
 *        Function to handle departing nyms.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle for the host.
 */
struct GNUNET_SOCIAL_Host *
GNUNET_SOCIAL_host_enter_by_name (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                  struct GNUNET_IDENTITY_Ego *ego,
                                  const char *gns_name,
                                  enum GNUNET_PSYC_Policy policy,
                                  struct GNUNET_SOCIAL_Slicer *slicer,
                                  GNUNET_SOCIAL_HostEnterCallback enter_cb,
                                  GNUNET_SOCIAL_AnswerDoorCallback answer_door_cb,
                                  GNUNET_SOCIAL_FarewellCallback farewell_cb,
                                  void *cls)
{
  struct GNUNET_CRYPTO_EddsaPrivateKey place_key = {};

  /* FIXME:
   * 1. get public key by looking up PLACE entry under gns_name
   *    in the zone of the ego.
   * 2. get private key from $GNUNET_DATA_HOME/social/places/PUB_KEY_HASH
   */

  return GNUNET_SOCIAL_host_enter (cfg, ego, &place_key, policy, slicer,
                                   enter_cb, answer_door_cb, farewell_cb, cls);
}


/**
 * Decision whether to admit @a nym into the place or refuse entry.
 *
 * @param hst
 *        Host of the place.
 * @param nym
 *        Handle for the entity that wanted to enter.
 * @param is_admitted
 *        #GNUNET_YES    if @a nym is admitted,
 *        #GNUNET_NO     if @a nym is refused entry,
 *        #GNUNET_SYSERR if we cannot answer the request.
 * @param method_name
 *        Method name for the rejection message.
 * @param env
 *        Environment containing variables for the message, or NULL.
 * @param data
 *        Data for the rejection message to send back.
 * @param data_size
 *        Number of bytes in @a data for method.
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR if the message is too large.
 */
int
GNUNET_SOCIAL_host_entry_decision (struct GNUNET_SOCIAL_Host *hst,
                                   struct GNUNET_SOCIAL_Nym *nym,
                                   int is_admitted,
                                   const struct GNUNET_PSYC_Message *entry_resp)
{
  struct GNUNET_PSYC_JoinDecisionMessage *dcsn;
  uint16_t entry_resp_size
    = (NULL != entry_resp) ? ntohs (entry_resp->header.size) : 0;

  if (GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD < sizeof (*dcsn) + entry_resp_size)
    return GNUNET_SYSERR;

  dcsn = GNUNET_malloc (sizeof (*dcsn) + entry_resp_size);
  dcsn->header.size = htons (sizeof (*dcsn) + entry_resp_size);
  dcsn->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_JOIN_DECISION);
  dcsn->is_admitted = htonl (is_admitted);
  dcsn->slave_key = nym->pub_key;

  if (0 < entry_resp_size)
    memcpy (&dcsn[1], entry_resp, entry_resp_size);

  GNUNET_CLIENT_MANAGER_transmit (hst->plc.client, &dcsn->header);
  return GNUNET_OK;
}


/**
 * Throw @a nym out of the place.
 *
 * The @a nym reference will remain valid until the
 * #GNUNET_SOCIAL_FarewellCallback is invoked,
 * which should be very soon after this call.
 *
 * @param host
 *        Host of the place.
 * @param nym
 *        Handle for the entity to be ejected.
 */
void
GNUNET_SOCIAL_host_eject (struct GNUNET_SOCIAL_Host *hst,
                          const struct GNUNET_SOCIAL_Nym *nym)
{
  struct GNUNET_ENV_Environment *env = GNUNET_ENV_environment_create ();
  GNUNET_ENV_environment_add (env, GNUNET_ENV_OP_SET,
                              "_nym", &nym->pub_key, sizeof (nym->pub_key));
  GNUNET_SOCIAL_host_announce (hst, "_notice_place_leave", env, NULL, NULL,
                               GNUNET_SOCIAL_ANNOUNCE_NONE);
}


/**
 * Get the public key of a @a nym.
 *
 * Suitable, for example, to be used with GNUNET_NAMESTORE_zone_to_name().
 *
 * @param nym
 *        Pseudonym to map to a cryptographic identifier.
 *
 * @return Public key of nym.
 */
const struct GNUNET_CRYPTO_EcdsaPublicKey *
GNUNET_SOCIAL_nym_get_key (const struct GNUNET_SOCIAL_Nym *nym)
{
  return &nym->pub_key;
}


/**
 * Get the hash of the public key of a @a nym.
 *
 * @param nym
 *        Pseudonym to map to a cryptographic identifier.
 *
 * @return Hash of the public key of nym.
 */
const struct GNUNET_HashCode *
GNUNET_SOCIAL_nym_get_key_hash (const struct GNUNET_SOCIAL_Nym *nym)
{
  return &nym->pub_key_hash;
}


/**
 * Obtain the private-public key pair of the hosted place.
 *
 * The public part is suitable for storing in GNS within a PLACE record,
 * along with peer IDs to join at.
 *
 * @param host
 *        Host of the place.
 *
 * @return Private-public key pair of the hosted place.
 */
const struct GNUNET_CRYPTO_EddsaPrivateKey *
GNUNET_SOCIAL_host_get_place_key (struct GNUNET_SOCIAL_Host *hst)
{
  return &hst->place_key;
}


/**
 * Connected to core service.
 */
static void
core_connected_cb  (void *cls, const struct GNUNET_PeerIdentity *my_identity)
{
  this_peer = *my_identity;
  // FIXME
}


/**
 * Advertise the place in the GNS zone of the @e ego of the @a host.
 *
 * @param hst
 *        Host of the place.
 * @param name
 *        The name for the PLACE record to put in the zone.
 * @param peer_count
 *        Number of elements in the @a peers array.
 * @param peers
 *        List of peers to put in the PLACE record to advertise
 *        as entry points to the place in addition to the origin.
 * @param expiration_time
 *        Expiration time of the record, use 0 to remove the record.
 * @param password
 *        Password used to encrypt the record or NULL to keep it cleartext.
 * @param result_cb
 *        Function called with the result of the operation.
 * @param result_cls
 *        Closure for @a result_cb
 */
void
GNUNET_SOCIAL_host_advertise (struct GNUNET_SOCIAL_Host *hst,
                              const char *name,
                              uint32_t peer_count,
                              const struct GNUNET_PeerIdentity *peers,
                              struct GNUNET_TIME_Absolute expiration_time,
                              const char *password,
                              GNUNET_NAMESTORE_ContinuationWithStatus result_cb,
                              void *result_cls)
{
  struct GNUNET_SOCIAL_Place *plc = &hst->plc;
  if (NULL == namestore)
    namestore = GNUNET_NAMESTORE_connect (plc->cfg);
  if (NULL == core)
    core = GNUNET_CORE_connect (plc->cfg, NULL, core_connected_cb, NULL, NULL,
                                NULL, GNUNET_NO, NULL, GNUNET_NO, NULL);

  struct GNUNET_GNSRECORD_Data rd = { };
  rd.record_type = GNUNET_GNSRECORD_TYPE_PLACE;
  rd.flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  rd.expiration_time = expiration_time.abs_value_us;

  struct GNUNET_GNSRECORD_PlaceData *
    rec = GNUNET_malloc (sizeof (*rec) + peer_count * sizeof (*peers));
  rec->place_key = plc->pub_key;
  rec->origin = this_peer;
  rec->relay_count = htonl (peer_count);
  memcpy (&rec[1], peers, peer_count * sizeof (*peers));

  rd.data = rec;
  rd.data_size = sizeof (*rec) + peer_count * sizeof (*peers);

  GNUNET_NAMESTORE_records_store (namestore, &hst->plc.ego_key,
                                  name, 1, &rd, result_cb, result_cls);
}


/**
 * Send a message to all nyms that are present in the place.
 *
 * This function is restricted to the host.  Nyms can only send requests
 * to the host who can decide to relay it to everyone in the place.
 *
 * @param host  Host of the place.
 * @param method_name Method to use for the announcement.
 * @param env  Environment containing variables for the message and operations
 *          on objects of the place.  Can be NULL.
 * @param notify Function to call to get the payload of the announcement.
 * @param notify_cls Closure for @a notify.
 * @param flags Flags for this announcement.
 *
 * @return NULL on error (announcement already in progress?).
 */
struct GNUNET_SOCIAL_Announcement *
GNUNET_SOCIAL_host_announce (struct GNUNET_SOCIAL_Host *hst,
                             const char *method_name,
                             const struct GNUNET_ENV_Environment *env,
                             GNUNET_PSYC_TransmitNotifyData notify_data,
                             void *notify_data_cls,
                             enum GNUNET_SOCIAL_AnnounceFlags flags)
{
  if (GNUNET_OK ==
      GNUNET_PSYC_transmit_message (hst->plc.tmit, method_name, env,
                                    NULL, notify_data, notify_data_cls, flags))
    return (struct GNUNET_SOCIAL_Announcement *) hst->plc.tmit;
  else
    return NULL;
}


/**
 * Resume transmitting announcement.
 *
 * @param a
 *        The announcement to resume.
 */
void
GNUNET_SOCIAL_host_announce_resume (struct GNUNET_SOCIAL_Announcement *a)
{
  GNUNET_PSYC_transmit_resume ((struct GNUNET_PSYC_TransmitHandle *) a);
}


/**
 * Cancel announcement.
 *
 * @param a
 *        The announcement to cancel.
 */
void
GNUNET_SOCIAL_host_announce_cancel (struct GNUNET_SOCIAL_Announcement *a)
{
  GNUNET_PSYC_transmit_cancel ((struct GNUNET_PSYC_TransmitHandle *) a);
}


/**
 * Obtain handle for a hosted place.
 *
 * The returned handle can be used to access the place API.
 *
 * @param host  Handle for the host.
 *
 * @return Handle for the hosted place, valid as long as @a host is valid.
 */
struct GNUNET_SOCIAL_Place *
GNUNET_SOCIAL_host_get_place (struct GNUNET_SOCIAL_Host *hst)
{
  return &hst->plc;
}


/**
 * Stop hosting a place.
 *
 * Invalidates host handle.
 *
 * @param host  Host leaving the place.
 * @param keep_active  Keep the place active after last host disconnected.
 */
void
GNUNET_SOCIAL_host_leave (struct GNUNET_SOCIAL_Host *hst,
                          int keep_active,
                          GNUNET_ContinuationCallback leave_cb,
                          void *leave_cls)
{
  struct GNUNET_SOCIAL_Place *plc = &hst->plc;

 /* FIXME: send msg to service */

  plc->is_disconnecting = GNUNET_YES;
  plc->disconnect_cb = leave_cb;
  plc->disconnect_cls = leave_cls;

  GNUNET_CLIENT_MANAGER_disconnect (plc->client, GNUNET_YES,
                                    &host_cleanup, hst);
}


/*** GUEST ***/

static struct GuestEnterRequest *
guest_enter_request_create (const struct GNUNET_CRYPTO_EcdsaPrivateKey *guest_key,
                            const struct GNUNET_CRYPTO_EddsaPublicKey *place_key,
                            const struct GNUNET_PeerIdentity *origin,
                            size_t relay_count,
                            const struct GNUNET_PeerIdentity *relays,
                            const struct GNUNET_PSYC_Message *join_msg)
{
  uint16_t join_msg_size = ntohs (join_msg->header.size);
  uint16_t relay_size = relay_count * sizeof (*relays);

  struct GuestEnterRequest *
    req = GNUNET_malloc (sizeof (*req) + relay_size + join_msg_size);

  req->header.size = htons (sizeof (*req) + relay_size + join_msg_size);
  req->header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER);
  req->place_key = *place_key;
  req->guest_key = *guest_key;
  req->origin = *origin;
  req->relay_count = htonl (relay_count);

  uint16_t p = sizeof (*req);
  if (0 < relay_size)
  {
    memcpy ((char *) req + p, relays, relay_size);
    p += relay_size;
  }

  memcpy ((char *) req + p, join_msg, join_msg_size);
  return req;
}

/**
 * Request entry to a place as a guest.
 *
 * @param cfg Configuration to contact the social service.
 * @param ego  Identity of the guest.
 * @param crypto_address Public key of the place to enter.
 * @param origin Peer identity of the origin of the underlying multicast group.
 * @param relay_count Number of elements in the @a relays array.
 * @param relays Relays for the underlying multicast group.
 * @param method_name Method name for the message.
 * @param env Environment containing variables for the message, or NULL.
 * @param data Payload for the message to give to the enter callback.
 * @param data_size Number of bytes in @a data.
 * @param slicer Slicer to use for processing incoming requests from guests.
 *
 * @return NULL on errors, otherwise handle for the guest.
 */
struct GNUNET_SOCIAL_Guest *
GNUNET_SOCIAL_guest_enter (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           const struct GNUNET_IDENTITY_Ego *ego,
                           const struct GNUNET_CRYPTO_EddsaPublicKey *place_key,
                           const struct GNUNET_PeerIdentity *origin,
                           uint32_t relay_count,
                           const struct GNUNET_PeerIdentity *relays,
                           const struct GNUNET_PSYC_Message *entry_msg,
                           struct GNUNET_SOCIAL_Slicer *slicer,
                           GNUNET_SOCIAL_GuestEnterCallback local_enter_cb,
                           GNUNET_SOCIAL_EntryDecisionCallback entry_dcsn_cb,
                           void *cls)
{
  struct GNUNET_SOCIAL_Guest *gst = GNUNET_malloc (sizeof (*gst));
  struct GNUNET_SOCIAL_Place *plc = &gst->plc;

  plc->ego_key = *GNUNET_IDENTITY_ego_get_private_key (ego);
  plc->pub_key = *place_key;
  plc->cfg = cfg;
  plc->is_host = GNUNET_YES;
  plc->slicer = slicer;

  gst->enter_cb = local_enter_cb;
  gst->entry_dcsn_cb = entry_dcsn_cb;
  gst->cb_cls = cls;

  plc->client = GNUNET_CLIENT_MANAGER_connect (cfg, "social", guest_handlers);
  GNUNET_CLIENT_MANAGER_set_user_context_ (plc->client, gst, sizeof (*plc));

  plc->tmit = GNUNET_PSYC_transmit_create (plc->client);
  plc->recv = GNUNET_PSYC_receive_create (NULL, slicer_message, plc->slicer);

  struct GuestEnterRequest *
    req = guest_enter_request_create (&plc->ego_key, place_key, origin,
                                      relay_count, relays, entry_msg);
  plc->connect_msg = &req->header;
  place_send_connect_msg (plc);
  return gst;
}


/**
 * Result of a GNS name lookup for entering a place.
 *
 * @see GNUNET_SOCIAL_guest_enter_by_name
 */
static void
gns_result_guest_enter (void *cls, uint32_t rd_count,
                        const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_SOCIAL_Guest *gst = cls;
  struct GNUNET_SOCIAL_Place *plc = &gst->plc;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%p GNS result: %u records.\n", gst, rd_count);

  const struct GNUNET_GNSRECORD_PlaceData *
    rec = (const struct GNUNET_GNSRECORD_PlaceData *) rd->data;

  if (0 == rd_count)
  {
    if (NULL != gst->enter_cb)
      gst->enter_cb (gst->cb_cls, GNUNET_SYSERR, 0);
    return;
  }

  if (rd->data_size < sizeof (*rec))
  {
    GNUNET_break_op (0);
    if (NULL != gst->enter_cb)
      gst->enter_cb (gst->cb_cls, GNUNET_SYSERR, 0);
    return;
  }

  uint16_t relay_count = ntohl (rec->relay_count);
  struct GNUNET_PeerIdentity *relays = NULL;

  if (0 < relay_count)
  {
    if (rd->data_size == sizeof (*rec) + relay_count * sizeof (struct GNUNET_PeerIdentity))
    {
      relays = (struct GNUNET_PeerIdentity *) &rec[1];
    }
    else
    {
      relay_count = 0;
      GNUNET_break_op (0);
    }
  }

  struct GuestEnterRequest *
    req = guest_enter_request_create (&plc->ego_key, &rec->place_key,
                                      &rec->origin, relay_count, relays,
                                      (struct GNUNET_PSYC_Message *) plc->connect_msg);
  GNUNET_free (plc->connect_msg);
  plc->connect_msg = &req->header;
  plc->pub_key = req->place_key;

  plc->tmit = GNUNET_PSYC_transmit_create (plc->client);
  plc->recv = GNUNET_PSYC_receive_create (NULL, slicer_message, plc->slicer);

  place_send_connect_msg (plc);
}


/**
 * Request entry to a place by name as a guest.
 *
 * @param cfg
 *        Configuration to contact the social service.
 * @param ego
 *        Identity of the guest.
 * @param gns_name
 *        GNS name of the place to enter.  Either in the form of
 *        'room.friend.gnu', or 'NYMPUBKEY.zkey'.  This latter case refers to
 *        the 'PLACE' record of the empty label ("+") in the GNS zone with the
 *        nym's public key 'NYMPUBKEY', and can be used to request entry to a
 *        pseudonym's place directly.
 * @param password
 *        Password to decrypt the record, or NULL for cleartext records.
 * @param join_msg
 *        Entry request message.
 * @param slicer
 *        Slicer to use for processing incoming requests from guests.
 * @param local_enter_cb
 *        Called upon connection established to the social service.
 * @param entry_decision_cb
 *        Called upon receiving entry decision.
 *
 * @return NULL on errors, otherwise handle for the guest.
 */
struct GNUNET_SOCIAL_Guest *
GNUNET_SOCIAL_guest_enter_by_name (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                   const struct GNUNET_IDENTITY_Ego *ego,
                                   const char *gns_name, const char *password,
                                   const struct GNUNET_PSYC_Message *join_msg,
                                   struct GNUNET_SOCIAL_Slicer *slicer,
                                   GNUNET_SOCIAL_GuestEnterCallback local_enter_cb,
                                   GNUNET_SOCIAL_EntryDecisionCallback entry_decision_cb,
                                   void *cls)
{
  struct GNUNET_SOCIAL_Guest *gst = GNUNET_malloc (sizeof (*gst));
  struct GNUNET_SOCIAL_Place *plc = &gst->plc;

  GNUNET_assert (NULL != join_msg);

  gst->enter_cb = local_enter_cb;
  gst->entry_dcsn_cb = entry_decision_cb;
  gst->cb_cls = cls;

  plc->ego_key = *GNUNET_IDENTITY_ego_get_private_key (ego);
  plc->cfg = cfg;
  plc->is_host = GNUNET_NO;
  plc->slicer = slicer;

  uint16_t join_msg_size = ntohs (join_msg->header.size);
  plc->connect_msg = GNUNET_malloc (join_msg_size);
  memcpy (plc->connect_msg, join_msg, join_msg_size);

  if (NULL == gns)
    gns = GNUNET_GNS_connect (cfg);

  plc->client = GNUNET_CLIENT_MANAGER_connect (cfg, "social", guest_handlers);
  GNUNET_CLIENT_MANAGER_set_user_context_ (plc->client, gst, sizeof (*plc));

  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key;
  GNUNET_IDENTITY_ego_get_public_key (ego, &ego_pub_key);
  GNUNET_GNS_lookup (gns, gns_name, &ego_pub_key,
                     GNUNET_GNSRECORD_TYPE_PLACE, GNUNET_GNS_LO_DEFAULT,
                     NULL, gns_result_guest_enter, gst);
  return gst;
}


/**
 * Talk to the host of the place.
 *
 * @param place
 *        Place where we want to talk to the host.
 * @param method_name
 *        Method to invoke on the host.
 * @param env
 *        Environment containing variables for the message, or NULL.
 * @param notify_data
 *        Function to use to get the payload for the method.
 * @param notify_data_cls
 *        Closure for @a notify_data.
 * @param flags
 *        Flags for the message being sent.
 *
 * @return NULL if we are already trying to talk to the host,
 *         otherwise handle to cancel the request.
 */
struct GNUNET_SOCIAL_TalkRequest *
GNUNET_SOCIAL_guest_talk (struct GNUNET_SOCIAL_Guest *gst,
                          const char *method_name,
                          const struct GNUNET_ENV_Environment *env,
                          GNUNET_PSYC_TransmitNotifyData notify_data,
                          void *notify_data_cls,
                          enum GNUNET_SOCIAL_TalkFlags flags)
{
  struct GNUNET_SOCIAL_Place *plc = &gst->plc;
  GNUNET_assert (NULL != plc->tmit);

  if (GNUNET_OK ==
      GNUNET_PSYC_transmit_message (plc->tmit, method_name, env,
                                    NULL, notify_data, notify_data_cls, flags))
    return (struct GNUNET_SOCIAL_TalkRequest *) plc->tmit;
  else
    return NULL;
}


/**
 * Resume talking to the host of the place.
 *
 * @param tr
 *        Talk request to resume.
 */
void
GNUNET_SOCIAL_guest_talk_resume (struct GNUNET_SOCIAL_TalkRequest *tr)
{
  GNUNET_PSYC_transmit_resume ((struct GNUNET_PSYC_TransmitHandle *) tr);
}


/**
 * Cancel talking to the host of the place.
 *
 * @param tr
 *        Talk request to cancel.
 */
void
GNUNET_SOCIAL_guest_talk_cancel (struct GNUNET_SOCIAL_TalkRequest *tr)
{
  GNUNET_PSYC_transmit_cancel ((struct GNUNET_PSYC_TransmitHandle *) tr);
}


/**
 * Leave a place temporarily or permanently.
 *
 * Notifies the owner of the place about leaving, and destroys the place handle.
 *
 * @param place
 *        Place to leave.
 * @param keep_active
 *        Keep place active after last application disconnected.
 *        #GNUNET_YES or #GNUNET_NO
 * @param env
 *        Optional environment for the leave message if @a keep_active
 *        is #GNUNET_NO.  NULL if not needed.
 * @param leave_cb
 *        Called upon disconnecting from the social service.
 */
void
GNUNET_SOCIAL_guest_leave (struct GNUNET_SOCIAL_Guest *gst,
                           int keep_active,
                           struct GNUNET_ENV_Environment *env,
                           GNUNET_ContinuationCallback leave_cb,
                           void *leave_cls)
{
  struct GNUNET_SOCIAL_Place *plc = &gst->plc;

  plc->is_disconnecting = GNUNET_YES;
  plc->disconnect_cb = leave_cb;
  plc->disconnect_cls = leave_cls;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Guest: leaving place.\n");

  if (GNUNET_NO == keep_active && NULL != plc->tmit)
  {
    GNUNET_SOCIAL_guest_talk (gst, "_notice_place_leave", env, NULL, NULL,
                              GNUNET_SOCIAL_TALK_NONE);
  }

  GNUNET_CLIENT_MANAGER_disconnect (plc->client, GNUNET_YES,
                                    &guest_cleanup, gst);
}


/**
 * Obtain handle for a place entered as guest.
 *
 * The returned handle can be used to access the place API.
 *
 * @param guest  Handle for the guest.
 *
 * @return Handle for the place, valid as long as @a guest is valid.
 */
struct GNUNET_SOCIAL_Place *
GNUNET_SOCIAL_guest_get_place (struct GNUNET_SOCIAL_Guest *gst)
{
  return &gst->plc;
}


static struct GNUNET_SOCIAL_HistoryRequest *
place_history_replay (struct GNUNET_SOCIAL_Place *plc,
                      uint64_t start_message_id,
                      uint64_t end_message_id,
                      uint64_t message_limit,
                      const char *method_prefix,
                      uint32_t flags,
                      struct GNUNET_SOCIAL_Slicer *slicer,
                      GNUNET_ResultCallback result_cb,
                      void *cls)
{
  struct GNUNET_PSYC_HistoryRequestMessage *req;
  struct GNUNET_SOCIAL_HistoryRequest *hist = GNUNET_malloc (sizeof (*hist));
  hist->plc = plc;
  hist->recv = GNUNET_PSYC_receive_create (NULL, slicer_message, slicer);
  hist->result_cb = result_cb;
  hist->cls = cls;
  hist->op_id = GNUNET_CLIENT_MANAGER_op_add (plc->client,
                                              &op_recv_history_result, hist);

  GNUNET_assert (NULL != method_prefix);
  uint16_t method_size = strnlen (method_prefix,
                                  GNUNET_SERVER_MAX_MESSAGE_SIZE
                                  - sizeof (*req)) + 1;
  GNUNET_assert ('\0' == method_prefix[method_size - 1]);
  req = GNUNET_malloc (sizeof (*req) + method_size);
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_HISTORY_REPLAY);
  req->header.size = htons (sizeof (*req) + method_size);
  req->start_message_id = GNUNET_htonll (start_message_id);
  req->end_message_id = GNUNET_htonll (end_message_id);
  req->message_limit = GNUNET_htonll (message_limit);
  req->flags = htonl (flags);
  req->op_id = GNUNET_htonll (hist->op_id);
  memcpy (&req[1], method_prefix, method_size);

  GNUNET_CLIENT_MANAGER_transmit (plc->client, &req->header);
  return hist;
}


/**
 * Learn about the history of a place.
 *
 * Messages are returned through the @a slicer function
 * and have the #GNUNET_PSYC_MESSAGE_HISTORIC flag set.
 *
 * @param place
 *        Place we want to learn more about.
 * @param start_message_id
 *        First historic message we are interested in.
 * @param end_message_id
 *        Last historic message we are interested in (inclusive).
 * @param method_prefix
 *        Only retrieve messages with this method prefix.
 * @param flags
 *        OR'ed GNUNET_PSYC_HistoryReplayFlags
 * @param slicer
 *        Slicer to use for retrieved messages.
 *        Can be the same as the slicer of the place.
 * @param result_cb
 *        Function called after all messages retrieved.
 *        NULL if not needed.
 * @param cls Closure for @a result_cb.
 */
struct GNUNET_SOCIAL_HistoryRequest *
GNUNET_SOCIAL_place_history_replay (struct GNUNET_SOCIAL_Place *plc,
                                    uint64_t start_message_id,
                                    uint64_t end_message_id,
                                    const char *method_prefix,
                                    uint32_t flags,
                                    struct GNUNET_SOCIAL_Slicer *slicer,
                                    GNUNET_ResultCallback result_cb,
                                    void *cls)
{
  return place_history_replay (plc, start_message_id, end_message_id, 0,
                               method_prefix, flags, slicer, result_cb, cls);
}


/**
 * Learn about the history of a place.
 *
 * Sends messages through the slicer function of the place where
 * start_message_id <= message_id <= end_message_id.
 * The messages will have the #GNUNET_PSYC_MESSAGE_HISTORIC flag set.
 *
 * To get the latest message, use 0 for both the start and end message ID.
 *
 * @param place
 *        Place we want to learn more about.
 * @param message_limit
 *        Maximum number of historic messages we are interested in.
 * @param method_prefix
 *        Only retrieve messages with this method prefix.
 * @param flags
 *        OR'ed GNUNET_PSYC_HistoryReplayFlags
 * @param result_cb
 *        Function called after all messages retrieved.
 *        NULL if not needed.
 * @param cls Closure for @a result_cb.
 */
struct GNUNET_SOCIAL_HistoryRequest *
GNUNET_SOCIAL_place_history_replay_latest (struct GNUNET_SOCIAL_Place *plc,
                                           uint64_t message_limit,
                                           const char *method_prefix,
                                           uint32_t flags,
                                           struct GNUNET_SOCIAL_Slicer *slicer,
                                           GNUNET_ResultCallback result_cb,
                                           void *cls)
{
  return place_history_replay (plc, 0, 0, message_limit, method_prefix, flags,
                               slicer, result_cb, cls);
}


/**
 * Cancel learning about the history of a place.
 *
 * @param hist
 *        History lesson to cancel.
 */
void
GNUNET_SOCIAL_place_history_replay_cancel (struct GNUNET_SOCIAL_HistoryRequest *hist)
{
  GNUNET_PSYC_receive_destroy (hist->recv);
  GNUNET_CLIENT_MANAGER_op_cancel (hist->plc->client, hist->op_id);
  GNUNET_free (hist);
}


/**
 * Request matching state variables.
 */
static struct GNUNET_SOCIAL_LookHandle *
place_state_get (struct GNUNET_SOCIAL_Place *plc,
                 uint16_t type, const char *name,
                 GNUNET_PSYC_StateVarCallback var_cb,
                 GNUNET_ResultCallback result_cb, void *cls)
{
  struct GNUNET_PSYC_StateRequestMessage *req;
  struct GNUNET_SOCIAL_LookHandle *look = GNUNET_malloc (sizeof (*look));
  look->plc = plc;
  look->var_cb = var_cb;
  look->result_cb = result_cb;
  look->cls = cls;
  look->op_id = GNUNET_CLIENT_MANAGER_op_add (plc->client,
                                              &op_recv_state_result, look);

  GNUNET_assert (NULL != name);
  size_t name_size = strnlen (name, GNUNET_SERVER_MAX_MESSAGE_SIZE
                              - sizeof (*req)) + 1;
  req = GNUNET_malloc (sizeof (*req) + name_size);
  req->header.type = htons (type);
  req->header.size = htons (sizeof (*req) + name_size);
  req->op_id = GNUNET_htonll (look->op_id);
  memcpy (&req[1], name, name_size);

  GNUNET_CLIENT_MANAGER_transmit (plc->client, &req->header);
  return look;
}


/**
 * Look at a particular object in the place.
 *
 * The best matching object is returned (its name might be less specific than
 * what was requested).
 *
 * @param place
 *        The place where to look.
 * @param full_name
 *        Full name of the object.
 * @param value_size
 *        Set to the size of the returned value.
 *
 * @return NULL if there is no such object at this place.
 */
struct GNUNET_SOCIAL_LookHandle *
GNUNET_SOCIAL_place_look_at (struct GNUNET_SOCIAL_Place *plc,
                             const char *full_name,
                             GNUNET_PSYC_StateVarCallback var_cb,
                             GNUNET_ResultCallback result_cb,
                             void *cls)
{
  return place_state_get (plc, GNUNET_MESSAGE_TYPE_PSYC_STATE_GET,
                          full_name, var_cb, result_cb, cls);
}


/**
 * Look for objects in the place with a matching name prefix.
 *
 * @param place
 *        The place where to look.
 * @param name_prefix
 *        Look at objects with names beginning with this value.
 * @param var_cb
 *        Function to call for each object found.
 * @param cls
 *        Closure for callback function.
 *
 * @return Handle that can be used to stop looking at objects.
 */
struct GNUNET_SOCIAL_LookHandle *
GNUNET_SOCIAL_place_look_for (struct GNUNET_SOCIAL_Place *plc,
                              const char *name_prefix,
                              GNUNET_PSYC_StateVarCallback var_cb,
                              GNUNET_ResultCallback result_cb,
                              void *cls)
{
  return place_state_get (plc, GNUNET_MESSAGE_TYPE_PSYC_STATE_GET_PREFIX,
                          name_prefix, var_cb, result_cb, cls);
}


/**
 * Cancel a state request operation.
 *
 * @param sr
 *        Handle for the operation to cancel.
 */
void
GNUNET_SOCIAL_place_look_cancel (struct GNUNET_SOCIAL_LookHandle *look)
{
  GNUNET_CLIENT_MANAGER_op_cancel (look->plc->client, look->op_id);
  GNUNET_free (look);
}


/**
 * Add public key to the GNS zone of the @e ego.
 *
 * @param cfg
 *        Configuration.
 * @param ego
 *        Ego.
 * @param name
 *        The name for the PKEY record to put in the zone.
 * @param pub_key
 *        Public key to add.
 * @param expiration_time
 *        Expiration time of the record, use 0 to remove the record.
 * @param result_cb
 *        Function called with the result of the operation.
 * @param result_cls
 *        Closure for @a result_cb
 */
void
GNUNET_SOCIAL_zone_add_pkey (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             const struct GNUNET_IDENTITY_Ego *ego,
                             const char *name,
                             const struct GNUNET_CRYPTO_EcdsaPublicKey *pub_key,
                             struct GNUNET_TIME_Absolute expiration_time,
                             GNUNET_NAMESTORE_ContinuationWithStatus result_cb,
                             void *result_cls)
{
  if (NULL == namestore)
    namestore = GNUNET_NAMESTORE_connect (cfg);

  struct GNUNET_GNSRECORD_Data rd = { };
  rd.record_type = GNUNET_GNSRECORD_TYPE_PKEY;
  rd.flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  rd.expiration_time = expiration_time.abs_value_us;
  rd.data = pub_key;
  rd.data_size = sizeof (*pub_key);

  GNUNET_NAMESTORE_records_store (namestore,
                                  GNUNET_IDENTITY_ego_get_private_key (ego),
                                  name, 1, &rd, result_cb, result_cls);
}


/* end of social_api.c */
