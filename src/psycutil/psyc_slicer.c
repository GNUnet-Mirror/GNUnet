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
 * @author Gabor X Toth
 *
 * @file
 * PSYC Slicer API
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_psyc_util_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "psyc-util-slicer",__VA_ARGS__)


/**
 * Handle for a try-and-slice instance.
 */
struct GNUNET_PSYC_Slicer
{
  /**
   * Method handlers: H(method_name) -> SlicerMethodCallbacks
   */
  struct GNUNET_CONTAINER_MultiHashMap *method_handlers;

  /**
   * Modifier handlers: H(modifier_name) -> SlicerModifierCallbacks
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
  struct GNUNET_CRYPTO_EcdsaPublicKey nym_pub_key;

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
  GNUNET_PSYC_MethodCallback method_cb;
  GNUNET_PSYC_ModifierCallback modifier_cb;
  GNUNET_PSYC_DataCallback data_cb;
  GNUNET_PSYC_EndOfMessageCallback eom_cb;
  void *cls;
};


struct SlicerMethodRemoveClosure
{
  struct GNUNET_PSYC_Slicer *slicer;
  struct SlicerMethodCallbacks rm_cbs;
};


/**
 * Callbacks for a slicer method handler.
 */
struct SlicerModifierCallbacks
{
  GNUNET_PSYC_ModifierCallback modifier_cb;
  void *cls;
};


struct SlicerModifierRemoveClosure
{
  struct GNUNET_PSYC_Slicer *slicer;
  struct SlicerModifierCallbacks rm_cbs;
};


/**
 * Call a method handler for an incoming message part.
 */
int
slicer_method_handler_notify (void *cls, const struct GNUNET_HashCode *key,
                              void *value)
{
  struct GNUNET_PSYC_Slicer *slicer = cls;
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
                    &slicer->nym_pub_key,
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
  struct GNUNET_PSYC_Slicer *slicer = cls;
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
void
GNUNET_PSYC_slicer_message (void *cls, const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_pub_key,
                            uint64_t message_id, uint32_t flags, uint64_t fragment_offset,
                            const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PSYC_Slicer *slicer = cls;
  slicer->nym_pub_key = *slave_pub_key;

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

  char *nym_str = GNUNET_CRYPTO_ecdsa_public_key_to_string (slave_pub_key);
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
struct GNUNET_PSYC_Slicer *
GNUNET_PSYC_slicer_create (void)
{
  struct GNUNET_PSYC_Slicer *slicer = GNUNET_malloc (sizeof (*slicer));
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
GNUNET_PSYC_slicer_method_add (struct GNUNET_PSYC_Slicer *slicer,
                               const char *method_name,
                               GNUNET_PSYC_MethodCallback method_cb,
                               GNUNET_PSYC_ModifierCallback modifier_cb,
                               GNUNET_PSYC_DataCallback data_cb,
                               GNUNET_PSYC_EndOfMessageCallback eom_cb,
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
  struct GNUNET_PSYC_Slicer *slicer = rm_cls->slicer;
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
GNUNET_PSYC_slicer_method_remove (struct GNUNET_PSYC_Slicer *slicer,
                                  const char *method_name,
                                  GNUNET_PSYC_MethodCallback method_cb,
                                  GNUNET_PSYC_ModifierCallback modifier_cb,
                                  GNUNET_PSYC_DataCallback data_cb,
                                  GNUNET_PSYC_EndOfMessageCallback eom_cb)
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
GNUNET_PSYC_slicer_modifier_add (struct GNUNET_PSYC_Slicer *slicer,
                                 const char *object_filter,
                                 GNUNET_PSYC_ModifierCallback modifier_cb,
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
  struct GNUNET_PSYC_Slicer *slicer = rm_cls->slicer;
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
GNUNET_PSYC_slicer_modifier_remove (struct GNUNET_PSYC_Slicer *slicer,
                                    const char *object_filter,
                                    GNUNET_PSYC_ModifierCallback modifier_cb)
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
GNUNET_PSYC_slicer_destroy (struct GNUNET_PSYC_Slicer *slicer)
{
  GNUNET_CONTAINER_multihashmap_iterate (slicer->method_handlers,
                                         slicer_method_free, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (slicer->method_handlers);
  GNUNET_free (slicer);
}
