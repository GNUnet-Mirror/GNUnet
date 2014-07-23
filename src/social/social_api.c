 /*
 * This file is part of GNUnet
 * (C) 2013 Christian Grothoff (and other contributing authors)
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
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
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
   * Transmission handle;
   */
  struct GNUNET_PSYC_TransmitHandle *tmit;

  /**
   * Receipt handle;
   */
  struct GNUNET_PSYC_ReceiveHandle *recv;

  /**
   * Message to send on reconnect.
   */
  struct GNUNET_MessageHeader *connect_msg;

  /**
   * Slicer for processing incoming methods.
   */
  struct GNUNET_SOCIAL_Slicer *slicer;

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

  GNUNET_SOCIAL_HostEnterCallback enter_cb;

  GNUNET_SOCIAL_AnswerDoorCallback answer_door_cb;

  GNUNET_SOCIAL_FarewellCallback farewell_cb;

  /**
   * Closure for callbacks.
   */
  void *cb_cls;
};


/**
 * Guest handle for place that we entered.
 */
struct GNUNET_SOCIAL_Guest
{
  struct GNUNET_SOCIAL_Place plc;

  GNUNET_SOCIAL_GuestEnterCallback enter_cb;

  GNUNET_SOCIAL_EntryDecisionCallback entry_dcsn_cb;

  /**
   * Closure for callbacks.
   */
  void *cb_cls;
};


/**
 * Handle for a pseudonym of another user in the network.
 */
struct GNUNET_SOCIAL_Nym
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pub_key;
  struct GNUNET_HashCode pub_key_hash;
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
   * Message handlers: method_name -> SlicerCallbacks
   */
  struct GNUNET_CONTAINER_MultiHashMap *handlers;


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
   * Public key of the nym the current message originates from.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey nym_key;

  /**
   * Size of @a method_name (including terminating \0).
   */
  uint16_t method_name_size;
};


/**
 * Callbacks for a slicer method handler.
 */
struct SlicerCallbacks
{
  GNUNET_SOCIAL_MethodCallback method_cb;
  GNUNET_SOCIAL_ModifierCallback modifier_cb;
  GNUNET_SOCIAL_DataCallback data_cb;
  GNUNET_SOCIAL_EndOfMessageCallback eom_cb;
  void *cls;
};


struct SlicerRemoveClosure
{
  struct GNUNET_SOCIAL_Slicer *slicer;
  struct SlicerCallbacks rm_cbs;
};


/**
 * Handle for an announcement request.
 */
struct GNUNET_SOCIAL_Announcement
{

};


struct GNUNET_SOCIAL_WatchHandle
{

};


struct GNUNET_SOCIAL_LookHandle
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
struct GNUNET_SOCIAL_HistoryLesson
{

};


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


/**
 * Call a handler for an incoming message part.
 *
 * @param cls
 * @param key
 * @param value
 *
 * @return
 */
int
slicer_handler_notify (void *cls, const struct GNUNET_HashCode *key,
                       void *value)
{
  struct GNUNET_SOCIAL_Slicer *slicer = cls;
  const struct GNUNET_MessageHeader *msg = slicer->msg;
  struct SlicerCallbacks *cbs = value;
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
    cbs->modifier_cb (cbs->cls, mod, slicer->message_id,
                      mod->oper, (const char *) &mod[1],
                      (const void *) &mod[1] + ntohs (mod->name_size),
                      ntohs (mod->value_size));
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT:
  {
    if (NULL == cbs->modifier_cb)
      break;
    /* FIXME: concatenate until done */
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
slicer_message (void *cls, uint64_t message_id, uint64_t fragment_offset,
                uint32_t flags, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Slicer *slicer = cls;
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

  LOG (GNUNET_ERROR_TYPE_WARNING,
       "Slicer received message of type %u and size %u, "
       "with ID %" PRIu64 " and method %s\n",
       ptype, ntohs (msg->size), message_id, slicer->method_name);

  slicer->msg = msg;
  char *name = GNUNET_malloc (slicer->method_name_size);
  memcpy (name, slicer->method_name, slicer->method_name_size);
  do
  {
    struct GNUNET_HashCode key;
    uint16_t name_len = strlen (name);
    GNUNET_CRYPTO_hash (name, name_len, &key);
    GNUNET_CONTAINER_multihashmap_get_multiple (slicer->handlers, &key,
                                                &slicer_handler_notify, slicer);
    char *p = strrchr (name, '_');
    if (NULL == p)
      break;
    *p = '\0';
  } while (1);
  GNUNET_free (name);
  slicer->msg = NULL;

  if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END <= ptype)
    GNUNET_free (slicer->method_name);
}


/**
 * Create a try-and-slice instance.
 *
 * @return A new try-and-slice construct.
 */
struct GNUNET_SOCIAL_Slicer *
GNUNET_SOCIAL_slicer_create (void)
{
  struct GNUNET_SOCIAL_Slicer *slicer = GNUNET_malloc (sizeof (*slicer));
  slicer->handlers = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  return slicer;
}


/**
 * Add a method to the try-and-slice instance.
 *
 * A slicer processes messages and calls methods that match a message. A match
 * happens whenever the method name of a message starts with the method_name
 * parameter given here.
 *
 * @param slicer The try-and-slice instance to extend.
 * @param method_name Name of the given method, use empty string for default.
 * @param method Method to invoke.
 * @param method_cls Closure for method.
 */
void
GNUNET_SOCIAL_slicer_add (struct GNUNET_SOCIAL_Slicer *slicer,
                          const char *method_name,
                          GNUNET_SOCIAL_MethodCallback method_cb,
                          GNUNET_SOCIAL_ModifierCallback modifier_cb,
                          GNUNET_SOCIAL_DataCallback data_cb,
                          GNUNET_SOCIAL_EndOfMessageCallback eom_cb,
                          void *cls)
{
  struct GNUNET_HashCode key;
  GNUNET_CRYPTO_hash (method_name, strlen (method_name), &key);

  struct SlicerCallbacks *cbs = GNUNET_malloc (sizeof (*cbs));
  cbs->method_cb = method_cb;
  cbs->modifier_cb = modifier_cb;
  cbs->data_cb = data_cb;
  cbs->eom_cb = eom_cb;
  cbs->cls = cls;

  GNUNET_CONTAINER_multihashmap_put (slicer->handlers, &key, cbs,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
}


int
slicer_remove_handler (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct SlicerRemoveClosure *rm_cls = cls;
  struct GNUNET_SOCIAL_Slicer *slicer = rm_cls->slicer;
  struct SlicerCallbacks *rm_cbs = &rm_cls->rm_cbs;
  struct SlicerCallbacks *cbs = value;

  if (cbs->method_cb == rm_cbs->method_cb
      && cbs->modifier_cb == rm_cbs->modifier_cb
      && cbs->data_cb == rm_cbs->data_cb
      && cbs->eom_cb == rm_cbs->eom_cb)
  {
    GNUNET_CONTAINER_multihashmap_remove (slicer->handlers, key, cbs);
    GNUNET_free (cbs);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Remove a registered method from the try-and-slice instance.
 *
 * Removes the first matching handler registered with @a method and the given callbacks.
 *
 * @param slicer The try-and-slice instance.
 * @param method_name Name of the method to remove.
 * @param method Method handler.
 *
 * @return #GNUNET_OK if a method handler was removed,
 *         #GNUNET_NO if no handler matched the given method name and callbacks.
 */
int
GNUNET_SOCIAL_slicer_remove (struct GNUNET_SOCIAL_Slicer *slicer,
                             const char *method_name,
                             GNUNET_SOCIAL_MethodCallback method_cb,
                             GNUNET_SOCIAL_ModifierCallback modifier_cb,
                             GNUNET_SOCIAL_DataCallback data_cb,
                             GNUNET_SOCIAL_EndOfMessageCallback eom_cb)
{
  struct GNUNET_HashCode key;
  GNUNET_CRYPTO_hash (method_name, strlen (method_name), &key);

  struct SlicerRemoveClosure rm_cls;
  rm_cls.slicer = slicer;
  struct SlicerCallbacks *rm_cbs = &rm_cls.rm_cbs;
  rm_cbs->method_cb = method_cb;
  rm_cbs->modifier_cb = modifier_cb;
  rm_cbs->data_cb = data_cb;
  rm_cbs->eom_cb = eom_cb;

  return
    (GNUNET_SYSERR
     == GNUNET_CONTAINER_multihashmap_get_multiple (slicer->handlers, &key,
                                                    &slicer_remove_handler,
                                                    &rm_cls))
    ? GNUNET_NO
    : GNUNET_OK;
}


int
slicer_free_handler (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct SlicerCallbacks *cbs = value;
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
  GNUNET_CONTAINER_multihashmap_iterate (slicer->handlers, &slicer_free_handler,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (slicer->handlers);
  GNUNET_free (slicer);
}


static void
place_send_connect_msg (struct GNUNET_SOCIAL_Place *plc)
{
  uint16_t cmsg_size = ntohs (plc->connect_msg->size);
  struct GNUNET_MessageHeader * cmsg = GNUNET_malloc (cmsg_size);
  memcpy (cmsg, plc->connect_msg, cmsg_size);
  GNUNET_CLIENT_MANAGER_transmit_now (plc->client, cmsg);
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
host_recv_enter_ack (void *cls,
                     struct GNUNET_CLIENT_MANAGER_Connection *client,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Host *
    hst = GNUNET_CLIENT_MANAGER_get_user_context_ (client,
                                                   sizeof (struct GNUNET_SOCIAL_Place));

  struct GNUNET_PSYC_CountersResultMessage *
    cres = (struct GNUNET_PSYC_CountersResultMessage *) msg;
  if (NULL != hst->enter_cb)
    hst->enter_cb (hst->cb_cls, GNUNET_ntohll (cres->max_message_id));
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
  const void *data = NULL;
  uint16_t data_size = 0;

  const struct GNUNET_PSYC_JoinRequestMessage *
    req = (const struct GNUNET_PSYC_JoinRequestMessage *) msg;
  const struct GNUNET_PSYC_Message *entry_msg = NULL;
  if (sizeof (*req) + sizeof (*entry_msg) <= ntohs (req->header.size))
  {
    entry_msg = (struct GNUNET_PSYC_Message *) &req[1];
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received entry_msg of type %u and size %u.\n",
         ntohs (entry_msg->header.type), ntohs (entry_msg->header.size));

    env = GNUNET_ENV_environment_create ();
    if (GNUNET_OK != GNUNET_PSYC_message_parse (entry_msg, &method_name, env,
                                                &data, &data_size))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Ignoring invalid entry request from nym %s.\n",
           GNUNET_CRYPTO_ecdsa_public_key_to_string (&req->slave_key));
      GNUNET_break_op (0);
      GNUNET_ENV_environment_destroy (env);
      return;
    }
  }

  struct GNUNET_SOCIAL_Nym *nym = nym_get_or_create (&req->slave_key);
  hst->answer_door_cb (hst->cb_cls, nym, method_name, env,
                       data_size, data);

  if (NULL != env)
    GNUNET_ENV_environment_destroy (env);
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
  if (NULL != gst->enter_cb)
    gst->enter_cb (gst->cb_cls, ntohl (cres->result_code),
                   GNUNET_ntohll (cres->max_message_id));
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
  { &host_recv_enter_ack, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER_ACK,
    sizeof (struct CountersResult), GNUNET_NO },

  { &host_recv_enter_request, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_JOIN_REQUEST,
    sizeof (struct GNUNET_PSYC_JoinRequestMessage), GNUNET_YES },

  { &place_recv_message, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MESSAGE,
    sizeof (struct GNUNET_PSYC_MessageHeader), GNUNET_YES },

  { &place_recv_message_ack, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_ACK,
    sizeof (struct GNUNET_MessageHeader), GNUNET_NO },

  { &place_recv_disconnect, NULL, 0, 0, GNUNET_NO },

  { NULL, NULL, 0, 0, GNUNET_NO }
};


static struct GNUNET_CLIENT_MANAGER_MessageHandler guest_handlers[] =
{
  { &guest_recv_enter_ack, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER_ACK,
    sizeof (struct CountersResult), GNUNET_NO },

  { &host_recv_enter_request, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_JOIN_REQUEST,
    sizeof (struct GNUNET_PSYC_JoinRequestMessage), GNUNET_YES },

  { &place_recv_message, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MESSAGE,
    sizeof (struct GNUNET_PSYC_MessageHeader), GNUNET_YES },

  { &place_recv_message_ack, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_ACK,
    sizeof (struct GNUNET_MessageHeader), GNUNET_NO },

  { &guest_recv_join_decision, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_JOIN_DECISION,
    sizeof (struct GNUNET_PSYC_JoinDecisionMessage), GNUNET_YES },

  { &place_recv_disconnect, NULL, 0, 0, GNUNET_NO },

  { NULL, NULL, 0, 0, GNUNET_NO }
};


static void
place_cleanup (struct GNUNET_SOCIAL_Place *plc)
{
  GNUNET_PSYC_transmit_destroy (plc->tmit);
  GNUNET_PSYC_receive_destroy (plc->recv);
  GNUNET_free (plc->connect_msg);
  if (NULL != plc->disconnect_cb)
    plc->disconnect_cb (plc->disconnect_cls);
}


static void
host_cleanup (void *cls)
{
  struct GNUNET_SOCIAL_Host *hst = cls;
  place_cleanup (&hst->plc);
  GNUNET_free (hst);
}


static void
guest_cleanup (void *cls)
{
  struct GNUNET_SOCIAL_Guest *gst = cls;
  place_cleanup (&gst->plc);
  GNUNET_free (gst);
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
  plc->ego_key = *GNUNET_IDENTITY_ego_get_private_key (ego);

  req->header.size = htons (sizeof (*req));
  req->header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER);
  req->policy = policy;
  req->place_key = hst->place_key;
  req->host_key = plc->ego_key;

  plc->connect_msg = (struct GNUNET_MessageHeader *) req;
  plc->cfg = cfg;
  plc->is_host = GNUNET_YES;
  plc->slicer = slicer;

  hst->plc.ego_key = *GNUNET_IDENTITY_ego_get_private_key (ego);
  hst->enter_cb = enter_cb;
  hst->answer_door_cb = answer_door_cb;
  hst->cb_cls = cls;

  plc->client = GNUNET_CLIENT_MANAGER_connect (cfg, "social", host_handlers);
  GNUNET_CLIENT_MANAGER_set_user_context_ (plc->client, hst, sizeof (*plc));

  plc->tmit = GNUNET_PSYC_transmit_create (plc->client);
  plc->recv = GNUNET_PSYC_receive_create (NULL, &slicer_message, plc->slicer);

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
 * @param host  Host of the place.
 * @param nym  Handle for the entity to be ejected.
 */
void
GNUNET_SOCIAL_host_eject (struct GNUNET_SOCIAL_Host *host,
                          struct GNUNET_SOCIAL_Nym *nym)
{

}


/**
 * Get the public key of a @a nym.
 *
 * Suitable, for example, to be used with GNUNET_NAMESTORE_zone_to_name().
 *
 * @param nym Pseudonym to map to a cryptographic identifier.
 * @param[out] nym_key Set to the public key of the nym.
 */
struct GNUNET_CRYPTO_EcdsaPublicKey *
GNUNET_SOCIAL_nym_get_key (struct GNUNET_SOCIAL_Nym *nym)
{
  return &nym->pub_key;
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


static void
namestore_result_host_advertise (void *cls, int32_t success, const char *emsg)
{

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
 * @param hst  Host of the place.
 * @param name The name for the PLACE record to put in the zone.
 * @param peer_count Number of elements in the @a peers array.
 * @param peers List of peers in the PLACE record that can be used to send join
 *        requests to.
 * @param expiration_time Expiration time of the record, use 0 to remove the record.
 * @param password Password used to encrypt the record.
 */
void
GNUNET_SOCIAL_host_advertise (struct GNUNET_SOCIAL_Host *hst,
                              const char *name,
                              size_t peer_count,
                              const struct GNUNET_PeerIdentity *peers,
                              struct GNUNET_TIME_Relative expiration_time,
                              const char *password)
{
  struct GNUNET_SOCIAL_Place *plc = &hst->plc;
  if (NULL == namestore)
    namestore = GNUNET_NAMESTORE_connect (plc->cfg);
  if (NULL == core)
    core = GNUNET_CORE_connect (plc->cfg, NULL, core_connected_cb, NULL, NULL,
                                NULL, GNUNET_NO, NULL, GNUNET_NO, NULL);

  struct GNUNET_GNSRECORD_Data rd = { 0 };
  rd.record_type = GNUNET_GNSRECORD_TYPE_PLACE;
  rd.flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  rd.expiration_time
    = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_WEEKS, 1).rel_value_us;

  struct GNUNET_GNSRECORD_PlaceData *rec = GNUNET_malloc (sizeof (*rec));
  rec->place_key = plc->pub_key;
  rec->origin = this_peer;
  rec->relay_count = htons (0); // FIXME

  rd.data_size = sizeof (*rec);
  rd.data = rec;

  GNUNET_NAMESTORE_records_store (namestore, &hst->plc.ego_key,
                                  name, 1, &rd, namestore_result_host_advertise,
                                  hst);
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
                                    NULL, notify_data, notify_data_cls, flags));
  return (struct GNUNET_SOCIAL_Announcement *) hst->plc.tmit;
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
  req->relay_count = relay_count;

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

  struct GuestEnterRequest *
    req = guest_enter_request_create (&plc->ego_key, place_key, origin,
                                      relay_count, relays, entry_msg);
  plc->connect_msg = &req->header;
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
  plc->recv = GNUNET_PSYC_receive_create (NULL, &slicer_message, plc->slicer);

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

  struct GuestEnterRequest *
    req = (struct GuestEnterRequest *) plc->connect_msg;
  uint16_t req_size = ntohs (req->header.size);

  struct GNUNET_PeerIdentity *relays = NULL;
  uint16_t relay_count = ntohs (rec->relay_count);

  if (0 < relay_count)
  {
    uint16_t relay_size = relay_count * sizeof (struct GNUNET_PeerIdentity);
    struct GuestEnterRequest *
      req2 = GNUNET_malloc (req_size + relay_size);

    req2->header.size = htons (req_size + relay_size);
    req2->header.type = req->header.type;
    req2->guest_key = req->guest_key;

    uint16_t p = sizeof (*req);
    if (0 < relay_size)
    {
      memcpy ((char *) req2 + p, relays, relay_size);
      p += relay_size;
    }

    memcpy ((char *) req + p, &req[1], req_size - sizeof (*req));

    plc->connect_msg = &req2->header;
    GNUNET_free (req);
    req = req2;
  }

  req->place_key = rec->place_key;
  req->origin = rec->origin;
  req->relay_count = rec->relay_count;
  memcpy (&req[1], &rec[1],
          ntohl (rec->relay_count) * sizeof (struct GNUNET_PeerIdentity));

  plc->connect_msg = &req->header;
  plc->pub_key = req->place_key;

  plc->tmit = GNUNET_PSYC_transmit_create (plc->client);
  plc->recv = GNUNET_PSYC_receive_create (NULL, &slicer_message, plc);

  place_send_connect_msg (plc);
}

/**
 * Request entry to a place as a guest.
 *
 * @param cfg  Configuration to contact the social service.
 * @param ego  Identity of the guest.
 * @param address GNS name of the place to enter.  Either in the form of
 *        'room.friend.gnu', or 'NYMPUBKEY.zkey'.  This latter case refers to
 *        the 'PLACE' record of the empty label ("+") in the GNS zone with the
 *        nym's public key 'NYMPUBKEY', and can be used to request entry to a
 *        pseudonym's place directly.
 * @param method_name Method name for the message.
 * @param env Environment containing variables for the message, or NULL.
 * @param data Payload for the message to give to the enter callback.
 * @param data_size Number of bytes in @a data.
 * @param slicer Slicer to use for processing incoming requests from guests.
 *
 * @return NULL on errors, otherwise handle for the guest.
 */
struct GNUNET_SOCIAL_Guest *
GNUNET_SOCIAL_guest_enter_by_name (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                   struct GNUNET_IDENTITY_Ego *ego,
                                   char *gns_name,
                                   const struct GNUNET_PSYC_Message *join_msg,
                                   struct GNUNET_SOCIAL_Slicer *slicer,
                                   GNUNET_SOCIAL_GuestEnterCallback local_enter_cb,
                                   GNUNET_SOCIAL_EntryDecisionCallback entry_decision_cb,
                                   void *cls)
{
  struct GNUNET_SOCIAL_Guest *gst = GNUNET_malloc (sizeof (*gst));
  struct GNUNET_SOCIAL_Place *plc = &gst->plc;

  gst->enter_cb = local_enter_cb;
  gst->cb_cls = cls;

  plc->ego_key = *GNUNET_IDENTITY_ego_get_private_key (ego);
  plc->cfg = cfg;
  plc->is_host = GNUNET_NO;
  plc->slicer = slicer;

  struct GuestEnterRequest *
    req = guest_enter_request_create (&plc->ego_key, NULL, NULL, 0, NULL,
                                      join_msg);
  plc->connect_msg = &req->header;

  /* FIXME: get the public key of the origin and relays
   *        by looking up the PLACE record of gns_name.
   */
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
GNUNET_SOCIAL_guest_talk (struct GNUNET_SOCIAL_Guest *guest,
                          const char *method_name,
                          const struct GNUNET_ENV_Environment *env,
                          GNUNET_PSYC_TransmitNotifyData notify_data,
                          void *notify_data_cls,
                          enum GNUNET_SOCIAL_TalkFlags flags)
{
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
 * Leave a place permanently.
 *
 * Notifies the owner of the place about leaving, and destroys the place handle.
 *
 * @param place Place to leave permanently.
 * @param keep_active Keep place active after last application disconnected.
 */
void
GNUNET_SOCIAL_guest_leave (struct GNUNET_SOCIAL_Guest *gst,
                           int keep_active,
                           GNUNET_ContinuationCallback leave_cb,
                           void *leave_cls)
{
  struct GNUNET_SOCIAL_Place *plc = &gst->plc;

  /* FIXME: send msg to service */

  plc->is_disconnecting = GNUNET_YES;
  plc->disconnect_cb = leave_cb;
  plc->disconnect_cls = leave_cls;

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


/**
 * A history lesson.
 */
struct GNUNET_SOCIAL_HistoryLesson;

/**
 * Learn about the history of a place.
 *
 * Sends messages through the slicer function of the place where
 * start_message_id <= message_id <= end_message_id.
 * The messages will have the #GNUNET_PSYC_MESSAGE_HISTORIC flag set.
 *
 * To get the latest message, use 0 for both the start and end message ID.
 *
 * @param place Place we want to learn more about.
 * @param start_message_id First historic message we are interested in.
 * @param end_message_id Last historic message we are interested in (inclusive).
 * @param slicer Slicer to use to process history.  Can be the same as the
 *               slicer of the place, as the HISTORIC flag allows distinguishing
 *               old messages from fresh ones.
 * @param finish_cb Function called after the last message in the history lesson
 *              is passed through the @a slicer. NULL if not needed.
 * @param finish_cb_cls Closure for @a finish_cb.
 * @return Handle to abort history lesson, never NULL (multiple lessons
 *         at the same time are allowed).
 */
struct GNUNET_SOCIAL_HistoryLesson *
GNUNET_SOCIAL_place_get_history (struct GNUNET_SOCIAL_Place *place,
                                 uint64_t start_message_id,
                                 uint64_t end_message_id,
                                 const struct GNUNET_SOCIAL_Slicer *slicer,
                                 void (*finish_cb)(void *),
                                 void *finish_cb_cls)
{
  return NULL;
}


/**
 * Stop processing messages from the history lesson.
 *
 * Must not be called after the finish callback of the history lesson is called.
 *
 * @param hist History lesson to cancel.
 */
void
GNUNET_SOCIAL_place_get_history_cancel (struct GNUNET_SOCIAL_HistoryLesson *hist)
{

}


struct GNUNET_SOCIAL_WatchHandle;

/**
 * Watch a place for changed objects.
 *
 * @param place Place to watch.
 * @param object_filter Object prefix to match.
 * @param state_cb Function to call when an object/state changes.
 * @param state_cb_cls Closure for callback.
 *
 * @return Handle that can be used to cancel watching.
 */
struct GNUNET_SOCIAL_WatchHandle *
GNUNET_SOCIAL_place_watch (struct GNUNET_SOCIAL_Place *place,
                           const char *object_filter,
                           GNUNET_PSYC_StateCallback state_cb,
                           void *state_cb_cls)
{
  return NULL;
}


/**
 * Cancel watching a place for changed objects.
 *
 * @param wh Watch handle to cancel.
 */
void
GNUNET_SOCIAL_place_watch_cancel (struct GNUNET_SOCIAL_WatchHandle *wh)
{

}


struct GNUNET_SOCIAL_LookHandle;


/**
 * Look at objects in the place with a matching name prefix.
 *
 * @param place The place to look its objects at.
 * @param name_prefix Look at objects with names beginning with this value.
 * @param state_cb Function to call for each object found.
 * @param state_cb_cls Closure for callback function.
 *
 * @return Handle that can be used to stop looking at objects.
 */
struct GNUNET_SOCIAL_LookHandle *
GNUNET_SOCIAL_place_look (struct GNUNET_SOCIAL_Place *place,
                          const char *name_prefix,
                          GNUNET_PSYC_StateCallback state_cb,
                          void *state_cb_cls)
{
  return NULL;
}


/**
 * Stop looking at objects.
 *
 * @param lh Look handle to stop.
 */
void
GNUNET_SOCIAL_place_look_cancel (struct GNUNET_SOCIAL_LookHandle *lh)
{

}



/**
 * Look at a particular object in the place.
 *
 * The best matching object is returned (its name might be less specific than
 * what was requested).
 *
 * @param place The place to look the object at.
 * @param full_name Full name of the object.
 * @param value_size Set to the size of the returned value.
 * @return NULL if there is no such object at this place.
 */
const void *
GNUNET_SOCIAL_place_look_at (struct GNUNET_SOCIAL_Place *place,
                             const char *full_name,
                             size_t *value_size)
{
  return NULL;
}


/* end of social_api.c */
