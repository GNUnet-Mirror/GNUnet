/*
 * This file is part of GNUnet
 * Copyright (C) 2013 GNUnet e.V.
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
 * Social service; implements social interactions using the PSYC service.
 */

#include <inttypes.h>
#include <string.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_psyc_service.h"
#include "gnunet_psyc_util_lib.h"
#include "gnunet_social_service.h"
#include "social.h"

#define LOG(kind,...) GNUNET_log_from (kind, "social-api",__VA_ARGS__)

/**
 * Handle for an ego.
 */
struct GNUNET_SOCIAL_Ego
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pub_key;
  struct GNUNET_HashCode pub_key_hash;
  char *name;
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
 * Handle for an application.
 */
struct GNUNET_SOCIAL_App
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Client connection to the service.
   */
  struct GNUNET_CLIENT_MANAGER_Connection *client;

  /*e
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
   * Application ID.
   */
  char *id;

  /**
   * Hash map of all egos.
   * pub_key_hash -> struct GNUNET_SOCIAL_Ego *
   */
  struct GNUNET_CONTAINER_MultiHashMap *egos;

  GNUNET_SOCIAL_AppEgoCallback ego_cb;
  GNUNET_SOCIAL_AppHostPlaceCallback host_cb;
  GNUNET_SOCIAL_AppGuestPlaceCallback guest_cb;
  void *cb_cls;

  /**
   * Is this place in the process of disconnecting from the service?
   * #GNUNET_YES or #GNUNET_NO
   */
  uint8_t is_disconnecting;
};


struct GNUNET_SOCIAL_HostConnection
{
  struct GNUNET_SOCIAL_App *app;

  struct AppPlaceMessage plc_msg;
};


struct GNUNET_SOCIAL_GuestConnection
{
  struct GNUNET_SOCIAL_App *app;

  struct AppPlaceMessage plc_msg;
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
   * Slicer for processing incoming messages.
   */
  struct GNUNET_PSYC_Slicer *slicer;

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
   * Public key of the ego.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key;

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

  /**
   * Slicer for processing incoming messages from guests.
   */
  struct GNUNET_PSYC_Slicer *slicer;

  GNUNET_SOCIAL_HostEnterCallback enter_cb;

  GNUNET_SOCIAL_AnswerDoorCallback answer_door_cb;

  GNUNET_SOCIAL_FarewellCallback farewell_cb;

  /**
   * Closure for callbacks.
   */
  void *cb_cls;

  struct GNUNET_SOCIAL_Nym *notice_place_leave_nym;
  struct GNUNET_PSYC_Environment *notice_place_leave_env;
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
 * Hash map of all nyms.
 * pub_key_hash -> struct GNUNET_SOCIAL_Nym *
 */
struct GNUNET_CONTAINER_MultiHashMap *nyms;


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
   * Slicer for processing incoming messages.
   */
  struct GNUNET_PSYC_Slicer *slicer;

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


struct ZoneAddPlaceHandle
{
  struct ZoneAddPlaceRequest *req;
  GNUNET_ResultCallback result_cb;
  void *result_cls;
};


struct ZoneAddNymHandle
{
  struct ZoneAddNymRequest *req;
  GNUNET_ResultCallback result_cb;
  void *result_cls;
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
                                     const struct GNUNET_PSYC_MessageHeader *msg,
                                     const struct GNUNET_PSYC_MessageMethod *meth,
                                     uint64_t message_id,
                                     const char *method_name)
{
  struct GNUNET_SOCIAL_Host *hst = cls;

  if (0 == memcmp (&(struct GNUNET_CRYPTO_EcdsaPublicKey) {},
                   &msg->slave_pub_key, sizeof (msg->slave_pub_key)))
    return;

  struct GNUNET_SOCIAL_Nym *nym = nym_get_or_create (&msg->slave_pub_key);

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Host received method for message ID %" PRIu64 " from nym %s: %s\n",
              message_id, GNUNET_h2s (&nym->pub_key_hash), method_name);

  hst->notice_place_leave_nym = (struct GNUNET_SOCIAL_Nym *) nym;
  hst->notice_place_leave_env = GNUNET_PSYC_env_create ();

  char *str = GNUNET_CRYPTO_ecdsa_public_key_to_string (&hst->notice_place_leave_nym->pub_key);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "_notice_place_leave: got method from nym %s (%s).\n",
              GNUNET_h2s (&hst->notice_place_leave_nym->pub_key_hash), str);
}


static void
host_recv_notice_place_leave_modifier (void *cls,
                                       const struct GNUNET_PSYC_MessageHeader *msg,
                                       const struct GNUNET_MessageHeader *pmsg,
                                       uint64_t message_id,
                                       enum GNUNET_PSYC_Operator oper,
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

  GNUNET_PSYC_env_add (hst->notice_place_leave_env,
                       GNUNET_PSYC_OP_SET, name, value, value_size);
}


static void
host_recv_notice_place_leave_eom (void *cls,
                                  const struct GNUNET_PSYC_MessageHeader *msg,
                                  const struct GNUNET_MessageHeader *pmsg,
                                  uint64_t message_id,
                                  uint8_t is_cancelled)
{
  struct GNUNET_SOCIAL_Host *hst = cls;
  if (NULL == hst->notice_place_leave_env)
    return;

  char *str = GNUNET_CRYPTO_ecdsa_public_key_to_string (&hst->notice_place_leave_nym->pub_key);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "_notice_place_leave: got EOM from nym %s (%s).\n",
              GNUNET_h2s (&hst->notice_place_leave_nym->pub_key_hash), str);

  if (GNUNET_YES != is_cancelled)
  {
    if (NULL != hst->farewell_cb)
      hst->farewell_cb (hst->cb_cls, hst->notice_place_leave_nym,
                        hst->notice_place_leave_env);
    /* announce leaving guest to place */
    GNUNET_PSYC_env_add (hst->notice_place_leave_env, GNUNET_PSYC_OP_SET,
                         "_nym", hst->notice_place_leave_nym,
                         sizeof (*hst->notice_place_leave_nym));
    GNUNET_SOCIAL_host_announce (hst, "_notice_place_leave",
                                 hst->notice_place_leave_env,
                                 NULL, NULL, GNUNET_SOCIAL_ANNOUNCE_NONE);
    nym_destroy (hst->notice_place_leave_nym);
  }
  GNUNET_PSYC_env_destroy (hst->notice_place_leave_env);
  hst->notice_place_leave_env = NULL;
}


/*** CLIENT ***/


static void
app_send_connect_msg (struct GNUNET_SOCIAL_App *app)
{
  uint16_t cmsg_size = ntohs (app->connect_msg->size);
  struct GNUNET_MessageHeader * cmsg = GNUNET_malloc (cmsg_size);
  memcpy (cmsg, app->connect_msg, cmsg_size);
  GNUNET_CLIENT_MANAGER_transmit_now (app->client, cmsg);
  GNUNET_free (cmsg);
}


static void
app_recv_disconnect (void *cls,
                     struct GNUNET_CLIENT_MANAGER_Connection *client,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_App *
    app = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*app));

  GNUNET_CLIENT_MANAGER_reconnect (client);
  app_send_connect_msg (app);
}


/*** PLACE ***/


static void
place_send_connect_msg (struct GNUNET_SOCIAL_Place *plc)
{
  uint16_t cmsg_size = ntohs (plc->connect_msg->size);
  struct GNUNET_MessageHeader * cmsg = GNUNET_malloc (cmsg_size);
  memcpy (cmsg, plc->connect_msg, cmsg_size);
  GNUNET_CLIENT_MANAGER_transmit_now (plc->client, cmsg);
  GNUNET_free (cmsg);
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
app_recv_result (void *cls,
                 struct GNUNET_CLIENT_MANAGER_Connection *client,
                 const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_App *
    app = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*app));

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
  GNUNET_CLIENT_MANAGER_op_result (app->client, GNUNET_ntohll (res->op_id),
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

  GNUNET_PSYC_slicer_message (hist->slicer,
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
  GNUNET_PSYC_slicer_message (plc->slicer,
                               (const struct GNUNET_PSYC_MessageHeader *) msg);
}


static void
host_recv_message (void *cls,
                   struct GNUNET_CLIENT_MANAGER_Connection *client,
                   const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_Host *
    hst = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (hst->plc));
  GNUNET_PSYC_slicer_message (hst->slicer,
                              (const struct GNUNET_PSYC_MessageHeader *) msg);
  GNUNET_PSYC_slicer_message (hst->plc.slicer,
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

  struct HostEnterAck *hack = (struct HostEnterAck *) msg;
  hst->plc.pub_key = hack->place_pub_key;

  int32_t result = ntohl (hack->result_code);
  if (NULL != hst->enter_cb)
    hst->enter_cb (hst->cb_cls, result, &hack->place_pub_key,
                   GNUNET_ntohll (hack->max_message_id));
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
  struct GNUNET_PSYC_Environment *env = NULL;
  struct GNUNET_PSYC_MessageHeader *entry_pmsg = NULL;
  const void *data = NULL;
  uint16_t data_size = 0;
  char *str;
  const struct GNUNET_PSYC_JoinRequestMessage *
    req = (const struct GNUNET_PSYC_JoinRequestMessage *) msg;
  const struct GNUNET_PSYC_Message *join_msg = NULL;

  do
  {
    if (sizeof (*req) + sizeof (*join_msg) <= ntohs (req->header.size))
    {
      join_msg = (struct GNUNET_PSYC_Message *) &req[1];
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Received join_msg of type %u and size %u.\n",
           ntohs (join_msg->header.type), ntohs (join_msg->header.size));

      env = GNUNET_PSYC_env_create ();
      entry_pmsg = GNUNET_PSYC_message_header_create_from_psyc (join_msg);
      if (GNUNET_OK != GNUNET_PSYC_message_parse (entry_pmsg, &method_name, env,
                                                  &data, &data_size))
      {
        GNUNET_break_op (0);
        str = GNUNET_CRYPTO_ecdsa_public_key_to_string (&req->slave_pub_key);
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Ignoring invalid entry request from nym %s.\n",
             str);
        GNUNET_free (str);
        break;
      }
    }

    struct GNUNET_SOCIAL_Nym *nym = nym_get_or_create (&req->slave_pub_key);
    hst->answer_door_cb (hst->cb_cls, nym, method_name, env,
                         data, data_size);
  } while (0);

  if (NULL != env)
    GNUNET_PSYC_env_destroy (env);
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
    gst->enter_cb (gst->cb_cls, result, &gst->plc.pub_key,
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


static void
app_recv_ego (void *cls,
              struct GNUNET_CLIENT_MANAGER_Connection *client,
              const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_App *
    app = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*app));

  struct AppEgoMessage *
    emsg = (struct AppEgoMessage *) msg;

  uint16_t name_size = ntohs (emsg->header.size) - sizeof (*emsg);

  struct GNUNET_HashCode ego_pub_hash;
  GNUNET_CRYPTO_hash (&emsg->ego_pub_key, sizeof (emsg->ego_pub_key),
                      &ego_pub_hash);

  struct GNUNET_SOCIAL_Ego *
    ego = GNUNET_CONTAINER_multihashmap_get (app->egos, &ego_pub_hash);
  if (NULL == ego)
  {
    ego = GNUNET_malloc (sizeof (*ego));
    ego->pub_key = emsg->ego_pub_key;
    ego->name = GNUNET_malloc (name_size);
    memcpy (ego->name, &emsg[1], name_size);
  }
  else
  {
    ego->name = GNUNET_realloc (ego->name, name_size);
    memcpy (ego->name, &emsg[1], name_size);
  }

  GNUNET_CONTAINER_multihashmap_put (app->egos, &ego_pub_hash, ego,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);

  if (NULL != app->ego_cb)
    app->ego_cb (app->cb_cls, ego, &ego->pub_key, ego->name);
}


static void
app_recv_place (void *cls,
                struct GNUNET_CLIENT_MANAGER_Connection *client,
                const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SOCIAL_App *
    app = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*app));

  struct AppPlaceMessage *
    pmsg = (struct AppPlaceMessage *) msg;

  if ((GNUNET_YES == pmsg->is_host && NULL == app->host_cb)
      || (GNUNET_NO == pmsg->is_host && NULL == app->guest_cb))
    return;

  struct GNUNET_HashCode ego_pub_hash;
  GNUNET_CRYPTO_hash (&pmsg->ego_pub_key, sizeof (pmsg->ego_pub_key),
                      &ego_pub_hash);
  struct GNUNET_SOCIAL_Ego *
    ego = GNUNET_CONTAINER_multihashmap_get (app->egos, &ego_pub_hash);
  if (NULL == ego)
  {
    GNUNET_break (0);
    return;
  }

  if (GNUNET_YES == pmsg->is_host)
  {
    struct GNUNET_SOCIAL_HostConnection *hconn = GNUNET_malloc (sizeof (*hconn));
    hconn->app = app;
    hconn->plc_msg = *pmsg;
    app->host_cb (app->cb_cls, hconn, ego, &pmsg->place_pub_key, pmsg->place_state);
  }
  else
  {
    struct GNUNET_SOCIAL_GuestConnection *gconn = GNUNET_malloc (sizeof (*gconn));
    gconn->app = app;
    gconn->plc_msg = *pmsg;
    app->guest_cb (app->cb_cls, gconn, ego, &pmsg->place_pub_key, pmsg->place_state);
  }
}


static struct GNUNET_CLIENT_MANAGER_MessageHandler host_handlers[] =
{
  { host_recv_enter_ack, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER_ACK,
    sizeof (struct HostEnterAck), GNUNET_NO },

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


static struct GNUNET_CLIENT_MANAGER_MessageHandler app_handlers[] =
{
  { app_recv_ego, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_APP_EGO,
    sizeof (struct AppEgoMessage), GNUNET_YES },

  { app_recv_place, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_APP_PLACE,
    sizeof (struct AppPlaceMessage), GNUNET_NO },

  { app_recv_result, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_RESULT_CODE,
    sizeof (struct GNUNET_OperationResultMessage), GNUNET_YES },

  { app_recv_disconnect, NULL, 0, 0, GNUNET_NO },

  { NULL, NULL, 0, 0, GNUNET_NO }
};


static void
place_cleanup (struct GNUNET_SOCIAL_Place *plc)
{
  struct GNUNET_HashCode place_pub_hash;
  GNUNET_CRYPTO_hash (&plc->pub_key, sizeof (plc->pub_key), &place_pub_hash);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s place cleanup: %s\n",
              GNUNET_YES == plc->is_host ? "host" : "guest",
              GNUNET_h2s (&place_pub_hash));

  if (NULL != plc->tmit)
    GNUNET_PSYC_transmit_destroy (plc->tmit);
  if (NULL != plc->connect_msg)
    GNUNET_free (plc->connect_msg);
  if (NULL != plc->disconnect_cb)
    plc->disconnect_cb (plc->disconnect_cls);
}


static void
host_cleanup (void *cls)
{
  struct GNUNET_SOCIAL_Host *hst = cls;
  place_cleanup (&hst->plc);
  if (NULL != hst->slicer)
  {
    GNUNET_PSYC_slicer_destroy (hst->slicer);
    hst->slicer = NULL;
  }
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
 * @param app
 *        Application handle.
 * @param ego
 *        Identity of the host.
 * @param place_key
 *        Private-public key pair of the place.
 *        NULL to generate a key.
 * @param policy
 *        Policy specifying entry and history restrictions for the place.
 * @param slicer
 *        Slicer to handle incoming messages.
 * @param enter_cb
 *        Function called when the place is entered and ready to use.
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
GNUNET_SOCIAL_host_enter (const struct GNUNET_SOCIAL_App *app,
                          const struct GNUNET_SOCIAL_Ego *ego,
                          enum GNUNET_PSYC_Policy policy,
                          struct GNUNET_PSYC_Slicer *slicer,
                          GNUNET_SOCIAL_HostEnterCallback enter_cb,
                          GNUNET_SOCIAL_AnswerDoorCallback answer_door_cb,
                          GNUNET_SOCIAL_FarewellCallback farewell_cb,
                          void *cls)
{
  struct GNUNET_SOCIAL_Host *hst = GNUNET_malloc (sizeof (*hst));
  struct GNUNET_SOCIAL_Place *plc = &hst->plc;

  plc->cfg = app->cfg;
  plc->is_host = GNUNET_YES;
  plc->slicer = slicer;

  hst->enter_cb = enter_cb;
  hst->answer_door_cb = answer_door_cb;
  hst->farewell_cb = farewell_cb;
  hst->cb_cls = cls;

  plc->client = GNUNET_CLIENT_MANAGER_connect (plc->cfg, "social", host_handlers);
  GNUNET_CLIENT_MANAGER_set_user_context_ (plc->client, hst, sizeof (*plc));

  plc->tmit = GNUNET_PSYC_transmit_create (plc->client);

  hst->slicer = GNUNET_PSYC_slicer_create ();
  GNUNET_PSYC_slicer_method_add (hst->slicer, "_notice_place_leave", NULL,
                                 host_recv_notice_place_leave_method,
                                 host_recv_notice_place_leave_modifier,
                                 NULL, host_recv_notice_place_leave_eom, hst);

  uint16_t app_id_size = strlen (app->id) + 1;
  struct HostEnterRequest *hreq = GNUNET_malloc (sizeof (*hreq) + app_id_size);
  hreq->header.size = htons (sizeof (*hreq) + app_id_size);
  hreq->header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER);
  hreq->policy = policy;
  hreq->ego_pub_key = ego->pub_key;
  memcpy (&hreq[1], app->id, app_id_size);

  plc->connect_msg = &hreq->header;
  place_send_connect_msg (plc);

  return hst;
}


/**
 * Reconnect to an already entered place as host.
 *
 * @param hconn
 *        Host connection handle.
 *        @see GNUNET_SOCIAL_app_connect() & GNUNET_SOCIAL_AppHostPlaceCallback()
 * @param slicer
 *        Slicer to handle incoming messages.
 * @param enter_cb
 *        Function called when the place is entered and ready to use.
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
GNUNET_SOCIAL_host_enter_reconnect (struct GNUNET_SOCIAL_HostConnection *hconn,
                                    struct GNUNET_PSYC_Slicer *slicer,
                                    GNUNET_SOCIAL_HostEnterCallback enter_cb,
                                    GNUNET_SOCIAL_AnswerDoorCallback answer_door_cb,
                                    GNUNET_SOCIAL_FarewellCallback farewell_cb,
                                    void *cls)
{
  struct GNUNET_SOCIAL_Host *hst = GNUNET_malloc (sizeof (*hst));
  struct GNUNET_SOCIAL_Place *plc = &hst->plc;

  size_t app_id_size = strlen (hconn->app->id) + 1;
  struct HostEnterRequest *hreq = GNUNET_malloc (sizeof (*hreq) + app_id_size);

  hst->enter_cb = enter_cb;
  hst->answer_door_cb = answer_door_cb;
  hst->farewell_cb = farewell_cb;
  hst->cb_cls = cls;

  plc->cfg = hconn->app->cfg;
  plc->is_host = GNUNET_YES;
  plc->slicer = slicer;
  plc->pub_key = hconn->plc_msg.place_pub_key;
  plc->ego_pub_key = hconn->plc_msg.ego_pub_key;

  plc->client = GNUNET_CLIENT_MANAGER_connect (plc->cfg, "social", host_handlers);
  GNUNET_CLIENT_MANAGER_set_user_context_ (plc->client, hst, sizeof (*plc));

  plc->tmit = GNUNET_PSYC_transmit_create (plc->client);

  hst->slicer = GNUNET_PSYC_slicer_create ();
  GNUNET_PSYC_slicer_method_add (hst->slicer, "_notice_place_leave", NULL,
                                 host_recv_notice_place_leave_method,
                                 host_recv_notice_place_leave_modifier,
                                 NULL, host_recv_notice_place_leave_eom, hst);

  hreq->header.size = htons (sizeof (*hreq) + app_id_size);
  hreq->header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER);
  hreq->place_pub_key = hconn->plc_msg.place_pub_key;
  hreq->ego_pub_key = hconn->plc_msg.ego_pub_key;
  memcpy (&hreq[1], hconn->app->id, app_id_size);

  plc->connect_msg = &hreq->header;
  place_send_connect_msg (plc);

  GNUNET_free (hconn);
  return hst;
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
  dcsn->slave_pub_key = nym->pub_key;

  if (0 < entry_resp_size)
    memcpy (&dcsn[1], entry_resp, entry_resp_size);

  GNUNET_CLIENT_MANAGER_transmit (hst->plc.client, &dcsn->header);
  GNUNET_free (dcsn);
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
 * @param env
 *        Environment for the message or NULL.
 */
void
GNUNET_SOCIAL_host_eject (struct GNUNET_SOCIAL_Host *hst,
                          const struct GNUNET_SOCIAL_Nym *nym,
                          struct GNUNET_PSYC_Environment *env)
{
  if (NULL == env)
    env = GNUNET_PSYC_env_create ();
  GNUNET_PSYC_env_add (env, GNUNET_PSYC_OP_SET,
                       "_nym", &nym->pub_key, sizeof (nym->pub_key));
  GNUNET_SOCIAL_host_announce (hst, "_notice_place_leave", env, NULL, NULL,
                               GNUNET_SOCIAL_ANNOUNCE_NONE);
}


/**
 * Get the public key of @a ego.
 *
 * @param ego
 *        Ego.
 *
 * @return Public key of ego.
 */
const struct GNUNET_CRYPTO_EcdsaPublicKey *
GNUNET_SOCIAL_ego_get_pub_key (const struct GNUNET_SOCIAL_Ego *ego)
{
  return &ego->pub_key;
}


/**
 * Get the hash of the public key of @a ego.
 *
 * @param ego
 *        Ego.
 *
 * @return Hash of the public key of @a ego.
 */
const struct GNUNET_HashCode *
GNUNET_SOCIAL_ego_get_pub_key_hash (const struct GNUNET_SOCIAL_Ego *ego)
{
  return &ego->pub_key_hash;
}


/**
 * Get the name of @a ego.
 *
 * @param ego
 *        Ego.
 *
 * @return Public key of @a ego.
 */
const char *
GNUNET_SOCIAL_ego_get_name (const struct GNUNET_SOCIAL_Ego *ego)
{
  return ego->name;
}


/**
 * Get the public key of @a nym.
 *
 * Suitable, for example, to be used with GNUNET_SOCIAL_zone_add_nym().
 *
 * @param nym
 *        Pseudonym.
 *
 * @return Public key of @a nym.
 */
const struct GNUNET_CRYPTO_EcdsaPublicKey *
GNUNET_SOCIAL_nym_get_pub_key (const struct GNUNET_SOCIAL_Nym *nym)
{
  return &nym->pub_key;
}


/**
 * Get the hash of the public key of @a nym.
 *
 * @param nym
 *        Pseudonym.
 *
 * @return Hash of the public key of @a nym.
 */
const struct GNUNET_HashCode *
GNUNET_SOCIAL_nym_get_pub_key_hash (const struct GNUNET_SOCIAL_Nym *nym)
{
  return &nym->pub_key_hash;
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
                             const struct GNUNET_PSYC_Environment *env,
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


void
place_leave (struct GNUNET_SOCIAL_Place *plc)
{
  struct GNUNET_MessageHeader msg;
  msg.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_PLACE_LEAVE);
  msg.size = htons (sizeof (msg));
  GNUNET_CLIENT_MANAGER_transmit (plc->client, &msg);
}


void
place_disconnect (struct GNUNET_SOCIAL_Place *plc,
                  GNUNET_ContinuationCallback disconnect_cb,
                  void *disconnect_cls)
{
  plc->is_disconnecting = GNUNET_YES;
  plc->disconnect_cb = disconnect_cb;
  plc->disconnect_cls = disconnect_cls;

  GNUNET_CLIENT_MANAGER_disconnect (plc->client, GNUNET_YES,
                                    GNUNET_YES == plc->is_host
                                    ? host_cleanup : guest_cleanup,
                                    plc);
}


/**
 * Disconnect from a home.
 *
 * Invalidates host handle.
 *
 * @param hst
 *        The host to disconnect.
 */
void
GNUNET_SOCIAL_host_disconnect (struct GNUNET_SOCIAL_Host *hst,
                               GNUNET_ContinuationCallback disconnect_cb,
                               void *cls)
{
  place_disconnect (&hst->plc, disconnect_cb, cls);
}


/**
 * Stop hosting the home.
 *
 * Sends a _notice_place_closing announcement to the home.
 * Invalidates host handle.
 *
 * @param hst
 *        The host leaving.
 * @param env
 *        Environment for the message or NULL.
 *        _nym is set to @e nym regardless whether an @e env is provided.
 * @param disconnect_cb
 *        Function called after the host left the place
 *        and disconnected from the social service.
 * @param cls
 *        Closure for @a disconnect_cb.
 */
void
GNUNET_SOCIAL_host_leave (struct GNUNET_SOCIAL_Host *hst,
                          const struct GNUNET_PSYC_Environment *env,
                          GNUNET_ContinuationCallback disconnect_cb,
                          void *cls)
{
  GNUNET_SOCIAL_host_announce (hst, "_notice_place_closing", env, NULL, NULL,
                               GNUNET_SOCIAL_ANNOUNCE_NONE);
  place_leave (&hst->plc);
  GNUNET_SOCIAL_host_disconnect (hst, disconnect_cb, cls);
}


/*** GUEST ***/

static struct GuestEnterRequest *
guest_enter_request_create (const char *app_id,
                            const struct GNUNET_CRYPTO_EcdsaPublicKey *ego_pub_key,
                            const struct GNUNET_CRYPTO_EddsaPublicKey *place_pub_key,
                            const struct GNUNET_PeerIdentity *origin,
                            size_t relay_count,
                            const struct GNUNET_PeerIdentity *relays,
                            const struct GNUNET_PSYC_Message *join_msg)
{
  uint16_t app_id_size = strlen (app_id) + 1;
  uint16_t join_msg_size = ntohs (join_msg->header.size);
  uint16_t relay_size = relay_count * sizeof (*relays);

  struct GuestEnterRequest *
    greq = GNUNET_malloc (sizeof (*greq) + app_id_size + relay_size + join_msg_size);

  greq->header.size = htons (sizeof (*greq) + app_id_size + relay_size + join_msg_size);
  greq->header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER);
  greq->place_pub_key = *place_pub_key;
  greq->ego_pub_key = *ego_pub_key;
  greq->origin = *origin;
  greq->relay_count = htonl (relay_count);

  char *p = (char *) &greq[1];
  memcpy (p, app_id, app_id_size);
  p += app_id_size;

  if (0 < relay_size)
  {
    memcpy (p, relays, relay_size);
    p += relay_size;
  }

  memcpy (p, join_msg, join_msg_size);
  return greq;
}


/**
 * Request entry to a place as a guest.
 *
 * @param app
 *        Application handle.
 * @param ego
 *        Identity of the guest.
 * @param place_pub_key
 *        Public key of the place to enter.
 * @param flags
 *        Flags for the entry.
 * @param origin
 *        Peer identity of the origin of the underlying multicast group.
 * @param relay_count
 *        Number of elements in the @a relays array.
 * @param relays
 *        Relays for the underlying multicast group.
 * @param method_name
 *        Method name for the message.
 * @param env
 *        Environment containing variables for the message, or NULL.
 * @param data
 *        Payload for the message to give to the enter callback.
 * @param data_size
 *        Number of bytes in @a data.
 * @param slicer
 *        Slicer to use for processing incoming requests from guests.
 *
 * @return NULL on errors, otherwise handle for the guest.
 */
struct GNUNET_SOCIAL_Guest *
GNUNET_SOCIAL_guest_enter (const struct GNUNET_SOCIAL_App *app,
                           const struct GNUNET_SOCIAL_Ego *ego,
                           const struct GNUNET_CRYPTO_EddsaPublicKey *place_pub_key,
                           enum GNUNET_PSYC_SlaveJoinFlags flags,
                           const struct GNUNET_PeerIdentity *origin,
                           uint32_t relay_count,
                           const struct GNUNET_PeerIdentity *relays,
                           const struct GNUNET_PSYC_Message *entry_msg,
                           struct GNUNET_PSYC_Slicer *slicer,
                           GNUNET_SOCIAL_GuestEnterCallback local_enter_cb,
                           GNUNET_SOCIAL_EntryDecisionCallback entry_dcsn_cb,
                           void *cls)
{
  struct GNUNET_SOCIAL_Guest *gst = GNUNET_malloc (sizeof (*gst));
  struct GNUNET_SOCIAL_Place *plc = &gst->plc;

  plc->ego_pub_key = ego->pub_key;
  plc->pub_key = *place_pub_key;
  plc->cfg = app->cfg;
  plc->is_host = GNUNET_NO;
  plc->slicer = slicer;

  gst->enter_cb = local_enter_cb;
  gst->entry_dcsn_cb = entry_dcsn_cb;
  gst->cb_cls = cls;

  plc->client = GNUNET_CLIENT_MANAGER_connect (plc->cfg, "social", guest_handlers);
  GNUNET_CLIENT_MANAGER_set_user_context_ (plc->client, gst, sizeof (*plc));

  plc->tmit = GNUNET_PSYC_transmit_create (plc->client);

  struct GuestEnterRequest *
    greq = guest_enter_request_create (app->id, &ego->pub_key, &plc->pub_key,
                                       origin, relay_count, relays, entry_msg);
  plc->connect_msg = &greq->header;
  place_send_connect_msg (plc);
  return gst;
}


/**
 * Request entry to a place by name as a guest.
 *
 * @param app
 *        Application handle.
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
 *        Entry request message or NULL.
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
GNUNET_SOCIAL_guest_enter_by_name (const struct GNUNET_SOCIAL_App *app,
                                   const struct GNUNET_SOCIAL_Ego *ego,
                                   const char *gns_name,
                                   const char *password,
                                   const struct GNUNET_PSYC_Message *join_msg,
                                   struct GNUNET_PSYC_Slicer *slicer,
                                   GNUNET_SOCIAL_GuestEnterCallback local_enter_cb,
                                   GNUNET_SOCIAL_EntryDecisionCallback entry_decision_cb,
                                   void *cls)
{
  struct GNUNET_SOCIAL_Guest *gst = GNUNET_malloc (sizeof (*gst));
  struct GNUNET_SOCIAL_Place *plc = &gst->plc;

  if (NULL == password)
    password = "";

  uint16_t app_id_size = strlen (app->id) + 1;
  uint16_t gns_name_size = strlen (gns_name) + 1;
  uint16_t password_size = strlen (password) + 1;

  uint16_t join_msg_size = 0;
  if (NULL != join_msg);
    join_msg_size = ntohs (join_msg->header.size);

  uint16_t greq_size = sizeof (struct GuestEnterByNameRequest)
    + app_id_size + gns_name_size + password_size + join_msg_size;
  struct GuestEnterByNameRequest *greq = GNUNET_malloc (greq_size);
  greq->header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER_BY_NAME);
  greq->header.size = htons (greq_size);
  greq->ego_pub_key = ego->pub_key;

  char *p = (char *) &greq[1];
  memcpy (p, app->id, app_id_size);
  p += app_id_size;
  memcpy (p, gns_name, gns_name_size);
  p += gns_name_size;
  memcpy (p, password, password_size);
  p += password_size;
  if (NULL != join_msg)
    memcpy (p, join_msg, join_msg_size);

  gst->enter_cb = local_enter_cb;
  gst->entry_dcsn_cb = entry_decision_cb;
  gst->cb_cls = cls;

  plc->ego_pub_key = ego->pub_key;
  plc->cfg = app->cfg;
  plc->is_host = GNUNET_NO;
  plc->slicer = slicer;

  plc->client = GNUNET_CLIENT_MANAGER_connect (app->cfg, "social", guest_handlers);
  GNUNET_CLIENT_MANAGER_set_user_context_ (plc->client, gst, sizeof (*plc));

  plc->tmit = GNUNET_PSYC_transmit_create (plc->client);

  plc->connect_msg = &greq->header;
  place_send_connect_msg (plc);

  return gst;
}


/**
 * Reconnect to an already entered place as guest.
 *
 * @param gconn
 *        Guest connection handle.
 *        @see GNUNET_SOCIAL_app_connect() & GNUNET_SOCIAL_AppGuestPlaceCallback()
 * @param flags
 *        Flags for the entry.
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
GNUNET_SOCIAL_guest_enter_reconnect (struct GNUNET_SOCIAL_GuestConnection *gconn,
                                     enum GNUNET_PSYC_SlaveJoinFlags flags,
                                     struct GNUNET_PSYC_Slicer *slicer,
                                     GNUNET_SOCIAL_GuestEnterCallback local_enter_cb,
                                     void *cls)
{
  struct GNUNET_SOCIAL_Guest *gst = GNUNET_malloc (sizeof (*gst));
  struct GNUNET_SOCIAL_Place *plc = &gst->plc;

  uint16_t app_id_size = strlen (gconn->app->id) + 1;
  uint16_t greq_size = sizeof (struct GuestEnterRequest) + app_id_size;
  struct GuestEnterRequest *greq = GNUNET_malloc (greq_size);
  greq->header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER);
  greq->header.size = htons (greq_size);
  greq->ego_pub_key = gconn->plc_msg.ego_pub_key;
  greq->place_pub_key = gconn->plc_msg.place_pub_key;
  greq->flags = htonl (flags);

  memcpy (&greq[1], gconn->app->id, app_id_size);

  gst->enter_cb = local_enter_cb;
  gst->cb_cls = cls;

  plc->cfg = gconn->app->cfg;
  plc->is_host = GNUNET_NO;
  plc->slicer = slicer;
  plc->pub_key = gconn->plc_msg.place_pub_key;
  plc->ego_pub_key = gconn->plc_msg.ego_pub_key;

  plc->client = GNUNET_CLIENT_MANAGER_connect (plc->cfg, "social", guest_handlers);
  GNUNET_CLIENT_MANAGER_set_user_context_ (plc->client, gst, sizeof (*plc));

  plc->tmit = GNUNET_PSYC_transmit_create (plc->client);

  plc->connect_msg = &greq->header;
  place_send_connect_msg (plc);

  GNUNET_free (gconn);
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
                          const struct GNUNET_PSYC_Environment *env,
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
  GNUNET_PSYC_transmit_cancel ( (struct GNUNET_PSYC_TransmitHandle *) tr);
}


/**
 * Disconnect from a place.
 *
 * Invalidates guest handle.
 *
 * @param gst
 *        The guest to disconnect.
 */
void
GNUNET_SOCIAL_guest_disconnect (struct GNUNET_SOCIAL_Guest *gst,
                                GNUNET_ContinuationCallback disconnect_cb,
                                void *cls)
{
  place_disconnect (&gst->plc, disconnect_cb, cls);
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
                           struct GNUNET_PSYC_Environment *env,
                           GNUNET_ContinuationCallback disconnect_cb,
                           void *cls)
{
  GNUNET_SOCIAL_guest_talk (gst, "_notice_place_leave", env, NULL, NULL,
                            GNUNET_SOCIAL_TALK_NONE);
  place_leave (&gst->plc);
  GNUNET_SOCIAL_guest_disconnect (gst, disconnect_cb, cls);
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
 * Obtain the public key of a place.
 *
 * @param plc
 *        Place.
 *
 * @return Public key of the place.
 */
const struct GNUNET_CRYPTO_EddsaPublicKey *
GNUNET_SOCIAL_place_get_pub_key (const struct GNUNET_SOCIAL_Place *plc)
{
  return &plc->pub_key;
}


/**
 * Set message processing @a flags for a @a method_prefix.
 *
 * @param plc
 *        Place.
 * @param method_prefix
 *        Method prefix @a flags apply to.
 * @param flags
 *        The flags that apply to a matching @a method_prefix.
 */
void
GNUNET_SOCIAL_place_msg_proc_set (struct GNUNET_SOCIAL_Place *plc,
                                  const char *method_prefix,
                                  enum GNUNET_SOCIAL_MsgProcFlags flags)
{
  GNUNET_assert (NULL != method_prefix);
  struct MsgProcRequest *mpreq;
  uint16_t method_size = strnlen (method_prefix,
                                  GNUNET_SERVER_MAX_MESSAGE_SIZE
                                  - sizeof (*mpreq)) + 1;
  GNUNET_assert ('\0' == method_prefix[method_size - 1]);
  mpreq = GNUNET_malloc (sizeof (*mpreq) + method_size);

  mpreq->header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_MSG_PROC_SET);
  mpreq->header.size = htons (sizeof (*mpreq) + method_size);
  mpreq->flags = htonl (flags);
  memcpy (&mpreq[1], method_prefix, method_size);

  GNUNET_CLIENT_MANAGER_transmit (plc->client, &mpreq->header);
  GNUNET_free (mpreq);
}


/**
 * Clear all message processing flags previously set for this place.
 */
void
GNUNET_SOCIAL_place_msg_proc_clear (struct GNUNET_SOCIAL_Place *plc)
{
  struct GNUNET_MessageHeader req;
  req.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_MSG_PROC_CLEAR);
  req.size = htons (sizeof (req));
  GNUNET_CLIENT_MANAGER_transmit (plc->client, &req);
}


static struct GNUNET_SOCIAL_HistoryRequest *
place_history_replay (struct GNUNET_SOCIAL_Place *plc,
                      uint64_t start_message_id,
                      uint64_t end_message_id,
                      uint64_t message_limit,
                      const char *method_prefix,
                      uint32_t flags,
                      struct GNUNET_PSYC_Slicer *slicer,
                      GNUNET_ResultCallback result_cb,
                      void *cls)
{
  struct GNUNET_PSYC_HistoryRequestMessage *req;
  struct GNUNET_SOCIAL_HistoryRequest *hist = GNUNET_malloc (sizeof (*hist));
  hist->plc = plc;
  hist->slicer = slicer;
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
  GNUNET_free (req);
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
                                    struct GNUNET_PSYC_Slicer *slicer,
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
                                           struct GNUNET_PSYC_Slicer *slicer,
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
  GNUNET_free (req);
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


static void
op_recv_zone_add_place_result (void *cls, int64_t result,
                               const void *err_msg, uint16_t err_msg_size)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received zone add place result: %" PRId64 ".\n", result);

  struct ZoneAddPlaceHandle *add_plc = cls;
  if (NULL != add_plc->result_cb)
    add_plc->result_cb (add_plc->result_cls, result, err_msg, err_msg_size);

  GNUNET_free (add_plc->req);
  GNUNET_free (add_plc);
}


/**
 * Advertise @e place in the GNS zone of @e ego.
 *
 * @param app
 *        Application handle.
 * @param ego
 *        Ego.
 * @param place_pub_key
 *        Public key of place to add.
 * @param name
 *        The name for the PLACE record to put in the zone.
 * @param password
 *        Password used to encrypt the record or NULL to keep it cleartext.
 * @param relay_count
 *        Number of elements in the @a relays array.
 * @param relays
 *        List of relays to put in the PLACE record to advertise
 *        as entry points to the place in addition to the origin.
 * @param expiration_time
 *        Expiration time of the record, use 0 to remove the record.
 * @param result_cb
 *        Function called with the result of the operation.
 * @param result_cls
 *        Closure for @a result_cb
 *
 * @return #GNUNET_OK if the request was sent,
 *         #GNUNET_SYSERR on error, e.g. the name/password is too long.
 */
int
GNUNET_SOCIAL_zone_add_place (const struct GNUNET_SOCIAL_App *app,
                              const struct GNUNET_SOCIAL_Ego *ego,
                              const char *name,
                              const char *password,
                              const struct GNUNET_CRYPTO_EddsaPublicKey *place_pub_key,
                              const struct GNUNET_PeerIdentity *origin,
                              uint32_t relay_count,
                              const struct GNUNET_PeerIdentity *relays,
                              struct GNUNET_TIME_Absolute expiration_time,
                              GNUNET_ResultCallback result_cb,
                              void *result_cls)
{
  struct ZoneAddPlaceRequest *preq;
  size_t name_size = strlen (name) + 1;
  size_t password_size = strlen (password) + 1;
  size_t relay_size = relay_count * sizeof (*relays);
  size_t preq_size = sizeof (*preq) + name_size + password_size + relay_size;

  if (GNUNET_SERVER_MAX_MESSAGE_SIZE < preq_size)
    return GNUNET_SYSERR;

  preq = GNUNET_malloc (preq_size);
  preq->header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_ZONE_ADD_PLACE);
  preq->header.size = htons (preq_size);
  preq->expiration_time = GNUNET_htonll (expiration_time.abs_value_us);
  preq->ego_pub_key = ego->pub_key;
  preq->place_pub_key = *place_pub_key;
  preq->origin = *origin;
  preq->relay_count = htonl (relay_count);

  char *p = (char *) &preq[1];
  memcpy (p, name, name_size);
  p += name_size;
  memcpy (p, password, password_size);
  p += password_size;
  memcpy (p, relays, relay_size);

  struct ZoneAddPlaceHandle * add_plc = GNUNET_malloc (sizeof (*add_plc));
  add_plc->req = preq;
  add_plc->result_cb = result_cb;
  add_plc->result_cls = result_cls;

  preq->op_id = GNUNET_htonll (GNUNET_CLIENT_MANAGER_op_add (app->client,
                                                             op_recv_zone_add_place_result,
                                                             add_plc));
  GNUNET_CLIENT_MANAGER_transmit_now (app->client, &preq->header);
  return GNUNET_OK;
}


static void
op_recv_zone_add_nym_result (void *cls, int64_t result,
                             const void *err_msg, uint16_t err_msg_size)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received zone add nym result: %" PRId64 ".\n", result);

  struct ZoneAddNymHandle *add_nym = cls;
  if (NULL != add_nym->result_cb)
    add_nym->result_cb (add_nym->result_cls, result, err_msg, err_msg_size);

  GNUNET_free (add_nym->req);
  GNUNET_free (add_nym);
}


/**
 * Add nym to the GNS zone of @e ego.
 *
 * @param cfg
 *        Configuration.
 * @param ego
 *        Ego.
 * @param name
 *        The name for the PKEY record to put in the zone.
 * @param nym_pub_key
 *        Public key of nym to add.
 * @param expiration_time
 *        Expiration time of the record, use 0 to remove the record.
 * @param result_cb
 *        Function called with the result of the operation.
 * @param result_cls
 *        Closure for @a result_cb
 *
 * @return #GNUNET_OK if the request was sent,
 *         #GNUNET_SYSERR on error, e.g. the name is too long.
 */
int
GNUNET_SOCIAL_zone_add_nym (const struct GNUNET_SOCIAL_App *app,
                            const struct GNUNET_SOCIAL_Ego *ego,
                            const char *name,
                            const struct GNUNET_CRYPTO_EcdsaPublicKey *nym_pub_key,
                            struct GNUNET_TIME_Absolute expiration_time,
                            GNUNET_ResultCallback result_cb,
                            void *result_cls)
{
  struct ZoneAddNymRequest *nreq;

  size_t name_size = strlen (name) + 1;
  if (GNUNET_SERVER_MAX_MESSAGE_SIZE < sizeof (*nreq) + name_size)
    return GNUNET_SYSERR;

  nreq = GNUNET_malloc (sizeof (*nreq) + name_size);
  nreq->header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_ZONE_ADD_NYM);
  nreq->header.size = htons (sizeof (*nreq) + name_size);
  nreq->expiration_time = GNUNET_htonll (expiration_time.abs_value_us);
  nreq->ego_pub_key = ego->pub_key;
  nreq->nym_pub_key = *nym_pub_key;
  memcpy (&nreq[1], name, name_size);

  struct ZoneAddNymHandle * add_nym = GNUNET_malloc (sizeof (*add_nym));
  add_nym->req = nreq;
  add_nym->result_cb = result_cb;
  add_nym->result_cls = result_cls;

  nreq->op_id = GNUNET_htonll (GNUNET_CLIENT_MANAGER_op_add (app->client,
                                                             op_recv_zone_add_nym_result,
                                                             add_nym));
  GNUNET_CLIENT_MANAGER_transmit_now (app->client, &nreq->header);
  return GNUNET_OK;
}


/**
 * Connect application to the social service.
 *
 * The @host_place_cb and @guest_place_cb functions are
 * initially called for each entered places,
 * then later each time a new place is entered with the current application ID.
 *
 * @param cfg
 *        Configuration.
 * @param id
 *        Application ID.
 * @param notify_host
 *        Function to notify about a place entered as host.
 * @param notify_guest
 *        Function to notify about a place entered as guest..
 * @param notify_cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to stop listening.
 */
struct GNUNET_SOCIAL_App *
GNUNET_SOCIAL_app_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           const char *id,
                           GNUNET_SOCIAL_AppEgoCallback ego_cb,
                           GNUNET_SOCIAL_AppHostPlaceCallback host_cb,
                           GNUNET_SOCIAL_AppGuestPlaceCallback guest_cb,
                           void *cls)
{
  uint16_t app_id_size = strnlen (id, GNUNET_SOCIAL_APP_MAX_ID_SIZE);
  if (GNUNET_SOCIAL_APP_MAX_ID_SIZE == app_id_size)
    return NULL;
  app_id_size++;

  struct GNUNET_SOCIAL_App *app = GNUNET_malloc (sizeof *app);
  app->cfg = cfg;
  app->ego_cb = ego_cb;
  app->host_cb = host_cb;
  app->guest_cb = guest_cb;
  app->cb_cls = cls;
  app->egos = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  app->client = GNUNET_CLIENT_MANAGER_connect (cfg, "social",
                                               app_handlers);
  GNUNET_CLIENT_MANAGER_set_user_context_ (app->client, app, sizeof (*app));

  app->id = GNUNET_malloc (app_id_size);
  memcpy (app->id, id, app_id_size);

  struct AppConnectRequest *creq = GNUNET_malloc (sizeof (*creq) + app_id_size);
  creq->header.size = htons (sizeof (*creq) + app_id_size);
  creq->header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_APP_CONNECT);
  memcpy (&creq[1], app->id, app_id_size);

  app->connect_msg = &creq->header;
  app_send_connect_msg (app);

  return app;
}


/**
 * Disconnect application.
 *
 * @param app
 *        Application handle.
 */
void
GNUNET_SOCIAL_app_disconnect (struct GNUNET_SOCIAL_App *app)
{
  GNUNET_CLIENT_MANAGER_disconnect (app->client, GNUNET_NO, NULL, NULL);
}


/**
 * Detach application from a place.
 *
 * Removes the place from the entered places list for this application.
 * Note: this does not disconnect from the place.
 *
 * @see GNUNET_SOCIAL_host_disconnect() and GNUNET_SOCIAL_guest_disconnect()
 *
 * @param app
 *        Application.
 * @param plc
 *        Place.
 */
void
GNUNET_SOCIAL_app_detach (struct GNUNET_SOCIAL_App *app,
                          struct GNUNET_SOCIAL_Place *plc)
{
  struct AppDetachRequest dreq;
  dreq.header.size = htons (sizeof (dreq));
  dreq.header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_APP_DETACH);
  dreq.place_pub_key = plc->pub_key;
  GNUNET_CLIENT_MANAGER_transmit_now (plc->client, &dreq.header);
}


/* end of social_api.c */
