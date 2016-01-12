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
 * @file psycstore/gnunet-service-psycstore.c
 * @brief PSYCstore service
 * @author Gabor X Toth
 * @author Christian Grothoff
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_psyc_util_lib.h"
#include "gnunet_psycstore_service.h"
#include "gnunet_psycstore_plugin.h"
#include "psycstore.h"


/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Notification context, simplifies client broadcasts.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Database handle
 */
static struct GNUNET_PSYCSTORE_PluginFunctions *db;

/**
 * Name of the database plugin
 */
static char *db_lib_name;


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
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
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name, db));
  GNUNET_free (db_lib_name);
  db_lib_name = NULL;
}


/**
 * Send a result code back to the client.
 *
 * @param client
 *        Client that should receive the result code.
 * @param result_code
 *        Code to transmit.
 * @param op_id
 *        Operation ID in network byte order.
 * @param err_msg
 *        Error message to include (or NULL for none).
 */
static void
send_result_code (struct GNUNET_SERVER_Client *client, uint64_t op_id,
                  int64_t result_code, const char *err_msg)
{
  struct OperationResult *res;
  size_t err_size = 0;

  if (NULL != err_msg)
    err_size = strnlen (err_msg,
                        GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (*res) - 1) + 1;
  res = GNUNET_malloc (sizeof (struct OperationResult) + err_size);
  res->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_CODE);
  res->header.size = htons (sizeof (struct OperationResult) + err_size);
  res->result_code = GNUNET_htonll (result_code - INT64_MIN);
  res->op_id = op_id;
  if (0 < err_size)
  {
    memcpy (&res[1], err_msg, err_size);
    ((char *) &res[1])[err_size - 1] = '\0';
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending result to client: %" PRId64 " (%s)\n",
	      result_code, err_msg);
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_notification_context_unicast (nc, client, &res->header,
                                              GNUNET_NO);
  GNUNET_free (res);
}


enum
{
  MEMBERSHIP_TEST_NOT_NEEDED = 0,
  MEMBERSHIP_TEST_NEEDED = 1,
  MEMBERSHIP_TEST_DONE = 2,
} MessageMembershipTest;


struct SendClosure
{
  struct GNUNET_SERVER_Client *client;

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey channel_key;

  /**
   * Slave's public key.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey slave_key;

  /**
   * Operation ID.
   */
  uint64_t op_id;

  /**
   * Membership test result.
   */
  int membership_test_result;

  /**
   * Do membership test with @a slave_key before returning fragment?
   * @see enum MessageMembershipTest
   */
  uint8_t membership_test;
};


static int
send_fragment (void *cls, struct GNUNET_MULTICAST_MessageHeader *msg,
               enum GNUNET_PSYCSTORE_MessageFlags flags)
{
  struct SendClosure *sc = cls;
  struct FragmentResult *res;

  if (MEMBERSHIP_TEST_NEEDED == sc->membership_test)
  {
    sc->membership_test = MEMBERSHIP_TEST_DONE;
    sc->membership_test_result
      = db->membership_test (db->cls, &sc->channel_key, &sc->slave_key,
                             GNUNET_ntohll (msg->message_id));
    switch (sc->membership_test_result)
    {
    case GNUNET_YES:
      break;

    case GNUNET_NO:
    case GNUNET_SYSERR:
      return GNUNET_NO;
    }
  }

  size_t msg_size = ntohs (msg->header.size);

  res = GNUNET_malloc (sizeof (struct FragmentResult) + msg_size);
  res->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_FRAGMENT);
  res->header.size = htons (sizeof (struct FragmentResult) + msg_size);
  res->op_id = sc->op_id;
  res->psycstore_flags = htonl (flags);
  memcpy (&res[1], msg, msg_size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending fragment %ld to client\n",
	      GNUNET_ntohll (msg->fragment_id));
  GNUNET_free (msg);
  GNUNET_SERVER_notification_context_add (nc, sc->client);
  GNUNET_SERVER_notification_context_unicast (nc, sc->client, &res->header,
                                              GNUNET_NO);
  GNUNET_free (res);
  return GNUNET_YES;
}


static int
send_state_var (void *cls, const char *name,
                const void *value, uint32_t value_size)
{
  struct SendClosure *sc = cls;
  struct StateResult *res;
  size_t name_size = strlen (name) + 1;

  /** @todo FIXME: split up value into 64k chunks */

  res = GNUNET_malloc (sizeof (struct StateResult) + name_size + value_size);
  res->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_STATE);
  res->header.size = htons (sizeof (struct StateResult) + name_size + value_size);
  res->op_id = sc->op_id;
  res->name_size = htons (name_size);
  memcpy (&res[1], name, name_size);
  memcpy ((char *) &res[1] + name_size, value, value_size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending state variable %s to client\n", name);
  GNUNET_SERVER_notification_context_add (nc, sc->client);
  GNUNET_SERVER_notification_context_unicast (nc, sc->client, &res->header,
                                              GNUNET_NO);
  GNUNET_free (res);
  return GNUNET_OK;
}


static void
handle_membership_store (void *cls,
                         struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *msg)
{
  const struct MembershipStoreRequest *req =
    (const struct MembershipStoreRequest *) msg;

  int ret = db->membership_store (db->cls, &req->channel_key, &req->slave_key,
                                  req->did_join,
                                  GNUNET_ntohll (req->announced_at),
                                  GNUNET_ntohll (req->effective_since),
                                  GNUNET_ntohll (req->group_generation));

  if (ret != GNUNET_OK)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to store membership information!\n"));

  send_result_code (client, req->op_id, ret, NULL);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
handle_membership_test (void *cls,
                        struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *msg)
{
  const struct MembershipTestRequest *req =
    (const struct MembershipTestRequest *) msg;

  int ret = db->membership_test (db->cls, &req->channel_key, &req->slave_key,
                                 GNUNET_ntohll (req->message_id));
  switch (ret)
  {
  case GNUNET_YES:
  case GNUNET_NO:
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to test membership!\n"));
  }

  send_result_code (client, req->op_id, ret, NULL);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
handle_fragment_store (void *cls,
                       struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *msg)
{
  const struct FragmentStoreRequest *req =
    (const struct FragmentStoreRequest *) msg;

  int ret = db->fragment_store (db->cls, &req->channel_key,
                                (const struct GNUNET_MULTICAST_MessageHeader *)
                                &req[1], ntohl (req->psycstore_flags));

  if (ret != GNUNET_OK)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to store fragment!\n"));

  send_result_code (client, req->op_id, ret, NULL);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
handle_fragment_get (void *cls,
                     struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *msg)
{
  const struct FragmentGetRequest *
    req = (const struct FragmentGetRequest *) msg;
  struct SendClosure
    sc = { .op_id = req->op_id,
           .client = client,
           .channel_key = req->channel_key,
           .slave_key = req->slave_key,
           .membership_test = req->do_membership_test };

  int64_t ret;
  uint64_t ret_frags = 0;
  uint64_t first_fragment_id = GNUNET_ntohll (req->first_fragment_id);
  uint64_t last_fragment_id = GNUNET_ntohll (req->last_fragment_id);
  uint64_t limit = GNUNET_ntohll (req->fragment_limit);

  if (0 == limit)
    ret = db->fragment_get (db->cls, &req->channel_key,
                            first_fragment_id, last_fragment_id,
                            &ret_frags, send_fragment, &sc);
  else
    ret = db->fragment_get_latest (db->cls, &req->channel_key, limit,
                                   &ret_frags, send_fragment, &sc);

  switch (ret)
  {
  case GNUNET_YES:
  case GNUNET_NO:
    if (MEMBERSHIP_TEST_DONE == sc.membership_test)
    {
      switch (sc.membership_test_result)
      {
      case GNUNET_YES:
        break;

      case GNUNET_NO:
        ret = GNUNET_PSYCSTORE_MEMBERSHIP_TEST_FAILED;
        break;

      case GNUNET_SYSERR:
        ret = GNUNET_SYSERR;
        break;
      }
    }
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to get fragment!\n"));
  }
  send_result_code (client, req->op_id, (ret < 0) ? ret : ret_frags, NULL);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
handle_message_get (void *cls,
                    struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *msg)
{
  const struct MessageGetRequest *
    req = (const struct MessageGetRequest *) msg;
  uint16_t size = ntohs (msg->size);
  const char *method_prefix = (const char *) &req[1];

  if (size < sizeof (*req) + 1
      || '\0' != method_prefix[size - sizeof (*req) - 1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Message get: invalid method prefix. size: %u < %u?\n",
                size, sizeof (*req) + 1);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  struct SendClosure
    sc = { .op_id = req->op_id,
           .client = client,
           .channel_key = req->channel_key,
           .slave_key = req->slave_key,
           .membership_test = req->do_membership_test };

  int64_t ret;
  uint64_t ret_frags = 0;
  uint64_t first_message_id = GNUNET_ntohll (req->first_message_id);
  uint64_t last_message_id = GNUNET_ntohll (req->last_message_id);
  uint64_t msg_limit = GNUNET_ntohll (req->message_limit);
  uint64_t frag_limit = GNUNET_ntohll (req->fragment_limit);

  /** @todo method_prefix */
  if (0 == msg_limit)
    ret = db->message_get (db->cls, &req->channel_key,
                           first_message_id, last_message_id, frag_limit,
                           &ret_frags, send_fragment, &sc);
  else
    ret = db->message_get_latest (db->cls, &req->channel_key, msg_limit,
                                  &ret_frags, send_fragment, &sc);

  switch (ret)
  {
  case GNUNET_YES:
  case GNUNET_NO:
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to get message!\n"));
  }

  send_result_code (client, req->op_id, (ret < 0) ? ret : ret_frags, NULL);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
handle_message_get_fragment (void *cls,
                             struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *msg)
{
  const struct MessageGetFragmentRequest *
    req = (const struct MessageGetFragmentRequest *) msg;
  struct SendClosure
    sc = { .op_id = req->op_id, .client = client,
           .channel_key = req->channel_key, .slave_key = req->slave_key,
           .membership_test = req->do_membership_test };

  int ret = db->message_get_fragment (db->cls, &req->channel_key,
                                      GNUNET_ntohll (req->message_id),
                                      GNUNET_ntohll (req->fragment_offset),
                                      &send_fragment, &sc);
  switch (ret)
  {
  case GNUNET_YES:
  case GNUNET_NO:
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to get message fragment!\n"));
  }

  send_result_code (client, req->op_id, ret, NULL);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
handle_counters_get (void *cls,
                     struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *msg)
{
  const struct OperationRequest *req = (const struct OperationRequest *) msg;
  struct CountersResult res = { {0} };

  int ret = db->counters_message_get (db->cls, &req->channel_key,
                                      &res.max_fragment_id, &res.max_message_id,
                                      &res.max_group_generation);
  switch (ret)
  {
  case GNUNET_OK:
    ret = db->counters_state_get (db->cls, &req->channel_key,
                                  &res.max_state_message_id);
  case GNUNET_NO:
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to get master counters!\n"));
  }

  res.header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_COUNTERS);
  res.header.size = htons (sizeof (res));
  res.result_code = htonl (ret);
  res.op_id = req->op_id;
  res.max_fragment_id = GNUNET_htonll (res.max_fragment_id);
  res.max_message_id = GNUNET_htonll (res.max_message_id);
  res.max_group_generation = GNUNET_htonll (res.max_group_generation);
  res.max_state_message_id = GNUNET_htonll (res.max_state_message_id);

  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_notification_context_unicast (nc, client, &res.header,
                                              GNUNET_NO);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


struct StateModifyClosure
{
  const struct GNUNET_CRYPTO_EddsaPublicKey channel_key;
  struct GNUNET_PSYC_ReceiveHandle *recv;
  enum GNUNET_PSYC_MessageState msg_state;
  char mod_oper;
  char *mod_name;
  char *mod_value;
  uint32_t mod_value_size;
  uint32_t mod_value_remaining;
};


static void
recv_state_message_part (void *cls,
                         const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                         uint64_t message_id, uint32_t flags, uint64_t data_offset,
                         const struct GNUNET_MessageHeader *msg)
{
  struct StateModifyClosure *scls = cls;
  uint16_t psize;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "recv_state_message_part()  message_id: %" PRIu64
              ", data_offset: %" PRIu64 ", flags: %u\n",
              message_id, data_offset, flags);

  if (NULL == msg)
  {
    scls->msg_state = GNUNET_PSYC_MESSAGE_STATE_ERROR;
    return;
  }

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD:
  {
    scls->msg_state = GNUNET_PSYC_MESSAGE_STATE_METHOD;
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
  {
    struct GNUNET_PSYC_MessageModifier *
      pmod = (struct GNUNET_PSYC_MessageModifier *) msg;
    psize = ntohs (pmod->header.size);
    uint16_t name_size = ntohs (pmod->name_size);
    uint32_t value_size = ntohl (pmod->value_size);

    const char *name = (const char *) &pmod[1];
    const void *value = name + name_size;

    if (GNUNET_PSYC_OP_SET != pmod->oper)
    { // Apply non-transient operation.
      if (psize == sizeof (*pmod) + name_size + value_size)
      {
        db->state_modify_op (db->cls, &scls->channel_key,
                             pmod->oper, name, value, value_size);
      }
      else
      {
        scls->mod_oper = pmod->oper;
        scls->mod_name = GNUNET_malloc (name_size);
        memcpy (scls->mod_name, name, name_size);

        scls->mod_value_size = value_size;
        scls->mod_value = GNUNET_malloc (scls->mod_value_size);
        scls->mod_value_remaining
          = scls->mod_value_size - (psize - sizeof (*pmod) - name_size);
        memcpy (scls->mod_value, value, value_size - scls->mod_value_remaining);
      }
    }
    scls->msg_state = GNUNET_PSYC_MESSAGE_STATE_MODIFIER;
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT:
    if (GNUNET_PSYC_OP_SET != scls->mod_oper)
    {
      if (scls->mod_value_remaining == 0)
      {
        GNUNET_break_op (0);
        scls->msg_state = GNUNET_PSYC_MESSAGE_STATE_ERROR;
      }
      psize = ntohs (msg->size);
      memcpy (scls->mod_value + (scls->mod_value_size - scls->mod_value_remaining),
              &msg[1], psize - sizeof (*msg));
      scls->mod_value_remaining -= psize - sizeof (*msg);
      if (0 == scls->mod_value_remaining)
      {
        db->state_modify_op (db->cls, &scls->channel_key,
                             scls->mod_oper, scls->mod_name,
                             scls->mod_value, scls->mod_value_size);
        GNUNET_free (scls->mod_name);
        GNUNET_free (scls->mod_value);
        scls->mod_oper = 0;
        scls->mod_name = NULL;
        scls->mod_value = NULL;
        scls->mod_value_size = 0;
      }
    }
    scls->msg_state = GNUNET_PSYC_MESSAGE_STATE_MOD_CONT;
    break;

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA:
    scls->msg_state = GNUNET_PSYC_MESSAGE_STATE_DATA;
    break;

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END:
    scls->msg_state = GNUNET_PSYC_MESSAGE_STATE_END;
    break;

  default:
    scls->msg_state = GNUNET_PSYC_MESSAGE_STATE_ERROR;
  }
}


static int
recv_state_fragment (void *cls, struct GNUNET_MULTICAST_MessageHeader *msg,
                     enum GNUNET_PSYCSTORE_MessageFlags flags)
{
  struct StateModifyClosure *scls = cls;

  if (NULL == scls->recv)
  {
    scls->recv = GNUNET_PSYC_receive_create (NULL, recv_state_message_part,
                                             scls);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "recv_state_fragment: %" PRIu64 "\n", GNUNET_ntohll (msg->fragment_id));

  struct GNUNET_PSYC_MessageHeader *
    pmsg = GNUNET_PSYC_message_header_create (msg, flags);
  GNUNET_PSYC_receive_message (scls->recv, pmsg);
  GNUNET_free (pmsg);

  return GNUNET_YES;
}


static void
handle_state_modify (void *cls,
                     struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *msg)
{
  const struct StateModifyRequest *req
    = (const struct StateModifyRequest *) msg;

  uint64_t message_id = GNUNET_ntohll (req->message_id);
  uint64_t state_delta = GNUNET_ntohll (req->state_delta);
  uint64_t ret_frags = 0;
  struct StateModifyClosure
    scls = { .channel_key = req->channel_key };

  int ret = db->state_modify_begin (db->cls, &req->channel_key,
                                    message_id, state_delta);

  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to begin modifying state: %d\n"), ret);
  }
  else
  {
    ret = db->message_get (db->cls, &req->channel_key,
                           message_id, message_id, 0,
                           &ret_frags, recv_state_fragment, &scls);
    if (GNUNET_OK != ret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to modify state: %d\n"), ret);
      GNUNET_break (0);
    }
    else
    {
      if (GNUNET_OK != db->state_modify_end (db->cls, &req->channel_key, message_id))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Failed to end modifying state!\n"));
        GNUNET_break (0);
      }
    }
    if (NULL != scls.recv)
    {
      GNUNET_PSYC_receive_destroy (scls.recv);
    }
  }

  send_result_code (client, req->op_id, ret, NULL);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/** @todo FIXME: stop processing further state sync messages after an error */
static void
handle_state_sync (void *cls,
                   struct GNUNET_SERVER_Client *client,
                   const struct GNUNET_MessageHeader *msg)
{
  const struct StateSyncRequest *req
    = (const struct StateSyncRequest *) msg;

  int ret = GNUNET_SYSERR;
  const char *name = (const char *) &req[1];
  uint16_t name_size = ntohs (req->name_size);

  if (name_size <= 2 || '\0' != name[name_size - 1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Tried to set invalid state variable name!\n"));
    GNUNET_break_op (0);
  }
  else
  {
    ret = GNUNET_OK;

    if (req->flags & STATE_OP_FIRST)
    {
      ret = db->state_sync_begin (db->cls, &req->channel_key);
    }
    if (ret != GNUNET_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to begin synchronizing state!\n"));
    }
    else
    {
      ret = db->state_sync_assign (db->cls, &req->channel_key, name,
                                   name + ntohs (req->name_size),
                                   ntohs (req->header.size) - sizeof (*req)
                                   - ntohs (req->name_size));
    }

    if (GNUNET_OK == ret && req->flags & STATE_OP_LAST)
    {
      ret = db->state_sync_end (db->cls, &req->channel_key,
                                GNUNET_ntohll (req->max_state_message_id),
                                GNUNET_ntohll (req->state_hash_message_id));
      if (ret != GNUNET_OK)
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Failed to end synchronizing state!\n"));
    }
  }
  send_result_code (client, req->op_id, ret, NULL);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
handle_state_reset (void *cls,
                    struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *msg)
{
  const struct OperationRequest *req =
    (const struct OperationRequest *) msg;

  int ret = db->state_reset (db->cls, &req->channel_key);

  if (ret != GNUNET_OK)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to reset state!\n"));

  send_result_code (client, req->op_id, ret, NULL);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
handle_state_hash_update (void *cls,
                          struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *msg)
{
  const struct OperationRequest *req =
    (const struct OperationRequest *) msg;

  int ret = db->state_reset (db->cls, &req->channel_key);

  if (ret != GNUNET_OK)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to reset state!\n"));

  send_result_code (client, req->op_id, ret, NULL);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
handle_state_get (void *cls,
                  struct GNUNET_SERVER_Client *client,
                  const struct GNUNET_MessageHeader *msg)
{
  const struct OperationRequest *req =
    (const struct OperationRequest *) msg;

  struct SendClosure sc = { .op_id = req->op_id, .client = client };
  int64_t ret = GNUNET_SYSERR;
  const char *name = (const char *) &req[1];
  uint16_t name_size = ntohs (req->header.size) - sizeof (*req);

  if (name_size <= 2 || '\0' != name[name_size - 1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Tried to get invalid state variable name!\n"));
    GNUNET_break (0);
  }
  else
  {
    ret = db->state_get (db->cls, &req->channel_key, name,
                         &send_state_var, &sc);
    if (GNUNET_NO == ret && name_size >= 5) /* min: _a_b\0 */
    {
      char *p, *n = GNUNET_malloc (name_size);
      memcpy (n, name, name_size);
      while (&n[1] < (p = strrchr (n, '_')) && GNUNET_NO == ret)
      {
        *p = '\0';
        ret = db->state_get (db->cls, &req->channel_key, n,
                             &send_state_var, &sc);
      }
      GNUNET_free (n);
    }
  }
  switch (ret)
  {
  case GNUNET_OK:
  case GNUNET_NO:
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to get state variable!\n"));
  }

  send_result_code (client, req->op_id, ret, NULL);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
handle_state_get_prefix (void *cls,
                         struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *msg)
{
  const struct OperationRequest *req =
    (const struct OperationRequest *) msg;

  struct SendClosure sc = { .op_id = req->op_id, .client = client };
  int64_t ret = GNUNET_SYSERR;
  const char *name = (const char *) &req[1];
  uint16_t name_size = ntohs (req->header.size) - sizeof (*req);

  if (name_size <= 1 || '\0' != name[name_size - 1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Tried to get invalid state variable name!\n"));
    GNUNET_break (0);
  }
  else
  {
    ret = db->state_get_prefix (db->cls, &req->channel_key, name,
                                &send_state_var, &sc);
  }
  switch (ret)
  {
  case GNUNET_OK:
  case GNUNET_NO:
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to get state variable!\n"));
  }

  send_result_code (client, req->op_id, ret, NULL);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Initialize the PSYCstore service.
 *
 * @param cls Closure.
 * @param server The initialized server.
 * @param c Configuration to use.
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    { &handle_membership_store, NULL,
      GNUNET_MESSAGE_TYPE_PSYCSTORE_MEMBERSHIP_STORE,
      sizeof (struct MembershipStoreRequest) },

    { &handle_membership_test, NULL,
      GNUNET_MESSAGE_TYPE_PSYCSTORE_MEMBERSHIP_TEST,
      sizeof (struct MembershipTestRequest) },

    { &handle_fragment_store, NULL,
      GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_STORE, 0, },

    { &handle_fragment_get, NULL,
      GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_GET,
      sizeof (struct FragmentGetRequest) },

    { &handle_message_get, NULL,
      GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET, 0 },

    { &handle_message_get_fragment, NULL,
      GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET_FRAGMENT,
      sizeof (struct MessageGetFragmentRequest) },

    { &handle_counters_get, NULL,
      GNUNET_MESSAGE_TYPE_PSYCSTORE_COUNTERS_GET,
      sizeof (struct OperationRequest) },

    { &handle_state_modify, NULL,
      GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_MODIFY, 0 },

    { &handle_state_sync, NULL,
      GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_SYNC, 0 },

    { &handle_state_reset, NULL,
      GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_RESET,
      sizeof (struct OperationRequest) },

    { &handle_state_hash_update, NULL,
      GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_HASH_UPDATE,
      sizeof (struct StateHashUpdateRequest) },

    { &handle_state_get, NULL,
      GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_GET, 0 },

    { &handle_state_get_prefix, NULL,
      GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_GET_PREFIX, 0 },

    { NULL, NULL, 0, 0 }
  };

  cfg = c;

  /* Loading database plugin */
  char *database;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "psycstore", "database",
                                             &database))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No database backend configured\n");
  }
  else
  {
    GNUNET_asprintf (&db_lib_name, "libgnunet_plugin_psycstore_%s", database);
    db = GNUNET_PLUGIN_load (db_lib_name, (void *) cfg);
    GNUNET_free (database);
  }
  if (NULL == db)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Could not load database backend `%s'\n",
		db_lib_name);
    GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
    return;
  }

  stats = GNUNET_STATISTICS_create ("psycstore", cfg);
  GNUNET_SERVER_add_handlers (server, handlers);
  nc = GNUNET_SERVER_notification_context_create (server, 1);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
}


/**
 * The main function for the service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "psycstore",
			      GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}


/* end of gnunet-service-psycstore.c */
