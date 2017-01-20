/**
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
 * Service handle.
 */
static struct GNUNET_SERVICE_Handle *service;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

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
 */
static void
shutdown_task (void *cls)
{
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
send_result_code (struct GNUNET_SERVICE_Client *client,
                  uint64_t op_id,
                  int64_t result_code,
                  const char *err_msg)
{
  struct OperationResult *res;
  size_t err_size = 0;

  if (NULL != err_msg)
    err_size = strnlen (err_msg,
                        GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (*res) - 1) + 1;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_extra (res, err_size,
                               GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_CODE);
  res->result_code = GNUNET_htonll (result_code - INT64_MIN);
  res->op_id = op_id;
  if (0 < err_size)
  {
    GNUNET_memcpy (&res[1], err_msg, err_size);
    ((char *) &res[1])[err_size - 1] = '\0';
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending result to client: %" PRId64 " (%s)\n",
	      result_code, err_msg);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client), env);
}


enum
{
  MEMBERSHIP_TEST_NOT_NEEDED = 0,
  MEMBERSHIP_TEST_NEEDED = 1,
  MEMBERSHIP_TEST_DONE = 2,
} MessageMembershipTest;


struct SendClosure
{
  struct GNUNET_SERVICE_Client *client;

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

  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_extra (res, msg_size,
                               GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_FRAGMENT);
  res->op_id = sc->op_id;
  res->psycstore_flags = htonl (flags);
  GNUNET_memcpy (&res[1], msg, msg_size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending fragment %llu to client\n",
	      (unsigned long long) GNUNET_ntohll (msg->fragment_id));
  GNUNET_free (msg);

  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (sc->client), env);
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

  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_extra (res, name_size + value_size,
                               GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_STATE);
  res->op_id = sc->op_id;
  res->name_size = htons (name_size);
  GNUNET_memcpy (&res[1], name, name_size);
  GNUNET_memcpy ((char *) &res[1] + name_size, value, value_size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending state variable %s to client\n", name);

  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (sc->client), env);
  return GNUNET_OK;
}


static void
handle_client_membership_store (void *cls,
                                const struct MembershipStoreRequest *req)
{
  struct GNUNET_SERVICE_Client *client = cls;

  int ret = db->membership_store (db->cls, &req->channel_key, &req->slave_key,
                                  req->did_join,
                                  GNUNET_ntohll (req->announced_at),
                                  GNUNET_ntohll (req->effective_since),
                                  GNUNET_ntohll (req->group_generation));

  if (ret != GNUNET_OK)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to store membership information!\n"));

  send_result_code (client, req->op_id, ret, NULL);
  GNUNET_SERVICE_client_continue (client);
}


static void
handle_client_membership_test (void *cls,
                               const struct MembershipTestRequest *req)
{
  struct GNUNET_SERVICE_Client *client = cls;

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
  GNUNET_SERVICE_client_continue (client);
}


static int
check_client_fragment_store (void *cls,
                             const struct FragmentStoreRequest *req)
{
  return GNUNET_OK;
}


static void
handle_client_fragment_store (void *cls,
                              const struct FragmentStoreRequest *req)
{
  struct GNUNET_SERVICE_Client *client = cls;

  const struct GNUNET_MessageHeader *
    msg = GNUNET_MQ_extract_nested_mh (req);
  if (NULL == msg
      || ntohs (msg->size) < sizeof (struct GNUNET_MULTICAST_MessageHeader))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Dropping invalid fragment\n"));
    GNUNET_SERVICE_client_drop (client);
    return;
  }

  int ret = db->fragment_store (db->cls, &req->channel_key,
                                (const struct GNUNET_MULTICAST_MessageHeader *)
                                msg, ntohl (req->psycstore_flags));

  if (ret != GNUNET_OK)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to store fragment\n"));

  send_result_code (client, req->op_id, ret, NULL);
  GNUNET_SERVICE_client_continue (client);
}


static void
handle_client_fragment_get (void *cls,
                            const struct FragmentGetRequest *req)
{
  struct GNUNET_SERVICE_Client *client = cls;

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
  GNUNET_SERVICE_client_continue (client);
}


static int
check_client_message_get (void *cls,
                          const struct MessageGetRequest *req)
{
  return GNUNET_OK;
}


static void
handle_client_message_get (void *cls,
                           const struct MessageGetRequest *req)
{
  struct GNUNET_SERVICE_Client *client = cls;

  uint16_t size = ntohs (req->header.size);
  const char *method_prefix = (const char *) &req[1];

  if (size < sizeof (*req) + 1
      || '\0' != method_prefix[size - sizeof (*req) - 1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Message get: invalid method prefix. size: %u < %u?\n",
                size,
                (unsigned int) (sizeof (*req) + 1));
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
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
  GNUNET_SERVICE_client_continue (client);
}


static void
handle_client_message_get_fragment (void *cls,
                                    const struct MessageGetFragmentRequest *req)
{
  struct GNUNET_SERVICE_Client *client = cls;

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
  GNUNET_SERVICE_client_continue (client);
}


static void
handle_client_counters_get (void *cls,
                            const struct OperationRequest *req)
{
  struct GNUNET_SERVICE_Client *client = cls;

  struct CountersResult *res;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg (res, GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_COUNTERS);

  int ret = db->counters_message_get (db->cls, &req->channel_key,
                                      &res->max_fragment_id, &res->max_message_id,
                                      &res->max_group_generation);
  switch (ret)
  {
  case GNUNET_OK:
    ret = db->counters_state_get (db->cls, &req->channel_key,
                                  &res->max_state_message_id);
  case GNUNET_NO:
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to get master counters!\n"));
  }

  res->result_code = htonl (ret);
  res->op_id = req->op_id;
  res->max_fragment_id = GNUNET_htonll (res->max_fragment_id);
  res->max_message_id = GNUNET_htonll (res->max_message_id);
  res->max_group_generation = GNUNET_htonll (res->max_group_generation);
  res->max_state_message_id = GNUNET_htonll (res->max_state_message_id);

  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client), env);
  GNUNET_SERVICE_client_continue (client);
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
                         const struct GNUNET_PSYC_MessageHeader *msg,
                         const struct GNUNET_MessageHeader *pmsg)
{
  struct StateModifyClosure *scls = cls;
  uint16_t psize;

  if (NULL == msg)
  { // FIXME: error on unknown message
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "recv_state_message_part()  message_id: %" PRIu64
              ", fragment_offset: %" PRIu64 ", flags: %u\n",
              GNUNET_ntohll (msg->message_id),
              GNUNET_ntohll (msg->fragment_offset),
              ntohl (msg->flags));

  if (NULL == pmsg)
  {
    scls->msg_state = GNUNET_PSYC_MESSAGE_STATE_ERROR;
    return;
  }

  switch (ntohs (pmsg->type))
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD:
  {
    scls->msg_state = GNUNET_PSYC_MESSAGE_STATE_METHOD;
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
  {
    struct GNUNET_PSYC_MessageModifier *
      pmod = (struct GNUNET_PSYC_MessageModifier *) pmsg;
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
        GNUNET_memcpy (scls->mod_name, name, name_size);

        scls->mod_value_size = value_size;
        scls->mod_value = GNUNET_malloc (scls->mod_value_size);
        scls->mod_value_remaining
          = scls->mod_value_size - (psize - sizeof (*pmod) - name_size);
        GNUNET_memcpy (scls->mod_value, value, value_size - scls->mod_value_remaining);
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
      psize = ntohs (pmsg->size);
      GNUNET_memcpy (scls->mod_value + (scls->mod_value_size - scls->mod_value_remaining),
              &pmsg[1], psize - sizeof (*pmsg));
      scls->mod_value_remaining -= psize - sizeof (*pmsg);
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
handle_client_state_modify (void *cls,
                            const struct StateModifyRequest *req)
{
  struct GNUNET_SERVICE_Client *client = cls;

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
  GNUNET_SERVICE_client_continue (client);
}


static int
check_client_state_sync (void *cls,
                         const struct StateSyncRequest *req)
{
  return GNUNET_OK;
}


/** @todo FIXME: stop processing further state sync messages after an error */
static void
handle_client_state_sync (void *cls,
                          const struct StateSyncRequest *req)
{
  struct GNUNET_SERVICE_Client *client = cls;

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
  GNUNET_SERVICE_client_continue (client);
}


static void
handle_client_state_reset (void *cls,
                           const struct OperationRequest *req)
{
  struct GNUNET_SERVICE_Client *client = cls;

  int ret = db->state_reset (db->cls, &req->channel_key);

  if (ret != GNUNET_OK)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to reset state!\n"));

  send_result_code (client, req->op_id, ret, NULL);
  GNUNET_SERVICE_client_continue (client);
}


static void
handle_client_state_hash_update (void *cls,
                                 const struct StateHashUpdateRequest *req)
{
  struct GNUNET_SERVICE_Client *client = cls;

  int ret = db->state_reset (db->cls, &req->channel_key);
  if (ret != GNUNET_OK)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to reset state!\n"));

  send_result_code (client, req->op_id, ret, NULL);
  GNUNET_SERVICE_client_continue (client);
}


static int
check_client_state_get (void *cls,
                        const struct OperationRequest *req)
{
  return GNUNET_OK;
}


static void
handle_client_state_get (void *cls,
                         const struct OperationRequest *req)
{
  struct GNUNET_SERVICE_Client *client = cls;

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
      GNUNET_memcpy (n, name, name_size);
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
  GNUNET_SERVICE_client_continue (client);
}


static int
check_client_state_get_prefix (void *cls,
                               const struct OperationRequest *req)
{
  return GNUNET_OK;
}


static void
handle_client_state_get_prefix (void *cls,
                                const struct OperationRequest *req)
{
  struct GNUNET_SERVICE_Client *client = cls;

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
  GNUNET_SERVICE_client_continue (client);
}


/**
 * A new client connected.
 *
 * @param cls NULL
 * @param client client to add
 * @param mq message queue for @a client
 * @return @a client
 */
static void *
client_notify_connect (void *cls,
                       struct GNUNET_SERVICE_Client *client,
                       struct GNUNET_MQ_Handle *mq)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client connected: %p\n", client);

  return client;
}


/**
 * Called whenever a client is disconnected.
 * Frees our resources associated with that client.
 *
 * @param cls closure
 * @param client identification of the client
 * @param app_ctx must match @a client
 */
static void
client_notify_disconnect (void *cls,
                          struct GNUNET_SERVICE_Client *client,
                          void *app_ctx)
{
}


/**
 * Initialize the PSYCstore service.
 *
 * @param cls Closure.
 * @param server The initialized server.
 * @param c Configuration to use.
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *svc)
{
  cfg = c;
  service = svc;

  /* Loading database plugin */
  char *database;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "psycstore", "database",
                                             &database))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "psycstore",
			       "database");
  }
  else
  {
    GNUNET_asprintf (&db_lib_name,
		     "libgnunet_plugin_psycstore_%s",
		     database);
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
  GNUNET_SCHEDULER_add_shutdown (shutdown_task,
				 NULL);
}

/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("psycstore",
 GNUNET_SERVICE_OPTION_NONE,
 run,
 client_notify_connect,
 client_notify_disconnect,
 NULL,
 GNUNET_MQ_hd_fixed_size (client_membership_store,
                          GNUNET_MESSAGE_TYPE_PSYCSTORE_MEMBERSHIP_STORE,
                          struct MembershipStoreRequest,
                          NULL),
 GNUNET_MQ_hd_fixed_size (client_membership_test,
                          GNUNET_MESSAGE_TYPE_PSYCSTORE_MEMBERSHIP_TEST,
                          struct MembershipTestRequest,
                          NULL),
 GNUNET_MQ_hd_var_size (client_fragment_store,
                        GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_STORE,
                        struct FragmentStoreRequest,
                        NULL),
 GNUNET_MQ_hd_fixed_size (client_fragment_get,
                          GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_GET,
                          struct FragmentGetRequest,
                          NULL),
 GNUNET_MQ_hd_var_size (client_message_get,
                        GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET,
                        struct MessageGetRequest,
                        NULL),
 GNUNET_MQ_hd_fixed_size (client_message_get_fragment,
                          GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET_FRAGMENT,
                          struct MessageGetFragmentRequest,
                          NULL),
 GNUNET_MQ_hd_fixed_size (client_counters_get,
                          GNUNET_MESSAGE_TYPE_PSYCSTORE_COUNTERS_GET,
                          struct OperationRequest,
                          NULL),
 GNUNET_MQ_hd_fixed_size (client_state_modify,
                          GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_MODIFY,
                          struct StateModifyRequest,
                          NULL),
 GNUNET_MQ_hd_var_size (client_state_sync,
                        GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_SYNC,
                        struct StateSyncRequest,
                        NULL),
 GNUNET_MQ_hd_fixed_size (client_state_reset,
                          GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_RESET,
                          struct OperationRequest,
                          NULL),
 GNUNET_MQ_hd_fixed_size (client_state_hash_update,
                          GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_HASH_UPDATE,
                          struct StateHashUpdateRequest,
                          NULL),
 GNUNET_MQ_hd_var_size (client_state_get,
                        GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_GET,
                        struct OperationRequest,
                        NULL),
 GNUNET_MQ_hd_var_size (client_state_get_prefix,
                        GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_GET_PREFIX,
                        struct OperationRequest,
                        NULL));

/* end of gnunet-service-psycstore.c */
