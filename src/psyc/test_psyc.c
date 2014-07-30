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
 * @file psyc/test_psyc.c
 * @brief Tests for the PSYC API.
 * @author Gabor X Toth
 * @author Christian Grothoff
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_env_lib.h"
#include "gnunet_psyc_util_lib.h"
#include "gnunet_psyc_service.h"
#include "gnunet_core_service.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * Return value from 'main'.
 */
int res;

const struct GNUNET_CONFIGURATION_Handle *cfg;

struct GNUNET_CORE_Handle *core;
struct GNUNET_PeerIdentity this_peer;

/**
 * Handle for task for timeout termination.
 */
GNUNET_SCHEDULER_TaskIdentifier end_badly_task;

struct GNUNET_PSYC_Master *mst;
struct GNUNET_PSYC_Slave *slv;

struct GNUNET_PSYC_Channel *mst_chn, *slv_chn;

struct GNUNET_CRYPTO_EddsaPrivateKey *channel_key;
struct GNUNET_CRYPTO_EcdsaPrivateKey *slave_key;

struct GNUNET_CRYPTO_EddsaPublicKey channel_pub_key;
struct GNUNET_CRYPTO_EcdsaPublicKey slave_pub_key;

struct TransmitClosure
{
  struct GNUNET_PSYC_MasterTransmitHandle *mst_tmit;
  struct GNUNET_PSYC_SlaveTransmitHandle *slv_tmit;
  struct GNUNET_ENV_Environment *env;
  struct GNUNET_ENV_Modifier *mod;
  char *data[16];
  const char *mod_value;
  size_t mod_value_size;
  uint8_t data_delay[16];
  uint8_t data_count;
  uint8_t paused;
  uint8_t n;
};

struct TransmitClosure *tmit;

uint8_t join_req_count;

enum
{
  TEST_NONE = 0,
  TEST_MASTER_START = 1,
  TEST_SLAVE_JOIN = 2,
  TEST_SLAVE_TRANSMIT = 3,
  TEST_MASTER_TRANSMIT = 4,
  TEST_MASTER_HISTORY_REPLAY_LATEST = 5,
  TEST_SLAVE_HISTORY_REPLAY_LATEST = 6,
  TEST_MASTER_HISTORY_REPLAY = 7,
  TEST_SLAVE_HISTORY_REPLAY = 8,
  TEST_MASTER_STATE_GET = 9,
  TEST_SLAVE_STATE_GET = 10,
  TEST_MASTER_STATE_GET_PREFIX = 11,
  TEST_SLAVE_STATE_GET_PREFIX = 12,
} test;


void
master_transmit ();


void master_stopped (void *cls)
{
  if (NULL != tmit)
  {
    GNUNET_ENV_environment_destroy (tmit->env);
    GNUNET_free (tmit);
    tmit = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}

void slave_parted (void *cls)
{
  if (NULL != mst)
  {
    GNUNET_PSYC_master_stop (mst, GNUNET_NO, &master_stopped, NULL);
    mst = NULL;
  }
  else
    master_stopped (NULL);
}

/**
 * Clean up all resources used.
 */
void
cleanup ()
{
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
  if (NULL != slv)
  {
    GNUNET_PSYC_slave_part (slv, GNUNET_NO, &slave_parted, NULL);
    slv = NULL;
  }
  else
    slave_parted (NULL);
}


/**
 * Terminate the test case (failure).
 *
 * @param cls NULL
 * @param tc scheduler context
 */
void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  res = 1;
  cleanup ();
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Test FAILED.\n");
}


/**
 * Terminate the test case (success).
 *
 * @param cls NULL
 * @param tc scheduler context
 */
void
end_normally (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  res = 0;
  cleanup ();
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Test PASSED.\n");
}


/**
 * Finish the test case (successfully).
 */
void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ending tests.\n");

  if (end_badly_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (end_badly_task);
    end_badly_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
				&end_normally, NULL);
}


void
state_get_var (void *cls, const char *name, const void *value, size_t value_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got state var: %s\n%.*s\n", name, value_size, value);  
}


/*** Slave state_get_prefix() ***/

void
slave_state_get_prefix_result (void *cls, int64_t result, const char *err_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "slave_state_get_prefix:\t%" PRId64 " (%s)\n", result, err_msg);
  // FIXME: GNUNET_assert (2 == result);
  end ();
}


void
slave_state_get_prefix ()
{
  test = TEST_SLAVE_STATE_GET_PREFIX;
  GNUNET_PSYC_channel_state_get_prefix (slv_chn, "_foo", &state_get_var,
                                        &slave_state_get_prefix_result, NULL);
}


/*** Master state_get_prefix() ***/


void
master_state_get_prefix_result (void *cls, int64_t result, const char *err_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "master_state_get_prefix:\t%" PRId64 " (%s)\n", result, err_msg);
  // FIXME: GNUNET_assert (2 == result);
  slave_state_get_prefix ();
}


void
master_state_get_prefix ()
{
  test = TEST_MASTER_STATE_GET_PREFIX;
  GNUNET_PSYC_channel_state_get_prefix (mst_chn, "_foo", &state_get_var,
                                        &master_state_get_prefix_result, NULL);
}


/*** Slave state_get() ***/


void
slave_state_get_result (void *cls, int64_t result, const char *err_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "slave_state_get:\t%" PRId64 " (%s)\n", result, err_msg);
  // FIXME: GNUNET_assert (2 == result);
  master_state_get_prefix ();
}


void
slave_state_get ()
{
  test = TEST_SLAVE_STATE_GET;
  GNUNET_PSYC_channel_state_get (slv_chn, "_foo_bar_baz", &state_get_var,
                                 &slave_state_get_result, NULL);
}


/*** Master state_get() ***/


void
master_state_get_result (void *cls, int64_t result, const char *err_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "master_state_get:\t%" PRId64 " (%s)\n", result, err_msg);
  // FIXME: GNUNET_assert (1 == result);
  slave_state_get ();
}


void
master_state_get ()
{
  test = TEST_MASTER_STATE_GET;
  GNUNET_PSYC_channel_state_get (mst_chn, "_foo_bar_baz", &state_get_var,
                                 &master_state_get_result, NULL);
}


/*** Slave history_replay() ***/

void
slave_history_replay_result (void *cls, int64_t result, const char *err_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "slave_history_replay:\t%" PRId64 " (%s)\n", result, err_msg);
  GNUNET_assert (9 == result);

  master_state_get ();
}


void
slave_history_replay ()
{
  test = TEST_SLAVE_HISTORY_REPLAY;
  GNUNET_PSYC_channel_history_replay (slv_chn, 1, 1,
                                      &slave_history_replay_result,
                                      NULL);
}


/*** Master history_replay() ***/


void
master_history_replay_result (void *cls, int64_t result, const char *err_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "master_history_replay:\t%" PRId64 " (%s)\n", result, err_msg);
  GNUNET_assert (9 == result);

  slave_history_replay ();
}


void
master_history_replay ()
{
  test = TEST_MASTER_HISTORY_REPLAY;
  GNUNET_PSYC_channel_history_replay (mst_chn, 1, 1,
                                      &master_history_replay_result,
                                      NULL);
}


/*** Slave history_replay_latest() ***/


void
slave_history_replay_latest_result (void *cls, int64_t result, const char *err_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "slave_history_replay_latest:\t%" PRId64 " (%s)\n", result, err_msg);
  GNUNET_assert (9 == result);

  master_history_replay ();
}


void
slave_history_replay_latest ()
{
  test = TEST_SLAVE_HISTORY_REPLAY_LATEST;
  GNUNET_PSYC_channel_history_replay_latest (slv_chn, 1,
                                             &slave_history_replay_latest_result,
                                             NULL);
}


/*** Master history_replay_latest() ***/


void
master_history_replay_latest_result (void *cls, int64_t result, const char *err_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "master_history_replay_latest:\t%" PRId64 " (%s)\n", result, err_msg);
  GNUNET_assert (9 == result);

  slave_history_replay_latest ();
}


void
master_history_replay_latest ()
{
  test = TEST_MASTER_HISTORY_REPLAY_LATEST;
  GNUNET_PSYC_channel_history_replay_latest (mst_chn, 1,
                                             &master_history_replay_latest_result,
                                             NULL);
}


void
master_message_cb (void *cls, uint64_t message_id, uint32_t flags,
                   const struct GNUNET_PSYC_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%d: Master got PSYC message fragment of size %u "
              "belonging to message ID %" PRIu64 " with flags %x\n",
              test, ntohs (msg->header.size), message_id, flags);
  // FIXME
}


void
master_message_part_cb (void *cls, uint64_t message_id,
                        uint64_t data_offset, uint32_t flags,
                        const struct GNUNET_MessageHeader *msg)
{
  if (NULL == msg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error while receiving message %" PRIu64 "\n", message_id);
    return;
  }

  uint16_t type = ntohs (msg->type);
  uint16_t size = ntohs (msg->size);

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%d: Master got message part of type %u and size %u "
              "belonging to message ID %" PRIu64 " with flags %x\n",
              test, type, size, message_id, flags);

  switch (test)
  {
  case TEST_SLAVE_TRANSMIT:
    if (GNUNET_PSYC_MESSAGE_REQUEST != flags)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Unexpected request flags: %x" PRIu32 "\n", flags);
      GNUNET_assert (0);
      return;
    }
    // FIXME: check rest of message

    if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END == type)
      master_transmit ();
    break;

  case TEST_MASTER_TRANSMIT:
    break;

  case TEST_MASTER_HISTORY_REPLAY:
  case TEST_MASTER_HISTORY_REPLAY_LATEST:
    if (GNUNET_PSYC_MESSAGE_HISTORIC != flags)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Test #%d: Unexpected flags for historic message: %x" PRIu32 "\n",
                  flags);
      GNUNET_assert (0);
      return;
    }
    break;

  default:
    GNUNET_assert (0);
  }
}


void
slave_message_cb (void *cls, uint64_t message_id, uint32_t flags,
                  const struct GNUNET_PSYC_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%d: Slave got PSYC message fragment of size %u "
              "belonging to message ID %" PRIu64 " with flags %x\n",
              test, ntohs (msg->header.size), message_id, flags);
  // FIXME
}


void
slave_message_part_cb (void *cls, uint64_t message_id,
                       uint64_t data_offset, uint32_t flags,
                       const struct GNUNET_MessageHeader *msg)
{
  if (NULL == msg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error while receiving message " PRIu64 "\n", message_id);
    return;
  }

  uint16_t type = ntohs (msg->type);
  uint16_t size = ntohs (msg->size);

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%d: Slave got message part of type %u and size %u "
              "belonging to message ID %" PRIu64 " with flags %x\n",
              test, type, size, message_id, flags);

  switch (test)
  {
  case TEST_MASTER_TRANSMIT:
    if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END == type)
      master_history_replay_latest ();
    break;

  case TEST_SLAVE_HISTORY_REPLAY:
  case TEST_SLAVE_HISTORY_REPLAY_LATEST:
    if (GNUNET_PSYC_MESSAGE_HISTORIC != flags)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Test #%d: Unexpected flags for historic message: %x" PRIu32 "\n",
                  flags);
      GNUNET_assert (0);
      return;
    }
    break;

  default:
    GNUNET_assert (0);
  }
}


void
transmit_resume (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmission resumed.\n");
  struct TransmitClosure *tmit = cls;
  if (NULL != tmit->mst_tmit)
    GNUNET_PSYC_master_transmit_resume (tmit->mst_tmit);
  else
    GNUNET_PSYC_slave_transmit_resume (tmit->slv_tmit);
}


int
tmit_notify_data (void *cls, uint16_t *data_size, void *data)
{
  struct TransmitClosure *tmit = cls;
  if (0 == tmit->data_count)
  {
    *data_size = 0;
    return GNUNET_YES;
  }

  uint16_t size = strlen (tmit->data[tmit->n]);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmit notify data: %u bytes available, "
              "processing fragment %u/%u (size %u).\n",
              *data_size, tmit->n + 1, tmit->data_count, size);
  if (*data_size < size)
  {
    *data_size = 0;
    GNUNET_assert (0);
    return GNUNET_SYSERR;
  }

  if (GNUNET_YES != tmit->paused && 0 < tmit->data_delay[tmit->n])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmission paused.\n");
    tmit->paused = GNUNET_YES;
    GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                     tmit->data_delay[tmit->n]),
      &transmit_resume, tmit);
    *data_size = 0;
    return GNUNET_NO;
  }
  tmit->paused = GNUNET_NO;

  *data_size = size;
  memcpy (data, tmit->data[tmit->n], size);

  return ++tmit->n < tmit->data_count ? GNUNET_NO : GNUNET_YES;
}


int
tmit_notify_mod (void *cls, uint16_t *data_size, void *data, uint8_t *oper,
                 uint32_t *full_value_size)
{
  struct TransmitClosure *tmit = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmit notify modifier: %lu bytes available, "
              "%u modifiers left to process.\n",
              *data_size, GNUNET_ENV_environment_get_count (tmit->env));

  uint16_t name_size = 0;
  size_t value_size = 0;
  const char *value = NULL;

  if (NULL != oper && NULL != tmit->mod)
  { /* New modifier */
    tmit->mod = tmit->mod->next;
    if (NULL == tmit->mod)
    { /* No more modifiers, continue with data */
      *data_size = 0;
      return GNUNET_YES;
    }

    GNUNET_assert (tmit->mod->value_size < UINT32_MAX);
    *full_value_size = tmit->mod->value_size;
    *oper = tmit->mod->oper;
    name_size = strlen (tmit->mod->name);

    if (name_size + 1 + tmit->mod->value_size <= *data_size)
    {
      *data_size = name_size + 1 + tmit->mod->value_size;
    }
    else
    {
      tmit->mod_value_size = tmit->mod->value_size;
      value_size = *data_size - name_size - 1;
      tmit->mod_value_size -= value_size;
      tmit->mod_value = tmit->mod->value + value_size;
    }

    memcpy (data, tmit->mod->name, name_size);
    ((char *)data)[name_size] = '\0';
    memcpy ((char *)data + name_size + 1, tmit->mod->value, value_size);
  }
  else if (NULL != tmit->mod_value && 0 < tmit->mod_value_size)
  { /* Modifier continuation */
    value = tmit->mod_value;
    if (tmit->mod_value_size <= *data_size)
    {
      value_size = tmit->mod_value_size;
      tmit->mod_value = NULL;
    }
    else
    {
      value_size = *data_size;
      tmit->mod_value += value_size;
    }
    tmit->mod_value_size -= value_size;

    if (*data_size < value_size)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "value larger than buffer: %u < %zu\n",
                  *data_size, value_size);
      *data_size = 0;
      return GNUNET_NO;
    }

    *data_size = value_size;
    memcpy (data, value, value_size);
  }

  return GNUNET_NO;
}


void
slave_join ();


void
slave_transmit ()
{

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Slave sending request to master.\n");
  test = TEST_SLAVE_TRANSMIT;

  tmit = GNUNET_new (struct TransmitClosure);
  tmit->env = GNUNET_ENV_environment_create ();
  GNUNET_ENV_environment_add (tmit->env, GNUNET_ENV_OP_ASSIGN,
                              "_abc", "abc def", 7);
  GNUNET_ENV_environment_add (tmit->env, GNUNET_ENV_OP_ASSIGN,
                              "_abc_def", "abc def ghi", 11);
  tmit->mod = GNUNET_ENV_environment_head (tmit->env);
  tmit->n = 0;
  tmit->data[0] = "slave test";
  tmit->data_count = 1;
  tmit->slv_tmit
    = GNUNET_PSYC_slave_transmit (slv, "_request_test", tmit_notify_mod,
                                  tmit_notify_data, tmit,
                                  GNUNET_PSYC_SLAVE_TRANSMIT_NONE);
}


void
slave_remove_cb (void *cls, int64_t result, const char *err_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "slave_remove:\t%" PRId64 " (%s)\n", result, err_msg);

  slave_transmit ();
}


void
slave_add_cb (void *cls, int64_t result, const char *err_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "slave_add:\t%" PRId64 " (%s)\n", result, err_msg);

  struct GNUNET_PSYC_Channel *chn = cls;
  GNUNET_PSYC_channel_slave_remove (chn, &slave_pub_key, 2,
                                    &slave_remove_cb, chn);

}


void
join_decision_cb (void *cls,
                  const struct GNUNET_PSYC_JoinDecisionMessage *dcsn,
                  int is_admitted,
                  const struct GNUNET_PSYC_Message *join_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Slave got join decision: %d\n", is_admitted);

  if (GNUNET_YES != is_admitted)
  { /* First join request is refused, retry. */
    GNUNET_assert (1 == join_req_count);
    slave_join ();
    return;
  }

  struct GNUNET_PSYC_Channel *chn = GNUNET_PSYC_master_get_channel (mst);
  GNUNET_PSYC_channel_slave_add (chn, &slave_pub_key, 2, 2, &slave_add_cb, chn);
}


void
join_request_cb (void *cls,
                 const struct GNUNET_PSYC_JoinRequestMessage *req,
                 const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                 const struct GNUNET_PSYC_Message *join_msg,
                 struct GNUNET_PSYC_JoinHandle *jh)
{
  struct GNUNET_HashCode slave_key_hash;
  GNUNET_CRYPTO_hash (slave_key, sizeof (*slave_key), &slave_key_hash);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Got join request #%u from %s.\n",
              join_req_count, GNUNET_h2s (&slave_key_hash));

  /* Reject first request */
  int is_admitted = (0 < join_req_count++) ? GNUNET_YES : GNUNET_NO;
  GNUNET_PSYC_join_decision (jh, is_admitted, 0, NULL, NULL);
}


void
slave_connect_cb (void *cls, int result, uint64_t max_message_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Slave connected: %d, max_message_id: %" PRIu64 "\n",
              result, max_message_id);
  GNUNET_assert (TEST_SLAVE_JOIN == test);
  GNUNET_assert (GNUNET_OK == result || GNUNET_NO == result);
}


void
slave_join ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Joining slave.\n");
  test = TEST_SLAVE_JOIN;

  struct GNUNET_PeerIdentity origin = this_peer;
  struct GNUNET_ENV_Environment *env = GNUNET_ENV_environment_create ();
  GNUNET_ENV_environment_add (env, GNUNET_ENV_OP_ASSIGN,
                              "_foo", "bar baz", 7);
  GNUNET_ENV_environment_add (env, GNUNET_ENV_OP_ASSIGN,
                              "_foo_bar", "foo bar baz", 11);
  struct GNUNET_PSYC_Message *
    join_msg = GNUNET_PSYC_message_create ("_request_join", env, "some data", 9);

  slv = GNUNET_PSYC_slave_join (cfg, &channel_pub_key, slave_key, &origin, 0, NULL,
                                &slave_message_cb, &slave_message_part_cb,
                                &slave_connect_cb, &join_decision_cb, NULL,
                                join_msg);
  slv_chn = GNUNET_PSYC_slave_get_channel (slv);
  GNUNET_ENV_environment_destroy (env);
}


void
master_transmit ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Master sending message to all.\n");
  test = TEST_MASTER_TRANSMIT;
  uint32_t i, j;

  char *name_max = "_test_max";
  uint8_t name_max_size = sizeof ("_test_max");
  char *val_max = GNUNET_malloc (GNUNET_PSYC_MODIFIER_MAX_PAYLOAD);
  for (i = 0; i < GNUNET_PSYC_MODIFIER_MAX_PAYLOAD; i++)
    val_max[i] = (0 == i % 10000) ? '0' + i / 10000 : '.';

  char *name_cont = "_test_cont";
  uint8_t name_cont_size = sizeof ("_test_cont");
  char *val_cont = GNUNET_malloc (GNUNET_PSYC_MODIFIER_MAX_PAYLOAD
                                  + GNUNET_PSYC_MOD_CONT_MAX_PAYLOAD);
  for (i = 0; i < GNUNET_PSYC_MODIFIER_MAX_PAYLOAD - name_cont_size; i++)
    val_cont[i] = (0 == i % 10000) ? '0' + i / 10000 : ':';
  for (j = 0; j < GNUNET_PSYC_MOD_CONT_MAX_PAYLOAD; j++, i++)
    val_cont[i] = (0 == j % 10000) ? '0' + j / 10000 : '!';

  tmit = GNUNET_new (struct TransmitClosure);
  tmit->env = GNUNET_ENV_environment_create ();
  GNUNET_ENV_environment_add (tmit->env, GNUNET_ENV_OP_ASSIGN,
                              "_foo", "bar baz", 7);
  GNUNET_ENV_environment_add (tmit->env, GNUNET_ENV_OP_ASSIGN,
                              name_max, val_max,
                              GNUNET_PSYC_MODIFIER_MAX_PAYLOAD
                              - name_max_size);
  GNUNET_ENV_environment_add (tmit->env, GNUNET_ENV_OP_ASSIGN,
                              "_foo_bar", "foo bar baz", 11);
  GNUNET_ENV_environment_add (tmit->env, GNUNET_ENV_OP_ASSIGN,
                              name_cont, val_cont,
                              GNUNET_PSYC_MODIFIER_MAX_PAYLOAD - name_cont_size
                              + GNUNET_PSYC_MOD_CONT_MAX_PAYLOAD);
  tmit->mod = GNUNET_ENV_environment_head (tmit->env);
  tmit->data[0] = "foo";
  tmit->data[1] =  GNUNET_malloc (GNUNET_PSYC_DATA_MAX_PAYLOAD + 1);
  for (i = 0; i < GNUNET_PSYC_DATA_MAX_PAYLOAD; i++)
    tmit->data[1][i] = (0 == i % 10000) ? '0' + i / 10000 : '_';
  tmit->data[2] = "foo bar";
  tmit->data[3] = "foo bar baz";
  tmit->data_delay[1] = 3;
  tmit->data_count = 4;
  tmit->mst_tmit
    = GNUNET_PSYC_master_transmit (mst, "_notice_test", tmit_notify_mod,
                                   tmit_notify_data, tmit,
                                   GNUNET_PSYC_MASTER_TRANSMIT_INC_GROUP_GEN);
}


void
master_start_cb (void *cls, int result, uint64_t max_message_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Master started: %d, max_message_id: %" PRIu64 "\n",
              result, max_message_id);
  GNUNET_assert (TEST_MASTER_START == test);
  GNUNET_assert (GNUNET_OK == result || GNUNET_NO == result);
  slave_join ();
}


void
master_start ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Starting master.\n");
  test = TEST_MASTER_START;
  mst = GNUNET_PSYC_master_start (cfg, channel_key, GNUNET_PSYC_CHANNEL_PRIVATE,
                                  &master_start_cb, &join_request_cb,
                                  &master_message_cb, &master_message_part_cb,
                                  NULL);
  mst_chn = GNUNET_PSYC_master_get_channel (mst);
}

void
schedule_master_start (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  master_start ();
}


void
core_connected (void *cls, const struct GNUNET_PeerIdentity *my_identity)
{
  this_peer = *my_identity;

#if DEBUG_TEST_PSYC
  master_start ();
#else
  /* Allow some time for the services to initialize. */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                &schedule_master_start, NULL);
#endif

}

/**
 * Main function of the test, run from scheduler.
 *
 * @param cls NULL
 * @param cfg configuration we use (also to connect to PSYC service)
 * @param peer handle to access more of the peer (not used)
 */
void
#if DEBUG_TEST_PSYC
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
#else
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_TESTING_Peer *peer)
#endif
{
  cfg = c;
  end_badly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  channel_key = GNUNET_CRYPTO_eddsa_key_create ();
  slave_key = GNUNET_CRYPTO_ecdsa_key_create ();

  GNUNET_CRYPTO_eddsa_key_get_public (channel_key, &channel_pub_key);
  GNUNET_CRYPTO_ecdsa_key_get_public (slave_key, &slave_pub_key);

  core = GNUNET_CORE_connect (cfg, NULL, &core_connected, NULL, NULL,
                              NULL, GNUNET_NO, NULL, GNUNET_NO, NULL);
}


int
main (int argc, char *argv[])
{
  res = 1;
#if DEBUG_TEST_PSYC
  const struct GNUNET_GETOPT_CommandLineOption opts[] = {
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_PROGRAM_run (argc, argv, "test-psyc",
                                       "test-psyc [options]",
                                       opts, &run, NULL))
    return 1;
#else
  if (0 != GNUNET_TESTING_peer_run ("test-psyc", "test_psyc.conf", &run, NULL))
    return 1;
#endif
  return res;
}

/* end of test_psyc.c */
