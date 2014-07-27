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

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * Return value from 'main'.
 */
int res;

const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle for task for timeout termination.
 */
GNUNET_SCHEDULER_TaskIdentifier end_badly_task;

struct GNUNET_PSYC_Master *mst;
struct GNUNET_PSYC_Slave *slv;

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
  TEST_NONE,
  TEST_SLAVE_TRANSMIT,
  TEST_MASTER_TRANSMIT,
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
master_message_cb (void *cls, uint64_t message_id, uint32_t flags,
                   const struct GNUNET_PSYC_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Master got PSYC message fragment of size %u "
              "belonging to message ID %llu with flags %x\n",
              ntohs (msg->header.size), message_id, flags);
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
                "Error while receiving message %llu\n", message_id);
    return;
  }

  uint16_t type = ntohs (msg->type);
  uint16_t size = ntohs (msg->size);

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Master got message part of type %u and size %u "
              "belonging to message ID %llu with flags %x\n",
              type, size, message_id, flags);

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

  default:
    GNUNET_assert (0);
  }
}


void
slave_message_cb (void *cls, uint64_t message_id, uint32_t flags,
                  const struct GNUNET_PSYC_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Slave got PSYC message fragment of size %u "
              "belonging to message ID %llu with flags %x\n",
              ntohs (msg->header.size), message_id, flags);
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
                "Error while receiving message %llu\n", message_id);
    return;
  }

  uint16_t type = ntohs (msg->type);
  uint16_t size = ntohs (msg->size);

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Slave got message part of type %u and size %u "
              "belonging to message ID %llu with flags %x\n",
              type, size, message_id, flags);

  switch (test)
  {
  case TEST_MASTER_TRANSMIT:
    if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END == type)
      end ();
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

  slave_transmit ();
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

  /* Membership store */
  struct GNUNET_PSYC_Channel *chn = GNUNET_PSYC_master_get_channel (mst);
  GNUNET_PSYC_channel_slave_add (chn, slave_key, 2, 2);
  GNUNET_PSYC_channel_slave_remove (chn, &slave_pub_key, 2);
}


void
slave_connect_cb (void *cls, uint64_t max_message_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Slave connected: %lu\n", max_message_id);
}


void
slave_join ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Joining slave.\n");

  struct GNUNET_PeerIdentity origin = {}; // FIXME: this peer
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
master_start_cb (void *cls, uint64_t max_message_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Master started: %" PRIu64 "\n", max_message_id);
  slave_join ();
}


void
master_start ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Starting master.\n");
  mst = GNUNET_PSYC_master_start (cfg, channel_key, GNUNET_PSYC_CHANNEL_PRIVATE,
                                  &master_start_cb, &join_request_cb,
                                  &master_message_cb, &master_message_part_cb,
                                  NULL);
}

void
schedule_master_start (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  master_start ();
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

#if DEBUG_TEST_PSYC
  master_start ();
#else
  /* Allow some time for the services to initialize. */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                &schedule_master_start, NULL);
#endif
  return;
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
