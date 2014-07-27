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
 * @file psycstore/test_psycstore.c
 * @brief Test for the PSYCstore service.
 * @author Gabor X Toth
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_common.h"
#include "gnunet_testing_lib.h"
#include "gnunet_psycstore_service.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


/**
 * Return value from 'main'.
 */
static int res;

/**
 * Handle to PSYCstore service.
 */
static struct GNUNET_PSYCSTORE_Handle *h;

/**
 * Handle to PSYCstore operation.
 */
static struct GNUNET_PSYCSTORE_OperationHandle *op;

/**
 * Handle for task for timeout termination.
 */
static GNUNET_SCHEDULER_TaskIdentifier end_badly_task;

static struct GNUNET_CRYPTO_EddsaPrivateKey *channel_key;
static struct GNUNET_CRYPTO_EcdsaPrivateKey *slave_key;

static struct GNUNET_CRYPTO_EddsaPublicKey channel_pub_key;
static struct GNUNET_CRYPTO_EcdsaPublicKey slave_pub_key;

static struct FragmentClosure
{
  uint8_t n;
  uint8_t n_expected;
  uint64_t flags[16];
  struct GNUNET_MULTICAST_MessageHeader *msg[16];
} fcls;

struct StateClosure {
  size_t n;
  char *name[16];
  void *value[16];
  size_t value_size[16];
} scls;

static struct GNUNET_ENV_Modifier modifiers[16];

/**
 * Clean up all resources used.
 */
static void
cleanup ()
{
  if (NULL != op)
  {
    GNUNET_PSYCSTORE_operation_cancel (op);
    op = NULL;
  }
  if (NULL != h)
  {
    GNUNET_PSYCSTORE_disconnect (h);
    h = NULL;
  }
  if (NULL != channel_key)
  {
    GNUNET_free (channel_key);
    channel_key = NULL;
  }
  if (NULL != slave_key)
  {
    GNUNET_free (slave_key);
    slave_key = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Terminate the testcase (failure).
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  res = 1;
  cleanup ();
}


/**
 * Terminate the testcase (success).
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
end_normally (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  res = 0;
  cleanup ();
}


/**
 * Finish the testcase (successfully).
 */
static void
end ()
{
  if (end_badly_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (end_badly_task);
    end_badly_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
				&end_normally, NULL);
}


void
state_reset_result (void *cls, int64_t result, const char *err_msg)
{
  op = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "state_reset_result:\t%d\n", result);
  GNUNET_assert (GNUNET_OK == result);

  op = GNUNET_PSYCSTORE_state_reset (h, &channel_pub_key,
                                     &state_reset_result, cls);
  GNUNET_PSYCSTORE_operation_cancel (op);
  op = NULL;
  end ();
}


static int
state_result (void *cls, const char *name, const void *value, size_t value_size)
{
  struct StateClosure *scls = cls;
  const char *nam = scls->name[scls->n];
  const void *val = scls->value[scls->n];
  size_t val_size = scls->value_size[scls->n++];

  if (value_size == val_size
      && 0 == memcmp (value, val, val_size)
      && 0 == strcmp (name, nam))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  variable %s matches\n", name);
    return GNUNET_YES;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "  variable %s differs\nReceived: %.*s\nExpected: %.*s\n",
                name, value_size, value, val_size, val);
    GNUNET_assert (0);
    return GNUNET_SYSERR;
  }
}


void
state_get_prefix_result (void *cls, int64_t result, const char *err_msg)
{
  struct StateClosure *scls = cls;
  op = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "state_get_prefix_result:\t%d\n", result);
  GNUNET_assert (GNUNET_OK == result && 2 == scls->n);

  op = GNUNET_PSYCSTORE_state_reset (h, &channel_pub_key,
                                     &state_reset_result, cls);
}


void
state_get_result (void *cls, int64_t result, const char *err_msg)
{
  op = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "state_get_result:\t%d\n", result);
  GNUNET_assert (GNUNET_OK == result);

  scls.n = 0;

  scls.name[0] = "_sync_bar";
  scls.value[0] = "ten eleven twelve";
  scls.value_size[0] = sizeof ("ten eleven twelve") - 1;

  scls.name[1] = "_sync_foo";
  scls.value[1] = "one two three";
  scls.value_size[1] = sizeof ("one two three") - 1;

  op = GNUNET_PSYCSTORE_state_get_prefix (h, &channel_pub_key, "_sync",
                                          &state_result,
                                          &state_get_prefix_result, &scls);
}


void
counters_result (void *cls, int status, uint64_t max_fragment_id,
                 uint64_t max_message_id, uint64_t max_group_generation,
                 uint64_t max_state_message_id)
{
  struct FragmentClosure *fcls = cls;
  int result = 0;
  op = NULL;

  if (GNUNET_OK == status
      && max_fragment_id == GNUNET_ntohll (fcls->msg[2]->fragment_id)
      && max_message_id == GNUNET_ntohll (fcls->msg[2]->message_id)
      && max_group_generation == GNUNET_ntohll (fcls->msg[2]->group_generation)
      && max_state_message_id == GNUNET_ntohll (fcls->msg[0]->message_id))
    result = 1;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "counters_get:\t%d\n", result);
  GNUNET_assert (result == 1);

  scls.n = 0;
  scls.name[0] = "_bar";
  scls.value[0] = "four five six";
  scls.value_size[0] = sizeof ("four five six") - 1;

  op = GNUNET_PSYCSTORE_state_get (h, &channel_pub_key, "_bar_x_yy_zzz",
                                   &state_result, &state_get_result, &scls);
}


void
state_modify_result (void *cls, int64_t result, const char *err_msg)
{
  op = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "state_modify_result:\t%d\n", result);
  GNUNET_assert (GNUNET_OK == result);

  op = GNUNET_PSYCSTORE_counters_get (h, &channel_pub_key,
                                      &counters_result, cls);
}


void
state_sync_result (void *cls, int64_t result, const char *err_msg)
{
  struct FragmentClosure *fcls = cls;
  op = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "state_sync_result:\t%d\n", result);
  GNUNET_assert (GNUNET_OK == result);

  modifiers[0] = (struct GNUNET_ENV_Modifier) {
    .oper = '=',
    .name = "_sync_foo",
    .value = "one two three",
    .value_size = sizeof ("one two three") - 1
  };
  modifiers[1] = (struct GNUNET_ENV_Modifier) {
    .oper = '=',
    .name = "_bar",
    .value = "four five six",
    .value_size = sizeof ("four five six") - 1
  };

  op = GNUNET_PSYCSTORE_state_modify (h, &channel_pub_key,
                                      GNUNET_ntohll (fcls->msg[0]->message_id), 0,
                                      2, modifiers, state_modify_result, fcls);
}


int
fragment_result (void *cls,
                 struct GNUNET_MULTICAST_MessageHeader *msg,
                 enum GNUNET_PSYCSTORE_MessageFlags flags)
{
  struct FragmentClosure *fcls = cls;
  struct GNUNET_MULTICAST_MessageHeader *msg0 = fcls->msg[fcls->n];
  uint64_t flags0 = fcls->flags[fcls->n++];

  if (flags == flags0 && msg->header.size == msg0->header.size
      && 0 == memcmp (msg, msg0, ntohs (msg->header.size)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  fragment %llu matches\n",
                GNUNET_ntohll (msg->fragment_id));
    return GNUNET_YES;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "  fragment %llu differs\n",
                GNUNET_ntohll (msg->fragment_id));
    GNUNET_assert (0);
    return GNUNET_SYSERR;
  }
}


void
message_get_result (void *cls, int64_t result, const char *err_msg)
{
  struct FragmentClosure *fcls = cls;
  op = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "message_get:\t%d\n", result);
  GNUNET_assert (result > 0 && fcls->n && fcls->n_expected);


  modifiers[0] = (struct GNUNET_ENV_Modifier) {
    .oper = '=',
    .name = "_sync_foo",
    .value = "three two one",
    .value_size = sizeof ("three two one") - 1
  };
  modifiers[1] = (struct GNUNET_ENV_Modifier) {
    .oper = '=',
    .name = "_sync_bar",
    .value = "ten eleven twelve",
    .value_size = sizeof ("ten eleven twelve") - 1
  };

  op = GNUNET_PSYCSTORE_state_sync (h, &channel_pub_key,
                                    GNUNET_ntohll (fcls->msg[0]->message_id) + 1,
                                    2, modifiers, state_sync_result, fcls);
}


void
message_get_fragment_result (void *cls, int64_t result, const char *err_msg)
{
  struct FragmentClosure *fcls = cls;
  op = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "message_get_fragment:\t%d\n", result);
  GNUNET_assert (result > 0 && fcls->n && fcls->n_expected);

  fcls->n = 0;
  fcls->n_expected = 3;
  op = GNUNET_PSYCSTORE_message_get (h, &channel_pub_key, &slave_pub_key,
                                     GNUNET_ntohll (fcls->msg[0]->message_id),
                                     &fragment_result,
                                     &message_get_result, fcls);
}


void
fragment_get_result (void *cls, int64_t result, const char *err_msg)
{
  struct FragmentClosure *fcls = cls;
  op = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "fragment_get:\t%d\n", result);
  GNUNET_assert (result > 0 && fcls->n && fcls->n_expected);

  fcls->n = 1;
  fcls->n_expected = 2;
  op = GNUNET_PSYCSTORE_message_get_fragment (h, &channel_pub_key, &slave_pub_key,
                                              GNUNET_ntohll (fcls->msg[1]->message_id),
                                              GNUNET_ntohll (fcls->msg[1]->fragment_offset),
                                              &fragment_result,
                                              &message_get_fragment_result,
                                              fcls);

}


void
fragment_store_result (void *cls, int64_t result, const char *err_msg)
{
  op = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "fragment_store:\t%d\n", result);
  GNUNET_assert (GNUNET_OK == result);

  if ((intptr_t) cls == GNUNET_YES)
  { /* last fragment */
    fcls.n = 0;
    fcls.n_expected = 1;
    op = GNUNET_PSYCSTORE_fragment_get (h, &channel_pub_key, &slave_pub_key,
                                        GNUNET_ntohll (fcls.msg[0]->fragment_id),
                                        &fragment_result,
                                        &fragment_get_result, &fcls);
  }
}


void
fragment_store ()
{
  struct GNUNET_MULTICAST_MessageHeader *msg;
  fcls.flags[0] = GNUNET_PSYCSTORE_MESSAGE_STATE;
  fcls.msg[0] = msg = GNUNET_malloc (sizeof (*msg) + sizeof (channel_pub_key));
  GNUNET_assert (msg != NULL);

  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE);
  msg->header.size = htons (sizeof (*msg) + sizeof (channel_pub_key));

  msg->hop_counter = htonl (9);
  msg->fragment_id = GNUNET_htonll (INT64_MAX - 8);
  msg->fragment_offset = GNUNET_htonll (0);
  msg->message_id = GNUNET_htonll (INT64_MAX - 10);
  msg->group_generation = GNUNET_htonll (INT64_MAX - 3);
  msg->flags = htonl (GNUNET_MULTICAST_MESSAGE_LAST_FRAGMENT);

  memcpy (&msg[1], &channel_pub_key, sizeof (channel_pub_key));

  msg->purpose.size = htonl (ntohs (msg->header.size)
                             - sizeof (msg->header)
                             - sizeof (msg->hop_counter)
                             - sizeof (msg->signature));
  msg->purpose.purpose = htonl (234);
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_eddsa_sign (channel_key, &msg->purpose,
                                                        &msg->signature));

  op = GNUNET_PSYCSTORE_fragment_store (h, &channel_pub_key, msg, fcls.flags[0],
                                        &fragment_store_result, GNUNET_NO);

  fcls.flags[1] = GNUNET_PSYCSTORE_MESSAGE_STATE_APPLIED;
  fcls.msg[1] = msg = GNUNET_malloc (sizeof (*msg) + sizeof (channel_pub_key));
  memcpy (msg, fcls.msg[0], sizeof (*msg) + sizeof (channel_pub_key));
  msg->fragment_id = GNUNET_htonll (INT64_MAX - 4);
  msg->fragment_offset = GNUNET_htonll (1024);

  op = GNUNET_PSYCSTORE_fragment_store (h, &channel_pub_key, msg, fcls.flags[1],
                                        &fragment_store_result, GNUNET_NO);

  fcls.flags[2] = GNUNET_PSYCSTORE_MESSAGE_STATE_HASH;
  fcls.msg[2] = msg = GNUNET_malloc (sizeof (*msg) + sizeof (channel_pub_key));
  memcpy (msg, fcls.msg[1], sizeof (*msg) + sizeof (channel_pub_key));
  msg->fragment_id = GNUNET_htonll (INT64_MAX);
  msg->fragment_offset = GNUNET_htonll (16384);

  op = GNUNET_PSYCSTORE_fragment_store (h, &channel_pub_key, msg, fcls.flags[2],
                                        &fragment_store_result, (void *) GNUNET_YES);
}


void
membership_test_result (void *cls, int64_t result, const char *err_msg)
{
  op = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "membership_test:\t%d\n", result);
  GNUNET_assert (GNUNET_OK == result);

  fragment_store ();
}


void
membership_store_result (void *cls, int64_t result, const char *err_msg)
{
  op = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "membership_store:\t%d\n", result);
  GNUNET_assert (GNUNET_OK == result);

  op = GNUNET_PSYCSTORE_membership_test (h, &channel_pub_key, &slave_pub_key,
                                         INT64_MAX - 10, 2,
                                         &membership_test_result, NULL);
}

/**
 * Main function of the test, run from scheduler.
 *
 * @param cls NULL
 * @param cfg configuration we use (also to connect to PSYCstore service)
 * @param peer handle to access more of the peer (not used)
 */
static void
#if DEBUG_TEST_PSYCSTORE
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
#else
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
#endif
{
  end_badly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  h = GNUNET_PSYCSTORE_connect (cfg);
  GNUNET_assert (NULL != h);

  channel_key = GNUNET_CRYPTO_eddsa_key_create ();
  slave_key = GNUNET_CRYPTO_ecdsa_key_create ();

  GNUNET_CRYPTO_eddsa_key_get_public (channel_key, &channel_pub_key);
  GNUNET_CRYPTO_ecdsa_key_get_public (slave_key, &slave_pub_key);

  op = GNUNET_PSYCSTORE_membership_store (h, &channel_pub_key, &slave_pub_key,
                                          GNUNET_YES, INT64_MAX - 5,
                                          INT64_MAX - 10, 2,
                                          &membership_store_result, NULL);
}


int
main (int argc, char *argv[])
{
  res = 1;
#if DEBUG_TEST_PSYCSTORE
  const struct GNUNET_GETOPT_CommandLineOption opts[] = {
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_PROGRAM_run (argc, argv, "test-psycstore",
                                       "test-psycstore [options]",
                                       opts, &run, NULL))
    return 1;
#else
  if (0 != GNUNET_TESTING_service_run ("test-psycstore", "psycstore",
                                       "test_psycstore.conf", &run, NULL))
    return 1;
#endif
  return res;
}

/* end of test_psycstore.c */
