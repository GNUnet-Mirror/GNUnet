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
 * @file social/test_social.c
 * @brief Tests for the Social API.
 * @author Gabor X Toth
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_env_lib.h"
#include "gnunet_psyc_util_lib.h"
#include "gnunet_social_service.h"
#include "gnunet_core_service.h"
#include "gnunet_identity_service.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

#define DATA2ARG(data) data, sizeof (data)

/**
 * Return value from 'main'.
 */
int res;

/**
 * Handle for task for timeout termination.
 */
struct GNUNET_SCHEDULER_Task * end_badly_task;

const struct GNUNET_CONFIGURATION_Handle *cfg;

struct GNUNET_CORE_Handle *core;
struct GNUNET_PeerIdentity this_peer;

struct GNUNET_IDENTITY_Handle *id;

const struct GNUNET_IDENTITY_Ego *host_ego;
const struct GNUNET_IDENTITY_Ego *guest_ego;

const char *host_name = "Host One";
const char *guest_name = "Guest One";

struct GNUNET_CRYPTO_EddsaPrivateKey *place_key;
struct GNUNET_CRYPTO_EcdsaPrivateKey *guest_key;

struct GNUNET_CRYPTO_EddsaPublicKey place_pub_key;
struct GNUNET_CRYPTO_EcdsaPublicKey guest_pub_key;
struct GNUNET_CRYPTO_EcdsaPublicKey host_pub_key;

struct GNUNET_SOCIAL_Slicer *host_slicer;
struct GNUNET_SOCIAL_Slicer *guest_slicer;

struct GNUNET_SOCIAL_Host *hst;
struct GNUNET_SOCIAL_Guest *gst;

struct GNUNET_SOCIAL_Place *hst_plc;
struct GNUNET_SOCIAL_Place *gst_plc;

struct GNUNET_SOCIAL_Nym *nym_eject;

struct GuestEnterMessage
{
  struct GNUNET_PSYC_Message *msg;
  const char *method_name;
  struct GNUNET_ENV_Environment *env;
  void *data;
  uint16_t data_size;
} guest_enter_msg;

struct TransmitClosure
{
  struct GNUNET_SOCIAL_Announcement *host_ann;
  struct GNUNET_SOCIAL_TalkRequest *guest_talk;
  struct GNUNET_ENV_Environment *env;
  char *data[16];
  uint8_t data_delay[16];
  uint8_t data_count;
  uint8_t paused;
  uint8_t n;
} tmit;

struct ResultClosure {
  uint32_t n;
} mod_foo_bar_rcls;

uint8_t join_req_count;
struct GNUNET_PSYC_Message *join_resp;

uint32_t counter;

uint8_t guest_pkey_added = GNUNET_NO;

enum
{
  TEST_NONE = 0,
  TEST_HOST_ANSWER_DOOR_REFUSE      =  1,
  TEST_GUEST_RECV_ENTRY_DCSN_REFUSE =  2,
  TEST_HOST_ANSWER_DOOR_ADMIT       =  3,
  TEST_GUEST_RECV_ENTRY_DCSN_ADMIT  =  4,
  TEST_HOST_ANNOUNCE   	            =  5,
  TEST_HOST_ANNOUNCE_END            =  6,
  TEST_HOST_ANNOUNCE2  	            =  7,
  TEST_HOST_ANNOUNCE2_END           =  8,
  TEST_GUEST_TALK                   =  9,
  TEST_GUEST_HISTORY_REPLAY         = 10,
  TEST_GUEST_HISTORY_REPLAY_LATEST  = 11,
  TEST_GUEST_LOOK_AT                = 12,
  TEST_GUEST_LOOK_FOR               = 13,
  TEST_GUEST_LEAVE                  = 14,
  TEST_HOST_ADVERTISE               = 15,
  TEST_GUEST_ENTER_BY_NAME          = 16,
  TEST_HOST_LEAVE                   = 17,
} test;


static void
guest_enter ();

static void
guest_enter_by_name ();

static void
guest_talk ();

static void
host_announce2 ();


/**
 * Clean up all resources used.
 */
static void
cleanup ()
{
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }

  if (NULL != id)
  {
    GNUNET_IDENTITY_disconnect (id);
    id = NULL;
  }

  if (NULL != gst)
  {
    GNUNET_SOCIAL_guest_leave (gst, GNUNET_NO, NULL, NULL, NULL);
    gst = NULL;
    gst_plc = NULL;
  }
  if (NULL != hst)
  {
    GNUNET_SOCIAL_host_leave (hst, GNUNET_NO, NULL, NULL);
    hst = NULL;
    hst_plc = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Terminate the test case (failure).
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
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
static void
end_normally (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  res = 0;
  cleanup ();
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Test PASSED.\n");
}


/**
 * Finish the test case (successfully).
 */
static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ending tests.\n");

  if (end_badly_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (end_badly_task);
    end_badly_task = NULL;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
				&end_normally, NULL);
}


static void
transmit_resume (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmission resumed.\n");
  struct TransmitClosure *tmit = cls;
  if (NULL != tmit->host_ann)
    GNUNET_SOCIAL_host_announce_resume (tmit->host_ann);
  else
    GNUNET_SOCIAL_guest_talk_resume (tmit->guest_talk);
}


static int
notify_data (void *cls, uint16_t *data_size, void *data)
{
  struct TransmitClosure *tmit = cls;
  if (NULL != tmit->env)
  {
    GNUNET_ENV_environment_destroy (tmit->env);
    tmit->env = NULL;
  }
  if (0 == tmit->data_count)
  {
    *data_size = 0;
    return GNUNET_YES;
  }

  uint16_t size = strlen (tmit->data[tmit->n]) + 1;
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


static void
host_left ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "The host has left the place.\n");
  GNUNET_SOCIAL_slicer_destroy (host_slicer);
  host_slicer = NULL;
  hst = NULL;
  hst_plc = NULL;

  end ();
}


static void
schedule_host_leave (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  test = TEST_HOST_LEAVE;
  GNUNET_SOCIAL_host_leave (hst, GNUNET_NO, &host_left, NULL);
}


static void
id_guest_ego_cb2 (void *cls, const struct GNUNET_IDENTITY_Ego *ego)
{
  GNUNET_assert (NULL != ego);
  guest_ego = ego;

  guest_enter_by_name ();
}


static void
host_recv_advertise_result (void *cls, int32_t success, const char *emsg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Advertise result: %d (%s).\n",
              test, success, emsg);
  GNUNET_assert (GNUNET_YES == success);

  GNUNET_assert (GNUNET_YES == guest_pkey_added);
  GNUNET_IDENTITY_ego_lookup (cfg, guest_name, id_guest_ego_cb2, NULL);
}


static void
host_advertise ()
{
  test = TEST_HOST_ADVERTISE;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Advertising place.\n", test);

  GNUNET_SOCIAL_host_advertise (hst, "home", 1, &this_peer,
                                GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES),
                                "let.me*in!", host_recv_advertise_result, hst);
}


static void
host_farewell (void *cls,
               const struct GNUNET_SOCIAL_Nym *nym,
               struct GNUNET_ENV_Environment *env)
{
  const struct GNUNET_CRYPTO_EcdsaPublicKey *
    nym_key = GNUNET_SOCIAL_nym_get_key (nym);

  char *str = GNUNET_CRYPTO_ecdsa_public_key_to_string (nym_key);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Farewell: nym %s (%s) has left the place.\n",
              GNUNET_h2s (GNUNET_SOCIAL_nym_get_key_hash (nym)), str);
  GNUNET_free (str);
  GNUNET_assert (1 == GNUNET_ENV_environment_get_count (env));
  if (0 != memcmp (&guest_pub_key, nym_key, sizeof (*nym_key)))
  {
    str = GNUNET_CRYPTO_ecdsa_public_key_to_string (&guest_pub_key);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Farewell: nym does not match guest: %s\n", str);
    GNUNET_free (str);
    GNUNET_assert (0);
  }
  host_advertise ();
}


static void
guest_left (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "The guest has left the place.\n");
  GNUNET_SOCIAL_slicer_destroy (guest_slicer);
  guest_slicer = NULL;
  gst = NULL;
  gst_plc = NULL;
}


static void
guest_leave()
{
  test = TEST_GUEST_LEAVE;

  struct GNUNET_ENV_Environment *env = GNUNET_ENV_environment_create ();
  GNUNET_ENV_environment_add (env, GNUNET_ENV_OP_SET,
                              "_message", DATA2ARG ("Leaving."));
  GNUNET_SOCIAL_guest_leave (gst, GNUNET_NO, env, &guest_left, NULL);
  GNUNET_ENV_environment_destroy (env);

  /* @todo test keep_active */
}


static void
schedule_guest_leave (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  guest_leave ();
}


static void
guest_look_for_result (void *cls, int64_t result_code,
                      const void *data, uint16_t data_size)
{
  struct ResultClosure *rcls = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "guest_look_for_result: %d\n", result_code);
  GNUNET_assert (GNUNET_OK == result_code);
  GNUNET_assert (3 == rcls->n);
  GNUNET_free (rcls);
  GNUNET_SCHEDULER_add_now (&schedule_guest_leave, NULL);
}


static void
guest_look_for_var (void *cls,
                   const struct GNUNET_MessageHeader *mod,
                   const char *name,
                   const void *value,
                   uint32_t value_size,
                   uint32_t full_value_size)
{
  struct ResultClosure *rcls = cls;
  rcls->n++;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "guest_look_for_var: %s\n%.*s\n",
              name, value_size, value);
}


static void
guest_look_for ()
{
  test = TEST_GUEST_LOOK_FOR;
  struct ResultClosure *rcls = GNUNET_malloc (sizeof (*rcls));
  GNUNET_SOCIAL_place_look_for (gst_plc, "_foo", guest_look_for_var, guest_look_for_result, rcls);
}


static void
guest_look_at_result (void *cls, int64_t result_code,
                      const void *data, uint16_t data_size)
{
  struct ResultClosure *rcls = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "guest_look_at_result: %d\n", result_code);
  GNUNET_assert (GNUNET_OK == result_code);
  GNUNET_assert (1 == rcls->n);
  GNUNET_free (rcls);
  guest_look_for ();
}


static void
guest_look_at_var (void *cls,
                   const struct GNUNET_MessageHeader *mod,
                   const char *name,
                   const void *value,
                   uint32_t value_size,
                   uint32_t full_value_size)
{
  struct ResultClosure *rcls = cls;
  rcls->n++;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "guest_look_at_var: %s\n%.*s\n",
              name, value_size, value);
}


static void
guest_look_at ()
{
  test = TEST_GUEST_LOOK_AT;
  struct ResultClosure *rcls = GNUNET_malloc (sizeof (*rcls));
  GNUNET_SOCIAL_place_look_at (gst_plc, "_foo_bar", guest_look_at_var, guest_look_at_result, rcls);
}


static void
guest_recv_history_replay_latest_result (void *cls, int64_t result,
                                         const void *data, uint16_t data_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received latest history replay result: %" PRId64 "\n"
              "%.*s\n",
              test, result, data_size, data);
  GNUNET_assert (2 == counter); /* message count */
  GNUNET_assert (7 == result); /* fragment count */

  guest_look_at ();
}


static void
guest_history_replay_latest ()
{
  test = TEST_GUEST_HISTORY_REPLAY_LATEST;
  counter = 0;
  GNUNET_SOCIAL_place_history_replay_latest (gst_plc, 3, "",
                                             GNUNET_PSYC_HISTORY_REPLAY_LOCAL,
                                             guest_slicer,
                                             &guest_recv_history_replay_latest_result,
                                             NULL);
}


static void
guest_recv_history_replay_result (void *cls, int64_t result,
                                  const void *data, uint16_t data_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received history replay result: %" PRId64 "\n"
              "%.*s\n",
              test, result, data_size, data);
  GNUNET_assert (2 == counter); /* message count */
  GNUNET_assert (7 == result); /* fragment count */

  guest_history_replay_latest ();
}


static void
guest_history_replay ()
{
  test = TEST_GUEST_HISTORY_REPLAY;
  counter = 0;
  GNUNET_SOCIAL_place_history_replay (gst_plc, 1, 3, "",
                                      GNUNET_PSYC_HISTORY_REPLAY_LOCAL,
                                      guest_slicer,
                                      &guest_recv_history_replay_result,
                                      NULL);
}


static void
guest_recv_method (void *cls,
                  const struct GNUNET_PSYC_MessageMethod *meth,
                  uint64_t message_id,
                  uint32_t flags,
                  const struct GNUNET_SOCIAL_Nym *nym,
                  const char *method_name)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received method for message ID %" PRIu64 ":\n"
              "%s (flags: %x)\n",
              test, message_id, method_name, flags);
  /** @todo FIXME: check message */
}


static void
guest_recv_modifier (void *cls,
                     const struct GNUNET_MessageHeader *msg,
                     uint64_t message_id,
                     enum GNUNET_ENV_Operator oper,
                     const char *name,
                     const void *value,
                     uint16_t value_size,
                     uint16_t full_value_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received modifier for message ID %" PRIu64 ":\n"
              "%c%s: %.*s (size: %u)\n",
              test, message_id, oper, name, value_size, value, value_size);
  /** @todo FIXME: check modifier */
}

static void
guest_recv_mod_foo_bar (void *cls,
                        const struct GNUNET_MessageHeader *msg,
                        uint64_t message_id,
                        enum GNUNET_ENV_Operator oper,
                        const char *name,
                        const void *value,
                        uint16_t value_size,
                        uint16_t full_value_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received modifier matching _foo_bar for message ID %" PRIu64 ":\n"
              "%c%s: %.*s (size: %u)\n",
              test, message_id, oper, name, value_size, value, value_size);
  struct ResultClosure *rc = cls;
  rc->n++;
  /** @todo FIXME: check modifier */
}


static void
guest_recv_data (void *cls,
                const struct GNUNET_MessageHeader *msg,
                uint64_t message_id,
                uint64_t data_offset,
                const void *data,
                uint16_t data_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received data for message ID %" PRIu64 ":\n"
              "%.*s\n",
              test, message_id, data_size, data);
  /** @todo FIXME: check data */
}


static void
guest_recv_eom (void *cls,
               const struct GNUNET_MessageHeader *msg,
               uint64_t message_id,
               uint8_t cancelled)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received end of message ID %" PRIu64
              ", cancelled: %u\n",
              test, message_id, cancelled);

  switch (test)
  {
  case TEST_HOST_ANNOUNCE:
    test = TEST_HOST_ANNOUNCE_END;
    break;

  case TEST_HOST_ANNOUNCE_END:
    host_announce2 ();
    break;

  case TEST_HOST_ANNOUNCE2:
    test = TEST_HOST_ANNOUNCE2_END;
    break;

  case TEST_HOST_ANNOUNCE2_END:
    guest_talk ();
    break;

  case TEST_GUEST_HISTORY_REPLAY:
  case TEST_GUEST_HISTORY_REPLAY_LATEST:
    counter++;
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "invalid test: %d\n", test);
    GNUNET_assert (0);
  }
}


static void
host_recv_method (void *cls,
                  const struct GNUNET_PSYC_MessageMethod *meth,
                  uint64_t message_id,
                  uint32_t flags,
                  const struct GNUNET_SOCIAL_Nym *nym,
                  const char *method_name)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Host received method for message ID %" PRIu64 ":\n"
              "%s\n",
              test, message_id, method_name);
  /** @todo FIXME: check message */
}


static void
host_recv_modifier (void *cls,
                    const struct GNUNET_MessageHeader *msg,
                    uint64_t message_id,
                    enum GNUNET_ENV_Operator oper,
                    const char *name,
                    const void *value,
                    uint16_t value_size,
                    uint16_t full_value_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Host received modifier for message ID %" PRIu64 ":\n"
              "%c%s: %.*s\n",
              test, message_id, oper, name, value_size, value);
}


static void
host_recv_data (void *cls,
                const struct GNUNET_MessageHeader *msg,
                uint64_t message_id,
                uint64_t data_offset,
                const void *data,
                uint16_t data_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Host received data for message ID %" PRIu64 ":\n"
              "%.*s\n",
              test, message_id, data_size, data);
}


static void
host_recv_eom (void *cls,
               const struct GNUNET_MessageHeader *msg,
               uint64_t message_id,
               uint8_t cancelled)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Host received end of message ID %" PRIu64
              ", cancelled: %u\n",
              test, message_id, cancelled);

  switch (test)
  {
  case TEST_HOST_ANNOUNCE:
    test = TEST_HOST_ANNOUNCE_END;
    break;

  case TEST_HOST_ANNOUNCE_END:
    host_announce2 ();
    break;

  case TEST_HOST_ANNOUNCE2:
    test = TEST_HOST_ANNOUNCE2_END;
    break;

  case TEST_HOST_ANNOUNCE2_END:
    guest_talk ();
    break;

  case TEST_GUEST_TALK:
    guest_history_replay ();
    break;

  default:
    if (TEST_GUEST_LEAVE <= test)
      break;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "invalid test: %d\n", test);
    GNUNET_assert (0);
  }
}


static void
guest_talk ()
{
  test = TEST_GUEST_TALK;

  tmit = (struct TransmitClosure) {};
  tmit.env = GNUNET_ENV_environment_create ();
  GNUNET_ENV_environment_add (tmit.env, GNUNET_ENV_OP_ASSIGN,
                              "_bar_foo", DATA2ARG ("one two three"));
  GNUNET_ENV_environment_add (tmit.env, GNUNET_ENV_OP_ASSIGN,
                              "_bar_baz", DATA2ARG ("four five"));
  tmit.data[0] = "zzz xxx yyy";
  tmit.data[1] = "zyx wvu tsr qpo";
  tmit.data_delay[1] = 1;
  tmit.data[2] = "testing ten nine eight";
  tmit.data_count = 3;

  tmit.guest_talk
    = GNUNET_SOCIAL_guest_talk (gst, "_message_guest", tmit.env,
                                &notify_data, &tmit,
                                GNUNET_SOCIAL_TALK_NONE);
}


static void
host_announce ()
{
  test = TEST_HOST_ANNOUNCE;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Host announcement.\n", test);

  tmit = (struct TransmitClosure) {};
  tmit.env = GNUNET_ENV_environment_create ();
  GNUNET_ENV_environment_add (tmit.env, GNUNET_ENV_OP_ASSIGN,
                              "_foo", DATA2ARG ("bar baz"));
  GNUNET_ENV_environment_add (tmit.env, GNUNET_ENV_OP_ASSIGN,
                              "_foo_bar", DATA2ARG ("foo bar"));
  GNUNET_ENV_environment_add (tmit.env, GNUNET_ENV_OP_ASSIGN,
                              "_foo_bar_baz", DATA2ARG ("foo bar baz"));
  tmit.data[0] = "aaa bbb ccc";
  tmit.data[1] = "abc def ghi jkl";
  tmit.data_delay[1] = 1;
  tmit.data[2] = "testing one two three";
  tmit.data[3] = "four five";
  tmit.data_count = 4;

  tmit.host_ann
    = GNUNET_SOCIAL_host_announce (hst, "_message_host", tmit.env,
                                   &notify_data, &tmit,
                                   GNUNET_SOCIAL_ANNOUNCE_NONE);
}


static void
host_announce2 ()
{
  GNUNET_assert (2 == mod_foo_bar_rcls.n);
  GNUNET_SOCIAL_slicer_modifier_remove (guest_slicer, "_foo_bar",
                                        guest_recv_mod_foo_bar);

  test = TEST_HOST_ANNOUNCE2;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Host announcement 2.\n", test);

  tmit = (struct TransmitClosure) {};
  tmit.env = GNUNET_ENV_environment_create ();
  GNUNET_ENV_environment_add (tmit.env, GNUNET_ENV_OP_ASSIGN,
                              "_foo2", DATA2ARG ("BAR BAZ"));
  GNUNET_ENV_environment_add (tmit.env, GNUNET_ENV_OP_ASSIGN,
                              "_foo2_bar", DATA2ARG ("FOO BAR"));
  GNUNET_ENV_environment_add (tmit.env, GNUNET_ENV_OP_ASSIGN,
                              "_foo2_bar", DATA2ARG ("FOO BAR BAZ"));
  tmit.data[0] = "AAA BBB CCC";
  tmit.data[1] = "ABC DEF GHI JKL";
  tmit.data[2] = "TESTING ONE TWO THREE";
  tmit.data_count = 3;

  tmit.host_ann
    = GNUNET_SOCIAL_host_announce (hst, "_message_host_two", tmit.env,
                                   &notify_data, &tmit,
                                   GNUNET_SOCIAL_ANNOUNCE_NONE);
}


static void
guest_recv_entry_decision (void *cls,
                           int is_admitted,
                           const struct GNUNET_PSYC_Message *entry_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received entry decision (try %u): %d.\n",
              test, join_req_count, is_admitted);

  if (NULL != entry_msg)
  {
    struct GNUNET_ENV_Environment *env = GNUNET_ENV_environment_create ();
    const char *method_name = NULL;
    const void *data = NULL;
    uint16_t data_size = 0;
    struct GNUNET_PSYC_MessageHeader *
      pmsg = GNUNET_PSYC_message_header_create_from_psyc (entry_msg);
    GNUNET_PSYC_message_parse (pmsg, &method_name, env, &data, &data_size);
    GNUNET_free (pmsg);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s\n%.*s\n",
                method_name, data_size, data);
    /** @todo FIXME: check response message */
  }

  switch (test)
  {
  case TEST_GUEST_RECV_ENTRY_DCSN_REFUSE:
    GNUNET_assert (GNUNET_NO == is_admitted);
    guest_enter ();
    break;

  case TEST_GUEST_RECV_ENTRY_DCSN_ADMIT:
    GNUNET_assert (GNUNET_YES == is_admitted);
    host_announce ();
    break;

  case TEST_GUEST_ENTER_BY_NAME:
    GNUNET_SCHEDULER_add_now (schedule_host_leave, NULL);
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "invalid test: %d\n", test);
    GNUNET_assert (0);
  }
}


static void
host_answer_door (void *cls,
                  struct GNUNET_SOCIAL_Nym *nym,
                  const char *method_name,
                  struct GNUNET_ENV_Environment *env,
                  size_t data_size,
                  const void *data)
{
  join_req_count++;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Host received entry request from guest (try %u).\n",
              test, join_req_count);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s\n%.*s\n",
              method_name, data_size, data);

  switch (test)
  {
  case TEST_HOST_ANSWER_DOOR_REFUSE:
    test = TEST_GUEST_RECV_ENTRY_DCSN_REFUSE;
    join_resp = GNUNET_PSYC_message_create ("_refuse_nym", env,
                                            DATA2ARG ("Go away!"));
    GNUNET_SOCIAL_host_entry_decision (hst, nym, GNUNET_NO, join_resp);
    break;

  case TEST_HOST_ANSWER_DOOR_ADMIT:
    test = TEST_GUEST_RECV_ENTRY_DCSN_ADMIT;
  case TEST_GUEST_ENTER_BY_NAME:
    join_resp = GNUNET_PSYC_message_create ("_admit_nym", env,
                                            DATA2ARG ("Welcome, nym!"));
    GNUNET_SOCIAL_host_entry_decision (hst, nym, GNUNET_YES, join_resp);
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "invalid test: %d\n", test);
    GNUNET_assert (0);
  }
}


static void
guest_recv_local_enter (void *cls, int result, uint64_t max_message_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest entered to local place: %d\n",
              test, result);
  GNUNET_assert (0 <= result);
}


static void
guest_enter ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Entering to place as guest.\n", test);

  struct GuestEnterMessage *emsg = &guest_enter_msg;

  emsg->method_name = "_request_enter";
  emsg->env = GNUNET_ENV_environment_create ();
  GNUNET_ENV_environment_add (emsg->env, GNUNET_ENV_OP_ASSIGN,
                              "_abc", "abc def", 7);
  GNUNET_ENV_environment_add (emsg->env, GNUNET_ENV_OP_ASSIGN,
                              "_abc_def", "abc def ghi", 11);
  emsg->data = "let me in";
  emsg->data_size = strlen (emsg->data) + 1;
  emsg->msg = GNUNET_PSYC_message_create (emsg->method_name, emsg->env,
                                          emsg->data, emsg->data_size);

  gst = GNUNET_SOCIAL_guest_enter (cfg, guest_ego, &place_pub_key,
                                   &this_peer, 0, NULL, emsg->msg, guest_slicer,
                                   guest_recv_local_enter,
                                   guest_recv_entry_decision, NULL);
  gst_plc = GNUNET_SOCIAL_guest_get_place (gst);
}


static void
guest_enter_by_name ()
{
  test = TEST_GUEST_ENTER_BY_NAME;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Entering to place by name as guest.\n", test);

  struct GuestEnterMessage *emsg = &guest_enter_msg;

  emsg->method_name = "_request_enter";
  emsg->env = GNUNET_ENV_environment_create ();
  GNUNET_ENV_environment_add (emsg->env, GNUNET_ENV_OP_ASSIGN,
                              "_abc", "abc def", 7);
  GNUNET_ENV_environment_add (emsg->env, GNUNET_ENV_OP_ASSIGN,
                              "_abc_def", "abc def ghi", 11);
  emsg->data = "let me in";
  emsg->data_size = strlen (emsg->data) + 1;
  emsg->msg = GNUNET_PSYC_message_create (emsg->method_name, emsg->env,
                                          emsg->data, emsg->data_size);

  gst = GNUNET_SOCIAL_guest_enter_by_name (cfg, guest_ego,
                                           "home.host.gnu", "let.me*in!",
                                           emsg->msg, guest_slicer,
                                           guest_recv_local_enter,
                                           guest_recv_entry_decision, NULL);
  gst_plc = GNUNET_SOCIAL_guest_get_place (gst);
}


static void
guest_recv_add_pkey_result (void *cls, int32_t success, const char *emsg)
{
  GNUNET_assert (GNUNET_YES == success);
  guest_pkey_added = GNUNET_YES;
}


static void
id_guest_ego_cb (void *cls, const struct GNUNET_IDENTITY_Ego *ego)
{
  GNUNET_assert (NULL != ego);
  guest_ego = ego;
  GNUNET_IDENTITY_ego_get_public_key (ego, &guest_pub_key);

  guest_slicer = GNUNET_SOCIAL_slicer_create ();
  GNUNET_SOCIAL_slicer_method_add (guest_slicer, "",
                                   guest_recv_method, guest_recv_modifier,
                                   guest_recv_data, guest_recv_eom, NULL);
  GNUNET_SOCIAL_slicer_modifier_add (guest_slicer, "_foo_bar",
                                     guest_recv_mod_foo_bar, &mod_foo_bar_rcls);
  test = TEST_HOST_ANSWER_DOOR_ADMIT;

  GNUNET_SOCIAL_zone_add_pkey (cfg, guest_ego, "host", &host_pub_key,
                               GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES),
                               guest_recv_add_pkey_result, NULL);

  guest_enter ();
}


static void
id_guest_created (void *cls, const char *emsg)
{
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not create guest identity: %s\n", emsg);
#if ! DEBUG_TEST_SOCIAL
    GNUNET_assert (0);
#endif
  }

 GNUNET_IDENTITY_ego_lookup (cfg, guest_name, &id_guest_ego_cb, NULL);
}


static void
host_entered (void *cls, int result, uint64_t max_message_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Host entered to place.\n");

  GNUNET_IDENTITY_create (id, guest_name, &id_guest_created, NULL);
}


static void
id_host_ego_cb (void *cls, const struct GNUNET_IDENTITY_Ego *ego)
{
  GNUNET_assert (NULL != ego);
  host_ego = ego;
  GNUNET_IDENTITY_ego_get_public_key (ego, &host_pub_key);

  host_slicer = GNUNET_SOCIAL_slicer_create ();
  GNUNET_SOCIAL_slicer_method_add (host_slicer, "",
                                   &host_recv_method, &host_recv_modifier,
                                   &host_recv_data, &host_recv_eom, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Entering to place as host.\n");
  hst = GNUNET_SOCIAL_host_enter (cfg, host_ego, place_key,
                                  GNUNET_PSYC_CHANNEL_PRIVATE, host_slicer,
                                  host_entered, host_answer_door,
                                  host_farewell, NULL);
  hst_plc = GNUNET_SOCIAL_host_get_place (hst);
}


static void
id_host_created (void *cls, const char *emsg)
{
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not create host identity: %s\n", emsg);
#if ! DEBUG_TEST_SOCIAL
    GNUNET_assert (0);
#endif
  }

  GNUNET_IDENTITY_ego_lookup (cfg, host_name, &id_host_ego_cb, NULL);
}


static void
identity_ego_cb (void *cls, struct GNUNET_IDENTITY_Ego *ego,
                 void **ctx, const char *name)
{

}


static void
core_connected (void *cls, const struct GNUNET_PeerIdentity *my_identity)
{
  this_peer = *my_identity;

  id = GNUNET_IDENTITY_connect (cfg, &identity_ego_cb, NULL);
  GNUNET_IDENTITY_create (id, host_name, &id_host_created, NULL);
}


/**
 * Main function of the test, run from scheduler.
 *
 * @param cls NULL
 * @param cfg configuration we use (also to connect to Social service)
 * @param peer handle to access more of the peer (not used)
 */
static void
#if DEBUG_TEST_SOCIAL
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

  place_key = GNUNET_CRYPTO_eddsa_key_create ();
  GNUNET_CRYPTO_eddsa_key_get_public (place_key, &place_pub_key);

  core = GNUNET_CORE_connect (cfg, NULL, &core_connected, NULL, NULL,
                              NULL, GNUNET_NO, NULL, GNUNET_NO, NULL);
}


int
main (int argc, char *argv[])
{
  res = 1;
#if DEBUG_TEST_SOCIAL
  const struct GNUNET_GETOPT_CommandLineOption opts[] = {
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_PROGRAM_run (argc, argv, "test-social",
                                       "test-social [options]",
                                       opts, &run, NULL))
    return 1;
#else
  if (0 != GNUNET_TESTING_peer_run ("test-social", "test_social.conf", &run, NULL))
    return 1;
#endif
  return res;
}

/* end of test_social.c */
