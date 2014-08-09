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
GNUNET_SCHEDULER_TaskIdentifier end_badly_task;

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

struct GNUNET_SOCIAL_Slicer *host_slicer;
struct GNUNET_SOCIAL_Slicer *guest_slicer;

struct GNUNET_SOCIAL_Host *hst;
struct GNUNET_SOCIAL_Guest *gst;

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

uint8_t join_req_count;
struct GNUNET_PSYC_Message *join_resp;

enum
{
  TEST_NONE = 0,
  TEST_HOST_ANSWER_DOOR_REFUSE      = 1,
  TEST_GUEST_RECV_ENTRY_DCSN_REFUSE = 2,
  TEST_HOST_ANSWER_DOOR_ADMIT       = 3,
  TEST_GUEST_RECV_ENTRY_DCSN_ADMIT  = 4,
  TEST_HOST_ANNOUNCE     = 5,
  TEST_HOST_ANNOUNCE_END = 6,
  TEST_GUEST_TALK        = 7,
  TEST_GUEST_LEAVE       = 8,
  TEST_HOST_LEAVE        = 9,
} test;


void
guest_enter ();


void
guest_talk ();


void
host_announce2 ();


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

  if (NULL != id)
  {
    GNUNET_IDENTITY_disconnect (id);
    id = NULL;
  }

  if (NULL != gst)
  {
    GNUNET_SOCIAL_guest_leave (gst, GNUNET_NO, NULL, NULL);
    gst = NULL;
  }
  if (NULL != hst)
  {
    GNUNET_SOCIAL_host_leave (hst, GNUNET_NO, NULL, NULL);
    hst = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
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


int
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


void host_left ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "The host has left the place.\n");
  GNUNET_SOCIAL_slicer_destroy (host_slicer);
  host_slicer = NULL;
  hst = NULL;

  end ();
}


void
schedule_host_leave (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  test = TEST_HOST_LEAVE;
  GNUNET_SOCIAL_host_leave (hst, GNUNET_NO, &host_left, NULL);
}


void
host_farewell (void *cls,
               struct GNUNET_SOCIAL_Nym *nym,
               struct GNUNET_ENV_Environment *env,
               size_t variable_count,
               struct GNUNET_ENV_Modifier *variables)
{
  // FIXME: this function is not called yet

  struct GNUNET_CRYPTO_EcdsaPublicKey *
    nym_key = GNUNET_SOCIAL_nym_get_key (nym);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Nym %s has left the place.\n",
              GNUNET_CRYPTO_ecdsa_public_key_to_string (nym_key));
  GNUNET_assert (0 == memcmp (&guest_pub_key, nym_key, sizeof (*nym_key)));

  GNUNET_SCHEDULER_add_now (&schedule_host_leave, NULL);
}


void
guest_left (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "The guest has left the place.\n");
  GNUNET_SOCIAL_slicer_destroy (guest_slicer);
  guest_slicer = NULL;
  gst = NULL;

  GNUNET_SCHEDULER_add_now (&schedule_host_leave, NULL);
}


void
guest_leave()
{
  test = TEST_GUEST_LEAVE;
  /* FIXME test keep_active */
  GNUNET_SOCIAL_guest_leave (gst, GNUNET_NO, &guest_left, NULL);
}



void
guest_recv_method (void *cls,
                  const struct GNUNET_PSYC_MessageMethod *meth,
                  uint64_t message_id,
                  uint32_t flags,
                  const struct GNUNET_SOCIAL_Nym *nym,
                  const char *method_name)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received method for message ID %" PRIu64 ":\n"
              "%s\n",
              test, message_id, method_name);
  /* FIXME: check message */
}


void
guest_recv_modifier (void *cls,
                    const struct GNUNET_PSYC_MessageModifier *mod,
                    uint64_t message_id,
                    enum GNUNET_ENV_Operator oper,
                    const char *name,
                    const void *value,
                    uint16_t value_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received modifier for message ID %" PRIu64 ":\n"
              "%c%s: %.*s\n",
              test, message_id, oper, name, value_size, value);
}


void
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
}


void
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
    guest_talk ();
    break;

  default:
    GNUNET_assert (0);
  }
}


void
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
  /* FIXME: check message */
}


void
host_recv_modifier (void *cls,
                    const struct GNUNET_PSYC_MessageModifier *mod,
                    uint64_t message_id,
                    enum GNUNET_ENV_Operator oper,
                    const char *name,
                    const void *value,
                    uint16_t value_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Host received modifier for message ID %" PRIu64 ":\n"
              "%c%s: %.*s\n",
              test, message_id, oper, name, value_size, value);
}


void
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


void
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
    //host_announce2 ();
    break;

  case TEST_HOST_ANNOUNCE_END:
    guest_talk ();
    break;

  case TEST_GUEST_TALK:
    guest_leave ();
    break;

  default:
    GNUNET_assert (0);
  }
}


void
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
  tmit.data[2] = "testing ten nine eight";
  tmit.data_count = 3;

  tmit.guest_talk
    = GNUNET_SOCIAL_guest_talk (gst, "_message_guest", tmit.env,
                                &notify_data, &tmit,
                                GNUNET_SOCIAL_TALK_NONE);
}

void
host_announce ()
{
  test = TEST_HOST_ANNOUNCE;

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
  tmit.data[2] = "testing one two three";
  tmit.data[3] = "four five";
  tmit.data_count = 4;

  tmit.host_ann
    = GNUNET_SOCIAL_host_announce (hst, "_message_host", tmit.env,
                                   &notify_data, &tmit,
                                   GNUNET_SOCIAL_ANNOUNCE_NONE);
}

void
host_announce2 ()
{
  test = TEST_HOST_ANNOUNCE;

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


void
guest_recv_entry_decision (void *cls,
                           int is_admitted,
                           const struct GNUNET_PSYC_Message *entry_resp)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Guest received entry decision (try %u): %d.\n",
              join_req_count, is_admitted);

  if (NULL != entry_resp)
  {
    struct GNUNET_ENV_Environment *env = GNUNET_ENV_environment_create ();
    const char *method_name = NULL;
    const void *data = NULL;
    uint16_t data_size = 0;
    GNUNET_PSYC_message_parse (entry_resp, &method_name, env, &data, &data_size);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s\n%.*s\n",
                method_name, data_size, data);
    /* FIXME: check response message */
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

  default:
    GNUNET_assert (0);
  }
}


void
host_answer_door (void *cls,
                  struct GNUNET_SOCIAL_Nym *nym,
                  const char *method_name,
                  struct GNUNET_ENV_Environment *env,
                  size_t data_size,
                  const void *data)
{
  join_req_count++;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Host received entry request from guest (try %u).\n",
                join_req_count);
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
    join_resp = GNUNET_PSYC_message_create ("_admit_nym", env,
                                            DATA2ARG ("Welcome, nym!"));
    GNUNET_SOCIAL_host_entry_decision (hst, nym, GNUNET_YES, join_resp);
    break;

  default:
    GNUNET_assert (0);
  }
}


void
guest_recv_local_enter (void *cls, int result, uint64_t max_message_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Guest entered to local place.\n");

}


void
guest_enter ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Entering to place as guest.\n");

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
                                   &this_peer, 0, NULL, emsg->msg,
                                   guest_slicer, &guest_recv_local_enter,
                                   &guest_recv_entry_decision, NULL);
}


void id_guest_ego_cb (void *cls, const struct GNUNET_IDENTITY_Ego *ego)
{
  GNUNET_assert (NULL != ego);
  guest_ego = ego;

  guest_slicer = GNUNET_SOCIAL_slicer_create ();
  GNUNET_SOCIAL_slicer_add (guest_slicer, "",
                            &guest_recv_method, &guest_recv_modifier,
                            &guest_recv_data, &guest_recv_eom, NULL);
  test = TEST_HOST_ANSWER_DOOR_ADMIT;
  //host_announce ();
  guest_enter ();
}


void id_guest_created (void *cls, const char *emsg)
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


void host_entered (void *cls, int result, uint64_t max_message_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Host entered to place.\n");

  GNUNET_IDENTITY_create (id, guest_name, &id_guest_created, NULL);
}


void id_host_ego_cb (void *cls, const struct GNUNET_IDENTITY_Ego *ego)
{
  GNUNET_assert (NULL != ego);
  host_ego = ego;

  host_slicer = GNUNET_SOCIAL_slicer_create ();
  GNUNET_SOCIAL_slicer_add (host_slicer, "",
                            &host_recv_method, &host_recv_modifier,
                            &host_recv_data, &host_recv_eom, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Entering to place as host.\n");
  hst = GNUNET_SOCIAL_host_enter (cfg, host_ego, place_key,
                                  GNUNET_PSYC_CHANNEL_PRIVATE, host_slicer,
                                  &host_entered, &host_answer_door,
                                  &host_farewell, NULL);
}


void id_host_created (void *cls, const char *emsg)
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


void identity_ego_cb (void *cls, struct GNUNET_IDENTITY_Ego *ego,
                      void **ctx, const char *name)
{

}


void
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
void
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
  guest_key = GNUNET_CRYPTO_ecdsa_key_create ();

  GNUNET_CRYPTO_eddsa_key_get_public (place_key, &place_pub_key);
  GNUNET_CRYPTO_ecdsa_key_get_public (guest_key, &guest_pub_key);

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
