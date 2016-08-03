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

struct GNUNET_SOCIAL_App *app;
const char *app_id = "test";

/**
 * Handle for task for timeout termination.
 */
struct GNUNET_SCHEDULER_Task *end_badly_task;

const struct GNUNET_CONFIGURATION_Handle *cfg;

struct GNUNET_CORE_Handle *core;
struct GNUNET_PeerIdentity this_peer;

struct GNUNET_IDENTITY_Handle *id;

const struct GNUNET_SOCIAL_Ego *host_ego;
const struct GNUNET_SOCIAL_Ego *guest_ego;

const char *host_name = "Host One";
const char *guest_name = "Guest One";

struct GNUNET_CRYPTO_EddsaPrivateKey *place_key;
struct GNUNET_CRYPTO_EcdsaPrivateKey *guest_key;

struct GNUNET_CRYPTO_EddsaPublicKey place_pub_key;
struct GNUNET_HashCode place_pub_hash;

struct GNUNET_CRYPTO_EcdsaPublicKey guest_pub_key;
struct GNUNET_CRYPTO_EcdsaPublicKey host_pub_key;

struct GNUNET_PSYC_Slicer *host_slicer;
struct GNUNET_PSYC_Slicer *guest_slicer;

struct GNUNET_SOCIAL_Host *hst;
struct GNUNET_SOCIAL_Guest *gst;

struct GNUNET_SOCIAL_Place *hst_plc;
struct GNUNET_SOCIAL_Place *gst_plc;

struct GNUNET_SOCIAL_Nym *nym_eject;

struct GuestEnterMessage
{
  struct GNUNET_PSYC_Message *msg;
  const char *method_name;
  struct GNUNET_PSYC_Environment *env;
  void *data;
  uint16_t data_size;
} guest_enter_msg;

struct TransmitClosure
{
  struct GNUNET_SOCIAL_Announcement *host_ann;
  struct GNUNET_SOCIAL_TalkRequest *guest_talk;
  struct GNUNET_PSYC_Environment *env;
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

uint8_t is_guest_nym_added = GNUNET_NO;
uint8_t is_host_reconnected = GNUNET_NO;
uint8_t is_guest_reconnected = GNUNET_NO;

enum
{
  TEST_NONE                         =  0,
  TEST_HOST_CREATE                  =  1,
  TEST_HOST_ENTER                   =  2,
  TEST_GUEST_CREATE                 =  3,
  TEST_GUEST_ENTER                  =  4,
  TEST_HOST_ANSWER_DOOR_REFUSE      =  5,
  TEST_GUEST_RECV_ENTRY_DCSN_REFUSE =  6,
  TEST_HOST_ANSWER_DOOR_ADMIT       =  7,
  TEST_GUEST_RECV_ENTRY_DCSN_ADMIT  =  8,
  TEST_HOST_ANNOUNCE   	            =  9,
  TEST_HOST_ANNOUNCE_END            = 10,
  TEST_GUEST_TALK                   = 11,
  TEST_HOST_ANNOUNCE2  	            = 12,
  TEST_HOST_ANNOUNCE2_END           = 13,
  TEST_GUEST_HISTORY_REPLAY         = 14,
  TEST_GUEST_HISTORY_REPLAY_LATEST  = 15,
  TEST_GUEST_LOOK_AT                = 16,
  TEST_GUEST_LOOK_FOR               = 17,
  TEST_GUEST_LEAVE                  = 18,
  TEST_ZONE_ADD_PLACE               = 19,
  TEST_GUEST_ENTER_BY_NAME          = 20,
  TEST_RECONNECT                    = 21,
  TEST_GUEST_LEAVE2                 = 22,
  TEST_HOST_LEAVE                   = 23,
} test;


static void
schedule_guest_leave (void *cls);


static void
host_answer_door (void *cls,
                  struct GNUNET_SOCIAL_Nym *nym,
                  const char *method_name,
                  struct GNUNET_PSYC_Environment *env,
                  const void *data,
                  size_t data_size);

static void
host_enter ();

static void
guest_init ();

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
    GNUNET_CORE_disconnecT (core);
    core = NULL;
  }

  if (NULL != id)
  {
    GNUNET_IDENTITY_disconnect (id);
    id = NULL;
  }

  if (NULL != guest_slicer)
  {
    GNUNET_PSYC_slicer_destroy (guest_slicer);
    guest_slicer = NULL;
  }

  if (NULL != host_slicer)
  {
    GNUNET_PSYC_slicer_destroy (host_slicer);
    host_slicer = NULL;
  }

  if (NULL != gst)
  {
    GNUNET_SOCIAL_guest_leave (gst, NULL, NULL, NULL);
    gst = NULL;
    gst_plc = NULL;
  }
  if (NULL != hst)
  {
    GNUNET_SOCIAL_host_leave (hst, NULL, NULL, NULL);
    hst = NULL;
    hst_plc = NULL;
  }
  GNUNET_SOCIAL_app_disconnect (app, NULL, NULL);
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Terminate the test case (failure).
 *
 * @param cls NULL
 */
static void
end_badly (void *cls)
{
  res = 1;
  cleanup ();
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Test FAILED.\n");
}


/**
 * Terminate the test case (success).
 *
 * @param cls NULL
 */
static void
end_normally (void *cls)
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
  GNUNET_SCHEDULER_add_now (&end_normally, NULL);
}


static void
transmit_resume (void *cls)
{
  struct TransmitClosure *tmit = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmission resumed.\n");
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
    GNUNET_PSYC_env_destroy (tmit->env);
    tmit->env = NULL;
  }
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
  GNUNET_memcpy (data, tmit->data[tmit->n], size);

  return ++tmit->n < tmit->data_count ? GNUNET_NO : GNUNET_YES;
}


static void
host_left ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "The host has left the place.\n");
  end ();
}


static void
schedule_host_leave (void *cls)
{
  test = TEST_HOST_LEAVE;
  GNUNET_SOCIAL_host_leave (hst, NULL, &host_left, NULL);
  hst = NULL;
  hst_plc = NULL;
}


static void
host_farewell2 (void *cls,
               const struct GNUNET_SOCIAL_Nym *nym,
               struct GNUNET_PSYC_Environment *env)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Nym left the place again.\n");
  GNUNET_SCHEDULER_add_now (&schedule_host_leave, NULL);
}


static void
host_reconnected (void *cls, int result,
		  const struct GNUNET_CRYPTO_EddsaPublicKey *home_pub_key,
		  uint64_t max_message_id)
{
  place_pub_key = *home_pub_key;
  GNUNET_CRYPTO_hash (&place_pub_key, sizeof (place_pub_key), &place_pub_hash);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Host reconnected to place %s\n",
              test, GNUNET_h2s (&place_pub_hash));

  is_host_reconnected = GNUNET_YES;
  if (GNUNET_YES == is_guest_reconnected)
  {
    GNUNET_SCHEDULER_add_now (&schedule_guest_leave, NULL);
  }
}


static void
guest_reconnected (void *cls, int result,
                   const struct GNUNET_CRYPTO_EddsaPublicKey *place_pub_key,
                   uint64_t max_message_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest reconnected to place: %d\n",
              test, result);
  GNUNET_assert (0 <= result);

  is_guest_reconnected = GNUNET_YES;
  if (GNUNET_YES == is_host_reconnected)
  {
    GNUNET_SCHEDULER_add_now (&schedule_guest_leave, NULL);
  }
}


static void
app_connected (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "App connected: %p\n", cls);
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
}


static void
app_recv_host (void *cls,
               struct GNUNET_SOCIAL_HostConnection *hconn,
               struct GNUNET_SOCIAL_Ego *ego,
               const struct GNUNET_CRYPTO_EddsaPublicKey *host_pub_key,
               enum GNUNET_SOCIAL_AppPlaceState place_state)
{
  struct GNUNET_HashCode host_pub_hash;
  GNUNET_CRYPTO_hash (host_pub_key, sizeof (*host_pub_key), &host_pub_hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got app host place notification: %s\n",
              GNUNET_h2s (&host_pub_hash));

  if (test == TEST_RECONNECT)
  {
    if (0 == memcmp (&place_pub_key, host_pub_key, sizeof (*host_pub_key)))
    {
      hst = GNUNET_SOCIAL_host_enter_reconnect (hconn, host_slicer, host_reconnected,
                                                host_answer_door, host_farewell2, NULL);
    }
  }
}


static void
app_recv_guest (void *cls,
                struct GNUNET_SOCIAL_GuestConnection *gconn,
                struct GNUNET_SOCIAL_Ego *ego,
                const struct GNUNET_CRYPTO_EddsaPublicKey *guest_pub_key,
                enum GNUNET_SOCIAL_AppPlaceState place_state)
{
  struct GNUNET_HashCode guest_pub_hash;
  GNUNET_CRYPTO_hash (guest_pub_key, sizeof (*guest_pub_key), &guest_pub_hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got app guest place notification: %s\n",
              GNUNET_h2s (&guest_pub_hash));

  if (test == TEST_RECONNECT)
  {
    if (0 == memcmp (&place_pub_key, guest_pub_key, sizeof (*guest_pub_key)))
    {
      gst = GNUNET_SOCIAL_guest_enter_reconnect (gconn, GNUNET_PSYC_SLAVE_JOIN_NONE,
                                                 guest_slicer, guest_reconnected, NULL);
    }
  }
}


static void
app_recv_ego (void *cls,
              struct GNUNET_SOCIAL_Ego *ego,
              const struct GNUNET_CRYPTO_EcdsaPublicKey *ego_pub_key,
              const char *name)
{
  char *ego_pub_str = GNUNET_CRYPTO_ecdsa_public_key_to_string (ego_pub_key);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Got app ego notification: %p %s %s\n",
              ego, name, ego_pub_str);
  GNUNET_free (ego_pub_str);

  if (NULL != strstr (name, host_name) && TEST_HOST_CREATE == test)
  {
    host_ego = ego;
    host_pub_key = *(GNUNET_SOCIAL_ego_get_pub_key (host_ego));
    GNUNET_assert (TEST_HOST_CREATE == test);
    host_enter ();
  }
  else if (NULL != strstr (name, guest_name))
  {
    guest_ego = ego;

    if (TEST_GUEST_CREATE == test)
      guest_init ();
  }
}


static void
schedule_reconnect (void *cls)
{
  test = TEST_RECONNECT;

  GNUNET_SOCIAL_host_disconnect (hst, NULL, NULL);
  GNUNET_SOCIAL_guest_disconnect (gst, NULL, NULL);
  hst = NULL;
  gst = NULL;

  GNUNET_SOCIAL_app_disconnect (app, NULL, NULL);
  app = GNUNET_SOCIAL_app_connect (cfg, app_id,
                                   app_recv_ego,
                                   app_recv_host,
                                   app_recv_guest,
                                   app_connected,
                                   NULL);
}


static void
host_recv_zone_add_place_result (void *cls, int64_t result,
                                 const void *data, uint16_t data_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Zone add place result: %" PRId64 " (%.*s).\n",
              test, result, data_size, (const char *) data);
  GNUNET_assert (GNUNET_YES == result);

  GNUNET_assert (GNUNET_YES == is_guest_nym_added);
  guest_enter_by_name ();
}


static void
zone_add_place ()
{
  test = TEST_ZONE_ADD_PLACE;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Adding place to zone.\n", test);

  GNUNET_SOCIAL_zone_add_place (app, host_ego, "home", "let.me*in!",
                                &place_pub_key, &this_peer, 1, &this_peer,
                                GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES),
                                host_recv_zone_add_place_result, app);
}


static void
host_farewell (void *cls,
               const struct GNUNET_SOCIAL_Nym *nym,
               struct GNUNET_PSYC_Environment *env)
{
  const struct GNUNET_CRYPTO_EcdsaPublicKey *
    nym_key = GNUNET_SOCIAL_nym_get_pub_key (nym);

  char *str = GNUNET_CRYPTO_ecdsa_public_key_to_string (nym_key);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Farewell: nym %s (%s) has left the place.\n",
              GNUNET_h2s (GNUNET_SOCIAL_nym_get_pub_key_hash (nym)), str);
  GNUNET_free (str);
  GNUNET_assert (1 == GNUNET_PSYC_env_get_count (env));
  if (0 != memcmp (&guest_pub_key, nym_key, sizeof (*nym_key)))
  {
    str = GNUNET_CRYPTO_ecdsa_public_key_to_string (&guest_pub_key);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Farewell: nym does not match guest: %s\n", str);
    GNUNET_free (str);
    GNUNET_assert (0);
  }
  zone_add_place ();
}


static void
guest_left (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "The guest has left the place.\n");
}


static void
guest_leave()
{
  if (test < TEST_RECONNECT)
    test = TEST_GUEST_LEAVE;
  else
    test = TEST_GUEST_LEAVE2;

  struct GNUNET_PSYC_Environment *env = GNUNET_PSYC_env_create ();
  GNUNET_PSYC_env_add (env, GNUNET_PSYC_OP_SET,
                       "_notice_place_leave", DATA2ARG ("Leaving."));
  GNUNET_SOCIAL_guest_leave (gst, env, &guest_left, NULL);
  GNUNET_PSYC_env_destroy (env);
  gst = NULL;
  gst_plc = NULL;
}


static void
schedule_guest_leave (void *cls)
{
  guest_leave ();
}


static void
guest_look_for_result (void *cls,
		       int64_t result_code,
		       const void *data,
		       uint16_t data_size)
{
  struct ResultClosure *rcls = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "guest_look_for_result: %" PRId64 "\n", result_code);
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
              name, value_size, (const char *) value);
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
              "guest_look_at_result: %" PRId64 "\n", result_code);
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
              name, value_size, (const char *) value);
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
              "Test #%u: Guest received latest history replay result "
              "(%" PRIu32 " messages, %" PRId64 " fragments):\n"
              "%.*s\n",
              test, counter, result, data_size, (const char *) data);
  //GNUNET_assert (2 == counter); /* message count */
  //GNUNET_assert (7 == result); /* fragment count */

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
              test, result, data_size, (const char *) data);
//  GNUNET_assert (2 == counter); /* message count */
//  GNUNET_assert (7 == result); /* fragment count */

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
                   const struct GNUNET_PSYC_MessageHeader *msg,
                   const struct GNUNET_PSYC_MessageMethod *meth,
                   uint64_t message_id,
                   const char *method_name)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received method for message ID %" PRIu64 ":\n"
              "%s (flags: %x)\n",
              test, message_id, method_name, ntohl (meth->flags));
  /** @todo FIXME: check message */
}


static void
guest_recv_modifier (void *cls,
                     const struct GNUNET_PSYC_MessageHeader *msg,
                     const struct GNUNET_MessageHeader *pmsg,
                     uint64_t message_id,
                     enum GNUNET_PSYC_Operator oper,
                     const char *name,
                     const void *value,
                     uint16_t value_size,
                     uint16_t full_value_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received modifier for message ID %" PRIu64 ":\n"
              "%c%s: %.*s (size: %u)\n",
              test, message_id, oper, name, value_size, (const char *) value, value_size);
  /** @todo FIXME: check modifier */
}

static void
guest_recv_mod_foo_bar (void *cls,
                        const struct GNUNET_PSYC_MessageHeader *msg,
                        const struct GNUNET_MessageHeader *pmsg,
                        uint64_t message_id,
                        enum GNUNET_PSYC_Operator oper,
                        const char *name,
                        const void *value,
                        uint16_t value_size,
                        uint16_t full_value_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received modifier matching _foo_bar for message ID %" PRIu64 ":\n"
              "%c%s: %.*s (size: %u)\n",
              test, message_id, oper, name, value_size, (const char *) value, value_size);
  struct ResultClosure *rc = cls;
  rc->n++;
  /** @todo FIXME: check modifier */
}


static void
guest_recv_data (void *cls,
                 const struct GNUNET_PSYC_MessageHeader *msg,
                 const struct GNUNET_MessageHeader *pmsg,
                 uint64_t message_id,
                 const void *data,
                 uint16_t data_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received data for message ID %" PRIu64 ":\n"
              "%.*s\n",
              test, message_id, data_size, (const char *) data);
  /** @todo FIXME: check data */
}


static void
guest_recv_eom (void *cls,
                const struct GNUNET_PSYC_MessageHeader *msg,
                const struct GNUNET_MessageHeader *pmsg,
                uint64_t message_id,
                uint8_t is_cancelled)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Guest received end of message ID %" PRIu64
              ", cancelled: %u\n",
              test, message_id, is_cancelled);

  switch (test)
  {
  case TEST_HOST_ANNOUNCE:
    test = TEST_HOST_ANNOUNCE_END;
    break;

  case TEST_HOST_ANNOUNCE_END:
    guest_talk ();
    break;

  case TEST_HOST_ANNOUNCE2:
    test = TEST_HOST_ANNOUNCE2_END;
    break;

  case TEST_HOST_ANNOUNCE2_END:
    guest_history_replay ();
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
                  const struct GNUNET_PSYC_MessageHeader *msg,
                  const struct GNUNET_PSYC_MessageMethod *meth,
                  uint64_t message_id,
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
                    const struct GNUNET_PSYC_MessageHeader *msg,
                    const struct GNUNET_MessageHeader *pmsg,
                    uint64_t message_id,
                    enum GNUNET_PSYC_Operator oper,
                    const char *name,
                    const void *value,
                    uint16_t value_size,
                    uint16_t full_value_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Host received modifier for message ID %" PRIu64 ":\n"
              "%c%s: %.*s\n",
              test, message_id, oper, name, value_size, (const char *) value);
}


static void
host_recv_data (void *cls,
                const struct GNUNET_PSYC_MessageHeader *msg,
                const struct GNUNET_MessageHeader *pmsg,
                uint64_t message_id,
                const void *data,
                uint16_t data_size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Host received data for message ID %" PRIu64 ":\n"
              "%.*s\n",
              test, message_id, data_size, (const char *) data);
}


static void
host_recv_eom (void *cls,
               const struct GNUNET_PSYC_MessageHeader *msg,
               const struct GNUNET_MessageHeader *pmsg,
               uint64_t message_id,
               uint8_t is_cancelled)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Host received end of message ID %" PRIu64
              ", cancelled: %u\n",
              test, message_id, is_cancelled);

  switch (test)
  {
  case TEST_HOST_ANNOUNCE:
    test = TEST_HOST_ANNOUNCE_END;
    break;

  case TEST_HOST_ANNOUNCE_END:
    guest_talk ();
    break;

  case TEST_HOST_ANNOUNCE2:
    test = TEST_HOST_ANNOUNCE2_END;
    break;

  case TEST_HOST_ANNOUNCE2_END:
    guest_history_replay ();
    break;

  case TEST_GUEST_TALK:
    host_announce2 ();
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
  tmit.env = GNUNET_PSYC_env_create ();
  GNUNET_PSYC_env_add (tmit.env, GNUNET_PSYC_OP_ASSIGN,
                       "_bar_foo", DATA2ARG ("one two three"));
  GNUNET_PSYC_env_add (tmit.env, GNUNET_PSYC_OP_ASSIGN,
                       "_bar_baz", DATA2ARG ("four five"));
  tmit.data[0] = "zzz xxx yyy ";
  tmit.data[1] = "zyx wvu tsr qpo.\n";
  tmit.data_delay[1] = 1;
  tmit.data[2] = "testing ten nine eight.\n";
  tmit.data_count = 3;

  tmit.guest_talk
    = GNUNET_SOCIAL_guest_talk (gst, "_converse_guest", tmit.env,
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
  tmit.env = GNUNET_PSYC_env_create ();
  GNUNET_PSYC_env_add (tmit.env, GNUNET_PSYC_OP_ASSIGN,
                       "_foo", DATA2ARG ("bar baz"));
  GNUNET_PSYC_env_add (tmit.env, GNUNET_PSYC_OP_ASSIGN,
                       "_foo_bar", DATA2ARG ("foo bar"));
  GNUNET_PSYC_env_add (tmit.env, GNUNET_PSYC_OP_ASSIGN,
                       "_foo_bar_baz", DATA2ARG ("foo bar baz"));
  tmit.data[0] = "aaa bbb ccc ";
  tmit.data[1] = "abc def ghi jkl.\n";
  tmit.data_delay[1] = 1;
  tmit.data[2] = "testing one two three ";
  tmit.data[3] = "four five.\n";
  tmit.data_count = 4;

  tmit.host_ann
    = GNUNET_SOCIAL_host_announce (hst, "_converse_host", tmit.env,
                                   &notify_data, &tmit,
                                   GNUNET_SOCIAL_ANNOUNCE_NONE);
}


static void
host_announce2 ()
{
  GNUNET_assert (2 == mod_foo_bar_rcls.n);
  GNUNET_PSYC_slicer_modifier_remove (guest_slicer, "_foo_bar",
                                      guest_recv_mod_foo_bar);

  test = TEST_HOST_ANNOUNCE2;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Host announcement 2.\n", test);

  tmit = (struct TransmitClosure) {};
  tmit.env = GNUNET_PSYC_env_create ();
  GNUNET_PSYC_env_add (tmit.env, GNUNET_PSYC_OP_ASSIGN,
                       "_foo2", DATA2ARG ("BAR BAZ"));
  GNUNET_PSYC_env_add (tmit.env, GNUNET_PSYC_OP_ASSIGN,
                       "_foo2_bar", DATA2ARG ("FOO BAR"));
  GNUNET_PSYC_env_add (tmit.env, GNUNET_PSYC_OP_ASSIGN,
                       "_foo2_bar", DATA2ARG ("FOO BAR BAZ"));
  tmit.data[0] = "AAA BBB CCC ";
  tmit.data[1] = "ABC DEF GHI JKL.\n";
  tmit.data[2] = "TESTING ONE TWO THREE.\n";
  tmit.data_count = 3;

  tmit.host_ann
    = GNUNET_SOCIAL_host_announce (hst, "_converse_host_two", tmit.env,
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
    struct GNUNET_PSYC_Environment *env = GNUNET_PSYC_env_create ();
    const char *method_name = NULL;
    const void *data = NULL;
    uint16_t data_size = 0;
    struct GNUNET_PSYC_MessageHeader *
      pmsg = GNUNET_PSYC_message_header_create_from_psyc (entry_msg);
    GNUNET_PSYC_message_parse (pmsg, &method_name, env, &data, &data_size);
    GNUNET_free (pmsg);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s\n%.*s\n",
                method_name, data_size, (const char *) data);
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
    GNUNET_SCHEDULER_add_now (&schedule_reconnect, NULL);
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
                  struct GNUNET_PSYC_Environment *env,
                  const void *data,
                  size_t data_size)
{
  join_req_count++;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Host received entry request from guest (try %u).\n",
              (uint8_t) test, join_req_count);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s\n%.*s\n",
              method_name, (int) data_size, (const char *) data);

  switch (test)
  {
  case TEST_HOST_ANSWER_DOOR_REFUSE:
    test = TEST_GUEST_RECV_ENTRY_DCSN_REFUSE;
    join_resp = GNUNET_PSYC_message_create ("_notice_place_refuse", env,
                                            DATA2ARG ("Go away!"));
    GNUNET_SOCIAL_host_entry_decision (hst, nym, GNUNET_NO, join_resp);
    break;

  case TEST_HOST_ANSWER_DOOR_ADMIT:
    test = TEST_GUEST_RECV_ENTRY_DCSN_ADMIT;
    // fall through

  case TEST_GUEST_ENTER_BY_NAME:
    join_resp = GNUNET_PSYC_message_create ("_notice_place_admit", env,
                                            DATA2ARG ("Welcome, nym!"));
    GNUNET_SOCIAL_host_entry_decision (hst, nym, GNUNET_YES, join_resp);
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "invalid test: %d\n", test);
    GNUNET_assert (0);
  }
}


static void
guest_recv_local_enter (void *cls, int result,
                        const struct GNUNET_CRYPTO_EddsaPublicKey *place_pub_key,
                        uint64_t max_message_id)
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
  emsg->env = GNUNET_PSYC_env_create ();
  GNUNET_PSYC_env_add (emsg->env, GNUNET_PSYC_OP_ASSIGN,
                       "_abc", "abc def", 7);
  GNUNET_PSYC_env_add (emsg->env, GNUNET_PSYC_OP_ASSIGN,
                       "_abc_def", "abc def ghi", 11);
  emsg->data = "let me in";
  emsg->data_size = strlen (emsg->data) + 1;
  emsg->msg = GNUNET_PSYC_message_create (emsg->method_name, emsg->env,
                                          emsg->data, emsg->data_size);

  gst = GNUNET_SOCIAL_guest_enter (app, guest_ego, &place_pub_key,
                                   GNUNET_PSYC_SLAVE_JOIN_NONE,
                                   &this_peer, 0, NULL, emsg->msg, guest_slicer,
                                   guest_recv_local_enter,
                                   guest_recv_entry_decision, NULL);
  gst_plc = GNUNET_SOCIAL_guest_get_place (gst);

  GNUNET_SOCIAL_place_msg_proc_set (gst_plc, "_converse",
                                    GNUNET_SOCIAL_MSG_PROC_SAVE);
}


static void
guest_enter_by_name ()
{
  test = TEST_GUEST_ENTER_BY_NAME;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Test #%u: Entering to place by name as guest.\n", test);

  struct GuestEnterMessage *emsg = &guest_enter_msg;

  emsg->method_name = "_request_enter";
  emsg->env = GNUNET_PSYC_env_create ();
  GNUNET_PSYC_env_add (emsg->env, GNUNET_PSYC_OP_ASSIGN,
                       "_abc", "abc def", 7);
  GNUNET_PSYC_env_add (emsg->env, GNUNET_PSYC_OP_ASSIGN,
                       "_abc_def", "abc def ghi", 11);
  emsg->data = "let me in";
  emsg->data_size = strlen (emsg->data) + 1;
  emsg->msg = GNUNET_PSYC_message_create (emsg->method_name, emsg->env,
                                          emsg->data, emsg->data_size);

  gst = GNUNET_SOCIAL_guest_enter_by_name (app, guest_ego,
                                           "home.host.gnu", "let.me*in!",
                                           emsg->msg, guest_slicer,
                                           guest_recv_local_enter,
                                           guest_recv_entry_decision, NULL);
  gst_plc = GNUNET_SOCIAL_guest_get_place (gst);
}


static void
app_recv_zone_add_nym_result (void *cls, int64_t result,
                              const void *data, uint16_t data_size)
{
  GNUNET_assert (GNUNET_YES == result);
  is_guest_nym_added = GNUNET_YES;
}


static void
guest_init ()
{
  guest_pub_key = *(GNUNET_SOCIAL_ego_get_pub_key (guest_ego));

  guest_slicer = GNUNET_PSYC_slicer_create ();
  GNUNET_PSYC_slicer_method_add (guest_slicer, "", NULL,
                                 guest_recv_method, guest_recv_modifier,
                                 guest_recv_data, guest_recv_eom, NULL);
  GNUNET_PSYC_slicer_modifier_add (guest_slicer, "_foo_bar",
                                   guest_recv_mod_foo_bar, &mod_foo_bar_rcls);
  test = TEST_HOST_ANSWER_DOOR_ADMIT;

  GNUNET_SOCIAL_zone_add_nym (app, guest_ego, "host", &host_pub_key,
                              GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES),
                              app_recv_zone_add_nym_result, NULL);
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
  if (NULL != guest_ego)
    guest_init ();
}


static void
host_entered (void *cls, int result,
              const struct GNUNET_CRYPTO_EddsaPublicKey *home_pub_key,
              uint64_t max_message_id)
{
  place_pub_key = *home_pub_key;
  GNUNET_CRYPTO_hash (&place_pub_key, sizeof (place_pub_key), &place_pub_hash);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Host entered to place %s\n", GNUNET_h2s (&place_pub_hash));

  test = TEST_GUEST_CREATE;
  GNUNET_IDENTITY_create (id, guest_name, &id_guest_created, NULL);
}


static void
host_enter ()
{
  host_slicer = GNUNET_PSYC_slicer_create ();
  GNUNET_PSYC_slicer_method_add (host_slicer, "", NULL,
                                 host_recv_method, host_recv_modifier,
                                 host_recv_data, host_recv_eom, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Entering to place as host.\n");
  test = TEST_HOST_ENTER;
  hst = GNUNET_SOCIAL_host_enter (app, host_ego,
                                  GNUNET_PSYC_CHANNEL_PRIVATE,
                                  host_slicer, host_entered,
                                  host_answer_door, host_farewell, NULL);
  hst_plc = GNUNET_SOCIAL_host_get_place (hst);

  GNUNET_SOCIAL_place_msg_proc_set (hst_plc, "_converse",
                                    GNUNET_SOCIAL_MSG_PROC_RELAY);
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

  app = GNUNET_SOCIAL_app_connect (cfg, app_id,
                                   app_recv_ego,
                                   app_recv_host,
                                   app_recv_guest,
                                   app_connected,
                                   NULL);
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

  test = TEST_HOST_CREATE;
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
  end_badly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
						 &end_badly, NULL);

  core = GNUNET_CORE_connecT (cfg, NULL, &core_connected, NULL, NULL, NULL);
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
