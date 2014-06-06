/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/
/**
 * @file conversation/test_conversation_api_twocalls.c
 * @brief testcase for conversation_api.c
 *
 * This test performs the operations of TWO calls made to a phone
 * where the phone user picks up one, suspends it, picks up the
 * second one; eventually, the initiator hangs up, the callee
 * resumes the first call, and then the initiator hangs up the
 * second call.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_conversation_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_namestore_service.h"

#define FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 250)

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 25)

#define LOG(kind,...)                           \
  GNUNET_log (kind, __VA_ARGS__)

#define LOG_DEBUG(...)                          \
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_IDENTITY_Handle *id;

static struct GNUNET_IDENTITY_Operation *op;

static struct GNUNET_CONVERSATION_Phone *phone;

static struct GNUNET_NAMESTORE_Handle *ns;

static struct GNUNET_CONVERSATION_Call *call1;

static struct GNUNET_CONVERSATION_Call *call2;

static struct GNUNET_NAMESTORE_QueueEntry *qe;

static struct GNUNET_CONVERSATION_Caller *active_caller1;

static struct GNUNET_CONVERSATION_Caller *active_caller2;

static char *gns_name;

static char *gns_caller_id;

static GNUNET_MICROPHONE_RecordedDataCallback phone_rdc;

static void *phone_rdc_cls;

static GNUNET_SCHEDULER_TaskIdentifier phone_task;

/**
 * Variable for recognizing caller1
 */
static const char *caller1 = "caller1";

/**
 * Variable for recognizing caller2
 */
static const char *caller2 = "caller2";

/**
 * Variable for recognizing callee
 */
static const char *phone0 = "phone";


#define CALLER1 &caller1
#define CALLER2 &caller2
#define PHONE0 &phone0

#define CLS_STR(caller) (*((char **)caller))


/**
 * Did caller1 call finish successfully
 */
static int call1_finished;

/**
 * Did caller2 call finish successfully
 */
static int call2_finished;

struct MicContext
{
  GNUNET_MICROPHONE_RecordedDataCallback rdc;

  void *rdc_cls;

  GNUNET_SCHEDULER_TaskIdentifier call_task;

};

static struct MicContext call1_mic_ctx;
static struct MicContext call2_mic_ctx;
//static struct MicContext phone_mic_ctx;


static void
phone_send (void *cls,
            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char buf[32];

  GNUNET_assert (NULL != phone_rdc);
  GNUNET_snprintf (buf, sizeof (buf), "phone");
  phone_rdc (phone_rdc_cls, strlen (buf) + 1, buf);
  phone_task = GNUNET_SCHEDULER_add_delayed (FREQ,
                                             &phone_send, NULL);
}


static void
call_send (void *cls,
           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MicContext *mc = cls;
  char buf[32];

  GNUNET_assert (NULL != mc->rdc);
  GNUNET_snprintf (buf, sizeof (buf), "call");
  mc->rdc (mc->rdc_cls, strlen (buf) + 1, buf);
  mc->call_task = GNUNET_SCHEDULER_add_delayed (FREQ,
                                                &call_send, mc);
}


static int
enable_speaker (void *cls)
{
  const char *origin = CLS_STR (cls);

  LOG_DEBUG ("Speaker %s enabled\n",
             origin);
  return GNUNET_OK;
}


static void
disable_speaker (void *cls)
{
  const char *origin = CLS_STR (cls);

  LOG_DEBUG ("Speaker %s disabled\n",
             origin);
}


static void
play (void *cls,
      size_t data_size,
      const void *data)
{
  static unsigned int phone_i;
  static unsigned int call_i;

  if (0 == strncmp ("call", data, data_size))
    call_i++;
  else if (0 == strncmp ("phone", data, data_size))
    phone_i++;
  else
  {
    LOG_DEBUG ("Received unexpected data %.*s\n",
               (int) data_size,
               (const char *) data);
  }

  if ( (20 < call_i) &&
       (20 < phone_i) &&
       (CALLER2 == cls) )
  {
    /* time to hang up ... */
    GNUNET_CONVERSATION_call_stop (call2);
    call2 = NULL;
    /* reset counters */
    call_i = 0;
    phone_i = 0;
    call2_finished = GNUNET_YES;
  }
  if ( (20 < call_i) &&
       (20 < phone_i) &&
       (CALLER1 == cls) )
  {
    /* time to hang up ... */
    GNUNET_CONVERSATION_call_stop (call1);
    call1 = NULL;
    call_i = 0;
    phone_i = 0;
    call1_finished = GNUNET_YES;
  }
}


static void
destroy_speaker (void *cls)
{
  const char *origin = CLS_STR (cls);

  LOG_DEBUG ("Speaker %s destroyed\n", origin);
}


static struct GNUNET_SPEAKER_Handle call1_speaker = {
  &enable_speaker,
  &play,
  &disable_speaker,
  &destroy_speaker,
  CALLER1
};


static struct GNUNET_SPEAKER_Handle call2_speaker = {
  &enable_speaker,
  &play,
  &disable_speaker,
  &destroy_speaker,
  CALLER2
};


static struct GNUNET_SPEAKER_Handle phone_speaker = {
  &enable_speaker,
  &play,
  &disable_speaker,
  &destroy_speaker,
  PHONE0
};


static int
enable_mic (void *cls,
            GNUNET_MICROPHONE_RecordedDataCallback rdc,
            void *rdc_cls)
{
  const char *origin = CLS_STR (cls);
  struct MicContext *mc;

  LOG_DEBUG ("Mic %s enabled\n",
             origin);
  if (PHONE0 == cls)
  {
    phone_rdc = rdc;
    phone_rdc_cls = rdc_cls;
    GNUNET_break (GNUNET_SCHEDULER_NO_TASK == phone_task);
    phone_task = GNUNET_SCHEDULER_add_now (&phone_send, NULL);
    return GNUNET_OK;
  }
  mc = (CALLER1 == cls) ? &call1_mic_ctx : &call2_mic_ctx;
  mc->rdc = rdc;
  mc->rdc_cls = rdc_cls;
  GNUNET_break (GNUNET_SCHEDULER_NO_TASK == mc->call_task);
  mc->call_task = GNUNET_SCHEDULER_add_now (&call_send, mc);
  return GNUNET_OK;
}


static void
disable_mic (void *cls)
{
  const char *origin = CLS_STR (cls);
  struct MicContext *mc;

  LOG_DEBUG ("Mic %s disabled\n",
             origin);
  if (PHONE0 == cls)
  {
    phone_rdc = NULL;
    phone_rdc_cls = NULL;
    GNUNET_SCHEDULER_cancel (phone_task);
    phone_task = GNUNET_SCHEDULER_NO_TASK;
    return;
  }
  mc = (CALLER1 == cls) ? &call1_mic_ctx : &call2_mic_ctx;
  mc->rdc = NULL;
  mc->rdc_cls = NULL;
  GNUNET_SCHEDULER_cancel (mc->call_task);
  mc->call_task = GNUNET_SCHEDULER_NO_TASK;
}


static void
destroy_mic (void *cls)
{
  const char *origin = CLS_STR (cls);

  LOG_DEBUG ("Mic %s destroyed\n",
             origin);
}


static struct GNUNET_MICROPHONE_Handle call1_mic = {
  &enable_mic,
  &disable_mic,
  &destroy_mic,
  CALLER1
};


static struct GNUNET_MICROPHONE_Handle call2_mic = {
  &enable_mic,
  &disable_mic,
  &destroy_mic,
  CALLER2
};


static struct GNUNET_MICROPHONE_Handle phone_mic = {
  &enable_mic,
  &disable_mic,
  &destroy_mic,
  PHONE0
};


/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
end_test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_SCHEDULER_shutdown ();
  if (NULL != op)
  {
    GNUNET_IDENTITY_cancel (op);
    op = NULL;
  }
  if (NULL != call1)
  {
    GNUNET_CONVERSATION_call_stop (call1);
    call1 = NULL;
  }
  if (NULL != call2)
  {
    GNUNET_CONVERSATION_call_stop (call2);
    call2 = NULL;
  }
  if (NULL != phone)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from PHONE service.\n");
    GNUNET_CONVERSATION_phone_destroy (phone);
    phone = NULL;
  }
  if (NULL != id)
  {
    GNUNET_IDENTITY_disconnect (id);
    id = NULL;
  }
  if (NULL != qe)
  {
    GNUNET_NAMESTORE_cancel (qe);
    qe = NULL;
  }
  if (NULL != ns)
  {
    GNUNET_NAMESTORE_disconnect (ns);
    ns = NULL;
  }
}


static void
caller_event_handler (void *cls,
                      enum GNUNET_CONVERSATION_CallerEventCode code)
{
  switch (code)
  {
  case GNUNET_CONVERSATION_EC_CALLER_SUSPEND:
  case GNUNET_CONVERSATION_EC_CALLER_RESUME:
    LOG (GNUNET_ERROR_TYPE_WARNING, "Unexpected caller code: %d\n", code);
    break;
  }
}


static void
phone_event_handler (void *cls,
                     enum GNUNET_CONVERSATION_PhoneEventCode code,
                     struct GNUNET_CONVERSATION_Caller *caller,
                     const struct GNUNET_CRYPTO_EcdsaPublicKey *caller_id)
{
  const char *cid;

  switch (code)
  {
  case GNUNET_CONVERSATION_EC_PHONE_RING:
    if (NULL == active_caller1)
    {
      active_caller1 = caller;
      cid = "caller1";
      GNUNET_CONVERSATION_caller_pick_up (caller,
                                          &caller_event_handler,
                                          (void *) cid,
                                          &phone_speaker,
                                          &phone_mic);
    }
    else
    {
      GNUNET_CONVERSATION_caller_suspend (active_caller1);
      active_caller2 = caller;
      cid = "caller2";
      GNUNET_CONVERSATION_caller_pick_up (caller,
                                          &caller_event_handler,
                                          (void *) cid,
                                          &phone_speaker,
                                          &phone_mic);
    }
    break;
  case GNUNET_CONVERSATION_EC_PHONE_HUNG_UP:
    if (caller == active_caller2)
    {
      active_caller2 = NULL;
      GNUNET_CONVERSATION_caller_resume (active_caller1,
                                         &phone_speaker,
                                         &phone_mic);
    }
    else if (caller == active_caller1)
    {
      active_caller1 = NULL;
      GNUNET_break (NULL == active_caller2);
      GNUNET_SCHEDULER_shutdown ();
    }
    break;
  default:
    LOG (GNUNET_ERROR_TYPE_WARNING, "Unexpected phone code: %d\n", code);
    break;
  }
}


static void
call_event_handler (void *cls,
                    enum GNUNET_CONVERSATION_CallEventCode code)
{
  const char *cid = cls;

  switch (code)
  {
  case GNUNET_CONVERSATION_EC_CALL_RINGING:
    break;
  case GNUNET_CONVERSATION_EC_CALL_PICKED_UP:
    LOG_DEBUG ("Call %s picked\n", cid);
    break;
  case GNUNET_CONVERSATION_EC_CALL_GNS_FAIL:
    LOG_DEBUG ("Call %s GNS lookup failed \n", cid);
  case GNUNET_CONVERSATION_EC_CALL_HUNG_UP:
    LOG_DEBUG ("Call %s hungup\n", cid);
    if (0 == strcmp (cid, "call1"))
      call1 = NULL;
    else
      call2 = NULL;
    break;
  case GNUNET_CONVERSATION_EC_CALL_SUSPENDED:
    LOG_DEBUG ("Call %s suspended\n", cid);
    break;
  case GNUNET_CONVERSATION_EC_CALL_RESUMED:
    LOG_DEBUG ("Call %s resumed\n", cid);
    break;
  case GNUNET_CONVERSATION_EC_CALL_ERROR:
    GNUNET_break (0);
    break;
  }
}


static void
caller_ego_create_cont (void *cls,
                        const char *emsg)
{
  op = NULL;
  GNUNET_assert (NULL == emsg);
}


static void
namestore_put_cont (void *cls,
                    int32_t success,
                    const char *emsg)
{
  qe = NULL;
  GNUNET_assert (GNUNET_YES == success);
  GNUNET_assert (NULL == emsg);
  GNUNET_assert (NULL == op);
  op = GNUNET_IDENTITY_create (id, "caller-ego", &caller_ego_create_cont, NULL);
}


static void
identity_cb (void *cls,
             struct GNUNET_IDENTITY_Ego *ego,
             void **ctx,
             const char *name)
{
  struct GNUNET_GNSRECORD_Data rd;
  struct GNUNET_CRYPTO_EcdsaPublicKey pub;

  if (NULL == name)
    return;
  if (NULL == ego)
    return;
  if (0 == strcmp (name, "phone-ego"))
  {
    GNUNET_IDENTITY_ego_get_public_key (ego, &pub);
    GNUNET_asprintf (&gns_name,
                     "phone.%s",
                     GNUNET_GNSRECORD_pkey_to_zkey (&pub));
    phone = GNUNET_CONVERSATION_phone_create (cfg,
                                              ego,
                                              &phone_event_handler,
                                              NULL);
    GNUNET_assert (NULL != phone);
    memset (&rd, 0, sizeof (rd));
    GNUNET_CONVERSATION_phone_get_record (phone,
                                          &rd);
    GNUNET_assert (rd.record_type == GNUNET_GNSRECORD_TYPE_PHONE);
    rd.expiration_time = UINT64_MAX;
    qe = GNUNET_NAMESTORE_records_store (ns,
                                         GNUNET_IDENTITY_ego_get_private_key (ego),
                                         "phone" /* GNS label */,
                                         1,
                                         &rd,
                                         &namestore_put_cont,
                                         NULL);
    return;
  }
  if (0 == strcmp (name, "caller-ego"))
  {
    GNUNET_IDENTITY_ego_get_public_key (ego, &pub);
    GNUNET_asprintf (&gns_caller_id,
                     "%s",
                     GNUNET_GNSRECORD_pkey_to_zkey (&pub));
    call1 = GNUNET_CONVERSATION_call_start (cfg,
                                            ego,
                                            ego,
                                            gns_name,
                                            &call1_speaker,
                                            &call1_mic,
                                            &call_event_handler,
                                            (void *) "call1");
    call2 = GNUNET_CONVERSATION_call_start (cfg,
                                            ego,
                                            ego,
                                            gns_name,
                                            &call2_speaker,
                                            &call2_mic,
                                            &call_event_handler,
                                            (void *) "call2");
    return;
  }
}


static void
phone_ego_create_cont (void *cls,
                       const char *emsg)
{
  op = NULL;
  GNUNET_assert (NULL == emsg);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_TESTING_Peer *peer)
{
  cfg = c;
  GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_test,
                                NULL);
  id = GNUNET_IDENTITY_connect (cfg,
                                &identity_cb,
                                NULL);
  op = GNUNET_IDENTITY_create (id, "phone-ego", &phone_ego_create_cont, NULL);
  ns = GNUNET_NAMESTORE_connect (cfg);
}


int
main (int argc, char *argv[])
{

  if (0 != GNUNET_TESTING_peer_run ("test_conversation_api_twocalls",
				    "test_conversation.conf",
				    &run, NULL))
    return 1;
  if (call1_finished && call2_finished)
    return 0;
  return 1;
}

/* end of test_conversation_api_twocalls.c */
