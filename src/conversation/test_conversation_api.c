/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2014 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file conversation/test_conversation_api.c
 * @brief testcase for conversation_api.c
 *
 * This test performs the operations of a call to a phone
 * where the phone user picks up and then the call is
 * terminated by the party that initiated the call.
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

static int ok = 1;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_IDENTITY_Handle *id;

static struct GNUNET_IDENTITY_Operation *op;

static struct GNUNET_CONVERSATION_Phone *phone;

static struct GNUNET_NAMESTORE_Handle *ns;

static struct GNUNET_CONVERSATION_Call *call;

static struct GNUNET_NAMESTORE_QueueEntry *qe;

static struct GNUNET_CONVERSATION_Caller *active_caller;

static char *gns_name;

static char *gns_caller_id;

static GNUNET_MICROPHONE_RecordedDataCallback phone_rdc;

static void *phone_rdc_cls;

static GNUNET_MICROPHONE_RecordedDataCallback call_rdc;

static void *call_rdc_cls;

static struct GNUNET_SCHEDULER_Task * phone_task;

static struct GNUNET_SCHEDULER_Task * call_task;


static void
phone_send (void *cls,
            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static unsigned int i;
  char buf[32];

  GNUNET_assert (NULL != phone_rdc);
  GNUNET_snprintf (buf, sizeof (buf), "phone-%u", i++);
  phone_rdc (phone_rdc_cls, strlen (buf) + 1, buf);
  phone_task = GNUNET_SCHEDULER_add_delayed (FREQ,
                                             &phone_send, NULL);
}


static void
call_send (void *cls,
            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static unsigned int i;
  char buf[32];

  GNUNET_assert (NULL != call_rdc);
  GNUNET_snprintf (buf, sizeof (buf), "call-%u", i++);
  call_rdc (call_rdc_cls, strlen (buf) + 1, buf);
  call_task = GNUNET_SCHEDULER_add_delayed (FREQ,
                                            &call_send, NULL);
}


static int
enable_speaker (void *cls)
{
  const char *origin = cls;

  fprintf (stderr,
           "Speaker %s enabled\n",
           origin);
  return GNUNET_OK;
}


static void
disable_speaker (void *cls)
{
  const char *origin = cls;

  fprintf (stderr,
           "Speaker %s disabled\n",
           origin);
}


static void
play (void *cls,
      size_t data_size,
      const void *data)
{
  const char *origin = cls;
  static unsigned int phone_i = 1;
  static unsigned int call_i;
  char buf[32];

  if (0 == strcmp (origin, "phone"))
    GNUNET_snprintf (buf, sizeof (buf), "call-%u", call_i++);
  else
    GNUNET_snprintf (buf, sizeof (buf), "phone-%u", phone_i++);
  if ( (data_size != strlen (buf) + 1) ||
       (0 != strncmp (buf, data, data_size)) )
  {
    fprintf (stderr,
             "Expected %s, received %.*s\n",
             buf,
             (int) data_size,
             (const char *) data);
  }
  else
  {
    fprintf (stderr, ".");
  }
  if ( (20 < call_i) &&
       (20 < phone_i) &&
       (NULL != call) )
  {
    /* time to hang up ... */
    GNUNET_CONVERSATION_call_stop (call);
    call = NULL;
  }
}


static void
destroy_speaker (void *cls)
{
  const char *origin = cls;

  fprintf (stderr, "Speaker %s destroyed\n", origin);
}


static struct GNUNET_SPEAKER_Handle call_speaker = {
  &enable_speaker,
  &play,
  &disable_speaker,
  &destroy_speaker,
  "caller"
};


static struct GNUNET_SPEAKER_Handle phone_speaker = {
  &enable_speaker,
  &play,
  &disable_speaker,
  &destroy_speaker,
  "phone"
};


static int
enable_mic (void *cls,
            GNUNET_MICROPHONE_RecordedDataCallback rdc,
            void *rdc_cls)
{
  const char *origin = cls;

  fprintf (stderr,
           "Mic %s enabled\n",
           origin);
  if (0 == strcmp (origin, "phone"))
  {
    phone_rdc = rdc;
    phone_rdc_cls = rdc_cls;
    phone_task = GNUNET_SCHEDULER_add_now (&phone_send, NULL);
  }
  else
  {
    call_rdc = rdc;
    call_rdc_cls = rdc_cls;
    call_task = GNUNET_SCHEDULER_add_now (&call_send, NULL);
  }
  return GNUNET_OK;
}


static void
disable_mic (void *cls)
{
  const char *origin = cls;

  fprintf (stderr,
           "Mic %s disabled\n",
           origin);
  if (0 == strcmp (origin, "phone"))
  {
    phone_rdc = NULL;
    phone_rdc_cls = NULL;
    GNUNET_SCHEDULER_cancel (phone_task);
    phone_task = NULL;
  }
  else
  {
    call_rdc = NULL;
    call_rdc_cls = NULL;
    GNUNET_SCHEDULER_cancel (call_task);
    call_task = NULL;
  }
}


static void
destroy_mic (void *cls)
{
  const char *origin = cls;

  fprintf (stderr,
           "Mic %s destroyed\n",
           origin);
}


static struct GNUNET_MICROPHONE_Handle call_mic = {
  &enable_mic,
  &disable_mic,
  &destroy_mic,
  "caller"
};


static struct GNUNET_MICROPHONE_Handle phone_mic = {
  &enable_mic,
  &disable_mic,
  &destroy_mic,
  "phone"
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
  if (NULL != call)
  {
    GNUNET_CONVERSATION_call_stop (call);
    call = NULL;
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
    fprintf (stderr, "Unexpected caller code: %d\n", code);
    break;
  }
}


static void
phone_event_handler (void *cls,
                     enum GNUNET_CONVERSATION_PhoneEventCode code,
                     struct GNUNET_CONVERSATION_Caller *caller,
                     const struct GNUNET_CRYPTO_EcdsaPublicKey *caller_id)
{
  static enum GNUNET_CONVERSATION_PhoneEventCode expect
    = GNUNET_CONVERSATION_EC_PHONE_RING;

  GNUNET_break (code == expect);
  switch (code)
  {
  case GNUNET_CONVERSATION_EC_PHONE_RING:
    active_caller = caller;
    GNUNET_CONVERSATION_caller_pick_up (caller,
                                        &caller_event_handler,
                                        NULL,
                                        &phone_speaker,
                                        &phone_mic);
    expect = GNUNET_CONVERSATION_EC_PHONE_HUNG_UP;
    break;
  case GNUNET_CONVERSATION_EC_PHONE_HUNG_UP:
    GNUNET_break (caller == active_caller);
    active_caller = NULL;
    ok = 0;
    GNUNET_SCHEDULER_shutdown ();
    break;
  default:
    fprintf (stderr, "Unexpected phone code: %d\n", code);
    break;
  }
}


static void
call_event_handler (void *cls,
                    enum GNUNET_CONVERSATION_CallEventCode code)
{
  static enum GNUNET_CONVERSATION_CallEventCode expect
    = GNUNET_CONVERSATION_EC_CALL_RINGING;

  GNUNET_break (code == expect);
  switch (code)
  {
  case GNUNET_CONVERSATION_EC_CALL_RINGING:
    expect = GNUNET_CONVERSATION_EC_CALL_PICKED_UP;
    break;
  case GNUNET_CONVERSATION_EC_CALL_PICKED_UP:
    expect = -1;
    break;
  case GNUNET_CONVERSATION_EC_CALL_GNS_FAIL:
  case GNUNET_CONVERSATION_EC_CALL_HUNG_UP:
    call = NULL;
    fprintf (stderr, "Unexpected call code: %d\n", code);
    break;
  case GNUNET_CONVERSATION_EC_CALL_SUSPENDED:
  case GNUNET_CONVERSATION_EC_CALL_RESUMED:
  case GNUNET_CONVERSATION_EC_CALL_ERROR:
    fprintf (stderr, "Unexpected call code: %d\n", code);
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
    call = GNUNET_CONVERSATION_call_start (cfg,
                                           ego,
                                           ego,
                                           gns_name,
                                           &call_speaker,
                                           &call_mic,
                                           &call_event_handler,
                                           NULL);
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
  if (0 != GNUNET_TESTING_peer_run ("test_conversation_api",
				    "test_conversation.conf",
				    &run, NULL))
    return 1;
  return ok;
}

/* end of test_conversation_api.c */
