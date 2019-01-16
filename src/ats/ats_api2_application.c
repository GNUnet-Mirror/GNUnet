/*
     This file is part of GNUnet.
     Copyright (C) 2010-2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/**
 * @file ats/ats_api2_application.c
 * @brief enable clients to ask ATS about establishing connections to peers
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_application_service.h"
#include "ats2.h"


#define LOG(kind,...) GNUNET_log_from(kind, "ats-application-api", __VA_ARGS__)


/**
 * Handle for ATS address suggestion requests.
 */
struct GNUNET_ATS_ApplicationSuggestHandle
{
  /**
   * ID of the peer for which address suggestion was requested.
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Connecitivity handle this suggestion handle belongs to.
   */
  struct GNUNET_ATS_ApplicationHandle *ch;

  /**
   * What preference is being expressed?
   */
  enum GNUNET_MQ_PreferenceKind pk;

  /**
   * How much bandwidth does the client expect?
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw;
};


/**
 * Handle to the ATS subsystem for application management.
 */
struct GNUNET_ATS_ApplicationHandle
{

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Map with the identities of all the peers for which we would
   * like to have address suggestions.  The key is the PID, the
   * value is currently the `struct GNUNET_ATS_ApplicationSuggestHandle`
   */
  struct GNUNET_CONTAINER_MultiPeerMap *sug_requests;

  /**
   * Message queue for sending requests to the ATS service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Task to trigger reconnect.
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Reconnect backoff delay.
   */
  struct GNUNET_TIME_Relative backoff;
};


/**
 * Re-establish the connection to the ATS service.
 *
 * @param ch handle to use to re-connect.
 */
static void
reconnect (struct GNUNET_ATS_ApplicationHandle *ch);


/**
 * Re-establish the connection to the ATS service.
 *
 * @param cls handle to use to re-connect.
 */
static void
reconnect_task (void *cls)
{
  struct GNUNET_ATS_ApplicationHandle *ch = cls;

  ch->task = NULL;
  reconnect (ch);
}


/**
 * Disconnect from ATS and then reconnect.
 *
 * @param ch our handle
 */
static void
force_reconnect (struct GNUNET_ATS_ApplicationHandle *ch)
{
  if (NULL != ch->mq)
  {
    GNUNET_MQ_destroy (ch->mq);
    ch->mq = NULL;
  }
  ch->backoff = GNUNET_TIME_STD_BACKOFF (ch->backoff);
  ch->task = GNUNET_SCHEDULER_add_delayed (ch->backoff,
                                           &reconnect_task,
                                           ch);
}


/**
 * We encountered an error handling the MQ to the
 * ATS service.  Reconnect.
 *
 * @param cls the `struct GNUNET_ATS_ApplicationHandle`
 * @param error details about the error
 */
static void
error_handler (void *cls,
               enum GNUNET_MQ_Error error)
{
  struct GNUNET_ATS_ApplicationHandle *ch = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "ATS connection died (code %d), reconnecting\n",
       (int) error);
  force_reconnect (ch);
}


/**
 * Transmit request for an address suggestion.
 *
 * @param cls the `struct GNUNET_ATS_ApplicationHandle`
 * @param peer peer to ask for an address suggestion for
 * @param value the `struct GNUNET_ATS_SuggestHandle`
 * @return #GNUNET_OK (continue to iterate), #GNUNET_SYSERR on
 *         failure (message queue no longer exists)
 */
static int
transmit_suggestion (void *cls,
                     const struct GNUNET_PeerIdentity *peer,
                     void *value)
{
  struct GNUNET_ATS_ApplicationHandle *ch = cls;
  struct GNUNET_ATS_ApplicationSuggestHandle *sh = value;
  struct GNUNET_MQ_Envelope *ev;
  struct ExpressPreferenceMessage *m;

  if (NULL == ch->mq)
    return GNUNET_SYSERR;
  ev = GNUNET_MQ_msg (m,
                      GNUNET_MESSAGE_TYPE_ATS_SUGGEST);
  m->pk = htonl ((uint32_t) sh->pk);
  m->bw = sh->bw;
  m->peer = *peer;
  GNUNET_MQ_send (ch->mq, ev);
  return GNUNET_OK;
}


/**
 * Re-establish the connection to the ATS service.
 *
 * @param ch handle to use to re-connect.
 */
static void
reconnect (struct GNUNET_ATS_ApplicationHandle *ch)
{
  static const struct GNUNET_MQ_MessageHandler handlers[] = {
    { NULL, 0, 0 }
  };

  GNUNET_assert (NULL == ch->mq);
  ch->mq = GNUNET_CLIENT_connect (ch->cfg,
                                  "ats",
                                  handlers,
                                  &error_handler,
                                  ch);
  if (NULL == ch->mq)
  {
    force_reconnect (ch);
    return;
  }
  GNUNET_CONTAINER_multipeermap_iterate (ch->sug_requests,
                                         &transmit_suggestion,
                                         ch);
}


/**
 * Initialize the ATS application suggestion client handle.
 *
 * @param cfg configuration to use
 * @return ats application handle, NULL on error
 */
struct GNUNET_ATS_ApplicationHandle *
GNUNET_ATS_application_init (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_ATS_ApplicationHandle *ch;

  ch = GNUNET_new (struct GNUNET_ATS_ApplicationHandle);
  ch->cfg = cfg;
  ch->sug_requests = GNUNET_CONTAINER_multipeermap_create (32,
                                                           GNUNET_YES);
  reconnect (ch);
  return ch;
}


/**
 * Function called to free all `struct GNUNET_ATS_ApplicationSuggestHandle`s
 * in the map.
 *
 * @param cls NULL
 * @param key the key
 * @param value the value to free
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_sug_handle (void *cls,
                 const struct GNUNET_PeerIdentity *key,
                 void *value)
{
  struct GNUNET_ATS_ApplicationSuggestHandle *cur = value;

  GNUNET_free (cur);
  return GNUNET_OK;
}


/**
 * Client is done with ATS application management, release resources.
 *
 * @param ch handle to release
 */
void
GNUNET_ATS_application_done (struct GNUNET_ATS_ApplicationHandle *ch)
{
  if (NULL != ch->mq)
  {
    GNUNET_MQ_destroy (ch->mq);
    ch->mq = NULL;
  }
  if (NULL != ch->task)
  {
    GNUNET_SCHEDULER_cancel (ch->task);
    ch->task = NULL;
  }
  GNUNET_CONTAINER_multipeermap_iterate (ch->sug_requests,
                                         &free_sug_handle,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (ch->sug_requests);
  GNUNET_free (ch);
}


/**
 * We would like to receive address suggestions for a peer. ATS will
 * respond with a call to the continuation immediately containing an address or
 * no address if none is available. ATS can suggest more addresses until we call
 * #GNUNET_ATS_application_suggest_cancel().
 *
 * @param ch handle
 * @param peer identity of the peer we need an address for
 * @param pk what kind of application will the application require (can be
 *         #GNUNET_MQ_PREFERENCE_NONE, we will still try to connect)
 * @param bw desired bandwith, can be zero (we will still try to connect)
 * @return suggest handle, NULL if a request is already pending
 */
struct GNUNET_ATS_ApplicationSuggestHandle *
GNUNET_ATS_application_suggest (struct GNUNET_ATS_ApplicationHandle *ch,
                                const struct GNUNET_PeerIdentity *peer,
                                enum GNUNET_MQ_PreferenceKind pk,
                                struct GNUNET_BANDWIDTH_Value32NBO bw)
{
  struct GNUNET_ATS_ApplicationSuggestHandle *s;

  s = GNUNET_new (struct GNUNET_ATS_ApplicationSuggestHandle);
  s->ch = ch;
  s->id = *peer;
  s->pk = pk;
  s->bw = bw;
  (void) GNUNET_CONTAINER_multipeermap_put (ch->sug_requests,
                                            &s->id,
                                            s,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Requesting ATS to suggest address for `%s'\n",
       GNUNET_i2s (peer));
  if (NULL == ch->mq)
    return s;
  GNUNET_assert (GNUNET_OK ==
                 transmit_suggestion (ch,
                                      &s->id,
                                      s));
  return s;
}


/**
 * We no longer care about being connected to a peer.
 *
 * @param sh handle to stop
 */
void
GNUNET_ATS_application_suggest_cancel (struct GNUNET_ATS_ApplicationSuggestHandle *sh)
{
  struct GNUNET_ATS_ApplicationHandle *ch = sh->ch;
  struct GNUNET_MQ_Envelope *ev;
  struct ExpressPreferenceMessage *m;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Telling ATS we no longer care for an address for `%s'\n",
       GNUNET_i2s (&sh->id));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_remove (ch->sug_requests,
                                                       &sh->id,
                                                       sh));
  if (NULL == ch->mq)
  {
    GNUNET_free (sh);
    return;
  }
  ev = GNUNET_MQ_msg (m,
		      GNUNET_MESSAGE_TYPE_ATS_SUGGEST_CANCEL);
  m->pk = htonl ((uint32_t) sh->pk);
  m->bw = sh->bw;
  m->peer = sh->id;
  GNUNET_MQ_send (ch->mq,
                  ev);
  GNUNET_free (sh);
}


/* end of ats_api2_application.c */
