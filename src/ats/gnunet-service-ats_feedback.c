/*
     This file is part of GNUnet.
     Copyright (C) 2011-2015 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_feedback.c
 * @brief ats service, handling of feedback
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-ats_plugins.h"
#include "gnunet-service-ats_feedback.h"
#include "ats.h"


/**
 * Change the preference for a peer
 *
 * @param application the client sending this request
 * @param peer the peer id
 * @param scope the time interval for this feedback: [now - scope .. now]
 * @param kind the preference kind to change
 * @param score_abs the new preference score
 */
static void
preference_feedback (struct GNUNET_SERVER_Client *application,
                     const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_TIME_Relative scope,
                     enum GNUNET_ATS_PreferenceKind kind,
                     float score_abs)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received PREFERENCE FEEDBACK for peer `%s'\n",
              GNUNET_i2s (peer));
  GAS_plugin_notify_feedback (application,
				  peer,
				  scope,
				  kind,
				  score_abs);
}


/**
 * Handle 'preference feedback' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_feedback (void *cls,
				struct GNUNET_SERVER_Client *client,
				const struct GNUNET_MessageHeader *message)
{
  const struct FeedbackPreferenceMessage *msg;
  const struct PreferenceInformation *pi;
  uint16_t msize;
  uint32_t nump;
  uint32_t i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received PREFERENCE_FEEDBACK message\n");
  msize = ntohs (message->size);
  if (msize < sizeof (struct FeedbackPreferenceMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
  msg = (const struct FeedbackPreferenceMessage *) message;
  nump = ntohl (msg->num_feedback);
  if (msize !=
      sizeof (struct FeedbackPreferenceMessage) +
      nump * sizeof (struct PreferenceInformation))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
  if (GNUNET_NO ==
      GNUNET_CONTAINER_multipeermap_contains (GSA_addresses,
					      &msg->peer))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
	       "Received PREFERENCE FEEDBACK for unknown peer `%s'\n",
	       GNUNET_i2s (&msg->peer));
    return;
  }

  GNUNET_STATISTICS_update (GSA_stats,
                            "# preference feedbacks requests processed",
                            1,
                            GNUNET_NO);
  pi = (const struct PreferenceInformation *) &msg[1];
  for (i = 0; i < nump; i++)
    preference_feedback (client,
                         &msg->peer,
                         GNUNET_TIME_relative_ntoh(msg->scope),
                         (enum GNUNET_ATS_PreferenceKind) ntohl (pi[i].preference_kind),
                         pi[i].preference_value);
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
}

/* end of gnunet-service-ats_feedback.c */
