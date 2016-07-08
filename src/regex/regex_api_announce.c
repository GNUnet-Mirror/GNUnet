/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013, 2016 GNUnet e.V.

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
 * @file regex/regex_api_announce.c
 * @brief access regex service to advertise capabilities via regex
 * @author Maximilian Szengel
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"
#include "gnunet_regex_service.h"
#include "regex_ipc.h"

#define LOG(kind,...) GNUNET_log_from (kind, "regex-api",__VA_ARGS__)

/**
 * Handle to store cached data about a regex announce.
 */
struct GNUNET_REGEX_Announcement
{
  /**
   * Connection to the regex service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Message we're sending to the service.
   */
  char *regex;

  /**
   * Frequency of announcements.
   */
  struct GNUNET_TIME_Relative refresh_delay;

  /**
   * Number of characters per edge.
   */
  uint16_t compression;
};



/**
 * (Re)connect to the REGEX service with the given announcement @a a.
 *
 * @param a REGEX to announce.
 */
static void
announce_reconnect (struct GNUNET_REGEX_Announcement *a);


/**
 * We got a disconnect after asking regex to do the announcement.
 * Retry.
 *
 * @param cls the `struct GNUNET_REGEX_Announcement` to retry
 * @param error error code
 */
static void
announce_mq_error_handler (void *cls,
                           enum GNUNET_MQ_Error error)
{
  struct GNUNET_REGEX_Announcement *a = cls;

  GNUNET_MQ_destroy (a->mq);
  a->mq = NULL;
  announce_reconnect (a);
}


/**
 * (Re)connect to the REGEX service with the given announcement @a a.
 *
 * @param a REGEX to announce.
 */
static void
announce_reconnect (struct GNUNET_REGEX_Announcement *a)
{
  struct GNUNET_MQ_Envelope *env;
  struct AnnounceMessage *am;
  size_t slen;

  a->mq = GNUNET_CLIENT_connecT (a->cfg,
                                 "regex",
                                 NULL,
                                 &announce_mq_error_handler,
                                 a);
  if (NULL == a->mq)
    return;
  slen = strlen (a->regex) + 1;
  env = GNUNET_MQ_msg_extra (am,
                             slen,
                             GNUNET_MESSAGE_TYPE_REGEX_ANNOUNCE);
  am->compression = htons (a->compression);
  am->reserved = htons (0);
  am->refresh_delay = GNUNET_TIME_relative_hton (a->refresh_delay);
  GNUNET_memcpy (&am[1],
          a->regex,
          slen);
  GNUNET_MQ_send (a->mq,
                  env);
}


/**
 * Announce the given peer under the given regular expression.
 *
 * @param cfg configuration to use
 * @param regex Regular expression to announce.
 * @param refresh_delay after what delay should the announcement be repeated?
 * @param compression How many characters per edge can we squeeze?
 * @return Handle to reuse o free cached resources.
 *         Must be freed by calling #GNUNET_REGEX_announce_cancel().
 */
struct GNUNET_REGEX_Announcement *
GNUNET_REGEX_announce (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       const char *regex,
		       struct GNUNET_TIME_Relative refresh_delay,
                       uint16_t compression)
{
  struct GNUNET_REGEX_Announcement *a;
  size_t slen;

  slen = strlen (regex) + 1;
  if (slen + sizeof (struct AnnounceMessage) >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Regex `%s' is too long!\n"),
                regex);
    GNUNET_break (0);
    return NULL;
  }
  a = GNUNET_new (struct GNUNET_REGEX_Announcement);
  a->cfg = cfg;
  a->refresh_delay = refresh_delay;
  a->compression = compression;
  a->regex = GNUNET_strdup (regex);
  announce_reconnect (a);
  if (NULL == a->mq)
  {
    GNUNET_free (a->regex);
    GNUNET_free (a);
    return NULL;
  }
  return a;
}


/**
 * Stop announcing the regex specified by the given handle.
 *
 * @param a handle returned by a previous #GNUNET_REGEX_announce() call.
 */
void
GNUNET_REGEX_announce_cancel (struct GNUNET_REGEX_Announcement *a)
{
  GNUNET_MQ_destroy (a->mq);
  GNUNET_free (a->regex);
  GNUNET_free (a);
}

/* end of regex_api_announce.c */
