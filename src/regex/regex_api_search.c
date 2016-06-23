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
 * @file regex/regex_api_search.c
 * @brief access regex service to discover
 *        peers using matching strings
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
 * Handle to store data about a regex search.
 */
struct GNUNET_REGEX_Search
{
  /**
   * Connection to the regex service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Function to call with results.
   */
  GNUNET_REGEX_Found callback;

  /**
   * Closure for @e callback.
   */
  void *callback_cls;

  /**
   * Search message to transmit to the service.
   */
  struct RegexSearchMessage *msg;
};


/**
 * We got a response or disconnect after asking regex
 * to do the search.  Handle it.
 *
 * @param cls the `struct GNUNET_REGEX_Search` to retry
 * @param msg NULL on disconnect
 */
static void
handle_search_response (void *cls,
			const struct GNUNET_MessageHeader *msg);


/**
 * Try sending the search request to regex.  On
 * errors (i.e. regex died), try again.
 *
 * @param s the search to retry
 */
static void
retry_search (struct GNUNET_REGEX_Search *s)
{
  GNUNET_assert (NULL != s->client);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CLIENT_transmit_and_get_response (s->client,
							  &s->msg->header,
							  GNUNET_TIME_UNIT_FOREVER_REL,
							  GNUNET_YES,
							  &handle_search_response,
							  s));
}


/**
 * We got a response or disconnect after asking regex
 * to do the search.  Handle it.
 *
 * @param cls the `struct GNUNET_REGEX_Search` to handle reply for
 * @param msg NULL on disconnect, otherwise presumably a response
 */
static void
handle_search_response (void *cls,
			const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_REGEX_Search *s = cls;
  const struct ResultMessage *result;
  uint16_t size;
  uint16_t gpl;
  uint16_t ppl;

  if (NULL == msg)
  {
    GNUNET_CLIENT_disconnect (s->client);
    s->client = GNUNET_CLIENT_connect ("regex", s->cfg);
    retry_search (s);
    return;
  }
  size = ntohs (msg->size);
  if ( (GNUNET_MESSAGE_TYPE_REGEX_RESULT == ntohs (msg->type)) &&
       (size >= sizeof (struct ResultMessage)) )
  {
    result = (const struct ResultMessage *) msg;
    gpl = ntohs (result->get_path_length);
    ppl = ntohs (result->put_path_length);
    if (size == (sizeof (struct ResultMessage) +
		 (gpl + ppl) * sizeof (struct GNUNET_PeerIdentity)))
    {
      const struct GNUNET_PeerIdentity *pid;

      GNUNET_CLIENT_receive (s->client,
			     &handle_search_response, s,
			     GNUNET_TIME_UNIT_FOREVER_REL);
      pid = &result->id;
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Got regex result %s\n",
           GNUNET_i2s (pid));
      s->callback (s->callback_cls,
		   pid,
		   &pid[1], gpl,
		   &pid[1 + gpl], ppl);
      return;
    }
  }
  GNUNET_break (0);
  GNUNET_CLIENT_disconnect (s->client);
  s->client = GNUNET_CLIENT_connect ("regex", s->cfg);
  retry_search (s);
}


/**
 * Search for a peer offering a regex matching certain string in the DHT.
 * The search runs until #GNUNET_REGEX_search_cancel() is called, even if results
 * are returned.
 *
 * @param cfg configuration to use
 * @param string String to match against the regexes in the DHT.
 * @param callback Callback for found peers.
 * @param callback_cls Closure for @c callback.
 * @return Handle to stop search and free resources.
 *         Must be freed by calling #GNUNET_REGEX_search_cancel().
 */
struct GNUNET_REGEX_Search *
GNUNET_REGEX_search (const struct GNUNET_CONFIGURATION_Handle *cfg,
		     const char *string,
                     GNUNET_REGEX_Found callback,
                     void *callback_cls)
{
  struct GNUNET_REGEX_Search *s;
  size_t slen;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Starting regex search for %s\n",
       string);
  slen = strlen (string) + 1;
  s = GNUNET_new (struct GNUNET_REGEX_Search);
  s->cfg = cfg;
  s->client = GNUNET_CLIENT_connect ("regex", cfg);
  if (NULL == s->client)
  {
    GNUNET_free (s);
    return NULL;
  }
  s->callback = callback;
  s->callback_cls = callback_cls;
  s->msg = GNUNET_malloc (sizeof (struct RegexSearchMessage) + slen);
  s->msg->header.type = htons (GNUNET_MESSAGE_TYPE_REGEX_SEARCH);
  s->msg->header.size = htons (sizeof (struct RegexSearchMessage) + slen);
  memcpy (&s->msg[1], string, slen);
  retry_search (s);
  return s;
}


/**
 * Stop search and free all data used by a #GNUNET_REGEX_search() call.
 *
 * @param s Handle returned by a previous #GNUNET_REGEX_search() call.
 */
void
GNUNET_REGEX_search_cancel (struct GNUNET_REGEX_Search *s)
{
  GNUNET_CLIENT_disconnect (s->client);
  GNUNET_free (s->msg);
  GNUNET_free (s);
}


/* end of regex_api.c */
