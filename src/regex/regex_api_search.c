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
  struct GNUNET_MQ_Handle *mq;

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
   * Search string to transmit to the service.
   */
  char *string;
};


/**
 * (Re)connect to the REGEX service for the given search @a s.
 *
 * @param s context for the search search for
 */
static void
search_reconnect (struct GNUNET_REGEX_Search *s);


/**
 * We got a response or disconnect after asking regex
 * to do the search.  Check it is well-formed.
 *
 * @param cls the `struct GNUNET_REGEX_Search` to handle reply for
 * @param result the message
 * @return #GNUNET_SYSERR if @a rm is not well-formed.
 */
static int
check_search_response (void *cls,
                       const struct ResultMessage *result)
{
  uint16_t size = ntohs (result->header.size) - sizeof (*result);
  uint16_t gpl = ntohs (result->get_path_length);
  uint16_t ppl = ntohs (result->put_path_length);

  if (size != (gpl + ppl) * sizeof (struct GNUNET_PeerIdentity))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * We got a response or disconnect after asking regex
 * to do the search.  Handle it.
 *
 * @param cls the `struct GNUNET_REGEX_Search` to handle reply for
 * @param result the message
 */
static void
handle_search_response (void *cls,
			const struct ResultMessage *result)
{
  struct GNUNET_REGEX_Search *s = cls;
  uint16_t gpl = ntohs (result->get_path_length);
  uint16_t ppl = ntohs (result->put_path_length);
  const struct GNUNET_PeerIdentity *pid;

  pid = &result->id;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got regex result %s\n",
       GNUNET_i2s (pid));
  s->callback (s->callback_cls,
               pid,
               &pid[1],
               gpl,
               &pid[1 + gpl],
               ppl);
}


/**
 * We got a disconnect after asking regex to do the announcement.
 * Retry.
 *
 * @param cls the `struct GNUNET_REGEX_Search` to retry
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_REGEX_Search *s = cls;

  GNUNET_MQ_destroy (s->mq);
  s->mq = NULL;
  search_reconnect (s);
}


/**
 * (Re)connect to the REGEX service for the given search @a s.
 *
 * @param s context for the search search for
 */
static void
search_reconnect (struct GNUNET_REGEX_Search *s)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (search_response,
                           GNUNET_MESSAGE_TYPE_REGEX_RESULT,
                           struct ResultMessage,
                           s),
    GNUNET_MQ_handler_end ()
  };
  size_t slen = strlen (s->string) + 1;
  struct GNUNET_MQ_Envelope *env;
  struct RegexSearchMessage *rsm;

  GNUNET_assert (NULL == s->mq);
  s->mq = GNUNET_CLIENT_connect (s->cfg,
                                 "regex",
                                 handlers,
                                 &mq_error_handler,
                                 s);
  if (NULL == s->mq)
    return;
  env = GNUNET_MQ_msg_extra (rsm,
                             slen,
                             GNUNET_MESSAGE_TYPE_REGEX_SEARCH);
  GNUNET_memcpy (&rsm[1],
          s->string,
          slen);
  GNUNET_MQ_send (s->mq,
                  env);
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
  size_t slen = strlen (string) + 1;

  if (slen + sizeof (struct RegexSearchMessage) >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Search string `%s' is too long!\n"),
                string);
    GNUNET_break (0);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Starting regex search for %s\n",
       string);
  s = GNUNET_new (struct GNUNET_REGEX_Search);
  s->cfg = cfg;
  s->string = GNUNET_strdup (string);
  s->callback = callback;
  s->callback_cls = callback_cls;
  search_reconnect (s);
  if (NULL == s->mq)
  {
    GNUNET_free (s->string);
    GNUNET_free (s);
    return NULL;
  }
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
  GNUNET_MQ_destroy (s->mq);
  GNUNET_free (s->string);
  GNUNET_free (s);
}


/* end of regex_api_search.c */
