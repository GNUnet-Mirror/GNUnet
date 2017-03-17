/*
     This file is part of GNUnet.
     Copyright (C) 2013 GNUnet e.V.

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
 * @file regex/gnunet-service-regex.c
 * @brief service to advertise capabilities described as regex and to
 *        lookup capabilities by regex
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "regex_internal_lib.h"
#include "regex_ipc.h"


/**
 * Information about one of our clients.
 */
struct ClientEntry
{

  /**
   * Queue for transmissions to @e client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Handle identifying the client.
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Search handle (if this client is searching).
   */
  struct REGEX_INTERNAL_Search *sh;

  /**
   * Announcement handle (if this client is announcing).
   */
  struct REGEX_INTERNAL_Announcement *ah;

  /**
   * Refresh frequency for announcements.
   */
  struct GNUNET_TIME_Relative frequency;

  /**
   * Task for re-announcing.
   */
  struct GNUNET_SCHEDULER_Task *refresh_task;

};


/**
 * Connection to the DHT.
 */
static struct GNUNET_DHT_Handle *dht;

/**
 * Handle for doing statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Private key for this peer.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
cleanup_task (void *cls)
{
  GNUNET_DHT_disconnect (dht);
  dht = NULL;
  GNUNET_STATISTICS_destroy (stats,
                             GNUNET_NO);
  stats = NULL;
  GNUNET_free (my_private_key);
  my_private_key = NULL;
}


/**
 * Periodic task to refresh our announcement of the regex.
 *
 * @param cls the `struct ClientEntry *` of the client that triggered the
 *        announcement
 */
static void
reannounce (void *cls)
{
  struct ClientEntry *ce = cls;

  REGEX_INTERNAL_reannounce (ce->ah);
  ce->refresh_task = GNUNET_SCHEDULER_add_delayed (ce->frequency,
						   &reannounce,
						   ce);
}


/**
 * Check ANNOUNCE message.
 *
 * @param cls identification of the client
 * @param am the actual message
 * @return #GNUNET_OK if @am is well-formed
 */
static int
check_announce (void *cls,
                const struct AnnounceMessage *am)
{
  struct ClientEntry *ce = cls;
  const char *regex;
  uint16_t size;

  size = ntohs (am->header.size) - sizeof (*am);
  regex = (const char *) &am[1];
  if ('\0' != regex[size - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (NULL != ce->ah)
  {
    /* only one announcement per client allowed */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle ANNOUNCE message.
 *
 * @param cls identification of the client
 * @param am the actual message
 */
static void
handle_announce (void *cls,
		 const struct AnnounceMessage *am)
{
  struct ClientEntry *ce = cls;
  const char *regex;

  regex = (const char *) &am[1];
  ce->frequency = GNUNET_TIME_relative_ntoh (am->refresh_delay);
  ce->refresh_task = GNUNET_SCHEDULER_add_delayed (ce->frequency,
						   &reannounce,
						   ce);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting to announce regex `%s' every %s\n",
	      regex,
	      GNUNET_STRINGS_relative_time_to_string (ce->frequency,
						      GNUNET_NO));
  ce->ah = REGEX_INTERNAL_announce (dht,
				    my_private_key,
				    regex,
				    ntohs (am->compression),
				    stats);
  if (NULL == ce->ah)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (ce->refresh_task);
    ce->refresh_task = NULL;
    GNUNET_SERVICE_client_drop (ce->client);
    return;
  }
  GNUNET_SERVICE_client_continue (ce->client);
}


/**
 * Handle result, pass it back to the client.
 *
 * @param cls the struct ClientEntry of the client searching
 * @param id Peer providing a regex that matches the string.
 * @param get_path Path of the get request.
 * @param get_path_length Lenght of @a get_path.
 * @param put_path Path of the put request.
 * @param put_path_length Length of the @a put_path.
 */
static void
handle_search_result (void *cls,
		      const struct GNUNET_PeerIdentity *id,
		      const struct GNUNET_PeerIdentity *get_path,
		      unsigned int get_path_length,
		      const struct GNUNET_PeerIdentity *put_path,
		      unsigned int put_path_length)
{
  struct ClientEntry *ce = cls;
  struct GNUNET_MQ_Envelope *env;
  struct ResultMessage *result;
  struct GNUNET_PeerIdentity *gp;
  uint16_t size;

  if ( (get_path_length >= 65536) ||
       (put_path_length >= 65536) ||
       ( (get_path_length + put_path_length) * sizeof (struct GNUNET_PeerIdentity))
       + sizeof (struct ResultMessage) >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  size = (get_path_length + put_path_length) * sizeof (struct GNUNET_PeerIdentity);
  env = GNUNET_MQ_msg_extra (result,
                             size,
                             GNUNET_MESSAGE_TYPE_REGEX_RESULT);
  result->get_path_length = htons ((uint16_t) get_path_length);
  result->put_path_length = htons ((uint16_t) put_path_length);
  result->id = *id;
  gp = &result->id;
  GNUNET_memcpy (&gp[1],
                 get_path,
                 get_path_length * sizeof (struct GNUNET_PeerIdentity));
  GNUNET_memcpy (&gp[1 + get_path_length],
                 put_path,
                 put_path_length * sizeof (struct GNUNET_PeerIdentity));
  GNUNET_MQ_send (ce->mq,
                  env);
}


/**
 * Check SEARCH message.
 *
 * @param cls identification of the client
 * @param message the actual message
 */
static int
check_search (void *cls,
              const struct RegexSearchMessage *sm)
{
  struct ClientEntry *ce = cls;
  const char *string;
  uint16_t size;

  size = ntohs (sm->header.size) - sizeof (*sm);
  string = (const char *) &sm[1];
  if ('\0' != string[size - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (NULL != ce->sh)
  {
    /* only one search allowed per client */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle SEARCH message.
 *
 * @param cls identification of the client
 * @param message the actual message
 */
static void
handle_search (void *cls,
	       const struct RegexSearchMessage *sm)
{
  struct ClientEntry *ce = cls;
  const char *string;

  string = (const char *) &sm[1];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting to search for `%s'\n",
	      string);
  ce->sh = REGEX_INTERNAL_search (dht,
                                  string,
                                  &handle_search_result,
                                  ce,
                                  stats);
  if (NULL == ce->sh)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (ce->client);
    return;
  }
  GNUNET_SERVICE_client_continue (ce->client);
}


/**
 * Process regex requests.
 *
 * @param cls closure
 * @param cfg configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_SERVICE_Handle *service)
{
  my_private_key = GNUNET_CRYPTO_eddsa_key_create_from_configuration (cfg);
  if (NULL == my_private_key)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  dht = GNUNET_DHT_connect (cfg, 1024);
  if (NULL == dht)
  {
    GNUNET_free (my_private_key);
    my_private_key = NULL;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_SCHEDULER_add_shutdown (&cleanup_task,
				 NULL);
  stats = GNUNET_STATISTICS_create ("regex", cfg);
}


/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return @a c
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *c,
		   struct GNUNET_MQ_Handle *mq)
{
  struct ClientEntry *ce;

  ce = GNUNET_new (struct ClientEntry);
  ce->client = c;
  ce->mq = mq;
  return ce;
}


/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls should be equal to @a c
 */
static void
client_disconnect_cb (void *cls,
		      struct GNUNET_SERVICE_Client *c,
		      void *internal_cls)
{
  struct ClientEntry *ce = internal_cls;

  if (NULL != ce->refresh_task)
  {
    GNUNET_SCHEDULER_cancel (ce->refresh_task);
    ce->refresh_task = NULL;
  }
  if (NULL != ce->ah)
  {
    REGEX_INTERNAL_announce_cancel (ce->ah);
    ce->ah = NULL;
  }
  if (NULL != ce->sh)
  {
    REGEX_INTERNAL_search_cancel (ce->sh);
    ce->sh = NULL;
  }
  GNUNET_free (ce);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("regex",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (announce,
                        GNUNET_MESSAGE_TYPE_REGEX_ANNOUNCE,
                        struct AnnounceMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (search,
                        GNUNET_MESSAGE_TYPE_REGEX_SEARCH,
                        struct RegexSearchMessage,
                        NULL),
 GNUNET_MQ_handler_end ());


/* end of gnunet-service-regex.c */
