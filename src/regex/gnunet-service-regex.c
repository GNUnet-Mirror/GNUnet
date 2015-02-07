/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
   * Kept in DLL.
   */
  struct ClientEntry *next;

  /**
   * Kept in DLL.
   */
  struct ClientEntry *prev;

  /**
   * Handle identifying the client.
   */
  struct GNUNET_SERVER_Client *client;

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
  struct GNUNET_SCHEDULER_Task * refresh_task;

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
 * Head of list of clients.
 */
static struct ClientEntry *client_head;

/**
 * End of list of clients.
 */
static struct ClientEntry *client_tail;

/**
 * Our notification context, used to send back results to the client.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Private key for this peer.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_DHT_disconnect (dht);
  dht = NULL;
  GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
  stats = NULL;
  GNUNET_SERVER_notification_context_destroy (nc);
  nc = NULL;
  GNUNET_free (my_private_key);
  my_private_key = NULL;
}


/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct ClientEntry *ce;
  struct ClientEntry *nx;

  nx = client_head;
  for (ce = nx; NULL != ce; ce = nx)
  {
    nx = ce->next;
    if (ce->client == client)
    {
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
      GNUNET_CONTAINER_DLL_remove (client_head, client_tail, ce);
      GNUNET_free (ce);
    }
  }
}


/**
 * Periodic task to refresh our announcement of the regex.
 *
 * @param cls the 'struct ClientEntry' of the client that triggered the
 *        announcement
 * @param tc scheduler context
 */
static void
reannounce (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ClientEntry *ce = cls;

  REGEX_INTERNAL_reannounce (ce->ah);
  ce->refresh_task = GNUNET_SCHEDULER_add_delayed (ce->frequency,
						   &reannounce,
						   ce);
}


/**
 * Handle ANNOUNCE message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_announce (void *cls,
		 struct GNUNET_SERVER_Client *client,
		 const struct GNUNET_MessageHeader *message)
{
  const struct AnnounceMessage *am;
  const char *regex;
  struct ClientEntry *ce;
  uint16_t size;

  size = ntohs (message->size);
  am = (const struct AnnounceMessage *) message;
  regex = (const char *) &am[1];
  if ( (size <= sizeof (struct AnnounceMessage)) ||
       ('\0' != regex[size - sizeof (struct AnnounceMessage) - 1]) )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  ce = GNUNET_new (struct ClientEntry);
  ce->client = client;
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
    GNUNET_free (ce);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_CONTAINER_DLL_insert (client_head,
			       client_tail,
			       ce);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle result, pass it back to the client.
 *
 * @param cls the struct ClientEntry of the client searching
 * @param id Peer providing a regex that matches the string.
 * @param get_path Path of the get request.
 * @param get_path_length Lenght of get_path.
 * @param put_path Path of the put request.
 * @param put_path_length Length of the put_path.
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
  size = (get_path_length + put_path_length) * sizeof (struct GNUNET_PeerIdentity) + sizeof (struct ResultMessage);
  result = GNUNET_malloc (size);
  result->header.size = htons (size);
  result->header.type = htons (GNUNET_MESSAGE_TYPE_REGEX_RESULT);
  result->get_path_length = htons ((uint16_t) get_path_length);
  result->put_path_length = htons ((uint16_t) put_path_length);
  result->id = *id;
  gp = &result->id;
  memcpy (&gp[1],
	  get_path,
	  get_path_length * sizeof (struct GNUNET_PeerIdentity));
  memcpy (&gp[1 + get_path_length],
	  put_path,
	  put_path_length * sizeof (struct GNUNET_PeerIdentity));
  GNUNET_SERVER_notification_context_unicast (nc,
					      ce->client,
					      &result->header, GNUNET_NO);
  GNUNET_free (result);
}


/**
 * Handle SEARCH message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_search (void *cls,
	       struct GNUNET_SERVER_Client *client,
	       const struct GNUNET_MessageHeader *message)
{
  const struct RegexSearchMessage *sm;
  const char *string;
  struct ClientEntry *ce;
  uint16_t size;

  size = ntohs (message->size);
  sm = (const struct RegexSearchMessage *) message;
  string = (const char *) &sm[1];
  if ( (size <= sizeof (struct RegexSearchMessage)) ||
       ('\0' != string[size - sizeof (struct RegexSearchMessage) - 1]) )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  ce = GNUNET_new (struct ClientEntry);
  ce->client = client;
  ce->sh = REGEX_INTERNAL_search (dht,
				string,
				&handle_search_result,
				ce,
				stats);
  if (NULL == ce->sh)
  {
    GNUNET_break (0);
    GNUNET_free (ce);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_CONTAINER_DLL_insert (client_head,
			       client_tail,
			       ce);
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Process regex requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_announce, NULL, GNUNET_MESSAGE_TYPE_REGEX_ANNOUNCE, 0},
    {&handle_search, NULL, GNUNET_MESSAGE_TYPE_REGEX_SEARCH, 0},
    {NULL, NULL, 0, 0}
  };

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
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);
  nc = GNUNET_SERVER_notification_context_create (server, 1);
  stats = GNUNET_STATISTICS_create ("regex", cfg);
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
}


/**
 * The main function for the regex service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "regex",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-regex.c */
