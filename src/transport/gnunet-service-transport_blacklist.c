/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_blacklist.c
 * @brief blacklisting implementation
 * @author Christian Grothoff
 * @author Matthias Wachs
 * @details This is the blacklisting component of transport service. With
 * blacklisting it is possible to deny connections to specific peers of
 * to use a specific plugin to a specific peer. Peers can be blacklisted using
 * the configuration or a blacklist client can be asked.
 *
 * To blacklist peers using the configuration you have to add a section to your
 * configuration containing the peer id of the peer to blacklist and the plugin
 * if required.
 *
 * Example:
 * To blacklist connections to P565... on peer AG2P... using tcp add:
 * [transport-blacklist-AG2PHES1BARB9IJCPAMJTFPVJ5V3A72S3F2A8SBUB8DAQ2V0O3V8G6G2JU56FHGFOHMQVKBSQFV98TCGTC3RJ1NINP82G0RC00N1520]
 * P565723JO1C2HSN6J29TAQ22MN6CI8HTMUU55T0FUQG4CMDGGEQ8UCNBKUMB94GC8R9G4FB2SF9LDOBAJ6AMINBP4JHHDD6L7VD801G = tcp
 *
 * To blacklist connections to P565... on peer AG2P... using all plugins add:
 * [transport-blacklist-AG2PHES1BARB9IJCPAMJTFPVJ5V3A72S3F2A8SBUB8DAQ2V0O3V8G6G2JU56FHGFOHMQVKBSQFV98TCGTC3RJ1NINP82G0RC00N1520]
 * P565723JO1C2HSN6J29TAQ22MN6CI8HTMUU55T0FUQG4CMDGGEQ8UCNBKUMB94GC8R9G4FB2SF9LDOBAJ6AMINBP4JHHDD6L7VD801G =
 *
 * You can also add a blacklist client usign the blacklist api. On a blacklist
 * check, blacklisting first checks internally if the peer is blacklisted and
 * if not, it asks the blacklisting clients. Clients are asked if it is OK to
 * connect to a peer ID, the plugin is omitted.
 *
 * On blacklist check for (peer, plugin)
 * - Do we have a local blacklist entry for this peer and this plugin?
 *   - YES: disallow connection
 * - Do we have a local blacklist entry for this peer and all plugins?
 *   - YES: disallow connection
 * - Does one of the clients disallow?
 *   - YES: disallow connection
 *
 */
#include "platform.h"
#include "gnunet-service-transport.h"
#include "gnunet-service-transport_blacklist.h"
#include "gnunet-service-transport_neighbours.h"
#include "transport.h"

/**
 * Size of the blacklist hash map.
 */
#define TRANSPORT_BLACKLIST_HT_SIZE 64


/**
 * Context we use when performing a blacklist check.
 */
struct GST_BlacklistCheck;


/**
 * Information kept for each client registered to perform
 * blacklisting.
 */
struct Blacklisters
{
  /**
   * This is a linked list.
   */
  struct Blacklisters *next;

  /**
   * This is a linked list.
   */
  struct Blacklisters *prev;

  /**
   * Client responsible for this entry.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Blacklist check that we're currently performing (or NULL
   * if we're performing one that has been cancelled).
   */
  struct GST_BlacklistCheck *bc;

  /**
   * Set to #GNUNET_YES if we're currently waiting for a reply.
   */
  int waiting_for_reply;

  /**
   * #GNUNET_YES if we have to call receive_done for this client
   */
  int call_receive_done;

};



/**
 * Context we use when performing a blacklist check.
 */
struct GST_BlacklistCheck
{

  /**
   * This is a linked list.
   */
  struct GST_BlacklistCheck *next;

  /**
   * This is a linked list.
   */
  struct GST_BlacklistCheck *prev;

  /**
   * Peer being checked.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Continuation to call with the result.
   */
  GST_BlacklistTestContinuation cont;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;

  /**
   * Current transmission request handle for this client, or NULL if no
   * request is pending.
   */
  struct GNUNET_SERVER_TransmitHandle *th;

  /**
   * Our current position in the blacklisters list.
   */
  struct Blacklisters *bl_pos;

  /**
   * Current task performing the check.
   */
  struct GNUNET_SCHEDULER_Task * task;

};


/**
 * Head of DLL of active blacklisting queries.
 */
static struct GST_BlacklistCheck *bc_head;

/**
 * Tail of DLL of active blacklisting queries.
 */
static struct GST_BlacklistCheck *bc_tail;

/**
 * Head of DLL of blacklisting clients.
 */
static struct Blacklisters *bl_head;

/**
 * Tail of DLL of blacklisting clients.
 */
static struct Blacklisters *bl_tail;

/**
 * Hashmap of blacklisted peers.  Values are of type 'char *' (transport names),
 * can be NULL if we have no static blacklist.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *blacklist;


/**
 * Perform next action in the blacklist check.
 *
 * @param cls the `struct BlacklistCheck*`
 * @param tc unused
 */
static void
do_blacklist_check (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Called whenever a client is disconnected.  Frees our
 * resources associated with that client.
 *
 * @param cls closure (unused)
 * @param client identification of the client
 */
static void
client_disconnect_notification (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct Blacklisters *bl;
  struct GST_BlacklistCheck *bc;

  if (NULL == client)
    return;
  for (bl = bl_head; bl != NULL; bl = bl->next)
  {
    if (bl->client != client)
      continue;
    for (bc = bc_head; bc != NULL; bc = bc->next)
    {
      if (bc->bl_pos != bl)
        continue;
      bc->bl_pos = bl->next;
      if (bc->th != NULL)
      {
        GNUNET_SERVER_notify_transmit_ready_cancel (bc->th);
        bc->th = NULL;
      }
      if (bc->task == NULL)
        bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check, bc);
    }
    GNUNET_CONTAINER_DLL_remove (bl_head, bl_tail, bl);
    GNUNET_SERVER_client_drop (bl->client);
    GNUNET_free (bl);
    break;
  }
}


/**
 * Function to iterate over options in the blacklisting section for a peer.
 *
 * @param cls closure
 * @param section name of the section
 * @param option name of the option
 * @param value value of the option
 */
static void
blacklist_cfg_iter (void *cls,
                    const char *section,
		    const char *option,
		    const char *value)
{
  unsigned int *res = cls;
  struct GNUNET_PeerIdentity peer;
  char *plugs;
  char *pos;

  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_public_key_from_string (option,
                                                  strlen (option),
                                                  &peer.public_key))
    return;

  if ((NULL == value) || (0 == strcmp(value, "")))
  {
    /* Blacklist whole peer */
    GST_blacklist_add_peer (&peer, NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Adding blacklisting entry for peer `%s'\n"),
                GNUNET_i2s (&peer));
  }
  else
  {
    plugs = GNUNET_strdup (value);
    for (pos = strtok (plugs, " "); pos != NULL; pos = strtok (NULL, " "))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		    _("Adding blacklisting entry for peer `%s':`%s'\n"),
		    GNUNET_i2s (&peer), pos);
	GST_blacklist_add_peer (&peer, pos);
      }
    GNUNET_free (plugs);
  }
  (*res)++;
}


/**
 * Read blacklist configuration
 *
 * @param cfg the configuration handle
 * @param my_id my peer identity
 */
static void
read_blacklist_configuration (const struct GNUNET_CONFIGURATION_Handle *cfg,
			      const struct GNUNET_PeerIdentity *my_id)
{
  char cfg_sect[512];
  unsigned int res = 0;

  GNUNET_snprintf (cfg_sect,
		   sizeof (cfg_sect),
		   "transport-blacklist-%s",
		   GNUNET_i2s_full (my_id));
  GNUNET_CONFIGURATION_iterate_section_values (cfg,
                                               cfg_sect,
                                               &blacklist_cfg_iter,
                                               &res);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loaded %u blacklisting entries from configuration\n",
              res);
}


/**
 * Start blacklist subsystem.
 *
 * @param server server used to accept clients from
 * @param cfg configuration handle
 * @param my_id my peer id
 */
void
GST_blacklist_start (struct GNUNET_SERVER_Handle *server,
		     const struct GNUNET_CONFIGURATION_Handle *cfg,
		     const struct GNUNET_PeerIdentity *my_id)
{
  GNUNET_assert (NULL != cfg);
  GNUNET_assert (NULL != my_id);
  read_blacklist_configuration (cfg, my_id);
  GNUNET_SERVER_disconnect_notify (server,
                                   &client_disconnect_notification,
                                   NULL);
}


/**
 * Free the given entry in the blacklist.
 *
 * @param cls unused
 * @param key host identity (unused)
 * @param value the blacklist entry
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_blacklist_entry (void *cls,
		      const struct GNUNET_PeerIdentity *key,
		      void *value)
{
  char *be = value;

  GNUNET_free_non_null (be);
  return GNUNET_OK;
}


/**
 * Stop blacklist subsystem.
 */
void
GST_blacklist_stop ()
{
  if (NULL == blacklist)
    return;
  GNUNET_CONTAINER_multipeermap_iterate (blacklist,
                                         &free_blacklist_entry,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (blacklist);
  blacklist = NULL;
}


/**
 * Transmit blacklist query to the client.
 *
 * @param cls the `struct GST_BlacklistCheck`
 * @param size number of bytes allowed
 * @param buf where to copy the message
 * @return number of bytes copied to @a buf
 */
static size_t
transmit_blacklist_message (void *cls, size_t size, void *buf)
{
  struct GST_BlacklistCheck *bc = cls;
  struct Blacklisters *bl;
  struct BlacklistMessage bm;

  bc->th = NULL;
  if (size == 0)
  {
    GNUNET_assert (bc->task == NULL);
    bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check, bc);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to send blacklist test for peer `%s' to client\n",
                GNUNET_i2s (&bc->peer));
    return 0;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending blacklist test for peer `%s' to client %p\n",
              GNUNET_i2s (&bc->peer), bc->bl_pos->client);
  bl = bc->bl_pos;
  bm.header.size = htons (sizeof (struct BlacklistMessage));
  bm.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_QUERY);
  bm.is_allowed = htonl (0);
  bm.peer = bc->peer;
  memcpy (buf, &bm, sizeof (bm));
  if (GNUNET_YES == bl->call_receive_done)
  {
    GNUNET_SERVER_receive_done (bl->client, GNUNET_OK);
    bl->call_receive_done = GNUNET_NO;
  }

  bl->waiting_for_reply = GNUNET_YES;
  return sizeof (bm);
}


/**
 * Perform next action in the blacklist check.
 *
 * @param cls the `struct GST_BlacklistCheck *`
 * @param tc unused
 */
static void
do_blacklist_check (void *cls,
                    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GST_BlacklistCheck *bc = cls;
  struct Blacklisters *bl;

  bc->task = NULL;
  bl = bc->bl_pos;
  if (bl == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No other blacklist clients active, will allow neighbour `%s'\n",
                GNUNET_i2s (&bc->peer));

    bc->cont (bc->cont_cls, &bc->peer, GNUNET_OK);
    GNUNET_CONTAINER_DLL_remove(bc_head, bc_tail, bc);
    GNUNET_free (bc);
    return;
  }
  if ((bl->bc != NULL) || (bl->waiting_for_reply != GNUNET_NO))
    return;                     /* someone else busy with this client */
  bl->bc = bc;
  bc->th =
      GNUNET_SERVER_notify_transmit_ready (bl->client,
                                           sizeof (struct BlacklistMessage),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           &transmit_blacklist_message, bc);
}


/**
 * Got the result about an existing connection from a new blacklister.
 * Shutdown the neighbour if necessary.
 *
 * @param cls unused
 * @param peer the neighbour that was investigated
 * @param allowed #GNUNET_OK if we can keep it,
 *                #GNUNET_NO if we must shutdown the connection
 */
static void
confirm_or_drop_neighbour (void *cls,
                           const struct GNUNET_PeerIdentity *peer,
                           int allowed)
{
  if (GNUNET_OK == allowed)
    return;                     /* we're done */
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# disconnects due to blacklist"), 1,
                            GNUNET_NO);
  GST_neighbours_force_disconnect (peer);
}


/**
 * Closure for 'test_connection_ok'.
 */
struct TestConnectionContext
{
  /**
   * Is this the first neighbour we're checking?
   */
  int first;

  /**
   * Handle to the blacklisting client we need to ask.
   */
  struct Blacklisters *bl;
};


/**
 * Test if an existing connection is still acceptable given a new
 * blacklisting client.
 *
 * @param cls the `struct TestConnectionContext *`
 * @param peer neighbour's identity
 * @param address the address
 * @param state current state this peer is in
 * @param state_timeout timeout for the current state of the peer
 * @param bandwidth_in bandwidth assigned inbound
 * @param bandwidth_out bandwidth assigned outbound
 */
static void
test_connection_ok (void *cls, const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_HELLO_Address *address,
    enum GNUNET_TRANSPORT_PeerState state,
    struct GNUNET_TIME_Absolute state_timeout,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  struct TestConnectionContext *tcc = cls;
  struct GST_BlacklistCheck *bc;

  bc = GNUNET_new (struct GST_BlacklistCheck);
  GNUNET_CONTAINER_DLL_insert(bc_head, bc_tail, bc);
  bc->peer = *peer;
  bc->cont = &confirm_or_drop_neighbour;
  bc->cont_cls = NULL;
  bc->bl_pos = tcc->bl;
  if (GNUNET_YES == tcc->first)
  {
    /* all would wait for the same client, no need to
     * create more than just the first task right now */
    bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check, bc);
    tcc->first = GNUNET_NO;
  }
}


/**
 * Initialize a blacklisting client.  We got a blacklist-init
 * message from this client, add him to the list of clients
 * to query for blacklisting.
 *
 * @param cls unused
 * @param client the client
 * @param message the blacklist-init message that was sent
 */
void
GST_blacklist_handle_init (void *cls, struct GNUNET_SERVER_Client *client,
                           const struct GNUNET_MessageHeader *message)
{
  struct Blacklisters *bl;
  struct TestConnectionContext tcc;

  for (bl = bl_head; NULL != bl; bl = bl->next)
    if (bl->client == client)
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }

  GNUNET_SERVER_client_mark_monitor (client);
  bl = GNUNET_new (struct Blacklisters);
  bl->client = client;
  bl->call_receive_done = GNUNET_YES;
  GNUNET_SERVER_client_keep (client);
  GNUNET_CONTAINER_DLL_insert_after (bl_head,
                                     bl_tail,
                                     bl_tail,
                                     bl);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New blacklist client %p\n",
              client);

  /* confirm that all existing connections are OK! */
  tcc.bl = bl;
  tcc.first = GNUNET_YES;
  GST_neighbours_iterate (&test_connection_ok, &tcc);
}


/**
 * A blacklisting client has sent us reply. Process it.
 *
 * @param cls unused
 * @param client the client
 * @param message the blacklist-init message that was sent
 */
void
GST_blacklist_handle_reply (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  const struct BlacklistMessage *msg =
      (const struct BlacklistMessage *) message;
  struct Blacklisters *bl;
  struct GST_BlacklistCheck *bc;

  bl = bl_head;
  while ((bl != NULL) && (bl->client != client))
    bl = bl->next;
  if (NULL == bl)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Blacklist client disconnected\n");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Blacklist client %p sent reply for `%s'\n",
              client,
              GNUNET_i2s(&msg->peer));

  bc = bl->bc;
  bl->bc = NULL;
  bl->waiting_for_reply = GNUNET_NO;
  bl->call_receive_done = GNUNET_YES; /* Remember to call receive_done */
  if (NULL != bc)
  {
    /* only run this if the blacklist check has not been
     * cancelled in the meantime... */
    if (ntohl (msg->is_allowed) == GNUNET_SYSERR)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Blacklist check failed, peer not allowed\n");
      bc->cont (bc->cont_cls, &bc->peer, GNUNET_NO);
      GNUNET_CONTAINER_DLL_remove (bc_head, bc_tail, bc);
      GNUNET_SERVER_receive_done (bl->client, GNUNET_OK);
      bl->call_receive_done = GNUNET_NO;
      GNUNET_free (bc);
      return;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Blacklist check succeeded, continuing with checks\n");
      GNUNET_SERVER_receive_done (bl->client, GNUNET_OK);
      bl->call_receive_done = GNUNET_NO;
      bc->bl_pos = bc->bl_pos->next;
      bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check, bc);
    }
  }
  /* check if any other blacklist checks are waiting for this blacklister */
  for (bc = bc_head; bc != NULL; bc = bc->next)
    if ((bc->bl_pos == bl) && (NULL == bc->task))
    {
      bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check, bc);
      break;
    }
}


/**
 * Add the given peer to the blacklist (for the given transport).
 *
 * @param peer peer to blacklist
 * @param transport_name transport to blacklist for this peer, NULL for all
 */
void
GST_blacklist_add_peer (const struct GNUNET_PeerIdentity *peer,
                        const char *transport_name)
{
  char *transport = NULL;

  if (NULL != transport_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Adding peer `%s' with plugin `%s' to blacklist\n",
		GNUNET_i2s (peer), transport_name);
    transport = GNUNET_strdup (transport_name);
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Adding peer `%s' with all plugins to blacklist\n",
		GNUNET_i2s (peer));
  if (NULL == blacklist)
    blacklist =
      GNUNET_CONTAINER_multipeermap_create (TRANSPORT_BLACKLIST_HT_SIZE,
					    GNUNET_NO);

  GNUNET_CONTAINER_multipeermap_put (blacklist, peer,
                                     transport,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
}


/**
 * Test if the given blacklist entry matches.  If so,
 * abort the iteration.
 *
 * @param cls the transport name to match (const char*)
 * @param key the key (unused)
 * @param value the 'char *' (name of a blacklisted transport)
 * @return #GNUNET_OK if the entry does not match, #GNUNET_NO if it matches
 */
static int
test_blacklisted (void *cls,
		  const struct GNUNET_PeerIdentity *key,
		  void *value)
{
  const char *transport_name = cls;
  char *be = value;

  /* Blacklist entry be:
   *  (NULL == be): peer is blacklisted with all plugins
   *  (NULL != be): peer is blacklisted for a specific plugin
   *
   * If (NULL != transport_name) we look for a transport specific entry:
   *  if (transport_name == be) forbidden
   *
   */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Comparing BL request for peer `%4s':`%s' with BL entry: `%s'\n",
	      GNUNET_i2s (key),
	      (NULL == transport_name) ? "unspecified" : transport_name,
	      (NULL == be) ? "all plugins" : be);
  /* all plugins for this peer were blacklisted: disallow */
  if (NULL == value)
  		return GNUNET_NO;

  /* blacklist check for specific transport */
  if ((NULL != transport_name) && (NULL != value))
  {
  	if (0 == strcmp (transport_name, be))
  			return GNUNET_NO;           /* plugin is blacklisted! */
  }
  return GNUNET_OK;
}


/**
 * Test if a peer/transport combination is blacklisted.
 *
 * @param peer the identity of the peer to test
 * @param transport_name name of the transport to test, never NULL
 * @param cont function to call with result
 * @param cont_cls closure for @a cont
 * @return handle to the blacklist check, NULL if the decision
 *        was made instantly and @a cont was already called
 */
struct GST_BlacklistCheck *
GST_blacklist_test_allowed (const struct GNUNET_PeerIdentity *peer,
                            const char *transport_name,
                            GST_BlacklistTestContinuation cont,
                            void *cont_cls)
{
  struct GST_BlacklistCheck *bc;

  GNUNET_assert (NULL != peer);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Blacklist check for peer `%s':%s\n",
              GNUNET_i2s (peer),
              (NULL != transport_name) ? transport_name : "unspecified");

  /* Check local blacklist by iterating over hashmap
   * If iteration is aborted, we found a matching blacklist entry */
  if ((NULL != blacklist) &&
      (GNUNET_SYSERR ==
       GNUNET_CONTAINER_multipeermap_get_multiple (blacklist, peer,
                                                   &test_blacklisted,
                                                   (void *) transport_name)))
  {
    /* Disallowed by config, disapprove instantly */
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# disconnects due to blacklist"),
                              1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Disallowing connection to peer `%s' on transport %s\n"),
    		GNUNET_i2s (peer),
                (NULL != transport_name) ? transport_name : "unspecified");
    if (cont != NULL)
      cont (cont_cls, peer, GNUNET_NO);
    return NULL;
  }

  if (NULL == bl_head)
  {
    /* no blacklist clients, approve instantly */
    if (cont != NULL)
      cont (cont_cls, peer, GNUNET_OK);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Allowing connection to peer `%s' %s\n",
    		GNUNET_i2s (peer),
                (NULL != transport_name) ? transport_name : "");
    return NULL;
  }

  /* need to query blacklist clients */
  bc = GNUNET_new (struct GST_BlacklistCheck);
  GNUNET_CONTAINER_DLL_insert (bc_head, bc_tail, bc);
  bc->peer = *peer;
  bc->cont = cont;
  bc->cont_cls = cont_cls;
  bc->bl_pos = bl_head;
  bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check, bc);
  return bc;
}


/**
 * Cancel a blacklist check.
 *
 * @param bc check to cancel
 */
void
GST_blacklist_test_cancel (struct GST_BlacklistCheck *bc)
{
  GNUNET_CONTAINER_DLL_remove (bc_head,
                               bc_tail,
                               bc);
  if (NULL != bc->bl_pos)
  {
    if (bc->bl_pos->bc == bc)
    {
      /* we're at the head of the queue, remove us! */
      bc->bl_pos->bc = NULL;
    }
  }
  if (NULL != bc->task)
  {
    GNUNET_SCHEDULER_cancel (bc->task);
    bc->task = NULL;
  }
  if (NULL != bc->th)
  {
    GNUNET_SERVER_notify_transmit_ready_cancel (bc->th);
    bc->th = NULL;
  }
  GNUNET_free (bc);
}


/* end of file gnunet-service-transport_blacklist.c */
