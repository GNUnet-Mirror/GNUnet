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
   * Set to GNUNET_YES if we're currently waiting for a reply.
   */
  int waiting_for_reply;

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
   * Closure for cont.
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
  GNUNET_SCHEDULER_TaskIdentifier task;

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
static struct GNUNET_CONTAINER_MultiHashMap *blacklist;


/**
 * Perform next action in the blacklist check.
 *
 * @param cls the 'struct BlacklistCheck*'
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

  if (client == NULL)
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
      if (bc->task == GNUNET_SCHEDULER_NO_TASK)
        bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check, bc);
      break;
    }
    GNUNET_CONTAINER_DLL_remove (bl_head, bl_tail, bl);
    GNUNET_SERVER_client_drop (bl->client);
    GNUNET_free (bl);
    break;
  }
}


/**
 * Read the blacklist file, containing transport:peer entries.
 * Provided the transport is loaded, set up hashmap with these
 * entries to blacklist peers by transport.
 *
 */
static void
read_blacklist_file ()
{
  char *fn;
  char *data;
  size_t pos;
  size_t colon_pos;
  int tsize;
  struct GNUNET_PeerIdentity pid;
  uint64_t fsize;
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  unsigned int entries_found;
  char *transport_name;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (GST_cfg, "TRANSPORT",
                                               "BLACKLIST_FILE", &fn))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Option `%s' in section `%s' not specified!\n",
                "BLACKLIST_FILE", "TRANSPORT");
    return;
  }
  if (GNUNET_OK != GNUNET_DISK_file_test (fn))
    GNUNET_DISK_fn_write (fn, NULL, 0,
                          GNUNET_DISK_PERM_USER_READ |
                          GNUNET_DISK_PERM_USER_WRITE);
  if (GNUNET_OK != GNUNET_DISK_file_size (fn,
      &fsize, GNUNET_NO, GNUNET_YES))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not read blacklist file `%s'\n"), fn);
    GNUNET_free (fn);
    return;
  }
  if (fsize == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Blacklist file `%s' is empty.\n"),
                fn);
    GNUNET_free (fn);
    return;
  }
  /* FIXME: use mmap */
  data = GNUNET_malloc_large (fsize);
  GNUNET_assert (data != NULL);
  if (fsize != GNUNET_DISK_fn_read (fn, data, fsize))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to read blacklist from `%s'\n"), fn);
    GNUNET_free (fn);
    GNUNET_free (data);
    return;
  }
  entries_found = 0;
  pos = 0;
  while ((pos < fsize) && isspace ((unsigned char) data[pos]))
    pos++;
  while ((fsize >= sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded)) &&
         (pos <=
          fsize - sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded)))
  {
    colon_pos = pos;
    while ((colon_pos < fsize) && (data[colon_pos] != ':') &&
           (!isspace ((unsigned char) data[colon_pos])))
      colon_pos++;
    if (colon_pos >= fsize)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Syntax error in blacklist file at offset %llu, giving up!\n"),
                  (unsigned long long) colon_pos);
      GNUNET_free (fn);
      GNUNET_free (data);
      return;
    }

    if (isspace ((unsigned char) data[colon_pos]))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Syntax error in blacklist file at offset %llu, skipping bytes.\n"),
                  (unsigned long long) colon_pos);
      pos = colon_pos;
      while ((pos < fsize) && isspace ((unsigned char) data[pos]))
        pos++;
      continue;
    }
    tsize = colon_pos - pos;
    if ((pos >= fsize) || (pos + tsize >= fsize) ||
        (tsize == 0))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Syntax error in blacklist file at offset %llu, giving up!\n"),
                  (unsigned long long) colon_pos);
      GNUNET_free (fn);
      GNUNET_free (data);
      return;
    }

    if (tsize < 1)
      continue;

    transport_name = GNUNET_malloc (tsize + 1);
    memcpy (transport_name, &data[pos], tsize);
    pos = colon_pos + 1;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Read transport name `%s' in blacklist file.\n",
                transport_name);
    memcpy (&enc, &data[pos], sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded));
    if (!isspace
        ((unsigned char)
         enc.encoding[sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1]))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Syntax error in blacklist file at offset %llu, skipping bytes.\n"),
                  (unsigned long long) pos);
      pos++;
      while ((pos < fsize) && (!isspace ((unsigned char) data[pos])))
        pos++;
      GNUNET_free_non_null (transport_name);
      continue;
    }
    enc.encoding[sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1] = '\0';
    if (GNUNET_OK !=
        GNUNET_CRYPTO_hash_from_string ((char *) &enc, &pid.hashPubKey))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Syntax error in blacklist file at offset %llu, skipping bytes `%s'.\n"),
                  (unsigned long long) pos, &enc);
    }
    else
    {
      if (0 !=
          memcmp (&pid, &GST_my_identity, sizeof (struct GNUNET_PeerIdentity)))
      {
        entries_found++;
        GST_blacklist_add_peer (&pid, transport_name);
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _("Found myself `%s' in blacklist (useless, ignored)\n"),
                    GNUNET_i2s (&pid));
      }
    }
    pos = pos + sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded);
    GNUNET_free_non_null (transport_name);
    while ((pos < fsize) && isspace ((unsigned char) data[pos]))
      pos++;
  }
  GNUNET_STATISTICS_update (GST_stats, "# Transport entries blacklisted",
                            entries_found, GNUNET_NO);
  GNUNET_free (data);
  GNUNET_free (fn);
}


/**
 * Start blacklist subsystem.
 *
 * @param server server used to accept clients from
 */
void
GST_blacklist_start (struct GNUNET_SERVER_Handle *server)
{
  read_blacklist_file ();
  GNUNET_SERVER_disconnect_notify (server, &client_disconnect_notification,
                                   NULL);
}


/**
 * Free the given entry in the blacklist.
 *
 * @param cls unused
 * @param key host identity (unused)
 * @param value the blacklist entry
 * @return GNUNET_OK (continue to iterate)
 */
static int
free_blacklist_entry (void *cls, const GNUNET_HashCode * key, void *value)
{
  char *be = value;

  GNUNET_free (be);
  return GNUNET_OK;
}


/**
 * Stop blacklist subsystem.
 */
void
GST_blacklist_stop ()
{
  if (NULL != blacklist)
  {
    GNUNET_CONTAINER_multihashmap_iterate (blacklist, &free_blacklist_entry,
                                           NULL);
    GNUNET_CONTAINER_multihashmap_destroy (blacklist);
    blacklist = NULL;
  }
}


/**
 * Transmit blacklist query to the client.
 *
 * @param cls the 'struct GST_BlacklistCheck'
 * @param size number of bytes allowed
 * @param buf where to copy the message
 * @return number of bytes copied to buf
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
    GNUNET_assert (bc->task == GNUNET_SCHEDULER_NO_TASK);
    bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check, bc);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to send blacklist test for peer `%s' to client\n",
                GNUNET_i2s (&bc->peer));
    return 0;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending blacklist test for peer `%s' to client\n",
              GNUNET_i2s (&bc->peer));
  bl = bc->bl_pos;
  bm.header.size = htons (sizeof (struct BlacklistMessage));
  bm.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_QUERY);
  bm.is_allowed = htonl (0);
  bm.peer = bc->peer;
  memcpy (buf, &bm, sizeof (bm));
  GNUNET_SERVER_receive_done (bl->client, GNUNET_OK);
  bl->waiting_for_reply = GNUNET_YES;
  return sizeof (bm);
}


/**
 * Perform next action in the blacklist check.
 *
 * @param cls the 'struct GST_BlacklistCheck*'
 * @param tc unused
 */
static void
do_blacklist_check (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GST_BlacklistCheck *bc = cls;
  struct Blacklisters *bl;

  bc->task = GNUNET_SCHEDULER_NO_TASK;
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
 * @param allowed GNUNET_OK if we can keep it,
 *                GNUNET_NO if we must shutdown the connection
 */
static void
confirm_or_drop_neighbour (void *cls, const struct GNUNET_PeerIdentity *peer,
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
 * @param cls the 'struct TestConnectionContest'
 * @param neighbour neighbour's identity
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 * @param address the address
 */
static void
test_connection_ok (void *cls, const struct GNUNET_PeerIdentity *neighbour,
                    const struct GNUNET_ATS_Information *ats,
                    uint32_t ats_count,
                    const struct GNUNET_HELLO_Address *address)
{
  struct TestConnectionContext *tcc = cls;
  struct GST_BlacklistCheck *bc;

  bc = GNUNET_malloc (sizeof (struct GST_BlacklistCheck));
  GNUNET_CONTAINER_DLL_insert (bc_head, bc_tail, bc);
  bc->peer = *neighbour;
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

  bl = bl_head;
  while (bl != NULL)
  {
    if (bl->client == client)
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    bl = bl->next;
  }
  GNUNET_SERVER_client_mark_monitor (client);
  bl = GNUNET_malloc (sizeof (struct Blacklisters));
  bl->client = client;
  GNUNET_SERVER_client_keep (client);
  GNUNET_CONTAINER_DLL_insert_after (bl_head, bl_tail, bl_tail, bl);

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
  if (bl == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Blacklist client disconnected\n");
    /* FIXME: other error handling here!? */
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  bc = bl->bc;
  bl->bc = NULL;
  bl->waiting_for_reply = GNUNET_NO;
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
      GNUNET_free (bc);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Blacklist check succeeded, continuing with checks\n");
      bc->bl_pos = bc->bl_pos->next;
      bc->task = GNUNET_SCHEDULER_add_now (&do_blacklist_check, bc);
    }
  }
  /* check if any other bc's are waiting for this blacklister */
  bc = bc_head;
  for (bc = bc_head; bc != NULL; bc = bc->next)
    if ((bc->bl_pos == bl) && (GNUNET_SCHEDULER_NO_TASK == bc->task))
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding peer `%s' with plugin `%s' to blacklist\n",
              GNUNET_i2s (peer), transport_name);
  if (blacklist == NULL)
    blacklist =
        GNUNET_CONTAINER_multihashmap_create (TRANSPORT_BLACKLIST_HT_SIZE);
  GNUNET_CONTAINER_multihashmap_put (blacklist, &peer->hashPubKey,
                                     GNUNET_strdup (transport_name),
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
}


/**
 * Test if the given blacklist entry matches.  If so,
 * abort the iteration.
 *
 * @param cls the transport name to match (const char*)
 * @param key the key (unused)
 * @param value the 'char *' (name of a blacklisted transport)
 * @return GNUNET_OK if the entry does not match, GNUNET_NO if it matches
 */
static int
test_blacklisted (void *cls, const GNUNET_HashCode * key, void *value)
{
  const char *transport_name = cls;
  char *be = value;

  /* blacklist check for specific no specific transport*/
  if (transport_name == NULL)
    return GNUNET_NO;

  /* blacklist check for specific transport */
  if (0 == strcmp (transport_name, be))
    return GNUNET_NO;           /* abort iteration! */
  return GNUNET_OK;
}


/**
 * Test if a peer/transport combination is blacklisted.
 *
 * @param peer the identity of the peer to test
 * @param transport_name name of the transport to test, never NULL
 * @param cont function to call with result
 * @param cont_cls closure for 'cont'
 * @return handle to the blacklist check, NULL if the decision
 *        was made instantly and 'cont' was already called
 */
struct GST_BlacklistCheck *
GST_blacklist_test_allowed (const struct GNUNET_PeerIdentity *peer,
                            const char *transport_name,
                            GST_BlacklistTestContinuation cont, void *cont_cls)
{
  struct GST_BlacklistCheck *bc;

  GNUNET_assert (peer != NULL);

  if ((blacklist != NULL) &&
      (GNUNET_SYSERR ==
       GNUNET_CONTAINER_multihashmap_get_multiple (blacklist, &peer->hashPubKey,
                                                   &test_blacklisted,
                                                   (void *) transport_name)))
  {
    /* disallowed by config, disapprove instantly */
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# disconnects due to blacklist"),
                              1, GNUNET_NO);
    if (cont != NULL)
      cont (cont_cls, peer, GNUNET_NO);
    return NULL;
  }

  if (bl_head == NULL)
  {
    /* no blacklist clients, approve instantly */
    if (cont != NULL)
      cont (cont_cls, peer, GNUNET_OK);
    return NULL;
  }

  /* need to query blacklist clients */
  bc = GNUNET_malloc (sizeof (struct GST_BlacklistCheck));
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
  GNUNET_CONTAINER_DLL_remove (bc_head, bc_tail, bc);
  if (bc->bl_pos != NULL)
  {
    if (bc->bl_pos->bc == bc)
    {
      /* we're at the head of the queue, remove us! */
      bc->bl_pos->bc = NULL;
    }
  }
  if (GNUNET_SCHEDULER_NO_TASK != bc->task)
  {
    GNUNET_SCHEDULER_cancel (bc->task);
    bc->task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != bc->th)
  {
    GNUNET_SERVER_notify_transmit_ready_cancel (bc->th);
    bc->th = NULL;
  }
  GNUNET_free (bc);
}


/* end of file gnunet-service-transport_blacklist.c */
