/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2012, 2014 Christian Grothoff (and other contributing authors)

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
 * @file statistics/gnunet-service-statistics.c
 * @brief program that tracks statistics
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_bio_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_disk_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_strings_lib.h"
#include "gnunet_time_lib.h"
#include "statistics.h"

/**
 * Watch entry.
 */
struct WatchEntry
{

  /**
   * Watch entries are kept in a linked list.
   */
  struct WatchEntry *next;

  /**
   * Watch entries are kept in a linked list.
   */
  struct WatchEntry *prev;

  /**
   * For which client is this watch entry?
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Last value we communicated to the client for this watch entry.
   */
  uint64_t last_value;

  /**
   * Unique watch number for this client and this watched value.
   */
  uint32_t wid;

  /**
   * Is last_value valid
   * #GNUNET_NO : last_value is n/a, #GNUNET_YES: last_value is valid
   */
  int last_value_set;

};


/**
 * We keep the statistics organized by subsystem for faster
 * lookup during SET operations.
 */
struct SubsystemEntry;


/**
 * Entry in the statistics list.
 */
struct StatsEntry
{
  /**
   * This is a linked list.
   */
  struct StatsEntry *next;

  /**
   * This is a linked list.
   */
  struct StatsEntry *prev;

  /**
   * Subsystem this entry belongs to.
   */
  struct SubsystemEntry *subsystem;

  /**
   * Name for the value stored by this entry, allocated at the end of
   * this struct.
   */
  const char *name;

  /**
   * Watch context for changes to this value, or NULL for none.
   */
  struct WatchEntry *we_head;

  /**
   * Watch context for changes to this value, or NULL for none.
   */
  struct WatchEntry *we_tail;

  /**
   * Our value.
   */
  uint64_t value;

  /**
   * Unique ID.
   */
  uint32_t uid;

  /**
   * Is this value persistent?
   */
  int persistent;

  /**
   * Is this value set?
   * #GNUNET_NO: value is n/a, #GNUNET_YES: value is valid
   */
  int set;

};


/**
 * We keep the statistics organized by subsystem for faster
 * lookup during SET operations.
 */
struct SubsystemEntry
{
  /**
   * Subsystems are kept in a DLL.
   */
  struct SubsystemEntry *next;

  /**
   * Subsystems are kept in a DLL.
   */
  struct SubsystemEntry *prev;

  /**
   * Head of list of values kept for this subsystem.
   */
  struct StatsEntry *stat_head;

  /**
   * Tail of list of values kept for this subsystem.
   */
  struct StatsEntry *stat_tail;

  /**
   * Name of the subsystem this entry is for, allocated at
   * the end of this struct, do not free().
   */
  const char *service;

};


/**
 * Client entry.
 */
struct ClientEntry
{
  /**
   * Corresponding server handle.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Which subsystem is this client writing to (SET/UPDATE)?
   */
  struct SubsystemEntry *subsystem;

  /**
   * Maximum watch ID used by this client so far.
   */
  uint32_t max_wid;

};


/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Head of linked list of subsystems with active statistics.
 */
static struct SubsystemEntry *sub_head;

/**
 * Tail of linked list of subsystems with active statistics.
 */
static struct SubsystemEntry *sub_tail;

/**
 * Number of connected clients.
 */
static unsigned int client_count;

/**
 * Handle to our server.
 */
static struct GNUNET_SERVER_Handle *srv;

/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Counter used to generate unique values.
 */
static uint32_t uidgen;

/**
 * Set to #GNUNET_YES if we are shutting down as soon as possible.
 */
static int in_shutdown;


/**
 * Inject a message to our server with a client of 'NULL'.
 *
 * @param cls the `struct GNUNET_SERVER_Handle`
 * @param client unused
 * @param msg message to inject
 */
static int
inject_message (void *cls,
                void *client,
                const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SERVER_Handle *server = cls;

  GNUNET_break (GNUNET_OK == GNUNET_SERVER_inject (server, NULL, msg));
  return GNUNET_OK;
}


/**
 * Load persistent values from disk.  Disk format is exactly the same
 * format that we also use for setting the values over the network.
 *
 * @param server handle to the server context
 */
static void
load (struct GNUNET_SERVER_Handle *server)
{
  char *fn;
  struct GNUNET_BIO_ReadHandle *rh;
  uint64_t fsize;
  char *buf;
  struct GNUNET_SERVER_MessageStreamTokenizer *mst;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               "STATISTICS",
                                               "DATABASE",
                                               &fn))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "STATISTICS",
                               "DATABASE");
    return;
  }
  if ( (GNUNET_OK !=
        GNUNET_DISK_file_size (fn,
                               &fsize,
                               GNUNET_NO,
                               GNUNET_YES)) ||
       (0 == fsize) )
  {
    GNUNET_free (fn);
    return;
  }
  buf = GNUNET_malloc (fsize);
  rh = GNUNET_BIO_read_open (fn);
  if (!rh)
  {
    GNUNET_free (buf);
    GNUNET_free (fn);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_BIO_read (rh,
                       fn,
                       buf,
                       fsize))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "read",
                              fn);
    GNUNET_break (GNUNET_OK ==
                  GNUNET_BIO_read_close (rh, NULL));
    GNUNET_free (buf);
    GNUNET_free (fn);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Loading %llu bytes of statistics from `%s'\n"),
              fsize, fn);
  mst = GNUNET_SERVER_mst_create (&inject_message,
                                  server);
  GNUNET_break (GNUNET_OK ==
                GNUNET_SERVER_mst_receive (mst, NULL,
                                           buf, fsize,
                                           GNUNET_YES,
                                           GNUNET_NO));
  GNUNET_SERVER_mst_destroy (mst);
  GNUNET_free (buf);
  GNUNET_break (GNUNET_OK ==
                GNUNET_BIO_read_close (rh,
                                       NULL));
  GNUNET_free (fn);
}


/**
 * Write persistent statistics to disk.
 */
static void
save ()
{
  struct SubsystemEntry *se;
  struct StatsEntry *pos;
  char *fn;
  struct GNUNET_BIO_WriteHandle *wh;
  uint16_t size;
  unsigned long long total;
  size_t nlen;
  size_t slen;
  struct GNUNET_STATISTICS_SetMessage *msg;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               "STATISTICS",
                                               "DATABASE",
                                               &fn))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "STATISTICS",
                               "DATABASE");
    return;
  }
  (void) GNUNET_DISK_directory_create_for_file (fn);
  wh = GNUNET_BIO_write_open (fn);
  total = 0;
  while (NULL != (se = sub_head))
  {
    GNUNET_CONTAINER_DLL_remove (sub_head,
                                 sub_tail,
                                 se);
    slen = strlen (se->service) + 1;
    while (NULL != (pos = se->stat_head))
    {
      GNUNET_CONTAINER_DLL_remove (se->stat_head,
                                   se->stat_tail,
                                   pos);
      if ((pos->persistent) && (NULL != wh))
      {
        nlen = strlen (pos->name) + 1;
        size = sizeof (struct GNUNET_STATISTICS_SetMessage) + nlen + slen;
        GNUNET_assert (size < UINT16_MAX);
        msg = GNUNET_malloc (size);

        msg->header.size = htons ((uint16_t) size);
        msg->header.type = htons (GNUNET_MESSAGE_TYPE_STATISTICS_SET);
        GNUNET_assert (nlen + slen ==
                       GNUNET_STRINGS_buffer_fill ((char *) &msg[1],
                                                   nlen + slen,
                                                   2,
                                                   se->service,
                                                   pos->name));
        msg->flags = htonl (pos->persistent ? GNUNET_STATISTICS_SETFLAG_PERSISTENT : 0);
        msg->value = GNUNET_htonll (pos->value);
        if (GNUNET_OK != GNUNET_BIO_write (wh,
                                           msg,
                                           size))
        {
          GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                    "write",
                                    fn);
          if (GNUNET_OK != GNUNET_BIO_write_close (wh))
            GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                      "close",
                                      fn);
          wh = NULL;
        }
        else
        {
          total += size;
        }
        GNUNET_free (msg);
      }
      GNUNET_free (pos);
    }
    GNUNET_free (se);
  }
  if (NULL != wh)
  {
    if (GNUNET_OK !=
        GNUNET_BIO_write_close (wh))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                "close",
                                fn);
    if (0 == total)
      GNUNET_break (0 ==
                    UNLINK (fn));
    else
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Wrote %llu bytes of statistics to `%s'\n"),
                  total,
                  fn);
  }
  GNUNET_free_non_null (fn);
}


/**
 * Transmit the given stats value.
 *
 * @param client receiver of the value
 * @param e value to transmit
 */
static void
transmit (struct GNUNET_SERVER_Client *client,
          const struct StatsEntry *e)
{
  struct GNUNET_STATISTICS_ReplyMessage *m;
  size_t size;

  size = sizeof (struct GNUNET_STATISTICS_ReplyMessage) +
    strlen (e->subsystem->service) + 1 +
    strlen (e->name) + 1;
  GNUNET_assert (size < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  m = GNUNET_malloc (size);
  m->header.type = htons (GNUNET_MESSAGE_TYPE_STATISTICS_VALUE);
  m->header.size = htons (size);
  m->uid = htonl (e->uid);
  if (e->persistent)
    m->uid |= htonl (GNUNET_STATISTICS_PERSIST_BIT);
  m->value = GNUNET_htonll (e->value);
  size -= sizeof (struct GNUNET_STATISTICS_ReplyMessage);
  GNUNET_assert (size ==
                 GNUNET_STRINGS_buffer_fill ((char *) &m[1],
                                             size,
                                             2,
                                             e->subsystem->service,
                                             e->name));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting value for `%s:%s' (%d): %llu\n",
              e->subsystem->service,
              e->name,
              e->persistent,
              e->value);
  GNUNET_SERVER_notification_context_unicast (nc, client, &m->header,
                                              GNUNET_NO);
  GNUNET_free (m);
}


/**
 * Find a client entry for the given client handle, or create one.
 *
 * @param client handle to match
 * @return corresponding client entry struct
 */
static struct ClientEntry *
make_client_entry (struct GNUNET_SERVER_Client *client)
{
  struct ClientEntry *ce;

  ce = GNUNET_SERVER_client_get_user_context (client,
                                              struct ClientEntry);
  if (NULL != ce)
    return ce;
  if (NULL == nc)
  {
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return NULL;
  }
  ce = GNUNET_new (struct ClientEntry);
  ce->client = client;
  GNUNET_SERVER_client_set_user_context (client, ce);
  client_count++;
  GNUNET_SERVER_notification_context_add (nc, client);
  return ce;
}


/**
 * Handle GET-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static void
handle_get (void *cls,
            struct GNUNET_SERVER_Client *client,
            const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MessageHeader end;
  const char *service;
  const char *name;
  size_t slen;
  size_t nlen;
  struct SubsystemEntry *se;
  struct StatsEntry *pos;
  size_t size;

  if (NULL == make_client_entry (client))
    return; /* new client during shutdown */
  size = ntohs (message->size) - sizeof (struct GNUNET_MessageHeader);
  if (size !=
      GNUNET_STRINGS_buffer_tokenize ((const char *) &message[1],
                                      size,
                                      2,
                                      &service,
                                      &name))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
  slen = strlen (service);
  nlen = strlen (name);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received request for statistics on `%s:%s'\n",
              slen ? service : "*",
              nlen ? name : "*");
  for (se = sub_head; NULL != se; se = se->next)
  {
    if (! ( (0 == slen) ||
            (0 == strcmp (service, se->service))) )
      continue;
    for (pos = se->stat_head; NULL != pos; pos = pos->next)
    {
      if  (! ( (0 == nlen) ||
               (0 == strcmp (name, pos->name))) )
        continue;
      transmit (client, pos);
    }
  }
  end.size = htons (sizeof (struct GNUNET_MessageHeader));
  end.type = htons (GNUNET_MESSAGE_TYPE_STATISTICS_END);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              client,
                                              &end,
                                              GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Notify all clients listening about a change to a value.
 *
 * @param se value that changed
 */
static void
notify_change (struct StatsEntry *se)
{
  struct GNUNET_STATISTICS_WatchValueMessage wvm;
  struct WatchEntry *pos;

  for (pos = se->we_head; NULL != pos; pos = pos->next)
  {
    if (GNUNET_YES == pos->last_value_set)
    {
      if (pos->last_value == se->value)
        continue;
    }
    else
    {
      pos->last_value_set = GNUNET_YES;
    }
    wvm.header.type = htons (GNUNET_MESSAGE_TYPE_STATISTICS_WATCH_VALUE);
    wvm.header.size =
      htons (sizeof (struct GNUNET_STATISTICS_WatchValueMessage));
    wvm.flags = htonl (se->persistent ? GNUNET_STATISTICS_SETFLAG_PERSISTENT : 0);
    wvm.wid = htonl (pos->wid);
    wvm.reserved = htonl (0);
    wvm.value = GNUNET_htonll (se->value);
    GNUNET_SERVER_notification_context_unicast (nc,
                                                pos->client,
                                                &wvm.header,
						GNUNET_NO);
    pos->last_value = se->value;
  }
}


/**
 * Find the subsystem entry of the given name for the specified client.
 *
 * @param ce client looking for the subsystem, may contain a hint
 *           to find the entry faster, can be NULL
 * @param service name of the subsystem to look for
 * @return subsystem entry, never NULL (subsystem entry is created if necessary)
 */
static struct SubsystemEntry *
find_subsystem_entry (struct ClientEntry *ce,
                      const char *service)
{
  size_t slen;
  struct SubsystemEntry *se;

  if (NULL != ce)
    se = ce->subsystem;
  else
    se = NULL;
  if ( (NULL == se) ||
       (0 != strcmp (service,
                     se->service)) )
  {
    for (se = sub_head; NULL != se; se = se->next)
      if (0 == strcmp (service,
                       se->service))
        break;
    if (NULL != ce)
      ce->subsystem = se;
  }
  if (NULL != se)
    return se;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Allocating new subsystem entry `%s'\n",
              service);
  slen = strlen (service) + 1;
  se = GNUNET_malloc (sizeof (struct SubsystemEntry) +
                      slen);
  memcpy (&se[1],
          service,
          slen);
  se->service = (const char *) &se[1];
  GNUNET_CONTAINER_DLL_insert (sub_head,
                               sub_tail,
                               se);
  if (NULL != ce)
    ce->subsystem = se;
  return se;
}


/**
 * Find the statistics entry of the given subsystem.
 *
 * @param subsystem subsystem to look in
 * @param name name of the entry to look for
 * @return statistis entry, or NULL if not found
 */
static struct StatsEntry *
find_stat_entry (struct SubsystemEntry *se,
                 const char *name)
{
  struct StatsEntry *pos;

  for (pos = se->stat_head; NULL != pos; pos = pos->next)
    if  (0 == strcmp (name, pos->name))
      return pos;
  return NULL;
}


/**
 * Handle SET-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_set (void *cls,
            struct GNUNET_SERVER_Client *client,
            const struct GNUNET_MessageHeader *message)
{
  const char *service;
  const char *name;
  size_t nlen;
  uint16_t msize;
  uint16_t size;
  const struct GNUNET_STATISTICS_SetMessage *msg;
  struct SubsystemEntry *se;
  struct ClientEntry *ce;
  struct StatsEntry *pos;
  uint32_t flags;
  uint64_t value;
  int64_t delta;
  int changed;
  int initial_set;

  ce = NULL;
  if ( (NULL != client) &&
       (NULL == (ce = make_client_entry (client))) )
    return; /* new client during shutdown */
  msize = ntohs (message->size);
  if (msize < sizeof (struct GNUNET_STATISTICS_SetMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  size = msize - sizeof (struct GNUNET_STATISTICS_SetMessage);
  msg = (const struct GNUNET_STATISTICS_SetMessage *) message;
  if (size !=
      GNUNET_STRINGS_buffer_tokenize ((const char *) &msg[1],
                                      size,
                                      2,
                                      &service,
                                      &name))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
  se = find_subsystem_entry (ce, service);
  flags = ntohl (msg->flags);
  value = GNUNET_ntohll (msg->value);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received request to update statistic on `%s:%s' (%u) to/by %llu\n",
              service,
              name,
              (unsigned int) flags,
              (unsigned long long) value);
  pos = find_stat_entry (se, name);
  if (NULL != pos)
  {
    initial_set = 0;
    if (0 == (flags & GNUNET_STATISTICS_SETFLAG_RELATIVE))
    {
      changed = (pos->value != value);
      pos->value = value;
    }
    else
    {
      delta = (int64_t) value;
      if ((delta < 0) && (pos->value < -delta))
      {
        changed = (0 != pos->value);
        pos->value = 0;
      }
      else
      {
        changed = (0 != delta);
        GNUNET_break ( (delta <= 0) ||
                       (pos->value + delta > pos->value) );
        pos->value += delta;
      }
    }
    if (GNUNET_NO == pos->set)
    {
      pos->set = GNUNET_YES;
      initial_set = 1;
    }
    pos->persistent = (0 != (flags & GNUNET_STATISTICS_SETFLAG_PERSISTENT));
    if (pos != se->stat_head)
    {
      /* move to front for faster setting next time! */
      GNUNET_CONTAINER_DLL_remove (se->stat_head,
                                   se->stat_tail,
                                   pos);
      GNUNET_CONTAINER_DLL_insert (se->stat_head,
                                   se->stat_tail,
                                   pos);
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Statistic `%s:%s' updated to value %llu (%d).\n",
                service,
                name,
                pos->value,
                pos->persistent);
    if ( (changed) ||
         (1 == initial_set) )
      notify_change (pos);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_OK);
    return;
  }
  /* not found, create a new entry */
  nlen = strlen (name) + 1;
  pos = GNUNET_malloc (sizeof (struct StatsEntry) + nlen);
  memcpy (&pos[1],
          name,
          nlen);
  pos->name = (const char *) &pos[1];
  pos->subsystem = se;
  if ( (0 == (flags & GNUNET_STATISTICS_SETFLAG_RELATIVE)) ||
       (0 < (int64_t) GNUNET_ntohll (msg->value)) )
  {
    pos->value = GNUNET_ntohll (msg->value);
    pos->set = GNUNET_YES;
  }
  else
  {
    pos->set = GNUNET_NO;
  }
  pos->uid = uidgen++;
  pos->persistent = (0 != (flags & GNUNET_STATISTICS_SETFLAG_PERSISTENT));
  GNUNET_CONTAINER_DLL_insert (se->stat_head,
                               se->stat_tail,
                               pos);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New statistic on `%s:%s' with value %llu created.\n",
              service,
              name,
              pos->value);
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
}


/**
 * Handle WATCH-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_watch (void *cls,
              struct GNUNET_SERVER_Client *client,
              const struct GNUNET_MessageHeader *message)
{
  const char *service;
  const char *name;
  uint16_t msize;
  uint16_t size;
  struct SubsystemEntry *se;
  struct StatsEntry *pos;
  struct ClientEntry *ce;
  struct WatchEntry *we;
  size_t nlen;

  if (NULL == nc)
  {
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
  GNUNET_SERVER_client_mark_monitor (client);
  ce = make_client_entry (client);
  msize = ntohs (message->size);
  if (msize < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  size = msize - sizeof (struct GNUNET_MessageHeader);
  if (size !=
      GNUNET_STRINGS_buffer_tokenize ((const char *) &message[1],
                                      size,
                                      2,
                                      &service,
                                      &name))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received request to watch statistic on `%s:%s'\n",
              service,
              name);
  se = find_subsystem_entry (ce, service);
  pos = find_stat_entry (se, name);
  if (NULL == pos)
  {
    nlen = strlen (name) + 1;
    pos = GNUNET_malloc (sizeof (struct StatsEntry) +
                         nlen);
    memcpy (&pos[1], name, nlen);
    pos->name = (const char *) &pos[1];
    pos->subsystem = se;
    GNUNET_CONTAINER_DLL_insert (se->stat_head,
                                 se->stat_tail,
                                 pos);
    pos->uid = uidgen++;
    pos->set = GNUNET_NO;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "New statistic on `%s:%s' with value %llu created.\n",
                service,
                name,
                pos->value);
  }
  we = GNUNET_new (struct WatchEntry);
  we->client = client;
  we->last_value_set = GNUNET_NO;
  we->wid = ce->max_wid++;
  GNUNET_CONTAINER_DLL_insert (pos->we_head,
                               pos->we_tail,
                               we);
  if (0 != pos->value)
    notify_change (pos);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Actually perform the shutdown.
 */
static void
do_shutdown ()
{
  struct WatchEntry *we;
  struct StatsEntry *pos;
  struct SubsystemEntry *se;

  if (NULL == nc)
    return;
  save ();
  GNUNET_SERVER_notification_context_destroy (nc);
  nc = NULL;
  GNUNET_assert (0 == client_count);
  while (NULL != (se = sub_head))
  {
    GNUNET_CONTAINER_DLL_remove (sub_head,
                                 sub_tail,
                                 se);
    while (NULL != (pos = se->stat_head))
    {
      GNUNET_CONTAINER_DLL_remove (se->stat_head,
                                   se->stat_tail,
                                   pos);
      while (NULL != (we = pos->we_head))
      {
        GNUNET_break (0);
        GNUNET_CONTAINER_DLL_remove (pos->we_head,
                                     pos->we_tail,
                                     we);
        GNUNET_free (we);
      }
      GNUNET_free (pos);
    }
    GNUNET_free (se);
  }
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  in_shutdown = GNUNET_YES;
  if (0 != client_count)
    return;
  do_shutdown ();
}


/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
                          struct GNUNET_SERVER_Client *client)
{
  struct ClientEntry *ce;
  struct WatchEntry *we;
  struct WatchEntry *wen;
  struct StatsEntry *pos;
  struct SubsystemEntry *se;

  if (NULL == client)
    return;
  ce = GNUNET_SERVER_client_get_user_context (client,
                                              struct ClientEntry);
  if (NULL == ce)
    return;
  GNUNET_SERVER_client_set_user_context (client,
                                         NULL);
  client_count--;
  for (se = sub_head; NULL != se; se = se->next)
  {
    for (pos = se->stat_head; NULL != pos; pos = pos->next)
    {
      wen = pos->we_head;
      while (NULL != (we = wen))
      {
        wen = we->next;
        if (we->client != client)
          continue;
        GNUNET_CONTAINER_DLL_remove (pos->we_head,
                                     pos->we_tail,
                                     we);
        GNUNET_free (we);
      }
    }
  }
  if ( (0 == client_count) &&
       (GNUNET_YES == in_shutdown) )
    do_shutdown ();
}


/**
 * Process statistics requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_set, NULL, GNUNET_MESSAGE_TYPE_STATISTICS_SET, 0},
    {&handle_get, NULL, GNUNET_MESSAGE_TYPE_STATISTICS_GET, 0},
    {&handle_watch, NULL, GNUNET_MESSAGE_TYPE_STATISTICS_WATCH, 0},
    {NULL, NULL, 0, 0}
  };
  cfg = c;
  srv = server;
  GNUNET_SERVER_add_handlers (server,
                              handlers);
  nc = GNUNET_SERVER_notification_context_create (server, 16);
  GNUNET_SERVER_disconnect_notify (server,
                                   &handle_client_disconnect,
                                   NULL);
  load (server);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task,
                                NULL);
}


/**
 * The main function for the statistics service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "statistics",
                              GNUNET_SERVICE_OPTION_SOFT_SHUTDOWN,
                              &run, NULL)) ? 0 : 1;
}

#ifdef LINUX
#include <malloc.h>

/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor))
GNUNET_STATISTICS_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}
#endif


/* end of gnunet-service-statistics.c */
