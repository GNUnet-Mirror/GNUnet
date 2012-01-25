/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2012 Christian Grothoff (and other contributing authors)

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

  struct WatchEntry *next;

  struct WatchEntry *prev;

  struct GNUNET_SERVER_Client *client;

  uint64_t last_value;

  uint32_t wid;

};


/**
 * Client entry.
 */
struct ClientEntry
{

  struct ClientEntry *next;

  struct ClientEntry *prev;

  struct GNUNET_SERVER_Client *client;

  uint32_t max_wid;

};

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
   * Name of the service, points into the
   * middle of msg.
   */
  const char *service;

  /**
   * Name for the value, points into
   * the middle of msg.
   */
  const char *name;

  /**
   * Message that can be used to set this value,
   * stored at the end of the memory used by
   * this struct.
   */
  struct GNUNET_STATISTICS_SetMessage *msg;

  /**
   * Watch context for changes to this
   * value, or NULL for none.
   */
  struct WatchEntry *we_head;

  /**
   * Watch context for changes to this
   * value, or NULL for none.
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

};

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Linked list of our active statistics.
 */
static struct StatsEntry *start;

static struct ClientEntry *client_head;

static struct ClientEntry *client_tail;

/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Counter used to generate unique values.
 */
static uint32_t uidgen;


static void
inject_message (void *cls, void *client, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SERVER_Handle *server = cls;

  GNUNET_break (GNUNET_OK == GNUNET_SERVER_inject (server, NULL, msg));
}


/**
 * Load persistent values from disk.  Disk format is
 * exactly the same format that we also use for
 * setting the values over the network.
 *
 * @param server handle to the server context
 */
static void
load (struct GNUNET_SERVER_Handle *server)
{
  char *fn;
  struct GNUNET_BIO_ReadHandle *rh;
  struct stat sb;
  char *buf;
  struct GNUNET_SERVER_MessageStreamTokenizer *mst;
  char *emsg;

  fn = GNUNET_DISK_get_home_filename (cfg, "statistics", "statistics.data",
                                      NULL);
  if (fn == NULL)
    return;
  if ((0 != stat (fn, &sb)) || (sb.st_size == 0))
  {
    GNUNET_free (fn);
    return;
  }
  buf = GNUNET_malloc (sb.st_size);
  rh = GNUNET_BIO_read_open (fn);
  if (!rh)
  {
    GNUNET_free (buf);
    GNUNET_free (fn);
    return;
  }
  if (GNUNET_OK != GNUNET_BIO_read (rh, fn, buf, sb.st_size))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "read", fn);
    GNUNET_break (GNUNET_OK == GNUNET_BIO_read_close (rh, &emsg));
    GNUNET_free (buf);
    GNUNET_free_non_null (emsg);
    GNUNET_free (fn);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Loading %llu bytes of statistics from `%s'\n"),
              (unsigned long long) sb.st_size, fn);
  mst = GNUNET_SERVER_mst_create (&inject_message, server);
  GNUNET_break (GNUNET_OK ==
                GNUNET_SERVER_mst_receive (mst, NULL, buf, sb.st_size,
                                           GNUNET_YES, GNUNET_NO));
  GNUNET_SERVER_mst_destroy (mst);
  GNUNET_free (buf);
  GNUNET_break (GNUNET_OK == GNUNET_BIO_read_close (rh, &emsg));
  GNUNET_free_non_null (emsg);
  GNUNET_free (fn);
}

/**
 * Write persistent statistics to disk.
 */
static void
save ()
{
  struct StatsEntry *pos;
  char *fn;
  struct GNUNET_BIO_WriteHandle *wh;
  
  uint16_t size;
  unsigned long long total;

  wh = NULL;
  fn = GNUNET_DISK_get_home_filename (cfg, "statistics", "statistics.data",
                                      NULL);
  if (fn != NULL)
    wh = GNUNET_BIO_write_open (fn);
  total = 0;
  while (NULL != (pos = start))
  {
    start = pos->next;
    if ((pos->persistent) && (NULL != wh))
    {
      size = htons (pos->msg->header.size);
      if (GNUNET_OK != GNUNET_BIO_write (wh, pos->msg, size))
      {
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "write", fn);
        if (GNUNET_OK != GNUNET_BIO_write_close (wh))
	  GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "close", fn);
        wh = NULL;
      }
      else
        total += size;
    }
    GNUNET_free (pos);
  }
  if (NULL != wh)
  {
    if (GNUNET_OK != GNUNET_BIO_write_close (wh))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "close", fn);
    if (total == 0)
      GNUNET_break (0 == UNLINK (fn));
    else
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Wrote %llu bytes of statistics to `%s'\n"), total, fn);
  }
  GNUNET_free_non_null (fn);
}


/**
 * Transmit the given stats value.
 */
static void
transmit (struct GNUNET_SERVER_Client *client, const struct StatsEntry *e)
{
  struct GNUNET_STATISTICS_ReplyMessage *m;
  size_t size;

  size =
      sizeof (struct GNUNET_STATISTICS_ReplyMessage) + strlen (e->service) + 1 +
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
                 GNUNET_STRINGS_buffer_fill ((char *) &m[1], size, 2,
                                             e->service, e->name));
#if DEBUG_STATISTICS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting value for `%s:%s' (%d): %llu\n", e->service,
              e->name, e->persistent, e->value);
#endif
  GNUNET_SERVER_notification_context_unicast (nc, client, &m->header,
                                              GNUNET_NO);
  GNUNET_free (m);
}


/**
 * Does this entry match the request?
 */
static int
matches (const struct StatsEntry *e, const char *service, const char *name)
{
  return ((0 == strlen (service)) || (0 == strcmp (service, e->service))) &&
      ((0 == strlen (name)) || (0 == strcmp (name, e->name)));
}


static struct ClientEntry *
make_client_entry (struct GNUNET_SERVER_Client *client)
{
  struct ClientEntry *ce;

  GNUNET_assert (client != NULL);
  ce = client_head;
  while (ce != NULL)
  {
    if (ce->client == client)
      return ce;
    ce = ce->next;
  }
  ce = GNUNET_malloc (sizeof (struct ClientEntry));
  ce->client = client;
  GNUNET_SERVER_client_keep (client);
  GNUNET_CONTAINER_DLL_insert (client_head, client_tail, ce);
  GNUNET_SERVER_notification_context_add (nc, client);
  return ce;
}


/**
 * Handle GET-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static void
handle_get (void *cls, struct GNUNET_SERVER_Client *client,
            const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MessageHeader end;
  char *service;
  char *name;
  struct StatsEntry *pos;
  size_t size;

  if (client != NULL)
    make_client_entry (client);
  size = ntohs (message->size) - sizeof (struct GNUNET_MessageHeader);
  if (size !=
      GNUNET_STRINGS_buffer_tokenize ((const char *) &message[1], size, 2,
                                      &service, &name))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
#if DEBUG_STATISTICS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received request for statistics on `%s:%s'\n",
              strlen (service) ? service : "*", strlen (name) ? name : "*");
#endif
  pos = start;
  while (pos != NULL)
  {
    if (matches (pos, service, name))
      transmit (client, pos);
    pos = pos->next;
  }
  end.size = htons (sizeof (struct GNUNET_MessageHeader));
  end.type = htons (GNUNET_MESSAGE_TYPE_STATISTICS_END);
  GNUNET_SERVER_notification_context_unicast (nc, client, &end, GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
notify_change (struct StatsEntry *se)
{
  struct GNUNET_STATISTICS_WatchValueMessage wvm;
  struct WatchEntry *pos;

  pos = se->we_head;
  while (pos != NULL)
  {
    if (pos->last_value != se->value)
    {
      wvm.header.type = htons (GNUNET_MESSAGE_TYPE_STATISTICS_WATCH_VALUE);
      wvm.header.size =
          htons (sizeof (struct GNUNET_STATISTICS_WatchValueMessage));
      wvm.flags = htonl (se->persistent ? GNUNET_STATISTICS_PERSIST_BIT : 0);
      wvm.wid = htonl (pos->wid);
      wvm.reserved = htonl (0);
      wvm.value = GNUNET_htonll (se->value);
      GNUNET_SERVER_notification_context_unicast (nc, pos->client, &wvm.header,
                                                  GNUNET_NO);
      pos->last_value = se->value;
    }
    pos = pos->next;
  }
}

/**
 * Handle SET-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_set (void *cls, struct GNUNET_SERVER_Client *client,
            const struct GNUNET_MessageHeader *message)
{
  char *service;
  char *name;
  uint16_t msize;
  uint16_t size;
  const struct GNUNET_STATISTICS_SetMessage *msg;
  struct StatsEntry *pos;
  struct StatsEntry *prev;
  uint32_t flags;
  uint64_t value;
  int64_t delta;
  int changed;

  if (client != NULL)
    make_client_entry (client);
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
      GNUNET_STRINGS_buffer_tokenize ((const char *) &msg[1], size, 2, &service,
                                      &name))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  flags = ntohl (msg->flags);
  value = GNUNET_ntohll (msg->value);
#if DEBUG_STATISTICS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received request to update statistic on `%s:%s' (%u) to/by %llu\n",
              service, name, (unsigned int) flags, (unsigned long long) value);
#endif
  pos = start;
  prev = NULL;
  while (pos != NULL)
  {
    if (matches (pos, service, name))
    {
      if ((flags & GNUNET_STATISTICS_SETFLAG_RELATIVE) == 0)
      {
        changed = (pos->value != value);
        pos->value = value;
      }
      else
      {
        delta = (int64_t) value;
        if ((delta < 0) && (pos->value < -delta))
        {
          changed = (pos->value != 0);
          pos->value = 0;
        }
        else
        {
          changed = (delta != 0);
          GNUNET_break ((delta <= 0) || (pos->value + delta > pos->value));
          pos->value += delta;
        }
      }
      pos->msg->value = GNUNET_htonll (pos->value);
      pos->msg->flags = msg->flags;
      pos->persistent = (0 != (flags & GNUNET_STATISTICS_SETFLAG_PERSISTENT));
      if (prev != NULL)
      {
        /* move to front for faster setting next time! */
        prev->next = pos->next;
        pos->next = start;
        start = pos;
      }
#if DEBUG_STATISTICS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Statistic `%s:%s' updated to value %llu.\n", service, name,
                  pos->value);
#endif
      if (changed)
        notify_change (pos);
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
    prev = pos;
    pos = pos->next;
  }
  pos = GNUNET_malloc (sizeof (struct StatsEntry) + msize);
  pos->next = start;
  if (((flags & GNUNET_STATISTICS_SETFLAG_RELATIVE) == 0) ||
      (0 < (int64_t) GNUNET_ntohll (msg->value)))
    pos->value = GNUNET_ntohll (msg->value);
  pos->uid = uidgen++;
  pos->persistent = (0 != (flags & GNUNET_STATISTICS_SETFLAG_PERSISTENT));
  pos->msg = (void *) &pos[1];
  memcpy (pos->msg, message, ntohs (message->size));
  pos->service = (const char *) &pos->msg[1];
  pos->name = &pos->service[strlen (pos->service) + 1];

  start = pos;
#if DEBUG_STATISTICS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New statistic on `%s:%s' with value %llu created.\n", service,
              name, pos->value);
#endif
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle WATCH-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_watch (void *cls, struct GNUNET_SERVER_Client *client,
              const struct GNUNET_MessageHeader *message)
{
  char *service;
  char *name;
  uint16_t msize;
  uint16_t size;
  struct StatsEntry *pos;
  struct ClientEntry *ce;
  struct WatchEntry *we;
  size_t slen;

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
      GNUNET_STRINGS_buffer_tokenize ((const char *) &message[1], size, 2,
                                      &service, &name))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
#if DEBUG_STATISTICS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received request to watch statistic on `%s:%s'\n", service,
              name);
#endif
  pos = start;
  while (pos != NULL)
  {
    if (matches (pos, service, name))
      break;
    pos = pos->next;
  }
  if (pos == NULL)
  {
    pos =
        GNUNET_malloc (sizeof (struct StatsEntry) +
                       sizeof (struct GNUNET_STATISTICS_SetMessage) + size);
    pos->next = start;
    pos->uid = uidgen++;
    pos->msg = (void *) &pos[1];
    pos->msg->header.size =
        htons (sizeof (struct GNUNET_STATISTICS_SetMessage) + size);
    pos->msg->header.type = htons (GNUNET_MESSAGE_TYPE_STATISTICS_SET);
    pos->service = (const char *) &pos->msg[1];
    slen = strlen (service) + 1;
    memcpy ((void *) pos->service, service, slen);
    pos->name = &pos->service[slen];
    memcpy ((void *) pos->name, name, strlen (name) + 1);
    start = pos;
  }
  we = GNUNET_malloc (sizeof (struct WatchEntry));
  we->client = client;
  GNUNET_SERVER_client_keep (client);
  we->wid = ce->max_wid++;
  GNUNET_CONTAINER_DLL_insert (pos->we_head, pos->we_tail, we);
  if (pos->value != 0)
    notify_change (pos);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ClientEntry *ce;
  struct WatchEntry *we;
  struct StatsEntry *se;

  save ();
  GNUNET_SERVER_notification_context_destroy (nc);
  nc = NULL;
  while (NULL != (ce = client_head))
  {
    GNUNET_SERVER_client_drop (ce->client);
    GNUNET_CONTAINER_DLL_remove (client_head, client_tail, ce);
    GNUNET_free (ce);
  }
  while (NULL != (se = start))
  {
    start = se->next;
    while (NULL != (we = se->we_head))
    {
      GNUNET_SERVER_client_drop (we->client);
      GNUNET_CONTAINER_DLL_remove (se->we_head, se->we_tail, we);
      GNUNET_free (we);
    }
    GNUNET_free (se);
  }
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
  struct WatchEntry *we;
  struct WatchEntry *wen;
  struct StatsEntry *se;

  ce = client_head;
  while (NULL != ce)
  {
    if (ce->client == client)
    {
      GNUNET_SERVER_client_drop (ce->client);
      GNUNET_CONTAINER_DLL_remove (client_head, client_tail, ce);
      GNUNET_free (ce);
      break;
    }
    ce = ce->next;
  }
  se = start;
  while (NULL != se)
  {
    wen = se->we_head;
    while (NULL != (we = wen))
    {
      wen = we->next;
      if (we->client != client)
        continue;
      GNUNET_SERVER_client_drop (we->client);
      GNUNET_CONTAINER_DLL_remove (se->we_head, se->we_tail, we);
      GNUNET_free (we);
    }
    se = se->next;
  }
}


/**
 * Process statistics requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_set, NULL, GNUNET_MESSAGE_TYPE_STATISTICS_SET, 0},
    {&handle_get, NULL, GNUNET_MESSAGE_TYPE_STATISTICS_GET, 0},
    {&handle_watch, NULL, GNUNET_MESSAGE_TYPE_STATISTICS_WATCH, 0},
    {NULL, NULL, 0, 0}
  };
  cfg = c;
  GNUNET_SERVER_add_handlers (server, handlers);
  nc = GNUNET_SERVER_notification_context_create (server, 16);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
  load (server);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
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
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-statistics.c */
