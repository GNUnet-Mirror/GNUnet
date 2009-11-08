/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * 
 * TODO:
 * - use BIO for IO operations
 */
#include "platform.h"
#include "gnunet_disk_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_strings_lib.h"
#include "gnunet_time_lib.h"
#include "statistics.h"

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

/**
 * Counter used to generate unique values.
 */
static uint32_t uidgen;

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
  struct GNUNET_DISK_FileHandle *fh;
  struct GNUNET_DISK_MapHandle *mh;
  struct stat sb;
  char *buf;
  size_t off;
  const struct GNUNET_MessageHeader *msg;

  fn = GNUNET_DISK_get_home_filename (cfg,
                                      "statistics", "statistics.data", NULL);
  if (fn == NULL)
    return;
  if ((0 != stat (fn, &sb)) || (sb.st_size == 0))
    {
      GNUNET_free (fn);
      return;
    }
  fh = GNUNET_DISK_file_open (fn, GNUNET_DISK_OPEN_READ,
			      GNUNET_DISK_PERM_NONE);
  if (!fh)
    {
      GNUNET_free (fn);
      return;
    }
  buf = GNUNET_DISK_file_map (fh, &mh, GNUNET_DISK_MAP_TYPE_READ, sb.st_size);
  if (NULL == buf)
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "mmap", fn);
      GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fh));
      GNUNET_free (fn);
      return;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Loading %llu bytes of statistics from `%s'\n"),
              (unsigned long long) sb.st_size, fn);
  off = 0;
  while (off + sizeof (struct GNUNET_MessageHeader) < sb.st_size)
    {
      msg = (const struct GNUNET_MessageHeader *) &buf[off];
      if ((ntohs (msg->size) + off > sb.st_size) ||
          (GNUNET_OK != GNUNET_SERVER_inject (server, NULL, msg)))
        {
          GNUNET_break (0);
          break;
        }
      off += ntohs (msg->size);
    }
  GNUNET_break (GNUNET_OK == GNUNET_DISK_file_unmap (mh));
  GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fh));
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
  struct GNUNET_DISK_FileHandle *fh;
  uint16_t size;
  unsigned long long total;

  fh = NULL;
  fn = GNUNET_DISK_get_home_filename (cfg,
                                      "statistics", "statistics.data", NULL);
  if (fn != NULL)
    fh = GNUNET_DISK_file_open (fn, GNUNET_DISK_OPEN_WRITE
        | GNUNET_DISK_OPEN_CREATE | GNUNET_DISK_OPEN_TRUNCATE,
        GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
  total = 0;
  while (NULL != (pos = start))
    {
      start = pos->next;
      if ((pos->persistent) && (NULL != fh))
        {
          size = htons (pos->msg->header.size);
          if (size != GNUNET_DISK_file_write (fh, pos->msg, size))
            {
              GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                        "write", fn);
              GNUNET_DISK_file_close (fh);
	      fh = NULL;
            }
          else
            total += size;
        }
      GNUNET_free (pos);
    }
  if (NULL != fh)
    {
      GNUNET_DISK_file_close (fh);
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
transmit (struct GNUNET_SERVER_TransmitContext *tc,
          const struct StatsEntry *e)
{
  struct GNUNET_STATISTICS_ReplyMessage *m;
  struct GNUNET_MessageHeader *h;
  size_t size;
  uint16_t msize;

  size =
    sizeof (struct GNUNET_STATISTICS_ReplyMessage) + strlen (e->service) + 1 +
    strlen (e->name) + 1;
  GNUNET_assert (size < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  msize = size - sizeof (struct GNUNET_MessageHeader);
  m = GNUNET_malloc (size);
  m->uid = htonl (e->uid);
  if (e->persistent)
    m->uid |= htonl (GNUNET_STATISTICS_PERSIST_BIT);
  m->value = GNUNET_htonll (e->value);
  size -= sizeof (struct GNUNET_STATISTICS_ReplyMessage);
  GNUNET_assert (size == GNUNET_STRINGS_buffer_fill ((char *) &m[1],
                                                     size,
                                                     2, e->service, e->name));
#if DEBUG_STATISTICS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting value for `%s:%s': %llu\n",
              e->service, e->name, e->value);
#endif
  h = &m->header;
  GNUNET_SERVER_transmit_context_append (tc,
                                         &h[1],
                                         msize,
                                         GNUNET_MESSAGE_TYPE_STATISTICS_VALUE);
  GNUNET_free (m);
}


/**
 * Does this entry match the request?
 */
static int
matches (const struct StatsEntry *e, const char *service, const char *name)
{
  return ((0 == strlen (service)) ||
          (0 == strcmp (service, e->service)))
    && ((0 == strlen (name)) || (0 == strcmp (name, e->name)));
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
handle_get (void *cls,
            struct GNUNET_SERVER_Client *client,
            const struct GNUNET_MessageHeader *message)
{
  char *service;
  char *name;
  struct StatsEntry *pos;
  struct GNUNET_SERVER_TransmitContext *tc;
  size_t size;

  size = ntohs (message->size) - sizeof (struct GNUNET_MessageHeader);
  if (size != GNUNET_STRINGS_buffer_tokenize ((const char *) &message[1],
                                              size, 2, &service, &name))
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
  tc = GNUNET_SERVER_transmit_context_create (client);
  pos = start;
  while (pos != NULL)
    {
      if (matches (pos, service, name))
        transmit (tc, pos);
      pos = pos->next;
    }
  GNUNET_SERVER_transmit_context_append (tc, NULL, 0,
                                         GNUNET_MESSAGE_TYPE_STATISTICS_END);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
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

  msize = ntohs (message->size);
  if (msize < sizeof (struct GNUNET_STATISTICS_SetMessage))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  size = msize - sizeof (struct GNUNET_STATISTICS_SetMessage);
  msg = (const struct GNUNET_STATISTICS_SetMessage *) message;

  if (size != GNUNET_STRINGS_buffer_tokenize ((const char *) &msg[1],
                                              size, 2, &service, &name))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
#if DEBUG_STATISTICS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received request to update statistic on `%s:%s'\n",
              service, name);
#endif
  flags = ntohl (msg->flags);
  value = GNUNET_ntohll (msg->value);
  pos = start;
  prev = NULL;
  while (pos != NULL)
    {
      if (matches (pos, service, name))
        {
          if ((flags & GNUNET_STATISTICS_SETFLAG_RELATIVE) == 0)
            {
              pos->value = value;
            }
          else
            {
              delta = (int64_t) value;
              if ((delta < 0) && (pos->value < -delta))
                {
                  pos->value = 0;
                }
              else
                {
                  GNUNET_break ((delta <= 0) ||
                                (pos->value + delta > pos->value));
                  pos->value += delta;
                }
            }
          pos->msg->value = GNUNET_htonll (pos->value);
          pos->msg->flags = msg->flags;
          pos->persistent =
            (0 != (flags & GNUNET_STATISTICS_SETFLAG_PERSISTENT));
          if (prev != NULL)
            {
              /* move to front for faster setting next time! */
              prev->next = pos->next;
              pos->next = start;
              start = pos;
            }
#if DEBUG_STATISTICS
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Statistic `%s:%s' updated to value %llu.\n",
                      service, name, pos->value);
#endif
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
              "New statistic on `%s:%s' with value %llu created.\n",
              service, name, pos->value);
#endif
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * List of handlers for the messages understood by this
 * service.
 */
static struct GNUNET_SERVER_MessageHandler handlers[] = {
  {&handle_set, NULL, GNUNET_MESSAGE_TYPE_STATISTICS_SET, 0},
  {&handle_get, NULL, GNUNET_MESSAGE_TYPE_STATISTICS_GET, 0},
  {NULL, NULL, 0, 0}
};


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
  save ();
}


/**
 * Process statistics requests.
 *
 * @param cls closure
 * @param sched scheduler to use
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;
  GNUNET_SERVER_add_handlers (server, handlers);
  load (server);
  GNUNET_SCHEDULER_add_delayed (sched,
				GNUNET_TIME_UNIT_FOREVER_REL,
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
          GNUNET_SERVICE_run (argc,
                              argv,
                              "statistics",
			      GNUNET_SERVICE_OPTION_NONE,
			      &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-statistics.c */
