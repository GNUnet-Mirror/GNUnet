/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2007, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file peerinfo/gnunet-service-peerinfo.c
 * @brief maintains list of known peers
 *
 * Code to maintain the list of currently known hosts (in memory
 * structure of data/hosts/).
 *
 * @author Christian Grothoff
 *
 * TODO:
 * - HostEntries are never 'free'd (add expiration, upper bound?)
 */

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_disk_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "peerinfo.h"

/**
 * How often do we scan the HOST_DIR for new entries?
 */
#define DATA_HOST_FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)

/**
 * How often do we discard old entries in data/hosts/?
 */
#define DATA_HOST_CLEAN_FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 60)

/**
 * In-memory cache of known hosts.
 */
struct HostEntry
{

  /**
   * Identity of the peer.
   */
  struct GNUNET_PeerIdentity identity;

  /**
   * Hello for the peer (can be NULL)
   */
  struct GNUNET_HELLO_Message *hello;

};


/**
 * The in-memory list of known hosts, mapping of
 * host IDs to 'struct HostEntry*' values.
 */
static struct GNUNET_CONTAINER_MultiHashMap *hostmap;

/**
 * Clients to immediately notify about all changes.
 */
static struct GNUNET_SERVER_NotificationContext *notify_list;

/**
 * Directory where the hellos are stored in (data/hosts)
 */
static char *networkIdDirectory;

/**
 * Handle for reporting statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;


/**
 * Notify all clients in the notify list about the
 * given host entry changing.
 */
static struct InfoMessage *
make_info_message (const struct HostEntry *he)
{
  struct InfoMessage *im;
  size_t hs;

  hs = (he->hello == NULL) ? 0 : GNUNET_HELLO_size (he->hello);
  im = GNUNET_malloc (sizeof (struct InfoMessage) + hs);
  im->header.size = htons (hs + sizeof (struct InfoMessage));
  im->header.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_INFO);
  im->peer = he->identity;
  if (he->hello != NULL)
    memcpy (&im[1], he->hello, hs);
  return im;
}


/**
 * Address iterator that causes expired entries to be discarded.
 *
 * @param cls pointer to the current time
 * @param address the address
 * @param expiration expiration time for the address
 * @return GNUNET_NO if expiration smaller than the current time
 */
static int
discard_expired (void *cls, const struct GNUNET_HELLO_Address *address,
                 struct GNUNET_TIME_Absolute expiration)
{
  const struct GNUNET_TIME_Absolute *now = cls;

  if (now->abs_value > expiration.abs_value)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Removing expired address of transport `%s'\n"),
                address->transport_name);
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


/**
 * Get the filename under which we would store the GNUNET_HELLO_Message
 * for the given host and protocol.
 * @return filename of the form DIRECTORY/HOSTID
 */
static char *
get_host_filename (const struct GNUNET_PeerIdentity *id)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded fil;
  char *fn;

  GNUNET_CRYPTO_hash_to_enc (&id->hashPubKey, &fil);
  GNUNET_asprintf (&fn, "%s%s%s", networkIdDirectory, DIR_SEPARATOR_STR, &fil);
  return fn;
}


/**
 * Broadcast information about the given entry to all
 * clients that care.
 *
 * @param entry entry to broadcast about
 */
static void
notify_all (struct HostEntry *entry)
{
  struct InfoMessage *msg;

  msg = make_info_message (entry);
  GNUNET_SERVER_notification_context_broadcast (notify_list, &msg->header,
                                                GNUNET_NO);
  GNUNET_free (msg);
}


/**
 * Add a host to the list.
 *
 * @param identity the identity of the host
 */
static void
add_host_to_known_hosts (const struct GNUNET_PeerIdentity *identity)
{
  struct HostEntry *entry;
  char buffer[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  const struct GNUNET_HELLO_Message *hello;
  struct GNUNET_HELLO_Message *hello_clean;
  int size;
  struct GNUNET_TIME_Absolute now;
  char *fn;

  entry = GNUNET_CONTAINER_multihashmap_get (hostmap, &identity->hashPubKey);
  if (entry != NULL)
    return;
  GNUNET_STATISTICS_update (stats, gettext_noop ("# peers known"), 1,
                            GNUNET_NO);
  entry = GNUNET_malloc (sizeof (struct HostEntry));
  entry->identity = *identity;

  fn = get_host_filename (identity);
  if (GNUNET_DISK_file_test (fn) == GNUNET_YES)
  {
    size = GNUNET_DISK_fn_read (fn, buffer, sizeof (buffer));
    hello = (const struct GNUNET_HELLO_Message *) buffer;
    if ((size < sizeof (struct GNUNET_MessageHeader)) ||
        (size != ntohs ((((const struct GNUNET_MessageHeader *) hello)->size)))
        || (size != GNUNET_HELLO_size (hello)))
    {
      GNUNET_break (0);
      if (0 != UNLINK (fn))
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
    }
    else
    {
      now = GNUNET_TIME_absolute_get ();
      hello_clean =
          GNUNET_HELLO_iterate_addresses (hello, GNUNET_YES, &discard_expired,
                                          &now);
      entry->hello = hello_clean;
    }
  }
  GNUNET_free (fn);
  GNUNET_CONTAINER_multihashmap_put (hostmap, &identity->hashPubKey, entry,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  notify_all (entry);
}


/**
 * Remove a file that should not be there.  LOG
 * success or failure.
 */
static void
remove_garbage (const char *fullname)
{
  if (0 == UNLINK (fullname))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
                _
                ("File `%s' in directory `%s' does not match naming convention. "
                 "Removed.\n"), fullname, networkIdDirectory);
  else
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                              "unlink", fullname);
}


static int
hosts_directory_scan_callback (void *cls, const char *fullname)
{
  unsigned int *matched = cls;
  struct GNUNET_PeerIdentity identity;
  const char *filename;

  if (GNUNET_DISK_file_test (fullname) != GNUNET_YES)
    return GNUNET_OK;           /* ignore non-files */
  if (strlen (fullname) < sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded))
  {
    remove_garbage (fullname);
    return GNUNET_OK;
  }
  filename =
      &fullname[strlen (fullname) -
                sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) + 1];
  if (filename[-1] != DIR_SEPARATOR)
  {
    remove_garbage (fullname);
    return GNUNET_OK;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_hash_from_string (filename, &identity.hashPubKey))
  {
    remove_garbage (fullname);
    return GNUNET_OK;
  }
  (*matched)++;
  add_host_to_known_hosts (&identity);
  return GNUNET_OK;
}


/**
 * Call this method periodically to scan data/hosts for new hosts.
 */
static void
cron_scan_directory_data_hosts (void *cls,
                                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static unsigned int retries;
  unsigned int count;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  count = 0;
  if (GNUNET_SYSERR == GNUNET_DISK_directory_create (networkIdDirectory))
  {
    GNUNET_SCHEDULER_add_delayed_with_priority (DATA_HOST_FREQ,
						GNUNET_SCHEDULER_PRIORITY_IDLE,
						&cron_scan_directory_data_hosts, NULL);
    return;
  }
  GNUNET_DISK_directory_scan (networkIdDirectory,
                              &hosts_directory_scan_callback, &count);
  if ((0 == count) && (0 == (++retries & 31)))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
                _("Still no peers found in `%s'!\n"), networkIdDirectory);
  GNUNET_SCHEDULER_add_delayed_with_priority (DATA_HOST_FREQ, 
					      GNUNET_SCHEDULER_PRIORITY_IDLE,
					      &cron_scan_directory_data_hosts,
					      NULL);
}


/**
 * Bind a host address (hello) to a hostId.
 *
 * @param peer the peer for which this is a hello
 * @param hello the verified (!) hello message
 */
static void
bind_address (const struct GNUNET_PeerIdentity *peer,
              const struct GNUNET_HELLO_Message *hello)
{
  char *fn;
  struct HostEntry *host;
  struct GNUNET_HELLO_Message *mrg;
  struct GNUNET_TIME_Absolute delta;

  add_host_to_known_hosts (peer);
  host = GNUNET_CONTAINER_multihashmap_get (hostmap, &peer->hashPubKey);
  GNUNET_assert (host != NULL);
  if (host->hello == NULL)
  {
    host->hello = GNUNET_malloc (GNUNET_HELLO_size (hello));
    memcpy (host->hello, hello, GNUNET_HELLO_size (hello));
  }
  else
  {
    mrg = GNUNET_HELLO_merge (host->hello, hello);
    delta = GNUNET_HELLO_equals (mrg, host->hello, GNUNET_TIME_absolute_get ());
    if (delta.abs_value == GNUNET_TIME_UNIT_FOREVER_ABS.abs_value)
    {
      GNUNET_free (mrg);
      return;
    }
    GNUNET_free (host->hello);
    host->hello = mrg;
  }
  fn = get_host_filename (peer);
  if (GNUNET_OK == GNUNET_DISK_directory_create_for_file (fn))
  {
    if (GNUNET_SYSERR ==
        GNUNET_DISK_fn_write (fn, host->hello, GNUNET_HELLO_size (host->hello),
                              GNUNET_DISK_PERM_USER_READ |
                              GNUNET_DISK_PERM_USER_WRITE |
                              GNUNET_DISK_PERM_GROUP_READ |
                              GNUNET_DISK_PERM_OTHER_READ))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "write", fn);

  }
  GNUNET_free (fn);
  notify_all (host);
}



/**
 * Do transmit info about peer to given host.
 *
 * @param cls NULL to hit all hosts, otherwise specifies a particular target
 * @param key hostID
 * @param value information to transmit
 * @return GNUNET_YES (continue to iterate)
 */
static int
add_to_tc (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_SERVER_TransmitContext *tc = cls;
  struct HostEntry *pos = value;
  struct InfoMessage *im;
  uint16_t hs;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];

  hs = 0;
  im = (struct InfoMessage *) buf;
  if (pos->hello != NULL)
  {
    hs = GNUNET_HELLO_size (pos->hello);
    GNUNET_assert (hs <
                   GNUNET_SERVER_MAX_MESSAGE_SIZE -
                   sizeof (struct InfoMessage));
    memcpy (&im[1], pos->hello, hs);
  }
  im->header.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_INFO);
  im->header.size = htons (sizeof (struct InfoMessage) + hs);
  im->reserved = htonl (0);
  im->peer = pos->identity;
  GNUNET_SERVER_transmit_context_append_message (tc, &im->header);
  return GNUNET_YES;
}


/**
 * @brief delete expired HELLO entries in data/hosts/
 */
static int
discard_hosts_helper (void *cls, const char *fn)
{
  struct GNUNET_TIME_Absolute *now = cls;
  char buffer[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  const struct GNUNET_HELLO_Message *hello;
  struct GNUNET_HELLO_Message *new_hello;
  int size;

  size = GNUNET_DISK_fn_read (fn, buffer, sizeof (buffer));
  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    if (0 != UNLINK (fn))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING |
                                GNUNET_ERROR_TYPE_BULK, "unlink", fn);
    return GNUNET_OK;
  }
  hello = (const struct GNUNET_HELLO_Message *) buffer;
  new_hello =
      GNUNET_HELLO_iterate_addresses (hello, GNUNET_YES, &discard_expired, now);
  if (new_hello != NULL)
  {
    GNUNET_DISK_fn_write (fn, new_hello, GNUNET_HELLO_size (new_hello),
                          GNUNET_DISK_PERM_USER_READ |
                          GNUNET_DISK_PERM_USER_WRITE |
                          GNUNET_DISK_PERM_GROUP_READ |
                          GNUNET_DISK_PERM_OTHER_READ);
    GNUNET_free (new_hello);
  }
  else
  {
    if (0 != UNLINK (fn))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING |
                                GNUNET_ERROR_TYPE_BULK, "unlink", fn);
  }
  return GNUNET_OK;
}


/**
 * Call this method periodically to scan data/hosts for new hosts.
 */
static void
cron_clean_data_hosts (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Absolute now;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  now = GNUNET_TIME_absolute_get ();
  GNUNET_DISK_directory_scan (networkIdDirectory, &discard_hosts_helper, &now);
  GNUNET_SCHEDULER_add_delayed (DATA_HOST_CLEAN_FREQ, &cron_clean_data_hosts,
                                NULL);
}


/**
 * Handle HELLO-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_hello (void *cls, struct GNUNET_SERVER_Client *client,
              const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_HELLO_Message *hello;
  struct GNUNET_PeerIdentity pid;

  hello = (const struct GNUNET_HELLO_Message *) message;
  if (GNUNET_OK != GNUNET_HELLO_get_id (hello, &pid))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
#if DEBUG_PEERINFO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s' message received for peer `%4s'\n",
              "HELLO", GNUNET_i2s (&pid));
#endif
  bind_address (&pid, hello);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle GET-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_get (void *cls, struct GNUNET_SERVER_Client *client,
            const struct GNUNET_MessageHeader *message)
{
  const struct ListPeerMessage *lpm;
  struct GNUNET_SERVER_TransmitContext *tc;

  lpm = (const struct ListPeerMessage *) message;
  GNUNET_break (0 == ntohl (lpm->reserved));
#if DEBUG_PEERINFO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s' message received for peer `%4s'\n",
              "GET", GNUNET_i2s (&lpm->peer));
#endif
  tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_CONTAINER_multihashmap_get_multiple (hostmap, &lpm->peer.hashPubKey,
                                              &add_to_tc, tc);
  GNUNET_SERVER_transmit_context_append_data (tc, NULL, 0,
                                              GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Handle GET-ALL-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_get_all (void *cls, struct GNUNET_SERVER_Client *client,
                const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVER_TransmitContext *tc;

#if DEBUG_PEERINFO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s' message received\n", "GET_ALL");
#endif
  tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_CONTAINER_multihashmap_iterate (hostmap, &add_to_tc, tc);
  GNUNET_SERVER_transmit_context_append_data (tc, NULL, 0,
                                              GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}


static int
do_notify_entry (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct HostEntry *he = value;
  struct InfoMessage *msg;

  msg = make_info_message (he);
  GNUNET_SERVER_notification_context_unicast (notify_list, client, &msg->header,
                                              GNUNET_NO);
  GNUNET_free (msg);
  return GNUNET_YES;
}


/**
 * Handle NOTIFY-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_notify (void *cls, struct GNUNET_SERVER_Client *client,
               const struct GNUNET_MessageHeader *message)
{
#if DEBUG_PEERINFO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s' message received\n", "NOTIFY");
#endif
  GNUNET_SERVER_notification_context_add (notify_list, client);
  GNUNET_CONTAINER_multihashmap_iterate (hostmap, &do_notify_entry, client);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static int
free_host_entry (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct HostEntry *he = value;

  GNUNET_free_non_null (he->hello);
  GNUNET_free (he);
  return GNUNET_YES;
}

/**
 * Clean up our state.  Called during shutdown.
 *
 * @param cls unused
 * @param tc scheduler task context, unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_SERVER_notification_context_destroy (notify_list);
  notify_list = NULL;
  GNUNET_CONTAINER_multihashmap_iterate (hostmap, &free_host_entry, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (hostmap);
  if (stats != NULL)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
}


/**
 * Process statistics requests.
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
    {&handle_hello, NULL, GNUNET_MESSAGE_TYPE_HELLO, 0},
    {&handle_get, NULL, GNUNET_MESSAGE_TYPE_PEERINFO_GET,
     sizeof (struct ListPeerMessage)},
    {&handle_get_all, NULL, GNUNET_MESSAGE_TYPE_PEERINFO_GET_ALL,
     sizeof (struct GNUNET_MessageHeader)},
    {&handle_notify, NULL, GNUNET_MESSAGE_TYPE_PEERINFO_NOTIFY,
     sizeof (struct GNUNET_MessageHeader)},
    {NULL, NULL, 0, 0}
  };

  hostmap = GNUNET_CONTAINER_multihashmap_create (1024);
  stats = GNUNET_STATISTICS_create ("peerinfo", cfg);
  notify_list = GNUNET_SERVER_notification_context_create (server, 0);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_filename (cfg, "peerinfo",
                                                          "HOSTS",
                                                          &networkIdDirectory));
  GNUNET_DISK_directory_create (networkIdDirectory);
  GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE,
                                      &cron_scan_directory_data_hosts, NULL);
  GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE,
                                      &cron_clean_data_hosts, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  GNUNET_SERVER_add_handlers (server, handlers);
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
  int ret;

  ret =
      (GNUNET_OK ==
       GNUNET_SERVICE_run (argc, argv, "peerinfo", GNUNET_SERVICE_OPTION_NONE,
                           &run, NULL)) ? 0 : 1;
  GNUNET_free_non_null (networkIdDirectory);
  return ret;
}


/* end of gnunet-service-peerinfo.c */
