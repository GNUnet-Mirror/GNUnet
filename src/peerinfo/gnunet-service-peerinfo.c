/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2007, 2009, 2010, 2012 Christian Grothoff (and other contributing authors)

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
 * - notify clients when addresses in HELLO expire (#1933)
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
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

  /**
   * Friend only hello for the peer (can be NULL)
   */
  struct GNUNET_HELLO_Message *friend_only_hello;

};

/**
 * Transmit context for GET requests
 */
struct TransmitContext
{
	/**
	 * Server transmit context
	 */
	struct GNUNET_SERVER_TransmitContext *tc;

	/**
		* Include friend only HELLOs GNUNET_YES or _NO
		*/
	int friend_only;
};

/**
 * Result of reading a file
 */
struct ReadHostFileContext
{
  /**
   * Hello for the peer (can be NULL)
   */
  struct GNUNET_HELLO_Message *hello;

  /**
   * Friend only hello for the peer (can be NULL)
   */
  struct GNUNET_HELLO_Message *friend_only_hello;
};


/**
 * Client notification context
 */
struct NotificationContext
{
	/**
	 * Next in DLL
	 */
	struct NotificationContext *prev;

	/**
	 * Previous in DLL
	 */
	struct NotificationContext *next;

	/**
	 * Server client
	 */
	struct GNUNET_SERVER_Client *client;

	/**
	 * Interested in friend only HELLO?
	 */
	int include_friend_only;
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
 * Directory where the hellos are stored in (peerinfo/)
 */
static char *networkIdDirectory;

/**
 * Handle for reporting statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * DLL of notification contexts: head
 */
static struct NotificationContext *nc_head;

/**
 * DLL of notification contexts: tail
 */
static struct NotificationContext *nc_tail;


/**
 * Notify all clients in the notify list about the
 * given host entry changing.
 *
 * @param he entry of the host for which we generate a notification
 * @return generated notification message
 */
static struct InfoMessage *
make_info_message (const struct HostEntry *he, int include_friend_only)
{
  struct InfoMessage *im;
  struct GNUNET_HELLO_Message *src;
  size_t hs;

  if (GNUNET_YES == include_friend_only)
  	src = he->friend_only_hello;
  else
  	src = he->hello;

  hs = (NULL == src) ? 0 : GNUNET_HELLO_size (src);
  im = GNUNET_malloc (sizeof (struct InfoMessage) + hs);
  im->header.size = htons (hs + sizeof (struct InfoMessage));
  im->header.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_INFO);
  im->peer = he->identity;
  if (NULL != src)
    memcpy (&im[1], src, hs);
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
 * Address iterator that counts the remaining addresses.
 *
 * @param cls pointer to the counter
 * @param address the address
 * @param expiration expiration time for the address
 * @return GNUNET_OK (always)
 */
static int
count_addresses (void *cls, const struct GNUNET_HELLO_Address *address,
                 struct GNUNET_TIME_Absolute expiration)
{
  unsigned int *cnt = cls;

  (*cnt)++;
  return GNUNET_OK;
}


/**
 * Get the filename under which we would store the GNUNET_HELLO_Message
 * for the given host and protocol.
 *
 * @param id peer for which we need the filename for the HELLO
 * @return filename of the form DIRECTORY/HOSTID
 */
static char *
get_host_filename (const struct GNUNET_PeerIdentity *id)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded fil;
  char *fn;

  if (NULL == networkIdDirectory)
    return NULL;
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
  struct InfoMessage *msg_pub;
  struct InfoMessage *msg_friend;
  struct NotificationContext *cur;

  msg_pub = make_info_message (entry, GNUNET_NO);
  msg_friend = make_info_message (entry, GNUNET_YES);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Notifying all clients about peer `%s'\n",
  		GNUNET_i2s(&entry->identity));
	for (cur = nc_head; NULL != cur; cur = cur->next)
	{
		if (GNUNET_NO == cur->include_friend_only)
		{
			GNUNET_SERVER_notification_context_unicast (notify_list,
																									cur->client,
																									&msg_pub->header,
																									GNUNET_NO);
		}
		if (GNUNET_YES == cur->include_friend_only)
		{
			GNUNET_SERVER_notification_context_unicast (notify_list,
																									cur->client,
																									&msg_friend->header,
																									GNUNET_NO);
		}
	}
  GNUNET_free (msg_pub);
  GNUNET_free (msg_friend);
}


/**
 * Bind a host address (hello) to a hostId.
 *
 * @param peer the peer for which this is a hello
 * @param hello the verified (!) hello message
 */
static void
update_hello (const struct GNUNET_PeerIdentity *peer,
              const struct GNUNET_HELLO_Message *hello);


/**
 * Try to read the HELLOs in the given filename and discard expired
 * addresses.  Removes the file if one the HELLO is mal-formed.  If all
 * addresses are expired, the HELLO is also removed (but the HELLO
 * with the public key is still returned if it was found and valid).
 * 
 * The file can contain up to two HELLO messages, a public and a friend only
 * HELLO
 *
 * @param fn name of the file
 * @param unlink_garbage if GNUNET_YES, try to remove useless files
 */
static void
read_host_file (const char *fn, int unlink_garbage, struct ReadHostFileContext *r)
{
  char buffer[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1] GNUNET_ALIGN;
  const struct GNUNET_HELLO_Message *hello_1st;
  const struct GNUNET_HELLO_Message *hello_2nd;
  struct GNUNET_HELLO_Message *hello_clean_1st;
  struct GNUNET_HELLO_Message *hello_clean_2nd;
  int size_1st;
  int size_2nd;
  int size_total;
  struct GNUNET_TIME_Absolute now;
  unsigned int left;

  hello_1st = NULL;
  hello_2nd = NULL;
  hello_clean_1st = NULL;
  hello_clean_2nd = NULL;
  size_1st = 0;
  size_2nd = 0;
  size_total = 0;
  r->friend_only_hello = NULL;
  r->hello = NULL;

  if (GNUNET_YES != GNUNET_DISK_file_test (fn))
  {
    return;
  }

  size_total = GNUNET_DISK_fn_read (fn, buffer, sizeof (buffer));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Read %u bytes from `%s'\n", size_total, fn);
  if (size_total < sizeof (struct GNUNET_MessageHeader))
  {
	    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
									_("Failed to parse HELLO in file `%s': %s\n"),
									fn, "Fail has invalid size");
    if ( (GNUNET_YES == unlink_garbage) && (0 != UNLINK (fn)) )
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
    return;
  }

  hello_1st = (const struct GNUNET_HELLO_Message *) buffer;
  size_1st = ntohs (((struct GNUNET_MessageHeader *) &buffer)->size);
  if (size_1st < sizeof (struct GNUNET_MessageHeader))
  {
	    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
									_("Failed to parse HELLO in file `%s': %s %u \n"),
									fn, "1st HELLO has invalid size of ", size_1st);
    if ((GNUNET_YES == unlink_garbage) && (0 != UNLINK (fn)))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
    return;
  }
	if (size_1st != GNUNET_HELLO_size (hello_1st))
	{
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
								_("Failed to parse HELLO in file `%s': %s \n"),
								fn, "1st HELLO is invalid");
    if ((GNUNET_YES == unlink_garbage) && (0 != UNLINK (fn)))
    	GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
    return;
	}

  if (size_total > size_1st)
  {
  		hello_2nd = (const struct GNUNET_HELLO_Message *) &buffer[size_1st];
  		size_2nd = ntohs (((const struct GNUNET_MessageHeader *) hello_2nd)->size);
  	  if ((size_2nd < sizeof (struct GNUNET_MessageHeader)) ||
  	  		(size_2nd != GNUNET_HELLO_size (hello_2nd)))
  	  {
  	    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
										_("Failed to parse HELLO in file `%s': %s\n"),
										fn, "2nd HELLO has wrong size");
  	    if ((GNUNET_YES == unlink_garbage) && (0 != UNLINK (fn)))
  	      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
  	    return;
  	  }
  }

  if (size_total != (size_1st + size_2nd))
  {
	    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
	    						_("Failed to parse HELLO in file `%s': %s\n"),
	    						fn, "Multiple HELLOs but total size is wrong");
	    if ((GNUNET_YES == unlink_garbage) && (0 != UNLINK (fn)))
	      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
	    return;
  }

  now = GNUNET_TIME_absolute_get ();
  hello_clean_1st = GNUNET_HELLO_iterate_addresses (hello_1st, GNUNET_YES,
  								 																  &discard_expired, &now);
  left = 0;
  (void) GNUNET_HELLO_iterate_addresses (hello_1st, GNUNET_NO,
  																			 &count_addresses, &left);
  if (0 == left)
  {
    /* no addresses left, remove from disk */
    if ((GNUNET_YES == unlink_garbage) && (0 != UNLINK (fn)))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
  }

  if (GNUNET_NO == GNUNET_HELLO_is_friend_only(hello_clean_1st))
  {
  	if (NULL == r->hello)
  		r->hello = hello_clean_1st;
  	else
  	{
  			GNUNET_break (0);
  			GNUNET_free (r->hello);
  			r->hello = hello_clean_1st;
  	}
  }
  else
  {
  	if (NULL == r->friend_only_hello)
  		r->friend_only_hello = hello_clean_1st;
  	else
  	{
  			GNUNET_break (0);
  			GNUNET_free (r->friend_only_hello);
  			r->friend_only_hello = hello_clean_1st;
  	}
  }

  if (NULL != hello_2nd)
  {
  	  hello_clean_2nd = GNUNET_HELLO_iterate_addresses (hello_2nd, GNUNET_YES,
  	  								 																  &discard_expired, &now);
  	  left = 0;
  	  (void) GNUNET_HELLO_iterate_addresses (hello_clean_2nd, GNUNET_NO,
  	  																			 &count_addresses, &left);
  	  if (0 == left)
  	  {
  	    /* no addresses left, remove from disk */
  	    if ((GNUNET_YES == unlink_garbage) && (0 != UNLINK (fn)))
  	      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
  	  }

  	  if (GNUNET_NO == GNUNET_HELLO_is_friend_only(hello_clean_2nd))
  	  {
  	  	if (NULL == r->hello)
  	  		r->hello = hello_clean_2nd;
  	  	else
  	  	{
  	  			GNUNET_break (0);
  	  			GNUNET_free (r->hello);
  	  			r->hello = hello_clean_2nd;
  	  	}
  	  }
  	  else
  	  {
  	  	if (NULL == r->friend_only_hello)
  	  		r->friend_only_hello = hello_clean_2nd;
  	  	else
  	  	{
  	  			GNUNET_break (0);
  	  			GNUNET_free (r->friend_only_hello);
  	  			r->friend_only_hello = hello_clean_2nd;
  	  	}
  	  }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found `%s' and `%s' HELLO message in file\n",
  		(NULL != r->hello) ? "public" : "NO public",
			(NULL != r->friend_only_hello) ? "friend only" : "NO friend only");


}


/**
 * Add a host to the list and notify clients about this event
 *
 * @param identity the identity of the host
 * @return the HostEntry
 */
static struct HostEntry *
add_host_to_known_hosts (const struct GNUNET_PeerIdentity *identity)
{
  struct HostEntry *entry;
  struct ReadHostFileContext r;
  char *fn;

  entry = GNUNET_CONTAINER_multihashmap_get (hostmap, &identity->hashPubKey);
  if (NULL == entry)
  {
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding new peer `%s'\n", GNUNET_i2s (identity));
  	GNUNET_STATISTICS_update (stats, gettext_noop ("# peers known"), 1,
                            GNUNET_NO);
  	entry = GNUNET_malloc (sizeof (struct HostEntry));
  	entry->identity = *identity;
  	GNUNET_CONTAINER_multihashmap_put (hostmap, &entry->identity.hashPubKey, entry,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    notify_all (entry);
    fn = get_host_filename (identity);
    if (NULL != fn)
    {
      read_host_file (fn, GNUNET_YES, &r);
      if (NULL != r.hello)
      	update_hello (identity, r.hello);
      if (NULL != r.friend_only_hello)
      	update_hello (identity, r.friend_only_hello);
      GNUNET_free_non_null (r.hello);
      GNUNET_free_non_null (r.friend_only_hello);
      GNUNET_free (fn);
    }
  }
  return entry;
}


/**
 * Remove a file that should not be there.  LOG
 * success or failure.
 *
 * @param fullname name of the file to remove
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


/**
 * Closure for 'hosts_directory_scan_callback'.
 */
struct DirScanContext
{
  /**
   * GNUNET_YES if we should remove files that are broken,
   * GNUNET_NO if the directory we are iterating over should
   * be treated as read-only by us.
   */ 
  int remove_files;

  /**
   * Counter for the number of (valid) entries found, incremented
   * by one for each match.
   */
  unsigned int matched;
};


/**
 * Function that is called on each HELLO file in a particular directory.
 * Try to parse the file and add the HELLO to our list.
 *
 * @param cls pointer to 'unsigned int' to increment for each file, or NULL
 *            if the file is from a read-only, read-once resource directory
 * @param fullname name of the file to parse
 * @return GNUNET_OK (continue iteration)
 */
static int
hosts_directory_scan_callback (void *cls, const char *fullname)
{
  struct DirScanContext *dsc = cls;
  struct GNUNET_PeerIdentity identity;
  struct ReadHostFileContext r;
  const char *filename;
  struct GNUNET_PeerIdentity id_public;
  struct GNUNET_PeerIdentity id_friend;
  struct GNUNET_PeerIdentity id;

  if (GNUNET_YES != GNUNET_DISK_file_test (fullname))
    return GNUNET_OK;           /* ignore non-files */

  filename = strrchr (fullname, DIR_SEPARATOR);
  if ((NULL == filename) || (1 > strlen (filename)))
   	filename = fullname;
  else
    filename ++;

  read_host_file (fullname, dsc->remove_files, &r);
	if ( (NULL == r.hello) && (NULL == r.friend_only_hello))
	{
    if (GNUNET_YES == dsc->remove_files)
      remove_garbage (fullname);
    return GNUNET_OK;
	}

	if (NULL != r.friend_only_hello)
	{
		if (GNUNET_OK != GNUNET_HELLO_get_id (r.friend_only_hello, &id_friend))
			if (GNUNET_YES == dsc->remove_files)
			{
				remove_garbage (fullname);
				return GNUNET_OK;
			}
		id = id_friend;
	}
	if (NULL != r.hello)
	{
		if (GNUNET_OK != GNUNET_HELLO_get_id (r.hello, &id_public))
			if (GNUNET_YES == dsc->remove_files)
			{
				remove_garbage (fullname);
				return GNUNET_OK;
			}
		id = id_public;
	}

	if ( (NULL != r.hello) && (NULL != r.friend_only_hello) &&
			(0 != memcmp (&id_friend, &id_public, sizeof (id_friend))) )
	{
		/* HELLOs are not for the same peer */
		GNUNET_break (0);
		if (GNUNET_YES == dsc->remove_files)
			remove_garbage (fullname);
		return GNUNET_OK;
	}
  if (GNUNET_OK == GNUNET_CRYPTO_hash_from_string (filename, &identity.hashPubKey))
  {
  		if (0 != memcmp (&id, &identity, sizeof (id_friend)))
  		{
  			/* HELLOs are not for the same peer */
  			GNUNET_break (0);
  			if (GNUNET_YES == dsc->remove_files)
  				remove_garbage (fullname);
  			return GNUNET_OK;
  		}
  }
	/* ok, found something valid, remember HELLO */
  add_host_to_known_hosts (&id);
  if (NULL != r.hello)
  {
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating peer `%s' public HELLO \n",
					GNUNET_i2s (&id));
  	update_hello (&id, r.hello);
  	GNUNET_free (r.hello);
  }
  if (NULL != r.friend_only_hello)
  {
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating peer `%s' friend only HELLO \n",
					GNUNET_i2s (&id));
  	update_hello (&id, r.friend_only_hello);
  	GNUNET_free (r.friend_only_hello);
  }
	dsc->matched++;
	return GNUNET_OK;
}


/**
 * Call this method periodically to scan data/hosts for new hosts.
 *
 * @param cls unused
 * @param tc scheduler context, aborted if reason is shutdown
 */
static void
cron_scan_directory_data_hosts (void *cls,
                                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static unsigned int retries;
  struct DirScanContext dsc;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  if (GNUNET_SYSERR == GNUNET_DISK_directory_create (networkIdDirectory))
  {
    GNUNET_SCHEDULER_add_delayed_with_priority (DATA_HOST_FREQ,
						GNUNET_SCHEDULER_PRIORITY_IDLE,
						&cron_scan_directory_data_hosts, NULL);
    return;
  }
  dsc.matched = 0;
  dsc.remove_files = GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO | GNUNET_ERROR_TYPE_BULK,
              _("Scanning directory `%s'\n"), networkIdDirectory);
  GNUNET_DISK_directory_scan (networkIdDirectory,
                              &hosts_directory_scan_callback, &dsc);
  if ((0 == dsc.matched) && (0 == (++retries & 31)))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
                _("Still no peers found in `%s'!\n"), networkIdDirectory);
  GNUNET_SCHEDULER_add_delayed_with_priority (DATA_HOST_FREQ, 
					      GNUNET_SCHEDULER_PRIORITY_IDLE,
					      &cron_scan_directory_data_hosts,
					      NULL);
}


static struct GNUNET_HELLO_Message *
update_friend_hello (const struct GNUNET_HELLO_Message *hello,
										 const struct GNUNET_HELLO_Message *friend_hello)
{
	struct GNUNET_HELLO_Message * res;
	struct GNUNET_HELLO_Message * tmp;
	struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded pk;

	if (NULL != friend_hello)
	{
		res = GNUNET_HELLO_merge (hello, friend_hello);
		GNUNET_assert (GNUNET_YES == GNUNET_HELLO_is_friend_only (res));
		return res;
	}

	GNUNET_HELLO_get_key (hello, &pk);
	tmp = GNUNET_HELLO_create (&pk, NULL, NULL, GNUNET_YES);
	res = GNUNET_HELLO_merge (hello, tmp);
	GNUNET_free (tmp);
	GNUNET_assert (GNUNET_YES == GNUNET_HELLO_is_friend_only (res));
	return res;
}



/**
 * Bind a host address (hello) to a hostId.
 *
 * @param peer the peer for which this is a hello
 * @param hello the verified (!) hello message
 */
static void
update_hello (const struct GNUNET_PeerIdentity *peer,
              const struct GNUNET_HELLO_Message *hello)
{
  char *fn;
  struct HostEntry *host;
  struct GNUNET_HELLO_Message *mrg;
  struct GNUNET_HELLO_Message **dest;
  struct GNUNET_TIME_Absolute delta;
  unsigned int cnt;
  unsigned int size;
  int friend_hello_type;
  int store_hello;
  int store_friend_hello;
  int pos;
  char *buffer;

  host = GNUNET_CONTAINER_multihashmap_get (hostmap, &peer->hashPubKey);
  GNUNET_assert (NULL != host);

  friend_hello_type = GNUNET_HELLO_is_friend_only (hello);
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating %s HELLO for `%s'\n",
			(GNUNET_YES == friend_hello_type) ? "friend-only" : "public",
			GNUNET_i2s (peer));

  dest = NULL;
  if (GNUNET_YES == friend_hello_type)
  {
  	dest = &host->friend_only_hello;
  }
  else
  {
  	dest = &host->hello;
  }

  if (NULL == (*dest))
  {
  	(*dest) = GNUNET_malloc (GNUNET_HELLO_size (hello));
    memcpy ((*dest), hello, GNUNET_HELLO_size (hello));
  }
  else
  {
    mrg = GNUNET_HELLO_merge ((*dest), hello);
    delta = GNUNET_HELLO_equals (mrg, (*dest), GNUNET_TIME_absolute_get ());
    if (delta.abs_value == GNUNET_TIME_UNIT_FOREVER_ABS.abs_value)
    {
      /* no differences, just ignore the update */
    	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No change in %s HELLO for `%s'\n",
    			(GNUNET_YES == friend_hello_type) ? "friend-only" : "public",
    			GNUNET_i2s (peer));
      GNUNET_free (mrg);
      return;
    }
    GNUNET_free ((*dest));
    (*dest) = mrg;
  }

  if ((NULL != (host->hello)) && (GNUNET_NO == friend_hello_type))
  {
  		/* Update friend only hello */
  		mrg = update_friend_hello (host->hello, host->friend_only_hello);
  		if (NULL != host->friend_only_hello)
  			GNUNET_free (host->friend_only_hello);
  		host->friend_only_hello = mrg;
  }

  if (NULL != host->hello)
  	GNUNET_assert ((GNUNET_NO == GNUNET_HELLO_is_friend_only (host->hello)));
  if (NULL != host->friend_only_hello)
    	GNUNET_assert ((GNUNET_YES == GNUNET_HELLO_is_friend_only(host->friend_only_hello)));

  store_hello = GNUNET_NO;
  store_friend_hello = GNUNET_NO;
	fn = get_host_filename (peer);
	if ( (NULL != fn) &&
			 (GNUNET_OK == GNUNET_DISK_directory_create_for_file (fn)) )
		{

			store_hello = GNUNET_NO;
			size = 0;
			cnt = 0;
			if (NULL != host->hello)
				(void) GNUNET_HELLO_iterate_addresses (host->hello,
									GNUNET_NO, &count_addresses, &cnt);
			if (cnt > 0)
			{
				store_hello = GNUNET_YES;
				size += GNUNET_HELLO_size (host->hello);
			}
			cnt = 0;
			if (NULL != host->friend_only_hello)
				(void) GNUNET_HELLO_iterate_addresses (host->friend_only_hello, GNUNET_NO,
										&count_addresses, &cnt);
			if (0 < cnt)
			{
				store_friend_hello = GNUNET_YES;
				size += GNUNET_HELLO_size (host->friend_only_hello);
			}

			if ((GNUNET_NO == store_hello) && (GNUNET_NO == store_friend_hello))
			{
				/* no valid addresses, don't put HELLO on disk; in fact,
		 	 	 	 if one exists on disk, remove it */
				(void) UNLINK (fn);
			}
			else
			{
				buffer = GNUNET_malloc (size);
				pos = 0;

				if (GNUNET_YES == store_hello)
				{
					memcpy (buffer, host->hello, GNUNET_HELLO_size (host->hello));
					pos += GNUNET_HELLO_size (host->hello);
				}
				if (GNUNET_YES == store_friend_hello)
				{
					memcpy (&buffer[pos], host->friend_only_hello, GNUNET_HELLO_size (host->friend_only_hello));
					pos += GNUNET_HELLO_size (host->friend_only_hello);
				}
				GNUNET_assert (pos == size);

				if (GNUNET_SYSERR == GNUNET_DISK_fn_write (fn, buffer, size,
					GNUNET_DISK_PERM_USER_READ |
					GNUNET_DISK_PERM_USER_WRITE |
					GNUNET_DISK_PERM_GROUP_READ |
					GNUNET_DISK_PERM_OTHER_READ))
					GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "write", fn);
				else
					GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stored %s %s HELLO in %s  with total size %u\n",
							(GNUNET_YES == store_friend_hello) ? "friend-only": "",
							(GNUNET_YES == store_hello) ? "public": "",
							fn, size);
				GNUNET_free (buffer);
			}
  }
	GNUNET_free_non_null (fn);
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
add_to_tc (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct TransmitContext *tc = cls;
  struct HostEntry *pos = value;
  struct InfoMessage *im;
  uint16_t hs;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1] GNUNET_ALIGN;

  hs = 0;
  im = (struct InfoMessage *) buf;

  if ((pos->hello != NULL) && (GNUNET_NO == tc->friend_only))
  {
  	/* Copy public HELLO */
    hs = GNUNET_HELLO_size (pos->hello);
    GNUNET_assert (hs < GNUNET_SERVER_MAX_MESSAGE_SIZE -
                   sizeof (struct InfoMessage));
    memcpy (&im[1], pos->hello, hs);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending public HELLO with size %u for peer `%4s'\n",
    		hs, GNUNET_h2s (key));
  }
  else if ((pos->friend_only_hello != NULL) && (GNUNET_YES == tc->friend_only))
  {
  	/* Copy friend only HELLO */
    hs = GNUNET_HELLO_size (pos->friend_only_hello);
    GNUNET_assert (hs < GNUNET_SERVER_MAX_MESSAGE_SIZE -
                   sizeof (struct InfoMessage));
    memcpy (&im[1], pos->friend_only_hello, hs);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending friend-only HELLO with size %u for peer `%4s'\n",
    		hs, GNUNET_h2s (key));
  }
  else
  {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding no HELLO for peer `%s'\n",
      		 GNUNET_h2s (key));
  }

  im->header.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_INFO);
  im->header.size = htons (sizeof (struct InfoMessage) + hs);
  im->reserved = htonl (0);
  im->peer = pos->identity;
  GNUNET_SERVER_transmit_context_append_message (tc->tc, &im->header);
  return GNUNET_YES;
}


/**
 * @brief delete expired HELLO entries in directory
 *
 * @param cls pointer to current time (struct GNUNET_TIME_Absolute)
 * @param fn filename to test to see if the HELLO expired
 * @return GNUNET_OK (continue iteration)
 */
static int
discard_hosts_helper (void *cls, const char *fn)
{
  struct GNUNET_TIME_Absolute *now = cls;
  char buffer[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1] GNUNET_ALIGN;
  const struct GNUNET_HELLO_Message *hello;
  struct GNUNET_HELLO_Message *new_hello;
  int read_size;
  int cur_hello_size;
  int new_hello_size;
  int read_pos;
  int write_pos;
  unsigned int cnt;
  char *writebuffer;


  read_size = GNUNET_DISK_fn_read (fn, buffer, sizeof (buffer));
  if (read_size < sizeof (struct GNUNET_MessageHeader))
  {
    if (0 != UNLINK (fn))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING |
                                GNUNET_ERROR_TYPE_BULK, "unlink", fn);
    return GNUNET_OK;
  }

  writebuffer = GNUNET_malloc (read_size);
  read_pos = 0;
  write_pos = 0;
  while (read_pos < read_size)
  {
  		/* Check each HELLO */
  		hello = (const struct GNUNET_HELLO_Message *) &buffer[read_pos];
  		cur_hello_size = GNUNET_HELLO_size (hello);
  		new_hello_size = 0;
  		if (0 == cur_hello_size)
  		{
  				/* Invalid data, discard */
  		    if (0 != UNLINK (fn))
  		      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING |
  		                                GNUNET_ERROR_TYPE_BULK, "unlink", fn);
  		    return GNUNET_OK;
  		}
  	  new_hello = GNUNET_HELLO_iterate_addresses (hello, GNUNET_YES, &discard_expired, now);
  	  cnt = 0;
  	  if (NULL != new_hello)
  	    (void) GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &count_addresses, &cnt);
  	  if ( (NULL != new_hello) && (0 < cnt) )
  	  {
  	  		/* Store new HELLO to write it when done */
  	  		new_hello_size = GNUNET_HELLO_size(new_hello);
  	  		memcpy (&writebuffer[write_pos], new_hello, new_hello_size);
  	   		write_pos += new_hello_size;
  	  }
   		read_pos += cur_hello_size;
  	  GNUNET_free_non_null (new_hello);
  }

  if (0 < write_pos)
  {
      GNUNET_DISK_fn_write (fn, writebuffer,write_pos,
                            GNUNET_DISK_PERM_USER_READ |
                            GNUNET_DISK_PERM_USER_WRITE |
                            GNUNET_DISK_PERM_GROUP_READ |
                            GNUNET_DISK_PERM_OTHER_READ);
  }
  else if (0 != UNLINK (fn))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING |
                              GNUNET_ERROR_TYPE_BULK, "unlink", fn);

  GNUNET_free (writebuffer);
  return GNUNET_OK;
}


/**
 * Call this method periodically to scan peerinfo/ for ancient
 * HELLOs to expire.
 *
 * @param cls unused
 * @param tc scheduler context, aborted if reason is shutdown
 */
static void
cron_clean_data_hosts (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Absolute now;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  now = GNUNET_TIME_absolute_get ();
  GNUNET_log (GNUNET_ERROR_TYPE_INFO | GNUNET_ERROR_TYPE_BULK,
              _("Cleaning up directory `%s'\n"), networkIdDirectory);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s' message received for peer `%4s'\n",
              "HELLO", GNUNET_i2s (&pid));
  add_host_to_known_hosts (&pid);
  update_hello (&pid, hello);
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
  struct TransmitContext tcx;

  lpm = (const struct ListPeerMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s' message received for peer `%4s'\n",
              "GET", GNUNET_i2s (&lpm->peer));
  tcx.friend_only = ntohl (lpm->include_friend_only);
  tcx.tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_CONTAINER_multihashmap_get_multiple (hostmap, &lpm->peer.hashPubKey,
                                              &add_to_tc, &tcx);
  GNUNET_SERVER_transmit_context_append_data (tcx.tc, NULL, 0,
                                              GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END);
  GNUNET_SERVER_transmit_context_run (tcx.tc, GNUNET_TIME_UNIT_FOREVER_REL);
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
  const struct ListAllPeersMessage *lapm;
  struct TransmitContext tcx;

  lapm = (const struct ListAllPeersMessage *) message;
  tcx.friend_only = ntohl (lapm->include_friend_only);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s' message received\n", "GET_ALL");
  tcx.tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_CONTAINER_multihashmap_iterate (hostmap, &add_to_tc, &tcx);
  GNUNET_SERVER_transmit_context_append_data (tcx.tc, NULL, 0,
                                              GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END);
  GNUNET_SERVER_transmit_context_run (tcx.tc, GNUNET_TIME_UNIT_FOREVER_REL);
}



/**
 * Pass the given client the information we have in the respective
 * host entry; the client is already in the notification context.
 *
 * @param cls the 'struct GNUNET_SERVER_Client' to notify
 * @param key key for the value (unused)
 * @param value the 'struct HostEntry' to notify the client about
 * @return GNUNET_YES (always, continue to iterate)
 */
static int
do_notify_entry (void *cls, const struct GNUNET_HashCode * key, void *value)
{
	struct NotificationContext *nc = cls;
  struct HostEntry *he = value;
  struct InfoMessage *msg;

	if ((NULL == he->hello) && (GNUNET_NO == nc->include_friend_only))
	{
		/* We have no public hello  */
	  return GNUNET_YES;
	}


	if ((NULL == he->friend_only_hello) && GNUNET_YES == nc->include_friend_only)
	{
		/* We have no friend hello */
	  return GNUNET_YES;
	}

	msg = make_info_message (he, nc->include_friend_only);
	GNUNET_SERVER_notification_context_unicast (notify_list,
			nc->client,
			&msg->header,
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
  struct NotifyMessage *nm = (struct NotifyMessage *) message;
  struct NotificationContext *nc;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s' message received\n", "NOTIFY");

	nc = GNUNET_malloc (sizeof (struct NotificationContext));
	nc->client = client;
	nc->include_friend_only = ntohl (nm->include_friend_only);

	GNUNET_CONTAINER_DLL_insert (nc_head, nc_tail, nc);
  GNUNET_SERVER_client_mark_monitor (client);
	GNUNET_SERVER_notification_context_add (notify_list, client);
  GNUNET_CONTAINER_multihashmap_iterate (hostmap, &do_notify_entry, nc);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Client disconnect callback
 *
 * @param cls unused
 * @param client server client
 */
static void disconnect_cb (void *cls,struct GNUNET_SERVER_Client *client)
{
	struct NotificationContext *cur;

	for (cur = nc_head; NULL != cur; cur = cur->next)
		if (cur->client == client)
			break;

	if (NULL == cur)
		return;

	GNUNET_CONTAINER_DLL_remove (nc_head, nc_tail, cur);
	GNUNET_free (cur);
}


/**
 * Release memory taken by a host entry.
 *
 * @param cls NULL
 * @param key key of the host entry
 * @param value the 'struct HostEntry' to free
 * @return GNUNET_YES (continue to iterate)
 */
static int
free_host_entry (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct HostEntry *he = value;

  GNUNET_free_non_null (he->hello);
  GNUNET_free_non_null (he->friend_only_hello);
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
	struct NotificationContext *cur;
	struct NotificationContext *next;
	GNUNET_SERVER_notification_context_destroy (notify_list);
  notify_list = NULL;

	for (cur = nc_head; NULL != cur; cur = next)
	{
			next = cur->next;
			GNUNET_CONTAINER_DLL_remove (nc_head, nc_tail, cur);
			GNUNET_free (cur);
	}

  GNUNET_CONTAINER_multihashmap_iterate (hostmap, &free_host_entry, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (hostmap);
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
}


/**
 * Start up peerinfo service.
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
     sizeof (struct ListAllPeersMessage)},
    {&handle_notify, NULL, GNUNET_MESSAGE_TYPE_PEERINFO_NOTIFY,
     sizeof (struct NotifyMessage)},
    {NULL, NULL, 0, 0}
  };
  char *peerdir;
  char *ip;
  struct DirScanContext dsc;
  int noio;

  hostmap = GNUNET_CONTAINER_multihashmap_create (1024, GNUNET_YES);
  stats = GNUNET_STATISTICS_create ("peerinfo", cfg);
  notify_list = GNUNET_SERVER_notification_context_create (server, 0);
  noio = GNUNET_CONFIGURATION_get_value_yesno (cfg, "peerinfo", "NO_IO");
  if (GNUNET_YES != noio)
  {
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONFIGURATION_get_value_filename (cfg, "peerinfo",
							    "HOSTS",
							    &networkIdDirectory));
    GNUNET_DISK_directory_create (networkIdDirectory);

    GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE,
					&cron_scan_directory_data_hosts, NULL);

    GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE,
					&cron_clean_data_hosts, NULL);

    ip = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DATADIR);
    GNUNET_asprintf (&peerdir,
		     "%shellos",
		     ip);
    GNUNET_free (ip);

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Importing HELLOs from `%s'\n"),
		peerdir);
    dsc.matched = 0;
    dsc.remove_files = GNUNET_NO;

    GNUNET_DISK_directory_scan (peerdir,
				&hosts_directory_scan_callback, &dsc);

    GNUNET_free (peerdir);
  }
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server, &disconnect_cb, NULL) ;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);

}


/**
 * The main function for the peerinfo service.
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
