/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2013 GNUnet e.V.

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
 * @file datastore/gnunet-datastore.c
 * @brief tool to manipulate datastores
 * @author Christian Grothoff
 */
#include <inttypes.h>
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_datastore_service.h"

GNUNET_NETWORK_STRUCT_BEGIN

struct DataRecord
{
  /**
   * Number of bytes in the item (NBO).
   */
  uint32_t size GNUNET_PACKED;

  /**
   * Type of the item (NBO) (actually an enum GNUNET_BLOCK_Type)
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Priority of the item (NBO).
   */
  uint32_t priority GNUNET_PACKED;

  /**
   * Desired anonymity level (NBO).
   */
  uint32_t anonymity GNUNET_PACKED;

  /**
   * Desired replication level (NBO).
   */
  uint32_t replication GNUNET_PACKED;

  /**
   * Expiration time (NBO).
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * Key under which the item can be found.
   */
  struct GNUNET_HashCode key;

};
GNUNET_NETWORK_STRUCT_END


/**
 * Length of our magic header.
 */
static const size_t MAGIC_LEN = 16;

/**
 * Magic header bytes.
 */
static const uint8_t MAGIC_BYTES[16] = "GNUNETDATASTORE1";

/**
 * Dump the database.
 */
static int dump;

/**
 * Insert into the database.
 */
static int insert;

/**
 * Dump file name.
 */
static char *file_name;

/**
 * Dump file handle.
 */
static struct GNUNET_DISK_FileHandle *file_handle;

/**
 * Global return value.
 */
static int ret;

/**
 * Handle for datastore.
 */
static struct GNUNET_DATASTORE_Handle *datastore;

/**
 * Current operation.
 */
static struct GNUNET_DATASTORE_QueueEntry *qe;

/**
 * Record count.
 */
static uint64_t record_count;


static void
do_shutdown (void *cls)
{
  if (NULL != qe)
    GNUNET_DATASTORE_cancel (qe);
  if (NULL != datastore)
    GNUNET_DATASTORE_disconnect (datastore, GNUNET_NO);
  if (NULL != file_handle)
    GNUNET_DISK_file_close (file_handle);
}


/**
 * Begin dumping the database.
 */
static void
start_dump (void);


/**
 * Begin inserting into the database.
 */
static void
start_insert (void);


/**
 * Perform next GET operation.
 */
static void
do_get (const uint64_t next_uid);


/**
 * Process a datum that was stored in the datastore.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
static void
get_cb (void *cls,
        const struct GNUNET_HashCode *key,
        size_t size,
        const void *data,
        enum GNUNET_BLOCK_Type type,
        uint32_t priority,
        uint32_t anonymity,
        uint32_t replication,
        struct GNUNET_TIME_Absolute expiration,
        uint64_t uid)
{
  qe = NULL;
  if (NULL == key)
  {
    FPRINTF (stderr,
             _("Dumped %" PRIu64 " records\n"),
             record_count);
    GNUNET_DISK_file_close (file_handle);
    file_handle = NULL;
    if (insert)
      start_insert();
    else
    {
      ret = 0;
      GNUNET_SCHEDULER_shutdown ();
    }
    return;
  }

  struct DataRecord dr;
  dr.size = htonl ((uint32_t) size);
  dr.type = htonl (type);
  dr.priority = htonl (priority);
  dr.anonymity = htonl (anonymity);
  dr.replication = htonl (replication);
  dr.expiration = GNUNET_TIME_absolute_hton (expiration);
  dr.key = *key;

  ssize_t len;
  len = GNUNET_DISK_file_write (file_handle, &dr, sizeof (dr));
  if (sizeof (dr) != len)
  {
    FPRINTF (stderr,
             _("Short write to file: %zd bytes expecting %zd\n"),
             len,
             sizeof (dr));
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  len = GNUNET_DISK_file_write (file_handle, data, size);
  if (size != len)
  {
    FPRINTF (stderr,
             _("Short write to file: %zd bytes expecting %zd\n"),
             len,
             size);
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  record_count++;
  do_get(uid + 1);
}


/**
 * Perform next GET operation.
 */
static void
do_get (const uint64_t next_uid)
{
  GNUNET_assert (NULL == qe);
  qe = GNUNET_DATASTORE_get_key (datastore,
                                 next_uid,
                                 false /* random */,
                                 NULL /* key */,
                                 GNUNET_BLOCK_TYPE_ANY,
                                 0 /* queue_priority */,
                                 1 /* max_queue_size */,
                                 &get_cb,
                                 NULL /* proc_cls */);
  if (NULL == qe)
  {
    FPRINTF (stderr,
             _("Error queueing datastore GET operation\n"));
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * Begin dumping the database.
 */
static void
start_dump ()
{
  record_count = 0;

  if (NULL != file_name)
  {
    file_handle = GNUNET_DISK_file_open (file_name,
                                         GNUNET_DISK_OPEN_WRITE |
                                         GNUNET_DISK_OPEN_TRUNCATE |
                                         GNUNET_DISK_OPEN_CREATE,
                                         GNUNET_DISK_PERM_USER_READ |
                                         GNUNET_DISK_PERM_USER_WRITE);
    if (NULL == file_handle)
    {
      FPRINTF (stderr,
               _("Unable to open dump file: %s\n"),
               file_name);
      ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
  else
  {
    file_handle = GNUNET_DISK_get_handle_from_int_fd (STDOUT_FILENO);
  }
  GNUNET_DISK_file_write (file_handle, MAGIC_BYTES, MAGIC_LEN);
  do_get(0);
}


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success GNUNET_SYSERR on failure (including timeout/queue drop)
 *                GNUNET_NO if content was already there
 *                GNUNET_YES (or other positive value) on success
 * @param min_expiration minimum expiration time required for 0-priority content to be stored
 *                by the datacache at this time, zero for unknown, forever if we have no
 *                space for 0-priority content
 * @param msg NULL on success, otherwise an error message
 */
static void
put_cb (void *cls,
        int32_t success,
        struct GNUNET_TIME_Absolute min_expiration,
        const char *msg)
{
  qe = NULL;
  if (GNUNET_SYSERR == success)
  {
    FPRINTF (stderr,
             _("Failed to store item: %s, aborting\n"),
             msg);
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  struct DataRecord dr;
  ssize_t len;

  len = GNUNET_DISK_file_read (file_handle, &dr, sizeof (dr));
  if (0 == len)
  {
    FPRINTF (stderr,
             _("Inserted %" PRIu64 " records\n"),
             record_count);
    ret = 0;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  else if (sizeof (dr) != len)
  {
    FPRINTF (stderr,
             _("Short read from file: %zd bytes expecting %zd\n"),
             len,
             sizeof (dr));
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  const size_t size = ntohl (dr.size);
  uint8_t data[size];
  len = GNUNET_DISK_file_read (file_handle, data, size);
  if (size != len)
  {
    FPRINTF (stderr,
             _("Short read from file: %zd bytes expecting %zd\n"),
             len,
             size);
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  record_count++;
  qe = GNUNET_DATASTORE_put (datastore,
                             0,
                             &dr.key,
                             size,
                             data,
                             ntohl (dr.type),
                             ntohl (dr.priority),
                             ntohl (dr.anonymity),
                             ntohl (dr.replication),
                             GNUNET_TIME_absolute_ntoh (dr.expiration),
                             0,
                             1,
                             &put_cb,
                             NULL);
  if (NULL == qe)
  {
    FPRINTF (stderr,
             _("Error queueing datastore PUT operation\n"));
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * Begin inserting into the database.
 */
static void
start_insert ()
{
  record_count = 0;

  if (NULL != file_name)
  {
    file_handle = GNUNET_DISK_file_open (file_name,
                                         GNUNET_DISK_OPEN_READ,
                                         GNUNET_DISK_PERM_NONE);
    if (NULL == file_handle)
    {
      FPRINTF (stderr,
               _("Unable to open dump file: %s\n"),
               file_name);
      ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
  else
  {
    file_handle = GNUNET_DISK_get_handle_from_int_fd (STDIN_FILENO);
  }

  uint8_t buf[MAGIC_LEN];
  ssize_t len;

  len = GNUNET_DISK_file_read (file_handle, buf, MAGIC_LEN);
  if (len != MAGIC_LEN ||
      0 != memcmp (buf, MAGIC_BYTES, MAGIC_LEN))
  {
    FPRINTF (stderr,
             _("Input file is not of a supported format\n"));
    return;
  }
  put_cb (NULL, GNUNET_YES, GNUNET_TIME_UNIT_ZERO_ABS, NULL);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
  datastore = GNUNET_DATASTORE_connect (cfg);
  if (NULL == datastore)
  {
    FPRINTF (stderr,
             _("Failed connecting to the datastore.\n"));
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (dump)
    start_dump();
  else if (insert)
    start_insert();
  else
  {
    FPRINTF (stderr,
             _("Please choose at least one operation: %s, %s\n"),
             "dump",
             "insert");
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * The main function to manipulate datastores.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_flag ('d',
                               "dump",
                               gettext_noop ("Dump all records from the datastore"),
                               &dump),
    GNUNET_GETOPT_option_flag ('i',
                               "insert",
                               gettext_noop ("Insert records into the datastore"),
                               &insert),
    GNUNET_GETOPT_option_filename ('f',
                                   "file",
                                   "FILENAME",
                                   gettext_noop ("File to dump or insert"),
                                   &file_name),
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv, "gnunet-datastore",
			  gettext_noop ("Manipulate GNUnet datastore"),
			  options, &run, NULL))
    ret = 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-datastore.c */
