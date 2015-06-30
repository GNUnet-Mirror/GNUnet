/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2013 Christian Grothoff (and other contributing authors)

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
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_datastore_service.h"


/**
 * Name of the second configuration file.
 */
static char *alternative_cfg;

/**
 * Global return value.
 */
static int ret;

/**
 * Our offset on 'get'.
 */
static uint64_t offset;

/**
 * First UID ever returned.
 */
static uint64_t first_uid;

/**
 * Configuration for the source database.
 */
static struct GNUNET_CONFIGURATION_Handle *scfg;

/**
 * Handle for database source.
 */
static struct GNUNET_DATASTORE_Handle *db_src;

/**
 * Handle for database destination.
 */
static struct GNUNET_DATASTORE_Handle *db_dst;

/**
 * Current operation.
 */
static struct GNUNET_DATASTORE_QueueEntry *qe;


static void
do_shutdown (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != qe)
    GNUNET_DATASTORE_cancel (qe);
  GNUNET_DATASTORE_disconnect (db_src, GNUNET_NO);
  GNUNET_DATASTORE_disconnect (db_dst, GNUNET_NO);
  GNUNET_CONFIGURATION_destroy (scfg);
}


/**
 * Perform next GET operation.
 */
static void
do_get (void);


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
do_finish (void *cls,
	   int32_t success,
	   struct GNUNET_TIME_Absolute min_expiration,
	   const char *msg)
{
  qe = NULL;
  if (GNUNET_SYSERR == success)
  {
    fprintf (stderr,
	     _("Failed to store item: %s, aborting\n"),
	     msg);
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  do_get ();
}


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
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
static void
do_put (void *cls,
	const struct GNUNET_HashCode *key,
	size_t size, const void *data,
	enum GNUNET_BLOCK_Type type,
	uint32_t priority,
	uint32_t anonymity,
	struct GNUNET_TIME_Absolute
	expiration, uint64_t uid)
{
  qe = NULL;
  if ( (0 != offset) &&
       (uid == first_uid) )
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (0 == offset)
    first_uid = uid;
  qe = GNUNET_DATASTORE_put (db_dst, 0,
			     key, size, data, type,
			     priority, anonymity,
			     0 /* FIXME: replication is lost... */,
			     expiration,
			     0, 1, GNUNET_TIME_UNIT_FOREVER_REL,
			     &do_finish, NULL);
}


/**
 * Perform next GET operation.
 */
static void
do_get ()
{
  qe = GNUNET_DATASTORE_get_key (db_src,
				 offset,
				 NULL, GNUNET_BLOCK_TYPE_ANY,
				 0, 1,
				 GNUNET_TIME_UNIT_FOREVER_REL,
				 &do_put, NULL);
}



/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used
 * @param cfg configuration -- for destination datastore
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  if (NULL == alternative_cfg)
    return; /* nothing to be done */
  if (0 == strcmp (cfgfile, alternative_cfg))
  {
    fprintf (stderr,
	     _("Cannot use the same configuration for source and destination\n"));
    ret = 1;
    return;
  }
  scfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_load (scfg,
				 alternative_cfg))
  {
    GNUNET_CONFIGURATION_destroy (scfg);
    ret = 1;
    return;
  }
  db_src = GNUNET_DATASTORE_connect (scfg);
  if (NULL == db_src)
  {
    GNUNET_CONFIGURATION_destroy (scfg);
    ret = 1;
    return;
  }
  db_dst = GNUNET_DATASTORE_connect (cfg);
  if (NULL == db_dst)
  {
    GNUNET_DATASTORE_disconnect (db_src, GNUNET_NO);
    GNUNET_CONFIGURATION_destroy (scfg);
    ret = 1;
    return;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&do_shutdown, NULL);
  do_get ();
}


/**
 * The main function to manipulate datastores.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    { 's', "sourcecfg", "FILENAME",
      gettext_noop ("specifies the configuration to use to access an alternative datastore; will merge that datastore into our current datastore"),
      1, &GNUNET_GETOPT_set_filename, &alternative_cfg },
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
