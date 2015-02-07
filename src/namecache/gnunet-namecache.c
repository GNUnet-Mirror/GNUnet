/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file gnunet-namecache.c
 * @brief command line tool to inspect the name cache
 * @author Christian Grothoff
 *
 * TODO:
 * - test
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_namecache_service.h"


/**
 * Handle to the namecache.
 */
static struct GNUNET_NAMECACHE_Handle *ns;

/**
 * Queue entry for the 'query' operation.
 */
static struct GNUNET_NAMECACHE_QueueEntry *qe;

/**
 * Name (label) of the records to list.
 */
static char *name;

/**
 * Public key of the zone to look in.
 */
static struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;

/**
 * Public key of the zone to look in, in ASCII.
 */
static char *pkey;

/**
 * Global return value
 */
static int ret;


/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
do_shutdown (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != qe)
  {
    GNUNET_NAMECACHE_cancel (qe);
    qe = NULL;
  }
  if (NULL != ns)
  {
    GNUNET_NAMECACHE_disconnect (ns);
    ns = NULL;
  }
}


/**
 * Process a record that was stored in the namecache in a block.
 *
 * @param cls closure, NULL
 * @param rd_len number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
display_records_from_block (void *cls,
			    unsigned int rd_len,
			    const struct GNUNET_GNSRECORD_Data *rd)
{
  const char *typestring;
  char *s;
  unsigned int i;

  if (0 == rd_len)
  {
    FPRINTF (stdout,
	     _("No records found for `%s'"),
	     name);
    return;
  }
  FPRINTF (stdout,
	   "%s:\n",
	   name);
  for (i=0;i<rd_len;i++)
  {
    typestring = GNUNET_GNSRECORD_number_to_typename (rd[i].record_type);
    s = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
					  rd[i].data,
					  rd[i].data_size);
    if (NULL == s)
    {
      FPRINTF (stdout, _("\tCorrupt or unsupported record of type %u\n"),
	       (unsigned int) rd[i].record_type);
      continue;
    }
    FPRINTF (stdout,
	     "\t%s: %s\n",
	     typestring,
	     s);
    GNUNET_free (s);
  }
  FPRINTF (stdout, "%s", "\n");
}


/**
 * Display block obtained from listing (by name).
 *
 * @param cls NULL
 * @param block NULL if not found
 */
static void
handle_block (void *cls,
	      const struct GNUNET_GNSRECORD_Block *block)
{
  qe = NULL;
  if (NULL == block)
  {
    fprintf (stderr,
	     "No matching block found\n");
  }
  else if (GNUNET_OK !=
	   GNUNET_GNSRECORD_block_decrypt (block,
					   &pubkey,
					   name,
					   &display_records_from_block,
					   NULL))
  {
    fprintf (stderr,
	     "Failed to decrypt block!\n");
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_HashCode dhash;

  if (NULL == pkey)
  {
    fprintf (stderr,
	     _("You must specify which zone should be accessed\n"));
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_public_key_from_string (pkey,
                                                  strlen (pkey),
                                                  &pubkey))
  {
    fprintf (stderr,
             _("Invalid public key for reverse lookup `%s'\n"),
             pkey);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (NULL == name)
  {
    fprintf (stderr,
             _("You must specify a name\n"));
    return;
  }


  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &do_shutdown,
                                NULL);
  ns = GNUNET_NAMECACHE_connect (cfg);
  GNUNET_GNSRECORD_query_from_public_key (&pubkey,
                                          name,
                                          &dhash);
  qe = GNUNET_NAMECACHE_lookup_block (ns,
                                      &dhash,
                                      &handle_block,
                                      NULL);
}


/**
 * The main function for gnunet-namecache.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'n', "name", "NAME",
     gettext_noop ("name of the record to add/delete/display"), 1,
     &GNUNET_GETOPT_set_string, &name},
    {'z', "zone", "PKEY",
     gettext_noop ("spezifies the public key of the zone to look in"), 1,
     &GNUNET_GETOPT_set_string, &pkey},
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  GNUNET_log_setup ("gnunet-namecache", "WARNING", NULL);
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv, "gnunet-namecache",
			  _("GNUnet zone manipulation tool"),
			  options,
			  &run, NULL))
  {
    GNUNET_free ((void*) argv);
    return 1;
  }
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-namecache.c */
