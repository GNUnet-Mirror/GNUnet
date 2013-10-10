
/*
     This file is part of GNUnet.
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file gnunet-namestore.c
 * @brief command line tool to manipulate the local zone
 * @author Christian Grothoff
 *
 * TODO:
 * - test
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_dnsparser_lib.h>
#include <gnunet_identity_service.h>
#include <gnunet_namestore_service.h>


/**
 * Handle to the namestore.
 */
static struct GNUNET_NAMESTORE_Handle *ns;

/**
 * Private key for the our zone.
 */
static struct GNUNET_CRYPTO_EcdsaPrivateKey zone_pkey;

/**
 * Handle to identity lookup.
 */
static struct GNUNET_IDENTITY_EgoLookup *el;

/**
 * Name of the ego controlling the zone.
 */
static char *ego_name;

/**
 * Desired action is to add a record.
 */
static int add;

/**
 * Iterator for the 'add' operation.
 */
static struct GNUNET_NAMESTORE_ZoneIterator *add_zit;

/**
 * Queue entry for the 'add-uri' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *add_qe_uri;

/**
 * Queue entry for the 'add' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *add_qe;

/**
 * Queue entry for the 'list' operation (in combination with a name).
 */
static struct GNUNET_NAMESTORE_QueueEntry *list_qe;

/**
 * Queue entry for the 'reverse lookup' operation (in combination with a name).
 */
static struct GNUNET_NAMESTORE_QueueEntry *reverse_qe;

/**
 * Desired action is to list records.
 */
static int list;

/**
 * List iterator for the 'list' operation.
 */
static struct GNUNET_NAMESTORE_ZoneIterator *list_it;

/**
 * Desired action is to remove a record.
 */
static int del;

/**
 * Is record public (opposite of #GNUNET_NAMESTORE_RF_PRIVATE)
 */
static int public;

/**
 * Is record a shadow record (#GNUNET_NAMESTORE_RF_SHADOW_RECORD)
 */
static int shadow;

/**
 * Queue entry for the 'del' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *del_qe;

/**
 * Name of the records to add/list/remove.
 */
static char *name;

/**
 * Value of the record to add/remove.
 */
static char *value;

/**
 * URI to import.
 */
static char *uri;

/**
 * Reverse lookup to perform.
 */
static char *reverse_pkey;

/**
 * Type of the record to add/remove, NULL to remove all.
 */
static char *typestring;

/**
 * Desired expiration time.
 */
static char *expirationstring;

/**
 * Global return value
 */
static int ret;

/**
 * Type string converted to DNS type value.
 */
static uint32_t type;

/**
 * Value in binary format.
 */
static void *data;

/**
 * Number of bytes in 'data'.
 */
static size_t data_size;

/**
 * Expirationstring converted to relative time.
 */
static struct GNUNET_TIME_Relative etime_rel;

/**
 * Expirationstring converted to absolute time.
 */
static struct GNUNET_TIME_Absolute etime_abs;

/**
 * Is expiration time relative or absolute time?
 */
static int etime_is_rel = GNUNET_SYSERR;

/**
 * Monitor handle.
 */
static struct GNUNET_NAMESTORE_ZoneMonitor *zm;

/**
 * Enables monitor mode.
 */
static int monitor;


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
  if (NULL != el)
  {
    GNUNET_IDENTITY_ego_lookup_cancel (el);
    el = NULL;
  }
  if (NULL != list_it)
  {
    GNUNET_NAMESTORE_zone_iteration_stop (list_it);
    list_it = NULL;
  }
  if (NULL != add_qe)
  {
    GNUNET_NAMESTORE_cancel (add_qe);
    add_qe = NULL;
  }
  if (NULL != list_qe)
  {
    GNUNET_NAMESTORE_cancel (list_qe);
    list_qe = NULL;
  }
  if (NULL != add_qe_uri)
  {
    GNUNET_NAMESTORE_cancel (add_qe_uri);
    add_qe_uri = NULL;
  }
  if (NULL != del_qe)
  {
    GNUNET_NAMESTORE_cancel (del_qe);
    del_qe = NULL;
  }
  if (NULL != ns)
  {
    GNUNET_NAMESTORE_disconnect (ns);
    ns = NULL;
  }
  memset (&zone_pkey, 0, sizeof (zone_pkey));
  if (NULL != uri)
  {
    GNUNET_free (uri);
    uri = NULL;
  }
  if (NULL != zm)
  {
    GNUNET_NAMESTORE_zone_monitor_stop (zm);
    zm = NULL;
  }
  if (NULL != data)
  {
    GNUNET_free (data);
    data = NULL;
  }
}


/**
 * Check if we are finished, and if so, perform shutdown.
 */
static void
test_finished ()
{
  if ( (NULL == add_qe) &&
       (NULL == list_qe) &&
       (NULL == add_qe_uri) &&
       (NULL == del_qe) &&
       (NULL == reverse_qe) &&
       (NULL == list_it) )
    GNUNET_SCHEDULER_shutdown ();
}


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure, location of the QueueEntry pointer to NULL out
 * @param success #GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                #GNUNET_NO if content was already there
 *                #GNUNET_YES (or other positive value) on success
 * @param emsg NULL on success, otherwise an error message
 */
static void
add_continuation (void *cls,
		  int32_t success,
		  const char *emsg)
{
  struct GNUNET_NAMESTORE_QueueEntry **qe = cls;

  *qe = NULL;
  if (GNUNET_YES != success)
  {
    fprintf (stderr,
	     _("Adding record failed: %s\n"),
	     (GNUNET_NO == success) ? "record exists" : emsg);
    if (GNUNET_NO != success)
      ret = 1;
  }
  test_finished ();
}


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure, unused
 * @param success #GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                #GNUNET_NO if content was already there
 *                #GNUNET_YES (or other positive value) on success
 * @param emsg NULL on success, otherwise an error message
 */
static void
del_continuation (void *cls,
		  int32_t success,
		  const char *emsg)
{
  del_qe = NULL;
  if (success != GNUNET_YES)
    fprintf (stderr,
	     _("Deleting record failed: %s\n"),
	     emsg);
  test_finished ();
}


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls closure
 * @param zone_key private key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_len number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
display_record (void *cls,
		const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
		const char *name,
		unsigned int rd_len,
		const struct GNUNET_NAMESTORE_RecordData *rd)
{
  const char *typestring;
  char *s;
  unsigned int i;
  const char *ets;
  struct GNUNET_TIME_Absolute at;
  struct GNUNET_TIME_Relative rt;

  if (NULL == name)
  {
    list_it = NULL;
    test_finished ();
    return;
  }
  FPRINTF (stdout,
	   "%s:\n",
	   name);
  for (i=0;i<rd_len;i++)
  {
    typestring = GNUNET_NAMESTORE_number_to_typename (rd[i].record_type);
    s = GNUNET_NAMESTORE_value_to_string (rd[i].record_type,
					  rd[i].data,
					  rd[i].data_size);
    if (NULL == s)
    {
      FPRINTF (stdout, _("\tCorrupt or unsupported record of type %u\n"),
	       (unsigned int) rd[i].record_type);
      continue;
    }
    if (0 != (rd[i].flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION))
    {
      rt.rel_value_us = rd[i].expiration_time;
      ets = GNUNET_STRINGS_relative_time_to_string (rt, GNUNET_YES);
    }
    else
    {
      at.abs_value_us = rd[i].expiration_time;
      ets = GNUNET_STRINGS_absolute_time_to_string (at);
    }
    FPRINTF (stdout,
	     "\t%s: %s (%s)\n",
	     typestring,
	     s,
             ets);
    GNUNET_free (s);
  }
  FPRINTF (stdout, "%s", "\n");
  GNUNET_NAMESTORE_zone_iterator_next (list_it);
}


/**
 * Function called once we are in sync in monitor mode.
 *
 * @param cls NULL
 */
static void
sync_cb (void *cls)
{
  FPRINTF (stdout, "%s", "Monitor is now in sync.\n");
}


/**
 * We're storing a record; this function is given the existing record
 * so that we can merge the information.
 *
 * @param cls closure, unused
 * @param zone_key private key of the zone
 * @param rec_name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
get_existing_record (void *cls,
		     const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
		     const char *rec_name,
		     unsigned int rd_count,
		     const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GNUNET_NAMESTORE_RecordData rdn[rd_count + 1];
  struct GNUNET_NAMESTORE_RecordData *rde;

  if ( (NULL != zone_key) &&
       (0 != strcmp (rec_name, name)) )
  {
    GNUNET_NAMESTORE_zone_iterator_next (add_zit);
    return;
  }
  memset (rdn, 0, sizeof (struct GNUNET_NAMESTORE_RecordData));
  memcpy (&rdn[1], rd, rd_count * sizeof (struct GNUNET_NAMESTORE_RecordData));
  /* FIXME: should add some logic to overwrite records if there
     can only be one record of a particular type, and to check
     if the combination of records is valid to begin with... */
  rde = &rdn[0];
  rde->data = data;
  rde->data_size = data_size;
  rde->record_type = type;
  if (1 != shadow)
    rde->flags |= GNUNET_NAMESTORE_RF_SHADOW_RECORD;
  if (1 != public)
    rde->flags |= GNUNET_NAMESTORE_RF_PRIVATE;
  if (GNUNET_YES == etime_is_rel)
  {
    rde->expiration_time = etime_rel.rel_value_us;
    rde->flags |= GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION;
  }
  else if (GNUNET_NO == etime_is_rel)
    rde->expiration_time = etime_abs.abs_value_us;
  else
    rde->expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
  GNUNET_assert (NULL != name);
  add_qe = GNUNET_NAMESTORE_records_store (ns,
					   &zone_pkey,
					   name,
					   rd_count + 1,
					   rde,
					   &add_continuation,
					   &add_qe);
  /* only cancel if we were not told that this
     was the end of the iteration already */
  if (NULL != rec_name)
    GNUNET_NAMESTORE_zone_iteration_stop (add_zit);
  add_zit = NULL;
}



/**
 * Process a record that was stored in the namestore in a block.
 *
 * @param cls closure, NULL
 * @param rd_len number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
display_records_from_block (void *cls,
			    unsigned int rd_len,
			    const struct GNUNET_NAMESTORE_RecordData *rd)
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
    typestring = GNUNET_NAMESTORE_number_to_typename (rd[i].record_type);
    s = GNUNET_NAMESTORE_value_to_string (rd[i].record_type,
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
	      const struct GNUNET_NAMESTORE_Block *block)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey zone_pubkey;

  list_qe = NULL;
  GNUNET_CRYPTO_ecdsa_key_get_public (&zone_pkey,
						  &zone_pubkey);
  if (NULL == block)
  {
    fprintf (stderr,
	     "No matching block found\n");
  }
  else if (GNUNET_OK !=
	   GNUNET_NAMESTORE_block_decrypt (block,
					   &zone_pubkey,
					   name,
					   &display_records_from_block,
					   NULL))
  {
    fprintf (stderr,
	     "Failed to decrypt block!\n");
  }
  test_finished ();
}


/**
 * Function called with the result of our attempt to obtain a name for a given
 * public key.
 *
 * @param cls NULL
 * @param zone private key of the zone; NULL on disconnect
 * @param label label of the records; NULL on disconnect
 * @param rd_count number of entries in @a rd array, 0 if label was deleted
 * @param rd array of records with data to store
 */
static void
handle_reverse_lookup (void *cls,
                       const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                       const char *label,
                       unsigned int rd_count,
                       const struct GNUNET_NAMESTORE_RecordData *rd)
{
  reverse_qe = NULL;
  if (NULL == label)
    FPRINTF (stdout,
             "%s.zkey\n",
             reverse_pkey);
  else
    FPRINTF (stdout,
             "%s.gnu\n",
             label);
  test_finished ();
}


/**
 * Function called with the result from the check if the namestore
 * service is actually running.  If it is, we start the actual
 * operation.
 *
 * @param cls closure with our configuration
 * @param result #GNUNET_YES if the namestore service is running
 */
static void
testservice_task (void *cls,
                  int result)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_CRYPTO_EcdsaPublicKey pub;
  struct GNUNET_NAMESTORE_RecordData rd;

  if (GNUNET_YES != result)
  {
    FPRINTF (stderr, _("Service `%s' is not running\n"),
	     "namestore");
    return;
  }
  if (! (add|del|list|(NULL != uri)|(NULL != reverse_pkey)) )
  {
    /* nothing more to be done */
    fprintf (stderr,
             _("No options given\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_CRYPTO_ecdsa_key_get_public (&zone_pkey,
                                    &pub);

  ns = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == ns)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to namestore\n"));
    return;
  }
  if (add)
  {
    if (NULL == name)
    {
      fprintf (stderr,
               _("Missing option `%s' for operation `%s'\n"),
               "-n", _("add"));
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    if (NULL == typestring)
    {
      fprintf (stderr,
	       _("Missing option `%s' for operation `%s'\n"),
	       "-t", _("add"));
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    type = GNUNET_NAMESTORE_typename_to_number (typestring);
    if (UINT32_MAX == type)
    {
      fprintf (stderr, _("Unsupported type `%s'\n"), typestring);
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    if (NULL == value)
    {
      fprintf (stderr,
	       _("Missing option `%s' for operation `%s'\n"),
	       "-V", _("add"));
      ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if (GNUNET_OK !=
	GNUNET_NAMESTORE_string_to_value (type,
					  value,
					  &data,
					  &data_size))
    {
      fprintf (stderr, _("Value `%s' invalid for record type `%s'\n"),
	       value,
	       typestring);
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    if (NULL == expirationstring)
    {
      fprintf (stderr,
	       _("Missing option `%s' for operation `%s'\n"),
	       "-e", _("add"));
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    if (0 == strcmp (expirationstring, "never"))
    {
      etime_abs = GNUNET_TIME_UNIT_FOREVER_ABS;
      etime_is_rel = GNUNET_NO;
    }
    else if (GNUNET_OK ==
             GNUNET_STRINGS_fancy_time_to_relative (expirationstring,
                                                    &etime_rel))
    {
      etime_is_rel = GNUNET_YES;
    }
    else if (GNUNET_OK ==
             GNUNET_STRINGS_fancy_time_to_absolute (expirationstring,
                                                    &etime_abs))
    {
      etime_is_rel = GNUNET_NO;
    }
    else
    {
      fprintf (stderr,
               _("Invalid time format `%s'\n"),
               expirationstring);
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    add_zit = GNUNET_NAMESTORE_zone_iteration_start (ns,
						     &zone_pkey,
						     &get_existing_record,
						     NULL);
  }
  if (del)
  {
    if (NULL == name)
    {
      fprintf (stderr,
               _("Missing option `%s' for operation `%s'\n"),
               "-n", _("del"));
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    del_qe = GNUNET_NAMESTORE_records_store (ns,
					     &zone_pkey,
					     name,
					     0, NULL,
					     &del_continuation,
					     NULL);
  }
  if (list)
  {
    if (NULL == name)
    {
      list_it = GNUNET_NAMESTORE_zone_iteration_start (ns,
						       &zone_pkey,
						       &display_record,
						       NULL);
    }
    else
    {
      struct GNUNET_HashCode query;
      struct GNUNET_CRYPTO_EcdsaPublicKey zone_pubkey;

      GNUNET_CRYPTO_ecdsa_key_get_public (&zone_pkey,
						      &zone_pubkey);
      GNUNET_NAMESTORE_query_from_public_key (&zone_pubkey,
					      name,
					      &query);
      list_qe = GNUNET_NAMESTORE_lookup_block (ns,
					       &query,
					       &handle_block,
					       NULL);
    }
  }
  if (NULL != reverse_pkey)
  {
    struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;

    if (GNUNET_OK !=
        GNUNET_CRYPTO_ecdsa_public_key_from_string (reverse_pkey,
                                                       strlen (reverse_pkey),
                                                       &pubkey))
    {
      fprintf (stderr,
               _("Invalid public key for reverse lookup `%s'\n"),
               reverse_pkey);
      GNUNET_SCHEDULER_shutdown ();
    }
    reverse_qe = GNUNET_NAMESTORE_zone_to_name (ns,
                                                &zone_pkey,
                                                &pubkey,
                                                &handle_reverse_lookup,
                                                NULL);
  }
  if (NULL != uri)
  {
    char sh[105];
    char sname[64];
    struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

    if ( (2 != (sscanf (uri,
                        "gnunet://gns/%104s/%63s",
                        sh,
                        sname)) ) ||
         (GNUNET_OK !=
          GNUNET_CRYPTO_ecdsa_public_key_from_string (sh, strlen (sh), &pkey)) )
    {
      fprintf (stderr,
               _("Invalid URI `%s'\n"),
               uri);
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    memset (&rd, 0, sizeof (rd));
    rd.data = &pkey;
    rd.data_size = sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey);
    rd.record_type = GNUNET_NAMESTORE_TYPE_PKEY;
    if (GNUNET_YES == etime_is_rel)
    {
      rd.expiration_time = etime_rel.rel_value_us;
      rd.flags |= GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION;
    }
    else if (GNUNET_NO == etime_is_rel)
      rd.expiration_time = etime_abs.abs_value_us;
    else
      rd.expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
    if (1 != shadow)
      rd.flags |= GNUNET_NAMESTORE_RF_SHADOW_RECORD;
    add_qe_uri = GNUNET_NAMESTORE_records_store (ns,
						 &zone_pkey,
						 sname,
						 1,
						 &rd,
						 &add_continuation,
						 &add_qe_uri);
  }
  if (monitor)
  {
    zm = GNUNET_NAMESTORE_zone_monitor_start (cfg,
					      &zone_pkey,
					      &display_record,
					      &sync_cb,
					      NULL);
  }
}


/**
 * Callback invoked from identity service with ego information.
 * An @a ego of NULL means the ego was not found.
 *
 * @param cls closure with the configuration
 * @param ego an ego known to identity service, or NULL
 */
static void
identity_cb (void *cls,
	     const struct GNUNET_IDENTITY_Ego *ego)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  el = NULL;
  if (NULL == ego)
  {
    fprintf (stderr,
	     _("Ego `%s' not known to identity service\n"),
	     ego_name);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  zone_pkey = *GNUNET_IDENTITY_ego_get_private_key (ego);
  GNUNET_free (ego_name);
  ego_name = NULL;
  GNUNET_CLIENT_service_test ("namestore", cfg,
			      GNUNET_TIME_UNIT_SECONDS,
			      &testservice_task,
			      (void *) cfg);
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
  if (NULL == ego_name)
  {
    fprintf (stderr,
	     _("You must specify which zone should be accessed\n"));
    return;
  }
  if ( (NULL != args[0]) && (NULL == uri) )
    uri = GNUNET_strdup (args[0]);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &do_shutdown, NULL);
  el = GNUNET_IDENTITY_ego_lookup (cfg,
				   ego_name,
				   &identity_cb,
				   (void *) cfg);
}


/**
 * The main function for gnunet-namestore.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  public = -1;

  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'a', "add", NULL,
     gettext_noop ("add record"), 0,
     &GNUNET_GETOPT_set_one, &add},
    {'d', "delete", NULL,
     gettext_noop ("delete record"), 0,
     &GNUNET_GETOPT_set_one, &del},
    {'D', "display", NULL,
     gettext_noop ("display records"), 0,
     &GNUNET_GETOPT_set_one, &list},
    {'e', "expiration", "TIME",
     gettext_noop ("expiration time for record to use (for adding only), \"never\" is possible"), 1,
     &GNUNET_GETOPT_set_string, &expirationstring},
    {'m', "monitor", NULL,
     gettext_noop ("monitor changes in the namestore"), 0,
     &GNUNET_GETOPT_set_one, &monitor},
    {'n', "name", "NAME",
     gettext_noop ("name of the record to add/delete/display"), 1,
     &GNUNET_GETOPT_set_string, &name},
    {'r', "reverse", "PKEY",
     gettext_noop ("determine our name for the given PKEY"), 1,
     &GNUNET_GETOPT_set_string, &reverse_pkey},
    {'t', "type", "TYPE",
     gettext_noop ("type of the record to add/delete/display"), 1,
     &GNUNET_GETOPT_set_string, &typestring},
    {'u', "uri", "URI",
     gettext_noop ("URI to import into our zone"), 1,
     &GNUNET_GETOPT_set_string, &uri},
    {'V', "value", "VALUE",
     gettext_noop ("value of the record to add/delete"), 1,
     &GNUNET_GETOPT_set_string, &value},
    {'p', "public", NULL,
     gettext_noop ("create or list public record"), 0,
     &GNUNET_GETOPT_set_one, &public},
    {'s', "shadow", NULL,
     gettext_noop ("create shadow record (only valid if all other records of the same type have expired"), 0,
     &GNUNET_GETOPT_set_one, &shadow},
    {'z', "zone", "EGO",
     gettext_noop ("name of the ego controlling the zone"), 1,
     &GNUNET_GETOPT_set_string, &ego_name},
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  GNUNET_log_setup ("gnunet-namestore", "WARNING", NULL);
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv, "gnunet-namestore",
			  _("GNUnet zone manipulation tool"),
			  options,
			  &run, NULL))
  {
    GNUNET_free ((void*) argv);
    GNUNET_CRYPTO_ecdsa_key_clear (&zone_pkey);
    return 1;
  }
  GNUNET_free ((void*) argv);
  GNUNET_CRYPTO_ecdsa_key_clear (&zone_pkey);
  return ret;
}

/* end of gnunet-namestore.c */
