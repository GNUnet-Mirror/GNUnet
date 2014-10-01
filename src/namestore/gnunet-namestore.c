/*
     This file is part of GNUnet.
     (C) 2012, 2013, 2014 Christian Grothoff (and other contributing authors)

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
#include <gnunet_gnsrecord_lib.h>
#include <gnunet_gns_service.h>
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
 * Identity service handle
 */
static struct GNUNET_IDENTITY_Handle *idh;

/**
 * Obtain default ego
 */
struct GNUNET_IDENTITY_Operation *get_default;

/**
 * Name of the ego controlling the zone.
 */
static char *ego_name;

/**
 * Desired action is to add a record.
 */
static int add;

/**
 * Queue entry for the 'add-uri' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *add_qe_uri;

/**
 * Queue entry for the 'add' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *add_qe;

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
 * Is record public (opposite of #GNUNET_GNSRECORD_RF_PRIVATE)
 */
static int is_public;

/**
 * Is record a shadow record (#GNUNET_GNSRECORD_RF_SHADOW_RECORD)
 */
static int is_shadow;

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
 * Desired nick name.
 */
static char *nickstring;

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
  if (NULL != get_default)
  {
    GNUNET_IDENTITY_cancel (get_default);
    get_default = NULL;
  }
  if (NULL != idh)
  {
    GNUNET_IDENTITY_disconnect (idh);
    idh = NULL;
  }
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
  ret = 0;
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
  if (GNUNET_NO == success)
  {
    fprintf (stderr,
	     _("Deleting record failed, record does not exist%s%s\n"),
	     (NULL != emsg) ? ": " : "",
	     (NULL != emsg) ? emsg : "");
  }
  if (GNUNET_SYSERR == success)
  {
    fprintf (stderr,
             _("Deleting record failed%s%s\n"),
             (NULL != emsg) ? ": " : "",
             (NULL != emsg) ? emsg : "");
  }
  test_finished ();
}


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls closure
 * @param zone_key private key of the zone
 * @param rname name that is being mapped (at most 255 characters long)
 * @param rd_len number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
display_record (void *cls,
		const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
		const char *rname,
		unsigned int rd_len,
		const struct GNUNET_GNSRECORD_Data *rd)
{
  const char *typestring;
  char *s;
  unsigned int i;
  const char *ets;
  struct GNUNET_TIME_Absolute at;
  struct GNUNET_TIME_Relative rt;

  if (NULL == rname)
  {
    list_it = NULL;
    test_finished ();
    return;
  }
  if ( (NULL != name) &&
       (0 != strcmp (name, rname)) )
  {
    GNUNET_NAMESTORE_zone_iterator_next (list_it);
    return;
  }
  FPRINTF (stdout,
	   "%s:\n",
	   rname);
  for (i=0;i<rd_len;i++)
  {
    if ( (GNUNET_GNSRECORD_TYPE_NICK == rd[i].record_type) &&
         (0 != strcmp (rname,
                       "+")) )
      continue;
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
    if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
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
	     "\t%s: %s (%s)\t%s\t%s\t%s\n",
	     typestring,
	     s,
             ets,
             (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_PRIVATE)) ? "PRIVATE" : "PUBLIC",
             (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_SHADOW_RECORD)) ? "SHADOW" : "");
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
		     const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data rdn[rd_count + 1];
  struct GNUNET_GNSRECORD_Data *rde;
  unsigned int i;

  add_qe = NULL;
  if ( (NULL != zone_key) &&
       (0 != strcmp (rec_name, name)) )
  {
    GNUNET_break (0);
    ret = 1;
    test_finished ();
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received %u records for name `%s'\n",
              rd_count, rec_name);
  for (i=0;i<rd_count;i++)
  {
    switch (rd[i].record_type)
    {
    case GNUNET_DNSPARSER_TYPE_CNAME:
      fprintf (stderr,
               _("A %s record exists already under `%s', no other records can be added.\n"),
               "CNAME",
               rec_name);
      ret = 1;
      test_finished ();
      return;
    case GNUNET_GNSRECORD_TYPE_PKEY:
      fprintf (stderr,
               _("A %s record exists already under `%s', no other records can be added.\n"),
               "PKEY",
               rec_name);
      ret = 1;
      test_finished ();
    case GNUNET_GNSRECORD_TYPE_GNS2DNS:
      fprintf (stderr,
               _("A %s record exists already under `%s', no other records can be added.\n"),
               "GNS2DNS",
               rec_name);
      ret = 1;
      test_finished ();
      return;
    }
  }
  switch (type)
  {
  case GNUNET_DNSPARSER_TYPE_CNAME:
    if (0 != rd_count)
    {
      fprintf (stderr,
               _("Records already exist under `%s', cannot add `%s' record.\n"),
               rec_name,
               "CNAME");
      ret = 1;
      test_finished ();
      return;
    }
    break;
  case GNUNET_GNSRECORD_TYPE_PKEY:
    if (0 != rd_count)
    {
      fprintf (stderr,
               _("Records already exist under `%s', cannot add `%s' record.\n"),
               rec_name,
               "PKEY");
      ret = 1;
      test_finished ();
      return;
    }
    break;
  case GNUNET_GNSRECORD_TYPE_GNS2DNS:
    if (0 != rd_count)
    {
      fprintf (stderr,
               _("Records already exist under `%s', cannot add `%s' record.\n"),
               rec_name,
               "GNS2DNS");
      ret = 1;
      test_finished ();
      return;
    }
    break;
  }
  memset (rdn, 0, sizeof (struct GNUNET_GNSRECORD_Data));
  memcpy (&rdn[1], rd, rd_count * sizeof (struct GNUNET_GNSRECORD_Data));
  rde = &rdn[0];
  rde->data = data;
  rde->data_size = data_size;
  rde->record_type = type;
  if (1 == is_shadow)
    rde->flags |= GNUNET_GNSRECORD_RF_SHADOW_RECORD;
  if (1 != is_public)
    rde->flags |= GNUNET_GNSRECORD_RF_PRIVATE;
  if (GNUNET_YES == etime_is_rel)
  {
    rde->expiration_time = etime_rel.rel_value_us;
    rde->flags |= GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
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
                       const struct GNUNET_GNSRECORD_Data *rd)
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
 * We were asked to delete something; this function is called with
 * the existing records. Now we should determine what should be
 * deleted and then issue the deletion operation.
 *
 * @param cls NULL
 * @param zone private key of the zone we are deleting from
 * @param label name of the records we are editing
 * @param rd_count size of the @a rd array
 * @param rd existing records
 */
static void
del_monitor (void *cls,
             const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
             const char *label,
             unsigned int rd_count,
             const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data rdx[rd_count];
  unsigned int rd_left;
  unsigned int i;
  uint32_t type;
  char *vs;

  del_qe = NULL;
  if (0 == rd_count)
  {
    FPRINTF (stderr,
             _("There are no records under label `%s' that could be deleted.\n"),
             label);
    test_finished ();
    return;
  }
  if ( (NULL == value) &&
       (NULL == typestring) )
  {
    /* delete everything */
    del_qe = GNUNET_NAMESTORE_records_store (ns,
                                             &zone_pkey,
                                             name,
                                             0, NULL,
                                             &del_continuation,
                                             NULL);
    return;
  }
  rd_left = 0;
  if (NULL != typestring)
    type = GNUNET_GNSRECORD_typename_to_number (typestring);
  else
    type = GNUNET_GNSRECORD_TYPE_ANY;
  for (i=0;i<rd_count;i++)
  {
    vs = NULL;
    if (! ( ( (GNUNET_GNSRECORD_TYPE_ANY == type) ||
              (rd[i].record_type == type) ) &&
            ( (NULL == value) ||
              (NULL == (vs = (GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                                                rd[i].data,
                                                                rd[i].data_size)))) ||
              (0 == strcmp (vs, value)) ) ) )
      rdx[rd_left++] = rd[i];
    GNUNET_free_non_null (vs);
  }
  if (rd_count == rd_left)
  {
    /* nothing got deleted */
    FPRINTF (stderr,
             _("There are no records under label `%s' that match the request for deletion.\n"),
             label);
    test_finished ();
    return;
  }
  /* delete everything but what we copied to 'rdx' */
  del_qe = GNUNET_NAMESTORE_records_store (ns,
                                           &zone_pkey,
                                           name,
                                           rd_left, rdx,
                                           &del_continuation,
                                           NULL);
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
  struct GNUNET_GNSRECORD_Data rd;

  if (GNUNET_YES != result)
  {
    FPRINTF (stderr, _("Service `%s' is not running\n"),
	     "namestore");
    return;
  }
  if (! (add|del|list|(NULL != nickstring)|(NULL != uri)|(NULL != reverse_pkey)) )
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
    type = GNUNET_GNSRECORD_typename_to_number (typestring);
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
	GNUNET_GNSRECORD_string_to_value (type,
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
    add_qe = GNUNET_NAMESTORE_records_lookup (ns, &zone_pkey, name,
        &get_existing_record, NULL );
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
    del_qe = GNUNET_NAMESTORE_records_lookup (ns,
                                              &zone_pkey,
                                              name,
                                              &del_monitor,
                                              NULL);
  }
  if (list)
  {
    list_it = GNUNET_NAMESTORE_zone_iteration_start (ns,
                                                     &zone_pkey,
                                                     &display_record,
                                                     NULL);
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

    GNUNET_STRINGS_utf8_tolower (uri, uri);
    if ( (2 != (sscanf (uri,
                        "gnunet://gns/%52s/%63s",
                        sh,
                        sname)) ) ||
         (GNUNET_OK != GNUNET_CRYPTO_ecdsa_public_key_from_string (sh, strlen (sh), &pkey)) )
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
    rd.record_type = GNUNET_GNSRECORD_TYPE_PKEY;
    if (GNUNET_YES == etime_is_rel)
    {
      rd.expiration_time = etime_rel.rel_value_us;
      rd.flags |= GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
    }
    else if (GNUNET_NO == etime_is_rel)
      rd.expiration_time = etime_abs.abs_value_us;
    else
      rd.expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;

    if (1 == is_shadow)
      rd.flags |= GNUNET_GNSRECORD_RF_SHADOW_RECORD;
    add_qe_uri = GNUNET_NAMESTORE_records_store (ns,
						 &zone_pkey,
						 sname,
						 1,
						 &rd,
						 &add_continuation,
						 &add_qe_uri);
  }
  if (NULL != nickstring)
  {
    if (0 == strlen(nickstring))
    {
      fprintf (stderr,
               _("Invalid nick `%s'\n"),
               nickstring);
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    add_qe_uri = GNUNET_NAMESTORE_set_nick(ns, &zone_pkey, nickstring,
        &add_continuation, &add_qe_uri);
  }
  if (monitor)
  {
    zm = GNUNET_NAMESTORE_zone_monitor_start (cfg,
					      &zone_pkey,
                                              GNUNET_YES,
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
    if (NULL != ego_name)
    {
      fprintf (stderr,
               _("Ego `%s' not known to identity service\n"),
               ego_name);
    }
    GNUNET_SCHEDULER_shutdown ();
    ret = -1;
    return;
  }
  zone_pkey = *GNUNET_IDENTITY_ego_get_private_key (ego);
  GNUNET_free_non_null (ego_name);
  ego_name = NULL;
  GNUNET_CLIENT_service_test ("namestore", cfg,
			      GNUNET_TIME_UNIT_SECONDS,
			      &testservice_task,
			      (void *) cfg);
}


static void
default_ego_cb (void *cls,
                struct GNUNET_IDENTITY_Ego *ego,
                void **ctx,
                const char *name)
{
  get_default = NULL;
  if (NULL == ego)
  {
    fprintf (stderr,
             _("No default ego configured in identity service\n"));
    GNUNET_SCHEDULER_shutdown ();
    ret = -1;
    return;
  }
  else
  {
    identity_cb (cls, ego);
  }
}


static void
id_connect_cb (void *cls,
               struct GNUNET_IDENTITY_Ego *ego,
               void **ctx,
               const char *name)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  if (NULL == ego)
  {
    get_default = GNUNET_IDENTITY_get (idh,
                                       "namestore",
                                       &default_ego_cb, (void *) cfg);
  }
}


static void
testservice_id_task (void *cls, int result)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  if (result != GNUNET_YES)
  {
    fprintf (stderr,
             _("Identity service is not running\n"));
    GNUNET_SCHEDULER_shutdown ();
    ret = -1;
    return;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &do_shutdown, (void *) cfg);

  if (NULL == ego_name)
  {
    idh = GNUNET_IDENTITY_connect (cfg, &id_connect_cb, (void *) cfg);
    if (NULL == idh)
      fprintf (stderr, _("Cannot connect to identity service\n"));
    ret = -1;
    return;
  }
  el = GNUNET_IDENTITY_ego_lookup (cfg,
                                   ego_name,
                                   &identity_cb,
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
  if ( (NULL != args[0]) && (NULL == uri) )
    uri = GNUNET_strdup (args[0]);

  GNUNET_CLIENT_service_test ("identity", cfg,
                              GNUNET_TIME_UNIT_SECONDS,
                              &testservice_id_task,
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
  is_public = -1;
  is_shadow = -1;

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
    {'i', "nick", "NICKNAME",
     gettext_noop ("set the desired nick name for the zone"), 1,
     &GNUNET_GETOPT_set_string, &nickstring},
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
     &GNUNET_GETOPT_set_one, &is_public},
    {'s', "shadow", NULL,
     gettext_noop ("create shadow record (only valid if all other records of the same type have expired"), 0,
     &GNUNET_GETOPT_set_one, &is_shadow},
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
