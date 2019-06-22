/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2014, 2019 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
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
 * Entry in record set for bulk processing.
 */
struct RecordSetEntry
{
  /**
   * Kept in a linked list.
   */
  struct RecordSetEntry *next;

  /**
   * The record to add/remove.
   */
  struct GNUNET_GNSRECORD_Data record;
};


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
 * Queue entry for the 'lookup' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *get_qe;

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
 * Queue entry for the 'set/replace' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *set_qe;

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
 * Number of bytes in #data.
 */
static size_t data_size;

/**
 * Expiration string converted to numeric value.
 */
static uint64_t etime;

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
 * Entry in record set for processing records in bulk.
 */
static struct RecordSetEntry *recordset;


/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 */
static void
do_shutdown (void *cls)
{
  (void) cls;
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
  if (NULL != set_qe)
  {
    GNUNET_NAMESTORE_cancel (set_qe);
    set_qe = NULL;
  }
  if (NULL != add_qe_uri)
  {
    GNUNET_NAMESTORE_cancel (add_qe_uri);
    add_qe_uri = NULL;
  }
  if (NULL != get_qe)
  {
    GNUNET_NAMESTORE_cancel (get_qe);
    get_qe = NULL;
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
  if ((NULL == add_qe) && (NULL == add_qe_uri) && (NULL == get_qe) &&
      (NULL == del_qe) && (NULL == reverse_qe) && (NULL == list_it))
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
add_continuation (void *cls, int32_t success, const char *emsg)
{
  struct GNUNET_NAMESTORE_QueueEntry **qe = cls;

  *qe = NULL;
  if (GNUNET_YES != success)
  {
    fprintf (stderr,
             _ ("Adding record failed: %s\n"),
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
del_continuation (void *cls, int32_t success, const char *emsg)
{
  (void) cls;
  del_qe = NULL;
  if (GNUNET_NO == success)
  {
    fprintf (stderr,
             _ ("Deleting record failed, record does not exist%s%s\n"),
             (NULL != emsg) ? ": " : "",
             (NULL != emsg) ? emsg : "");
  }
  if (GNUNET_SYSERR == success)
  {
    fprintf (stderr,
             _ ("Deleting record failed%s%s\n"),
             (NULL != emsg) ? ": " : "",
             (NULL != emsg) ? emsg : "");
  }
  test_finished ();
}


/**
 * Function called when we are done with a zone iteration.
 */
static void
zone_iteration_finished (void *cls)
{
  (void) cls;
  list_it = NULL;
  test_finished ();
}


/**
 * Function called when we encountered an error in a zone iteration.
 */
static void
zone_iteration_error_cb (void *cls)
{
  (void) cls;
  list_it = NULL;
  fprintf (stderr, "Error iterating over zone\n");
  ret = 1;
  test_finished ();
}


/**
 * Process a record that was stored in the namestore.
 *
 * @param rname name that is being mapped (at most 255 characters long)
 * @param rd_len number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
display_record (const char *rname,
                unsigned int rd_len,
                const struct GNUNET_GNSRECORD_Data *rd)
{
  const char *typestr;
  char *s;
  const char *ets;
  struct GNUNET_TIME_Absolute at;
  struct GNUNET_TIME_Relative rt;
  int have_record;

  if ((NULL != name) && (0 != strcmp (name, rname)))
  {
    GNUNET_NAMESTORE_zone_iterator_next (list_it, 1);
    return;
  }
  have_record = GNUNET_NO;
  for (unsigned int i = 0; i < rd_len; i++)
  {
    if ((GNUNET_GNSRECORD_TYPE_NICK == rd[i].record_type) &&
        (0 != strcmp (rname, GNUNET_GNS_EMPTY_LABEL_AT)))
      continue;
    if ((type != rd[i].record_type) && (GNUNET_GNSRECORD_TYPE_ANY != type))
      continue;
    have_record = GNUNET_YES;
    break;
  }
  if (GNUNET_NO == have_record)
    return;
  FPRINTF (stdout, "%s:\n", rname);
  if (NULL != typestring)
    type = GNUNET_GNSRECORD_typename_to_number (typestring);
  else
    type = GNUNET_GNSRECORD_TYPE_ANY;
  for (unsigned int i = 0; i < rd_len; i++)
  {
    if ((GNUNET_GNSRECORD_TYPE_NICK == rd[i].record_type) &&
        (0 != strcmp (rname, GNUNET_GNS_EMPTY_LABEL_AT)))
      continue;
    if ((type != rd[i].record_type) && (GNUNET_GNSRECORD_TYPE_ANY != type))
      continue;
    typestr = GNUNET_GNSRECORD_number_to_typename (rd[i].record_type);
    s = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                          rd[i].data,
                                          rd[i].data_size);
    if (NULL == s)
    {
      FPRINTF (stdout,
               _ ("\tCorrupt or unsupported record of type %u\n"),
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
             "\t%s: %s (%s)\t%s\t%s\n",
             typestr,
             s,
             ets,
             (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_PRIVATE)) ? "PRIVATE"
                                                                : "PUBLIC",
             (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_SHADOW_RECORD)) ? "SHADOW"
                                                                      : "");
    GNUNET_free (s);
  }
  FPRINTF (stdout, "%s", "\n");
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
display_record_iterator (void *cls,
                         const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
                         const char *rname,
                         unsigned int rd_len,
                         const struct GNUNET_GNSRECORD_Data *rd)
{
  (void) cls;
  (void) zone_key;
  display_record (rname, rd_len, rd);
  GNUNET_NAMESTORE_zone_iterator_next (list_it, 1);
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
display_record_monitor (void *cls,
                        const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
                        const char *rname,
                        unsigned int rd_len,
                        const struct GNUNET_GNSRECORD_Data *rd)
{
  (void) cls;
  (void) zone_key;
  display_record (rname, rd_len, rd);
  GNUNET_NAMESTORE_zone_monitor_next (zm, 1);
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
display_record_lookup (void *cls,
                       const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
                       const char *rname,
                       unsigned int rd_len,
                       const struct GNUNET_GNSRECORD_Data *rd)
{
  (void) cls;
  (void) zone_key;
  get_qe = NULL;
  display_record (rname, rd_len, rd);
  test_finished ();
}


/**
 * Function called once we are in sync in monitor mode.
 *
 * @param cls NULL
 */
static void
sync_cb (void *cls)
{
  (void) cls;
  FPRINTF (stdout, "%s", "Monitor is now in sync.\n");
}


/**
 * Function called on errors while monitoring.
 *
 * @param cls NULL
 */
static void
monitor_error_cb (void *cls)
{
  (void) cls;
  FPRINTF (stderr, "%s", "Monitor disconnected and out of sync.\n");
}


/**
 * Function called on errors while monitoring.
 *
 * @param cls NULL
 */
static void
lookup_error_cb (void *cls)
{
  (void) cls;
  get_qe = NULL;
  FPRINTF (stderr, "%s", "Failed to lookup record.\n");
  test_finished ();
}


/**
 * Function called if lookup fails.
 */
static void
add_error_cb (void *cls)
{
  (void) cls;
  add_qe = NULL;
  GNUNET_break (0);
  ret = 1;
  test_finished ();
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

  (void) cls;
  (void) zone_key;
  add_qe = NULL;
  if (0 != strcmp (rec_name, name))
  {
    GNUNET_break (0);
    ret = 1;
    test_finished ();
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received %u records for name `%s'\n",
              rd_count,
              rec_name);
  for (unsigned int i = 0; i < rd_count; i++)
  {
    switch (rd[i].record_type)
    {
    case GNUNET_DNSPARSER_TYPE_CNAME:
      fprintf (
        stderr,
        _ (
          "A %s record exists already under `%s', no other records can be added.\n"),
        "CNAME",
        rec_name);
      ret = 1;
      test_finished ();
      return;
    case GNUNET_GNSRECORD_TYPE_PKEY:
      fprintf (
        stderr,
        _ (
          "A %s record exists already under `%s', no other records can be added.\n"),
        "PKEY",
        rec_name);
      ret = 1;
      test_finished ();
      return;
    case GNUNET_DNSPARSER_TYPE_SOA:
      if (GNUNET_DNSPARSER_TYPE_SOA == type)
      {
        fprintf (
          stderr,
          _ (
            "A SOA record exists already under `%s', cannot add a second SOA to the same zone.\n"),
          rec_name);
        ret = 1;
        test_finished ();
        return;
      }
      break;
    }
  }
  switch (type)
  {
  case GNUNET_DNSPARSER_TYPE_CNAME:
    if (0 != rd_count)
    {
      fprintf (stderr,
               _ (
                 "Records already exist under `%s', cannot add `%s' record.\n"),
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
               _ (
                 "Records already exist under `%s', cannot add `%s' record.\n"),
               rec_name,
               "PKEY");
      ret = 1;
      test_finished ();
      return;
    }
    break;
  case GNUNET_GNSRECORD_TYPE_GNS2DNS:
    for (unsigned int i = 0; i < rd_count; i++)
      if (GNUNET_GNSRECORD_TYPE_GNS2DNS != rd[i].record_type)
      {
        fprintf (
          stderr,
          _ (
            "Non-GNS2DNS records already exist under `%s', cannot add GNS2DNS record.\n"),
          rec_name);
        ret = 1;
        test_finished ();
        return;
      }
    break;
  }
  memset (rdn, 0, sizeof (struct GNUNET_GNSRECORD_Data));
  GNUNET_memcpy (&rdn[1], rd, rd_count * sizeof (struct GNUNET_GNSRECORD_Data));
  rde = &rdn[0];
  rde->data = data;
  rde->data_size = data_size;
  rde->record_type = type;
  if (1 == is_shadow)
    rde->flags |= GNUNET_GNSRECORD_RF_SHADOW_RECORD;
  if (1 != is_public)
    rde->flags |= GNUNET_GNSRECORD_RF_PRIVATE;
  rde->expiration_time = etime;
  if (GNUNET_YES == etime_is_rel)
    rde->flags |= GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  else if (GNUNET_NO != etime_is_rel)
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
 * Function called if we encountered an error in zone-to-name.
 */
static void
reverse_error_cb (void *cls)
{
  (void) cls;
  reverse_qe = NULL;
  FPRINTF (stdout, "%s.zkey\n", reverse_pkey);
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
  (void) cls;
  (void) zone;
  (void) rd_count;
  (void) rd;
  reverse_qe = NULL;
  if (NULL == label)
    FPRINTF (stdout, "%s\n", reverse_pkey);
  else
    FPRINTF (stdout, "%s.%s\n", label, ego_name);
  test_finished ();
}


/**
 * Function called if lookup for deletion fails.
 */
static void
del_lookup_error_cb (void *cls)
{
  (void) cls;
  del_qe = NULL;
  GNUNET_break (0);
  ret = 1;
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
  uint32_t type;
  char *vs;

  (void) cls;
  (void) zone;
  del_qe = NULL;
  if (0 == rd_count)
  {
    FPRINTF (stderr,
             _ (
               "There are no records under label `%s' that could be deleted.\n"),
             label);
    ret = 1;
    test_finished ();
    return;
  }
  if ((NULL == value) && (NULL == typestring))
  {
    /* delete everything */
    del_qe = GNUNET_NAMESTORE_records_store (ns,
                                             &zone_pkey,
                                             name,
                                             0,
                                             NULL,
                                             &del_continuation,
                                             NULL);
    return;
  }
  rd_left = 0;
  if (NULL != typestring)
    type = GNUNET_GNSRECORD_typename_to_number (typestring);
  else
    type = GNUNET_GNSRECORD_TYPE_ANY;
  for (unsigned int i = 0; i < rd_count; i++)
  {
    vs = NULL;
    if (! (((GNUNET_GNSRECORD_TYPE_ANY == type) ||
            (rd[i].record_type == type)) &&
           ((NULL == value) ||
            (NULL ==
             (vs = (GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                                      rd[i].data,
                                                      rd[i].data_size)))) ||
            (0 == strcmp (vs, value)))))
      rdx[rd_left++] = rd[i];
    GNUNET_free_non_null (vs);
  }
  if (rd_count == rd_left)
  {
    /* nothing got deleted */
    FPRINTF (
      stderr,
      _ (
        "There are no records under label `%s' that match the request for deletion.\n"),
      label);
    test_finished ();
    return;
  }
  /* delete everything but what we copied to 'rdx' */
  del_qe = GNUNET_NAMESTORE_records_store (ns,
                                           &zone_pkey,
                                           name,
                                           rd_left,
                                           rdx,
                                           &del_continuation,
                                           NULL);
}


/**
 * Parse expiration time.
 *
 * @param expirationstring text to parse
 * @param etime_is_rel[out] set to #GNUNET_YES if time is relative
 * @param etime[out] set to expiration time (abs or rel)
 * @return #GNUNET_OK on success
 */
static int
parse_expiration (const char *expirationstring,
                  int *etime_is_rel,
                  uint64_t *etime)
{
  struct GNUNET_TIME_Relative etime_rel;
  struct GNUNET_TIME_Absolute etime_abs;

  if (0 == strcmp (expirationstring, "never"))
  {
    *etime = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
    *etime_is_rel = GNUNET_NO;
    return GNUNET_OK;
  }
  if (GNUNET_OK ==
      GNUNET_STRINGS_fancy_time_to_relative (expirationstring, &etime_rel))
  {
    *etime_is_rel = GNUNET_YES;
    *etime = etime_rel.rel_value_us;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Storing record with relative expiration time of %s\n",
                GNUNET_STRINGS_relative_time_to_string (etime_rel, GNUNET_NO));
    return GNUNET_OK;
  }
  if (GNUNET_OK ==
      GNUNET_STRINGS_fancy_time_to_absolute (expirationstring, &etime_abs))
  {
    *etime_is_rel = GNUNET_NO;
    *etime = etime_abs.abs_value_us;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Storing record with absolute expiration time of %s\n",
                GNUNET_STRINGS_absolute_time_to_string (etime_abs));
    return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}


/**
 * Function called when namestore is done with the replace
 * operation.
 *
 * @param cls NULL
 * @param success #GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                #GNUNET_NO if content was already there or not found
 *                #GNUNET_YES (or other positive value) on success
 * @param emsg NULL on success, otherwise an error message
 */
static void
replace_cont (void *cls, int success, const char *emsg)
{
  (void) cls;

  set_qe = NULL;
  if (GNUNET_OK != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                _ ("Failed to replace records: %s\n"),
                emsg);
    ret = 1; /* fail from 'main' */
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * We have obtained the zone's private key, so now process
 * the main commands using it.
 *
 * @param cfg configuration to use
 */
static void
run_with_zone_pkey (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_GNSRECORD_Data rd;

  if (! (add | del | list | (NULL != nickstring) | (NULL != uri) |
         (NULL != reverse_pkey) | (NULL != recordset)))
  {
    /* nothing more to be done */
    fprintf (stderr, _ ("No options given\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  ns = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == ns)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to connect to namestore\n"));
    return;
  }

  if (NULL != recordset)
  {
    /* replace entire record set */
    unsigned int rd_count;
    struct GNUNET_GNSRECORD_Data *rd;

    if (NULL == name)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-R",
               _ ("replace"));
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    rd_count = 0;
    for (struct RecordSetEntry *e = recordset; NULL != e; e = e->next)
      rd_count++;
    rd = GNUNET_new_array (rd_count, struct GNUNET_GNSRECORD_Data);
    rd_count = 0;
    for (struct RecordSetEntry *e = recordset; NULL != e; e = e->next)
    {
      rd[rd_count] = e->record;
      rd_count++;
    }
    set_qe = GNUNET_NAMESTORE_records_store (ns,
                                             &zone_pkey,
                                             name,
                                             rd_count,
                                             rd,
                                             &replace_cont,
                                             NULL);
    GNUNET_free (rd);
    return;
  }

  if (add)
  {
    if (NULL == name)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-n",
               _ ("add"));
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    if (NULL == typestring)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-t",
               _ ("add"));
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    type = GNUNET_GNSRECORD_typename_to_number (typestring);
    if (UINT32_MAX == type)
    {
      fprintf (stderr, _ ("Unsupported type `%s'\n"), typestring);
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    if (NULL == value)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-V",
               _ ("add"));
      ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if (GNUNET_OK !=
        GNUNET_GNSRECORD_string_to_value (type, value, &data, &data_size))
    {
      fprintf (stderr,
               _ ("Value `%s' invalid for record type `%s'\n"),
               value,
               typestring);
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    if (NULL == expirationstring)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-e",
               _ ("add"));
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    if (GNUNET_OK != parse_expiration (expirationstring, &etime_is_rel, &etime))
    {
      fprintf (stderr, _ ("Invalid time format `%s'\n"), expirationstring);
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    add_qe = GNUNET_NAMESTORE_records_lookup (ns,
                                              &zone_pkey,
                                              name,
                                              &add_error_cb,
                                              NULL,
                                              &get_existing_record,
                                              NULL);
  }
  if (del)
  {
    if (NULL == name)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-n",
               _ ("del"));
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    del_qe = GNUNET_NAMESTORE_records_lookup (ns,
                                              &zone_pkey,
                                              name,
                                              &del_lookup_error_cb,
                                              NULL,
                                              &del_monitor,
                                              NULL);
  }
  if (list)
  {
    if (NULL != name)
      get_qe = GNUNET_NAMESTORE_records_lookup (ns,
                                                &zone_pkey,
                                                name,
                                                &lookup_error_cb,
                                                NULL,
                                                &display_record_lookup,
                                                NULL);
    else
      list_it = GNUNET_NAMESTORE_zone_iteration_start (ns,
                                                       &zone_pkey,
                                                       &zone_iteration_error_cb,
                                                       NULL,
                                                       &display_record_iterator,
                                                       NULL,
                                                       &zone_iteration_finished,
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
               _ ("Invalid public key for reverse lookup `%s'\n"),
               reverse_pkey);
      GNUNET_SCHEDULER_shutdown ();
    }
    reverse_qe = GNUNET_NAMESTORE_zone_to_name (ns,
                                                &zone_pkey,
                                                &pubkey,
                                                &reverse_error_cb,
                                                NULL,
                                                &handle_reverse_lookup,
                                                NULL);
  }
  if (NULL != uri)
  {
    char sh[105];
    char sname[64];
    struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

    GNUNET_STRINGS_utf8_tolower (uri, uri);
    if ((2 != (sscanf (uri, "gnunet://gns/%52s/%63s", sh, sname))) ||
        (GNUNET_OK !=
         GNUNET_CRYPTO_ecdsa_public_key_from_string (sh, strlen (sh), &pkey)))
    {
      fprintf (stderr, _ ("Invalid URI `%s'\n"), uri);
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    memset (&rd, 0, sizeof (rd));
    rd.data = &pkey;
    rd.data_size = sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey);
    rd.record_type = GNUNET_GNSRECORD_TYPE_PKEY;
    rd.expiration_time = etime;
    if (GNUNET_YES == etime_is_rel)
      rd.flags |= GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
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
    if (0 == strlen (nickstring))
    {
      fprintf (stderr, _ ("Invalid nick `%s'\n"), nickstring);
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    add_qe_uri = GNUNET_NAMESTORE_set_nick (ns,
                                            &zone_pkey,
                                            nickstring,
                                            &add_continuation,
                                            &add_qe_uri);
  }
  if (monitor)
  {
    zm = GNUNET_NAMESTORE_zone_monitor_start (cfg,
                                              &zone_pkey,
                                              GNUNET_YES,
                                              &monitor_error_cb,
                                              NULL,
                                              &display_record_monitor,
                                              NULL,
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
identity_cb (void *cls, const struct GNUNET_IDENTITY_Ego *ego)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  el = NULL;
  if ((NULL != name) && (0 != strchr (name, '.')))
  {
    fprintf (stderr,
             _ ("Label `%s' contains `.' which is not allowed\n"),
             name);
    GNUNET_SCHEDULER_shutdown ();
    ret = -1;
    return;
  }

  if (NULL == ego)
  {
    if (NULL != ego_name)
    {
      fprintf (stderr,
               _ ("Ego `%s' not known to identity service\n"),
               ego_name);
    }
    GNUNET_SCHEDULER_shutdown ();
    ret = -1;
    return;
  }
  zone_pkey = *GNUNET_IDENTITY_ego_get_private_key (ego);
  GNUNET_free_non_null (ego_name);
  ego_name = NULL;
  run_with_zone_pkey (cfg);
}


/**
 * Function called with the default ego to be used for GNS
 * operations. Used if the user did not specify a zone via
 * command-line or environment variables.
 *
 * @param cls NULL
 * @param ego default ego, NULL for none
 * @param ctx NULL
 * @param name unused
 */
static void
default_ego_cb (void *cls,
                struct GNUNET_IDENTITY_Ego *ego,
                void **ctx,
                const char *name)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  (void) ctx;
  (void) name;
  get_default = NULL;
  if (NULL == ego)
  {
    fprintf (stderr, _ ("No default ego configured in identity service\n"));
    GNUNET_SCHEDULER_shutdown ();
    ret = -1;
    return;
  }
  else
  {
    identity_cb ((void *) cfg, ego);
  }
}


/**
 * Function called with ALL of the egos known to the
 * identity service, used on startup if the user did
 * not specify a zone on the command-line.
 * Once the iteration is done (@a ego is NULL), we
 * ask for the default ego for "namestore".
 *
 * @param cls a `struct GNUNET_CONFIGURATION_Handle`
 * @param ego an ego, NULL for end of iteration
 * @param ctx NULL
 * @param name name associated with @a ego
 */
static void
id_connect_cb (void *cls,
               struct GNUNET_IDENTITY_Ego *ego,
               void **ctx,
               const char *name)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  (void) ctx;
  (void) name;
  if (NULL != ego)
    return;
  get_default =
    GNUNET_IDENTITY_get (idh, "namestore", &default_ego_cb, (void *) cfg);
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  const char *pkey_str;

  (void) cls;
  (void) args;
  (void) cfgfile;
  if (NULL != args[0])
    GNUNET_log (
      GNUNET_ERROR_TYPE_WARNING,
      _ ("Superfluous command line arguments (starting with `%s') ignored\n"),
      args[0]);
  if ((NULL != args[0]) && (NULL == uri))
    uri = GNUNET_strdup (args[0]);

  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, (void *) cfg);
  pkey_str = getenv ("GNUNET_NAMESTORE_EGO_PRIVATE_KEY");
  if (NULL != pkey_str)
  {
    if (GNUNET_OK != GNUNET_STRINGS_string_to_data (pkey_str,
                                                    strlen (pkey_str),
                                                    &zone_pkey,
                                                    sizeof (zone_pkey)))
    {
      fprintf (stderr,
               "Malformed private key `%s' in $%s\n",
               pkey_str,
               "GNUNET_NAMESTORE_EGO_PRIVATE_KEY");
      ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    run_with_zone_pkey (cfg);
    return;
  }
  if (NULL == ego_name)
  {
    idh = GNUNET_IDENTITY_connect (cfg, &id_connect_cb, (void *) cfg);
    if (NULL == idh)
      fprintf (stderr, _ ("Cannot connect to identity service\n"));
    ret = -1;
    return;
  }
  el = GNUNET_IDENTITY_ego_lookup (cfg, ego_name, &identity_cb, (void *) cfg);
}


/**
 * Command-line option parser function that allows the user to specify
 * a complete record as one argument for adding/removing.  A pointer
 * to the head of the list of record sets must be passed as the "scls"
 * argument.
 *
 * @param ctx command line processor context
 * @param scls must be of type "struct GNUNET_FS_Uri **"
 * @param option name of the option (typically 'R')
 * @param value command line argument given; format is
 *        "TTL TYPE FLAGS VALUE" where TTL is an expiration time (rel or abs),
 *        always given in seconds (without the unit),
 *         TYPE is a DNS/GNS record type, FLAGS is either "n" for no flags or
 *         a combination of 's' (shadow) and 'p' (public) and VALUE is the
 *         value (in human-readable format)
 * @return #GNUNET_OK on success
 */
static int
multirecord_process (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                     void *scls,
                     const char *option,
                     const char *value)
{
  struct RecordSetEntry **head = scls;
  struct RecordSetEntry *r;
  struct GNUNET_GNSRECORD_Data record;
  char *cp;
  char *tok;
  char *saveptr;
  int etime_is_rel;
  void *raw_data;

  (void) ctx;
  (void) option;
  cp = GNUNET_strdup (value);
  tok = strtok_r (cp, " ", &saveptr);
  if (NULL == tok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Empty record line argument is not allowed.\n"));
    GNUNET_free (cp);
    return GNUNET_SYSERR;
  }
  {
    char *etime_in_s;

    GNUNET_asprintf (&etime_in_s, "%s s", tok);
    if (GNUNET_OK !=
        parse_expiration (etime_in_s, &etime_is_rel, &record.expiration_time))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Invalid expiration time `%s' (must be without unit)\n"),
                  tok);
      GNUNET_free (cp);
      GNUNET_free (etime_in_s);
      return GNUNET_SYSERR;
    }
    GNUNET_free (etime_in_s);
  }
  tok = strtok_r (NULL, " ", &saveptr);
  if (NULL == tok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Missing entries in record line `%s'.\n"),
                value);
    GNUNET_free (cp);
    return GNUNET_SYSERR;
  }
  record.record_type = GNUNET_GNSRECORD_typename_to_number (tok);
  if (UINT32_MAX == record.record_type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _ ("Unknown record type `%s'\n"), tok);
    GNUNET_free (cp);
    return GNUNET_SYSERR;
  }
  tok = strtok_r (NULL, " ", &saveptr);
  if (NULL == tok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Missing entries in record line `%s'.\n"),
                value);
    GNUNET_free (cp);
    return GNUNET_SYSERR;
  }
  record.flags = GNUNET_GNSRECORD_RF_NONE;
  if (etime_is_rel)
    record.flags |= GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  if (NULL == strchr (tok, (unsigned char) 'p')) /* p = public */
    record.flags |= GNUNET_GNSRECORD_RF_PRIVATE;
  if (NULL != strchr (tok, (unsigned char) 's'))
    record.flags |= GNUNET_GNSRECORD_RF_SHADOW_RECORD;
  /* find beginning of record value */
  tok = strchr (&value[tok - cp], (unsigned char) ' ');
  if (NULL == tok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Missing entries in record line `%s'.\n"),
                value);
    GNUNET_free (cp);
    return GNUNET_SYSERR;
  }
  GNUNET_free (cp);
  tok++; /* skip space */
  if (GNUNET_OK != GNUNET_GNSRECORD_string_to_value (record.record_type,
                                                     tok,
                                                     &raw_data,
                                                     &record.data_size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Invalid record data for type %s: `%s'.\n"),
                GNUNET_GNSRECORD_number_to_typename (record.record_type),
                tok);
    return GNUNET_SYSERR;
  }

  r = GNUNET_malloc (sizeof (struct RecordSetEntry) + record.data_size);
  r->next = *head;
  record.data = &r[1];
  memcpy (&r[1], raw_data, record.data_size);
  GNUNET_free (raw_data);
  r->record = record;
  *head = r;
  return GNUNET_OK;
}


/**
 * Allow user to specify keywords.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] topKeywords set to the desired value
 */
struct GNUNET_GETOPT_CommandLineOption
multirecord_option (char shortName,
                    const char *name,
                    const char *argumentHelp,
                    const char *description,
                    struct RecordSetEntry **rs)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {.shortName = shortName,
                                                .name = name,
                                                .argumentHelp = argumentHelp,
                                                .description = description,
                                                .require_argument = 1,
                                                .processor =
                                                  &multirecord_process,
                                                .scls = (void *) rs};

  return clo;
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
  struct GNUNET_GETOPT_CommandLineOption options[] =
    {GNUNET_GETOPT_option_flag ('a', "add", gettext_noop ("add record"), &add),
     GNUNET_GETOPT_option_flag ('d',
                                "delete",
                                gettext_noop ("delete record"),
                                &del),
     GNUNET_GETOPT_option_flag ('D',
                                "display",
                                gettext_noop ("display records"),
                                &list),
     GNUNET_GETOPT_option_string (
       'e',
       "expiration",
       "TIME",
       gettext_noop (
         "expiration time for record to use (for adding only), \"never\" is possible"),
       &expirationstring),
     GNUNET_GETOPT_option_string ('i',
                                  "nick",
                                  "NICKNAME",
                                  gettext_noop (
                                    "set the desired nick name for the zone"),
                                  &nickstring),
     GNUNET_GETOPT_option_flag ('m',
                                "monitor",
                                gettext_noop (
                                  "monitor changes in the namestore"),
                                &monitor),
     GNUNET_GETOPT_option_string ('n',
                                  "name",
                                  "NAME",
                                  gettext_noop (
                                    "name of the record to add/delete/display"),
                                  &name),
     GNUNET_GETOPT_option_string ('r',
                                  "reverse",
                                  "PKEY",
                                  gettext_noop (
                                    "determine our name for the given PKEY"),
                                  &reverse_pkey),
     multirecord_option (
       'R',
       "replace",
       "RECORDLINE",
       gettext_noop (
         "set record set to values given by (possibly multiple) RECORDLINES; can be specified multiple times"),
       &recordset),
     GNUNET_GETOPT_option_string ('t',
                                  "type",
                                  "TYPE",
                                  gettext_noop (
                                    "type of the record to add/delete/display"),
                                  &typestring),
     GNUNET_GETOPT_option_string ('u',
                                  "uri",
                                  "URI",
                                  gettext_noop ("URI to import into our zone"),
                                  &uri),
     GNUNET_GETOPT_option_string ('V',
                                  "value",
                                  "VALUE",
                                  gettext_noop (
                                    "value of the record to add/delete"),
                                  &value),
     GNUNET_GETOPT_option_flag ('p',
                                "public",
                                gettext_noop ("create or list public record"),
                                &is_public),
     GNUNET_GETOPT_option_flag (
       's',
       "shadow",
       gettext_noop (
         "create shadow record (only valid if all other records of the same type have expired"),
       &is_shadow),
     GNUNET_GETOPT_option_string ('z',
                                  "zone",
                                  "EGO",
                                  gettext_noop (
                                    "name of the ego controlling the zone"),
                                  &ego_name),
     GNUNET_GETOPT_OPTION_END};
  int lret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  is_public = -1;
  is_shadow = -1;
  GNUNET_log_setup ("gnunet-namestore", "WARNING", NULL);
  if (GNUNET_OK !=
      (lret = GNUNET_PROGRAM_run (argc,
                                  argv,
                                  "gnunet-namestore",
                                  _ ("GNUnet zone manipulation tool"),
                                  options,
                                  &run,
                                  NULL)))
  {
    GNUNET_free ((void *) argv);
    GNUNET_CRYPTO_ecdsa_key_clear (&zone_pkey);
    return lret;
  }
  GNUNET_free ((void *) argv);
  GNUNET_CRYPTO_ecdsa_key_clear (&zone_pkey);
  return ret;
}

/* end of gnunet-namestore.c */
