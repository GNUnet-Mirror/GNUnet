/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * - allow users to set record options (not just 'RF_AUTHORITY')
 * - test
 * - add options to list/lookup individual records
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_dnsparser_lib.h>
#include <gnunet_namestore_service.h>


/**
 * Hostkey generation context
 */
struct GNUNET_CRYPTO_RsaKeyGenerationContext * keygen;

/**
 * Handle to the namestore.
 */
static struct GNUNET_NAMESTORE_Handle *ns;

/**
 * Hash of the public key of our zone.
 */
static struct GNUNET_CRYPTO_ShortHashCode zone;

/**
 * Private key for the our zone.
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *zone_pkey;

/**
 * Keyfile to manipulate.
 */
static char *keyfile;	

/**
 * Desired action is to add a record.
 */
static int add;

/**
 * Queue entry for the 'add' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *add_qe;

/**
 * Queue entry for the 'add-uri' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *add_qe_uri;

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
 * Is record public
 */
static int public;

/**
 * Is record authority
 */
static int nonauthority;

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
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
do_shutdown (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != keygen)
  {
    GNUNET_CRYPTO_rsa_key_create_stop (keygen);
    keygen = NULL;
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
  if (NULL != zone_pkey)
  {
    GNUNET_CRYPTO_rsa_key_free (zone_pkey);
    zone_pkey = NULL;
  }
  if (NULL != uri)
  {
    GNUNET_free (uri);
    uri = NULL;
  }
}


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure, location of the QueueEntry pointer to NULL out
 * @param success GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                GNUNET_NO if content was already there
 *                GNUNET_YES (or other positive value) on success
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
  if ( (NULL == add_qe) &&
       (NULL == add_qe_uri) &&
       (NULL == del_qe) &&
       (NULL == list_it) )
    GNUNET_SCHEDULER_shutdown ();
}


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure, unused
 * @param success GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                GNUNET_NO if content was already there
 *                GNUNET_YES (or other positive value) on success
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
  if ( (NULL == add_qe) &&
       (NULL == add_qe_uri) &&
       (NULL == list_it) )
    GNUNET_SCHEDULER_shutdown ();
}


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls closure
 * @param zone_key public key of the zone
 * @param expire when does the corresponding block in the DHT expire (until
 *               when should we never do a DHT lookup for the same name again)?; 
 *               GNUNET_TIME_UNIT_ZERO_ABS if there are no records of any type in the namestore,
 *               or the expiration time of the block in the namestore (even if there are zero
 *               records matching the desired record type)
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_len number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature of the record block, NULL if signature is unavailable (i.e. 
 *        because the user queried for a particular record type only)
 */
static void
display_record (void *cls,
		const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
		struct GNUNET_TIME_Absolute expire,			    
		const char *name,
		unsigned int rd_len,
		const struct GNUNET_NAMESTORE_RecordData *rd,
		const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  const char *typestring;
  char *s;
  unsigned int i;
  const char *etime;
  struct GNUNET_TIME_Absolute aex;
  struct GNUNET_TIME_Relative rex;

  if (NULL == name)
  {
    list_it = NULL;
    if ( (NULL == del_qe) &&
	 (NULL == add_qe_uri) &&
	 (NULL == add_qe) )
      GNUNET_SCHEDULER_shutdown ();
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
      rex.rel_value = rd[i].expiration_time;
      etime = GNUNET_STRINGS_relative_time_to_string (rex, GNUNET_YES);
    }
    else
    {
      aex.abs_value = rd[i].expiration_time;
      etime = GNUNET_STRINGS_absolute_time_to_string (aex);
    }
    FPRINTF (stdout, "\t%s: %s (%s %s)\n", typestring, s, 
	     (0 != (rd[i].flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION)) 
	     ? _(/* what follows is relative expiration */ "for at least")
	     : _(/* what follows is absolute expiration */ "until"),
	     etime);
    GNUNET_free (s);    
  }
  FPRINTF (stdout, "%s", "\n");
  GNUNET_NAMESTORE_zone_iterator_next (list_it);
}

static void
key_generation_cb (void *cls,
                   struct GNUNET_CRYPTO_RsaPrivateKey *pk,
                   const char *emsg)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;
  uint32_t type;
  void *data = NULL;
  size_t data_size = 0;
  struct GNUNET_TIME_Relative etime_rel;
  struct GNUNET_TIME_Absolute etime_abs;
  int etime_is_rel = GNUNET_SYSERR;
  struct GNUNET_NAMESTORE_RecordData rd;

  keygen = NULL;
  if (NULL == pk)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  zone_pkey = pk;

  if (! (add|del|list|(NULL != uri)))
  {
    /* nothing more to be done */  
    fprintf (stderr,
             _("No options given\n"));
    GNUNET_CRYPTO_rsa_key_free (zone_pkey);
    zone_pkey = NULL;
    return; 
  }
  if (NULL == zone_pkey)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to read or create private zone key\n"));
    return;
  }
  GNUNET_CRYPTO_rsa_key_get_public (zone_pkey,
                                    &pub);
  GNUNET_CRYPTO_short_hash (&pub, sizeof (pub), &zone);

  ns = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == ns)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to namestore\n"));
    return;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &do_shutdown, NULL);
  if (NULL == typestring)
    type = 0;
  else
    type = GNUNET_NAMESTORE_typename_to_number (typestring);
  if (UINT32_MAX == type)
  {
    fprintf (stderr, _("Unsupported type `%s'\n"), typestring);
    GNUNET_SCHEDULER_shutdown ();
    ret = 1;
    return;
  }
  if ((NULL == typestring) && (add | del))
  {
    fprintf (stderr,
             _("Missing option `%s' for operation `%s'\n"),
             "-t", _("add/del"));
    GNUNET_SCHEDULER_shutdown ();
    ret = 1;
    return;     
  }
  if (NULL != value)
  {
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
  } else if (add | del)
  {
    fprintf (stderr,
             _("Missing option `%s' for operation `%s'\n"),
             "-V", _("add/del"));
    ret = 1;   
    GNUNET_SCHEDULER_shutdown ();
    return;     
  }
  if (NULL != expirationstring)
  {
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
    if (etime_is_rel && del)
    {
      fprintf (stderr,
               _("Deletion requires either absolute time, or no time at all. Got relative time `%s' instead.\n"),
               expirationstring);
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
  } 
  else if (add)
  {
    fprintf (stderr,
             _("Missing option `%s' for operation `%s'\n"),
             "-e", _("add"));
    GNUNET_SCHEDULER_shutdown ();
    ret = 1;    
    return;     
  }
  memset (&rd, 0, sizeof (rd));
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
    rd.data = data;
    rd.data_size = data_size;
    rd.record_type = type;
    if (GNUNET_YES == etime_is_rel)
    {
      rd.expiration_time = etime_rel.rel_value;
      rd.flags |= GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION;
    }
    else if (GNUNET_NO == etime_is_rel)
      rd.expiration_time = etime_abs.abs_value;
    else
    {
      fprintf (stderr,
               _("No valid expiration time for operation `%s'\n"),
               _("add"));
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    if (1 != nonauthority)
      rd.flags |= GNUNET_NAMESTORE_RF_AUTHORITY;
    if (1 != public)
      rd.flags |= GNUNET_NAMESTORE_RF_PRIVATE;
    add_qe = GNUNET_NAMESTORE_record_create (ns,
                                             zone_pkey,
                                             name,
                                             &rd,
                                             &add_continuation,
                                             &add_qe);
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
    rd.data = data;
    rd.data_size = data_size;
    rd.record_type = type;
    rd.expiration_time = 0;
    if (!etime_is_rel)
      rd.expiration_time = etime_abs.abs_value;
    rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;
    del_qe = GNUNET_NAMESTORE_record_remove (ns,
                                             zone_pkey,
                                             name,
                                             &rd,
                                             &del_continuation,
                                             NULL);
  }
  if (list)
  {
    uint32_t must_not_flags = 0;

    if (1 == nonauthority) /* List non-authority records */
      must_not_flags |= GNUNET_NAMESTORE_RF_AUTHORITY;

    if (1 == public)
      must_not_flags |= GNUNET_NAMESTORE_RF_PRIVATE;

    list_it = GNUNET_NAMESTORE_zone_iteration_start (ns,
                                                     &zone,
                                                     GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION,
                                                     must_not_flags,
                                                     &display_record,
                                                     NULL);
  }
  if (NULL != uri)
  {
    char sh[53];
    char name[64];
    struct GNUNET_CRYPTO_ShortHashCode sc;

    if ( (2 != (sscanf (uri,
                        "gnunet://gns/%52s/%63s",
                        sh,
                        name)) ) ||
         (GNUNET_OK !=
          GNUNET_CRYPTO_short_hash_from_string (sh, &sc)) )
    {
      fprintf (stderr, 
               _("Invalid URI `%s'\n"),
               uri);
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    rd.data = &sc;
    rd.data_size = sizeof (struct GNUNET_CRYPTO_ShortHashCode);
    rd.record_type = GNUNET_NAMESTORE_TYPE_PKEY;
    if (GNUNET_YES == etime_is_rel)
    {
      rd.expiration_time = etime_rel.rel_value;
      rd.flags |= GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION;
    }
    else if (GNUNET_NO == etime_is_rel)
      rd.expiration_time = etime_abs.abs_value;
    else    
      rd.expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value;
    if (1 != nonauthority)
      rd.flags |= GNUNET_NAMESTORE_RF_AUTHORITY;

    add_qe_uri = GNUNET_NAMESTORE_record_create (ns,
                                                 zone_pkey,
                                                 name,
                                                 &rd,
                                                 &add_continuation,
                                                 &add_qe_uri);
  }
  GNUNET_free_non_null (data);

}


static void
testservice_task (void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT))
  {
      FPRINTF (stderr, _("Service `%s' is not running\n"), "namestore");
      return;
  }


  if (NULL == keyfile)
  {
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                              "ZONEKEY", &keyfile))
    {
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
				 "gns", "ZONEKEY");
      return;
    }
    fprintf (stderr,
             _("Using default zone file `%s'\n"),
             keyfile);
  }
  keygen = GNUNET_CRYPTO_rsa_key_create_start (keyfile, key_generation_cb, cfg);
  GNUNET_free (keyfile);
  keyfile = NULL;
  if (NULL == keygen)
  {
    GNUNET_SCHEDULER_shutdown ();
    ret = 1;
  }
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

  GNUNET_CLIENT_service_test ("namestore", cfg,
      GNUNET_TIME_UNIT_SECONDS,
      &testservice_task,
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
  nonauthority = -1;
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
    {'n', "name", "NAME",
     gettext_noop ("name of the record to add/delete/display"), 1,
     &GNUNET_GETOPT_set_string, &name},   
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
    {'N', "non-authority", NULL,
     gettext_noop ("create or list non-authority record"), 0,
     &GNUNET_GETOPT_set_one, &nonauthority},
    {'z', "zonekey", "FILENAME",
     gettext_noop ("filename with the zone key"), 1,
     &GNUNET_GETOPT_set_string, &keyfile},   
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
    return 1;
  }
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-namestore.c */
