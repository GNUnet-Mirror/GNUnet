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
 * @file gnunet-gns.c
 * @brief command line tool to manipulate the local zone
 * @author Christian Grothoff
 *
 * TODO:
 * - everything
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_dnsparser_lib.h>
#include <gnunet_namestore_service.h>

/**
 * Handle to the namestore.
 */
static struct GNUNET_NAMESTORE_Handle *ns;

/**
 * Hash of the public key of our zone.
 */
static GNUNET_HashCode zone;

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
 * Desired action is to list records.
 */
static int list;

/**
 * Desired action is to remove a record.
 */
static int del;

/**
 * Name of the records to add/list/remove.
 */
static char *name;

/**
 * Value of the record to add/remove.
 */
static char *value;

/**
 * Type of the record to add/remove, NULL to remove all.
 */
static char *typestring;

/**
 * Desired expiration time.
 */
static char *expirationstring;
		

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
  if (NULL != ns)
  {
    GNUNET_NAMESTORE_disconnect (ns, GNUNET_NO);
    ns = NULL;
  }
  if (NULL != zone_pkey)
  {
    GNUNET_CRYPTO_rsa_key_free (zone_pkey);
    zone_pkey = NULL;
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
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;
  uint32_t type;
  const void *data;
  size_t data_size;
  struct in_addr value_a;
  struct in6_addr value_aaaa;
  struct GNUNET_TIME_Relative etime;

  if (NULL == keyfile)
  {
    fprintf (stderr,
	     _("Option `%s' not given, but I need a zone key file!\n"),
	     "z");
    return;
  }
  zone_pkey = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  keyfile = NULL;
  if (! (add|del|list))
  {
    /* nothing more to be done */  
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
  GNUNET_CRYPTO_hash (&pub, sizeof (pub), &zone);

  ns = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == ns)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to connect to namestore\n"));
    return;
  }
  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
  if (NULL == typestring)
    type = 0;
  else
    type = GNUNET_NAMESTORE_typename_to_number (typestring);
  if (UINT32_MAX == type)
  {
    fprintf (stderr, _("Unsupported type `%s'\n"), typestring);
    GNUNET_SCHEDULER_shutdown ();
    return;
  } else if (add)
  {
    fprintf (stderr,
	     _("Missing option `%s' for operation `%s'\n"),
	     "-t", _("add"));
    GNUNET_SCHEDULER_shutdown ();
    return;     
  }
  if (NULL != value)
  {
    switch (type)
    {
    case 0:
      fprintf (stderr, _("Need a record type to interpret value `%s'\n"), value);
      GNUNET_SCHEDULER_shutdown ();
      break;
    case GNUNET_DNSPARSER_TYPE_A:
      if (1 != inet_pton (AF_INET, value, &value_a))
      {
	fprintf (stderr, _("Value `%s' invalid for record type `%s'\n"), 
		 value,
		 typestring);
	GNUNET_SCHEDULER_shutdown ();
	return;
      }
      data = &value_a;
      data_size = sizeof (value_a);
      break;
    case GNUNET_DNSPARSER_TYPE_NS:
      data = value;
      data_size = strlen (value);
      break;
    case GNUNET_DNSPARSER_TYPE_CNAME:
      data = value;
      data_size = strlen (value);
      break;
    case GNUNET_DNSPARSER_TYPE_SOA:
      fprintf (stderr, _("Record type `%s' not implemented yet\n"), typestring);
      GNUNET_SCHEDULER_shutdown ();
      return;
    case GNUNET_DNSPARSER_TYPE_PTR:
      fprintf (stderr, _("Record type `%s' not implemented yet\n"), typestring);
      GNUNET_SCHEDULER_shutdown ();
      return;
    case GNUNET_DNSPARSER_TYPE_MX:
      fprintf (stderr, _("Record type `%s' not implemented yet\n"), typestring);
      GNUNET_SCHEDULER_shutdown ();
      return;
    case GNUNET_DNSPARSER_TYPE_TXT:
      data = value;
      data_size = strlen (value);
      break;
    case GNUNET_DNSPARSER_TYPE_AAAA:
      if (1 != inet_pton (AF_INET6, value, &value_aaaa))
      {
	fprintf (stderr, _("Value `%s' invalid for record type `%s'\n"), 
		 value,
		 typestring);
	GNUNET_SCHEDULER_shutdown ();
	return;
      }
      data = &value_aaaa;
      data_size = sizeof (value_aaaa);
      break;
    case GNUNET_GNS_TYPE_PKEY:
      fprintf (stderr, _("Record type `%s' not implemented yet\n"), typestring);
      GNUNET_SCHEDULER_shutdown ();
      return;
    case GNUNET_GNS_TYPE_PSEU:
      data = value;
      data_size = strlen (value);
      break;
    default:
      GNUNET_assert (0);
    }
  } else if (add)
  {
    fprintf (stderr,
	     _("Missing option `%s' for operation `%s'\n"),
	     "-V", _("add"));
    GNUNET_SCHEDULER_shutdown ();
    return;     
  }
  if (NULL != expirationstring)
  {
    if (GNUNET_OK !=
	GNUNET_STRINGS_fancy_time_to_relative (expirationstring,
					       &etime))
    {
      fprintf (stderr,
	       _("Invalid time format `%s'\n"),
	       expirationstring);
      GNUNET_SCHEDULER_shutdown ();
      return;     
    }
  } else if (add)
  {
    fprintf (stderr,
	     _("Missing option `%s' for operation `%s'\n"),
	     "-e", _("add"));
    GNUNET_SCHEDULER_shutdown ();
    return;     
  }
  if (add)
  {
    // FIXME
  }
  if (del)
  {
    // FIXME
  }
  if (list)
  {
    // FIXME
  }
}


/**
 * The main function for gnunet-gns.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
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
     gettext_noop ("expiration time to use (for adding only)"), 1,
     &GNUNET_GETOPT_set_string, &expirationstring},   
    {'n', "name", "NAME",
     gettext_noop ("name of the record to add/delete/display"), 1,
     &GNUNET_GETOPT_set_string, &name},   
    {'t', "type", "TYPE",
     gettext_noop ("type of the record to add/delete/display"), 1,
     &GNUNET_GETOPT_set_string, &typestring},   
    {'V', "value", "VALUE",
     gettext_noop ("value of the record to add/delete"), 1,
     &GNUNET_GETOPT_set_string, &value},   
    {'z', "zonekey", "FILENAME",
     gettext_noop ("filename with the zone key"), 1,
     &GNUNET_GETOPT_set_string, &keyfile},   
    GNUNET_GETOPT_OPTION_END
  };

  int ret;

  GNUNET_log_setup ("gnunet-gns", "WARNING", NULL);
  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv, "gnunet-gns",
                           _("GNUnet GNS zone manipulation tool"), 
			   options,
                           &run, NULL)) ? 0 : 1;

  return ret;
}

/* end of gnunet-gns.c */
