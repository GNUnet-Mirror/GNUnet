/*
     This file is part of GNUnet.
     Copyright (C) 2012-2013 Christian Grothoff (and other contributing authors)

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
 * @brief binary version of gnunet-gns-import.sh
 *        (for OSes that have no POSIX shell).
 * @author LRN
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_gnsrecord_lib.h>
#include <gnunet_identity_service.h>
#include <gnunet_namestore_service.h>

/**
 * Configuration we are using.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to IDENTITY service.
 */
static struct GNUNET_IDENTITY_Handle *sh;

/**
 * Zone iterator for master zone
 */
struct GNUNET_NAMESTORE_ZoneIterator *list_it;

/**
 * Handle to the namestore.
 */
static struct GNUNET_NAMESTORE_Handle *ns;

/**
 * String version of PKEY for master-zone.
 */
static char *master_zone_pkey;

/**
 * Binary version of PKEY for master-zone.
 */
static struct GNUNET_CRYPTO_EcdsaPrivateKey master_pk;

/**
 * String version of PKEY for short-zone.
 */
static char *short_zone_pkey;

/**
 * String version of PKEY for private-zone.
 */
static char *private_zone_pkey;

/**
 * String version of PKEY for pin-zone.
 */
static char *pin_zone_pkey = "72QC35CO20UJN1E91KPJFNT9TG4CLKAPB4VK9S3Q758S9MLBRKOG";

/**
 * Set to GNUNET_YES if private record was found;
 */
static int found_private_rec = GNUNET_NO;

/**
 * Set to GNUNET_YES if short record was found;
 */
static int found_short_rec = GNUNET_NO;

/**
 * Set to GNUNET_YES if pin record was found;
 */
static int found_pin_rec = GNUNET_NO;

/**
 * Exit code.
 */
static int ret;


static int
run_process_and_wait (int pipe_control,
                      enum GNUNET_OS_InheritStdioFlags std_inheritance,
                      struct GNUNET_DISK_PipeHandle *pipe_stdin,
                      struct GNUNET_DISK_PipeHandle *pipe_stdout,
                      enum GNUNET_OS_ProcessStatusType *st,
                      unsigned long *code,
                      const char *filename, ...)
{
  static struct GNUNET_OS_Process *p;
  int arglen;
  char *arg;
  char *args;
  char *argp;
  va_list ap, apc1, apc2;

  va_start (ap, filename);
  va_copy (apc1, ap);
  va_copy (apc2, ap);
  arglen = 0;
  while (NULL != (arg = va_arg (apc1, char *)))
    arglen += strlen (arg) + 1;
  va_end (apc1);
  args = argp = GNUNET_malloc (arglen);
  while (NULL != (arg = va_arg (apc2, char *)))
  {
    strcpy (argp, arg);
    argp += strlen (arg);
    *argp = ' ';
    argp += 1;
  }
  va_end (apc2);
  if (arglen > 0)
    argp[-1] = '\0';
  p = GNUNET_OS_start_process_va (pipe_control, std_inheritance,
                                  pipe_stdin,
                                  pipe_stdout,
                                  NULL,
                                  filename, ap);
  va_end (ap);
  if (NULL == p)
  {
    ret = 3;
    fprintf (stderr, "Failed to run `%s'\n", args);
    GNUNET_free (args);
    return 1;
  }

  if (GNUNET_OK != GNUNET_OS_process_wait (p))
  {
    ret = 4;
    fprintf (stderr, "Failed to wait for `%s'\n", args);
    GNUNET_free (args);
    return 1;
  }

  switch (GNUNET_OS_process_status (p, st, code))
  {
    case GNUNET_OK:
      break;
    case GNUNET_NO:
      ret = 5;
      fprintf (stderr, "`%s' is still running\n", args);
      GNUNET_free (args);
      return 1;
    default:
    case GNUNET_SYSERR:
      ret = 6;
      fprintf (stderr, "Failed to check the status of `%s'\n", args);
      GNUNET_free (args);
      return 1;
  }
#ifdef WINDOWS
  if (GNUNET_OS_PROCESS_EXITED != *st || 0 != *code)
  {
    ret = 7;
    fprintf (stderr, "`%s' did not end correctly (%d, %d)\n", args, *st, *code);
    return 1;
  }
#endif
  return 0;
}

static void
check_pkey (unsigned int rd_len, const struct GNUNET_GNSRECORD_Data *rd,
    char *pk, int *found_rec)
{
  int i;
  for (i = 0; i < rd_len; i++)
  {
    char *s;
    if (GNUNET_GNSRECORD_TYPE_PKEY != rd[i].record_type ||
        rd[i].data_size != sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey))
      continue;
    s = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
					  rd[i].data,
					  rd[i].data_size);
    if (NULL == s)
      continue;
    if (0 == strcmp (s, pk))
      *found_rec = GNUNET_YES;
    GNUNET_free (s);
  }
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
zone_iterator (void *cls,
    const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
    const char *rname, unsigned int rd_len,
    const struct GNUNET_GNSRECORD_Data *rd)
{
  if (NULL != rname)
  {
    if (0 == strcmp (rname, "private"))
      check_pkey (rd_len, rd, private_zone_pkey, &found_private_rec);
    else if (0 == strcmp (rname, "short"))
      check_pkey (rd_len, rd, short_zone_pkey, &found_short_rec);
    else if (0 == strcmp (rname, "pin"))
      check_pkey (rd_len, rd, pin_zone_pkey, &found_pin_rec);
  }
  if (NULL == rname && 0 == rd_len && NULL == rd)
  {
    enum GNUNET_OS_ProcessStatusType st;
    unsigned long code;
    if (!found_private_rec)
    {
      if (0 != run_process_and_wait (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR, NULL, NULL, &st, &code,
          "gnunet-namestore",
          "gnunet-namestore", "-z", "master-zone", "-a", "-e", "never", "-n", "private", "-p", "-t", "PKEY", "-V", private_zone_pkey, NULL))
      {
        ret = 8;
        return;
      }
    }
    if (!found_short_rec)
    {
      if (0 != run_process_and_wait (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR, NULL, NULL, &st, &code,
          "gnunet-namestore",
          "gnunet-namestore", "-z", "master-zone", "-a", "-e", "never", "-n", "short", "-p", "-t", "PKEY", "-V", short_zone_pkey, NULL))
      {
        ret = 9;
        return;
      }
    }
    if (!found_pin_rec)
    {
      if (0 != run_process_and_wait (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR, NULL, NULL, &st, &code,
          "gnunet-namestore",
          "gnunet-namestore", "-z", "master-zone", "-a", "-e", "never", "-n", "pin", "-p", "-t", "PKEY", "-V", pin_zone_pkey, NULL))
      {
        ret = 10;
        return;
      }
    }
    list_it = NULL;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_NAMESTORE_zone_iterator_next (list_it);
}

/**
 * Get master-zone, short-zone and private-zone keys.
 *
 * This function is initially called for all egos and then again
 * whenever a ego's identifier changes or if it is deleted.  At the
 * end of the initial pass over all egos, the function is once called
 * with 'NULL' for 'ego'. That does NOT mean that the callback won't
 * be invoked in the future or that there was an error.
 *
 * When used with 'GNUNET_IDENTITY_create' or 'GNUNET_IDENTITY_get',
 * this function is only called ONCE, and 'NULL' being passed in
 * 'ego' does indicate an error (i.e. name is taken or no default
 * value is known).  If 'ego' is non-NULL and if '*ctx'
 * is set in those callbacks, the value WILL be passed to a subsequent
 * call to the identity callback of 'GNUNET_IDENTITY_connect' (if
 * that one was not NULL).
 *
 * When an identity is renamed, this function is called with the
 * (known) ego but the NEW identifier.
 *
 * When an identity is deleted, this function is called with the
 * (known) ego and "NULL" for the 'identifier'.  In this case,
 * the 'ego' is henceforth invalid (and the 'ctx' should also be
 * cleaned up).
 *
 * @param cls closure
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param identifier identifier assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
*/
static void
get_ego (void *cls,
         struct GNUNET_IDENTITY_Ego *ego,
         void **ctx,
         const char *identifier)
{
  static struct GNUNET_CRYPTO_EcdsaPublicKey pk;
  if (NULL == ego)
  {
    if (NULL == master_zone_pkey ||
        NULL == short_zone_pkey ||
        NULL == private_zone_pkey)
    {
      ret = 11;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    list_it = GNUNET_NAMESTORE_zone_iteration_start (ns,
        &master_pk, &zone_iterator, NULL);
    if (NULL == list_it)
    {
      ret = 12;
      GNUNET_SCHEDULER_shutdown ();
    }
    return;
  }
  GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
  if (NULL != identifier)
  {
    if (NULL == master_zone_pkey && 0 == strcmp ("master-zone", identifier))
    {
      master_zone_pkey = GNUNET_CRYPTO_ecdsa_public_key_to_string (&pk);
      master_pk = *GNUNET_IDENTITY_ego_get_private_key (ego);
    }
    else if (NULL == short_zone_pkey && 0 == strcmp ("short-zone", identifier))
      short_zone_pkey = GNUNET_CRYPTO_ecdsa_public_key_to_string (&pk);
    else if (NULL == private_zone_pkey && 0 == strcmp ("private-zone", identifier))
      private_zone_pkey = GNUNET_CRYPTO_ecdsa_public_key_to_string (&pk);
  }
}

/**
 * Task run on shutdown.
 *
 * @param cls NULL
 * @param tc unused
 */
static void
shutdown_task (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_free_non_null (master_zone_pkey);
  master_zone_pkey = NULL;
  GNUNET_free_non_null (short_zone_pkey);
  short_zone_pkey = NULL;
  GNUNET_free_non_null (private_zone_pkey);
  private_zone_pkey = NULL;
  if (NULL != list_it)
  {
    GNUNET_NAMESTORE_zone_iteration_stop (list_it);
    list_it = NULL;
  }
  if (NULL != ns)
  {
    GNUNET_NAMESTORE_disconnect (ns);
    ns = NULL;
  }
  if (NULL != sh)
  {
    GNUNET_IDENTITY_disconnect (sh);
    sh = NULL;
  }
}

/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  enum GNUNET_OS_ProcessStatusType st;
  unsigned long code;

  cfg = c;

  if (0 != run_process_and_wait (GNUNET_NO, 0, NULL, NULL, &st, &code,
      "gnunet-arm",
      "gnunet-arm", "-I", NULL))
  {
    if (7 == ret)
      fprintf (stderr, "GNUnet is not running, please start GNUnet before running import\n");
    return;
  }

  if (0 != run_process_and_wait (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR, NULL, NULL, &st, &code,
      "gnunet-identity",
      "gnunet-identity", "-C", "master-zone", NULL))
    return;

  if (0 != run_process_and_wait (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR, NULL, NULL, &st, &code,
      "gnunet-identity",
      "gnunet-identity", "-C", "short-zone", NULL))
    return;

  if (0 != run_process_and_wait (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR, NULL, NULL, &st, &code,
      "gnunet-identity",
      "gnunet-identity", "-C", "private-zone", NULL))
    return;

  if (0 != run_process_and_wait (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR, NULL, NULL, &st, &code,
      "gnunet-identity",
      "gnunet-identity", "-C", "sks-zone", NULL))
    return;

  if (0 != run_process_and_wait (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR, NULL, NULL, &st, &code,
      "gnunet-identity",
      "gnunet-identity", "-e", "short-zone", "-s", "gns-short", NULL))
    return;

  if (0 != run_process_and_wait (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR, NULL, NULL, &st, &code,
      "gnunet-identity",
      "gnunet-identity", "-e", "master-zone", "-s", "gns-master", NULL))
    return;

  if (0 != run_process_and_wait (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR, NULL, NULL, &st, &code,
      "gnunet-identity",
      "gnunet-identity", "-e", "master-zone", "-s", "namestore", NULL))
    return;

  if (0 != run_process_and_wait (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR, NULL, NULL, &st, &code,
      "gnunet-identity",
      "gnunet-identity", "-e", "short-zone", "-s", "gns-proxy", NULL))
    return;

  if (0 != run_process_and_wait (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR, NULL, NULL, &st, &code,
      "gnunet-identity",
      "gnunet-identity", "-e", "private-zone", "-s", "gns-private", NULL))
    return;

  if (0 != run_process_and_wait (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR, NULL, NULL, &st, &code,
      "gnunet-identity",
      "gnunet-identity", "-e", "sks-zone", "-s", "fs-sks", NULL))
    return;

  ns = GNUNET_NAMESTORE_connect (cfg);
  sh = GNUNET_IDENTITY_connect (cfg, &get_ego, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task, NULL);
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
    GNUNET_GETOPT_OPTION_END
  };
  int r;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  GNUNET_log_setup ("gnunet-gns-import", "WARNING", NULL);
  ret = 0;
  r = GNUNET_PROGRAM_run (argc, argv, "gnunet-gns-import",
                          _("This program will import some GNS authorities into your GNS namestore."),
			  options,
                          &run, NULL);
  GNUNET_free ((void*) argv);
  return GNUNET_OK == r ? ret : 1;
}

/* end of gnunet-gns-import.c */
