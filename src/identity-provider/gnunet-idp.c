/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

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
 * @author Martin Schanzenbach
 * @file src/identity-provider/gnunet-idp.c
 * @brief Identity Provider utility
 *
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_signatures.h"

/**
 * The attribute
 */
static char* attr_name;

/**
 * Attribute value
 */
static char* attr_value;

/**
 * Ego name
 */
static char* ego_name;

/**
 * Identity handle
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * Namestore handle
 */
static struct GNUNET_NAMESTORE_Handle *namestore_handle;

/**
 * Namestore queue
 */
static struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

/**
 * Master ABE key
 */
static struct GNUNET_CRYPTO_AbeMasterKey *abe_key;

static void
do_cleanup(void *cls)
{
  if (NULL != ns_qe)
    GNUNET_NAMESTORE_cancel (ns_qe);
  if (NULL != namestore_handle)
    GNUNET_NAMESTORE_disconnect (namestore_handle);
  if (NULL != identity_handle)
    GNUNET_IDENTITY_disconnect (identity_handle);
  if (NULL != abe_key)
    GNUNET_free (abe_key);
}

static void
ns_error_cb (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
              "Failed.");
  do_cleanup(NULL);
  return;
}

static void
store_attr_cont (void *cls,
                 int32_t success,
                 const char*emsg)
{
  if (GNUNET_SYSERR == success) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s\n", emsg);
  } else {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                "Sucessfully added identity attribute %s=%s\n",
                attr_name, attr_value);
  }
  GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
}

static void
abe_lookup_cb (void *cls,
               const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
               const char *label,
               unsigned int rd_count,
               const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data new_record;
  int i;
  ssize_t size;

  for (i=0;i<rd_count;i++) {
    if (GNUNET_GNSRECORD_TYPE_ABE_MASTER != rd[i].record_type)
      continue;
    abe_key = GNUNET_CRYPTO_cpabe_deserialize_master_key (rd[i].data,
                                                          rd[i].data_size);
  }
  if (NULL == abe_key) {
    GNUNET_SCHEDULER_add_now (do_error, NULL);
    return;
  }

  size = GNUNET_CRYPTO_cpabe_encrypt (attr_value,
                                      strlen (attr_value) + 1,
                                      attr_name,
                                      abe_key,
                                      new_record.data);
  new_record.data_size = size;
  new_record.record_type = GNUNET_GNSRECORD_TYPE_ABE_ID_ATTR;
  new_record.expiration_time = GNUNET_TIME_UNIT_HOURS;
  new_record.flags = GNUNET_GNSRECORD_RF_NONE;

  ns_qe = GNUNET_NAMESTORE_records_store (namestore_handle,
                                          zone,
                                          attr_name,
                                          1,
                                          &new_record,
                                          &store_attr_cont,
                                          NULL);
}

static void
ego_cb (void *cls,
        struct GNUNET_IDENTITY_Ego *ego,
        void **ctx,
        const char *name)
{
  struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey;
  if (0 != strcmp (name, ego_name))
    return;
  pkey = GNUNET_IDENTITY_ego_get_private_key (ego);
  ns_qe = GNUNET_NAMESTORE_records_lookup (namestore_handle,
                                           pkey,
                                           "+",
                                           &ns_error_cb,
                                           NULL,
                                           &abe_lookup_cb,
                                           NULL);
}

static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{

  if (NULL == attr_name)
  {
    return;
  }
  if (NULL == ego_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                _("Ego is required\n"));
    return;
  }
  if (NULL == attr_value)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                _("Value is required\n"));
    return;
  }
  namestore_handle = GNUNET_NAMESTORE_connect (cfgfile);
  //Get Ego
  identity_handle = GNUNE_IDENTITY_connect (cfgfile,
                                            &ego_cb,
                                            NULL);


}


int
main(int argc, char *const argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {

    GNUNET_GETOPT_option_string ('a',
                                 "add",
                                 NULL,
                                 gettext_noop ("Add attribute"),
                                 &attr_name),

    GNUNET_GETOPT_option_flag ('V',
                               "value",
                               gettext_noop ("Attribute value"),
                               &attr_value),

    GNUNET_GETOPT_OPTION_END
  };
  return GNUNET_PROGRAM_run (argc, argv, "ct",
                             "ct", options,
                             &run, NULL);
}
