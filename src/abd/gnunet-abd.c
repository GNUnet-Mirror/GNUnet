/*
     This file is part of GNUnet.
     Copyright (C) 2012-2013 GNUnet e.V.

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
 * @file gnunet-abd.c
 * @brief command line tool to access command line Credential service
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_abd_service.h>
#include <gnunet_gnsrecord_lib.h>
#include <gnunet_namestore_service.h>
#include "delegate_misc.h"
#include "abd_serialization.h"

/**
 * Configuration we are using.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the namestore.
 */
static struct GNUNET_NAMESTORE_Handle *ns;

/**
 * Private key for the our zone.
 */
static struct GNUNET_CRYPTO_EcdsaPrivateKey zone_pkey;

/**
 * EgoLookup
 */
static struct GNUNET_IDENTITY_EgoLookup *el;

/**
 * Handle to Credential service.
 */
static struct GNUNET_ABD_Handle *abd;

/**
 * Desired timeout for the lookup (default is no timeout).
 */
static struct GNUNET_TIME_Relative timeout;

/**
 * Handle to verify request
 */
static struct GNUNET_ABD_Request *verify_request;

/**
 * Handle to collect request
 */
static struct GNUNET_ABD_Request *collect_request;

/**
 * Task scheduled to handle timeout.
 */
static struct GNUNET_SCHEDULER_Task *tt;

/**
 * Return value of the commandline.
 */
static int ret = 0;

/**
 * Subject pubkey string
 */
static char *subject;

/**
 * Subject delegate string
 */
static char *subject_delegate;

/**
 * Credential TTL
 */
static char *expiration;

/**
 * Subject key
 */
struct GNUNET_CRYPTO_EcdsaPublicKey subject_pkey;

/**
 * Issuer key
 */
struct GNUNET_CRYPTO_EcdsaPublicKey issuer_pkey;


/**
 * Issuer pubkey string
 */
static char *issuer_key;

/**
 * ego
 */
static char *ego_name;

/**
 * Issuer attribute
 */
static char *issuer_attr;

/**
 * Verify mode
 */
static int verify;

/**
 * Collect mode
 */
static int collect;

/**
 * Create mode
 */
static int create_is;

/**
 * Create mode
 */
static int create_ss;

/**
 * Create mode
 */
static int sign_ss;

/**
 * Signed issue credentials
 */
static char *import;

/**
 * Is record private
 */
static int is_private;

/**
 * Search direction: forward
 */
static int forward;

/**
 * Search direction: backward
 */
static int backward;

/**
 * API enum, filled and passed for collect/verify
 */
enum GNUNET_ABD_AlgoDirectionFlags direction = 0;

/**
 * Queue entry for the 'add' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *add_qe;

/**
 * Value in binary format.
 */
static void *data;

/**
 * Number of bytes in #data.
 */
static size_t data_size;

/**
 * Type string converted to DNS type value.
 */
static uint32_t type;

/**
 * Type of the record to add/remove, NULL to remove all.
 */
static char *typestring;
/**
 * Expiration string converted to numeric value.
 */
static uint64_t etime;

/**
 * Is expiration time relative or absolute time?
 */
static int etime_is_rel = GNUNET_SYSERR;

/**
 * Fixed size of the public/private keys
 */
static const int key_length = 52;

/**
 * Record label for storing delegations
 */
static char *record_label;

/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 */
static void
do_shutdown (void *cls)
{
  if (NULL != verify_request)
  {
    GNUNET_ABD_request_cancel (verify_request);
    verify_request = NULL;
  }
  if (NULL != abd)
  {
    GNUNET_ABD_disconnect (abd);
    abd = NULL;
  }
  if (NULL != tt)
  {
    GNUNET_SCHEDULER_cancel (tt);
    tt = NULL;
  }
  if (NULL != el)
  {
    GNUNET_IDENTITY_ego_lookup_cancel (el);
    el = NULL;
  }
  if (NULL != add_qe)
  {
    GNUNET_NAMESTORE_cancel (add_qe);
    add_qe = NULL;
  }
  if (NULL != ns)
  {
    GNUNET_NAMESTORE_disconnect (ns);
    ns = NULL;
  }
}


/**
 * Task run on timeout. Triggers shutdown.
 *
 * @param cls unused
 */
static void
do_timeout (void *cls)
{
  tt = NULL;
  GNUNET_SCHEDULER_shutdown ();
}


static void
handle_intermediate_result (void *cls,
                            struct GNUNET_ABD_Delegation *dd,
                            bool is_bw)
{
  char *prefix = "";
  if (is_bw)
    prefix = "Backward -";
  else
    prefix = "Forward -";

  printf ("%s Intermediate result: %s.%s <- %s.%s\n",
          prefix,
          GNUNET_CRYPTO_ecdsa_public_key_to_string (&dd->issuer_key),
          dd->issuer_attribute,
          GNUNET_CRYPTO_ecdsa_public_key_to_string (&dd->subject_key),
          dd->subject_attribute);
}


static void
handle_collect_result (void *cls,
                       unsigned int d_count,
                       struct GNUNET_ABD_Delegation *dc,
                       unsigned int c_count,
                       struct GNUNET_ABD_Delegate *dele)
{
  int i;
  char *line;

  verify_request = NULL;
  if (NULL != dele)
  {
    for (i = 0; i < c_count; i++)
    {
      line = GNUNET_ABD_delegate_to_string (&dele[i]);
      printf ("%s\n", line);
      GNUNET_free (line);
    }
  }
  else
  {
    printf ("Received NULL\n");
  }

  GNUNET_SCHEDULER_shutdown ();
}


static void
handle_verify_result (void *cls,
                      unsigned int d_count,
                      struct GNUNET_ABD_Delegation *dc,
                      unsigned int c_count,
                      struct GNUNET_ABD_Delegate *dele)
{
  int i;
  char *iss_key;
  char *sub_key;

  verify_request = NULL;
  if (NULL == dele)
    ret = 1;
  else
  {
    printf ("Delegation Chain:\n");
    for (i = 0; i < d_count; i++)
    {
      iss_key = GNUNET_CRYPTO_ecdsa_public_key_to_string (&dc[i].issuer_key);
      sub_key = GNUNET_CRYPTO_ecdsa_public_key_to_string (&dc[i].subject_key);

      if (0 != dc[i].subject_attribute_len)
      {
        printf ("(%d) %s.%s <- %s.%s\n",
                i,
                iss_key,
                dc[i].issuer_attribute,
                sub_key,
                dc[i].subject_attribute);
      }
      else
      {
        printf ("(%d) %s.%s <- %s\n",
                i,
                iss_key,
                dc[i].issuer_attribute,
                sub_key);
      }
      GNUNET_free (iss_key);
      GNUNET_free (sub_key);
    }
    printf ("\nDelegate(s):\n");
    for (i = 0; i < c_count; i++)
    {
      iss_key = GNUNET_CRYPTO_ecdsa_public_key_to_string (&dele[i].issuer_key);
      sub_key = GNUNET_CRYPTO_ecdsa_public_key_to_string (&dele[i].subject_key);
      printf ("%s.%s <- %s\n", iss_key, dele[i].issuer_attribute, sub_key);
      GNUNET_free (iss_key);
      GNUNET_free (sub_key);
    }
    printf ("Successful.\n");
  }

  GNUNET_SCHEDULER_shutdown ();
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
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;

  el = NULL;
  if (NULL == ego)
  {
    if (NULL != ego_name)
    {
      fprintf (stderr,
               _ ("Ego `%s' not known to identity service\n"),
               ego_name);
    }
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_YES == collect)
  {

    if (GNUNET_OK !=
        GNUNET_CRYPTO_ecdsa_public_key_from_string (issuer_key,
                                                    strlen (issuer_key),
                                                    &issuer_pkey))
    {
      fprintf (stderr,
               _ ("Issuer public key `%s' is not well-formed\n"),
               issuer_key);
      GNUNET_SCHEDULER_shutdown ();
    }
    privkey = GNUNET_IDENTITY_ego_get_private_key (ego);

    collect_request = GNUNET_ABD_collect (abd,
                                          &issuer_pkey,
                                          issuer_attr,
                                          privkey,
                                          direction,
                                          &handle_collect_result,
                                          NULL,
                                          &handle_intermediate_result,
                                          NULL);
    return;
  }
  GNUNET_SCHEDULER_shutdown ();
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
  // copied from namestore/gnunet-namestore.c
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
 * Function called if lookup fails.
 */
static void
error_cb (void *cls)
{
  fprintf (stderr, "Error occured during lookup, shutting down.\n");
  GNUNET_SCHEDULER_shutdown ();
  return;
}


static void
add_continuation (void *cls, int32_t success, const char *emsg)
{
  struct GNUNET_NAMESTORE_QueueEntry **qe = cls;
  *qe = NULL;

  if (GNUNET_OK == success)
    printf ("Adding successful.\n");
  else
    fprintf (stderr, "Error occured during adding, shutting down.\n");

  GNUNET_SCHEDULER_shutdown ();
}


static void
get_existing_record (void *cls,
                     const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
                     const char *rec_name,
                     unsigned int rd_count,
                     const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data rdn[rd_count + 1];
  struct GNUNET_GNSRECORD_Data *rde;

  memset (rdn, 0, sizeof (struct GNUNET_GNSRECORD_Data));
  GNUNET_memcpy (&rdn[1], rd, rd_count * sizeof (struct GNUNET_GNSRECORD_Data));
  rde = &rdn[0];
  rde->data = data;
  rde->data_size = data_size;
  rde->record_type = type;

  // Set flags
  if (GNUNET_YES == is_private)
    rde->flags |= GNUNET_GNSRECORD_RF_PRIVATE;
  rde->expiration_time = etime;
  if (GNUNET_YES == etime_is_rel)
    rde->flags |= GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  else if (GNUNET_NO != etime_is_rel)
    rde->expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;

  GNUNET_assert (NULL != rec_name);
  add_qe = GNUNET_NAMESTORE_records_store (ns,
                                           &zone_pkey,
                                           rec_name,
                                           rd_count + 1,
                                           rde,
                                           &add_continuation,
                                           &add_qe);

  return;
}


static void
store_cb (void *cls, const struct GNUNET_IDENTITY_Ego *ego)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  el = NULL;

  ns = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == ns)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to connect to namestore\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  // Key handling
  zone_pkey = *GNUNET_IDENTITY_ego_get_private_key (ego);

  if (GNUNET_GNSRECORD_TYPE_DELEGATE == type)
  {
    // Parse import
    struct GNUNET_ABD_Delegate *cred;
    cred = GNUNET_ABD_delegate_from_string (import);

    // Get import subject public key string
    char *subject_pubkey_str =
      GNUNET_CRYPTO_ecdsa_public_key_to_string (&cred->subject_key);

    // Get zone public key string
    struct GNUNET_CRYPTO_EcdsaPublicKey zone_pubkey;
    GNUNET_IDENTITY_ego_get_public_key (ego, &zone_pubkey);
    char *zone_pubkey_str =
      GNUNET_CRYPTO_ecdsa_public_key_to_string (&zone_pubkey);

    // Check if the subject key in the signed import matches the zone's key it is issued to
    if (strcmp (zone_pubkey_str, subject_pubkey_str) != 0)
    {
      fprintf (stderr,
               "Import signed delegate does not match this ego's public key.\n");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }

    // Expiration
    etime = cred->expiration.abs_value_us;
    etime_is_rel = GNUNET_NO;

    // Prepare the data to be store in the record
    data_size = GNUNET_ABD_delegate_serialize (cred, (char **) &data);
    GNUNET_free (cred);
  }
  else
  {
    // For all other types e.g. GNUNET_GNSRECORD_TYPE_ATTRIBUTE
    if (GNUNET_OK !=
        GNUNET_GNSRECORD_string_to_value (type, subject, &data, &data_size))
    {
      fprintf (stderr,
               "Value `%s' invalid for record type `%s'\n",
               subject,
               typestring);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }

    // Take care of expiration
    if (NULL == expiration)
    {
      fprintf (stderr, "Missing option -e for operation 'create'\n");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if (GNUNET_OK != parse_expiration (expiration, &etime_is_rel, &etime))
    {
      fprintf (stderr, "Invalid time format `%s'\n", expiration);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }

  // Start lookup
  add_qe = GNUNET_NAMESTORE_records_lookup (ns,
                                            &zone_pkey,
                                            record_label,
                                            &error_cb,
                                            NULL,
                                            &get_existing_record,
                                            NULL);
  return;
}


static void
sign_cb (void *cls, const struct GNUNET_IDENTITY_Ego *ego)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;
  struct GNUNET_ABD_Delegate *dele;
  struct GNUNET_TIME_Absolute etime_abs;
  char *res;

  el = NULL;

  // work on expiration time
  if (NULL == expiration)
  {
    fprintf (stderr, "Please specify a TTL\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  else if (GNUNET_OK !=
           GNUNET_STRINGS_fancy_time_to_absolute (expiration, &etime_abs))
  {
    fprintf (stderr,
             "%s is not a valid ttl! Only absolute times are accepted!\n",
             expiration);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  // If contains a space - split it by the first space only - assume first entry is subject followed by attribute(s)
  char *subject_pubkey_str;
  char *subject_attr = NULL;
  char *token;

  // Subject Public Key
  token = strtok (subject, " ");
  if (key_length == strlen (token))
  {
    subject_pubkey_str = token;
  }
  else
  {
    fprintf (stderr, "Key error, wrong length: %ld!\n", strlen (token));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  // Subject Attribute(s)
  token = strtok (NULL, " ");
  if (NULL != token)
  {
    subject_attr = token;
  }

  // work on keys
  privkey = GNUNET_IDENTITY_ego_get_private_key (ego);

  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_public_key_from_string (subject_pubkey_str,
                                                  strlen (subject_pubkey_str),
                                                  &subject_pkey))
  {
    fprintf (stderr,
             "Subject public key `%s' is not well-formed\n",
             subject_pubkey_str);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  // Sign delegate
  dele = GNUNET_ABD_delegate_issue (privkey,
                                    &subject_pkey,
                                    issuer_attr,
                                    subject_attr,
                                    &etime_abs);
  res = GNUNET_ABD_delegate_to_string (dele);
  GNUNET_free (dele);
  printf ("%s\n", res);

  GNUNET_free_non_null (ego_name);
  ego_name = NULL;

  GNUNET_SCHEDULER_shutdown ();
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;

  tt = GNUNET_SCHEDULER_add_delayed (timeout, &do_timeout, NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);

  // Check relevant cmdline parameters
  if (GNUNET_YES == create_is)
  {
    if (NULL == ego_name)
    {
      fprintf (stderr, "Missing option '-ego'\n");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if (NULL == issuer_attr)
    {
      fprintf (stderr, "Missing option '-attribute' for issuer attribute\n");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if (NULL == subject)
    {
      fprintf (stderr, "Missing option -subject for operation 'create'.'\n");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }

    // Lookup ego, on success call store_cb and store as ATTRIBUTE type
    type = GNUNET_GNSRECORD_TYPE_ATTRIBUTE;
    record_label = issuer_attr;
    el = GNUNET_IDENTITY_ego_lookup (cfg, ego_name, &store_cb, (void *) cfg);
    return;
  }

  if (GNUNET_YES == create_ss)
  {

    // check if signed parameter has been passed in cmd line call
    if (NULL == import)
    {
      fprintf (stderr, "'import' required\n");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }

    type = GNUNET_GNSRECORD_TYPE_DELEGATE;
    record_label = GNUNET_GNS_EMPTY_LABEL_AT;
    // Store subject side
    el = GNUNET_IDENTITY_ego_lookup (cfg, ego_name, &store_cb, (void *) cfg);

    return;
  }

  if (GNUNET_YES == sign_ss)
  {
    if (NULL == ego_name)
    {
      fprintf (stderr, "ego required\n");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if (NULL == subject)
    {
      fprintf (stderr, "Subject public key needed\n");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }

    // lookup ego and call function sign_cb on success
    el = GNUNET_IDENTITY_ego_lookup (cfg, ego_name, &sign_cb, (void *) cfg);
    return;
  }

  if ((GNUNET_NO == forward) && (GNUNET_NO == backward))
  {
    // set default: bidirectional
    forward = GNUNET_YES;
    backward = GNUNET_YES;
  }
  if (GNUNET_YES == forward)
    direction |= GNUNET_ABD_FLAG_FORWARD;
  if (GNUNET_YES == backward)
    direction |= GNUNET_ABD_FLAG_BACKWARD;

  if (GNUNET_YES == collect)
  {
    if (NULL == issuer_key)
    {
      fprintf (stderr, _ ("Issuer public key not well-formed\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }

    abd = GNUNET_ABD_connect (cfg);

    if (NULL == abd)
    {
      fprintf (stderr, _ ("Failed to connect to ABD\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if (NULL == issuer_attr)
    {
      fprintf (stderr, _ ("You must provide issuer the attribute\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }

    if (NULL == ego_name)
    {
      fprintf (stderr, _ ("ego required\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    el = GNUNET_IDENTITY_ego_lookup (cfg, ego_name, &identity_cb, (void *) cfg);
    return;
  }

  if (NULL == subject)
  {
    fprintf (stderr, _ ("Subject public key needed\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_OK != GNUNET_CRYPTO_ecdsa_public_key_from_string (subject,
                                                               strlen (subject),
                                                               &subject_pkey))
  {
    fprintf (stderr,
             _ ("Subject public key `%s' is not well-formed\n"),
             subject);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_YES == verify)
  {
    if (NULL == issuer_key)
    {
      fprintf (stderr, _ ("Issuer public key not well-formed\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if (GNUNET_OK !=
        GNUNET_CRYPTO_ecdsa_public_key_from_string (issuer_key,
                                                    strlen (issuer_key),
                                                    &issuer_pkey))
    {
      fprintf (stderr,
               _ ("Issuer public key `%s' is not well-formed\n"),
               issuer_key);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    abd = GNUNET_ABD_connect (cfg);

    if (NULL == abd)
    {
      fprintf (stderr, _ ("Failed to connect to ABD\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if ((NULL == issuer_attr) || (NULL == subject_delegate))
    {
      fprintf (stderr, _ ("You must provide issuer and subject attributes\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }

    // Subject credentials are comma separated
    char *tmp = GNUNET_strdup (subject_delegate);
    char *tok = strtok (tmp, ",");
    if (NULL == tok)
    {
      fprintf (stderr, "Invalid subject credentials\n");
      GNUNET_free (tmp);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    int count = 1;
    int i;
    while (NULL != (tok = strtok (NULL, ",")))
      count++;
    struct GNUNET_ABD_Delegate delegates[count];
    struct GNUNET_ABD_Delegate *dele;
    GNUNET_free (tmp);
    tmp = GNUNET_strdup (subject_delegate);
    tok = strtok (tmp, ",");
    for (i = 0; i < count; i++)
    {
      dele = GNUNET_ABD_delegate_from_string (tok);
      GNUNET_memcpy (&delegates[i],
                     dele,
                     sizeof (struct GNUNET_ABD_Delegate));
      delegates[i].issuer_attribute = GNUNET_strdup (dele->issuer_attribute);
      tok = strtok (NULL, ",");
      GNUNET_free (dele);
    }

    verify_request = GNUNET_ABD_verify (abd,
                                        &issuer_pkey,
                                        issuer_attr,
                                        &subject_pkey,
                                        count,
                                        delegates,
                                        direction,
                                        &handle_verify_result,
                                        NULL,
                                        &handle_intermediate_result,
                                        NULL);
    for (i = 0; i < count; i++)
    {
      GNUNET_free ((char *) delegates[i].issuer_attribute);
    }
    GNUNET_free (tmp);
  }
  else
  {
    fprintf (stderr,
             _ (
               "Please specify name to lookup, subject key and issuer key!\n"));
    GNUNET_SCHEDULER_shutdown ();
  }
  return;
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
  struct GNUNET_GETOPT_CommandLineOption options[] =
  {GNUNET_GETOPT_option_flag ('V',
                              "verify",
                              gettext_noop (
                                "verify credential against attribute"),
                              &verify),
   GNUNET_GETOPT_option_string (
     's',
     "subject",
     "PKEY",
     gettext_noop (
       "The public key of the subject to lookup the"
       "credential for, or for issuer side storage: subject and its attributes"),
     &subject),
   GNUNET_GETOPT_option_string (
     'd',
     "delegate",
     "DELE",
     gettext_noop ("The private, signed delegate presented by the subject"),
     &subject_delegate),
   GNUNET_GETOPT_option_string (
     'i',
     "issuer",
     "PKEY",
     gettext_noop (
       "The public key of the authority to verify the credential against"),
     &issuer_key),
   GNUNET_GETOPT_option_string ('e',
                                "ego",
                                "EGO",
                                gettext_noop ("The ego/zone name to use"),
                                &ego_name),
   GNUNET_GETOPT_option_string (
     'a',
     "attribute",
     "ATTR",
     gettext_noop ("The issuer attribute to verify against or to issue"),
     &issuer_attr),
   GNUNET_GETOPT_option_string ('T',
                                "ttl",
                                "EXP",
                                gettext_noop (
                                  "The time to live for the credential."
                                  "e.g. 5m, 6h, \"1990-12-30 12:00:00\""),
                                &expiration),
   GNUNET_GETOPT_option_flag ('g',
                              "collect",
                              gettext_noop ("collect credentials"),
                              &collect),
   GNUNET_GETOPT_option_flag ('U',
                              "createIssuerSide",
                              gettext_noop (
                                "Create and issue a credential issuer side."),
                              &create_is),
   GNUNET_GETOPT_option_flag ('C',
                              "createSubjectSide",
                              gettext_noop (
                                "Issue a credential subject side."),
                              &create_ss),
   GNUNET_GETOPT_option_flag (
     'S',
     "signSubjectSide",
     gettext_noop ("Create, sign and return a credential subject side."),
     &sign_ss),
   GNUNET_GETOPT_option_string (
     'x',
     "import",
     "IMP",
     gettext_noop (
       "Import signed credentials that should be issued to a zone/ego"),
     &import),
   GNUNET_GETOPT_option_flag ('P',
                              "private",
                              gettext_noop ("Create private record entry."),
                              &is_private),
   GNUNET_GETOPT_option_flag (
     'F',
     "forward",
     gettext_noop (
       "Indicates that the collect/verify process is done via forward search."),
     &forward),
   GNUNET_GETOPT_option_flag (
     'B',
     "backward",
     gettext_noop (
       "Indicates that the collect/verify process is done via forward search."),
     &backward),
   GNUNET_GETOPT_OPTION_END};


  timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  GNUNET_log_setup ("gnunet-abd", "WARNING", NULL);
  if (GNUNET_OK != GNUNET_PROGRAM_run (argc,
                                       argv,
                                       "gnunet-abd",
                                       _ ("GNUnet abd resolver tool"),
                                       options,
                                       &run,
                                       NULL))
    ret = 1;
  GNUNET_free ((void *) argv);
  return ret;
}


/* end of gnunet-abd.c */
