/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

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
   */
/**
 * @author Martin Schanzenbach
 * @file src/zklaim/gnunet-zklaim.c
 * @brief ZKlaim CLI
 *
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_zklaim_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_signatures.h"

/**
 * state
 */
static int init;

/**
 * return value
 */
static int ret;

/**
 * Create new ZKlaim issuer context flag
 */
static int create;

/**
 * Name of new context
 */
static char* context_name;

/**
 * Attribute names for issuer context data
 */
static char* issue_attrs;

/**
 * Attribute names for issuer context data
 */
static char* credential;

/**
 * Attribute names for issuer context data
 */
static char* prove_predicate;

/**
 * Attribute names for issuer context data
 */
static char* create_attrs;

/**
 * Ego name
 */
static char* ego_name;

/**
 * The proving key
 */
static char* pkey_fn;

/**
 * The proof to verify
 */
static char* verify_proof;


/**
 * ZKLAIM handle
 */
static struct GNUNET_ZKLAIM_Handle *zklaim_handle;

/**
 * ZKLAIM Operation
 */
static struct GNUNET_ZKLAIM_Operation *zklaim_op;

/**
 * IDENTITY handle
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * ego private key
 */
static const struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey;

/**
 * Timeout task
 */
static struct GNUNET_SCHEDULER_Task *timeout;

/**
 * Cleanup task
 */
static struct GNUNET_SCHEDULER_Task *cleanup_task;

static void
do_cleanup(void *cls)
{
  cleanup_task = NULL;
  if (NULL != timeout)
    GNUNET_SCHEDULER_cancel (timeout);
  if (NULL != zklaim_op)
    GNUNET_ZKLAIM_cancel (zklaim_op);
  if (NULL != zklaim_handle)
    GNUNET_ZKLAIM_disconnect (zklaim_handle);
  if (NULL != identity_handle)
    GNUNET_IDENTITY_disconnect (identity_handle);
}

static void
timeout_task (void *cls)
{
  timeout = NULL;
  ret = 1;
  fprintf (stderr,
           "Timeout\n");
  if (NULL == cleanup_task)
    cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
}

static void
context_create_cb (void *cls,
                   int32_t success,
                   const char* emsg)
{
  zklaim_op = NULL;
  if (GNUNET_OK == success)
    fprintf (stdout,
             "Created.\n");
  else
    fprintf(stderr,
            "Failed.\n");
  if (NULL == cleanup_task)
    cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
  return;
}

static void
issue_iter (void *cls,
            const char* attr_name,
            uint64_t *data)
{
  char *tmp;
  char *key;
  char *val;
  tmp = GNUNET_strdup (issue_attrs);
  key = strtok (tmp, "=");
  while (NULL != key)
  {
    val = strtok (NULL, ";");
    if (0 != strcmp (attr_name, key))
    {
      key = strtok (NULL, "=");
      continue;
    }
    if (1 != sscanf (val, "%lu", data))
      fprintf (stderr, 
               "Failed to fill %s with %s\n",
               key, val);
    key = strtok (NULL, "=");
  }
  GNUNET_free (tmp);
  fprintf (stdout, "Setting %s=%lu\n", attr_name, *data);
}

static void
context_cb (void *cls,
            const struct GNUNET_ZKLAIM_Context *ctx)
{
  int ret;
  size_t len;
  char* data;
  char *str;

  zklaim_op = NULL;
  if (NULL == ctx)
  {
    fprintf (stderr,
             "Context does not exist!\n");
  } 
  else
  {
    ret = GNUNET_ZKLAIM_issue_from_context ((struct GNUNET_ZKLAIM_Context*)ctx,
                                            (struct GNUNET_CRYPTO_EcdsaPrivateKey*)pkey,
                                            &issue_iter,
                                            NULL);
    if (0 != ret)
    {
      fprintf (stderr,
               "Failed (%d)\n", ret);
    }
    else 
    {
      len = GNUNET_ZKLAIM_context_serialize (ctx,
                                             &data);
      GNUNET_STRINGS_base64_encode (data,
                                    len,
                                    &str);
      fprintf (stdout,
               "%s\n", str);
      GNUNET_free (str);
    }
  }
  if (NULL == cleanup_task)
    cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
  return;

}

enum zklaim_op
op_str_to_enum (const char* op_str)
{

  if (0 == strcmp ("<", op_str))
    return zklaim_less;
  else if (0 == strcmp ("<=", op_str))
    return zklaim_less_or_eq;
  else if (0 == strcmp ("==", op_str))
    return zklaim_eq;
  else if (0 == strcmp ("<=", op_str))
    return zklaim_greater_or_eq;
  else if (0 == strcmp ("<", op_str))
    return zklaim_greater;
  else if (0 == strcmp ("!=", op_str))
    return zklaim_not_eq;
  return zklaim_noop;
}

void
prove_iter (void *cls,
            const char* name,
            enum zklaim_op *zop,
            uint64_t *ref)
{
  char *tmp;
  char *attr;
  char *val;
  char *op;
  tmp = GNUNET_strdup (prove_predicate);
  attr = strtok (tmp, " ");
  while (NULL != attr)
  {
    op = strtok (NULL, " ");
    if (NULL == op)
      break;
    val = strtok (NULL, ";");
    if (NULL == val)
      break;
    if (0 != strcmp (name, attr))
    {
      attr = strtok (NULL, " ");
      continue;
    }
    *zop = op_str_to_enum (op);
    if (1 != sscanf (val, "%lu", ref))
      fprintf (stderr, 
               "Failed parse %s %s %s\n",
               attr, op, val);
    attr = strtok (NULL, " ");
  }
  GNUNET_free (tmp);

}

const char* zklaim_parse_op (enum zklaim_op e) {
  switch (e) {
    case zklaim_noop:
      return "noop";
    case zklaim_less:
      return "<";
    case zklaim_less_or_eq:
      return "<=";
    case zklaim_eq:
      return "=";
    case zklaim_greater_or_eq:
      return ">=";
    case zklaim_greater:
      return ">";
    case zklaim_not_eq:
      return "!=";
    default:
      return "enum zklaim_op: no valid value";
  }
}

void
verify_iter (void *cls,
             const char* name,
             enum zklaim_op *zop,
             uint64_t *ref)
{
  const char *op = zklaim_parse_op (*zop);
  fprintf (stdout,
           "%s %s %lu\n", name, op, *ref);
}

static void
handle_arguments ()
{
  struct GNUNET_ZKLAIM_Context *ctx;
  size_t len;
  char *data;
  char *proof_str;
  char *proof_data;
  int ret;
  size_t proof_size;

  timeout = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 60),
                                          &timeout_task,
                                          NULL);
  if (create)
  {
    fprintf (stdout,
             "Creating context...\n");
    zklaim_op = GNUNET_ZKLAIM_context_create (zklaim_handle,
                                              pkey,
                                              context_name,
                                              create_attrs,
                                              &context_create_cb,
                                              NULL);
    return;
  }
  else if (issue_attrs)
  {
    zklaim_op = GNUNET_ZKLAIM_lookup_context (zklaim_handle,
                                              context_name,
                                              pkey,
                                              &context_cb,
                                              NULL);
    return;
  }
  else if (prove_predicate)
  {
    len = GNUNET_STRINGS_base64_decode (credential,
                                        strlen (credential),
                                        (void**)&data);

    ctx = GNUNET_ZKLAIM_context_deserialize (data,
                                             len);
    fprintf (stdout, "Proving %s...", prove_predicate);
    ret = GNUNET_ZKLAIM_context_prove_with_keyfile (ctx,
                                                    pkey_fn,
                                                    &prove_iter,
                                                    NULL);
    fprintf (stdout,
             "%s\n", ret ? "failed." : "success.");
    proof_size = GNUNET_ZKLAIM_context_serialize (ctx,
                                                  &proof_data);
    GNUNET_STRINGS_base64_encode (proof_data,
                                  proof_size,
                                  &proof_str);
    fprintf (stdout,
             "Here is your proof:\n%s\n", proof_str);
    GNUNET_free (proof_str);
    GNUNET_free (proof_data);
    GNUNET_ZKLAIM_context_destroy (ctx);
  }
  else if (verify_proof)
  {
    proof_size = GNUNET_STRINGS_base64_decode (verify_proof,
                                               strlen (verify_proof),
                                               (void**)&proof_data);
    ctx = GNUNET_ZKLAIM_context_deserialize (proof_data,
                                             proof_size);
    ret = GNUNET_ZKLAIM_context_verify (ctx,
                                        &verify_iter,
                                        NULL);
    fprintf (stdout,
             "Proof is %s (%d)\n", ret ? "INVALID" : "VALID", ret);
    GNUNET_free (proof_data);
    GNUNET_ZKLAIM_context_destroy (ctx);
  }
  cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
}

static void
ego_cb (void *cls,
        struct GNUNET_IDENTITY_Ego *ego,
        void **ctx,
        const char *name)
{
  if (NULL == name) {
    if (GNUNET_YES == init) {
      init = GNUNET_NO;
      handle_arguments();
    }
    return;
  }
  if (0 != strcmp (name, ego_name))
    return;
  pkey = GNUNET_IDENTITY_ego_get_private_key (ego);
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  ret = 0;
  if (NULL == ego_name)
  {
    ret = 1;
    fprintf (stderr,
             _("Ego is required\n"));
    return;
  }

  if ( (create) && (NULL == context_name) )
  {
    ret = 1;
    fprintf (stderr,
             _("Context name missing!\n"));
    return;
  }
  if ( (create) && (NULL == create_attrs) )
  {
    ret = 1;
    fprintf (stderr,
             _("Context attributes missing!\n"));
    return;
  }

  zklaim_handle = GNUNET_ZKLAIM_connect (c);
  //Get Ego
  init = GNUNET_YES;
  identity_handle = GNUNET_IDENTITY_connect (c,
                                             &ego_cb,
                                             NULL);


}


int
main(int argc, char *const argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {

    GNUNET_GETOPT_option_string ('n',
                                 "name",
                                 NULL,
                                 gettext_noop ("Context name"),
                                 &context_name),
    GNUNET_GETOPT_option_string ('A',
                                 "attributes",
                                 NULL,
                                 gettext_noop ("Context attributes (comma separated)"),
                                 &create_attrs),
    GNUNET_GETOPT_option_string ('e',
                                 "ego",
                                 NULL,
                                 gettext_noop ("Ego"),
                                 &ego_name),
    GNUNET_GETOPT_option_flag ('C',
                               "create",
                               gettext_noop ("Create new issuer context"),
                               &create),
    GNUNET_GETOPT_option_string ('I',
                                 "issue",
                                 NULL,
                                 gettext_noop ("Issue a credential with the given attributes and given zklaim context"),
                                 &issue_attrs),
    GNUNET_GETOPT_option_string ('P',
                                 "predicate",
                                 NULL,
                                 gettext_noop ("Predicate to prove"),
                                 &prove_predicate),
    GNUNET_GETOPT_option_string ('R',
                                 "credential",
                                 NULL,
                                 gettext_noop ("A credential"),
                                 &credential),
    GNUNET_GETOPT_option_filename ('K',
                                   "provingkey",
                                   NULL,
                                   gettext_noop ("The proving key to use"),
                                   &pkey_fn),
    GNUNET_GETOPT_option_string ('V',
                                 "verify",
                                 NULL,
                                 gettext_noop ("Proof to verify"),
                                 &verify_proof),

    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_PROGRAM_run (argc, argv, "ct",
                                       "ct", options,
                                       &run, NULL))
    return 1;
  else
    return ret;
}
