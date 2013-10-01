/*
     This file is part of GNUnet.
     (C) 2012,2013 Christian Grothoff (and other contributing authors)

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
 * @file experimentation/gnunet-daemon-experimentation_experiments.c
 * @brief experimentation daemon: experiment management
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-daemon-experimentation.h"


/**
 * Hashmap containing valid experiment issuers.
 */
struct GNUNET_CONTAINER_MultiHashMap *valid_issuers;

/**
 * Hashmap containing valid experiments
 */
static struct GNUNET_CONTAINER_MultiHashMap *experiments;


/**
 * Verify experiment signature
 *
 * @param i issuer
 * @param e experiment
 * @return #GNUNET_OK or #GNUNET_SYSERR
 */
static int
experiment_verify (struct Issuer *i, struct Experiment *e)
{
  GNUNET_assert (NULL != i);
  GNUNET_assert (NULL != e);
  
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
	      "Verification: to be implemented\n");
  return GNUNET_OK;
}


static int 
free_experiment (void *cls,
		 const struct GNUNET_HashCode * key,
		 void *value)
{
  struct Experiment *e = value;

  GNUNET_break (0 == GNUNET_CONTAINER_multihashmap_remove (experiments, key, value));
  GNUNET_free_non_null (e->description);
  GNUNET_free_non_null (e->name);
  GNUNET_free (e);
  return GNUNET_OK;
}


/**
 * Free issuer element
 *
 * @param cls unused
 * @param key the key
 * @param value the issuer element to free
 * @return GNUNET_OK to continue
 */
static int 
free_issuer (void *cls,
	     const struct GNUNET_HashCode * key,
	     void *value)
{
  struct Issuer *i = value;

  GNUNET_break (0 == GNUNET_CONTAINER_multihashmap_remove (valid_issuers, 
							   key, 
							   i));
  GNUNET_free (i);
  return GNUNET_OK;
}


/**
 * Is peer a valid issuer
 *
 * @return #GNUNET_YES or #GNUNET_NO
 */
int
GED_experiments_issuer_accepted (const struct GNUNET_CRYPTO_EccPublicSignKey *issuer_id)
{
  struct GNUNET_HashCode hash;

  GNUNET_CRYPTO_hash (issuer_id, sizeof (struct GNUNET_CRYPTO_EccPublicSignKey), &hash);
  if (GNUNET_CONTAINER_multihashmap_contains (valid_issuers, &hash))
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Get the key under which the given experiment is stored in the
 * experiment map.
 */
static void
get_experiment_key (const struct GNUNET_CRYPTO_EccPublicSignKey *issuer,
		    const char *name,
		    const struct GNUNET_TIME_Absolute version,
		    struct GNUNET_HashCode *key)
{
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CRYPTO_kdf (key, sizeof (struct GNUNET_HashCode),
				    issuer, sizeof (struct GNUNET_CRYPTO_EccPublicSignKey),
				    name, strlen (name),
				    &version, sizeof (version),
				    NULL, 0));
}


/**
 * Find an experiment based on issuer name and version
 *
 * @param issuer the issuer
 * @param name experiment name
 * @param version experiment version
 * @return the experiment or NULL if not found
 */
struct Experiment *
GED_experiments_find (const struct GNUNET_CRYPTO_EccPublicSignKey *issuer,
		      const char *name,
		      const struct GNUNET_TIME_Absolute version)
{
  struct GNUNET_HashCode hc;
  
  get_experiment_key (issuer, 
		      name,
		      version,
		      &hc);
  return GNUNET_CONTAINER_multihashmap_get (experiments,
					    &hc);
}


struct GetCtx
{
  struct Node *n;

  GNUNET_EXPERIMENTATION_experiments_get_cb get_cb;

  struct GNUNET_CRYPTO_EccPublicSignKey *issuer;
};


static int
get_it (void *cls,
	const struct GNUNET_HashCode *key,
	void *value)
{
  struct GetCtx *get_ctx = cls;
  struct Experiment *e = value;

  if (0 == memcmp (&e->issuer,
		   get_ctx->issuer,
		   sizeof (struct GNUNET_CRYPTO_EccPublicSignKey)))
    get_ctx->get_cb (get_ctx->n, e);  
  return GNUNET_OK;
}


void
GED_experiments_get (struct Node *n,
		     struct GNUNET_CRYPTO_EccPublicSignKey *issuer,
		     GNUNET_EXPERIMENTATION_experiments_get_cb get_cb)
{
  struct GetCtx get_ctx;

  GNUNET_assert (NULL != n);
  GNUNET_assert (NULL != experiments);
  GNUNET_assert (NULL != get_cb);
  get_ctx.n = n;
  get_ctx.get_cb = get_cb;
  get_ctx.issuer = issuer;
  GNUNET_CONTAINER_multihashmap_iterate (experiments,
					 &get_it, &get_ctx);
  get_cb (n, NULL); // FIXME: ugly, end is easily signalled as we return: synchronous API!
}


/**
 * Add a new experiment
 */
int
GNUNET_EXPERIMENTATION_experiments_add (struct Issuer *i,
					const char *name,
					const struct GNUNET_CRYPTO_EccPublicSignKey *issuer_id,
					struct GNUNET_TIME_Absolute version,
					char *description,
					uint32_t required_capabilities,
					struct GNUNET_TIME_Absolute start,
					struct GNUNET_TIME_Relative frequency,
					struct GNUNET_TIME_Relative duration,
					struct GNUNET_TIME_Absolute stop)
{
  struct Experiment *e;
  struct GNUNET_HashCode hc;

  e = GNUNET_new (struct Experiment);  
  e->name = GNUNET_strdup (name);
  e->issuer = *issuer_id;
  e->version = version;
  if (NULL != description)
    e->description = GNUNET_strdup (description);
  e->required_capabilities = required_capabilities;
  e->start = start;
  e->frequency = frequency;
  e->duration = duration;
  e->stop = stop;
  
  /* verify experiment */
  if (GNUNET_SYSERR == experiment_verify (i, e))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Experiment `%s': Experiment signature is invalid\n"), 
		name);
    GNUNET_free (e);
    GNUNET_free_non_null (e->name);
    GNUNET_free_non_null (e->description);
    return GNUNET_SYSERR;
  }
  
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      _("Adding experiment `%s' running from `%s' to `%s' every %llu sec. for %llu sec. \n"),
	      e->name,
	      GNUNET_STRINGS_absolute_time_to_string (start),
	      GNUNET_STRINGS_absolute_time_to_string (stop),
	      (long long unsigned int) frequency.rel_value_us / 1000000LL,
	      (long long unsigned int) duration.rel_value_us / 1000000LL);
  get_experiment_key (&e->issuer,
		      name,
		      version,
		      &hc);
  GNUNET_CONTAINER_multihashmap_put (experiments,
				     &hc,
				     e, 
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_STATISTICS_set (GED_stats, 
			 "# experiments", 
			 GNUNET_CONTAINER_multihashmap_size (experiments), GNUNET_NO);
  
  return GNUNET_OK;
}


/**
 * Parse a configuration section containing experiments
 *
 * @param cls configuration handle
 * @param name section name
 */
static void
exp_file_iterator (void *cls,
		   const char *name)
{
  struct GNUNET_CONFIGURATION_Handle *exp = cls;
  struct Issuer *i;
  char *val;
  unsigned long long number;
  /* Experiment values */
  struct GNUNET_CRYPTO_EccPublicSignKey issuer;
  struct GNUNET_TIME_Absolute version;
  char *description;
  uint32_t required_capabilities;
  struct GNUNET_TIME_Absolute start ;
  struct GNUNET_TIME_Absolute stop;
  struct GNUNET_TIME_Relative frequency;
  struct GNUNET_TIME_Relative duration;
  struct GNUNET_HashCode phash;
  
  /* Mandatory fields */
  
  /* Issuer */
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (exp, name, "ISSUER", &val))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Experiment `%s': Issuer missing\n"), name);
    return;
  }
  if (GNUNET_SYSERR == 
      GNUNET_CRYPTO_ecc_public_sign_key_from_string (val, 
						     strlen (val),
						     &issuer))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Experiment `%s': Issuer invalid\n"), name);
    GNUNET_free (val);
    return;
  }
  GNUNET_CRYPTO_hash (&issuer, sizeof (issuer), &phash);
  if (NULL == (i = GNUNET_CONTAINER_multihashmap_get (valid_issuers, &phash)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Experiment `%s': Issuer not accepted!\n"), name);
    GNUNET_free (val);
    return;
  }
  GNUNET_free (val);
  
  /* Version */
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (exp, name, "VERSION", &number))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		_("Experiment `%s': Version missing or invalid \n"), name);
    return;
  }
  version.abs_value_us = number; // FIXME: what is this supposed to be? Version != TIME!???
  
  /* Required capabilities */
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (exp, name, "CAPABILITIES", &number))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		_("Experiment `%s': Required capabilities missing \n"), name);
    return;
  }
  if (number > UINT32_MAX)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Experiment `%s': Required capabilities invalid \n"), name);
    return;
  }
  required_capabilities = number;
  
  /* Optional fields */
  
  /* Description */
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (exp, name, "DESCRIPTION", &description))
    description = NULL;
  
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (exp, name, "START", (long long unsigned int *) &start.abs_value_us))
    start = GNUNET_TIME_UNIT_ZERO_ABS;
  
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time (exp, name, "FREQUENCY", &frequency))
    frequency = EXP_DEFAULT_EXP_FREQ;
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time (exp, name, "DURATION", &duration))
    duration = EXP_DEFAULT_EXP_DUR;
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (exp, name, "STOP", (long long unsigned int *)&stop.abs_value_us))
    stop = GNUNET_TIME_UNIT_FOREVER_ABS;
  
  GNUNET_EXPERIMENTATION_experiments_add (i, name, &issuer, version,
					  description, required_capabilities,
					  start, frequency, duration, stop);
  GNUNET_free_non_null (description);
}


/**
 * Load experiments from file
 *
 * @param file source file
 */
static void
load_file (const char * file)
{
  struct GNUNET_CONFIGURATION_Handle *exp = GNUNET_CONFIGURATION_create();

  if (NULL == exp)
    return;
  
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_parse (exp, file))
  {
    GNUNET_CONFIGURATION_destroy (exp);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to parse file `%s'\n"), 
		file);
    return;
  }
  GNUNET_CONFIGURATION_iterate_sections (exp, &exp_file_iterator, exp);
  GNUNET_CONFIGURATION_destroy (exp);
}


/**
 * Start experiments management
 */
int
GED_experiments_start ()
{
  struct Issuer *i;
  char *issuers;
  char *file;
  char *pos;
  struct GNUNET_CRYPTO_EccPublicSignKey issuer_ID;
  struct GNUNET_HashCode hash;
  
  /* Load valid issuer */
  if (GNUNET_SYSERR == 
      GNUNET_CONFIGURATION_get_value_string (GED_cfg, 
					     "EXPERIMENTATION", 
					     "ISSUERS",
					     &issuers))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		_("No valid experiment issuers configured! Set value to public keys of issuers! Exiting.\n"));
    GED_experiments_stop ();
    return GNUNET_SYSERR;
  }
  
  valid_issuers = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  for (pos = strtok (issuers, " "); pos != NULL; pos = strtok (NULL, " "))
  {   
    if (GNUNET_SYSERR == GNUNET_CRYPTO_ecc_public_sign_key_from_string (pos,
									strlen (pos),
									&issuer_ID))
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR, 
				 "EXPERIMENTATION",
				 "ISSUERS",
				 _("Invalid value for public key\n"));
      GED_experiments_stop ();
      return GNUNET_SYSERR;
    }
    i = GNUNET_new (struct Issuer);
    i->pubkey = issuer_ID;
    GNUNET_CRYPTO_hash( &issuer_ID, sizeof (issuer_ID), &hash);
    GNUNET_CONTAINER_multihashmap_put (valid_issuers, 
				       &hash,
				       i,
				       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);   
  }
  GNUNET_free (issuers);
  if (0 == GNUNET_CONTAINER_multihashmap_size (valid_issuers))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		_("No valid experiment issuers configured! Set value to public keys of issuers! Exiting.\n"));
    GED_experiments_stop ();
    return GNUNET_SYSERR;
  }
  GNUNET_STATISTICS_set (GED_stats,
			 "# issuer", 
			 GNUNET_CONTAINER_multihashmap_size (valid_issuers), 
			 GNUNET_NO);
  
  experiments = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  /* Load experiments from file */
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (GED_cfg,
					     "EXPERIMENTATION", 
					     "EXPERIMENTS",
					     &file))
    return GNUNET_OK;
  
  if (GNUNET_YES != GNUNET_DISK_file_test (file))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Cannot read experiments file `%s'\n"), file);
    GNUNET_free (file);
    return GNUNET_OK;
  }
  load_file (file);
  GNUNET_free (file);
  return GNUNET_OK;
}


/**
 * Stop experiments management
 */
void
GED_experiments_stop ()
{
  if (NULL != valid_issuers)
  {
    GNUNET_CONTAINER_multihashmap_iterate (valid_issuers, &free_issuer, NULL);
    GNUNET_CONTAINER_multihashmap_destroy (valid_issuers);
  }
  valid_issuers = NULL;
  if (NULL != experiments)
  {
    GNUNET_CONTAINER_multihashmap_iterate (experiments, &free_experiment, NULL);
    GNUNET_CONTAINER_multihashmap_destroy (experiments);
  }
  experiments = NULL;
}

/* end of gnunet-daemon-experimentation_experiments.c */
