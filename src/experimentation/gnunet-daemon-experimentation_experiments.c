/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
#include "gnunet_getopt_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-daemon-experimentation.h"



/**
 * Struct to store information about an experiment issuer
 */
struct Issuer
{
	struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded pubkey;
};


/**
 * Hashmap containing valid experiment issuer
 */
static struct GNUNET_CONTAINER_MultiHashMap *valid_issuers;


/**
 * Hashmap containing valid experiments
 */
static struct GNUNET_CONTAINER_MultiHashMap *experiments;


uint32_t GSE_my_issuer_count;

/**
 * Valid experiment issuer for this daemon
 *
 * Array Experimentation_Issuer with GSE_my_issuer_count elements
 */
struct Experimentation_Issuer *GSE_my_issuer;


/**
 * Verify experiment signature
 *
 * @param i issuer
 * @param e experiment
 * @return GNUNET_OK or GNUNET_SYSERR
 */
int
experiment_verify (struct Issuer *i, struct Experiment *e)
{
	GNUNET_assert (NULL != i);
	GNUNET_assert (NULL != e);

	GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Verification: to be implemented\n");
	return GNUNET_OK;
}

int free_experiment (void *cls,
										 const struct GNUNET_HashCode * key,
										 void *value)
{
	struct Experiment *e = value;
	GNUNET_CONTAINER_multihashmap_remove (experiments, key, value);
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
int free_issuer (void *cls,
								 const struct GNUNET_HashCode * key,
								 void *value)
{
	struct Issuer *i = value;
	GNUNET_CONTAINER_multihashmap_remove (valid_issuers, key, value);
	GNUNET_free (i);
	return GNUNET_OK;
}

int create_issuer (void *cls,
								 const struct GNUNET_HashCode * key,
								 void *value)
{
	static int i = 0;
	GNUNET_assert (i < GSE_my_issuer_count);
	GSE_my_issuer[i].issuer_id.hashPubKey = *key;

	i++;
	return GNUNET_OK;

}



/**
 * Is peer a valid issuer
 *
 * @return GNUNET_YES or GNUNET_NO
 */
int
GNUNET_EXPERIMENTATION_experiments_issuer_accepted (struct GNUNET_PeerIdentity *issuer_ID)
{
	if (GNUNET_CONTAINER_multihashmap_contains (valid_issuers, &issuer_ID->hashPubKey))
		return GNUNET_YES;
	else
		return GNUNET_NO;
}

struct GetCtx
{
	struct Node *n;
	GNUNET_EXPERIMENTATION_experiments_get_cb get_cb;
};

static int
get_it (void *cls,
				const struct GNUNET_HashCode * key,
				void *value)
{
	struct GetCtx *get_ctx = cls;
	struct Experiment *e = value;

	get_ctx->get_cb (get_ctx->n, e);

	return GNUNET_OK;
}




void
GNUNET_EXPERIMENTATION_experiments_get (struct Node *n,
																				struct GNUNET_PeerIdentity *issuer,
																				GNUNET_EXPERIMENTATION_experiments_get_cb get_cb)
{
	struct GetCtx get_ctx;

	GNUNET_assert (NULL != n);
	GNUNET_assert (NULL != experiments);
	GNUNET_assert (NULL != get_cb);

	get_ctx.n = n;
	get_ctx.get_cb = get_cb;

	GNUNET_CONTAINER_multihashmap_get_multiple (experiments,
			&issuer->hashPubKey, &get_it, &get_ctx);

	get_cb (n, NULL);
}

/**
 * Add a new experiment
 */
int GNUNET_EXPERIMENTATION_experiments_add (struct Issuer *i,
																						const char *name,
																						struct GNUNET_PeerIdentity issuer_id,
																						struct GNUNET_TIME_Absolute version,
																						char *description,
																						uint32_t required_capabilities,
																						struct GNUNET_TIME_Absolute start,
																						struct GNUNET_TIME_Relative frequency,
																						struct GNUNET_TIME_Relative duration,
																						struct GNUNET_TIME_Absolute stop)
{
	struct Experiment *e;
	e = GNUNET_malloc (sizeof (struct Experiment));

	e->name = GNUNET_strdup (name);
	e->issuer = issuer_id;
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
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Experiment `%s': Experiment signature is invalid\n"), name);
			GNUNET_free (e);
			GNUNET_free_non_null (e->name);
			GNUNET_free_non_null (e->description);
			return GNUNET_SYSERR;
	}

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Adding experiment `%s' running from `%s' to `%s' every %llu sec. for %llu sec. \n"),
			e->name,
			GNUNET_STRINGS_absolute_time_to_string (start),
			GNUNET_STRINGS_absolute_time_to_string (stop),
			(long long unsigned int) frequency.rel_value / 1000,
			(long long unsigned int) duration.rel_value / 1000);
	GNUNET_CONTAINER_multihashmap_put (experiments, &e->issuer.hashPubKey, e, GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_STATISTICS_set (GSE_stats, "# experiments", GNUNET_CONTAINER_multihashmap_size (experiments), GNUNET_NO);

	return GNUNET_OK;
}


/**
 * Parse a configuration section containing experiments
 *
 * @param cls configuration handle
 * @param name section name
 */
void exp_file_iterator (void *cls,
												const char *name)
{
	struct GNUNET_CONFIGURATION_Handle *exp = cls;
	struct Issuer *i;

	char *val;
	unsigned long long number;

	/* Experiment values */
	struct GNUNET_PeerIdentity issuer;
	struct GNUNET_TIME_Absolute version;
	char *description;
	uint32_t required_capabilities;
	struct GNUNET_TIME_Absolute start ;
	struct GNUNET_TIME_Absolute stop;
	struct GNUNET_TIME_Relative frequency;
	struct GNUNET_TIME_Relative duration;

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Parsing section `%s'\n", name);

	/* Mandatory fields */

	/* Issuer */
	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (exp, name, "ISSUER", &val))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Experiment `%s': Issuer missing\n"), name);
			return;
	}
	if (GNUNET_SYSERR == GNUNET_CRYPTO_hash_from_string (val, &issuer.hashPubKey))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Experiment `%s': Issuer invalid\n"), name);
			GNUNET_free (val);
			return;
	}
	if (NULL == (i = GNUNET_CONTAINER_multihashmap_get (valid_issuers, &issuer.hashPubKey)))
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Experiment `%s': Issuer not accepted!\n"), name);
		GNUNET_free (val);
		return;
	}
	GNUNET_free (val);

	/* Version */
	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (exp, name, "VERSION", &number))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Experiment `%s': Version missing or invalid \n"), name);
			return;
	}
	version.abs_value = number;

	/* Required capabilities */
	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (exp, name, "CAPABILITIES", &number))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Experiment `%s': Required capabilities missing \n"), name);
			return;
	}
	if (number > UINT32_MAX)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Experiment `%s': Required capabilities invalid \n"), name);
		return;
	}
	required_capabilities = number;

	/* Optional fields */

	/* Description */
	GNUNET_CONFIGURATION_get_value_string (exp, name, "DESCRIPTION", &description);



	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (exp, name, "START", (long long unsigned int *) &start.abs_value))
			start = GNUNET_TIME_UNIT_ZERO_ABS;

	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time (exp, name, "FREQUENCY", &frequency))
			frequency = EXP_DEFAULT_EXP_FREQ;
	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time (exp, name, "DURATION", &duration))
			duration = EXP_DEFAULT_EXP_DUR;
	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (exp, name, "STOP", (long long unsigned int *)&stop.abs_value))
			stop = GNUNET_TIME_UNIT_FOREVER_ABS;

	GNUNET_EXPERIMENTATION_experiments_add (i, name, issuer, version,
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
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Failed to parse file `%s'\n"), file);
		return;
	}
	GNUNET_CONFIGURATION_iterate_sections (exp, &exp_file_iterator, exp);
	GNUNET_CONFIGURATION_destroy (exp);
}


/**
 * Start experiments management
 */
int
GNUNET_EXPERIMENTATION_experiments_start ()
{
	struct Issuer *i;
	char *issuers;
	char *file;
	char *pubkey;
	char *pos;
	struct GNUNET_PeerIdentity issuer_ID;
	struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded pub;
	struct GNUNET_HashCode hash;

	/* Load valid issuer */
	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (GSE_cfg, "EXPERIMENTATION", "ISSUERS", &issuers))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("No valid experiment issuers configured! Set value to peer id of issuer! Exit...\n"));
			return GNUNET_SYSERR;
	}

	valid_issuers = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  for (pos = strtok (issuers, " "); pos != NULL; pos = strtok (NULL, " "))
  {

  		if (GNUNET_SYSERR == GNUNET_CRYPTO_hash_from_string (pos, &issuer_ID.hashPubKey))
  		{
  	  		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Invalid value `%s'\n"), pos);
  		}
  		else
  		{
  				GNUNET_log (GNUNET_ERROR_TYPE_INFO, "`%s' is a valid issuer \n", GNUNET_i2s (&issuer_ID));
  				i = GNUNET_malloc (sizeof (struct Issuer));
  				GNUNET_CONTAINER_multihashmap_put (valid_issuers, &issuer_ID.hashPubKey,
  						i, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  				i = NULL;
  		}
  }
  GNUNET_free (issuers);

  if (0 == GNUNET_CONTAINER_multihashmap_size (valid_issuers))
  {
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("No valid experiment issuers configured! Set value to peer id of issuer! Exit...\n"));
		GNUNET_EXPERIMENTATION_experiments_stop ();
		return GNUNET_SYSERR;
  }
  GNUNET_STATISTICS_set (GSE_stats, "# issuer", GNUNET_CONTAINER_multihashmap_size (valid_issuers), GNUNET_NO);

	if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (GSE_cfg, "EXPERIMENTATION", "PUBKEY", &pubkey))
	{
			if (GNUNET_OK != GNUNET_CRYPTO_ecc_public_key_from_string(pubkey, strlen (pubkey), &pub))
	  		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Invalid public key `%s'\n"), pubkey);
			else
			{
				GNUNET_CRYPTO_hash( &pub, sizeof (pub), &hash);
				if (NULL != (i = GNUNET_CONTAINER_multihashmap_get (valid_issuers, &hash)))
				{
						i->pubkey = pub;
						GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Found issuer for public key `%s'\n"), pubkey);
				}
				else
					GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("No issuer for public key `%s'\n"), pubkey);
			}
			GNUNET_free (pubkey);
	}

	GSE_my_issuer_count = GNUNET_CONTAINER_multihashmap_size (valid_issuers);
	GSE_my_issuer = GNUNET_malloc (GSE_my_issuer_count * sizeof (struct Experimentation_Issuer));
	GNUNET_CONTAINER_multihashmap_iterate (valid_issuers, &create_issuer, GSE_my_issuer);
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Daemon has %u issuers\n"), GSE_my_issuer_count);

  experiments = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  /* Load experiments from file */
	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (GSE_cfg, "EXPERIMENTATION", "EXPERIMENTS", &file))
		return GNUNET_OK;

	if (GNUNET_YES != GNUNET_DISK_file_test (file))
	{
  		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Cannot read experiments file `%s'\n"), file);
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
GNUNET_EXPERIMENTATION_experiments_stop ()
{
	if (NULL != GSE_my_issuer)
	{
		GNUNET_free (GSE_my_issuer);
		GSE_my_issuer = NULL;
		GSE_my_issuer_count = 0;
	}
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
