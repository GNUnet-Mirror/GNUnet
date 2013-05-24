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

struct Experiment
{
	/* Header */
	char *name;

	/* Experiment issuer */
	struct GNUNET_PeerIdentity issuer;

	/* Experiment version as timestamp of creation */
	struct GNUNET_TIME_Absolute version;

	/* Description */
	char *description;

	/* Required capabilities  */
	uint32_t required_capabilities;

	/* Experiment itself */

	/* TBD */
};

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

int free_issuer (void *cls,
								 const struct GNUNET_HashCode * key,
								 void *value)
{
	struct Issuer *i = value;
	GNUNET_CONTAINER_multihashmap_remove (valid_issuers, key, value);
	GNUNET_free (i);
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


void exp_file_iterator (void *cls,
												const char *section)
{
	struct GNUNET_CONFIGURATION_Handle *exp = cls;
	struct Experiment *e;
	struct Issuer *i;

	char *val;
	unsigned long long number;

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Parsing section `%s'\n", section);

	e = GNUNET_malloc (sizeof (struct Experiment));
	/* Mandatory fields */

	/* Issuer */
	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (exp, section, "ISSUER", &val))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Experiment `%s': Issuer missing\n"), section);
			GNUNET_free (e);
			return;
	}
	if (GNUNET_SYSERR == GNUNET_CRYPTO_hash_from_string (val, &e->issuer.hashPubKey))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Experiment `%s': Issuer invalid\n"), section);
			GNUNET_free (val);
			GNUNET_free (e);
			return;
	}
	if (NULL == (i = GNUNET_CONTAINER_multihashmap_get (valid_issuers, &e->issuer.hashPubKey)))
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Experiment `%s': Issuer not accepted!\n"), section);
		GNUNET_free (val);
		GNUNET_free (e);
		return;
	}
	GNUNET_free (val);

	/* Version */
	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (exp, section, "VERSION", &number))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Experiment `%s': Version missing or invalid \n"), section);
			GNUNET_free (e);
			return;
	}
	e->version.abs_value = number;

	/* Required capabilities */
	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (exp, section, "CAPABILITIES", &number))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Experiment `%s': Required capabilities missing \n"), section);
			GNUNET_free (e);
			return;
	}
	if (number > UINT32_MAX)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Experiment `%s': Required capabilities invalid \n"), section);
		GNUNET_free (e);
		return;
	}
	e->required_capabilities = number;
	e->name = GNUNET_strdup (section);

	/* Optional fields */
	/* Description */
	GNUNET_CONFIGURATION_get_value_string (exp, section, "DESCRIPTION", &e->description);

	/* verify experiment */
	if (GNUNET_SYSERR == experiment_verify (i, e))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Experiment `%s': Experiment signature is invalid\n"), section);
			GNUNET_free (e);
			GNUNET_free_non_null (e->name);
			GNUNET_free_non_null (e->description);
			return;
	}
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Adding experiment `%s'\n"), e->name);
	GNUNET_CONTAINER_multihashmap_put (experiments, &e->issuer.hashPubKey, e, GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_STATISTICS_set (GSE_stats, "# experiments", GNUNET_CONTAINER_multihashmap_size (experiments), GNUNET_NO);
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
