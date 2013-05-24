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

/**
 * Hashmap containing valid experiment issuer
 */
static struct GNUNET_CONTAINER_MultiHashMap *valid_issuers;

void
GNUNET_EXPERIMENTATION_experiments_verify ()
{

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
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Section `%s': Issuer missing\n", section);
			GNUNET_free (e);
			return;
	}
	if (GNUNET_SYSERR == GNUNET_CRYPTO_hash_from_string (section, &e->issuer.hashPubKey))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Section `%s': Issuer invalid\n", section);
			GNUNET_free (val);
			GNUNET_free (e);
			return;
	}
	if (NULL == (i = GNUNET_CONTAINER_multihashmap_get (valid_issuers, &e->issuer.hashPubKey)))
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Section `%s': Issuer not accepted!\n", section);
		GNUNET_free (val);
		GNUNET_free (e);
		return;
	}

	GNUNET_free (val);

	/* Version */
	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (exp, section, "VERSION", &number))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Section `%s': Version missing \n", section);
			GNUNET_free (e);
			return;
	}
	e->version.abs_value = number;

	/* Required capabilities */
	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number (exp, section, "CAPABILITIES", &number))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Section `%s': Required capabilities missing \n", section);
			GNUNET_free (e);
			return;
	}
	if (number > UINT32_MAX)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Section `%s': Required capabilities invalid \n", section);
		GNUNET_free (e);
		return;
	}
	e->required_capabilities = number;

	/* Optional fields  */

	/* Description */
	GNUNET_CONFIGURATION_get_value_string (exp, section, "DESCRIPTION", &e->description);


	/* verify experiment */

}

/**
 * Load experiments from file
 * FIXME: Not yet sure how to store that on disk ...
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
	char *issuers;
	char *file;
	char *pos;
	struct GNUNET_PeerIdentity issuer_ID;

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
  				GNUNET_CONTAINER_multihashmap_put (valid_issuers, &issuer_ID.hashPubKey,
  						NULL, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
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

  /* Load experiments from file */
	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (GSE_cfg, "EXPERIMENTATION", "EXPERIMENTS", &file))
		return GNUNET_OK;

	if (GNUNET_YES != GNUNET_DISK_file_test (file))
	{
  		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Cannot read experiments file `%s'\n"), file);
			return GNUNET_OK;
	}
	load_file (file);

	return GNUNET_OK;
}

/**
 * Stop experiments management
 */
void
GNUNET_EXPERIMENTATION_experiments_stop ()
{
	if (NULL != valid_issuers)
		GNUNET_CONTAINER_multihashmap_destroy (valid_issuers);
	valid_issuers = NULL;
}

/* end of gnunet-daemon-experimentation_experiments.c */
