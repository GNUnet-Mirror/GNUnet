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

struct GNUNET_CONTAINER_MultiHashMap *issuer;

/**
 * Is peer a valid issuer
 *
 * @return GNUNET_YES or GNUNET_NO
 */
int
GNUNET_EXPERIMENTATION_experiments_issuer_accepted (struct GNUNET_PeerIdentity *issuer_ID)
{
	if (GNUNET_CONTAINER_multihashmap_contains (issuer, &issuer_ID->hashPubKey))
		return GNUNET_YES;
	else
		return GNUNET_NO;
}


/**
 * Start experiments management
 */
int
GNUNET_EXPERIMENTATION_experiments_start ()
{
	char *issuers;
	char *pos;
	struct GNUNET_PeerIdentity issuer_ID;

	/* Load valid issuer */
	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (GSE_cfg, "EXPERIMENTATION", "ISSUERS", &issuers))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("No valid experiment issuers configured! Set value to peer id of issuer! Exit...\n"));
			return GNUNET_SYSERR;
	}

	issuer = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);

  for (pos = strtok (issuers, " "); pos != NULL; pos = strtok (NULL, " "))
  {

  		if (GNUNET_SYSERR == GNUNET_CRYPTO_hash_from_string (pos, &issuer_ID.hashPubKey))
  		{
  	  		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Invalid value `%s'\n"), pos);
  		}
  		else
  		{
  				GNUNET_log (GNUNET_ERROR_TYPE_INFO, "`%s' is a valid issuer \n", GNUNET_i2s (&issuer_ID));
  				GNUNET_CONTAINER_multihashmap_put (issuer, &issuer_ID.hashPubKey,
  						NULL, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  		}
  }
  GNUNET_free (issuers);

  if (0 == GNUNET_CONTAINER_multihashmap_size (issuer))
  {
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("No valid experiment issuers configured! Set value to peer id of issuer! Exit...\n"));
		GNUNET_EXPERIMENTATION_experiments_stop ();
		return GNUNET_SYSERR;
  }

  GNUNET_STATISTICS_set (GSE_stats, "# issuer", GNUNET_CONTAINER_multihashmap_size (issuer), GNUNET_NO);
	return GNUNET_OK;
}

/**
 * Stop experiments management
 */
void
GNUNET_EXPERIMENTATION_experiments_stop ()
{
	if (NULL != issuer)
		GNUNET_CONTAINER_multihashmap_destroy (issuer);
	issuer = NULL;
}

/* end of gnunet-daemon-experimentation_experiments.c */
