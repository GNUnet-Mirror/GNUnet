/*
      This file is part of GNUnet
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
 * @file testing/helper.c
 * @brief helper functions for testing
 * @author Christian Grothoff
 *
 */
#include "platform.h"
#include "gnunet_testing_lib.h"




/**
 * Obtain the peer identity of the peer with the given configuration
 * handle.  This function reads the private key of the peer, obtains
 * the public key and hashes it.
 *
 * @param cfg configuration of the peer
 * @param pid where to store the peer identity
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_TESTING_get_peer_identity (const struct GNUNET_CONFIGURATION_Handle *cfg,
				  struct GNUNET_PeerIdentity *pid)
{
  char *keyfile;
  struct GNUNET_CRYPTO_RsaPrivateKey *my_private_key;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded my_public_key;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "GNUNETD", "HOSTKEY",
                                               &keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Peer is lacking HOSTKEY configuration setting.\n"));
    return GNUNET_SYSERR;
  }
  my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (my_private_key == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not access hostkey.\n"));
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_rsa_key_free (my_private_key);
  GNUNET_CRYPTO_hash (&my_public_key, sizeof (my_public_key),
                      &pid->hashPubKey);
  return GNUNET_OK;
}


/* end of helper.c */
