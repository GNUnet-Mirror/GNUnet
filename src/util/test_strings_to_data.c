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
 * @file util/test_strings_to_data.c
 * @brief testcase for strings.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_strings_lib.h"


int
main (int argc, char *argv[])
{
	GNUNET_log_setup ("util", "DEBUG", NULL);
	char *conv;
	struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded src;
	struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded dest;

	memset (&src, '\1', sizeof (src));
	memset (&dest, '\2', sizeof (dest));


	conv = GNUNET_CRYPTO_ecc_public_key_to_string (&src);
	GNUNET_assert (NULL != conv);
	fprintf (stderr, "Key `%s'\n",conv);
	//GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_ecc_public_key_from_string (conv, strlen (conv), &dest));
  GNUNET_assert (GNUNET_OK == GNUNET_STRINGS_string_to_data (conv, strlen (conv), (unsigned char *) &dest, sizeof (dest)));
  GNUNET_assert (0 == memcmp (&src, &dest, sizeof (dest)));

	return 0;
}


/* end of test_strings_to_data.c */
