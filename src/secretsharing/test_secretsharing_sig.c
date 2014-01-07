/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file secretsharing/test_secretsharing_sig.c
 * @brief ...
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "secretsharing_protocol.h"


int
main (int argc, char **argv)
{
  struct GNUNET_SECRETSHARING_KeygenCommitData *d;
  struct GNUNET_CRYPTO_EddsaPrivateKey *private_key;

  private_key = GNUNET_CRYPTO_eddsa_key_create ();

  d = GNUNET_malloc (sizeof *d);
  d->purpose.size = htons ((sizeof *d) - offsetof (struct GNUNET_SECRETSHARING_KeygenCommitData, purpose));
  d->purpose.purpose = htons (GNUNET_SIGNATURE_PURPOSE_SECRETSHARING_DKG1);
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_eddsa_sign (private_key, &d->purpose, &d->signature));
  return 0;
}

