/*
  This file is part of GNUnet
  (C) 2014 Christian Grothoff (and other contributing authors)

  GNUnet is free software; you can redistribute it and/or modify it under the
  terms of the GNU General Public License as published by the Free Software
  Foundation; either version 3, or (at your option) any later version.

  GNUnet is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along with
  GNUnet; see the file COPYING.  If not, If not, see <http://www.gnu.org/licenses/>
*/
/**
 * @file util/test_crypto_hash_context.c
 * @brief test case for incremental hashing
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#define LEN 1234

int main()
{
  char data[1234];
  struct GNUNET_HashCode hc1;
  struct GNUNET_HashCode hc2;
  struct GNUNET_HashContext *hctx;

  memset (data, 42, LEN);

  hctx = GNUNET_CRYPTO_hash_context_start ();
  GNUNET_CRYPTO_hash_context_read (hctx, data, LEN);
  GNUNET_CRYPTO_hash_context_finish (hctx, &hc1);

  GNUNET_CRYPTO_hash (data, LEN, &hc2);

  if (0 == memcmp (&hc1, &hc2, sizeof (struct GNUNET_HashCode)))
    return 0;
  return 1;
}

