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
 * @file util/test_crypto_random.c
 * @brief testcase for crypto_random.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"

static int
test (enum GNUNET_CRYPTO_Quality mode)
{

  int buf[1024];
  unsigned int *b2;
  int i;
  unsigned long long n;

  for (i = 0; i < 1024; i++)
    GNUNET_break (1024 > (buf[i] = GNUNET_CRYPTO_random_u32 (mode, 1024)));
  for (i = 0; i < 10; i++)
  {
    b2 = GNUNET_CRYPTO_random_permute (mode, 1024);
    if (0 == memcmp (b2, buf, sizeof (buf)))
    {
      FPRINTF (stderr, "%s",  "!");
      GNUNET_free (b2);
      continue;
    }
    GNUNET_free (b2);
    break;
  }
  if (i == 10)
    return 1;                   /* virtually impossible... */

  for (n = 10; n < 1024LL * 1024LL * 1024LL; n *= 10)
    GNUNET_break (n > GNUNET_CRYPTO_random_u64 (mode, n));
  return 0;
}

int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test-crypto-random", "WARNING", NULL);
  if (0 != test (GNUNET_CRYPTO_QUALITY_WEAK))
    return 1;
  if (0 != test (GNUNET_CRYPTO_QUALITY_STRONG))
    return 1;

  return 0;
}
