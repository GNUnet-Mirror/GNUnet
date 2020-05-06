/*
     This file is part of GNUnet.
     Copyright (C) 2015 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @author Bart Polot
 * @file util/perf_crypto_asymmetric.c
 * @brief measure performance of public key functions
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gauger.h>

static struct GNUNET_TIME_Absolute start;

#define l 500

struct TestSig
{
  struct GNUNET_CRYPTO_EccSignaturePurpose purp;
  struct GNUNET_HashCode h;
  struct GNUNET_CRYPTO_EddsaSignature sig;
};


static void
log_duration (const char *cryptosystem,
              const char *description)
{
  struct GNUNET_TIME_Relative t;
  char s[64];

  sprintf (s, "%6s %15s", cryptosystem, description);
  t = GNUNET_TIME_absolute_get_duration (start);
  t = GNUNET_TIME_relative_divide (t, l);
  fprintf (stdout,
           "%s: %10s\n",
           s,
           GNUNET_STRINGS_relative_time_to_string (t,
                                                   GNUNET_NO));
  GAUGER ("UTIL", s, t.rel_value_us, "us");
}


int
main (int argc, char *argv[])
{
  int i;
  struct GNUNET_CRYPTO_EcdhePrivateKey ecdhe[l];
  struct GNUNET_CRYPTO_EcdhePublicKey dhpub[l];
  struct GNUNET_CRYPTO_EddsaPrivateKey eddsa[l];
  struct GNUNET_CRYPTO_EddsaPublicKey dspub[l];
  struct TestSig sig[l];

  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < l; i++)
  {
    sig[i].purp.purpose = 0;
    sig[i].purp.size = htonl (sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
                              + sizeof(struct GNUNET_HashCode));
    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                                &sig[i].h,
                                sizeof(sig[i].h));
  }
  log_duration ("", "Init");

  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < l; i++)
    GNUNET_CRYPTO_eddsa_key_create (&eddsa[i]);
  log_duration ("EdDSA", "create key");

  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < l; i++)
    GNUNET_CRYPTO_eddsa_key_get_public (&eddsa[i], &dspub[i]);
  log_duration ("EdDSA", "get public");

  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < l; i++)
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_eddsa_sign_ (&eddsa[i],
                                              &sig[i].purp,
                                              &sig[i].sig));
  log_duration ("EdDSA", "sign HashCode");

  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < l; i++)
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_eddsa_verify_ (0,
                                                &sig[i].purp,
                                                &sig[i].sig,
                                                &dspub[i]));
  log_duration ("EdDSA", "verify HashCode");

  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < l; i++)
    GNUNET_CRYPTO_ecdhe_key_create (&ecdhe[i]);
  log_duration ("ECDH", "create key");

  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < l; i++)
    GNUNET_CRYPTO_ecdhe_key_get_public (&ecdhe[i], &dhpub[i]);
  log_duration ("ECDH", "get public");

  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < l - 1; i += 2)
  {
    GNUNET_CRYPTO_ecc_ecdh (&ecdhe[i], &dhpub[i + 1], &sig[i].h);
    GNUNET_CRYPTO_ecc_ecdh (&ecdhe[i + 1], &dhpub[i], &sig[i + 1].h);
  }
  log_duration ("ECDH", "do DH");

  return 0;
}


/* end of perf_crypto_asymmetric.c */
