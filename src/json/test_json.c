/*
  This file is part of GNUnet
  (C) 2015, 2016 GNUnet e.V.

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
 * @file json/test_json.c
 * @brief Tests for JSON conversion functions
 * @author Christian Grothoff <christian@grothoff.org>
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_json_lib.h"


/**
 * Test absolute time conversion from/to JSON.
 *
 * @return 0 on success
 */
static int
test_abs_time ()
{
  json_t *j;
  struct GNUNET_TIME_Absolute a1;
  struct GNUNET_TIME_Absolute a2;
  struct GNUNET_JSON_Specification s1[] = {
    GNUNET_JSON_spec_absolute_time (NULL, &a2),
    GNUNET_JSON_spec_end()
  };
  struct GNUNET_JSON_Specification s2[] = {
    GNUNET_JSON_spec_absolute_time (NULL, &a2),
    GNUNET_JSON_spec_end()
  };

  a1 = GNUNET_TIME_absolute_get ();
  GNUNET_TIME_round_abs (&a1);
  j = GNUNET_JSON_from_time_abs (a1);
  GNUNET_assert (NULL != j);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_JSON_parse (j, s1, NULL, NULL));
  GNUNET_assert (a1.abs_value_us ==
		 a2.abs_value_us);
  json_decref (j);

  a1 = GNUNET_TIME_UNIT_FOREVER_ABS;
  j = GNUNET_JSON_from_time_abs (a1);
  GNUNET_assert (NULL != j);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_JSON_parse (j, s2, NULL, NULL));
  GNUNET_assert (a1.abs_value_us ==
		 a2.abs_value_us);
  json_decref (j);
  return 0;
}


/**
 * Test relative time conversion from/to JSON.
 *
 * @return 0 on success
 */
static int
test_rel_time ()
{
  json_t *j;
  struct GNUNET_TIME_Relative r1;
  struct GNUNET_TIME_Relative r2;
  struct GNUNET_JSON_Specification s1[] = {
    GNUNET_JSON_spec_relative_time (NULL, &r2),
    GNUNET_JSON_spec_end()
  };
  struct GNUNET_JSON_Specification s2[] = {
    GNUNET_JSON_spec_relative_time (NULL, &r2),
    GNUNET_JSON_spec_end()
  };

  r1 = GNUNET_TIME_UNIT_SECONDS;
  j = GNUNET_JSON_from_time_rel (r1);
  GNUNET_assert (NULL != j);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_JSON_parse (j, s1, NULL, NULL));
  GNUNET_assert (r1.rel_value_us ==
		 r2.rel_value_us);
  json_decref (j);

  r1 = GNUNET_TIME_UNIT_FOREVER_REL;
  j = GNUNET_JSON_from_time_rel (r1);
  GNUNET_assert (NULL != j);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_JSON_parse (j, s2, NULL, NULL));
  GNUNET_assert (r1.rel_value_us ==
		 r2.rel_value_us);
  json_decref (j);
  return 0;
}


/**
 * Test raw (binary) conversion from/to JSON.
 *
 * @return 0 on success
 */
static int
test_raw ()
{
  char blob[256];
  unsigned int i;
  json_t *j;

  for (i=0;i<=256;i++)
  {
    char blob2[256];
    struct GNUNET_JSON_Specification spec[] = {
      GNUNET_JSON_spec_fixed (NULL, blob2, i),
      GNUNET_JSON_spec_end()
    };

    memset (blob, i, i);
    j = GNUNET_JSON_from_data (blob, i);
    GNUNET_assert (NULL != j);
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_JSON_parse (j, spec,
                                      NULL, NULL));
    GNUNET_assert (0 ==
		   memcmp (blob,
			   blob2,
			   i));
  }
  return 0;
}


/**
 * Test rsa conversions from/to JSON.
 *
 * @return 0 on success
 */
static int
test_rsa ()
{
  struct GNUNET_CRYPTO_RsaPublicKey *pub;
  struct GNUNET_CRYPTO_RsaPublicKey *pub2;
  struct GNUNET_JSON_Specification pspec[] = {
    GNUNET_JSON_spec_rsa_public_key (NULL, &pub2),
    GNUNET_JSON_spec_end()
  };
  struct GNUNET_CRYPTO_RsaSignature *sig;
  struct GNUNET_CRYPTO_RsaSignature *sig2;
  struct GNUNET_JSON_Specification sspec[] = {
    GNUNET_JSON_spec_rsa_signature (NULL, &sig2),
    GNUNET_JSON_spec_end()
  };
  struct GNUNET_CRYPTO_RsaPrivateKey *priv;
  struct GNUNET_HashCode msg;
  json_t *jp;
  json_t *js;

  priv = GNUNET_CRYPTO_rsa_private_key_create (1024);
  pub = GNUNET_CRYPTO_rsa_private_key_get_public (priv);
  memset (&msg, 42, sizeof (msg));
  sig = GNUNET_CRYPTO_rsa_sign_fdh (priv,
                                    &msg);
  GNUNET_assert (NULL != (jp = GNUNET_JSON_from_rsa_public_key (pub)));
  GNUNET_assert (NULL != (js = GNUNET_JSON_from_rsa_signature (sig)));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_JSON_parse (jp, pspec,
                                    NULL, NULL));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_JSON_parse (js, sspec,
                                    NULL, NULL));
  GNUNET_break (0 ==
		GNUNET_CRYPTO_rsa_signature_cmp (sig,
						 sig2));
  GNUNET_break (0 ==
		GNUNET_CRYPTO_rsa_public_key_cmp (pub,
						  pub2));
  GNUNET_CRYPTO_rsa_signature_free (sig);
  GNUNET_CRYPTO_rsa_signature_free (sig2);
  GNUNET_CRYPTO_rsa_private_key_free (priv);
  GNUNET_CRYPTO_rsa_public_key_free (pub);
  GNUNET_CRYPTO_rsa_public_key_free (pub2);
  return 0;
}


int
main(int argc,
     const char *const argv[])
{
  GNUNET_log_setup ("test-json",
		    "WARNING",
		    NULL);
  if (0 != test_abs_time ())
    return 1;
  if (0 != test_rel_time ())
    return 1;
  if (0 != test_raw ())
    return 1;
  if (0 != test_rsa ())
    return 1;
  /* FIXME: test EdDSA signature conversion... */
  return 0;
}

/* end of test_json.c */
