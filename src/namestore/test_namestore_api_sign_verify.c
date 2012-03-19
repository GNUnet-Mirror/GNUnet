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
 * @file namestore/test_namestore_api_sign_verify.c
 * @brief testcase for signing and verifying
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_namestore_service.h"
#include "namestore.h"
#include "gnunet_signatures.h"

#define VERBOSE GNUNET_NO

#define RECORDS 5
#define TEST_RECORD_TYPE 1234
#define TEST_RECORD_DATALEN 123
#define TEST_RECORD_DATA 'a'

#define TEST_REMOVE_RECORD_TYPE 4321
#define TEST_REMOVE_RECORD_DATALEN 255
#define TEST_REMOVE_RECORD_DATA 'b'

static struct GNUNET_CRYPTO_RsaPrivateKey * privkey;
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pubkey;
struct GNUNET_CRYPTO_RsaSignature s_signature;
struct GNUNET_NAMESTORE_RecordData *s_rd;
static char *s_name;

static int res;

static struct GNUNET_NAMESTORE_RecordData *
create_record (int count)
{
  int c;
  struct GNUNET_NAMESTORE_RecordData * rd;
  rd = GNUNET_malloc (count * sizeof (struct GNUNET_NAMESTORE_RecordData));

  for (c = 0; c < RECORDS; c++)
  {
  rd[c].expiration = GNUNET_TIME_absolute_get();
  rd[c].record_type = TEST_RECORD_TYPE;
  rd[c].data_size = TEST_RECORD_DATALEN;
  rd[c].data = GNUNET_malloc(TEST_RECORD_DATALEN);
  memset ((char *) rd[c].data, TEST_RECORD_DATA, TEST_RECORD_DATALEN);
  }

  return rd;
}



static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CRYPTO_RsaSignature * signature;

  /* load privat key */
  char *hostkey_file;
  GNUNET_asprintf(&hostkey_file,"zonefiles%s%s",DIR_SEPARATOR_STR,
      "N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Using zonekey file `%s' \n", hostkey_file);
  privkey = GNUNET_CRYPTO_rsa_key_create_from_file(hostkey_file);
  GNUNET_free (hostkey_file);
  GNUNET_assert (privkey != NULL);
  struct GNUNET_TIME_Absolute expire = GNUNET_TIME_absolute_get();
  /* get public key */
  GNUNET_CRYPTO_rsa_key_get_public(privkey, &pubkey);

  int res_c;
  int res_w;

  /* create record */
  s_name = "dummy.dummy.gnunet";
  s_rd = create_record (RECORDS);

  signature = GNUNET_NAMESTORE_create_signature (privkey, expire, s_name, s_rd, RECORDS);
  GNUNET_assert (signature != NULL);

  res_c = GNUNET_NAMESTORE_verify_signature(&pubkey, expire, s_name, RECORDS, s_rd, signature);
  GNUNET_break (res == GNUNET_OK);

  GNUNET_free (signature);

  signature = GNUNET_NAMESTORE_create_signature (privkey, expire, s_name, s_rd, RECORDS);
  GNUNET_break (signature != NULL);

  GNUNET_log_skip(1, GNUNET_NO);
  res_w = GNUNET_NAMESTORE_verify_signature(&pubkey, expire, s_name, RECORDS - 1, s_rd, signature);
  GNUNET_break (res_w == GNUNET_SYSERR);

  GNUNET_free (signature);

  if ((res_c == GNUNET_OK) && (res_w == GNUNET_SYSERR))
    res = 0;
  else
    res = 1;

}

static int
check ()
{
  static char *const argv[] = { "test-namestore-api",
    "-c",
    "test_namestore_api.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  res = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv, "test-namestore-api",
                      "nohelp", options, &run, &res);
  return res;
}

int
main (int argc, char *argv[])
{
  int ret;

  ret = check ();

  return ret;
}

/* end of test_namestore_api_sign_verify.c */
