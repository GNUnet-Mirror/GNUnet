/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_pseudonym.c
 * @brief testcase for pseudonym.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_disk_lib.h"
#include "gnunet_pseudonym_lib.h"

#define CHECK(a) do { if (!(a)) { ok = GNUNET_NO; GNUNET_break(0); goto FAILURE; } } while (0)

static struct GNUNET_CONTAINER_MetaData *meta;

static GNUNET_HashCode id1;

static int
iter (void *cls, const GNUNET_HashCode * pseudonym,
      const struct GNUNET_CONTAINER_MetaData *md, int rating)
{
  int *ok = cls;

  if ((0 == memcmp (pseudonym, &id1, sizeof (GNUNET_HashCode))) &&
      (!GNUNET_CONTAINER_meta_data_test_equal (md, meta)))
  {
    *ok = GNUNET_NO;
    GNUNET_break (0);
  }
  return GNUNET_OK;
}

static int
noti_callback (void *cls, const GNUNET_HashCode * pseudonym,
               const struct GNUNET_CONTAINER_MetaData *md, int rating)
{
  int *ret = cls;

  (*ret)++;
  return GNUNET_OK;
}

static int
fake_noti_callback (void *cls, const GNUNET_HashCode * pseudonym,
                    const struct GNUNET_CONTAINER_MetaData *md, int rating)
{
  int *ret = cls;

  (*ret)++;
  return GNUNET_OK;
}

static int
false_callback (void *cls, const GNUNET_HashCode * pseudonym,
                const struct GNUNET_CONTAINER_MetaData *md, int rating)
{
  return GNUNET_OK;
}

int
main (int argc, char *argv[])
{
  int ok;
  GNUNET_HashCode rid1;
  GNUNET_HashCode id2;
  GNUNET_HashCode rid2;
  GNUNET_HashCode fid;
  GNUNET_HashCode id3;

  int old;
  int newVal;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  char *name1;
  char *name2;
  char *name3;
  char *noname;
  int notiCount, fakenotiCount;
  int count;
  static char m[1024 * 1024 * 10];

  memset (m, 'b', sizeof (m));
  m[sizeof (m) - 1] = '\0';

  GNUNET_log_setup ("test-pseudonym", "WARNING", NULL);
  ok = GNUNET_YES;
  GNUNET_CRYPTO_random_disable_entropy_gathering ();
  (void) GNUNET_DISK_directory_remove ("/tmp/gnunet-pseudonym-test");
  cfg = GNUNET_CONFIGURATION_create ();
  if (-1 == GNUNET_CONFIGURATION_parse (cfg, "test_pseudonym_data.conf"))
  {
    GNUNET_CONFIGURATION_destroy (cfg);
    GNUNET_break (0);
    return -1;
  }
  notiCount = 0;
  fakenotiCount = 0;
  count = 0;
  GNUNET_PSEUDONYM_discovery_callback_register (cfg, &fake_noti_callback,
                                                &fakenotiCount);
  GNUNET_PSEUDONYM_discovery_callback_register (cfg, &noti_callback,
                                                &notiCount);
  GNUNET_PSEUDONYM_discovery_callback_unregister (&false_callback, &count);
  GNUNET_PSEUDONYM_discovery_callback_unregister (&fake_noti_callback,
                                                  &fakenotiCount);

  /* ACTUAL TEST CODE */
  old = GNUNET_PSEUDONYM_list_all (cfg, NULL, NULL);
  meta = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_CONTAINER_meta_data_insert (meta, "<test>", EXTRACTOR_METATYPE_TITLE,
                                     EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                     "test", strlen ("test") + 1);
  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &id1);
  GNUNET_PSEUDONYM_add (cfg, &id1, meta);
  CHECK (notiCount == 1);
  GNUNET_PSEUDONYM_add (cfg, &id1, meta);
  CHECK (notiCount == 2);
  newVal = GNUNET_PSEUDONYM_list_all (cfg, &iter, &ok);
  CHECK (old < newVal);
  old = newVal;
  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &id2);
  GNUNET_PSEUDONYM_add (cfg, &id2, meta);
  CHECK (notiCount == 3);
  newVal = GNUNET_PSEUDONYM_list_all (cfg, &iter, &ok);
  CHECK (old < newVal);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_meta_data_insert (meta, "<test>",
                                                    EXTRACTOR_METATYPE_COMMENT,
                                                    EXTRACTOR_METAFORMAT_UTF8,
                                                    "text/plain", m,
                                                    strlen (m) + 1));
  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &id3);
  GNUNET_PSEUDONYM_add (cfg, &id3, meta);
  name3 = GNUNET_PSEUDONYM_id_to_name (cfg, &id3);
  name2 = GNUNET_PSEUDONYM_id_to_name (cfg, &id2);
  CHECK (name2 != NULL);
  name1 = GNUNET_PSEUDONYM_id_to_name (cfg, &id1);
  CHECK (name1 != NULL);
  CHECK (0 != strcmp (name1, name2));
  CHECK (GNUNET_SYSERR == GNUNET_PSEUDONYM_name_to_id (cfg, "fake", &rid2));
  CHECK (GNUNET_OK == GNUNET_PSEUDONYM_name_to_id (cfg, name2, &rid2));
  CHECK (GNUNET_OK == GNUNET_PSEUDONYM_name_to_id (cfg, name1, &rid1));
  CHECK (0 == memcmp (&id1, &rid1, sizeof (GNUNET_HashCode)));
  CHECK (0 == memcmp (&id2, &rid2, sizeof (GNUNET_HashCode)));

  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &fid);
  GNUNET_log_skip (1, GNUNET_NO);
  CHECK (0 == GNUNET_PSEUDONYM_rank (cfg, &fid, 0));
  GNUNET_log_skip (0, GNUNET_YES);
  noname = GNUNET_PSEUDONYM_id_to_name (cfg, &fid);
  CHECK (noname != NULL);
  CHECK (0 == GNUNET_PSEUDONYM_rank (cfg, &id1, 0));
  CHECK (5 == GNUNET_PSEUDONYM_rank (cfg, &id1, 5));
  CHECK (-5 == GNUNET_PSEUDONYM_rank (cfg, &id1, -10));
  CHECK (0 == GNUNET_PSEUDONYM_rank (cfg, &id1, 5));
  GNUNET_free (name1);
  GNUNET_free (name2);
  GNUNET_free (name3);
  GNUNET_free (noname);
  /* END OF TEST CODE */
FAILURE:
  GNUNET_PSEUDONYM_discovery_callback_unregister (&noti_callback, &notiCount);
  GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_break (GNUNET_OK ==
                GNUNET_DISK_directory_remove ("/tmp/gnunet-pseudonym-test"));
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of test_pseudoynm.c */
