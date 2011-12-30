/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_fs_uri.c
 * @brief Test for fs_uri.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "fs_api.h"

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); return 1; }

static int
testKeyword ()
{
  char *uri;
  struct GNUNET_FS_Uri *ret;
  char *emsg;

  if (NULL != (ret = GNUNET_FS_uri_parse ("gnunet://fs/ksk/++", &emsg)))
  {
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }
  GNUNET_free (emsg);
  ret = GNUNET_FS_uri_parse ("gnunet://fs/ksk/foo+bar", &emsg);
  if (ret == NULL)
  {
    GNUNET_free (emsg);
    ABORT ();
  }
  if (!GNUNET_FS_uri_test_ksk (ret))
  {
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }
  if ((2 != ret->data.ksk.keywordCount) ||
      (0 != strcmp (" foo", ret->data.ksk.keywords[0])) ||
      (0 != strcmp (" bar", ret->data.ksk.keywords[1])))
  {
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }

  uri = GNUNET_FS_uri_to_string (ret);
  if (0 != strcmp (uri, "gnunet://fs/ksk/foo+bar"))
  {
    GNUNET_free (uri);
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }
  GNUNET_free (uri);
  GNUNET_FS_uri_destroy (ret);
  return 0;
}

static int
testLocation ()
{
  struct GNUNET_FS_Uri *uri;
  char *uric;
  struct GNUNET_FS_Uri *uri2;
  struct GNUNET_FS_Uri *baseURI;
  char *emsg;
  struct GNUNET_CONFIGURATION_Handle *cfg;

  baseURI =
      GNUNET_FS_uri_parse
      ("gnunet://fs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.42",
       &emsg);
  GNUNET_assert (baseURI != NULL);
  GNUNET_assert (emsg == NULL);
  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK != GNUNET_CONFIGURATION_load (cfg, "test_fs_uri_data.conf"))
  {
    FPRINTF (stderr, "%s",  "Failed to parse configuration file\n");
    GNUNET_FS_uri_destroy (baseURI);
    GNUNET_CONFIGURATION_destroy (cfg);
    return 1;
  }
  uri = GNUNET_FS_uri_loc_create (baseURI, cfg, GNUNET_TIME_absolute_get ());
  if (uri == NULL)
  {
    GNUNET_break (0);
    GNUNET_FS_uri_destroy (baseURI);
    GNUNET_CONFIGURATION_destroy (cfg);
    return 1;
  }
  if (!GNUNET_FS_uri_test_loc (uri))
  {
    GNUNET_break (0);
    GNUNET_FS_uri_destroy (uri);
    GNUNET_FS_uri_destroy (baseURI);
    GNUNET_CONFIGURATION_destroy (cfg);
    return 1;
  }
  uri2 = GNUNET_FS_uri_loc_get_uri (uri);
  if (!GNUNET_FS_uri_test_equal (baseURI, uri2))
  {
    GNUNET_break (0);
    GNUNET_FS_uri_destroy (uri);
    GNUNET_FS_uri_destroy (uri2);
    GNUNET_FS_uri_destroy (baseURI);
    GNUNET_CONFIGURATION_destroy (cfg);
    return 1;
  }
  GNUNET_FS_uri_destroy (uri2);
  GNUNET_FS_uri_destroy (baseURI);
  uric = GNUNET_FS_uri_to_string (uri);
#if 0
  /* not for the faint of heart: */
  printf ("URI: `%s'\n", uric);
#endif
  uri2 = GNUNET_FS_uri_parse (uric, &emsg);
  GNUNET_free (uric);
  if (uri2 == NULL)
  {
    GNUNET_break (0);
    GNUNET_FS_uri_destroy (uri);
    GNUNET_CONFIGURATION_destroy (cfg);
    GNUNET_free (emsg);
    return 1;
  }
  GNUNET_assert (NULL == emsg);
  if (GNUNET_YES != GNUNET_FS_uri_test_equal (uri, uri2))
  {
    GNUNET_break (0);
    GNUNET_FS_uri_destroy (uri);
    GNUNET_FS_uri_destroy (uri2);
    GNUNET_CONFIGURATION_destroy (cfg);
    return 1;
  }
  GNUNET_FS_uri_destroy (uri2);
  GNUNET_FS_uri_destroy (uri);
  GNUNET_CONFIGURATION_destroy (cfg);
  return 0;
}

static int
testNamespace (int i)
{
  char *uri;
  struct GNUNET_FS_Uri *ret;
  char *emsg;

  if (NULL !=
      (ret =
       GNUNET_FS_uri_parse ("gnunet://fs/sks/D1KJS9H2A82Q65VKQ0ML3RFU6U1D3VUK",
                            &emsg)))
  {
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }
  GNUNET_free (emsg);
  if (NULL !=
      (ret =
       GNUNET_FS_uri_parse
       ("gnunet://fs/sks/D1KJS9H2A82Q65VKQ0ML3RFU6U1D3V/test", &emsg)))
  {
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }
  GNUNET_free (emsg);
  if (NULL != (ret = GNUNET_FS_uri_parse ("gnunet://fs/sks/test", &emsg)))
  {
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }
  GNUNET_free (emsg);
  ret =
      GNUNET_FS_uri_parse
      ("gnunet://fs/sks/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820/test",
       &emsg);
  if (ret == NULL)
  {
    GNUNET_free (emsg);
    ABORT ();
  }
  if (GNUNET_FS_uri_test_ksk (ret))
  {
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }
  if (!GNUNET_FS_uri_test_sks (ret))
  {
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }

  uri = GNUNET_FS_uri_to_string (ret);
  if (0 !=
      strcmp (uri,
              "gnunet://fs/sks/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820/test"))
  {
    GNUNET_FS_uri_destroy (ret);
    GNUNET_free (uri);
    ABORT ();
  }
  GNUNET_free (uri);
  GNUNET_FS_uri_destroy (ret);
  return 0;
}

static int
testFile (int i)
{
  char *uri;
  struct GNUNET_FS_Uri *ret;
  char *emsg;

  if (NULL !=
      (ret =
       GNUNET_FS_uri_parse
       ("gnunet://fs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H00000440000.42",
        &emsg)))
  {
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }
  GNUNET_free (emsg);
  if (NULL !=
      (ret =
       GNUNET_FS_uri_parse
       ("gnunet://fs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000",
        &emsg)))
  {
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }
  GNUNET_free (emsg);
  if (NULL !=
      (ret =
       GNUNET_FS_uri_parse
       ("gnunet://fs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.FGH",
        &emsg)))
  {
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }
  GNUNET_free (emsg);
  ret =
      GNUNET_FS_uri_parse
      ("gnunet://fs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.42",
       &emsg);
  if (ret == NULL)
  {
    GNUNET_free (emsg);
    ABORT ();
  }
  if (GNUNET_FS_uri_test_ksk (ret))
  {
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }
  if (GNUNET_FS_uri_test_sks (ret))
  {
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }
  if (GNUNET_ntohll (ret->data.chk.file_length) != 42)
  {
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }

  uri = GNUNET_FS_uri_to_string (ret);
  if (0 !=
      strcmp (uri,
              "gnunet://fs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.42"))
  {
    GNUNET_free (uri);
    GNUNET_FS_uri_destroy (ret);
    ABORT ();
  }
  GNUNET_free (uri);
  GNUNET_FS_uri_destroy (ret);
  return 0;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;
  int i;

  GNUNET_log_setup ("test_fs_uri",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  GNUNET_CRYPTO_random_disable_entropy_gathering ();
  failureCount += testKeyword ();
  failureCount += testLocation ();
  for (i = 0; i < 255; i++)
  {
    /* FPRINTF (stderr, "%s",  "."); */
    failureCount += testNamespace (i);
    failureCount += testFile (i);
  }
  /* FPRINTF (stderr, "%s",  "\n"); */
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-fs-uri");
  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of test_fs_uri.c */
