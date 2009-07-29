/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2006, 2007 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file applications/fs/ecrs/uritest.c
 * @brief Test for uri.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "ecrs.h"

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); return 1; }

static int
testKeyword ()
{
  char *uri;
  struct GNUNET_ECRS_URI *ret;

  if (NULL != GNUNET_ECRS_string_to_uri (NULL, "gnunet://ecrs/ksk/++"))
    ABORT ();
  ret = GNUNET_ECRS_string_to_uri (NULL, "gnunet://ecrs/ksk/foo+bar");
  if (ret == NULL)
    ABORT ();
  if (!GNUNET_ECRS_uri_test_ksk (ret))
    {
      GNUNET_ECRS_uri_destroy (ret);
      ABORT ();
    }
  if ((2 != ret->data.ksk.keywordCount) ||
      (0 != strcmp (" foo", ret->data.ksk.keywords[0])) ||
      (0 != strcmp (" bar", ret->data.ksk.keywords[1])))
    {
      GNUNET_ECRS_uri_destroy (ret);
      ABORT ();
    }

  uri = GNUNET_ECRS_uri_to_string (ret);
  if (0 != strcmp (uri, "gnunet://ecrs/ksk/foo+bar"))
    {
      GNUNET_free (uri);
      GNUNET_ECRS_uri_destroy (ret);
      ABORT ();
    }
  GNUNET_free (uri);
  GNUNET_ECRS_uri_destroy (ret);
  return 0;
}

static int
testLocation ()
{
  struct GNUNET_ECRS_URI *uri;
  char *uric;
  struct GNUNET_ECRS_URI *uri2;
  GNUNET_RSA_PublicKey pk;
  struct GNUNET_RSA_PrivateKey *hk;
  struct GNUNET_ECRS_URI *baseURI;

  baseURI =
    GNUNET_ECRS_string_to_uri (NULL,
                               "gnunet://ecrs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.42");
  hk = GNUNET_RSA_create_key ();
  GNUNET_RSA_get_public_key (hk, &pk);
  uri = GNUNET_ECRS_location_to_uri (baseURI,
                                     &pk, 43,
                                     (GNUNET_ECRS_SignFunction) &
                                     GNUNET_RSA_sign, hk);
  GNUNET_RSA_free_key (hk);
  if (uri == NULL)
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_ECRS_uri_destroy (baseURI);
      return 1;
    }
  if (!GNUNET_ECRS_uri_test_loc (uri))
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_ECRS_uri_destroy (uri);
      GNUNET_ECRS_uri_destroy (baseURI);
      return 1;
    }
  uri2 = GNUNET_ECRS_uri_get_content_uri_from_loc (uri);
  if (!GNUNET_ECRS_uri_test_equal (baseURI, uri2))
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_ECRS_uri_destroy (uri);
      GNUNET_ECRS_uri_destroy (uri2);
      GNUNET_ECRS_uri_destroy (baseURI);
      return 1;
    }
  GNUNET_ECRS_uri_destroy (uri2);
  GNUNET_ECRS_uri_destroy (baseURI);
  uric = GNUNET_ECRS_uri_to_string (uri);
#if 0
  /* not for the faint of heart: */
  printf ("URI: `%s'\n", uric);
#endif
  uri2 = GNUNET_ECRS_string_to_uri (NULL, uric);
  GNUNET_free (uric);
  if (uri2 == NULL)
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_ECRS_uri_destroy (uri);
      return 1;
    }
  if (GNUNET_YES != GNUNET_ECRS_uri_test_equal (uri, uri2))
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_ECRS_uri_destroy (uri);
      GNUNET_ECRS_uri_destroy (uri2);
      return 1;
    }
  GNUNET_ECRS_uri_destroy (uri2);
  GNUNET_ECRS_uri_destroy (uri);
  return 0;
}

static int
testNamespace (int i)
{
  char *uri;
  struct GNUNET_ECRS_URI *ret;

  if (NULL !=
      GNUNET_ECRS_string_to_uri (NULL,
                                 "gnunet://ecrs/sks/D1KJS9H2A82Q65VKQ0ML3RFU6U1D3VUK"))
    ABORT ();
  if (NULL !=
      GNUNET_ECRS_string_to_uri (NULL,
                                 "gnunet://ecrs/sks/D1KJS9H2A82Q65VKQ0ML3RFU6U1D3V/test"))
    ABORT ();
  if (NULL != GNUNET_ECRS_string_to_uri (NULL, "gnunet://ecrs/sks/test"))
    ABORT ();
  ret =
    GNUNET_ECRS_string_to_uri (NULL,
                               "gnunet://ecrs/sks/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820/test");
  if (ret == NULL)
    ABORT ();
  if (GNUNET_ECRS_uri_test_ksk (ret))
    {
      GNUNET_ECRS_uri_destroy (ret);
      ABORT ();
    }
  if (!GNUNET_ECRS_uri_test_sks (ret))
    {
      GNUNET_ECRS_uri_destroy (ret);
      ABORT ();
    }

  uri = GNUNET_ECRS_uri_to_string (ret);
  if (0 != strcmp (uri,
                   "gnunet://ecrs/sks/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820/test"))
    {
      GNUNET_ECRS_uri_destroy (ret);
      GNUNET_free (uri);
      ABORT ();
    }
  GNUNET_free (uri);
  GNUNET_ECRS_uri_destroy (ret);
  return 0;
}

static int
testFile (int i)
{
  char *uri;
  struct GNUNET_ECRS_URI *ret;

  if (NULL !=
      GNUNET_ECRS_string_to_uri (NULL,
                                 "gnunet://ecrs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H00000440000.42"))
    ABORT ();
  if (NULL !=
      GNUNET_ECRS_string_to_uri (NULL,
                                 "gnunet://ecrs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000"))
    ABORT ();
  if (NULL !=
      GNUNET_ECRS_string_to_uri (NULL,
                                 "gnunet://ecrs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.FGH"))
    ABORT ();
  ret =
    GNUNET_ECRS_string_to_uri (NULL,
                               "gnunet://ecrs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.42");
  if (ret == NULL)
    ABORT ();
  if (GNUNET_ECRS_uri_test_ksk (ret))
    {
      GNUNET_ECRS_uri_destroy (ret);
      ABORT ();
    }
  if (GNUNET_ECRS_uri_test_sks (ret))
    {
      GNUNET_ECRS_uri_destroy (ret);
      ABORT ();
    }
  if (GNUNET_ntohll (ret->data.fi.file_length) != 42)
    {
      GNUNET_ECRS_uri_destroy (ret);
      ABORT ();
    }

  uri = GNUNET_ECRS_uri_to_string (ret);
  if (0 != strcmp (uri,
                   "gnunet://ecrs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.42"))
    {
      GNUNET_free (uri);
      GNUNET_ECRS_uri_destroy (ret);
      ABORT ();
    }
  GNUNET_free (uri);
  GNUNET_ECRS_uri_destroy (ret);
  return 0;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;
  int i;

  GNUNET_disable_entropy_gathering ();
  failureCount += testKeyword ();
  failureCount += testLocation ();
  for (i = 0; i < 255; i++)
    {
      failureCount += testNamespace (i);
      failureCount += testFile (i);
    }
  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of uritest.c */
