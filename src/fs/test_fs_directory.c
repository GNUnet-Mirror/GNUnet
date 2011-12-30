/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_fs_directory.c
 * @brief Test for fs_directory.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include <extractor.h>
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "fs_api.h"

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); return 1; }

struct PCLS
{
  struct GNUNET_FS_Uri **uri;
  struct GNUNET_CONTAINER_MetaData **md;
  unsigned int pos;
  unsigned int max;
};

static void
processor (void *cls, const char *filename, const struct GNUNET_FS_Uri *uri,
           const struct GNUNET_CONTAINER_MetaData *md, size_t length,
           const void *data)
{
  struct PCLS *p = cls;
  int i;

  if (NULL == uri)
    return;                     /* ignore directory's meta data */
  for (i = 0; i < p->max; i++)
  {
    if (GNUNET_CONTAINER_meta_data_test_equal (p->md[i], md) &&
        GNUNET_FS_uri_test_equal (p->uri[i], uri))
    {
      p->pos++;
      return;
    }
  }
  FPRINTF (stderr, "Error at %s:%d\n", __FILE__, __LINE__);
}

static int
testDirectory (unsigned int i)
{
  struct GNUNET_FS_DirectoryBuilder *db;
  char *data;
  size_t dlen;
  struct GNUNET_FS_Uri **uris;
  struct GNUNET_CONTAINER_MetaData **mds;
  struct GNUNET_CONTAINER_MetaData *meta;
  struct PCLS cls;
  char *emsg;
  int p;
  int q;
  char uri[512];
  char txt[128];
  int ret = 0;
  struct GNUNET_TIME_Absolute start;
  char *s;

  cls.max = i;
  uris = GNUNET_malloc (sizeof (struct GNUNET_FS_Uri *) * i);
  mds = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_MetaData *) * i);
  meta = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_CONTAINER_meta_data_insert (meta, "<test>", EXTRACTOR_METATYPE_TITLE,
                                     EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                     "A title", strlen ("A title") + 1);
  GNUNET_CONTAINER_meta_data_insert (meta, "<test>",
                                     EXTRACTOR_METATYPE_AUTHOR_NAME,
                                     EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                     "An author", strlen ("An author") + 1);
  for (p = 0; p < i; p++)
  {
    mds[p] = GNUNET_CONTAINER_meta_data_create ();
    for (q = 0; q <= p; q++)
    {
      GNUNET_snprintf (txt, sizeof (txt), "%u -- %u\n", p, q);
      GNUNET_CONTAINER_meta_data_insert (mds[p], "<test>",
                                         q % EXTRACTOR_metatype_get_max (),
                                         EXTRACTOR_METAFORMAT_UTF8,
                                         "text/plain", txt, strlen (txt) + 1);
    }
    GNUNET_snprintf (uri, sizeof (uri),
                     "gnunet://fs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.%u",
                     p);
    emsg = NULL;
    uris[p] = GNUNET_FS_uri_parse (uri, &emsg);
    if (uris[p] == NULL)
    {
      GNUNET_CONTAINER_meta_data_destroy (mds[p]);
      while (--p > 0)
      {
        GNUNET_CONTAINER_meta_data_destroy (mds[p]);
        GNUNET_FS_uri_destroy (uris[p]);
      }
      GNUNET_free (mds);
      GNUNET_free (uris);
      GNUNET_free (emsg);
      GNUNET_CONTAINER_meta_data_destroy (meta);
      ABORT ();                 /* error in testcase */
    }
    GNUNET_assert (emsg == NULL);
  }
  start = GNUNET_TIME_absolute_get ();
  db = GNUNET_FS_directory_builder_create (meta);
  for (p = 0; p < i; p++)
    GNUNET_FS_directory_builder_add (db, uris[p], mds[p], NULL);
  GNUNET_FS_directory_builder_finish (db, &dlen, (void **) &data);
  s = GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration
                                              (start));
  FPRINTF (stdout,
           "Creating directory with %u entires and total size %llu took %s\n",
           i, (unsigned long long) dlen, s);
  GNUNET_free (s);
  if (i < 100)
  {
    cls.pos = 0;
    cls.uri = uris;
    cls.md = mds;
    GNUNET_FS_directory_list_contents (dlen, data, 0, &processor, &cls);
    GNUNET_assert (cls.pos == i);
  }
  GNUNET_free (data);
  GNUNET_CONTAINER_meta_data_destroy (meta);
  for (p = 0; p < i; p++)
  {
    GNUNET_CONTAINER_meta_data_destroy (mds[p]);
    GNUNET_FS_uri_destroy (uris[p]);
  }
  GNUNET_free (uris);
  GNUNET_free (mds);
  return ret;
}


int
main (int argc, char *argv[])
{
  int failureCount = 0;
  int i;

  GNUNET_log_setup ("test_fs_directory",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  for (i = 17; i < 1000; i *= 2)
    failureCount += testDirectory (i);
  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of test_fs_directory.c */
