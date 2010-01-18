/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2006, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file util/test_container_meta_data.c
 * @brief Test for container_meta_data.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_container_lib.h"

#define ABORT(m) { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); if (m != NULL) GNUNET_CONTAINER_meta_data_destroy(m); return 1; }

static int
testMeta (int i)
{
  struct GNUNET_CONTAINER_MetaData *m;
  char val[256];
  char *sval;
  int j;
  unsigned int size;

  m = GNUNET_CONTAINER_meta_data_create ();
  if (GNUNET_OK !=
      GNUNET_CONTAINER_meta_data_insert (m,
					 "<test>",
					 EXTRACTOR_METATYPE_TITLE, 
					 EXTRACTOR_METAFORMAT_UTF8,
					 "text/plain",
					 "TestTitle",
					 strlen("TestTitle")+1))
    ABORT (m);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_meta_data_insert (m, 
					 "<test>",
					 EXTRACTOR_METATYPE_AUTHOR_NAME, 
					 EXTRACTOR_METAFORMAT_UTF8,
					 "text/plain",
					 "TestTitle",
					 strlen ("TestTitle")+1))
    ABORT (m);
  if (GNUNET_OK == GNUNET_CONTAINER_meta_data_insert (m, 
						      "<test>",
						      EXTRACTOR_METATYPE_TITLE, 
						      EXTRACTOR_METAFORMAT_UTF8,
						      "text/plain",
						      "TestTitle",
						      strlen ("TestTitle")+1)) /* dup! */
    ABORT (m);
  if (GNUNET_OK == GNUNET_CONTAINER_meta_data_insert (m,
						      "<test>",
						      EXTRACTOR_METATYPE_AUTHOR_NAME,
						      EXTRACTOR_METAFORMAT_UTF8,
						      "text/plain",
						      "TestTitle",
						      strlen ("TestTitle")+1))        /* dup! */
    ABORT (m);
  if (2 != GNUNET_CONTAINER_meta_data_iterate (m, NULL, NULL))
    ABORT (m);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_meta_data_delete (m,
					 EXTRACTOR_METATYPE_AUTHOR_NAME,
					 "TestTitle",
					 strlen("TestTitle")+1))
    ABORT (m);
  if (GNUNET_OK == GNUNET_CONTAINER_meta_data_delete (m,
						      EXTRACTOR_METATYPE_AUTHOR_NAME, 
						      "TestTitle",
						      strlen ("TestTitle")+1))        /* already gone */
    ABORT (m);
  if (1 != GNUNET_CONTAINER_meta_data_iterate (m, NULL, NULL))
    ABORT (m);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_meta_data_delete (m, 
					 EXTRACTOR_METATYPE_TITLE,
					 "TestTitle",
					 strlen ("TestTitle")+1))
    ABORT (m);
  if (GNUNET_OK == GNUNET_CONTAINER_meta_data_delete (m, 
						      EXTRACTOR_METATYPE_TITLE, 
						      "TestTitle",
						      strlen ("TestTitle")+1)) /* already gone */
    ABORT (m);
  if (0 != GNUNET_CONTAINER_meta_data_iterate (m, NULL, NULL))
    ABORT (m);
  for (j = 0; j < i; j++)
    {
      GNUNET_snprintf (val, 
		       sizeof(val),
		       "%s.%d",
                       "A teststring that should compress well.", j);
      if (GNUNET_OK !=
          GNUNET_CONTAINER_meta_data_insert (m,
					     "<test>",
					     EXTRACTOR_METATYPE_UNKNOWN, 
					     EXTRACTOR_METAFORMAT_UTF8,
					     "text/plain",
					     val,
					     strlen(val)+1))
	ABORT (m);        
    }
  if (i != GNUNET_CONTAINER_meta_data_iterate (m, NULL, NULL))
    ABORT (m);

  size =
    GNUNET_CONTAINER_meta_data_get_serialized_size (m);
  sval = NULL;
  if (size != GNUNET_CONTAINER_meta_data_serialize (m,
						    &sval, size,
                                                    GNUNET_CONTAINER_META_DATA_SERIALIZE_FULL))
    {
      GNUNET_free_non_null (sval);
      ABORT (m);
    }
  GNUNET_CONTAINER_meta_data_destroy (m);
  m = GNUNET_CONTAINER_meta_data_deserialize (sval, size);
  GNUNET_free (sval);
  if (m == NULL)
    ABORT (m);
  for (j = 0; j < i; j++)
    {
      GNUNET_snprintf (val, 
		       sizeof(val), "%s.%d",
                       "A teststring that should compress well.", j);
      if (GNUNET_OK !=
          GNUNET_CONTAINER_meta_data_delete (m,
					     EXTRACTOR_METATYPE_UNKNOWN, 
					     val,
					     strlen(val)+1))
        {
          ABORT (m);
        }
    }
  if (0 != GNUNET_CONTAINER_meta_data_iterate (m, NULL, NULL))
    ABORT (m);    
  GNUNET_CONTAINER_meta_data_destroy (m);
  return 0;
}

int
testMetaMore (int i)
{
  struct GNUNET_CONTAINER_MetaData *meta;
  int q;
  char txt[128];
  char *data;
  unsigned long long size;

  meta = GNUNET_CONTAINER_meta_data_create ();
  for (q = 0; q <= i; q++)
    {
      GNUNET_snprintf (txt, 128, "%u -- %u\n", i, q);
      GNUNET_CONTAINER_meta_data_insert (meta,
					 "<test>",
                                         q % EXTRACTOR_metatype_get_max(), 
					 EXTRACTOR_METAFORMAT_UTF8,
					 "text/plain",
					 txt,
					 strlen (txt)+1);
    }
  size =
    GNUNET_CONTAINER_meta_data_get_serialized_size (meta);
  data = GNUNET_malloc (size * 4);
  if (size != GNUNET_CONTAINER_meta_data_serialize (meta,
                                                    &data, size * 4,
                                                    GNUNET_CONTAINER_META_DATA_SERIALIZE_FULL))
    {
      GNUNET_free (data);
      ABORT (meta);
    }
  GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_free (data);
  return 0;
}

static int
testMetaLink ()
{
  struct GNUNET_CONTAINER_MetaData *m;
  char *val;
  unsigned int size;

  m = GNUNET_CONTAINER_meta_data_create ();
  if (GNUNET_OK !=
      GNUNET_CONTAINER_meta_data_insert (m, 
					 "<test>",
					 EXTRACTOR_METATYPE_UNKNOWN, 
					 EXTRACTOR_METAFORMAT_UTF8,
					 "text/plain",
					 "link",
					 strlen("link")+1))
    ABORT (m);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_meta_data_insert (m,
					 "<test>",
					 EXTRACTOR_METATYPE_FILENAME,
					 EXTRACTOR_METAFORMAT_UTF8,
					 "text/plain",
                                         "lib-link.m4",
					 strlen ("lib-link.m4")+1))
    ABORT (m);
  val = NULL;
  size = GNUNET_CONTAINER_meta_data_serialize (m, &val, (size_t) -1,
					       GNUNET_CONTAINER_META_DATA_SERIALIZE_FULL);
  GNUNET_CONTAINER_meta_data_destroy (m);
  m = GNUNET_CONTAINER_meta_data_deserialize (val, size);
  GNUNET_free (val);
  if (m == NULL)
    ABORT (m);
  GNUNET_CONTAINER_meta_data_destroy (m);
  return 0;
}


static int
testThumbnail ()
{
  struct GNUNET_CONTAINER_MetaData *m;
  struct GNUNET_CONTAINER_MetaData *d;
  struct EXTRACTOR_PluginList *ex;
  unsigned char *thumb;
  size_t size;
  char *date;

  ex = EXTRACTOR_plugin_add_config (NULL, "thumbnailgtk", EXTRACTOR_OPTION_DEFAULT_POLICY);
  if (ex == NULL)
    {
      fprintf (stderr,
               "Test incomplete, have no GTK thumbnail extractor available.\n");
      return 0;                 /* can not test, no thumbnailer */
    }
  ex = EXTRACTOR_plugin_add_config (ex, "mime", EXTRACTOR_OPTION_DEFAULT_POLICY);
  m = GNUNET_CONTAINER_meta_data_create ();
  if (3 != GNUNET_CONTAINER_meta_data_extract_from_file (m,
                                                         "test_container_meta_data_image.jpg",
                                                         ex))
    {
      GNUNET_break (0);
      EXTRACTOR_plugin_remove_all (ex);
      GNUNET_CONTAINER_meta_data_destroy (m);
      return 1;
    }
  EXTRACTOR_plugin_remove_all (ex);
  d = GNUNET_CONTAINER_meta_data_duplicate (m);
  GNUNET_CONTAINER_meta_data_destroy (m);
  thumb = NULL;
  size = GNUNET_CONTAINER_meta_data_get_thumbnail (d, &thumb);
  if (size == 0)
    {
      GNUNET_break (0);
      GNUNET_CONTAINER_meta_data_destroy (d);
      return 1;
    }
  GNUNET_free (thumb);
  GNUNET_CONTAINER_meta_data_add_publication_date (d);
  date = GNUNET_CONTAINER_meta_data_get_by_type (d,
                                                 EXTRACTOR_METATYPE_PUBLICATION_DATE);
  if (date == NULL)
    {
      GNUNET_break (0);
      GNUNET_CONTAINER_meta_data_destroy (d);
      return 1;
    }
  GNUNET_free (date);
  GNUNET_CONTAINER_meta_data_destroy (d);
  return 0;
}


int
main (int argc, char *argv[])
{
  int failureCount = 0;
  int i;

  GNUNET_log_setup ("test-container-meta-data", "WARNING", NULL);
  for (i = 0; i < 255; i++)
    failureCount += testMeta (i);
  for (i = 1; i < 255; i++)
    failureCount += testMetaMore (i);
  failureCount += testMetaLink ();
  failureCount += testThumbnail ();

  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of test_container_meta_data.c */
