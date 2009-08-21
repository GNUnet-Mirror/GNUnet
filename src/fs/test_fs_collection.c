/*
     This file is part of GNUnet.
     (C) 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_fs_collection.c
 * @brief testcase for fs_collection.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_break(0); goto FAILURE; }

int
main (int argc, char *argv[])
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  int ok;
  struct GNUNET_ClientServerConnection *sock;
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_CONTAINER_MetaData *have;
  char *emsg;
  struct GNUNET_FS_Uri *uri;
  struct GNUNET_CONTAINER_MetaData *md;
  struct GNUNET_FS_Handle *fsh;

  GNUNET_CRYPTO_random_disable_entropy_gathering ();
  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_parse (cfg, "check.conf"))
    {
      GNUNET_CONFIGURATION_destroy (cfg);
      return -1;
    }
  sock = NULL;
  meta = NULL;
  ok = GNUNET_YES;
  meta = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_CONTAINER_meta_data_insert (meta, EXTRACTOR_MIMETYPE, "test/foo");


  fsh = GNUNET_FS_start (sched,
			 cfg,
			 "test-fs-collection",
			 &progress_cb,
			 NULL);

  /* ACTUAL TEST CODE */
  GNUNET_FS_collection_stop (fsh);
  CHECK (NULL == GNUNET_FS_collection_get (fsh));
  CHECK (GNUNET_OK == GNUNET_FS_collection_start (fsh, 
						  namespace));
  have = GNUNET_FS_collection_get (fsh);
  CHECK (NULL != have);
  CHECK (GNUNET_CONTAINER_meta_data_test_equal (have, meta));
  GNUNET_CONTAINER_meta_data_destroy (have);
  md = meta;
  uri =
    GNUNET_FS_uri_parse ("gnunet://ecrs/chk/0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000.0", &emsg);
  GNUNET_FS_collection_add (fsh, uri, md);
  GNUNET_FS_uri_destroy (uri);
  GNUNET_FS_stop (fsh);
  fsh = GNUNET_FS_start (sched, cfg,
			 "test-fs-collection",
			 &progress_cb,
			 NULL);
  have = GNUNET_FS_collection_get (fsh);
  CHECK (NULL != have);
  CHECK (GNUNET_CONTAINER_meta_data_test_equal (have, meta));
  GNUNET_CONTAINER_meta_data_destroy (have);
  GNUNET_FS_collection_publish (fsh);
  GNUNET_FS_collection_stop (fsh);
  CHECK (NULL == GNUNET_FS_collection_get (fsh));
  GNUNET_FS_stop (fsh);

  /* END OF TEST CODE */
FAILURE:
  if (meta != NULL)
    GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_CONFIGURATION_destroy (cfg);
  
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of test_fs_collection.c */
