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

static struct GNUNET_CONFIGURATION_Handle *cfg;

static void* progress_cb (void *cls,
			  const struct GNUNET_FS_ProgressInfo *info)
{
  GNUNET_break (0);
  return NULL;
}


static void
task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_Namespace *have;
  struct GNUNET_FS_Namespace *ns;
  char *emsg;
  struct GNUNET_FS_Uri *uri;
  struct GNUNET_FS_Handle *fsh;
  struct GNUNET_CONTAINER_MetaData *md;

  fsh = GNUNET_FS_start (tc->sched,
			 cfg,
			 "test-fs-collection",
			 &progress_cb,
			 NULL);
  GNUNET_assert (NULL != fsh);
  GNUNET_FS_collection_stop (fsh);
  GNUNET_assert (NULL == GNUNET_FS_collection_get (fsh));
  ns = GNUNET_FS_namespace_create (fsh, "test-namespace");
  GNUNET_assert (NULL != ns);
  GNUNET_assert (GNUNET_OK == GNUNET_FS_collection_start (fsh, 
							  ns));
  GNUNET_FS_namespace_delete (ns, GNUNET_NO);
  have = GNUNET_FS_collection_get (fsh);
  GNUNET_assert (NULL != have);
  GNUNET_FS_namespace_delete (have, GNUNET_NO);
  uri =
    GNUNET_FS_uri_parse ("gnunet://fs/chk/0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000.0", &emsg);
  GNUNET_assert (NULL != uri);
  md = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_FS_collection_add (fsh, uri, md);
  GNUNET_CONTAINER_meta_data_destroy (md);
  GNUNET_FS_uri_destroy (uri);
  GNUNET_FS_stop (fsh);
  fsh = GNUNET_FS_start (tc->sched,
			 cfg,
			 "test-fs-collection",
			 &progress_cb,
			 NULL);
  have = GNUNET_FS_collection_get (fsh);
  GNUNET_assert (NULL != have);
  GNUNET_FS_namespace_delete (have, GNUNET_NO);
  GNUNET_FS_collection_publish (fsh);
  GNUNET_FS_collection_stop (fsh);
  GNUNET_assert (NULL == GNUNET_FS_collection_get (fsh));
  GNUNET_FS_stop (fsh);
}


int
main (int argc, char *argv[])
{
  int ok;

  GNUNET_log_setup ("test_fs_collection", 
#if VERBOSE
		    "DEBUG",
#else
		    "WARNING",
#endif
		    NULL);
  GNUNET_CRYPTO_random_disable_entropy_gathering ();
  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_parse (cfg, "test_fs_collection_data.conf"))
    {
      GNUNET_CONFIGURATION_destroy (cfg);
      return -1;
    }
  ok = GNUNET_YES;
  GNUNET_SCHEDULER_run (&task, &ok);
  GNUNET_CONFIGURATION_destroy (cfg);
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of test_fs_collection.c */
