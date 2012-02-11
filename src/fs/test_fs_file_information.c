/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_fs_file_information.c
 * @brief simple testcase for file_information operations
 * @author Christian Grothoff
 *
 * TODO:
 * - test that metatdata, etc. are all correct (for example,
 *   there is a known bug with dirname never being set that is
 *   not detected!)
 * - need to iterate over file-information structure
 * - other API functions may not yet be tested (such as
 *   filedata-from-callback)
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"

#define VERBOSE GNUNET_NO

/**
 * File-size we use for testing.
 */
#define FILESIZE (1024 * 1024 * 2)

/**
 * How long should our test-content live?
 */
#define LIFETIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)


static int
mycleaner (void *cls, struct GNUNET_FS_FileInformation *fi, uint64_t length,
           struct GNUNET_CONTAINER_MetaData *meta, struct GNUNET_FS_Uri **uri,
           struct GNUNET_FS_BlockOptions *bo, int *do_index, void **client_info)
{
  return GNUNET_OK;
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  const char *keywords[] = {
    "down_foo",
    "down_bar",
  };
  char *fn1;
  char *fn2;
  char *buf;
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_FS_Uri *kuri;
  struct GNUNET_FS_FileInformation *fi1;
  struct GNUNET_FS_FileInformation *fi2;
  struct GNUNET_FS_FileInformation *fidir;
  struct GNUNET_FS_Handle *fs;
  size_t i;
  struct GNUNET_FS_BlockOptions bo;

  fs = GNUNET_FS_start (cfg, "test-fs-file-information", NULL, NULL,
                        GNUNET_FS_FLAGS_NONE, GNUNET_FS_OPTIONS_END);
  fn1 = GNUNET_DISK_mktemp ("gnunet-file_information-test-dst");
  buf = GNUNET_malloc (FILESIZE);
  for (i = 0; i < FILESIZE; i++)
    buf[i] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 256);
  GNUNET_assert (FILESIZE ==
                 GNUNET_DISK_fn_write (fn1, buf, FILESIZE,
                                       GNUNET_DISK_PERM_USER_READ |
                                       GNUNET_DISK_PERM_USER_WRITE));
  GNUNET_free (buf);

  fn2 = GNUNET_DISK_mktemp ("gnunet-file_information-test-dst");
  buf = GNUNET_malloc (FILESIZE);
  for (i = 0; i < FILESIZE; i++)
    buf[i] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 256);
  GNUNET_assert (FILESIZE ==
                 GNUNET_DISK_fn_write (fn2, buf, FILESIZE,
                                       GNUNET_DISK_PERM_USER_READ |
                                       GNUNET_DISK_PERM_USER_WRITE));
  GNUNET_free (buf);

  meta = GNUNET_CONTAINER_meta_data_create ();
  kuri = GNUNET_FS_uri_ksk_create_from_args (2, keywords);
  bo.content_priority = 42;
  bo.anonymity_level = 1;
  bo.replication_level = 0;
  bo.expiration_time = GNUNET_TIME_relative_to_absolute (LIFETIME);
  fi1 =
      GNUNET_FS_file_information_create_from_file (fs,
                                                   "file_information-context1",
                                                   fn1, kuri, meta, GNUNET_YES,
                                                   &bo);
  GNUNET_assert (fi1 != NULL);
  fi2 =
      GNUNET_FS_file_information_create_from_file (fs,
                                                   "file_information-context2",
                                                   fn2, kuri, meta, GNUNET_YES,
                                                   &bo);
  GNUNET_assert (fi2 != NULL);
  fidir =
      GNUNET_FS_file_information_create_empty_directory (fs,
                                                         "file_information-context-dir",
                                                         kuri, meta, &bo, NULL);
  GNUNET_assert (GNUNET_OK == GNUNET_FS_file_information_add (fidir, fi1));
  GNUNET_assert (GNUNET_OK == GNUNET_FS_file_information_add (fidir, fi2));
  GNUNET_FS_uri_destroy (kuri);
  GNUNET_CONTAINER_meta_data_destroy (meta);
  GNUNET_assert (NULL != fidir);
  /* FIXME: test more of API! */
  GNUNET_FS_file_information_destroy (fidir, &mycleaner, NULL);
  GNUNET_DISK_directory_remove (fn1);
  GNUNET_DISK_directory_remove (fn2);
  GNUNET_free_non_null (fn1);
  GNUNET_free_non_null (fn2);
  GNUNET_FS_stop (fs);
}





int
main (int argc, char *argv[])
{
  char *const argvx[] = {
    "test-fs-file_information",
    "-c",
    "test_fs_file_information_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_log_setup ("test_fs_file_information",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  GNUNET_PROGRAM_run ((sizeof (argvx) / sizeof (char *)) - 1, argvx,
                      "test-fs-file_information", "nohelp", options, &run,
                      NULL);
  return 0;
}

/* end of test_fs_file_information.c */
