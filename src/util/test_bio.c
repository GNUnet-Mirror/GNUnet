/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file util/test_bio.c
 * @brief testcase for the buffered IO module
 * @author Ji Lu
 */


#include "platform.h"
#include "gnunet_util_lib.h"
#define TESTSTRING "testString"
#define TESTNUMBER64 ((int64_t) 100000L)


static int
test_normal_rw (void)
{
  struct GNUNET_BIO_WriteHandle *wh;
  struct GNUNET_BIO_ReadHandle *rh;
  void *buffer;
  size_t buffer_size = 0;
  char *filename = GNUNET_DISK_mktemp ("gnunet-bio");
  struct GNUNET_CONTAINER_MetaData *mdW;
  struct GNUNET_CONTAINER_MetaData *mdR = NULL;
  char *rString = NULL;
  int64_t wNum = TESTNUMBER64;
  int64_t rNum = 0;

  mdW = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_CONTAINER_meta_data_add_publication_date (mdW);

  struct GNUNET_BIO_WriteSpec ws[] = {
    GNUNET_BIO_write_spec_string ("test-normal-rw-string", TESTSTRING),
    GNUNET_BIO_write_spec_meta_data ("test-normal-rw-metadata", mdW),
    GNUNET_BIO_write_spec_int64 ("test-normal-rw-int64", &wNum),
    GNUNET_BIO_write_spec_end(),
  };

  struct GNUNET_BIO_ReadSpec rs[] = {
    GNUNET_BIO_read_spec_string ("test-normal-rw-string", &rString, 200),
    GNUNET_BIO_read_spec_meta_data ("test-normal-rw-metadata", &mdR),
    GNUNET_BIO_read_spec_int64 ("test-normal-rw-int64", &rNum),
    GNUNET_BIO_read_spec_end(),
  };

  /* I/O on file */
  wh = GNUNET_BIO_write_open_file (filename);
  GNUNET_assert (NULL != wh);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_spec_commit (wh, ws));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (wh, NULL));

  rh = GNUNET_BIO_read_open_file (filename);
  GNUNET_assert (NULL != rh);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_read_spec_commit (rh, rs));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_read_close (rh, NULL));
  GNUNET_assert (0 == strcmp (TESTSTRING, rString));
  GNUNET_assert (GNUNET_YES == GNUNET_CONTAINER_meta_data_test_equal (mdR, mdW));
  GNUNET_assert (wNum == rNum);

  GNUNET_CONTAINER_meta_data_destroy (mdR);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (filename));
  GNUNET_free(filename);

  /* I/O on buffer */
  wh = GNUNET_BIO_write_open_buffer ();
  GNUNET_assert (NULL != wh);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_spec_commit (wh, ws));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_BIO_get_buffer_contents (wh,
                                                 NULL,
                                                 &buffer,
                                                 &buffer_size));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (wh, NULL));

  rh = GNUNET_BIO_read_open_buffer (buffer, buffer_size);
  GNUNET_assert (NULL != rh);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_read_spec_commit (rh, rs));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_read_close (rh, NULL));
  GNUNET_assert (0 == strcmp (TESTSTRING, rString));
  GNUNET_assert (GNUNET_YES == GNUNET_CONTAINER_meta_data_test_equal (mdR, mdW));
  GNUNET_assert (wNum == rNum);

  GNUNET_free (buffer);

  GNUNET_CONTAINER_meta_data_destroy (mdW);
  GNUNET_CONTAINER_meta_data_destroy (mdR);
  return 0;
}


static int
test_nullstring_rw (void)
{
  struct GNUNET_BIO_WriteHandle *wh;
  struct GNUNET_BIO_ReadHandle *rh;
  char *filename = GNUNET_DISK_mktemp ("gnunet_bio");
  char *rString = "not null";

  wh = GNUNET_BIO_write_open_file (filename);
  GNUNET_assert (NULL != wh);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_string (wh,
                                                       "test-nullstring-rw",
                                                       NULL));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (wh, NULL));

  rh = GNUNET_BIO_read_open_file (filename);
  GNUNET_assert (NULL != rh);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_read_string (rh,
                                                      "test-nullstring-rw",
                                                      &rString, 200));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_read_close (rh, NULL));

  GNUNET_assert (NULL == rString);

  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (filename));
  GNUNET_free (filename);
  return 0;
}


static int
test_emptystring_rw (void)
{
  struct GNUNET_BIO_WriteHandle *wh;
  struct GNUNET_BIO_ReadHandle *rh;
  char *filename = GNUNET_DISK_mktemp ("gnunet_bio");
  char *rString = NULL;

  wh = GNUNET_BIO_write_open_file (filename);
  GNUNET_assert (NULL != wh);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_string (wh,
                                                       "test-emptystring-rw",
                                                       ""));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (wh, NULL));

  rh = GNUNET_BIO_read_open_file (filename);
  GNUNET_assert (NULL != rh);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_read_string (rh,
                                                      "test-emptystring-rw",
                                                      &rString, 200));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_read_close (rh, NULL));

  GNUNET_free (rString);

  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (filename));
  GNUNET_free (filename);
  return 0;
}


static int
test_bigstring_rw (void)
{
  struct GNUNET_BIO_WriteHandle *wh;
  struct GNUNET_BIO_ReadHandle *rh;
  char *filename = GNUNET_DISK_mktemp ("gnunet_bio");
  char *rString = NULL;

  wh = GNUNET_BIO_write_open_file (filename);
  GNUNET_assert (NULL != wh);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_string (wh,
                                                       "test-bigstring-rw",
                                                       TESTSTRING));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (wh, NULL));

  rh = GNUNET_BIO_read_open_file (filename);
  GNUNET_assert (NULL != rh);
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_read_string (rh,
                                                          "test-bigstring-rw",
                                                          &rString, 1));
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_read_close (rh, NULL));

  GNUNET_assert (NULL == rString);

  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (filename));
  GNUNET_free (filename);
  return 0;
}


static int
test_bigmeta_rw (void)
{
  static char meta[1024 * 1024 * 10];
  struct GNUNET_BIO_WriteHandle *wh;
  struct GNUNET_BIO_ReadHandle *rh;
  char *filename = GNUNET_DISK_mktemp ("gnunet_bio");
  struct GNUNET_CONTAINER_MetaData *mdR = NULL;

  memset (meta, 'b', sizeof (meta));
  meta[sizeof (meta) - 1] = '\0';

  wh = GNUNET_BIO_write_open_file (filename);
  GNUNET_assert (NULL != wh);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_int32 (wh,
                                                      "test-bigmeta-rw-int32",
                                                      sizeof (meta)));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write (wh,
                                                "test-bigmeta-rw-bytes",
                                                meta,
                                                sizeof (meta)));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (wh, NULL));

  rh = GNUNET_BIO_read_open_file (filename);
  GNUNET_assert (NULL != rh);
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_BIO_read_meta_data (rh,
                                            "test-bigmeta-rw-metadata",
                                            &mdR));
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_read_close (rh, NULL));

  GNUNET_assert (NULL == mdR);

  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (filename));
  GNUNET_free (filename);
  return 0;
}


static int
test_directory_r (void)
{
#ifdef LINUX
  struct GNUNET_BIO_ReadHandle *rh;
  char rString[200];

  rh = GNUNET_BIO_read_open_file ("/dev");
  GNUNET_assert (NULL != rh);
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_read (rh,
                                                   "test-directory-r",
                                                   rString,
                                                   sizeof (rString)));
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_read_close (rh, NULL));
#endif
  return 0;
}


static int
test_nullfile_rw (void)
{
  static char filename[102401];
  struct GNUNET_BIO_WriteHandle *wh;
  struct GNUNET_BIO_ReadHandle *rh;

  memset (filename, 'a', sizeof (filename));
  filename[sizeof (filename) - 1] = '\0';

  GNUNET_log_skip (2, GNUNET_NO);
  wh = GNUNET_BIO_write_open_file (filename);
  GNUNET_log_skip (0, GNUNET_YES);
  GNUNET_assert (NULL == wh);

  GNUNET_log_skip (2, GNUNET_NO);
  rh = GNUNET_BIO_read_open_file (filename);
  GNUNET_log_skip (0, GNUNET_YES);
  GNUNET_assert (NULL == rh);

  return 0;
}


static int
test_fullfile_rw (void)
{
#ifdef LINUX
  /* /dev/full doesn't exist on every platform */
  struct GNUNET_BIO_WriteHandle *wh;
  struct GNUNET_BIO_ReadHandle *rh;
  char *rString = NULL;
  char rResult[200];
  struct GNUNET_CONTAINER_MetaData *mdW;
  struct GNUNET_CONTAINER_MetaData *mdR = NULL;

  mdW = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_CONTAINER_meta_data_add_publication_date (mdW);

  struct GNUNET_BIO_WriteSpec ws[] = {
    GNUNET_BIO_write_spec_object ("test-fullfile-rw-bytes",
                                  TESTSTRING,
                                  strlen (TESTSTRING)),
    GNUNET_BIO_write_spec_string ("test-fullfile-rw-string",
                                  TESTSTRING),
    GNUNET_BIO_write_spec_meta_data ("test-fullfile-rw-metadata",
                                     mdW),
    GNUNET_BIO_write_spec_end (),
  };

  struct GNUNET_BIO_ReadSpec rs[] = {
    GNUNET_BIO_read_spec_object ("test-fullfile-rw-bytes",
                                 rResult,
                                 sizeof (rResult)),
    GNUNET_BIO_read_spec_string ("test-fullfile-rw-string",
                                 &rString,
                                 200),
    GNUNET_BIO_read_spec_meta_data ("test-fullfile-rw-metadata",
                                    &mdR),
    GNUNET_BIO_read_spec_end(),
  };

  wh = GNUNET_BIO_write_open_file ("/dev/full");
  GNUNET_assert (NULL != wh);
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_write_spec_commit (wh, ws));
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_write_close (wh, NULL));

  rh = GNUNET_BIO_read_open_file ("/dev/null");
  GNUNET_assert (NULL != rh);
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_read_spec_commit (rh, rs));
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_read_close (rh, NULL));

  GNUNET_assert (NULL == rString);
  GNUNET_assert (NULL == mdR);
#endif
  return 0;
}


static int
test_fakestring_rw (void)
{
  struct GNUNET_BIO_WriteHandle *wh;
  struct GNUNET_BIO_ReadHandle *rh;
  char *filename = GNUNET_DISK_mktemp ("gnunet_bio");
  char *rString = NULL;

  wh = GNUNET_BIO_write_open_file (filename);
  GNUNET_assert (NULL != wh);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_int32 (wh,
                                                      "test-fakestring-rw-int32",
                                                      2));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (wh, NULL));

  rh = GNUNET_BIO_read_open_file (filename);
  GNUNET_assert (NULL != rh);
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_BIO_read_string (rh,
                                         "test-fakestring-rw-string",
                                         &rString, 200));
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_read_close (rh, NULL));

  GNUNET_assert (NULL == rString);

  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (filename));
  GNUNET_free (filename);
  return 0;
}


static int
test_fakemeta_rw (void)
{
  struct GNUNET_BIO_WriteHandle *wh;
  struct GNUNET_BIO_ReadHandle *rh;
  char *filename = GNUNET_DISK_mktemp ("gnunet_bio");
  struct GNUNET_CONTAINER_MetaData *mdR = NULL;

  wh = GNUNET_BIO_write_open_file (filename);
  GNUNET_assert (NULL != wh);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_int32 (wh,
                                                      "test-fakestring-rw-int32",
                                                      2));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (wh, NULL));

  rh = GNUNET_BIO_read_open_file (filename);
  GNUNET_assert (NULL != rh);
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_BIO_read_meta_data (rh,
                                            "test-fakestring-rw-metadata",
                                            &mdR));
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_read_close (rh, NULL));

  GNUNET_assert (NULL == mdR);

  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (filename));
  GNUNET_free (filename);
  return 0;
}


static int
test_fakebigmeta_rw (void)
{
  struct GNUNET_BIO_WriteHandle *wh;
  struct GNUNET_BIO_ReadHandle *rh;
  char *filename = GNUNET_DISK_mktemp ("gnunet_bio");
  struct GNUNET_CONTAINER_MetaData *mdR = NULL;
  int32_t wNum = 1024 * 1024 * 10;

  wh = GNUNET_BIO_write_open_file (filename);
  GNUNET_assert (NULL != wh);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_int32 (wh,
                                                      "test-fakebigmeta-rw-int32",
                                                      wNum));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (wh, NULL));

  rh = GNUNET_BIO_read_open_file (filename);
  GNUNET_assert (NULL != rh);
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_BIO_read_meta_data (rh,
                                            "test-fakebigmeta-rw-metadata",
                                            &mdR));
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_read_close (rh, NULL));

  GNUNET_assert (NULL == mdR);

  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (filename));
  GNUNET_free (filename);
  return 0;
}


static int
check_string_rw (void)
{
  GNUNET_assert (0 == test_nullstring_rw ());
  GNUNET_assert (0 == test_emptystring_rw ());
  GNUNET_assert (0 == test_bigstring_rw ());
  GNUNET_assert (0 == test_fakestring_rw ());
  return 0;
}


static int
check_metadata_rw (void)
{
  GNUNET_assert (0 == test_fakebigmeta_rw ());
  GNUNET_assert (0 == test_fakemeta_rw ());
  GNUNET_assert (0 == test_bigmeta_rw ());
  return 0;
}


static int
check_file_rw (void)
{
  GNUNET_assert (0 == test_normal_rw ());
  GNUNET_assert (0 == test_nullfile_rw ());
  GNUNET_assert (0 == test_fullfile_rw ());
  GNUNET_assert (0 == test_directory_r ());
  return 0;
}


int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test-bio", "WARNING", NULL);
  GNUNET_assert (0 == check_file_rw ());
  GNUNET_assert (0 == check_metadata_rw ());
  GNUNET_assert (0 == check_string_rw ());
  return 0;
}


/* end of test_bio.c */
