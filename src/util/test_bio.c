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
 * @file util/test_bio.c
 * @brief testcase for the buffered IO module
 * @author Ji Lu
 */


#include "platform.h"
#include "gnunet_util_lib.h"
#define TESTSTRING "testString"
#define TESTNUMBER64 ((int64_t)100000L)

static int
test_normal_rw ()
{
  char *msg;
  int64_t testNum;
  char *readResultString;
  char *fileName = GNUNET_DISK_mktemp ("gnunet_bio");
  struct GNUNET_BIO_WriteHandle *fileW;
  struct GNUNET_BIO_ReadHandle *fileR;
  struct GNUNET_CONTAINER_MetaData *metaDataW;
  struct GNUNET_CONTAINER_MetaData *metaDataR;

  metaDataW = GNUNET_CONTAINER_meta_data_create ();
  metaDataR = NULL;
  GNUNET_CONTAINER_meta_data_add_publication_date (metaDataW);

  fileW = GNUNET_BIO_write_open (fileName);
  GNUNET_assert (NULL != fileW);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_string (fileW, TESTSTRING));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_meta_data (fileW, metaDataW));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_int64 (fileW, TESTNUMBER64));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (fileW));

  fileR = GNUNET_BIO_read_open (fileName);
  GNUNET_assert (NULL != fileR);
  readResultString = NULL;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_BIO_read_string (fileR, "Read string error",
                                         &readResultString, 200));
  GNUNET_assert (NULL != readResultString);
  GNUNET_assert (0 == strcmp (TESTSTRING, readResultString));
  GNUNET_free (readResultString);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_BIO_read_meta_data (fileR, "Read meta error",
                                            &metaDataR));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_meta_data_test_equal (metaDataR, metaDataW));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_read_int64 (fileR, &testNum));
  GNUNET_BIO_read_close (fileR, &msg);
  GNUNET_CONTAINER_meta_data_destroy (metaDataW);
  GNUNET_CONTAINER_meta_data_destroy (metaDataR);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (fileName));
  GNUNET_free (fileName);
  return 0;
}

static int
test_nullstring_rw ()
{
  char *msg;
  char *readResultString = (char *) "not null";
  struct GNUNET_BIO_WriteHandle *fileW;
  struct GNUNET_BIO_ReadHandle *fileR;
  char *fileName = GNUNET_DISK_mktemp ("gnunet_bio");

  fileW = GNUNET_BIO_write_open (fileName);
  GNUNET_assert (NULL != fileW);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_string (fileW, NULL));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (fileW));

  fileR = GNUNET_BIO_read_open (fileName);
  GNUNET_assert (NULL != fileR);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_BIO_read_string (fileR, "Read string error",
                                         &readResultString, 200));
  GNUNET_assert (NULL == readResultString);
  GNUNET_BIO_read_close (fileR, &msg);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (fileName));
  GNUNET_free (fileName);

  return 0;
}

static int
test_emptystring_rw ()
{
  char *msg;
  char *readResultString;
  struct GNUNET_BIO_WriteHandle *fileW;
  struct GNUNET_BIO_ReadHandle *fileR;
  char *fileName = GNUNET_DISK_mktemp ("gnunet_bio");

  fileW = GNUNET_BIO_write_open (fileName);
  GNUNET_assert (NULL != fileW);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_string (fileW, ""));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (fileW));

  fileR = GNUNET_BIO_read_open (fileName);
  GNUNET_assert (NULL != fileR);
  readResultString = NULL;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_BIO_read_string (fileR, "Read string error",
                                         &readResultString, 200));
  GNUNET_free (readResultString);
  GNUNET_BIO_read_close (fileR, &msg);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (fileName));
  GNUNET_free (fileName);
  return 0;
}

static int
test_bigstring_rw ()
{
  char *msg;
  char *readResultString;
  struct GNUNET_BIO_WriteHandle *fileW;
  struct GNUNET_BIO_ReadHandle *fileR;
  char *fileName = GNUNET_DISK_mktemp ("gnunet_bio");

  fileW = GNUNET_BIO_write_open (fileName);
  GNUNET_assert (NULL != fileW);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_string (fileW, TESTSTRING));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (fileW));

  fileR = GNUNET_BIO_read_open (fileName);
  GNUNET_assert (NULL != fileR);
  readResultString = NULL;
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_BIO_read_string (fileR, "Read string error",
                                         &readResultString, 1));
  GNUNET_assert (NULL == readResultString);
  msg = NULL;
  GNUNET_BIO_read_close (fileR, &msg);
  GNUNET_free (msg);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (fileName));
  GNUNET_free (fileName);
  return 0;
}

static int
test_bigmeta_rw ()
{
  char *msg;
  static char meta[1024 * 1024 * 10];
  struct GNUNET_BIO_WriteHandle *fileW;
  struct GNUNET_BIO_ReadHandle *fileR;
  char *fileName = GNUNET_DISK_mktemp ("gnunet_bio");
  struct GNUNET_CONTAINER_MetaData *metaDataR;

  memset (meta, 'b', sizeof (meta));
  meta[sizeof (meta) - 1] = '\0';
  fileW = GNUNET_BIO_write_open (fileName);
  GNUNET_assert (NULL != fileW);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_int32 (fileW, sizeof (meta)));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write (fileW, meta, sizeof (meta)));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (fileW));

  fileR = GNUNET_BIO_read_open (fileName);
  GNUNET_assert (NULL != fileR);
  metaDataR = NULL;
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_BIO_read_meta_data (fileR, "Read meta error",
                                            &metaDataR));
  msg = NULL;
  GNUNET_BIO_read_close (fileR, &msg);
  GNUNET_free (msg);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (fileName));
  GNUNET_assert (NULL == metaDataR);
  GNUNET_free (fileName);
  return 0;
}

static int
test_directory_r ()
{
#if LINUX
  char *msg;
  char readResult[200];
  struct GNUNET_BIO_ReadHandle *fileR;

  fileR = GNUNET_BIO_read_open ("/dev");
  GNUNET_assert (NULL != fileR);
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_BIO_read (fileR, "Read error", readResult,
                                  sizeof (readResult)));
  msg = NULL;
  GNUNET_BIO_read_close (fileR, &msg);
  GNUNET_free (msg);
#endif
  return 0;
}

static int
test_nullfile_rw ()
{
  static char fileNameNO[102401];
  struct GNUNET_BIO_WriteHandle *fileWNO;
  struct GNUNET_BIO_ReadHandle *fileRNO;

  memset (fileNameNO, 'a', sizeof (fileNameNO));
  fileNameNO[sizeof (fileNameNO) - 1] = '\0';

  GNUNET_log_skip (1, GNUNET_NO);
  fileWNO = GNUNET_BIO_write_open (fileNameNO);
  GNUNET_log_skip (0, GNUNET_YES);
  GNUNET_assert (NULL == fileWNO);

  GNUNET_log_skip (1, GNUNET_NO);
  fileRNO = GNUNET_BIO_read_open (fileNameNO);
  GNUNET_log_skip (0, GNUNET_YES);
  GNUNET_assert (NULL == fileRNO);
  return 0;
}


static int
test_fullfile_rw ()
{
#ifdef LINUX
  /* /dev/full only seems to exist on Linux */
  char *msg;
  int64_t testNum;
  char *readResultString;
  char readResult[200];
  struct GNUNET_BIO_WriteHandle *fileW;
  struct GNUNET_BIO_ReadHandle *fileR;
  struct GNUNET_CONTAINER_MetaData *metaDataW;
  struct GNUNET_CONTAINER_MetaData *metaDataR;

  metaDataW = GNUNET_CONTAINER_meta_data_create ();
  GNUNET_CONTAINER_meta_data_add_publication_date (metaDataW);

  fileW = GNUNET_BIO_write_open ("/dev/full");
  GNUNET_assert (NULL != fileW);
  (void) GNUNET_BIO_write (fileW, TESTSTRING, strlen (TESTSTRING));
  (void) GNUNET_BIO_write_string (fileW, TESTSTRING);
  (void) GNUNET_BIO_write_meta_data (fileW, metaDataW);
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_write_close (fileW));
  GNUNET_CONTAINER_meta_data_destroy (metaDataW);

  fileW = GNUNET_BIO_write_open ("/dev/full");
  GNUNET_assert (NULL != fileW);
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_write_close (fileW));

  fileR = GNUNET_BIO_read_open ("/dev/null");
  GNUNET_assert (NULL != fileR);
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_BIO_read (fileR, "Read error", readResult,
                                  sizeof (readResult)));
  readResultString = NULL;
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_BIO_read_string (fileR, "Read string error",
                                         &readResultString, 200));
  GNUNET_assert (NULL == readResultString);
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_read_int64 (fileR, &testNum));
  metaDataR = NULL;
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_BIO_read_meta_data (fileR, "Read meta error",
                                            &metaDataR));
  msg = NULL;
  GNUNET_BIO_read_close (fileR, &msg);
  GNUNET_free (msg);
  GNUNET_assert (NULL == metaDataR);
#endif
  return 0;
}

static int
test_fakestring_rw ()
{
  char *msg;
  int32_t tmpInt = 2;
  char *readResult;
  struct GNUNET_BIO_WriteHandle *fileW;
  struct GNUNET_BIO_ReadHandle *fileR;
  char *fileName = GNUNET_DISK_mktemp ("gnunet_bio");

  fileW = GNUNET_BIO_write_open (fileName);
  GNUNET_assert (NULL != fileW);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_int32 (fileW, tmpInt));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (fileW));

  fileR = GNUNET_BIO_read_open (fileName);
  GNUNET_assert (NULL != fileR);
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_BIO_read_string (fileR, "Read string error",
                                         &readResult, 200));
  msg = NULL;
  GNUNET_BIO_read_close (fileR, &msg);
  GNUNET_free (msg);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (fileName));
  GNUNET_free (fileName);
  return 0;
}

static int
test_fakemeta_rw ()
{
  char *msg;
  int32_t tmpInt = 2;
  struct GNUNET_BIO_WriteHandle *fileW;
  struct GNUNET_BIO_ReadHandle *fileR;
  char *fileName = GNUNET_DISK_mktemp ("gnunet_bio");
  struct GNUNET_CONTAINER_MetaData *metaDataR;

  fileW = GNUNET_BIO_write_open (fileName);
  GNUNET_assert (NULL != fileW);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_int32 (fileW, tmpInt));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (fileW));

  fileR = GNUNET_BIO_read_open (fileName);
  GNUNET_assert (NULL != fileR);
  metaDataR = NULL;
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_BIO_read_meta_data (fileR, "Read meta error",
                                            &metaDataR));
  GNUNET_assert (NULL == metaDataR);
  msg = NULL;
  GNUNET_BIO_read_close (fileR, &msg);
  GNUNET_free (msg);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (fileName));
  GNUNET_free (fileName);
  return 0;
}

static int
test_fakebigmeta_rw ()
{
  char *msg;
  int32_t tmpInt = 1024 * 1024 * 10;
  struct GNUNET_BIO_WriteHandle *fileW;
  struct GNUNET_BIO_ReadHandle *fileR;
  char *fileName = GNUNET_DISK_mktemp ("gnunet_bio");
  struct GNUNET_CONTAINER_MetaData *metaDataR;

  fileW = GNUNET_BIO_write_open (fileName);
  GNUNET_assert (NULL != fileW);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_int32 (fileW, tmpInt));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (fileW));

  fileR = GNUNET_BIO_read_open (fileName);
  GNUNET_assert (NULL != fileR);
  metaDataR = NULL;
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_BIO_read_meta_data (fileR, "Read meta error",
                                            &metaDataR));
  msg = NULL;
  GNUNET_BIO_read_close (fileR, &msg);
  GNUNET_free (msg);
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (fileName));
  GNUNET_assert (NULL == metaDataR);
  GNUNET_free (fileName);
  return 0;
}

static int
check_string_rw ()
{
  GNUNET_assert (0 == test_nullstring_rw ());
  GNUNET_assert (0 == test_emptystring_rw ());
  GNUNET_assert (0 == test_bigstring_rw ());
  GNUNET_assert (0 == test_fakestring_rw ());
  return 0;
}

static int
check_metadata_rw ()
{
  GNUNET_assert (0 == test_fakebigmeta_rw ());
  GNUNET_assert (0 == test_fakemeta_rw ());
  GNUNET_assert (0 == test_bigmeta_rw ());
  return 0;
}

static int
check_file_rw ()
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
