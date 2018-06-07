/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2005, 2006, 2009 GNUnet e.V.

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
*/

/**
 * @file util/test_disk.c
 * @brief testcase for the storage module
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#define TESTSTRING "Hello World\0"


static int
testReadWrite ()
{
  char tmp[100 + 1];
  int ret;

  if (strlen (TESTSTRING) !=
      GNUNET_DISK_fn_write (".testfile", TESTSTRING, strlen (TESTSTRING),
                            GNUNET_DISK_PERM_USER_READ |
                            GNUNET_DISK_PERM_USER_WRITE))
    return 1;
  if (GNUNET_OK != GNUNET_DISK_file_test (".testfile"))
    return 1;
  ret = GNUNET_DISK_fn_read (".testfile", tmp, sizeof (tmp) - 1);
  if (ret < 0)
  {
    FPRINTF (stderr, "Error reading file `%s' in testReadWrite\n", ".testfile");
    return 1;
  }
  tmp[ret] = '\0';
  if (0 != memcmp (tmp, TESTSTRING, strlen (TESTSTRING) + 1))
  {
    FPRINTF (stderr, "Error in testReadWrite: *%s* != *%s* for file %s\n", tmp,
             TESTSTRING, ".testfile");
    return 1;
  }
  GNUNET_DISK_file_copy (".testfile", ".testfile2");
  memset (tmp, 0, sizeof (tmp));
  ret = GNUNET_DISK_fn_read (".testfile2", tmp, sizeof (tmp) - 1);
  if (ret < 0)
  {
    FPRINTF (stderr, "Error reading file `%s' in testReadWrite\n",
             ".testfile2");
    return 1;
  }
  tmp[ret] = '\0';
  if (0 != memcmp (tmp, TESTSTRING, strlen (TESTSTRING) + 1))
  {
    FPRINTF (stderr, "Error in testReadWrite: *%s* != *%s* for file %s\n", tmp,
             TESTSTRING, ".testfile2");
    return 1;
  }

  GNUNET_break (0 == UNLINK (".testfile"));
  GNUNET_break (0 == UNLINK (".testfile2"));
  if (GNUNET_NO != GNUNET_DISK_file_test (".testfile"))
    return 1;

  return 0;
}


static int
testOpenClose ()
{
  struct GNUNET_DISK_FileHandle *fh;
  uint64_t size;

  fh = GNUNET_DISK_file_open (".testfile",
                              GNUNET_DISK_OPEN_READWRITE |
                              GNUNET_DISK_OPEN_CREATE,
                              GNUNET_DISK_PERM_USER_READ |
                              GNUNET_DISK_PERM_USER_WRITE);
  GNUNET_assert (GNUNET_NO == GNUNET_DISK_handle_invalid (fh));
  GNUNET_break (5 == GNUNET_DISK_file_write (fh, "Hello", 5));
  GNUNET_DISK_file_close (fh);
  GNUNET_break (GNUNET_OK ==
                GNUNET_DISK_file_size (".testfile", &size, GNUNET_NO, GNUNET_YES));
  if (size != 5)
    return 1;
  GNUNET_break (0 == UNLINK (".testfile"));

  return 0;
}

static int ok;


static int
scan_callback (void *want, const char *filename)
{
  if (NULL != strstr (filename, want))
    ok++;
  return GNUNET_OK;
}


static int
testDirScan ()
{
  if (GNUNET_OK !=
      GNUNET_DISK_directory_create ("test" DIR_SEPARATOR_STR "entry"))
  {
    GNUNET_break (0);
    return 1;
  }
  if (GNUNET_OK !=
      GNUNET_DISK_directory_create ("test" DIR_SEPARATOR_STR "entry_more"))
  {
    GNUNET_break (0);
    return 1;
  }
  GNUNET_DISK_directory_scan ("test", &scan_callback,
                              "test" DIR_SEPARATOR_STR "entry");
  if (GNUNET_OK != GNUNET_DISK_directory_remove ("test"))
  {
    GNUNET_break (0);
    return 1;
  }
  if (ok < 2)
  {
    GNUNET_break (0);
    return 1;
  }
  return 0;
}


static int
iter_callback (void *cls,
	       const char *filename)
{
  int *i = cls;
  
  (*i)++;
  return GNUNET_OK;
}


static int
testDirIter ()
{
  int i;

  i = 0;
  if (GNUNET_OK != GNUNET_DISK_directory_create ("test/entry"))
  {
    GNUNET_break (0);
    return 1;
  }
  if (GNUNET_OK != GNUNET_DISK_directory_create ("test/entry_many"))
  {
    GNUNET_break (0);
    return 1;
  }
  if (GNUNET_OK != GNUNET_DISK_directory_create ("test/entry_more"))
  {
    GNUNET_break (0);
    return 1;
  }
  GNUNET_DISK_directory_scan ("test",
			      &iter_callback,
                              &i);
  if (GNUNET_OK != GNUNET_DISK_directory_remove ("test"))
  {
    GNUNET_break (0);
    return 1;
  }
  if (i < 3)
  {
    GNUNET_break (0);
    return 1;
  }
  return 0;
}


static int
testCanonicalize ()
{
  char *fn = GNUNET_strdup ("ab?><|cd*ef:/g\"");

  GNUNET_DISK_filename_canonicalize (fn);
  if (0 != strcmp (fn, "ab____cd_ef__g_"))
  {
    GNUNET_free (fn);
    return 1;
  }
  GNUNET_free (fn);
  return 0;
}


static int
testChangeOwner ()
{
#ifndef WINDOWS
  GNUNET_log_skip (1, GNUNET_NO);
  if (GNUNET_OK == GNUNET_DISK_file_change_owner ("/dev/null", "unknownuser"))
    return 1;
#endif
  return 0;
}


static int
testDirMani ()
{
  if (GNUNET_OK != GNUNET_DISK_directory_create_for_file ("test/ing"))
  {
    GNUNET_break (0);
    return 1;
  }
  if (GNUNET_NO != GNUNET_DISK_file_test ("test"))
  {
    GNUNET_break (0);
    return 1;
  }
  if (GNUNET_NO != GNUNET_DISK_file_test ("test/ing"))
  {
    GNUNET_break (0);
    return 1;
  }
  if (GNUNET_OK != GNUNET_DISK_directory_remove ("test"))
  {
    GNUNET_break (0);
    return 1;
  }
  if (GNUNET_OK != GNUNET_DISK_directory_create ("test"))
  {
    GNUNET_break (0);
    return 1;
  }
  if (GNUNET_YES != GNUNET_DISK_directory_test ("test", GNUNET_YES))
  {
    GNUNET_break (0);
    return 1;
  }
  if (GNUNET_OK != GNUNET_DISK_directory_remove ("test"))
  {
    GNUNET_break (0);
    return 1;
  }
  return 0;
}


int
main (int argc, char *argv[])
{
  unsigned int failureCount = 0;

  GNUNET_log_setup ("test-disk", "WARNING", NULL);
  failureCount += testReadWrite ();
  failureCount += testOpenClose ();
  failureCount += testDirScan ();
  failureCount += testDirIter ();
  failureCount += testCanonicalize ();
  failureCount += testChangeOwner ();
  failureCount += testDirMani ();
  if (0 != failureCount)
  {
    FPRINTF (stderr,
	     "\n%u TESTS FAILED!\n",
	     failureCount);
    return -1;
  }
  return 0;
}                               /* end of main */
