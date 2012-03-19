/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2005, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_disk.c
 * @brief testcase for the storage module
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_disk_lib.h"
#include "gnunet_scheduler_lib.h"

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
  long avail;

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

  /* test that avail goes down as we fill the disk... */
  GNUNET_log_skip (1, GNUNET_NO);
  avail = GNUNET_DISK_get_blocks_available (".testfile");
  GNUNET_log_skip (0, GNUNET_NO);
  fh = GNUNET_DISK_file_open (".testfile",
                              GNUNET_DISK_OPEN_READWRITE |
                              GNUNET_DISK_OPEN_CREATE,
                              GNUNET_DISK_PERM_USER_WRITE |
                              GNUNET_DISK_PERM_USER_READ);
  GNUNET_assert (GNUNET_NO == GNUNET_DISK_handle_invalid (fh));
  while ((avail == GNUNET_DISK_get_blocks_available (".testfile")) &&
         (avail != -1))
    if (16 != GNUNET_DISK_file_write (fh, "HelloWorld123456", 16))
    {
      GNUNET_DISK_file_close (fh);
      GNUNET_break (0 == UNLINK (".testfile"));
      return 1;
    }
  GNUNET_DISK_file_close (fh);
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
    return 1;
  if (GNUNET_OK !=
      GNUNET_DISK_directory_create ("test" DIR_SEPARATOR_STR "entry_more"))
    return 1;
  GNUNET_DISK_directory_scan ("test", &scan_callback,
                              "test" DIR_SEPARATOR_STR "entry");
  if (GNUNET_OK != GNUNET_DISK_directory_remove ("test"))
    return 1;
  if (ok < 2)
    return 1;
  return 0;
}

static void
iter_callback (void *cls, struct GNUNET_DISK_DirectoryIterator *di,
               const char *filename, const char *dirname)
{
  int *i = cls;

  (*i)++;
  GNUNET_DISK_directory_iterator_next (di, GNUNET_NO);
}

static void
iter_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_DISK_directory_iterator_start (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                        "test", &iter_callback, cls);
}

static int
testDirIter ()
{
  int i;

  i = 0;
  if (GNUNET_OK != GNUNET_DISK_directory_create ("test/entry"))
    return 1;
  if (GNUNET_OK != GNUNET_DISK_directory_create ("test/entry_many"))
    return 1;
  if (GNUNET_OK != GNUNET_DISK_directory_create ("test/entry_more"))
    return 1;
  GNUNET_SCHEDULER_run (&iter_task, &i);
  if (GNUNET_OK != GNUNET_DISK_directory_remove ("test"))
    return 1;
  if (i < 3)
    return 1;
  return 0;
}


static int
testGetHome ()
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  char *fn;
  int ret;

  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (cfg != NULL);
  GNUNET_CONFIGURATION_set_value_string (cfg, "service", "HOME",
                                         "/tmp/test-gnunet-disk-a/b/c");
  fn = GNUNET_DISK_get_home_filename (cfg, "service", "d", "e", NULL);
  GNUNET_assert (fn != NULL);
  GNUNET_CONFIGURATION_destroy (cfg);
  ret = strcmp ("/tmp/test-gnunet-disk-a/b/c/d/e", fn);
  GNUNET_free (fn);
  GNUNET_break (GNUNET_OK ==
                GNUNET_DISK_directory_remove ("/tmp/test-gnunet-disk-a"));
  return ret;
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
  GNUNET_log_skip (1, GNUNET_NO);
  if (GNUNET_OK == GNUNET_DISK_file_change_owner ("/dev/null", "unknownuser"))
    return 1;
  return 0;
}

static int
testDirMani ()
{
  if (GNUNET_OK != GNUNET_DISK_directory_create_for_file ("test/ing"))
    return 1;
  if (GNUNET_NO != GNUNET_DISK_file_test ("test"))
    return 1;
  if (GNUNET_NO != GNUNET_DISK_file_test ("test/ing"))
    return 1;
  if (GNUNET_OK != GNUNET_DISK_directory_remove ("test"))
    return 1;
  if (GNUNET_OK != GNUNET_DISK_directory_create ("test"))
    return 1;
  if (GNUNET_YES != GNUNET_DISK_directory_test ("test"))
    return 1;
  if (GNUNET_OK != GNUNET_DISK_directory_remove ("test"))
    return 1;


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
  failureCount += testGetHome ();
  failureCount += testCanonicalize ();
  failureCount += testChangeOwner ();
  failureCount += testDirMani ();
  if (failureCount != 0)
  {
    FPRINTF (stderr, "\n%u TESTS FAILED!\n", failureCount);
    return -1;
  }
  return 0;
}                               /* end of main */
