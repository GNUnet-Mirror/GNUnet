/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_os_priority.c
 * @brief testcase for util/os_priority.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_os_lib.h"

#define VERBOSE 0

static int
testprio ()
{
  if (GNUNET_OK !=
      GNUNET_OS_set_process_priority (GNUNET_OS_process_current (),
                                      GNUNET_SCHEDULER_PRIORITY_DEFAULT))
    return 1;
  if (GNUNET_OK !=
      GNUNET_OS_set_process_priority (GNUNET_OS_process_current (),
                                      GNUNET_SCHEDULER_PRIORITY_UI))
    return 1;
  if (GNUNET_OK !=
      GNUNET_OS_set_process_priority (GNUNET_OS_process_current (),
                                      GNUNET_SCHEDULER_PRIORITY_IDLE))
    return 1;
  if (GNUNET_OK !=
      GNUNET_OS_set_process_priority (GNUNET_OS_process_current (),
                                      GNUNET_SCHEDULER_PRIORITY_BACKGROUND))
    return 1;
  if (GNUNET_OK !=
      GNUNET_OS_set_process_priority (GNUNET_OS_process_current (),
                                      GNUNET_SCHEDULER_PRIORITY_HIGH))
    return 1;
  if (GNUNET_OK !=
      GNUNET_OS_set_process_priority (GNUNET_OS_process_current (),
                                      GNUNET_SCHEDULER_PRIORITY_HIGH))
    return 1;
  return 0;
}

int
main (int argc, char *argv[])
{
  int errCnt = 0;

  GNUNET_log_setup ("test_os_priority", "WARNING", NULL);
  if (0 != testprio ())
    errCnt++;
  return errCnt;
}
