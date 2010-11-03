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
 * @file monkey/test_gnunet_monkey.c
 * @brief Testcase for Monkey
 * @author Safey Abdel Halim
 */

/**
 * Test case for Monkey Automatic Debugger.
 * It launches Monkey to run binaries having 
 * known bugs (e.g. Null Pointer Exception)
 * Monkey should be able to detect the problem and send an e-mail
 * containing the problem description.
 */


#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_program_lib.h"


static int
check ()
{
    GNUNET_OS_process_close (GNUNET_OS_start_process (NULL, NULL,
    			                              "gnunet-monkey",
	                                              "gnunet-monkey",
	                                        "./bug_null_pointer_exception",
                                                      NULL));
    
	return 0;
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-gnunet-monkey",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  return ret;
}

/* end of test_gnunet_monkey.c */

