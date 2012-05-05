/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
 * @file testing/testbed_api_operations.c
 * @brief functions to manage operation queues
 * @author Christian Grothoff
 */
#include "platform.h"
#include "testbed_api_operations.h"


/**
 * Opaque handle to an abstract operation to be executed by the testing framework.
 */
struct GNUNET_TESTBED_Operation
{
  // FIXME!
};



/**
 * Cancel a pending operation.  Releases all resources
 * of the operation and will ensure that no event
 * is generated for the operation.  Does NOT guarantee
 * that the operation will be fully undone (or that
 * nothing ever happened).  
 * 
 * @param operation operation to cancel
 */
void
GNUNET_TESTBED_operation_cancel (struct GNUNET_TESTBED_Operation *operation)
{
  GNUNET_break (0);

}


/**
 * Signal that the information from an operation has been fully
 * processed.  This function MUST be called for each event
 * of type 'operation_finished' to fully remove the operation
 * from the operation queue.  After calling this function, the
 * 'op_result' becomes invalid (!).
 * 
 * @param operation operation to signal completion for
 */
void
GNUNET_TESTBED_operation_done (struct GNUNET_TESTBED_Operation *operation)
{
  GNUNET_break (0);
}



/* end of testbed_api_operations.c */
