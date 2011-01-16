/*
     This file is part of GNUnet.
     (C) 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file monkey/action_api.c
 * @brief Monkey API for actions taken by Monkey while debugging
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_monkey_action.h"


int GNUNET_MONKEY_ACTION_report_file()
{
	return GNUNET_OK;
}


int GNUNET_MONKEY_ACTION_report_email()
{
	return GNUNET_OK;
}



int GNUNET_MONKEY_ACTION_rerun_with_valgrind()
{
	return GNUNET_OK;
}


int GNUNET_MONKEY_ACTION_rerun_with_gdb()
{
	return GNUNET_OK;
}


int GNUNET_MONKEY_ACTION_check_bug_redundancy()
{
	return GNUNET_OK;
}
