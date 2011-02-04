/*
      This file is part of GNUnet
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
 * @file monkey/gnunet_monkey_action.h
 * @brief Monkey API for actions taken by Monkey while debugging
 */

#ifndef GNUNET_MONKEY_ACTION_H
#define GNUNET_MONKEY_ACTION_H

#include "gdbmi.h"

#ifdef __cplusplus
extern "C"
{
#if 0				/* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Context for the Action API
 */
struct GNUNET_MONKEY_ACTION_Context
{
	const char* binary_name;
	int debug_mode;
	char* debug_report;

	/* gdb debugging attributes */
	mi_stop* gdb_stop_reason;
	mi_frames* gdb_frames;
};

int GNUNET_MONKEY_ACTION_report_file(struct GNUNET_MONKEY_ACTION_Context* cntxt, const char* dumpFileName);
int GNUNET_MONKEY_ACTION_report_email(struct GNUNET_MONKEY_ACTION_Context* cntxt);
int GNUNET_MONKEY_ACTION_rerun_with_valgrind();
int GNUNET_MONKEY_ACTION_rerun_with_gdb(struct GNUNET_MONKEY_ACTION_Context* cntxt);
int GNUNET_MONKEY_ACTION_format_report(struct GNUNET_MONKEY_ACTION_Context* cntxt);
int GNUNET_MONKEY_ACTION_check_bug_redundancy();


#if 0				/* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif
#endif
