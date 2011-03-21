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
#include <libesmtp.h>

extern void sendMail (const char *messageContents, const char *emailAddress);


static int async_c=0;


static void cb_console(const char *str, void *data)
{
 printf("CONSOLE> %s\n",str);
}


/* Note that unlike what's documented in gdb docs it isn't usable. */
static void cb_target(const char *str, void *data)
{
 printf("TARGET> %s\n",str);
}


static void cb_log(const char *str, void *data)
{
 printf("LOG> %s\n",str);
}


static void cb_to(const char *str, void *data)
{
 printf(">> %s",str);
}


static void cb_from(const char *str, void *data)
{
 printf("<< %s\n",str);
}


static void cb_async(mi_output *o, void *data)
{
 printf("ASYNC\n");
 async_c++;
}


static int wait_for_stop(mi_h *h, struct GNUNET_MONKEY_ACTION_Context *cntxt)
{
	while (!mi_get_response(h))
		usleep(1000);
	/* The end of the async. */
	cntxt->gdb_stop_reason=mi_res_stop(h);
	if (cntxt->gdb_stop_reason)
	{
		if (cntxt->gdb_stop_reason->reason == sr_exited_normally)
			return GDB_STATE_EXIT_NORMALLY;

		cntxt->gdb_frames = gmi_stack_info_frame(h);
		if (NULL == cntxt->gdb_frames)
		  GNUNET_break(0);

		return GDB_STATE_STOPPED;
	}
	return GDB_STATE_ERROR;
}


int GNUNET_MONKEY_ACTION_report_file(struct GNUNET_MONKEY_ACTION_Context* cntxt, const char* dumpFileName)
{
	FILE* file = fopen(dumpFileName, "w");
	GNUNET_assert(NULL != file);
	fprintf(file,"%s", cntxt->debug_report);
	fclose(file);
	return GNUNET_OK;
}


int GNUNET_MONKEY_ACTION_report_email(struct GNUNET_MONKEY_ACTION_Context* cntxt)
{
	if (cntxt->debug_mode == DEBUG_MODE_REPORT_READY)
		sendMail(cntxt->debug_report, cntxt->email_address);

	return GNUNET_OK;
}



int GNUNET_MONKEY_ACTION_rerun_with_valgrind()
{
	return GNUNET_OK;
}


int GNUNET_MONKEY_ACTION_rerun_with_gdb(struct GNUNET_MONKEY_ACTION_Context* cntxt)
{
	cntxt->debug_mode = DEBUG_MODE_GDB;

	/* This is like a file-handle for fopen.
	    Here we have all the state of gdb "connection". */
	mi_set_gdb_exe("/tmp/gdb/bin/gdb");
	mi_h *h;
	int ret;

	 /* Connect to gdb child. */
	 h = mi_connect_local();
	 if (!h)
	   {
	    printf("Connect failed\n");
	    return GNUNET_NO;
	   }
	 printf("Connected to gdb!\n");

	 /* Set all callbacks. */
	 mi_set_console_cb(h,cb_console,NULL);
	 mi_set_target_cb(h,cb_target,NULL);
	 mi_set_log_cb(h,cb_log,NULL);
	 mi_set_async_cb(h,cb_async,NULL);
	 mi_set_to_gdb_cb(h,cb_to,NULL);
	 mi_set_from_gdb_cb(h,cb_from,NULL);

	 /* Set the name of the child and the command line aguments. */
	 if (!gmi_set_exec(h, cntxt->binary_name, NULL))
	   {
	    printf("Error setting exec y args\n");
	    mi_disconnect(h);
	    return GNUNET_NO;
	   }

	 /* Tell gdb to attach the child to a terminal. */
	 if (!gmi_target_terminal(h, ttyname(STDIN_FILENO)))
	   {
	    printf("Error selecting target terminal\n");
	    mi_disconnect(h);
	    return GNUNET_NO;
	   }

	 /* Run the program. */
	 if (!gmi_exec_run(h))
	   {
	    printf("Error in run!\n");
	    mi_disconnect(h);
	    return GNUNET_NO;
	   }
	 /* Here we should be stopped when the program crashes */
	 ret = wait_for_stop(h, cntxt);
	 if (ret != GDB_STATE_ERROR)
	    mi_disconnect(h);

	return ret;
}


int GNUNET_MONKEY_ACTION_format_report(struct GNUNET_MONKEY_ACTION_Context* cntxt)
{
	switch (cntxt->debug_mode) {
	case DEBUG_MODE_GDB:
		GNUNET_asprintf(&(cntxt->debug_report),
			"Bug detected in file:%s\nfunction:%s\nline:%d\nreason:%s\nreceived signal:%s\n%s\n",
			cntxt->gdb_frames->file, cntxt->gdb_frames->func, cntxt->gdb_frames->line, mi_reason_enum_to_str(cntxt->gdb_stop_reason->reason), cntxt->gdb_stop_reason->signal_name, cntxt->gdb_stop_reason->signal_meaning);
		break;
	case DEBUG_MODE_VALGRIND:
		break;
	default:
		break;
	}

	cntxt->debug_mode = DEBUG_MODE_REPORT_READY;
	return GNUNET_OK;
}


int GNUNET_MONKEY_ACTION_check_bug_redundancy()
{
	return GNUNET_OK;
}
