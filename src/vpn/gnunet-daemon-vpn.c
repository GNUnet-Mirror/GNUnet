/*
     This file is part of GNUnet.
     (C) 2010 Philipp Tölke

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
 * @file vpn/gnunet-daemon-vpn.c
 * @brief 
 * @author Philipp Tölke
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_os_lib.h"
/* #include "gnunet_template_service.h" */

/**
 * Final status code.
 */
static int ret;

struct vpn_cls {
	struct GNUNET_DISK_PipeHandle* helper_in;
	struct GNUNET_DISK_PipeHandle* helper_out;

	pid_t helper_pid;
};

static void cleanup(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tskctx) {
	struct vpn_cls* mycls = (struct vpn_cls*) cls;
	if (tskctx->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN) {
		PLIBC_KILL(mycls->helper_pid, SIGTERM);
		GNUNET_OS_process_wait(mycls->helper_pid);
	}
}

static void helper_read(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tsdkctx) {
}

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param sched the scheduler to use
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
	 struct GNUNET_SCHEDULER_Handle *sched,
	 char *const *args,
	 const char *cfgfile,
	 const struct GNUNET_CONFIGURATION_Handle *cfg) {

	struct vpn_cls* mycls = (struct vpn_cls*) cls;

	GNUNET_SCHEDULER_add_delayed(sched, GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, cls);

	mycls->helper_in = GNUNET_DISK_pipe(1);
	mycls->helper_out = GNUNET_DISK_pipe(1);

	mycls->helper_pid = GNUNET_OS_start_process(mycls->helper_in, mycls->helper_out, "gnunet-vpn-helper", "gnunet-vpn-helper", NULL);

	const struct GNUNET_DISK_FileHandle* fh = GNUNET_DISK_pipe_handle (mycls->helper_out, GNUNET_DISK_PIPE_END_READ);
	
	GNUNET_SCHEDULER_add_read_file (sched, GNUNET_TIME_UNIT_FOREVER_REL, fh, &helper_read, mycls);
}


/**
 * The main function to obtain template from gnunetd.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  struct vpn_cls* cls = (struct vpn_cls*)malloc(sizeof(struct vpn_cls));

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-daemon-vpn",
                              gettext_noop ("help text"),
                              options, &run, cls)) ? ret : 1;
}

/* end of gnunet-daemon-vpn.c */
