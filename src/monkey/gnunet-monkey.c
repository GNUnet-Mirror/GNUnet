/**[txh]********************************************************************

  Copyright (c) 2004 by Salvador E. Tropea.
  Covered by the GPL license.

  Comment:
  X11 example/test of the libmigdb.
  Run it from an X11 terminal (xterm, Eterm, etc.).
  
***************************************************************************/

#include <stdio.h>
#include <unistd.h> //usleep
#include <libesmtp.h>
#include "gdbmi.h"

void cb_console(const char *str, void *data)
{
 printf("CONSOLE> %s\n",str);
}

/* Note that unlike what's documented in gdb docs it isn't usable. */
void cb_target(const char *str, void *data)
{
 printf("TARGET> %s\n",str);
}

void cb_log(const char *str, void *data)
{
 printf("LOG> %s\n",str);
}

void cb_to(const char *str, void *data)
{
 printf(">> %s",str);
}

void cb_from(const char *str, void *data)
{
 printf("<< %s\n",str);
}

volatile int async_c=0;

void cb_async(mi_output *o, void *data)
{
 printf("ASYNC\n");
 async_c++;
}

int wait_for_stop(mi_h *h)
{
 int res=1;
 mi_stop *sr;
 mi_frames *f;

 while (!mi_get_response(h))
    usleep(1000);
 /* The end of the async. */
 sr=mi_res_stop(h);
 if (sr)
   {
    printf("Stopped, reason: %s\n",mi_reason_enum_to_str(sr->reason));
    printf("Received signal name: %s\n", sr->signal_name);
    printf("Received signal meaning: %s\n", sr->signal_meaning);
    //printf("In file: %s\n", sr->frame->file);
    //printf("Line Number: %d\n", sr->frame->line);
    f = gmi_stack_info_frame(h);
    mi_free_stop(sr);
   }
 else
   {
    printf("Error while waiting\n");
    printf("mi_error: %d\nmi_error_from_gdb: %s\n",mi_error,mi_error_from_gdb);
    res=0;
   }
 return res;
}

int main(int argc, char *argv[])
{
 mi_aux_term *xterm_tty=NULL;
 
 /* This is like a file-handle for fopen.
    Here we have all the state of gdb "connection". */
 mi_h *h;

 /* Connect to gdb child. */
 h=mi_connect_local();
 if (!h)
   {
    printf("Connect failed\n");
    return 1;
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
 if (!gmi_set_exec(h,"bug_null_pointer_exception", NULL))
   {
    printf("Error setting exec y args\n");
    mi_disconnect(h);
    return 1;
   }

 /* Tell gdb to attach the child to a terminal. */
 if (!gmi_target_terminal(h, ttyname(STDIN_FILENO)))
   {
    printf("Error selecting target terminal\n");
    mi_disconnect(h);
    return 1;
   }

 /* Run the program. */
 if (!gmi_exec_run(h))
   {
    printf("Error in run!\n");
    mi_disconnect(h);
    return 1;
   }
 /* Here we should be stopped when the program crashes */
 if (!wait_for_stop(h))
   {
    mi_disconnect(h);
    return 1;
   }

 /* Continue execution. */
 if (!gmi_exec_continue(h))
   {
    printf("Error in continue!\n");
    mi_disconnect(h);
    return 1;
   }
 /* Here we should be terminated. */
 if (!wait_for_stop(h))
   {
    mi_disconnect(h);
    return 1;
   }

 /* Exit from gdb. */
 gmi_gdb_exit(h);
 /* Close the connection. */
 mi_disconnect(h);
 /* Wait 5 seconds and close the auxiliar terminal. */
 printf("Waiting 5 seconds\n");
 sleep(5);
 gmi_end_aux_term(xterm_tty);

 return 0;
}
