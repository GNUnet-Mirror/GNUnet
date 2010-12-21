/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file include/gnunet_os_lib.h
 * @brief low level process routines
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 * @author Milan
 */

#ifndef GNUNET_OS_LIB_H
#define GNUNET_OS_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_scheduler_lib.h"

/**
 * Process information (OS-dependent)
 */
struct GNUNET_OS_Process;


/**
 * Possible installation paths to request
 */
enum GNUNET_OS_InstallationPathKind
{
  /**
   * Return the "PREFIX" directory given to configure.
   */
  GNUNET_OS_IPK_PREFIX,

  /**
   * Return the directory where the program binaries are installed. (bin/)
   */
  GNUNET_OS_IPK_BINDIR,

  /**
   * Return the directory where libraries are installed. (lib/)
   */
  GNUNET_OS_IPK_LIBDIR,

  /**
   * Return the directory where data is installed (share/)
   */
  GNUNET_OS_IPK_DATADIR,

  /**
   * Return the directory where translations are installed (share/locale/)
   */
  GNUNET_OS_IPK_LOCALEDIR,

  /**
   * Return the installation directory of this application, not
   * the one of the overall GNUnet installation (in case they
   * are different).
   */
  GNUNET_OS_IPK_SELF_PREFIX,

  /**
   * Return the prefix of the path with application icons.
   */
  GNUNET_OS_IPK_ICONDIR
};


/**
 * Process status types
 */
enum GNUNET_OS_ProcessStatusType
{
  /**
   * The process is not known to the OS (or at
   * least not one of our children).
   */
  GNUNET_OS_PROCESS_UNKNOWN,

  /**
   * The process is still running.
   */
  GNUNET_OS_PROCESS_RUNNING,

  /**
   * The process is paused (but could be resumed).
   */
  GNUNET_OS_PROCESS_STOPPED,

  /**
   * The process exited with a return code.
   */
  GNUNET_OS_PROCESS_EXITED,

  /**
   * The process was killed by a signal.
   */
  GNUNET_OS_PROCESS_SIGNALED
};


/**
 * Get the path to a specific GNUnet installation directory or, with
 * GNUNET_OS_IPK_SELF_PREFIX, the current running apps installation
 * directory.
 *
 * @param dirkind what kind of directory is desired?
 * @return a pointer to the dir path (to be freed by the caller)
 */
char *GNUNET_OS_installation_get_path (enum GNUNET_OS_InstallationPathKind
                                       dirkind);


/**
 * Callback function invoked for each interface found.
 *
 * @param cls closure
 * @param name name of the interface (can be NULL for unknown)
 * @param isDefault is this presumably the default interface
 * @param addr address of this interface (can be NULL for unknown or unassigned)
 * @param addrlen length of the address
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_OS_NetworkInterfaceProcessor) (void *cls,
                                                    const char *name,
                                                    int isDefault,
                                                    const struct sockaddr *
                                                    addr, socklen_t addrlen);


/**
 * @brief Enumerate all network interfaces
 * @param proc the callback function
 * @param proc_cls closure for proc
 */
void GNUNET_OS_network_interfaces_list (GNUNET_OS_NetworkInterfaceProcessor
                                        proc, void *proc_cls);

/**
 * @brief Get maximum string length returned by gethostname()
 */
#if HAVE_SYSCONF && defined(_SC_HOST_NAME_MAX)
#define GNUNET_OS_get_hostname_max_length() ({ int __sc_tmp = sysconf(_SC_HOST_NAME_MAX); __sc_tmp <= 0 ? 255 : __sc_tmp; })
#elif defined(HOST_NAME_MAX)
#define GNUNET_OS_get_hostname_max_length() HOST_NAME_MAX
#else
#define GNUNET_OS_get_hostname_max_length() 255
#endif


/**
 * Get process structure for current process
 *
 * The pointer it returns points to static memory location and must not be
 * deallocated/closed
 *
 * @return pointer to the process sturcutre for this process
 */
struct GNUNET_OS_Process *GNUNET_OS_process_current (void);


/**
 * Sends sig to the process
 *
 * @param proc pointer to process structure
 * @param sig signal
 * @return 0 on success, -1 on error
 */
int GNUNET_OS_process_kill (struct GNUNET_OS_Process *proc, int sig);


/**
 * Cleans up process structure contents (OS-dependent) and deallocates it
 *
 * @param proc pointer to process structure
 */
void GNUNET_OS_process_close (struct GNUNET_OS_Process *proc);

/**
 * Get the pid of the process in question
 *
 * @param proc the process to get the pid of
 *
 * @return the current process id
 */
pid_t
GNUNET_OS_process_get_pid (struct GNUNET_OS_Process *proc);

/**
 * Set process priority
 *
 * @param proc pointer to process structure
 * @param prio priority value
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_OS_set_process_priority (struct GNUNET_OS_Process *proc,
                                    enum GNUNET_SCHEDULER_Priority prio);


/**
 * Start a process.
 *
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param filename name of the binary
 * @param ... NULL-terminated list of arguments to the process
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process (struct GNUNET_DISK_PipeHandle *pipe_stdin, 
			 struct GNUNET_DISK_PipeHandle *pipe_stdout, 
			 const char *filename, ...);


/**
 * Start a process.
 *
 * @param lsocks array of listen sockets to dup systemd-style (or NULL);
 *         must be NULL on platforms where dup is not supported
 * @param filename name of the binary
 * @param argv NULL-terminated list of arguments to the process,
 *             including the process name as the first argument
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_v (const int *lsocks, const char *filename,
			   char *const argv[]);


/**
 * Retrieve the status of a process
 * @param proc pointer to process structure
 * @param type status type
 * @param code return code/signal number
 * @return GNUNET_OK on success, GNUNET_NO if the process is still running, GNUNET_SYSERR otherwise
 */
int GNUNET_OS_process_status (struct GNUNET_OS_Process *proc,
			      enum GNUNET_OS_ProcessStatusType *type, unsigned long *code);


/**
 * Wait for a process
 * @param proc pointer to process structure of the process to wait for
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int GNUNET_OS_process_wait (struct GNUNET_OS_Process *proc);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_OS_LIB_H */
#endif
/* end of gnunet_os_lib.h */
