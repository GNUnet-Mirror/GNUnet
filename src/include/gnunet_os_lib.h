/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2011 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 * @author Milan
 *
 * @file
 * Low level process routines
 *
 * @defgroup os  OS library
 * Low level process routines.
 *
 * This code manages child processes.  We can communicate with child
 * processes using signals.  Because signals are not supported on W32
 * and Java (at least not nicely), we can alternatively use a pipe
 * to send signals to the child processes (if the child process is
 * a full-blown GNUnet process that supports reading signals from
 * a pipe, of course).  Naturally, this also only works for 'normal'
 * termination via signals, and not as a replacement for SIGKILL.
 * Thus using pipes to communicate signals should only be enabled if
 * the child is a Java process OR if we are on Windoze.
 *
 * @{
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
 * Flags that determine which of the standard streams
 * should be inherited by the child process.
 */
enum GNUNET_OS_InheritStdioFlags
{

  /**
   * No standard streams should be inherited.
   */
  GNUNET_OS_INHERIT_STD_NONE = 0,

  /**
   * When this flag is set, the child process will
   * inherit stdin of the parent.
   */
  GNUNET_OS_INHERIT_STD_IN = 1,

  /**
   * When this flag is set, the child process will
   * inherit stdout of the parent.
   */
  GNUNET_OS_INHERIT_STD_OUT = 2,

  /**
   * When this flag is set, the child process will
   * inherit stderr of the parent.
   */
  GNUNET_OS_INHERIT_STD_ERR = 4,

  /**
   * When these flags are set, the child process will
   * inherit stdout and stderr of the parent.
   */
  GNUNET_OS_INHERIT_STD_OUT_AND_ERR = 6,

  /**
   * Use this option to have all of the standard streams
   * (stdin, stdout and stderror) be inherited.
   */
  GNUNET_OS_INHERIT_STD_ALL = 7
};


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
   * Return the directory where libraries are installed. (lib/gnunet/)
   */
  GNUNET_OS_IPK_LIBDIR,

  /**
   * Return the directory where data is installed (share/gnunet/)
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
   * Return the prefix of the path with application icons (share/icons/).
   */
  GNUNET_OS_IPK_ICONDIR,

  /**
   * Return the prefix of the path with documentation files, including the
   * license (share/doc/gnunet/).
   */
  GNUNET_OS_IPK_DOCDIR,

  /**
   * Return the directory where helper binaries are installed (lib/gnunet/libexec/)
   */
  GNUNET_OS_IPK_LIBEXECDIR
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
 * Project-specific data used to help the OS subsystem
 * find installation paths.
 */
struct GNUNET_OS_ProjectData
{
  /**
   * Name of a library that is installed in the "lib/" directory of
   * the project, such as "libgnunetutil".  Used to locate the
   * installation by scanning dependencies of the current process.
   */
  const char *libname;

  /**
   * Name of the project that is used in the "libexec" prefix, For
   * example, "gnunet".  Certain helper binaries are then expected to
   * be installed in "$PREFIX/libexec/gnunet/" and resources in
   * "$PREFIX/share/gnunet/".
   */
  const char *project_dirname;

  /**
   * Name of a project-specific binary that should be in "$PREFIX/bin/".
   * Used to determine installation path from $PATH variable.
   * For example "gnunet-arm".  On W32, ".exe" should be omitted.
   */
  const char *binary_name;

  /**
   * Name of an environment variable that can be used to override
   * installation path detection, for example "GNUNET_PREFIX".
   */
  const char *env_varname;

  /**
   * Alternative name of an environment variable that can be used to
   * override installation path detection, if "env_varname" is not
   * set. Again, for example, "GNUNET_PREFIX".
   */
  const char *env_varname_alt;

  /**
   * E-mail address for reporting bugs.
   */
  const char *bug_email;

  /**
   * Project homepage.
   */
  const char *homepage;

  /**
   * Configuration file name (in $XDG_CONFIG_HOME) to use.
   */
  const char *config_file;

};


/**
 * Return default project data used by 'libgnunetutil' for GNUnet.
 */
const struct GNUNET_OS_ProjectData *
GNUNET_OS_project_data_default (void);


/**
 * @return current (actual) project data.
 */
const struct GNUNET_OS_ProjectData *
GNUNET_OS_project_data_get (void);


/**
 * Setup OS subsystem with project data.
 *
 * @param pd project data used to determine paths.
 */
void
GNUNET_OS_init (const struct GNUNET_OS_ProjectData *pd);


/**
 * Get the path to a specific GNUnet installation directory or, with
 * #GNUNET_OS_IPK_SELF_PREFIX, the current running apps installation
 * directory.
 *
 * @param dirkind what kind of directory is desired?
 * @return a pointer to the dir path (to be freed by the caller)
 */
char *
GNUNET_OS_installation_get_path (enum GNUNET_OS_InstallationPathKind dirkind);


/**
 * Given the name of a gnunet-helper, gnunet-service or gnunet-daemon
 * binary, try to prefix it with the libexec/-directory to get the
 * full path.
 *
 * @param progname name of the binary
 * @return full path to the binary, if possible, otherwise copy of 'progname'
 */
char *
GNUNET_OS_get_libexec_binary_path (const char *progname);


/**
 * Callback function invoked for each interface found.
 *
 * @param cls closure
 * @param name name of the interface (can be NULL for unknown)
 * @param isDefault is this presumably the default interface
 * @param addr address of this interface (can be NULL for unknown or unassigned)
 * @param broadcast_addr the broadcast address (can be NULL for unknown or unassigned)
 * @param netmask the network mask (can be NULL for unknown or unassigned)
 * @param addrlen length of the address
 * @return #GNUNET_OK to continue iteration, #GNUNET_SYSERR to abort
 */
typedef int
(*GNUNET_OS_NetworkInterfaceProcessor) (void *cls,
                                        const char *name,
                                        int isDefault,
                                        const struct sockaddr *addr,
                                        const struct sockaddr *broadcast_addr,
                                        const struct sockaddr *netmask,
                                        socklen_t addrlen);


/**
 * @brief Enumerate all network interfaces
 *
 * @param proc the callback function
 * @param proc_cls closure for @a proc
 */
void
GNUNET_OS_network_interfaces_list (GNUNET_OS_NetworkInterfaceProcessor proc,
                                   void *proc_cls);

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
struct GNUNET_OS_Process *
GNUNET_OS_process_current (void);


/**
 * Sends a signal to the process
 *
 * @param proc pointer to process structure
 * @param sig signal
 * @return 0 on success, -1 on error
 */
int
GNUNET_OS_process_kill (struct GNUNET_OS_Process *proc, int sig);


/**
 * Cleans up process structure contents (OS-dependent) and deallocates it
 *
 * @param proc pointer to process structure
 */
void
GNUNET_OS_process_destroy (struct GNUNET_OS_Process *proc);


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
 * Start a process.
 *
 * @param pipe_control should a pipe be used to send signals to the child?
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param pipe_stderr pipe to use to get error output from child process (or NULL)
 * @param filename name of the binary
 * @param argv NULL-terminated array of arguments to the process
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_vap (int pipe_control,
                             enum GNUNET_OS_InheritStdioFlags std_inheritance,
			     struct GNUNET_DISK_PipeHandle *pipe_stdin,
			     struct GNUNET_DISK_PipeHandle *pipe_stdout,
			     struct GNUNET_DISK_PipeHandle *pipe_stderr,
			     const char *filename,
			     char *const argv[]);


/**
 * Start a process.
 *
 * @param pipe_control should a pipe be used to send signals to the child?
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param pipe_stderr pipe to use to get error output from child process (or NULL)
 * @param filename name of the binary
 * @param ... NULL-terminated list of arguments to the process
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process (int pipe_control,
                         enum GNUNET_OS_InheritStdioFlags std_inheritance,
			 struct GNUNET_DISK_PipeHandle *pipe_stdin,
                         struct GNUNET_DISK_PipeHandle *pipe_stdout,
                         struct GNUNET_DISK_PipeHandle *pipe_stderr,
                         const char *filename, ...);


/**
 * Start a process.
 *
 * @param pipe_control should a pipe be used to send signals to the child?
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param pipe_stderr pipe to use to get error output from child process (or NULL)
 * @param filename name of the binary
 * @param va NULL-terminated list of arguments to the process
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_va (int pipe_control,
                            enum GNUNET_OS_InheritStdioFlags std_inheritance,
			    struct GNUNET_DISK_PipeHandle *pipe_stdin,
                            struct GNUNET_DISK_PipeHandle *pipe_stdout,
                            struct GNUNET_DISK_PipeHandle *pipe_stderr,
                            const char *filename, va_list va);

/**
 * Start a process.
 *
 * @param pipe_control should a pipe be used to send signals to the child?
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param lsocks array of listen sockets to dup systemd-style (or NULL);
 *         must be NULL on platforms where dup is not supported
 * @param filename name of the binary
 * @param argv NULL-terminated list of arguments to the process,
 *             including the process name as the first argument
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_v (int pipe_control,
                           enum GNUNET_OS_InheritStdioFlags std_inheritance,
			   const SOCKTYPE *lsocks,
			   const char *filename,
                           char *const argv[]);


/**
 * Start a process.  This function is similar to the GNUNET_OS_start_process_*
 * except that the filename and arguments can have whole strings which contain
 * the arguments.  These arguments are to be separated by spaces and are parsed
 * in the order they appear.  Arguments containing spaces can be used by
 * quoting them with @em ".
 *
 * @param pipe_control should a pipe be used to send signals to the child?
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param lsocks array of listen sockets to dup systemd-style (or NULL);
 *         must be NULL on platforms where dup is not supported
 * @param filename name of the binary.  It is valid to have the arguments
 *         in this string when they are separated by spaces.
 * @param ... more arguments.  Should be of type `char *`.  It is valid
 *         to have the arguments in these strings when they are separated by
 *         spaces.  The last argument MUST be NULL.
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_s (int pipe_control,
                           unsigned int std_inheritance,
                           const SOCKTYPE * lsocks,
                           const char *filename, ...);


/**
 * Handle to a command action.
 */
struct GNUNET_OS_CommandHandle;


/**
 * Type of a function to process a line of output.
 *
 * @param cls closure
 * @param line line of output from a command, NULL for the end
 */
typedef void (*GNUNET_OS_LineProcessor) (void *cls, const char *line);


/**
 * Stop/kill a command.
 *
 * @param cmd handle to the process
 */
void
GNUNET_OS_command_stop (struct GNUNET_OS_CommandHandle *cmd);


/**
 * Run the given command line and call the given function
 * for each line of the output.
 *
 * @param proc function to call for each line of the output
 * @param proc_cls closure for proc
 * @param timeout when to time out
 * @param binary command to run
 * @param ... arguments to command
 * @return NULL on error
 */
struct GNUNET_OS_CommandHandle *
GNUNET_OS_command_run (GNUNET_OS_LineProcessor proc, void *proc_cls,
                       struct GNUNET_TIME_Relative timeout, const char *binary,
                       ...);


/**
 * Retrieve the status of a process, waiting on him if dead.
 * Nonblocking version.
 *
 * @param proc pointer to process structure
 * @param type status type
 * @param code return code/signal number
 * @return #GNUNET_OK on success, #GNUNET_NO if the process is still running, #GNUNET_SYSERR otherwise
 */
int
GNUNET_OS_process_status (struct GNUNET_OS_Process *proc,
                          enum GNUNET_OS_ProcessStatusType *type,
                          unsigned long *code);


/**
 * Wait for a process to terminate.  The return code is discarded.
 * You must not use #GNUNET_OS_process_status() on the same process
 * after calling this function!  This function is blocking and should
 * thus only be used if the child process is known to have terminated
 * or to terminate very soon.
 *
 * @param proc pointer to process structure of the process to wait for
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_OS_process_wait (struct GNUNET_OS_Process *proc);


/**
 * Connects this process to its parent via pipe;
 * essentially, the parent control handler will read signal numbers
 * from the #GNUNET_OS_CONTROL_PIPE (as given in an environment
 * variable) and raise those signals.
 *
 * @param cls closure (unused)
 */
void
GNUNET_OS_install_parent_control_handler (void *cls);


/**
 * Check whether an executable exists and possibly
 * if the suid bit is set on the file.
 * Attempts to find the file using the current
 * PATH environment variable as a search path.
 *
 * @param binary the name of the file to check.
 *        W32: must not have an .exe suffix.
 * @param check_suid input true if the binary should be checked for SUID (*nix)
 *        W32: checks if the program has sufficient privileges by executing this
 *             binary with the -d flag. -d omits a programs main loop and only
 *             executes all privileged operations in an binary.
 * @param params parameters used for w32 privilege checking (can be NULL for != w32, or when not checking for suid/permissions )
 * @return #GNUNET_YES if the file is SUID (*nix) or can be executed with current privileges (W32),
 *         #GNUNET_NO if not SUID (but binary exists),
 *         #GNUNET_SYSERR on error (no such binary or not executable)
 */
int
GNUNET_OS_check_helper_binary (const char *binary,
                               int check_suid,
                               const char *params);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_OS_LIB_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_os_lib.h */
