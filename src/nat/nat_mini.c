/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file nat/nat_mini.c
 * @brief functions for interaction with miniupnp
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_nat_lib.h"
#include "nat.h"

/**
 * How long do we give upnpc to create a mapping?
 */
#define MAP_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)


/**
 * How long do we give upnpc to remove a mapping?
 */
#define UNMAP_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * How often do we check for changes in the mapping?
 */
#define MAP_REFRESH_FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)


/**
 * Try to get the external IPv4 address of this peer.
 * Note: calling this function may block this process
 * for a few seconds (!).
 *
 * @param addr address to set
 * @return GNUNET_OK on success,
 *         GNUNET_NO if the result is questionable,
 *         GNUNET_SYSERR on error
 */
int
GNUNET_NAT_mini_get_external_ipv4 (struct in_addr *addr)
{
  struct GNUNET_OS_Process *eip;
  struct GNUNET_DISK_PipeHandle *opipe;
  const struct GNUNET_DISK_FileHandle *r;
  size_t off;
  char buf[17];
  ssize_t ret;
  int iret;

  opipe = GNUNET_DISK_pipe (GNUNET_YES,
			    GNUNET_NO,
			    GNUNET_YES);
  if (NULL == opipe)
    return GNUNET_SYSERR;
  eip = GNUNET_OS_start_process (NULL,
				 opipe,
				 "external-ip",
				 "external-ip", NULL);
  if (NULL == eip)
    {
      GNUNET_DISK_pipe_close (opipe);
      return GNUNET_SYSERR;
    }
  GNUNET_DISK_pipe_close_end (opipe, GNUNET_DISK_PIPE_END_WRITE);
  iret = GNUNET_SYSERR;
  r = GNUNET_DISK_pipe_handle (opipe,
			       GNUNET_DISK_PIPE_END_READ);
  off = 0;
  while (0 < (ret = GNUNET_DISK_file_read (r, &buf[off], sizeof (buf)-off)))
    off += ret;
  if ( (off > 7) &&    
       (buf[off-1] == '\n') )    
    {
      buf[off-1] = '\0';
      if (1 == inet_pton (AF_INET, buf, addr))
	{
	  if (addr->s_addr == 0)
	    iret = GNUNET_NO; /* got 0.0.0.0 */
	  iret = GNUNET_OK;
	}
    }
  (void) GNUNET_OS_process_kill (eip, SIGKILL);
  GNUNET_OS_process_close (eip);
  GNUNET_DISK_pipe_close (opipe);
  return iret; 
}


/**
 * Handle to a mapping created with upnpc.
 */ 
struct GNUNET_NAT_MiniHandle
{

  /**
   * Function to call on mapping changes.
   */
  GNUNET_NAT_AddressCallback ac;

  /**
   * Closure for 'ac'.
   */
  void *ac_cls;

  /**
   * Command used to install the map.
   */
  struct GNUNET_OS_CommandHandle *map_cmd;

  /**
   * Command used to refresh our map information.
   */
  struct GNUNET_OS_CommandHandle *refresh_cmd;

  /**
   * Command used to remove the mapping.
   */
  struct GNUNET_OS_CommandHandle *unmap_cmd;

  /**
   * Our current external mapping (if we have one).
   */
  struct sockaddr_in current_addr;

  /**
   * We check the mapping periodically to see if it
   * still works.  This task triggers the check.
   */
  GNUNET_SCHEDULER_TaskIdentifier refresh_task;

  /**
   * Are we mapping TCP or UDP?
   */
  int is_tcp;

  /**
   * Did we succeed with creating a mapping?
   */
  int did_map;

  /**
   * Which port are we mapping?
   */
  uint16_t port;

};


/**
 * Run upnpc -l to find out if our mapping changed.
 *
 * @param cls the 'struct GNUNET_NAT_MiniHandle'
 * @param tc scheduler context
 */
static void
do_refresh (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Process the output from 'upnpc -l' to see if our
 * external mapping changed.  If so, do the notifications.
 *
 * @param cls the 'struct GNUNET_NAT_MiniHandle'
 * @param line line of output, NULL at the end
 */
static void
process_refresh_output (void *cls,
			const char *line)
{
  struct GNUNET_NAT_MiniHandle *mini = cls;

  if (NULL == line)
    {
      GNUNET_OS_command_stop (mini->refresh_cmd);
      mini->refresh_cmd = NULL;
      mini->refresh_task = GNUNET_SCHEDULER_add_delayed (MAP_REFRESH_FREQ,
							 &do_refresh,
							 mini);
      return;
    }
  /* FIXME: parse 'line' */
  fprintf (stderr,
	   "Refresh output: `%s'\n",
	   line);
}


/**
 * Run upnpc -l to find out if our mapping changed.
 *
 * @param cls the 'struct GNUNET_NAT_MiniHandle'
 * @param tc scheduler context
 */
static void
do_refresh (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_MiniHandle *mini = cls;

  mini->refresh_task = GNUNET_SCHEDULER_NO_TASK;
  mini->refresh_cmd = GNUNET_OS_command_run (&process_refresh_output,
					     mini,
					     MAP_TIMEOUT,
					     "upnpc",
					     "upnpc",
					     "-l",
					     NULL);
}


/**
 * Process the output from the 'upnpc -r' command.
 *
 * @param cls the 'struct GNUNET_NAT_MiniHandle'
 * @param line line of output, NULL at the end
 */
static void
process_map_output (void *cls,
		    const char *line)
{
  struct GNUNET_NAT_MiniHandle *mini = cls;
  const char *ipaddr;
  char *ipa;
  const char *pstr;
  unsigned int port;

  if (NULL == line)
    {
      GNUNET_OS_command_stop (mini->map_cmd);
      mini->map_cmd = NULL;
      if (mini->did_map == GNUNET_YES)
	mini->refresh_task = GNUNET_SCHEDULER_add_delayed (MAP_REFRESH_FREQ,
							   &do_refresh,
							   mini);
      return;
    }
  /*
    The upnpc output we're after looks like this:

     "external 87.123.42.204:3000 TCP is redirected to internal 192.168.2.150:3000"
  */
  if ( (NULL == (ipaddr = strstr (line, " "))) ||
       (NULL == (pstr = strstr (ipaddr, ":"))) ||
       (1 != sscanf (pstr + 1, "%u", &port)) )
    {
      fprintf (stderr,
	       "Skipping output `%s'\n",
	       line);
      return; /* skip line */
    }
  ipa = GNUNET_strdup (ipaddr + 1);
  strstr (ipa, ":")[0] = '\0';
  if (1 != inet_pton (AF_INET,
		      ipa, 
		      &mini->current_addr.sin_addr))
    {
      GNUNET_free (ipa);
      fprintf (stderr,
	       "Skipping output `%s'\n",
	       line);
      return; /* skip line */
    }
  GNUNET_free (ipa);	      

  mini->current_addr.sin_port = htons (port);
  mini->current_addr.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  mini->current_addr.sin_len = sizeof (struct sockaddr_in);
#endif
  mini->did_map = GNUNET_YES;
  mini->ac (mini->ac_cls, GNUNET_YES,
	    (const struct sockaddr*) &mini->current_addr,
	    sizeof (mini->current_addr));
}


/**
 * Start mapping the given port using (mini)upnpc.  This function
 * should typically not be used directly (it is used within the
 * general-purpose 'GNUNET_NAT_register' code).  However, it can be
 * used if specifically UPnP-based NAT traversal is to be used or
 * tested.
 * 
 * @param port port to map
 * @param is_tcp GNUNET_YES to map TCP, GNUNET_NO for UDP
 * @param ac function to call with mapping result
 * @param ac_cls closure for 'ac'
 * @return NULL on error
 */
struct GNUNET_NAT_MiniHandle *
GNUNET_NAT_mini_map_start (uint16_t port,
			   int is_tcp,
			   GNUNET_NAT_AddressCallback ac,
			   void *ac_cls)
{
  struct GNUNET_NAT_MiniHandle *ret;
  char pstr[6];

  ret = GNUNET_malloc (sizeof (struct GNUNET_NAT_MiniHandle));
  ret->ac = ac;
  ret->ac_cls = ac_cls;
  ret->is_tcp = is_tcp;
  ret->port = port;
  GNUNET_snprintf (pstr, sizeof (pstr),
		   "%u",
		   (unsigned int) port);
  ret->map_cmd = GNUNET_OS_command_run (&process_map_output,
					ret,
					MAP_TIMEOUT,
					"upnpc",
					"upnpc",
					"-r", pstr, 
					is_tcp ? "tcp" : "udp",
					NULL);
  
  return ret;
}


/**
 * Process output from our 'unmap' command.
 *
 * @param cls the 'struct GNUNET_NAT_MiniHandle'
 * @param line line of output, NULL at the end
 */
static void
process_unmap_output (void *cls,
		      const char *line)
{
  struct GNUNET_NAT_MiniHandle *mini = cls;

  if (NULL == line)
    {
      GNUNET_OS_command_stop (mini->unmap_cmd);
      mini->unmap_cmd = NULL;
      GNUNET_free (mini);
      return;
    }
  /* we don't really care about the output... */
}


/**
 * Remove a mapping created with (mini)upnpc.  Calling
 * this function will give 'upnpc' 1s to remove tha mapping,
 * so while this function is non-blocking, a task will be
 * left with the scheduler for up to 1s past this call.
 * 
 * @param mini the handle
 */
void
GNUNET_NAT_mini_map_stop (struct GNUNET_NAT_MiniHandle *mini)
{
  char pstr[6];

  if (! mini->did_map)
    {
      if (mini->map_cmd != NULL)
	{
	  GNUNET_OS_command_stop (mini->map_cmd);
	  mini->map_cmd = NULL;
	}
      GNUNET_free (mini);
      return;
    }
  if (GNUNET_SCHEDULER_NO_TASK != mini->refresh_task)
    {
      GNUNET_SCHEDULER_cancel (mini->refresh_task);
      mini->refresh_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (mini->refresh_cmd != NULL)
    {
      GNUNET_OS_command_stop (mini->refresh_cmd);
      mini->refresh_cmd = NULL;
    }
  mini->ac (mini->ac_cls, GNUNET_NO,
	    (const struct sockaddr*) &mini->current_addr,
	    sizeof (mini->current_addr));
  GNUNET_snprintf (pstr, sizeof (pstr),
		   "%u",
		   (unsigned int) mini->port);
  mini->unmap_cmd = GNUNET_OS_command_run (&process_unmap_output,
					   mini,
					   UNMAP_TIMEOUT,
					   "upnpc",
					   "upnpc",
					   "-d", pstr, 
					   mini->is_tcp ? "tcp" : "udp",
					   NULL);
}


/* end of nat_mini.c */
