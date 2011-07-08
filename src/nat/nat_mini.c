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



/* end of nat_mini.c */
