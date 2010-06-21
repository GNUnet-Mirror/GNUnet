/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/server_mst.c
 * @brief convenience functions for handling inbound message buffers
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_connection_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"


/**
 * Handle to a message stream tokenizer.
 */
struct GNUNET_SERVER_MessageStreamTokenizer
{

  size_t maxbuf;

  size_t off;

  void *client_identity;

  GNUNET_SERVER_MessageTokenizerCallback cb;

  void *cb_cls;

  /**
   * Beginning of the buffer.
   */
  struct GNUNET_MessageHeader hdr;

};



/**
 * Create a message stream tokenizer.
 *
 * @param maxbuf maximum message size to support (typically
 *    GNUNET_SERVER_MAX_MESSAGE_SIZE)
 * @param client_identity ID of client for which this is a buffer,
 *        can be NULL (will be passed back to 'cb')
 * @return handle to tokenizer
 */
struct GNUNET_SERVER_MessageStreamTokenizer *
GNUNET_SERVER_mst_create (size_t maxbuf,
			  void *client_identity,
			  GNUNET_SERVER_MessageTokenizerCallback cb,
			  void *cb_cls)
{
  struct GNUNET_SERVER_MessageStreamTokenizer *ret;

  ret = GNUNET_malloc (maxbuf + sizeof (struct GNUNET_SERVER_MessageStreamTokenizer));
  ret->maxbuf = maxbuf;
  ret->client_identity = client_identity;
  ret->cb = cb;
  ret->cb_cls = cb_cls;
  return ret;
}


/**
 * Add incoming data to the receive buffer and call the
 * callback for all complete messages.
 *
 * @param mst tokenizer to use
 * @param buf input data to add
 * @param size number of bytes in buf
 * @param purge should any excess bytes in the buffer be discarded 
 *       (i.e. for packet-based services like UDP)
 * @return GNUNET_NO if the data stream is corrupt 
 *         GNUNET_SYSERR if the data stream is corrupt beyond repair
 */
int
GNUNET_SERVER_mst_receive (struct GNUNET_SERVER_MessageStreamTokenizer *mst,
			   const char *buf,
			   size_t size,
			   int purge)
{
  const struct GNUNET_MessageHeader *hdr;
  size_t delta;
  size_t want;
  char *ibuf;
  int need_align;
  unsigned long offset;

  ibuf = (char*) &mst->hdr;
  if (mst->off > 0)
    {
    do_align:
      if (mst->off < sizeof (struct GNUNET_MessageHeader))
	{
	  delta = GNUNET_MIN (sizeof (struct GNUNET_MessageHeader) - mst->off,
			      size);
	  memcpy (&ibuf[mst->off],
		  buf,
		  delta);
	  mst->off += delta;
	  buf += delta;
	  size -= delta;
	}
      if (mst->off < sizeof (struct GNUNET_MessageHeader))
	{
	  if (purge)
	    mst->off = 0;    
	  return GNUNET_OK;
	}
      want = ntohs (mst->hdr.size);
      if (want < sizeof (struct GNUNET_MessageHeader))
	{
	  GNUNET_break_op (0);
	  if (purge)
	    return GNUNET_NO;
	  return GNUNET_SYSERR;
	}
      if (want < mst->off)
	{
	  delta = GNUNET_MIN (want - mst->off,
			      size);
	  memcpy (&ibuf[mst->off],
		  buf,
		  delta);
	  mst->off += delta;
	  buf += delta;
	  size -= delta;
	}
      if (want < mst->off)
	{
	  if (purge)
	    mst->off = 0;    
	  return GNUNET_OK;
	}
      mst->cb (mst->cb_cls, mst->client_identity, &mst->hdr);
      mst->off = 0;
    }
  while (size > 0)
    {
      if (size < sizeof (struct GNUNET_MessageHeader))
	break;
      offset = (unsigned long) buf;
#if HAVE_UNALIGNED_64_ACCESS
      need_align = (0 != offset % 4) ? GNUNET_YES : GNUNET_NO;
#else
      need_align = (0 != offset % 8) ? GNUNET_YES : GNUNET_NO;
#endif
      if (GNUNET_NO == need_align)
	{
	  /* can try to do zero-copy */
	  hdr = (const struct GNUNET_MessageHeader *) buf;
	  want = ntohs (hdr->size);
	  if (size < want)
	    break; /* or not, buffer incomplete... */
	  mst->cb (mst->cb_cls, mst->client_identity, hdr);
	  buf += want;
	  size -= want;
	}
      else
	{
	  /* yes, we go a bit more spagetti than usual here */
	  goto do_align;
	}
    }
  if ( (size > 0) && (! purge) )
    {
      memcpy (&mst->hdr, buf, size);
      mst->off = size;
      size = 0;
    }
  if (purge)
    mst->off = 0;    
  return GNUNET_OK;
}


/**
 * Destroys a tokenizer.
 *
 * @param mst tokenizer to destroy
 */
void
GNUNET_SERVER_mst_destroy (struct GNUNET_SERVER_MessageStreamTokenizer *mst)
{
  GNUNET_free (mst);
}



/* end of server_mst.c */
