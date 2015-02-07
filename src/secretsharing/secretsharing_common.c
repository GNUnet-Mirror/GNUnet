/*
     This file is part of GNUnet.
     Copyright (C) 2014 Christian Grothoff (and other contributing authors)

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

#include "secretsharing.h"

/**
 * Read a share from its binary representation.
 *
 * @param data Binary representation of the share.
 * @param len Length of @a data.
 * @param[out] readlen Number of bytes read,
 *             ignored if NULL.
 * @return The share, or NULL on error.
 */
struct GNUNET_SECRETSHARING_Share *
GNUNET_SECRETSHARING_share_read (const void *data,
                                 size_t len,
                                 size_t *readlen)
{
  struct GNUNET_SECRETSHARING_Share *share;
  const struct GNUNET_SECRETSHARING_ShareHeaderNBO *sh = data;
  char *p;
  size_t n;
  uint16_t payload_size;

  payload_size = ntohs (sh->num_peers) *
      (sizeof (uint16_t) + sizeof (struct GNUNET_SECRETSHARING_FieldElement) +
       sizeof (struct GNUNET_PeerIdentity));

  if (NULL != readlen)
    *readlen = payload_size + sizeof *sh;

  share = GNUNET_malloc (sizeof *share);

  share->threshold = ntohs (sh->threshold);
  share->num_peers = ntohs (sh->num_peers);
  share->my_peer = ntohs (sh->my_peer);

  share->my_share = sh->my_share;
  share->public_key = sh->public_key;

  p = (void *) &sh[1];

  n = share->num_peers * sizeof (struct GNUNET_PeerIdentity);
  share->peers = GNUNET_malloc (n);
  memcpy (share->peers, p, n);
  p += n;

  n = share->num_peers * sizeof (struct GNUNET_SECRETSHARING_FieldElement);
  share->sigmas = GNUNET_malloc (n);
  memcpy (share->sigmas, p, n);
  p += n;

  n = share->num_peers * sizeof (uint16_t);
  share->original_indices = GNUNET_malloc (n);
  memcpy (share->original_indices, p, n);

  return share;
}


/**
 * Convert a share to its binary representation.
 * Can be called with a NULL @a buf to get the size of the share.
 *
 * @param share Share to write.
 * @param buf Buffer to write to.
 * @param buflen Number of writable bytes in @a buf.
 * @param[out] writelen Pointer to store number of bytes written,
 *             ignored if NULL.
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure.
 */
int
GNUNET_SECRETSHARING_share_write (const struct GNUNET_SECRETSHARING_Share *share,
                                  void *buf, size_t buflen, size_t *writelen)
{
  uint16_t payload_size;
  struct GNUNET_SECRETSHARING_ShareHeaderNBO *sh;
  char *p;
  int n;

  payload_size = share->num_peers *
      (sizeof (uint16_t) + sizeof (struct GNUNET_SECRETSHARING_FieldElement) +
       sizeof (struct GNUNET_PeerIdentity));

  if (NULL != writelen)
    *writelen = payload_size + sizeof (struct GNUNET_SECRETSHARING_ShareHeaderNBO);

  /* just a query for the writelen */
  if (buf == NULL)
    return GNUNET_OK;

  /* wrong buffer size */
  if (buflen < payload_size + sizeof (struct GNUNET_SECRETSHARING_ShareHeaderNBO))
    return GNUNET_SYSERR;

  sh = buf;

  sh->threshold = htons (share->threshold);
  sh->num_peers = htons (share->num_peers);
  sh->my_peer = htons (share->my_peer);

  sh->my_share = share->my_share;
  sh->public_key = share->public_key;

  p = (void *) &sh[1];

  n = share->num_peers * sizeof (struct GNUNET_PeerIdentity);
  memcpy (p, share->peers, n);
  p += n;

  n = share->num_peers * sizeof (struct GNUNET_SECRETSHARING_FieldElement);
  memcpy (p, share->sigmas, n);
  p += n;

  n = share->num_peers * sizeof (uint16_t);
  memcpy (p, share->original_indices, n);

  return GNUNET_OK;
}


void
GNUNET_SECRETSHARING_share_destroy (struct GNUNET_SECRETSHARING_Share *share)
{
  GNUNET_free (share->original_indices);
  share->original_indices = NULL;
  GNUNET_free (share->sigmas);
  share->sigmas = NULL;
  GNUNET_free (share->peers);
  share->peers = NULL;
  GNUNET_free (share);
}


