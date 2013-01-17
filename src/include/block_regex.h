/*
     This file is part of GNUnet.
     (C) 2012,2013 Christian Grothoff (and other contributing authors)

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
 * @file include/block_regex.h
 * @brief regex block formats
 * @author Bartlomiej Polot
 */
#ifndef BLOCK_REGEX_H
#define BLOCK_REGEX_H

#ifdef __cplusplus
extern "C"
{
#if 0
  /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include <stdint.h>


/**
 * @brief A RegexBlock contains one or more of this struct in the payload.
 */
struct RegexEdge
{
      /**
       * Destination of this edge.
       */
    struct GNUNET_HashCode key;

      /**
       * Length of the token towards the new state.
       */
    unsigned int n_token;

    /* char token[n_token] */
};

/**
 * @brief Block to announce a regex state.
 */
struct RegexBlock
{
      /**
       * The key of the state.
       */
    struct GNUNET_HashCode key;

      /**
       * Length of the proof regex string.
       */
    unsigned int n_proof;

      /**
       * Numer of edges parting from this state.
       */
    unsigned int n_edges;

      /**
       * Is this state an accepting state?
       */
    int accepting;

    /* char proof[n_proof] */
    /* struct RegexEdge edges[n_edges] */
};

/**
 * @brief Block to announce a peer accepting a state.
 */
struct RegexAccept
{
      /**
       * The key of the state.
       */
    struct GNUNET_HashCode key;

      /**
       * Length of the proof regex string.
       * FIXME necessary???
       * already present in the leading MeshRegexBlock
       */
    // unsigned int n_proof;

      /**
       * The identity of the peer accepting the state
       */
    struct GNUNET_PeerIdentity id;

};

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif