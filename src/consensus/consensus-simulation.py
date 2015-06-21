#!/usr/bin/python
# This file is part of GNUnet
# (C) 2013 Christian Grothoff (and other contributing authors)
#
# GNUnet is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 2, or (at your
# option) any later version.
#
# GNUnet is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNUnet; see the file COPYING.  If not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

import argparse
import random
from math import ceil,log,floor

def bsc(n):
  """ count the bits set in n"""
  l = n.bit_length()
  c = 0
  x = 1
  for _ in range(0, l):
    if n & x:
      c = c + 1
    x = x << 1
  return c

def simulate(k, n, verbose):
  assert k < n
  largest_arc = int(2**ceil(log(n, 2))) / 2
  num_ghosts = (2 * largest_arc) - n
  if verbose:
    print "we have", num_ghosts, "ghost peers"
  # n.b. all peers with idx<k are evil
  peers = range(n)
  info = [1 << x for x in xrange(n)]
  def done_p():
    for x in xrange(k, n):
      if bsc(info[x]) < n-k:
        return False
    return True
  rounds = 0
  while not done_p():
    if verbose:
      print "-- round --"
    arc = 1
    while arc <= largest_arc:
      if verbose:
        print "-- subround --"
      new_info = [x for x in info]
      for peer_physical in xrange(n):
        peer_logical = peers[peer_physical]
        peer_type = None
        partner_logical = (peer_logical + arc) % n
        partner_physical = peers.index(partner_logical)
        if peer_physical < k or partner_physical < k:
          if verbose:
            print "bad peer in connection", peer_physical, "--", partner_physical
          continue
        if peer_logical & arc == 0:
          # we are outgoing
          if verbose:
            print peer_physical, "connects to", partner_physical
          peer_type = "outgoing"
          if peer_logical < num_ghosts:
            # we have a ghost, check if the peer who connects
            # to our ghost is actually outgoing
            ghost_partner_logical = (peer_logical - arc) % n
            if ghost_partner_logical & arc == 0:
              peer_type = peer_type + ", ghost incoming"
          new_info[peer_physical] = new_info[peer_physical] | info[peer_physical] | info[partner_physical]
          new_info[partner_physical] = new_info[partner_physical] | info[peer_physical] | info[partner_physical]
        else:
          peer_type = "incoming"
        if verbose > 1:
          print "type of", str(peer_physical) + ":", peer_type
      info = new_info
      arc = arc << 1;
    rounds = rounds + 1
    random.shuffle(peers)
  return rounds

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("k", metavar="k", type=int, help="#(bad peers)")
  parser.add_argument("n", metavar="n", type=int, help="#(all peers)")
  parser.add_argument("r", metavar="r", type=int, help="#(rounds)")
  parser.add_argument('--verbose', '-v', action='count')

  args = parser.parse_args()
  sum = 0.0;
  for n in xrange (0, args.r):
    sum += simulate(args.k, args.n, args.verbose)
  print sum / args.r;


