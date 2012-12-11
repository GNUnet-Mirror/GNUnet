/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/test_ats_api_common.h
 * @brief shared definitions for ats testcases
 * @author Christian Grothoff
 * @author Matthias Wachs
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_ats_service.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

#define PEERID0 "2AK99KD8RM9UA9LC3QKA0IQ5UBFC0FBB50EBGCFQT8448DGGACNAC4CJQDD1CPFS494O41U88DJD1FLIG8VA5CQR9IN4L96GP104MVO"
#define PEERID1 "5ED7I0AR3MSTAL7FQN04S22E0EQ3CR9RLASCDLVMM1BNFPUPTCT46DLKNJ4DACASJ6U0DR5J8S3R2UJL49682JS7MOVRAB8P8A4PJH0"

struct Test_Address
{
  char *plugin;
  size_t plugin_len;

  void *addr;
  size_t addr_len;

  struct GNUNET_ATS_Information *ats;
  int ats_count;

  void *session;
};

struct PeerContext
{
  struct GNUNET_PeerIdentity id;

  struct Test_Address *addr;

  unsigned long long bw_out_assigned;

  unsigned long long bw_in_assigned;
};

void
free_test_address (struct Test_Address *dest);

void
create_test_address (struct Test_Address *dest, char * plugin, void *session, void *addr, size_t addrlen);

int
compare_addresses (const struct GNUNET_HELLO_Address *address1, void *session1,
                   const struct GNUNET_HELLO_Address *address2, void *session2);

int
compare_ats (const struct GNUNET_ATS_Information *ats_is, uint32_t ats_count_is,
             const struct GNUNET_ATS_Information *ats_should, uint32_t ats_count_should);

/* end of file test_ats_api_common.h */
