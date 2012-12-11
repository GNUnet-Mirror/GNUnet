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
 * @file ats/test_ats_api_common.c
 * @brief shared functions for ats test
 * @author Christian Grothoff
 * @author Matthias Wachs
 */

#include "test_ats_api_common.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

#define PEERID0 "2AK99KD8RM9UA9LC3QKA0IQ5UBFC0FBB50EBGCFQT8448DGGACNAC4CJQDD1CPFS494O41U88DJD1FLIG8VA5CQR9IN4L96GP104MVO"
#define PEERID1 "5ED7I0AR3MSTAL7FQN04S22E0EQ3CR9RLASCDLVMM1BNFPUPTCT46DLKNJ4DACASJ6U0DR5J8S3R2UJL49682JS7MOVRAB8P8A4PJH0"

void
create_test_address (struct Test_Address *dest, char * plugin, void *session, void *addr, size_t addrlen)
{

  dest->plugin = GNUNET_strdup (plugin);
  dest->session = session;
  if (addrlen > 0)
  {
    dest->addr = GNUNET_malloc (addrlen);
    memcpy (dest->addr, addr, addrlen);
  }
  else
      dest->addr = NULL;
  dest->addr_len = addrlen;
}

void
free_test_address (struct Test_Address *dest)
{
  GNUNET_free (dest->plugin);
  if (NULL != dest->addr)
    GNUNET_free (dest->addr);
}

int
compare_addresses (const struct GNUNET_HELLO_Address *address1, void *session1,
                   const struct GNUNET_HELLO_Address *address2, void *session2)
{
  if (0 != memcmp (&address1->peer, &address2->peer, sizeof (struct GNUNET_PeerIdentity)))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid peer id'\n");
      return GNUNET_SYSERR;
  }
  if (0 != strcmp (address1->transport_name, address2->transport_name))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid plugin'\n");
      return GNUNET_SYSERR;
  }
  if (address1->address_length != address2->address_length)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid address length'\n");
      return GNUNET_SYSERR;

  }
  else if (0 != memcmp (address1->address, address2->address, address2->address_length))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid address'\n");
      return GNUNET_SYSERR;
  }
  if (session1 != session2)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid session1 %p vs session2 %p'\n",
                  session1, session2);
      return GNUNET_SYSERR;

  }
  return GNUNET_OK;
}


int
compare_ats (const struct GNUNET_ATS_Information *ats_is, uint32_t ats_count_is,
             const struct GNUNET_ATS_Information *ats_should, uint32_t ats_count_should)
{
  unsigned int c_o;
  unsigned int c_i;
  char *prop[] = GNUNET_ATS_PropertyStrings;
  uint32_t type1;
  uint32_t type2;
  uint32_t val1;
  uint32_t val2;
  int res = GNUNET_OK;

  for (c_o = 0; c_o < ats_count_is; c_o++)
  {
    for (c_i = 0; c_i < ats_count_should; c_i++)
    {
        type1 = ntohl(ats_is[c_o].type);
        type2 = ntohl(ats_should[c_i].type);
        if (type1 == type2)
        {
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS type `%s'\n",
                        prop[type1]);
            val1 = ntohl(ats_is[c_o].value);
            val2 = ntohl(ats_should[c_i].value);
            if (val1 != val2)
            {
                GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ATS value `%s' not equal: %u != %u\n",
                            prop[type1],
                            val1, val2);
                res = GNUNET_SYSERR;
            }
            else
            {
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS value `%s' equal: %u == %u\n",
                          prop[type1],
                          val1, val2);
            }
        }
    }
  }
  return res;
}


/* end of file test_ats_api_common.c */
