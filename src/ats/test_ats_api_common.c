/*
     This file is part of GNUnet.
     Copyright (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
#define BIG_M_STRING "unlimited"


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
  GNUNET_free_non_null (dest->plugin);
  dest->plugin = NULL;
  GNUNET_free_non_null (dest->addr);
  dest->addr = NULL;
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
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid address length\n");
      return GNUNET_SYSERR;

  }
  else if (0 != memcmp (address1->address, address2->address, address2->address_length))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid address\n");
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
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "ATS type `%s'\n",
                        GNUNET_ATS_print_property_type (type1));
            val1 = ntohl(ats_is[c_o].value);
            val2 = ntohl(ats_should[c_i].value);
            if (val1 != val2)
            {
                GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                            "ATS value `%s' not equal: %u != %u\n",
                            GNUNET_ATS_print_property_type (type1),
                            val1, val2);
                res = GNUNET_SYSERR;
            }
            else
            {
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          "ATS value `%s' equal: %u == %u\n",
                          GNUNET_ATS_print_property_type (type1),
                          val1, val2);
            }
        }
    }
  }
  return res;
}


/**
 * Load quotas for networks from configuration
 *
 * @param cfg configuration handle
 * @param out_dest where to write outbound quotas
 * @param in_dest where to write inbound quotas
 * @param dest_length length of inbound and outbound arrays
 * @return number of networks loaded
 */
unsigned int
load_quotas (const struct GNUNET_CONFIGURATION_Handle *cfg,
						 unsigned long long *out_dest,
						 unsigned long long *in_dest,
						 int dest_length)
{
  char *entry_in = NULL;
  char *entry_out = NULL;
  char *quota_out_str;
  char *quota_in_str;
  int c;
  int res;

  for (c = 0; (c < GNUNET_ATS_NetworkTypeCount) && (c < dest_length); c++)
  {
    in_dest[c] = 0;
    out_dest[c] = 0;
    GNUNET_asprintf (&entry_out,
                     "%s_QUOTA_OUT",
                     GNUNET_ATS_print_network_type (c));
    GNUNET_asprintf (&entry_in,
                     "%s_QUOTA_IN",
                     GNUNET_ATS_print_network_type (c));

    /* quota out */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", entry_out, &quota_out_str))
    {
      res = GNUNET_NO;
      if (0 == strcmp(quota_out_str, BIG_M_STRING))
      {
        out_dest[c] = GNUNET_ATS_MaxBandwidth;
        res = GNUNET_YES;
      }
      if ((GNUNET_NO == res) && (GNUNET_OK == GNUNET_STRINGS_fancy_size_to_bytes (quota_out_str, &out_dest[c])))
        res = GNUNET_YES;
      if ((GNUNET_NO == res) && (GNUNET_OK == GNUNET_CONFIGURATION_get_value_number (cfg, "ats", entry_out,  &out_dest[c])))
         res = GNUNET_YES;

      if (GNUNET_NO == res)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Could not load quota for network `%s':  `%s', assigning default bandwidth %llu\n"),
                    GNUNET_ATS_print_network_type (c),
                    quota_out_str,
                    GNUNET_ATS_DefaultBandwidth);
          out_dest[c] = GNUNET_ATS_DefaultBandwidth;
      }
      else
      {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Outbound quota configure for network `%s' is %llu\n",
                      GNUNET_ATS_print_network_type (c),
                      out_dest[c]);
      }
      GNUNET_free (quota_out_str);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("No outbound quota configured for network `%s', assigning default bandwidth %llu\n"),
                  GNUNET_ATS_print_network_type (c),
                  GNUNET_ATS_DefaultBandwidth);
      out_dest[c] = GNUNET_ATS_DefaultBandwidth;
    }

    /* quota in */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", entry_in, &quota_in_str))
    {
      res = GNUNET_NO;
      if (0 == strcmp(quota_in_str, BIG_M_STRING))
      {
        in_dest[c] = GNUNET_ATS_MaxBandwidth;
        res = GNUNET_YES;
      }
      if ((GNUNET_NO == res) && (GNUNET_OK == GNUNET_STRINGS_fancy_size_to_bytes (quota_in_str, &in_dest[c])))
        res = GNUNET_YES;
      if ((GNUNET_NO == res) && (GNUNET_OK == GNUNET_CONFIGURATION_get_value_number (cfg, "ats", entry_in,  &in_dest[c])))
         res = GNUNET_YES;

      if (GNUNET_NO == res)
      {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("Could not load quota for network `%s':  `%s', assigning default bandwidth %llu\n"),
                      GNUNET_ATS_print_network_type (c),
                      quota_in_str,
                      GNUNET_ATS_DefaultBandwidth);
          in_dest[c] = GNUNET_ATS_DefaultBandwidth;
      }
      else
      {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Inbound quota configured for network `%s' is %llu\n",
                      GNUNET_ATS_print_network_type (c),
                      in_dest[c]);
      }
      GNUNET_free (quota_in_str);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("No outbound quota configure for network `%s', assigning default bandwidth %llu\n"),
                  GNUNET_ATS_print_network_type (c),
                  GNUNET_ATS_DefaultBandwidth);
      out_dest[c] = GNUNET_ATS_DefaultBandwidth;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Loaded quota for network `%s' (in/out): %llu %llu\n",
                GNUNET_ATS_print_network_type (c),
                in_dest[c],
                out_dest[c]);
    GNUNET_free (entry_out);
    GNUNET_free (entry_in);
  }
  return GNUNET_ATS_NetworkTypeCount;
}

/**
 * Create a ATS_address with the given information
 * @param peer peer
 * @param plugin_name plugin
 * @param plugin_addr address
 * @param plugin_addr_len address length
 * @param session_id session
 * @return the ATS_Address
 */
struct ATS_Address *
create_address (const struct GNUNET_PeerIdentity *peer,
                const char *plugin_name,
                const void *plugin_addr, size_t plugin_addr_len,
                uint32_t session_id)
{
  struct ATS_Address *aa = NULL;

  aa = GNUNET_malloc (sizeof (struct ATS_Address) + plugin_addr_len + strlen (plugin_name) + 1);
  aa->peer = *peer;
  aa->addr_len = plugin_addr_len;
  aa->addr = &aa[1];
  aa->plugin = (char *) &aa[1] + plugin_addr_len;
  memcpy (&aa[1], plugin_addr, plugin_addr_len);
  memcpy (aa->plugin, plugin_name, strlen (plugin_name) + 1);
  aa->session_id = session_id;
  return aa;
}

/* end of file test_ats_api_common.c */
