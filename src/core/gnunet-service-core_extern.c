/* code that should be moved outside of core/ entirely */

/**
 * Merge the given performance data with the data we currently
 * track for the given neighbour.
 *
 * @param n neighbour
 * @param ats new performance data
 * @param ats_count number of records in ats
 */
static void
update_neighbour_performance (struct Neighbour *n,
                              const struct GNUNET_TRANSPORT_ATS_Information
                              *ats, uint32_t ats_count)
{
  uint32_t i;
  unsigned int j;

  if (ats_count == 0)
    return;
  for (i = 0; i < ats_count; i++)
  {
    for (j = 0; j < n->ats_count; j++)
    {
      if (n->ats[j].type == ats[i].type)
      {
        n->ats[j].value = ats[i].value;
        break;
      }
    }
    if (j == n->ats_count)
    {
      GNUNET_array_append (n->ats, n->ats_count, ats[i]);
    }
  }
}



