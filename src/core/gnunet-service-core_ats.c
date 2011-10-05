
/**
 * How much inbound bandwidth are we supposed to be using per second?
 */
static unsigned long long bandwidth_target_in_bps;

/**
 * How much outbound bandwidth are we supposed to be using per second?
 */
static unsigned long long bandwidth_target_out_bps;



/**
 * Schedule the task that will recalculate the bandwidth
 * quota for this peer (and possibly force a disconnect of
 * idle peers by calculating a bandwidth of zero).
 */
static void
schedule_quota_update (struct Neighbour *n)
{
  GNUNET_assert (n->quota_update_task == GNUNET_SCHEDULER_NO_TASK);
  n->quota_update_task =
      GNUNET_SCHEDULER_add_delayed (QUOTA_UPDATE_FREQUENCY,
                                    &neighbour_quota_update, n);
}


/**
 * Function that recalculates the bandwidth quota for the
 * given neighbour and transmits it to the transport service.
 *
 * @param cls neighbour for the quota update
 * @param tc context
 */
static void
neighbour_quota_update (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Neighbour *n = cls;
  struct GNUNET_BANDWIDTH_Value32NBO q_in;
  struct GNUNET_BANDWIDTH_Value32NBO q_out;
  struct GNUNET_BANDWIDTH_Value32NBO q_out_min;
  double pref_rel;
  double share;
  unsigned long long distributable;
  uint64_t need_per_peer;
  uint64_t need_per_second;
  unsigned int neighbour_count;

#if DEBUG_CORE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Neighbour quota update calculation running for peer `%4s'\n",
              GNUNET_i2s (&n->peer));
#endif
  n->quota_update_task = GNUNET_SCHEDULER_NO_TASK;
  /* calculate relative preference among all neighbours;
   * divides by a bit more to avoid division by zero AND to
   * account for possibility of new neighbours joining any time
   * AND to convert to double... */
  neighbour_count = GNUNET_CONTAINER_multihashmap_size (neighbours);
  if (neighbour_count == 0)
    return;
  if (preference_sum == 0)
  {
    pref_rel = 1.0 / (double) neighbour_count;
  }
  else
  {
    pref_rel = (double) n->current_preference / preference_sum;
  }
  need_per_peer =
      GNUNET_BANDWIDTH_value_get_available_until (MIN_BANDWIDTH_PER_PEER,
                                                  GNUNET_TIME_UNIT_SECONDS);
  need_per_second = need_per_peer * neighbour_count;

  /* calculate inbound bandwidth per peer */
  distributable = 0;
  if (bandwidth_target_in_bps > need_per_second)
    distributable = bandwidth_target_in_bps - need_per_second;
  share = distributable * pref_rel;
  if (share + need_per_peer > UINT32_MAX)
    q_in = GNUNET_BANDWIDTH_value_init (UINT32_MAX);
  else
    q_in = GNUNET_BANDWIDTH_value_init (need_per_peer + (uint32_t) share);

  /* calculate outbound bandwidth per peer */
  distributable = 0;
  if (bandwidth_target_out_bps > need_per_second)
    distributable = bandwidth_target_out_bps - need_per_second;
  share = distributable * pref_rel;
  if (share + need_per_peer > UINT32_MAX)
    q_out = GNUNET_BANDWIDTH_value_init (UINT32_MAX);
  else
    q_out = GNUNET_BANDWIDTH_value_init (need_per_peer + (uint32_t) share);
  n->bw_out_internal_limit = q_out;

  q_out_min =
      GNUNET_BANDWIDTH_value_min (n->bw_out_external_limit,
                                  n->bw_out_internal_limit);
  GNUNET_BANDWIDTH_tracker_update_quota (&n->available_send_window, n->bw_out);

  /* check if we want to disconnect for good due to inactivity */
  if ((GNUNET_TIME_absolute_get_duration (get_neighbour_timeout (n)).rel_value >
       0) &&
      (GNUNET_TIME_absolute_get_duration (n->time_established).rel_value >
       GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value))
  {
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Forcing disconnect of `%4s' due to inactivity\n",
                GNUNET_i2s (&n->peer));
#endif
    GNUNET_STATISTICS_update (stats,
			      gettext_noop ("# peers disconnected due to inactivity"), 1,
			      GNUNET_NO);
    q_in = GNUNET_BANDWIDTH_value_init (0);     /* force disconnect */
  }
#if DEBUG_CORE_QUOTA
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Current quota for `%4s' is %u/%llu b/s in (old: %u b/s) / %u out (%u internal)\n",
              GNUNET_i2s (&n->peer), (unsigned int) ntohl (q_in.value__),
              bandwidth_target_out_bps, (unsigned int) ntohl (n->bw_in.value__),
              (unsigned int) ntohl (n->bw_out.value__),
              (unsigned int) ntohl (n->bw_out_internal_limit.value__));
#endif
  if ((n->bw_in.value__ != q_in.value__) ||
      (n->bw_out.value__ != q_out_min.value__))
  {
    if (n->bw_in.value__ != q_in.value__)
      n->bw_in = q_in;
    if (n->bw_out.value__ != q_out_min.value__)
      n->bw_out = q_out_min;
    if (GNUNET_YES == n->is_connected)
      GNUNET_TRANSPORT_set_quota (transport, &n->peer, n->bw_in, n->bw_out);
    handle_peer_status_change (n);
  }
  schedule_quota_update (n);
}



void
GSC_ATS_init ()
{
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (c, "CORE", "TOTAL_QUOTA_IN",
                                              &bandwidth_target_in_bps)) ||
      (GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (c, "CORE", "TOTAL_QUOTA_OUT",
                                              &bandwidth_target_out_bps)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Core service is lacking key configuration settings.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}
