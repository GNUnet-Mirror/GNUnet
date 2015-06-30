/*
 This file is part of GNUnet.
 Copyright (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 Boston, MA 02110-1301, USA.
 */
/**
 * @file ats/perf_ats_logging.c
 * @brief ats benchmark: logging for performance tests
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "perf_ats.h"

#define THROUGHPUT_TEMPLATE "#!/usr/bin/gnuplot \n" \
"set datafile separator ';' \n" \
"set title \"Throughput between Master and Slaves\" \n" \
"set xlabel \"Time in ms\" \n" \
"set ylabel \"Bytes/s\" \n" \
"set grid \n"

#define RTT_TEMPLATE "#!/usr/bin/gnuplot \n" \
"set datafile separator ';' \n" \
"set title \"Application level roundtrip time between Master and Slaves\" \n" \
"set xlabel \"Time in ms\" \n" \
"set ylabel \"ms\" \n" \
"set grid \n"

#define BW_TEMPLATE "#!/usr/bin/gnuplot \n" \
"set datafile separator ';' \n" \
"set title \"Bandwidth inbound and outbound between Master and Slaves\" \n" \
"set xlabel \"Time in ms\" \n" \
"set ylabel \"Bytes / s \" \n" \
"set grid \n"

#define LOG_ITEMS_TIME 2
#define LOG_ITEMS_PER_PEER 17

#define LOG_ITEM_BYTES_SENT 1
#define LOG_ITEM_MSGS_SENT 2
#define LOG_ITEM_THROUGHPUT_SENT 3
#define LOG_ITEM_BYTES_RECV 4
#define LOG_ITEM_MSGS_RECV 5
#define LOG_ITEM_THROUGHPUT_RECV 6
#define LOG_ITEM_APP_RTT 7
#define LOG_ITEM_ATS_BW_IN 8
#define LOG_ITEM_ATS_BW_OUT 9
#define LOG_ITEM_ATS_COSTS_LAN 10
#define LOG_ITEM_ATS_WAN 11
#define LOG_ITEM_ATS_WLAN 12
#define LOG_ITEM_ATS_DELAY 13
#define LOG_ITEM_ATS_DISTANCE 14
#define LOG_ITEM_ATS_NETWORKTYPE 15
#define LOG_ITEM_ATS_UTIL_UP 16
#define LOG_ITEM_ATS_UTIL_DOWN 17

/**
 * Logging task
 */
static struct GNUNET_SCHEDULER_Task * log_task;

/**
 * Reference to perf_ats' masters
 */
static int num_peers;
static int running;
static char *name;
static struct GNUNET_TIME_Relative frequency;

/**
 * A single logging time step for a partner
 */
struct PartnerLoggingTimestep
{
  /**
   * Peer
   */
  struct BenchmarkPeer *slave;

  /**
   * Total number of messages this peer has sent
   */
  unsigned int total_messages_sent;

  /**
   * Total number of bytes this peer has sent
   */
  unsigned int total_bytes_sent;

  /**
   * Total number of messages this peer has received
   */
  unsigned int total_messages_received;

  /**
   * Total number of bytes this peer has received
   */
  unsigned int total_bytes_received;

  /**
   * Total outbound throughput for master in Bytes / s
   */
  unsigned int throughput_sent;

  /**
   * Total inbound throughput for master in Bytes / s
   */
  unsigned int throughput_recv;

  /**
   * Accumulated RTT for all messages
   */
  unsigned int total_app_rtt;

  /**
   * Current application level delay
   */
  unsigned int app_rtt;

  /* Current ATS properties */

  uint32_t ats_distance;

  uint32_t ats_delay;

  uint32_t bandwidth_in;

  uint32_t bandwidth_out;

  uint32_t ats_utilization_up;

  uint32_t ats_utilization_down;

  uint32_t ats_network_type;

  uint32_t ats_cost_wan;

  uint32_t ats_cost_lan;

  uint32_t ats_cost_wlan;
};


/**
 * A single logging time step for a peer
 */
struct PeerLoggingTimestep
{
  /**
   * Next in DLL
   */
  struct PeerLoggingTimestep *next;

  /**
   * Prev in DLL
   */
  struct PeerLoggingTimestep *prev;

  /**
   * Logging timestamp
   */
  struct GNUNET_TIME_Absolute timestamp;

  /**
   * Total number of messages this peer has sent
   */
  unsigned int total_messages_sent;

  /**
   * Total number of bytes this peer has sent
   */
  unsigned int total_bytes_sent;

  /**
   * Total number of messages this peer has received
   */
  unsigned int total_messages_received;

  /**
   * Total number of bytes this peer has received
   */
  unsigned int total_bytes_received;

  /**
   * Total outbound throughput for master in Bytes / s
   */
  unsigned int total_throughput_send;

  /**
   * Total inbound throughput for master in Bytes / s
   */
  unsigned int total_throughput_recv;

  /**
   * Logs for slaves
   */
  struct PartnerLoggingTimestep *slaves_log;
};

/**
 * Entry for a benchmark peer
 */
struct LoggingPeer
{
  /**
   * Peer
   */
  struct BenchmarkPeer *peer;

  /**
   * Start time
   */
  struct GNUNET_TIME_Absolute start;

  /**
   * DLL for logging entries: head
   */
  struct PeerLoggingTimestep *head;

  /**
   * DLL for logging entries: tail
   */
  struct PeerLoggingTimestep *tail;
};

/**
 * Log structure of length num_peers
 */
static struct LoggingPeer *lp;


static void
write_throughput_gnuplot_script (char * fn, struct LoggingPeer *lp)
{
  struct GNUNET_DISK_FileHandle *f;
  char * gfn;
  char *data;
  int c_s;
  int peer_index;

  GNUNET_asprintf (&gfn, "gnuplot_throughput_%s",fn);
  f = GNUNET_DISK_file_open (gfn,
      GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE,
      GNUNET_DISK_PERM_USER_EXEC | GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
  if (NULL == f)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot open gnuplot file `%s'\n", gfn);
    GNUNET_free (gfn);
    return;
  }

  /* Write header */

  if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, THROUGHPUT_TEMPLATE, strlen(THROUGHPUT_TEMPLATE)))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);

  /* Write master data */
  peer_index = LOG_ITEMS_TIME;
  GNUNET_asprintf (&data, "plot '%s' using 2:%u with lines title 'Master %u send total', \\\n" \
                           "'%s' using 2:%u with lines title 'Master %u receive total', \\\n",
                           fn, peer_index + LOG_ITEM_THROUGHPUT_SENT, lp->peer->no,
                           fn, peer_index + LOG_ITEM_THROUGHPUT_RECV, lp->peer->no);
  if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, data, strlen(data)))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);
  GNUNET_free (data);

  peer_index = LOG_ITEMS_TIME + LOG_ITEMS_PER_PEER ;
  for (c_s = 0; c_s < lp->peer->num_partners; c_s++)
  {
    GNUNET_asprintf (&data, "'%s' using 2:%u with lines title 'Master %u - Slave %u send', \\\n" \
                            "'%s' using 2:%u with lines title 'Master %u - Slave %u receive'%s\n",
                            fn, peer_index + LOG_ITEM_THROUGHPUT_SENT, lp->peer->no, lp->peer->partners[c_s].dest->no,
                            fn, peer_index + LOG_ITEM_THROUGHPUT_RECV, lp->peer->no, lp->peer->partners[c_s].dest->no,
                            (c_s < lp->peer->num_partners -1) ? ", \\" : "\n pause -1");
    if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, data, strlen(data)))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);
    GNUNET_free (data);
    peer_index += LOG_ITEMS_PER_PEER;
  }

  if (GNUNET_SYSERR == GNUNET_DISK_file_close(f))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot close gnuplot file `%s'\n", gfn);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Data successfully written to plot file `%s'\n", gfn);

  GNUNET_free (gfn);
}


static void
write_rtt_gnuplot_script (char * fn, struct LoggingPeer *lp)
{
  struct GNUNET_DISK_FileHandle *f;
  char * gfn;
  char *data;
  int c_s;
  int index;

  GNUNET_asprintf (&gfn, "gnuplot_rtt_%s",fn);
  f = GNUNET_DISK_file_open (gfn,
      GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE,
      GNUNET_DISK_PERM_USER_EXEC | GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
  if (NULL == f)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot open gnuplot file `%s'\n", gfn);
    GNUNET_free (gfn);
    return;
  }

  /* Write header */

  if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, RTT_TEMPLATE, strlen(RTT_TEMPLATE)))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);

  index = LOG_ITEMS_TIME + LOG_ITEMS_PER_PEER;
  for (c_s = 0; c_s < lp->peer->num_partners; c_s++)
  {
    GNUNET_asprintf (&data, "%s'%s' using 2:%u with lines title 'Master %u - Slave %u '%s\n",
        (0 == c_s) ? "plot " :"",
        fn, index + LOG_ITEM_APP_RTT, lp->peer->no, lp->peer->partners[c_s].dest->no,
        (c_s < lp->peer->num_partners -1) ? ", \\" : "\n pause -1");
    if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, data, strlen(data)))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);
    GNUNET_free (data);
    index += LOG_ITEMS_PER_PEER;
  }

  if (GNUNET_SYSERR == GNUNET_DISK_file_close(f))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot close gnuplot file `%s'\n", gfn);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Data successfully written to plot file `%s'\n", gfn);
  GNUNET_free (gfn);
}

static void
write_bw_gnuplot_script (char * fn, struct LoggingPeer *lp)
{
  struct GNUNET_DISK_FileHandle *f;
  char * gfn;
  char *data;
  int c_s;
  int index;

  GNUNET_asprintf (&gfn, "gnuplot_bw_%s",fn);
  f = GNUNET_DISK_file_open (gfn,
      GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE,
      GNUNET_DISK_PERM_USER_EXEC | GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
  if (NULL == f)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot open gnuplot file `%s'\n", gfn);
    GNUNET_free (gfn);
    return;
  }

  /* Write header */

  if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, BW_TEMPLATE, strlen(BW_TEMPLATE)))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);

  index = LOG_ITEMS_TIME + LOG_ITEMS_PER_PEER;
  for (c_s = 0; c_s < lp->peer->num_partners; c_s++)
  {
    GNUNET_asprintf (&data, "%s"\
        "'%s' using 2:%u with lines title 'BW out master %u - Slave %u ', \\\n" \
        "'%s' using 2:%u with lines title 'BW in master %u - Slave %u '"\
        "%s\n",
        (0 == c_s) ? "plot " :"",
        fn, index + LOG_ITEM_ATS_BW_OUT, lp->peer->no, lp->peer->partners[c_s].dest->no,
        fn, index + LOG_ITEM_ATS_BW_IN, lp->peer->no, lp->peer->partners[c_s].dest->no,
        (c_s < lp->peer->num_partners -1) ? ", \\" : "\n pause -1");
    if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, data, strlen(data)))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);
    GNUNET_free (data);
    index += LOG_ITEMS_PER_PEER;
  }

  if (GNUNET_SYSERR == GNUNET_DISK_file_close(f))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot close gnuplot file `%s'\n", gfn);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Data successfully written to plot file `%s'\n", gfn);
  GNUNET_free (gfn);
}


static void
write_to_file ()
{
  struct GNUNET_DISK_FileHandle *f;

  char * filename;
  char *data;
  char *slave_string;
  char *slave_string_tmp;
  struct PeerLoggingTimestep *cur_lt;
  struct PartnerLoggingTimestep *plt;
  int c_m;
  int c_s;

  for (c_m = 0; c_m < num_peers; c_m++)
  {
    GNUNET_asprintf (&filename, "%llu_master_%u_%s_%s.data", GNUNET_TIME_absolute_get().abs_value_us,
        lp[c_m].peer->no, GNUNET_i2s(&lp[c_m].peer->id), name);

    f = GNUNET_DISK_file_open (filename,
        GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE,
        GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
    if (NULL == f)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot open log file `%s'\n", filename);
      GNUNET_free (filename);
      return;
    }

    for (cur_lt = lp[c_m].head; NULL != cur_lt; cur_lt = cur_lt->next)
    {
       GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Master [%u]: timestamp %llu %llu ; %u %u %u ; %u %u %u\n", lp[c_m].peer->no,
          cur_lt->timestamp, GNUNET_TIME_absolute_get_difference(lp[c_m].start,cur_lt->timestamp).rel_value_us / 1000,
          cur_lt->total_messages_sent, cur_lt->total_bytes_sent, cur_lt->total_throughput_send,
          cur_lt->total_messages_received, cur_lt->total_bytes_received, cur_lt->total_throughput_recv);

      slave_string = GNUNET_strdup (";");
      for (c_s = 0; c_s < lp[c_m].peer->num_partners; c_s++)
      {
        plt = &cur_lt->slaves_log[c_s];
        /* Log partners */

        /* Assembling slave string */
        GNUNET_log(GNUNET_ERROR_TYPE_INFO,
            "\t Slave [%u]: %u %u %u ; %u %u %u rtt %u delay %u bw_in %u bw_out %u \n", plt->slave->no,
            plt->total_messages_sent, plt->total_bytes_sent, plt->throughput_sent,
            plt->total_messages_received, plt->total_bytes_received, plt->throughput_recv,
            plt->app_rtt, plt->ats_delay,
            plt->bandwidth_in, plt->bandwidth_out);

        GNUNET_asprintf(&slave_string_tmp, "%s%u;%u;%u;%u;%u;%u;%.3f;%u;%u;%u;%u;%u;%u;%u;%u;%u;%u;",slave_string,
            plt->total_messages_sent, plt->total_bytes_sent,  plt->throughput_sent,
            plt->total_messages_received, plt->total_bytes_received,  plt->throughput_sent,
            (double) plt->app_rtt / 1000,
            plt->bandwidth_in,plt->bandwidth_out,
            plt->ats_cost_lan, plt->ats_cost_wan, plt->ats_cost_wlan,
            plt->ats_delay, plt->ats_distance, plt->ats_network_type,
            plt->ats_utilization_up, plt->ats_utilization_down);
        GNUNET_free (slave_string);
        slave_string = slave_string_tmp;
      }
      /* Assembling master string */



      GNUNET_asprintf (&data, "%llu;%llu;%u;%u;%u;%u;%u;%u;;;;;;;;;;;%s\n",
          cur_lt->timestamp,
          GNUNET_TIME_absolute_get_difference(lp[c_m].start,cur_lt->timestamp).rel_value_us / 1000,
          cur_lt->total_messages_sent, cur_lt->total_bytes_sent,  cur_lt->total_throughput_send,
          cur_lt->total_messages_received, cur_lt->total_bytes_received, cur_lt->total_throughput_recv,
          slave_string);
      GNUNET_free (slave_string);

      if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, data, strlen(data)))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to log file `%s'\n", filename);
      GNUNET_free (data);
    }
    if (GNUNET_SYSERR == GNUNET_DISK_file_close(f))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot close log file `%s'\n", filename);
      GNUNET_free (filename);
      return;
    }

    write_throughput_gnuplot_script (filename, lp);
    write_rtt_gnuplot_script (filename, lp);
    write_bw_gnuplot_script (filename, lp);

    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Data file successfully written to log file `%s'\n", filename);
    GNUNET_free (filename);
  }
}


void
collect_log_now (void)
{
  struct LoggingPeer *bp;
  struct PeerLoggingTimestep *mlt;
  struct PeerLoggingTimestep *prev_log_mlt;
  struct PartnerLoggingTimestep *slt;
  struct PartnerLoggingTimestep *prev_log_slt;
  struct BenchmarkPartner *p;
  struct GNUNET_TIME_Relative delta;
  int c_s;
  int c_m;
  unsigned int app_rtt;
  double mult;

  if (GNUNET_YES != running)
    return;

  for (c_m = 0; c_m < num_peers; c_m++)
  {
    bp = &lp[c_m];
    mlt = GNUNET_new (struct PeerLoggingTimestep);
    GNUNET_CONTAINER_DLL_insert_tail(bp->head, bp->tail, mlt);
    prev_log_mlt = mlt->prev;

    /* Collect data */

    /* Current master state */
    mlt->timestamp = GNUNET_TIME_absolute_get();
    mlt->total_bytes_sent = bp->peer->total_bytes_sent;
    mlt->total_messages_sent = bp->peer->total_messages_sent;
    mlt->total_bytes_received = bp->peer->total_bytes_received;
    mlt->total_messages_received = bp->peer->total_messages_received;

    /* Throughput */
    if (NULL == prev_log_mlt)
     {
       /* Get difference to start */
       delta = GNUNET_TIME_absolute_get_difference (lp[c_m].start, mlt->timestamp);
     }
     else
     {
       /* Get difference to last timestep */
       delta = GNUNET_TIME_absolute_get_difference (mlt->prev->timestamp, mlt->timestamp);
     }

     /* Multiplication factor for throughput calculation */
     mult = (1.0 * 1000 * 1000) / (delta.rel_value_us);

     /* Total throughput */
     if (NULL != prev_log_mlt)
     {
       if (mlt->total_bytes_sent - mlt->prev->total_bytes_sent > 0)
         mlt->total_throughput_send = mult * (mlt->total_bytes_sent - mlt->prev->total_bytes_sent);
       else
         mlt->total_throughput_send = prev_log_mlt->total_throughput_send; /* no msgs send */

       if (mlt->total_bytes_received - mlt->prev->total_bytes_received > 0)
         mlt->total_throughput_recv = mult * (mlt->total_bytes_received - mlt->prev->total_bytes_received);
       else
         mlt->total_throughput_recv = prev_log_mlt->total_throughput_recv; /* no msgs received */
     }
     else
     {
       mlt->total_throughput_send = mult * mlt->total_bytes_sent;
       mlt->total_throughput_send = mult * mlt->total_bytes_received;
     }

    mlt->slaves_log = GNUNET_malloc (bp->peer->num_partners *
        sizeof (struct PartnerLoggingTimestep));

    for (c_s = 0; c_s < bp->peer->num_partners; c_s++)
    {
      p = &bp->peer->partners[c_s];
      slt = &mlt->slaves_log[c_s];

      slt->slave = p->dest;
      /* Bytes sent from master to this slave */
      slt->total_bytes_sent = p->bytes_sent;
      /* Messages sent from master to this slave */
      slt->total_messages_sent = p->messages_sent;
      /* Bytes master received from this slave */
      slt->total_bytes_received = p->bytes_received;
      /* Messages master received from this slave */
      slt->total_messages_received = p->messages_received;
      slt->total_app_rtt = p->total_app_rtt;
      /* ats performance information */
      slt->ats_cost_lan = p->ats_cost_lan;
      slt->ats_cost_wan = p->ats_cost_wan;
      slt->ats_cost_wlan = p->ats_cost_wlan;
      slt->ats_delay = p->ats_delay;
      slt->ats_distance = p->ats_distance;
      slt->ats_network_type = p->ats_network_type;
      slt->ats_utilization_down = p->ats_utilization_down;
      slt->ats_utilization_up = p->ats_utilization_up;
      slt->bandwidth_in = p->bandwidth_in;
      slt->bandwidth_out = p->bandwidth_out;

      /* Total application level rtt  */
      if (NULL == prev_log_mlt)
      {
        if (0 != slt->total_messages_sent)
          app_rtt = slt->total_app_rtt / slt->total_messages_sent;
        else
          app_rtt = 0;
      }
      else
      {
        prev_log_slt =  &prev_log_mlt->slaves_log[c_s];
        if ((slt->total_messages_sent - prev_log_slt->total_messages_sent) > 0)
          app_rtt = (slt->total_app_rtt - prev_log_slt->total_app_rtt) /
                  (slt->total_messages_sent - prev_log_slt->total_messages_sent);
        else
          app_rtt = prev_log_slt->app_rtt; /* No messages were */
      }
      slt->app_rtt = app_rtt;

      /* Partner throughput */
      if (NULL != prev_log_mlt)
      {
        prev_log_slt =  &prev_log_mlt->slaves_log[c_s];
        if (slt->total_bytes_sent - prev_log_slt->total_bytes_sent > 0)
          slt->throughput_sent = mult * (slt->total_bytes_sent - prev_log_slt->total_bytes_sent);
        else
          slt->throughput_sent = prev_log_slt->throughput_sent; /* no msgs send */

        if (slt->total_bytes_received - prev_log_slt->total_bytes_received > 0)
          slt->throughput_recv = mult * (slt->total_bytes_received - prev_log_slt->total_bytes_received);
        else
          slt->throughput_recv = prev_log_slt->throughput_recv; /* no msgs received */
      }
      else
      {
        slt->throughput_sent = mult * slt->total_bytes_sent;
        slt->throughput_sent = mult * slt->total_bytes_received;
      }

      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Master [%u]: slave [%u]\n",
          bp->peer->no, p->dest->no);
    }
  }
}

static void
collect_log_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  log_task = NULL;

  collect_log_now();

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  log_task = GNUNET_SCHEDULER_add_delayed (frequency,
      &collect_log_task, NULL);
}


void
perf_logging_stop ()
{
  int c_m;
  struct GNUNET_SCHEDULER_TaskContext tc;
  struct PeerLoggingTimestep *cur;

  if (GNUNET_YES!= running)
    return;

  if (NULL != log_task)
    GNUNET_SCHEDULER_cancel (log_task);
  log_task = NULL;
  tc.reason = GNUNET_SCHEDULER_REASON_SHUTDOWN;
  collect_log_task (NULL, &tc);

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      _("Stop logging\n"));

  write_to_file ();

  for (c_m = 0; c_m < num_peers; c_m++)
  {
    while (NULL != (cur = lp[c_m].head))
    {
      GNUNET_CONTAINER_DLL_remove (lp[c_m].head, lp[c_m].tail, cur);
      GNUNET_free (cur->slaves_log);
      GNUNET_free (cur);
    }
  }

  GNUNET_free (lp);
}

void
perf_logging_start (struct GNUNET_TIME_Relative log_frequency,
    char * testname, struct BenchmarkPeer *masters, int num_masters)
{
  int c_m;
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      _("Start logging `%s'\n"), testname);

  num_peers = num_masters;
  name = testname;
  frequency = log_frequency;

  lp = GNUNET_malloc (num_masters * sizeof (struct LoggingPeer));

  for (c_m = 0; c_m < num_masters; c_m ++)
  {
    lp[c_m].peer = &masters[c_m];
    lp[c_m].start = GNUNET_TIME_absolute_get();
  }

  /* Schedule logging task */
  log_task = GNUNET_SCHEDULER_add_now (&collect_log_task, NULL);
  running = GNUNET_YES;
}
/* end of file perf_ats_logging.c */

