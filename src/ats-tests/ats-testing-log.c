/*
 This file is part of GNUnet.
 (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file ats-tests/ats-testing-log.c
 * @brief ats benchmark: logging for performance tests
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "ats-testing.h"

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

  double pref_bandwidth;
  double pref_delay;
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

struct LoggingHandle
{
  /**
   * Logging task
   */
  GNUNET_SCHEDULER_TaskIdentifier log_task;

  /**
   * Reference to perf_ats' masters
   */
  int num_masters;
  int num_slaves;
  int running;
  int verbose;
  char *name;
  struct GNUNET_TIME_Relative frequency;

  /**
   * Log structure of length num_peers
   */
  struct LoggingPeer *lp;
};



static void
write_throughput_gnuplot_script (char * fn, struct LoggingPeer *lp, char **fs, int slaves)
{
  struct GNUNET_DISK_FileHandle *f;
  char * gfn;
  char *data;
  int c_s;

  GNUNET_asprintf (&gfn, "gnuplot_throughput_%s",fn);
  fprintf (stderr, "Writing throughput plot for master %u and %u slaves to `%s'\n",
      lp->peer->no, slaves, gfn);

  f = GNUNET_DISK_file_open (gfn,
      GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE,
      GNUNET_DISK_PERM_USER_EXEC | GNUNET_DISK_PERM_USER_READ |
      GNUNET_DISK_PERM_USER_WRITE);
  if (NULL == f)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot open gnuplot file `%s'\n", gfn);
    GNUNET_free (gfn);
    return;
  }

  /* Write header */
  if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, THROUGHPUT_TEMPLATE,
      strlen(THROUGHPUT_TEMPLATE)))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Cannot write data to plot file `%s'\n", gfn);

  /* Write master data */
  GNUNET_asprintf (&data,
      "plot '%s' using 2:%u with lines title 'Master %u send total', \\\n" \
      "'%s' using 2:%u with lines title 'Master %u receive total', \\\n",
      fn, LOG_ITEMS_TIME + LOG_ITEM_THROUGHPUT_SENT, lp->peer->no,
      fn, LOG_ITEMS_TIME + LOG_ITEM_THROUGHPUT_RECV, lp->peer->no);
  if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, data, strlen(data)))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);
  GNUNET_free (data);

  for (c_s = 0; c_s < slaves; c_s++)
  {
    GNUNET_asprintf (&data, "'%s' using 2:%u with lines title 'Master %u - Slave %u send', \\\n" \
        "'%s' using 2:%u with lines title 'Master %u - Slave %u receive'%s\n",
        fs[c_s],
        LOG_ITEMS_TIME + LOG_ITEM_THROUGHPUT_SENT,
        lp->peer->no,
        lp->peer->partners[c_s].dest->no,
        fs[c_s],
        LOG_ITEMS_TIME + LOG_ITEM_THROUGHPUT_RECV,
        lp->peer->no,
        lp->peer->partners[c_s].dest->no,
        (c_s < lp->peer->num_partners -1) ? ", \\" : "\n pause -1");
    if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, data, strlen(data)))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);
    GNUNET_free (data);
  }

  if (GNUNET_SYSERR == GNUNET_DISK_file_close(f))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Cannot close gnuplot file `%s'\n", gfn);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
        "Data successfully written to plot file `%s'\n", gfn);
  GNUNET_free (gfn);
}


static void
write_rtt_gnuplot_script (char * fn, struct LoggingPeer *lp, char **fs, int slaves)
{
  struct GNUNET_DISK_FileHandle *f;
  char * gfn;
  char *data;
  int c_s;

  GNUNET_asprintf (&gfn, "gnuplot_rtt_%s",fn);
  fprintf (stderr, "Writing rtt plot for master %u to `%s'\n",
      lp->peer->no, gfn);

  f = GNUNET_DISK_file_open (gfn,
      GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE,
      GNUNET_DISK_PERM_USER_EXEC | GNUNET_DISK_PERM_USER_READ |
      GNUNET_DISK_PERM_USER_WRITE);
  if (NULL == f)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot open gnuplot file `%s'\n", gfn);
    GNUNET_free (gfn);
    return;
  }

  /* Write header */
  if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, RTT_TEMPLATE, strlen(RTT_TEMPLATE)))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);

  for (c_s = 0; c_s < slaves; c_s++)
  {
    GNUNET_asprintf (&data, "%s'%s' using 2:%u with lines title 'Master %u - Slave %u '%s\n",
        (0 == c_s) ? "plot " :"",
        fs[c_s],
        LOG_ITEMS_TIME + LOG_ITEM_APP_RTT,
        lp->peer->no,
        lp->peer->partners[c_s].dest->no,
        (c_s < lp->peer->num_partners -1) ? ", \\" : "\n pause -1");
    if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, data, strlen(data)))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);
    GNUNET_free (data);
  }

  if (GNUNET_SYSERR == GNUNET_DISK_file_close(f))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot close gnuplot file `%s'\n", gfn);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Data successfully written to plot file `%s'\n", gfn);
  GNUNET_free (gfn);
}

static void
write_bw_gnuplot_script (char * fn, struct LoggingPeer *lp, char **fs, int slaves)
{
  struct GNUNET_DISK_FileHandle *f;
  char * gfn;
  char *data;
  int c_s;

  GNUNET_asprintf (&gfn, "gnuplot_bw_%s",fn);
  fprintf (stderr, "Writing bandwidth plot for master %u to `%s'\n",
      lp->peer->no, gfn);

  f = GNUNET_DISK_file_open (gfn,
      GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE,
      GNUNET_DISK_PERM_USER_EXEC | GNUNET_DISK_PERM_USER_READ |
      GNUNET_DISK_PERM_USER_WRITE);
  if (NULL == f)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot open gnuplot file `%s'\n", gfn);
    GNUNET_free (gfn);
    return;
  }

  /* Write header */
  if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, BW_TEMPLATE, strlen(BW_TEMPLATE)))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Cannot write data to plot file `%s'\n", gfn);

  for (c_s = 0; c_s < slaves; c_s++)
  {
    GNUNET_asprintf (&data, "%s"\
        "'%s' using 2:%u with lines title 'BW out master %u - Slave %u ', \\\n" \
        "'%s' using 2:%u with lines title 'BW in master %u - Slave %u '"\
        "%s\n",
        (0 == c_s) ? "plot " :"",
        fs[c_s],
        LOG_ITEMS_TIME + LOG_ITEM_ATS_BW_OUT,
        lp->peer->no, c_s,
        fs[c_s],
        LOG_ITEMS_TIME + LOG_ITEM_ATS_BW_IN,
        lp->peer->no, c_s,
        (c_s < lp->peer->num_partners -1) ? ", \\" : "\n pause -1");
    if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, data, strlen(data)))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);
    GNUNET_free (data);
  }

  if (GNUNET_SYSERR == GNUNET_DISK_file_close(f))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot close gnuplot file `%s'\n", gfn);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Data successfully written to plot file `%s'\n", gfn);
  GNUNET_free (gfn);
}


void
GNUNET_ATS_TEST_logging_write_to_file (struct LoggingHandle *l,
    char *experiment_name, int plots)
{
  struct GNUNET_DISK_FileHandle *f[l->num_slaves];
  struct GNUNET_DISK_FileHandle *f_m;
  char *tmp_exp_name;
  char *filename_master;
  char *filename_slaves[l->num_slaves];
  char *data;
  struct PeerLoggingTimestep *cur_lt;
  struct PartnerLoggingTimestep *plt;
  struct GNUNET_TIME_Absolute timestamp;
  int c_m;
  int c_s;


  timestamp = GNUNET_TIME_absolute_get();

  tmp_exp_name = experiment_name;
  for (c_m = 0; c_m < l->num_masters; c_m++)
  {
    GNUNET_asprintf (&filename_master, "%s_%llu_master%u_%s",
        experiment_name, timestamp.abs_value_us, c_m, l->name);
    fprintf (stderr, "Writing data for master %u to file `%s'\n",
        c_m,filename_master);

    f_m = GNUNET_DISK_file_open (filename_master,
        GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE,
        GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
    if (NULL == f_m)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot open log file `%s'\n", filename_master);
      GNUNET_free (filename_master);
      return;
    }

    GNUNET_asprintf (&data, "# master %u; experiment : %s\n"
        "timestamp; timestamp delta; #messages sent; #bytes sent; #throughput sent; #messages received; #bytes received; #throughput received; \n" ,
        c_m,  experiment_name);
    if (GNUNET_SYSERR == GNUNET_DISK_file_write(f_m, data, strlen(data)))
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
          "Cannot write data to log file `%s'\n",filename_master);
    GNUNET_free (data);

    for (c_s = 0; c_s < l->lp[c_m].peer->num_partners; c_s++)
    {
      GNUNET_asprintf (&filename_slaves[c_s], "%s_%llu_master%u_slave_%u_%s",
          tmp_exp_name, timestamp.abs_value_us, c_m, c_s, l->name);

      fprintf (stderr, "Writing data for master %u slave %u to file `%s'\n",
          c_m, c_s, filename_slaves[c_s]);

      f[c_s] = GNUNET_DISK_file_open (filename_slaves[c_s],
          GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE,
          GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
      if (NULL == f[c_s])
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot open log file `%s'\n", filename_slaves[c_s]);
        GNUNET_free (filename_slaves[c_s]);
        GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close(f_m));
        return;
      }

      /* Header */
      GNUNET_asprintf (&data, "# master %u; slave %u ; experiment : %s\n"
          "timestamp; timestamp delta; #messages sent; #bytes sent; #throughput sent; #messages received; #bytes received; #throughput received; " \
          "rtt; bw in; bw out; ats_cost_lan; ats_cost_wlan; ats_delay; ats_distance; ats_network_type; ats_utilization_up ;ats_utilization_down;" \
          "pref bandwidth; pref delay\n",
          c_m, c_s, experiment_name);
      if (GNUNET_SYSERR == GNUNET_DISK_file_write(f[c_s], data, strlen(data)))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
            "Cannot write data to log file `%s'\n",filename_slaves[c_s]);
      GNUNET_free (data);
    }

    for (cur_lt = l->lp[c_m].head; NULL != cur_lt; cur_lt = cur_lt->next)
    {
      if (l->verbose)
        fprintf (stderr,
           "Master [%u]: timestamp %llu %llu ; %u %u %u ; %u %u %u\n",
           l->lp[c_m].peer->no,
           (long long unsigned int) cur_lt->timestamp.abs_value_us,
           (long long unsigned int) GNUNET_TIME_absolute_get_difference(l->lp[c_m].start,
               cur_lt->timestamp).rel_value_us / 1000,
           cur_lt->total_messages_sent,
           cur_lt->total_bytes_sent,
           cur_lt->total_throughput_send,
           cur_lt->total_messages_received,
           cur_lt->total_bytes_received,
           cur_lt->total_throughput_recv);

      /* Assembling master string */
      GNUNET_asprintf (&data, "%llu;%llu;%u;%u;%u;%u;%u;%u;\n",
          (long long unsigned int) cur_lt->timestamp.abs_value_us,
          (long long unsigned int) GNUNET_TIME_absolute_get_difference(l->lp[c_m].start,
              cur_lt->timestamp).rel_value_us / 1000,
          cur_lt->total_messages_sent,
          cur_lt->total_bytes_sent,
          cur_lt->total_throughput_send,
          cur_lt->total_messages_received,
          cur_lt->total_bytes_received,
          cur_lt->total_throughput_recv);

      if (GNUNET_SYSERR == GNUNET_DISK_file_write(f_m, data, strlen(data)))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
            "Cannot write data to master file %u\n", c_m);
      GNUNET_free (data);


      for (c_s = 0; c_s < l->lp[c_m].peer->num_partners; c_s++)
      {
        plt = &cur_lt->slaves_log[c_s];
        /* Log partners */

        /* Assembling slave string */
        GNUNET_asprintf(&data,
            "%llu;%llu;%u;%u;%u;%u;%u;%u;%.3f;%u;%u;%u;%u;%u;%u;%u;%u;%u;%u;%.3f;%.3f\n",
            (long long unsigned int) cur_lt->timestamp.abs_value_us,
            (long long unsigned int) GNUNET_TIME_absolute_get_difference(l->lp[c_m].start,
                cur_lt->timestamp).rel_value_us / 1000,
            plt->total_messages_sent,
            plt->total_bytes_sent,
            plt->throughput_sent,
            plt->total_messages_received,
            plt->total_bytes_received,
            plt->throughput_recv,
            (double) plt->app_rtt / 1000,
            plt->bandwidth_in,
            plt->bandwidth_out,
            plt->ats_cost_lan,
            plt->ats_cost_wan,
            plt->ats_cost_wlan,
            plt->ats_delay,
            plt->ats_distance,
            plt->ats_network_type,
            plt->ats_utilization_up,
            plt->ats_utilization_down,
            plt->pref_bandwidth,
            plt->pref_delay);

        if (l->verbose)
          fprintf (stderr,
              "\t Slave [%u]: %u %u %u ; %u %u %u rtt %u delay %u bw_in %u bw_out %u \n",
              plt->slave->no,
              plt->total_messages_sent,
              plt->total_bytes_sent,
              plt->throughput_sent,
              plt->total_messages_received,
              plt->total_bytes_received,
              plt->throughput_recv,
              plt->app_rtt,
              plt->ats_delay,
              plt->bandwidth_in,
              plt->bandwidth_out);

        if (GNUNET_SYSERR == GNUNET_DISK_file_write(f[c_s], data, strlen(data)))
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Cannot write data to log file `%s'\n", filename_slaves[c_s]);
        GNUNET_free (data);

      }
    }

    for (c_s = 0; c_s < l->lp[c_m].peer->num_partners; c_s++)
    {
      if (GNUNET_SYSERR == GNUNET_DISK_file_close(f[c_s]))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
            "Cannot close log file for master[%u] slave[%u]\n", c_m, c_s);
        continue;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Data file successfully written to log file for `%s'\n",
          filename_slaves[c_s]);
    }

    if (GNUNET_SYSERR == GNUNET_DISK_file_close(f_m))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "close",
                                filename_master);
      GNUNET_free (filename_master);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
        "Data file successfully written to log file for master `%s'\n", filename_master);

    if (GNUNET_YES == plots)
    {
      write_throughput_gnuplot_script (filename_master, &l->lp[c_m], filename_slaves, l->num_slaves);
      write_rtt_gnuplot_script (filename_master, &l->lp[c_m], filename_slaves, l->num_slaves);
      write_bw_gnuplot_script (filename_master, &l->lp[c_m], filename_slaves, l->num_slaves);
    }
  }
  GNUNET_free (filename_master);
}

/**
 * Log all data now
 *
 * @param l logging handle to use
 */
void
GNUNET_ATS_TEST_logging_now (struct LoggingHandle *l)
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

  if (GNUNET_YES != l->running)
    return;

  for (c_m = 0; c_m < l->num_masters; c_m++)
  {
    bp = &l->lp[c_m];
    mlt = GNUNET_new (struct PeerLoggingTimestep);
    GNUNET_CONTAINER_DLL_insert_tail(l->lp[c_m].head, l->lp[c_m].tail, mlt);
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
       delta = GNUNET_TIME_absolute_get_difference (l->lp[c_m].start, mlt->timestamp);
     }
     else
     {
       /* Get difference to last timestep */
       delta = GNUNET_TIME_absolute_get_difference (mlt->prev->timestamp, mlt->timestamp);
     }

     /* Multiplication factor for throughput calculation */
     mult = (double) GNUNET_TIME_UNIT_SECONDS.rel_value_us / (delta.rel_value_us);

     /* Total throughput */
     if (NULL != prev_log_mlt)
     {
       if (mlt->total_bytes_sent - mlt->prev->total_bytes_sent > 0)
       {
         mlt->total_throughput_send = mult * (mlt->total_bytes_sent - mlt->prev->total_bytes_sent);
       }
       else
       {
         mlt->total_throughput_send = 0;
        // mlt->total_throughput_send = prev_log_mlt->total_throughput_send; /* no msgs send */
       }

       if (mlt->total_bytes_received - mlt->prev->total_bytes_received > 0)
       {
         mlt->total_throughput_recv = mult * (mlt->total_bytes_received - mlt->prev->total_bytes_received);
       }
       else
       {
         mlt->total_throughput_send = 0;
         //mlt->total_throughput_recv = prev_log_mlt->total_throughput_recv; /* no msgs received */
       }
     }
     else
     {
       mlt->total_throughput_send = mult * mlt->total_bytes_sent;
       mlt->total_throughput_send = mult * mlt->total_bytes_received;
     }

    if (GNUNET_YES == l->verbose)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
          "Master[%u] delta: %llu us, bytes (sent/received): %u / %u; throughput send/recv: %u / %u\n", c_m,
          delta.rel_value_us,
          mlt->total_bytes_sent,
          mlt->total_bytes_received,
          mlt->total_throughput_send,
          mlt->total_throughput_recv);
    }

    mlt->slaves_log = GNUNET_malloc (bp->peer->num_partners *
        sizeof (struct PartnerLoggingTimestep));

    for (c_s = 0; c_s < bp->peer->num_partners; c_s++)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
          "Collect logging data master[%u] slave [%u]\n", c_m, c_s);

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
      slt->pref_bandwidth = p->pref_bandwidth;
      slt->pref_delay = p->pref_delay;

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
        {
          app_rtt = prev_log_slt->app_rtt; /* No messages were */
        }
      }
      slt->app_rtt = app_rtt;

      /* Partner throughput */
      if (NULL != prev_log_mlt)
      {
        prev_log_slt =  &prev_log_mlt->slaves_log[c_s];
        if (slt->total_bytes_sent > prev_log_slt->total_bytes_sent)
          slt->throughput_sent = mult * (slt->total_bytes_sent - prev_log_slt->total_bytes_sent);
        else
          slt->throughput_sent = 0;

        if (slt->total_bytes_received > prev_log_slt->total_bytes_received)
          slt->throughput_recv = mult *
              (slt->total_bytes_received - prev_log_slt->total_bytes_received);
        else
          slt->throughput_recv = 0;
      }
      else
      {
        slt->throughput_sent = mult * slt->total_bytes_sent;
        slt->throughput_recv = mult * slt->total_bytes_received;
      }

      if (GNUNET_YES == l->verbose)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
            "Master [%u] -> Slave [%u]: delta: %llu us, bytes (sent/received): %u / %u; throughput send/recv: %u / %u\n",
            c_m, c_s,
            delta.rel_value_us,
            mlt->total_bytes_sent,
            mlt->total_bytes_received,
            slt->throughput_sent,
            slt->throughput_recv);
      }
      else
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Master [%u]: slave [%u]\n",
          bp->peer->no, p->dest->no);
    }
  }
}

static void
collect_log_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct LoggingHandle *l = cls;
  l->log_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_ATS_TEST_logging_now (l);

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  l->log_task = GNUNET_SCHEDULER_add_delayed (l->frequency,
      &collect_log_task, l);
}

/**
 * Stop logging
 *
 * @param l the logging handle
 */
void
GNUNET_ATS_TEST_logging_stop (struct LoggingHandle *l)
{
  if (GNUNET_YES!= l->running)
    return;

  if (GNUNET_SCHEDULER_NO_TASK != l->log_task)
    GNUNET_SCHEDULER_cancel (l->log_task);
  l->log_task = GNUNET_SCHEDULER_NO_TASK;
  l->running = GNUNET_NO;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      _("Stop logging\n"));
}

/**
 * Clean up logging data
 *
 * @param l the logging handle
 */
void
GNUNET_ATS_TEST_logging_clean_up (struct LoggingHandle *l)
{
  int c_m;
  struct PeerLoggingTimestep *cur;

  if (GNUNET_YES == l->running)
    GNUNET_ATS_TEST_logging_stop (l);

  for (c_m = 0; c_m < l->num_masters; c_m++)
  {
    while (NULL != (cur = l->lp[c_m].head))
    {
      GNUNET_CONTAINER_DLL_remove (l->lp[c_m].head, l->lp[c_m].tail, cur);
      GNUNET_free (cur->slaves_log);
      GNUNET_free (cur);
    }
  }

  GNUNET_free (l->lp);
  GNUNET_free (l);
}


/**
 * Start logging
 *
 * @param log_frequency the logging frequency
 * @param testname the testname
 * @param masters the master peers used for benchmarking
 * @param num_masters the number of master peers
 * @param num_slaves the number of slave peers
 * @param verbose verbose logging
 * @return the logging handle or NULL on error
 */
struct LoggingHandle *
GNUNET_ATS_TEST_logging_start(struct GNUNET_TIME_Relative log_frequency,
    char *testname, struct BenchmarkPeer *masters, int num_masters, int num_slaves,
    int verbose)
{
  struct LoggingHandle *l;
  int c_m;
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      _("Start logging `%s'\n"), testname);

  l = GNUNET_new (struct LoggingHandle);
  l->num_masters = num_masters;
  l->num_slaves = num_slaves;
  l->name = testname;
  l->frequency = log_frequency;
  l->verbose = verbose;
  l->lp = GNUNET_malloc (num_masters * sizeof (struct LoggingPeer));

  for (c_m = 0; c_m < num_masters; c_m ++)
  {
    l->lp[c_m].peer = &masters[c_m];
    l->lp[c_m].start = GNUNET_TIME_absolute_get();
  }

  /* Schedule logging task */
  l->log_task = GNUNET_SCHEDULER_add_now (&collect_log_task, l);
  l->running = GNUNET_YES;

  return l;
}
/* end of file ats-testing-log.c */

