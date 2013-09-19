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
 * @file ats/perf_ats_logging.c
 * @brief ats benchmark: logging for performance tests
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "perf_ats.h"

#define LOGGING_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 500)

#define THROUGHPUT_TEMPLATE "#!/usr/bin/gnuplot \n" \
"set datafile separator ';' \n" \
"set title \"Throughput\" \n" \
"set xlabel \"Time in ms\" \n" \
"set ylabel \"Bytes/s\" \n"

/**
 * Logging task
 */
static GNUNET_SCHEDULER_TaskIdentifier log_task;

/**
 * Reference to perf_ats' masters
 */
static int num_peers;
static int running;
static char *name;

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
write_gnuplot_script (char * fn, struct LoggingPeer *lp)
{
  struct GNUNET_DISK_FileHandle *f;
  char * gfn;
  char *data;
  int c_s;
  int index;

  GNUNET_asprintf (&gfn, "gnuplot_%s",fn);
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
  GNUNET_asprintf (&data, "plot '%s' using 2:%u with lines title 'Master %u send', \\\n" \
                           "'%s' using 2:%u with lines title 'Master %u receive', \\\n",
                           fn, 5, lp->peer->no,
                           fn, 8, lp->peer->no);
  if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, data, strlen(data)))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);
  GNUNET_free (data);

  index = 11;
  for (c_s = 0; c_s < lp->peer->num_partners; c_s++)
  {
    GNUNET_asprintf (&data, "'%s' using 2:%u with lines title 'Slave %u send', \\\n" \
                            "'%s' using 2:%u with lines title 'Slave %u receive'%s\n",
                            fn, index, lp->peer->no,
                            fn, index+3, lp->peer->no,
                            (c_s < lp->peer->num_partners -1) ? ", \\" : "\n pause -1");
    if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, data, strlen(data)))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);
    GNUNET_free (data);
    index += 6;
  }

  if (GNUNET_SYSERR == GNUNET_DISK_file_close(f))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot close gnuplot file `%s'\n", gfn);

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
  unsigned int throughput_recv;
  unsigned int throughput_send;
  unsigned int throughput_recv_slave;
  unsigned int throughput_send_slave;
  double mult;

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
      mult = (1.0 * 1000 * 1000) /  (LOGGING_FREQUENCY.rel_value_us);
      if (NULL != cur_lt->prev)
      {
        throughput_send = cur_lt->total_bytes_sent - cur_lt->prev->total_bytes_sent;
        throughput_recv = cur_lt->total_bytes_received - cur_lt->prev->total_bytes_received;
      }
      else
      {
        throughput_send = cur_lt->total_bytes_sent;
        throughput_recv = cur_lt->total_bytes_received;
      }
      throughput_send *= mult;
      throughput_recv *= mult;


      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Master [%u]: timestamp %llu %llu ; %u %u %u ; %u %u %u\n", lp[c_m].peer->no,
          cur_lt->timestamp, GNUNET_TIME_absolute_get_difference(lp[c_m].start,cur_lt->timestamp).rel_value_us / 1000,
          cur_lt->total_messages_sent, cur_lt->total_bytes_sent, throughput_send,
          cur_lt->total_messages_received, cur_lt->total_bytes_received, throughput_recv);

      slave_string = GNUNET_strdup (";");
      for (c_s = 0; c_s < lp[c_m].peer->num_partners; c_s++)
      {
        /* Log partners */
        plt = &cur_lt->slaves_log[c_s];
        if (NULL != cur_lt->prev)
        {
          throughput_send_slave = plt->total_bytes_sent - cur_lt->prev->slaves_log[c_s].total_bytes_sent;
          throughput_recv_slave = plt->total_bytes_received - cur_lt->prev->slaves_log[c_s].total_bytes_received;
        }
        else
        {
          throughput_send_slave = plt->total_bytes_sent;
          throughput_recv_slave = plt->total_bytes_received;
        }
        throughput_send_slave *= mult;
        throughput_recv_slave *= mult;

        GNUNET_log(GNUNET_ERROR_TYPE_INFO,
            "\t Slave [%u]: %u %u %u ; %u %u %u \n", plt->slave->no,
            plt->total_messages_sent, plt->total_bytes_sent, throughput_send_slave,
            plt->total_messages_received, plt->total_bytes_received, throughput_recv_slave);


        GNUNET_asprintf(&slave_string_tmp, "%s%u;%u;%u;%u;%u;%u;",slave_string,
            plt->total_messages_sent, plt->total_bytes_sent, throughput_send_slave,
            plt->total_messages_received, plt->total_bytes_received, throughput_recv_slave);
        GNUNET_free (slave_string);
        slave_string = slave_string_tmp;
      }

      GNUNET_asprintf (&data, "%llu;%llu;%u;%u;%u;%u;%u;%u%s\n",
          cur_lt->timestamp,
          GNUNET_TIME_absolute_get_difference(lp[c_m].start,cur_lt->timestamp).rel_value_us / 1000,
          cur_lt->total_messages_sent, cur_lt->total_bytes_sent, throughput_send,
          cur_lt->total_messages_received, cur_lt->total_bytes_received, throughput_recv,
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

    write_gnuplot_script (filename, lp);

    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Data file successfully written to log file `%s'\n", filename);
    GNUNET_free (filename);
  }
}

static void
collect_log_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c_m;
  int c_s;
  struct PeerLoggingTimestep *mlt;
  struct PartnerLoggingTimestep *slt;
  struct BenchmarkPartner *p;

  log_task = GNUNET_SCHEDULER_NO_TASK;

  for (c_m = 0; c_m < num_peers; c_m++)
  {
    mlt = GNUNET_malloc (sizeof (struct PeerLoggingTimestep));
    GNUNET_CONTAINER_DLL_insert_tail(lp[c_m].head, lp[c_m].tail, mlt);

    /* Collect data */
    mlt->timestamp = GNUNET_TIME_absolute_get();
    mlt->total_bytes_sent = lp[c_m].peer->total_bytes_sent;
    mlt->total_messages_sent = lp[c_m].peer->total_messages_sent;
    mlt->total_bytes_received = lp[c_m].peer->total_bytes_received;
    mlt->total_messages_received = lp[c_m].peer->total_messages_received;

    mlt->slaves_log = GNUNET_malloc (lp[c_m].peer->num_partners *
        sizeof (struct PartnerLoggingTimestep));

    for (c_s = 0; c_s < lp[c_m].peer->num_partners; c_s++)
    {
      p = &lp[c_m].peer->partners[c_s];
      slt = &mlt->slaves_log[c_s];
      slt->slave = p->dest;
      slt->total_bytes_sent = p->dest->total_bytes_sent;
      slt->total_messages_sent = p->dest->total_messages_sent;
      slt->total_bytes_received = p->dest->total_bytes_received;
      slt->total_messages_received = p->dest->total_messages_received;

      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Master [%u]: slave [%u]\n",
          lp[c_m].peer->no, p->dest->no);
    }
  }

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  log_task = GNUNET_SCHEDULER_add_delayed (LOGGING_FREQUENCY,
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

  if (GNUNET_SCHEDULER_NO_TASK != log_task)
    GNUNET_SCHEDULER_cancel (log_task);
  log_task = GNUNET_SCHEDULER_NO_TASK;
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
perf_logging_start (char * testname, struct BenchmarkPeer *masters, int num_masters)
{
  int c_m;
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      _("Start logging `%s'\n"), testname);

  num_peers = num_masters;
  name = testname;

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

