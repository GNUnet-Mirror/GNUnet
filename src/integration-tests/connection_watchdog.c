/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file integration-tests/connection_watchdog.c
 * @brief tool to monitor core and transport connections for consistency
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_core_service.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_statistics_service.h"


#define CHECK_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define STATS_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define REPEATED_STATS_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define STATS_VALUES 4

/**
 * Final status code.
 */
static int ret;
static int ping;

static int have_tcp;
static int have_udp;
static int have_http;
static int have_https;
static int have_unix;

static struct GNUNET_TRANSPORT_Handle *th;
static struct GNUNET_CORE_Handle *ch;
static struct GNUNET_PeerIdentity my_peer_id;
static const struct GNUNET_CONFIGURATION_Handle *mycfg;
static struct GNUNET_STATISTICS_Handle *stats;


static unsigned int transport_connections;
static unsigned int core_connections;

static GNUNET_SCHEDULER_TaskIdentifier check_task;
static GNUNET_SCHEDULER_TaskIdentifier statistics_task;

static uint64_t statistics_transport_connections;
static uint64_t statistics_transport_tcp_connections;
static uint64_t statistics_core_neighbour_entries;
static uint64_t statistics_core_entries_session_map;

int stat_check_running;

static struct GNUNET_CONTAINER_MultiHashMap *peers;

struct PeerContainer
{
  struct GNUNET_PeerIdentity id;
  int transport_connected;
  int core_connected;
  struct GNUNET_TRANSPORT_TransmitHandle *th_ping;
  struct GNUNET_CORE_TransmitHandle *ch_ping;

  struct GNUNET_TRANSPORT_TransmitHandle *th_pong;
  struct GNUNET_CORE_TransmitHandle *ch_pong;
};


enum protocol
{
  tcp,
  udp,
  unixdomain
};

struct TransportPlugin
{
  /**
   * This is a doubly-linked list.
   */
  struct TransportPlugin *next;

  /**
   * This is a doubly-linked list.
   */
  struct TransportPlugin *prev;

  /**
   * Short name for the plugin (i.e. "tcp").
   */
  char *short_name;

  int port;

  int protocol;
};

struct TransportPlugin *phead;
struct TransportPlugin *ptail;

static int 
map_check_it (void *cls,
	      const GNUNET_HashCode * key,
	      void *value)
{
  int *fail = cls;
  struct PeerContainer *pc = value;
  if (pc->core_connected != pc->transport_connected)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
     "Inconsistent peer `%s': TRANSPORT %s <-> CORE %s\n",
     GNUNET_i2s (&pc->id),
     (GNUNET_YES == pc->transport_connected) ? "YES" : "NO",
     (GNUNET_YES == pc->core_connected) ? "YES" : "NO");
    (*fail) ++;
  }

  return GNUNET_OK;
}


static int 
map_cleanup_it (void *cls,
		const GNUNET_HashCode * key,
		void *value)
{
  struct PeerContainer *pc = value;
  GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_remove(peers, key, value));
  if (NULL != pc->th_ping)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel(pc->th_ping);
    pc->th_ping = NULL;
  }
  if (NULL != pc->th_pong)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel(pc->th_pong);
    pc->th_pong = NULL;
  }
  if (NULL != pc->ch_ping)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (pc->ch_ping);
    pc->ch_ping = NULL;
  }
  if (NULL != pc->ch_pong)
  {
    GNUNET_CORE_notify_transmit_ready_cancel(pc->ch_pong);
    pc->ch_pong = NULL;
  }
  GNUNET_free (pc);
  return GNUNET_OK;
}

static void
map_cleanup (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_CONTAINER_multihashmap_iterate (peers, &map_cleanup_it, NULL);
  GNUNET_CONTAINER_multihashmap_destroy(peers);
}

static void
map_check (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int fail = 0;
  check_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_CONTAINER_multihashmap_iterate (peers, &map_check_it, &fail);
  if (0 > fail)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
       "Inconsistent peers after connection consistency check: %u\n", fail);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
       "Inconsistent peers after connection consistency check: %u\n", fail);


  if (NULL != cls)
  {
    GNUNET_SCHEDULER_add_now (cls, NULL);
  }
}


static void
stats_check (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

static int
check_lowlevel_connections (int port, int protocol)
{
  FILE *f;
  char * cmdline;
  char * proto;
  char line[1024];
  int count = -1;
#ifdef MINGW
  /* not supported */
  return count;
#else

  switch (protocol) {
    case tcp:
      proto = "-t";
      break;
    case udp:
      proto = "-u";
      break;
    case unixdomain:
      proto = "-x";
      break;
    default:
      proto = "";
      break;
  }

  /* Use netstat to get a numeric list of all connections on port 'port' in state 'ESTABLISHED' */
  GNUNET_asprintf(&cmdline, "netstat -n %s | grep %u | grep ESTABLISHED", proto, port);

  if (system ("netstat -n > /dev/null 2> /dev/null"))
    if (system ("netstat -n > /dev/null 2> /dev/null") == 0)
      f = popen (cmdline, "r");
    else
      f = NULL;
  else
    f = popen (cmdline, "r");
  if (!f)
  {
    GNUNET_log_strerror(GNUNET_ERROR_TYPE_ERROR, "ss");
    GNUNET_free (cmdline);
    return -1;
  }

  count = 0;
  while (NULL != fgets (line, sizeof (line), f))
  {
    /* read */
    //printf ("%s", line);
    count ++;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%i TCP connections established with port %u\n",
       count, port);

  pclose (f);
  GNUNET_free (cmdline);
  return count;
#endif
}


static struct TransportPlugin *
find_plugin (char * name)
{
  struct TransportPlugin *cur = NULL;

  for (cur = phead; cur != NULL; cur = cur->next)
  {
    if (0 == strcmp(name, cur->short_name))
      return cur;
  }
  return cur;
}

static int 
stats_check_cb (void *cls, const char *subsystem,
		const char *name, uint64_t value,
		int is_persistent)
{
  static int counter;

  uint64_t *val = cls;

  if (NULL != val)
    (*val) = value;

  counter ++;
  if ((STATS_VALUES == counter) || ((GNUNET_NO == have_tcp) && (STATS_VALUES - 1 == counter)))
  {
    int fail = GNUNET_NO;



    int low_level_connections_udp = check_lowlevel_connections (2086, udp);

    if (transport_connections != core_connections)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           "%u transport notifications <-> %u core notifications\n",
           transport_connections, core_connections);
      fail = GNUNET_YES;
    }

    if (transport_connections != statistics_transport_connections)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           "%u transport notifications <-> %u in statistics (peers connected)\n",
           transport_connections, statistics_transport_connections);
      fail = GNUNET_YES;
    }

    if (core_connections != statistics_core_entries_session_map)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           "%u core notifications <-> %u in statistics (entries session map)\n",
           core_connections, statistics_core_entries_session_map);
      fail = GNUNET_YES;
    }

    if (core_connections != statistics_core_neighbour_entries)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           "%u core notifications <-> %u in statistics (neighbour entries allocated)\n",
           core_connections, statistics_core_neighbour_entries);
      fail = GNUNET_YES;
    }

    if (GNUNET_NO == fail)
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
         "Check successful : (%u transport / %u core) connections established\n", transport_connections, core_connections);

    /* TCP plugin specific checks */
    if (GNUNET_YES == have_tcp)
    {
      struct TransportPlugin * p = find_plugin ("tcp");
      int low_level_connections_tcp = check_lowlevel_connections (p->port, p->protocol);

      if (low_level_connections_tcp != -1)
      {
        if (statistics_transport_tcp_connections > low_level_connections_tcp)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
               "%u transport tcp sessions <-> %i established tcp connections\n",
               statistics_transport_tcp_connections, low_level_connections_tcp);
          fail = GNUNET_YES;
        }
        else if (low_level_connections_tcp != -1)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
               "%u TCP connections, %u UDP connections \n",
               low_level_connections_tcp, low_level_connections_udp);
        }
      }
      if (transport_connections > statistics_transport_tcp_connections)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
             "%u transport notifications <-> %u in statistics (statistics_transport_tcp_connections)\n",
             transport_connections, statistics_transport_tcp_connections);
        fail = GNUNET_YES;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
             " %u transport notifications <-> %u in statistics (statistics_transport_tcp_connections)\n",
             transport_connections, statistics_transport_tcp_connections);
      }
    }

    if (GNUNET_SCHEDULER_NO_TASK == statistics_task)
      statistics_task = GNUNET_SCHEDULER_add_delayed(REPEATED_STATS_DELAY, &stats_check, NULL);

    stat_check_running = GNUNET_NO;
    counter = 0;
  }

  return GNUNET_OK;
}

GNUNET_NETWORK_STRUCT_BEGIN

struct PING
{
  struct GNUNET_MessageHeader header;

  uint16_t src;
};

struct PONG
{
  struct GNUNET_MessageHeader header;

  uint16_t src;
};
GNUNET_NETWORK_STRUCT_END


static size_t 
send_transport_ping_cb (void *cls, size_t size, void *buf)
{
 struct PeerContainer * pc = cls;
 struct PING ping;
 size_t mlen = sizeof (struct PING);

 if (size < mlen)
 {
   GNUNET_break (0);
   return 0;
 }

 GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Sending transport ping to `%s'\n", GNUNET_i2s  (&pc->id));
 ping.header.size = htons (mlen);
 ping.header.type = htons (1234);
 ping.src = htons (0);

 pc->th_ping = NULL;

 memcpy (buf, &ping, mlen);
 return mlen;
}

size_t send_core_ping_cb (void *cls, size_t size, void *buf)
{
struct PeerContainer * pc = cls;
struct PING ping;
size_t mlen = sizeof (struct PING);

if (size < mlen)
{
  GNUNET_break (0);
  return 0;
}

GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
     "Sending core ping to `%s'\n", GNUNET_i2s  (&pc->id));
ping.header.size = htons (mlen);
ping.header.type = htons (1234);
ping.src = htons (1);

pc->ch_ping = NULL;

memcpy (buf, &ping, mlen);
return mlen;
}


int map_ping_it (void *cls,
                  const GNUNET_HashCode * key,
                  void *value)
{
  struct PeerContainer *pc = value;

  if (ping == GNUNET_YES)
  {
    if ((GNUNET_YES == pc->transport_connected) && (NULL == pc->th_ping))
      pc->th_ping = GNUNET_TRANSPORT_notify_transmit_ready(th, &pc->id,
          sizeof (struct PING), UINT_MAX,
          GNUNET_TIME_UNIT_FOREVER_REL, &send_transport_ping_cb, pc);
    else
      GNUNET_break(0);

    if ((GNUNET_YES == pc->core_connected) && (NULL == pc->ch_ping))
      pc->ch_ping = GNUNET_CORE_notify_transmit_ready(ch,
                                               GNUNET_NO, UINT_MAX,
						      GNUNET_TIME_UNIT_FOREVER_REL,
                                               &pc->id,
                                               sizeof (struct PING),
                                               send_core_ping_cb, pc);
    else
      GNUNET_break (0);
  }
  return GNUNET_OK;
}


static void
stats_check (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  statistics_task = GNUNET_SCHEDULER_NO_TASK;

  if (GNUNET_YES == stat_check_running)
  {
    statistics_task = GNUNET_SCHEDULER_add_delayed(STATS_DELAY, &stats_check, NULL);
  }

  GNUNET_CONTAINER_multihashmap_iterate (peers, &map_ping_it, NULL);

  stat_check_running = GNUNET_YES;

  statistics_transport_connections = 0 ;
  statistics_core_entries_session_map = 0;
  statistics_core_neighbour_entries = 0;

  GNUNET_STATISTICS_get (stats, "transport", "# peers connected", GNUNET_TIME_UNIT_MINUTES, NULL, &stats_check_cb, &statistics_transport_connections);
  GNUNET_STATISTICS_get (stats, "core", "# neighbour entries allocated", GNUNET_TIME_UNIT_MINUTES, NULL, &stats_check_cb, &statistics_core_neighbour_entries);
  GNUNET_STATISTICS_get (stats, "core", "# peers connected", GNUNET_TIME_UNIT_MINUTES, NULL, &stats_check_cb, &statistics_core_entries_session_map);

  /* TCP plugin specific checks */
  if (GNUNET_YES == have_tcp)
    GNUNET_STATISTICS_get (stats, "transport", "# TCP sessions active", GNUNET_TIME_UNIT_MINUTES, NULL, &stats_check_cb, &statistics_transport_tcp_connections);
}



size_t send_transport_pong_cb (void *cls, size_t size, void *buf)
{
 struct PeerContainer * pc = cls;
 struct PING ping;
 size_t mlen = sizeof (struct PING);

 if (size < mlen)
 {
   GNUNET_break (0);
   return 0;
 }

 GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Sending transport pong to `%s'\n", GNUNET_i2s  (&pc->id));
 ping.header.size = htons (mlen);
 ping.header.type = htons (4321);
 ping.src = htons (0);

 pc->th_pong = NULL;

 memcpy (buf, &ping, mlen);
 return mlen;
}

static size_t 
send_core_pong_cb (void *cls, size_t size, void *buf)
{
struct PeerContainer * pc = cls;
struct PING ping;
size_t mlen = sizeof (struct PING);

if (size < mlen)
{
  GNUNET_break (0);
  return 0;
}

GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
     "Sending core pong to `%s'\n", GNUNET_i2s  (&pc->id));
ping.header.size = htons (mlen);
ping.header.type = htons (4321);
ping.src = htons (1);

pc->ch_pong = NULL;

memcpy (buf, &ping, mlen);
return mlen;
}


static void
map_connect (const struct GNUNET_PeerIdentity *peer, void * source)
{
  struct PeerContainer * pc;
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(peers, &peer->hashPubKey))
  {
    pc = GNUNET_malloc (sizeof (struct PeerContainer));
    pc->id = *peer;
    pc->core_connected = GNUNET_NO;
    pc->transport_connected = GNUNET_NO;
    GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(peers, &peer->hashPubKey, pc, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }

  pc = GNUNET_CONTAINER_multihashmap_get(peers, &peer->hashPubKey);
  if (source == th)
  {
    if (GNUNET_NO == pc->transport_connected)
    {
      pc->transport_connected = GNUNET_YES;
      if (GNUNET_YES == ping)
      {
        if (NULL == pc->th_ping)
          pc->th_ping = GNUNET_TRANSPORT_notify_transmit_ready(th, peer, sizeof (struct PING), UINT_MAX, GNUNET_TIME_UNIT_FOREVER_REL, &send_transport_ping_cb, pc);
        else
          GNUNET_break(0);
      }
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           "%s notified multiple times about for peers `%s' (%s : %s)\n",
           "TRANSPORT",
           GNUNET_i2s (&pc->id),
           "CORE", (pc->core_connected == GNUNET_YES) ? "yes" : "no");
      GNUNET_break (0);
    }
  }
  if (source == ch)
  {
    if (GNUNET_NO == pc->core_connected)
    {
      pc->core_connected = GNUNET_YES;
      if (GNUNET_YES == ping)
      {
        if (NULL == pc->ch_ping)
          pc->ch_ping = GNUNET_CORE_notify_transmit_ready(ch,
                                                 GNUNET_NO, UINT_MAX,
							  GNUNET_TIME_UNIT_FOREVER_REL,
                                                 peer,
                                                 sizeof (struct PING),
                                                 send_core_ping_cb, pc);
        else
          GNUNET_break (0);
      }
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           "%s notified multiple times about for peers `%s' (%s : %s)\n",
           "CORE",
           GNUNET_i2s (&pc->id),
               "TRANSPORT", (pc->transport_connected == GNUNET_YES) ? "yes" : "no");
      GNUNET_break (0);
    }
  }
  if (GNUNET_SCHEDULER_NO_TASK != check_task)
    GNUNET_SCHEDULER_cancel(check_task);
  check_task = GNUNET_SCHEDULER_add_delayed(CHECK_DELAY, &map_check, NULL);

  if (GNUNET_SCHEDULER_NO_TASK != statistics_task)
    GNUNET_SCHEDULER_cancel(statistics_task);
  statistics_task = GNUNET_SCHEDULER_add_delayed(STATS_DELAY, &stats_check, NULL);
}


static void
map_disconnect (const struct GNUNET_PeerIdentity * peer, void * source)
{

  struct PeerContainer * pc;
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(peers, &peer->hashPubKey))
  {
    if (source == th)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
         "%s disconnect notification for unknown peer `%s'\n",
         "TRANSPORT", GNUNET_i2s (peer));
      GNUNET_break (0);
      return;
    }
    if (source == ch)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
         "%s disconnect notification for unknown peer `%s'\n",
         "CORE", GNUNET_i2s (peer));
      return;
    }
  }

  pc = GNUNET_CONTAINER_multihashmap_get(peers, &peer->hashPubKey);
  if (source == th)
  {
    if (NULL != pc->th_ping)
    {
      GNUNET_TRANSPORT_notify_transmit_ready_cancel(pc->th_ping);
      pc->th_ping = NULL;
    }
    if (NULL != pc->th_pong)
    {
      GNUNET_TRANSPORT_notify_transmit_ready_cancel(pc->th_pong);
      pc->th_pong = NULL;
    }

    if (GNUNET_YES == pc->transport_connected)
    {
      pc->transport_connected = GNUNET_NO;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           "%s notified for not connected peer `%s' (%s : %s)\n",
           "TRANSPORT",
           GNUNET_i2s (&pc->id),
           "CORE", (pc->core_connected == GNUNET_YES) ? "yes" : "no");
      GNUNET_break (0);
    }
  }
  if (source == ch)
  {
    if (NULL != pc->ch_ping)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (pc->ch_ping);
      pc->ch_ping = NULL;
    }
    if (NULL != pc->ch_pong)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (pc->ch_pong);
      pc->ch_pong = NULL;
    }

    if (GNUNET_YES == pc->core_connected)
    {
      pc->core_connected = GNUNET_NO;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           "%s notified for not connected peer `%s' (%s : %s)\n",
           "CORE",
           GNUNET_i2s (&pc->id),
           "TRANSPORT", (pc->transport_connected == GNUNET_YES) ? "yes" : "no");
      GNUNET_break (0);
    }
  }

  if ((GNUNET_NO == pc->core_connected) && (GNUNET_NO == pc->transport_connected))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Removing peer `%s'\n", GNUNET_i2s (&pc->id));
    GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_remove (peers, &peer->hashPubKey, pc));


    GNUNET_free (pc);
  }

  if (GNUNET_SCHEDULER_NO_TASK != check_task)
    GNUNET_SCHEDULER_cancel(check_task);
  check_task = GNUNET_SCHEDULER_add_delayed(CHECK_DELAY, &map_check, NULL);

  if (GNUNET_SCHEDULER_NO_TASK != statistics_task)
    GNUNET_SCHEDULER_cancel(statistics_task);
  statistics_task = GNUNET_SCHEDULER_add_delayed(STATS_DELAY, &stats_check, NULL);
}


static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TransportPlugin * cur = phead;

  if (NULL != th)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Disconnecting from transport service\n");
    GNUNET_TRANSPORT_disconnect (th);
    th = NULL;
  }


  if (NULL != ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Disconnecting from core service\n");
    GNUNET_CORE_disconnect (ch);
    ch = NULL;
  }

  if (GNUNET_SCHEDULER_NO_TASK != statistics_task)
  {
    GNUNET_SCHEDULER_cancel(statistics_task);
    statistics_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (GNUNET_SCHEDULER_NO_TASK != check_task)
  {
    GNUNET_SCHEDULER_cancel(check_task);
    check_task = GNUNET_SCHEDULER_NO_TASK;
  }

  for (cur = phead; cur != NULL; cur = phead)
  {
    GNUNET_CONTAINER_DLL_remove(phead, ptail, cur);
    GNUNET_free (cur->short_name);
    GNUNET_free (cur);
  }

  check_task = GNUNET_SCHEDULER_add_now (&map_check, &map_cleanup);
}

static void
transport_notify_connect_cb (void *cls,
                const struct GNUNET_PeerIdentity
                * peer,
                const struct
                GNUNET_ATS_Information * ats,
                uint32_t ats_count)
{
  transport_connections ++;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "TRANSPORT connect for peer `%s' (%u total)\n",
      GNUNET_i2s (peer), transport_connections);
  map_connect (peer, th);
}

/**
 * Function called to notify transport users that another
 * peer disconnected from us.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 */
static void
transport_notify_disconnect_cb (void *cls,
                               const struct
                               GNUNET_PeerIdentity * peer)
{
  GNUNET_assert (transport_connections > 0);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "TRANSPORT disconnect for peer `%s' (%u total)\n",
      GNUNET_i2s (peer), transport_connections) ;
  map_disconnect (peer, th);
  transport_connections --;

}

static void
transport_notify_receive_cb (void *cls,
                            const struct
                            GNUNET_PeerIdentity * peer,
                            const struct
                            GNUNET_MessageHeader *
                            message,
                            const struct
                            GNUNET_ATS_Information * ats,
                            uint32_t ats_count)
{


  struct PeerContainer *pc = NULL;

  pc = GNUNET_CONTAINER_multihashmap_get(peers, &peer->hashPubKey);

  if (NULL == pc)
  {
    GNUNET_break (0);
    return;
  }

  if ((message->size == ntohs (sizeof (struct PING))) && (message->type == ntohs (1234)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Received %s %s from peer `%s'\n",
        "TRANSPORT",
        "PING",
        GNUNET_i2s (peer)) ;
    if (GNUNET_YES == ping)
    {
      if (NULL == pc->th_pong)
        pc->th_pong = GNUNET_TRANSPORT_notify_transmit_ready(th,
          peer, sizeof (struct PONG),
							     UINT_MAX, GNUNET_TIME_UNIT_FOREVER_REL,
          &send_transport_pong_cb, pc);
      else
        GNUNET_break (0);
    }

  }
  if ((message->size == ntohs (sizeof (struct PONG))) && (message->type == ntohs (4321)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Received %s %s from peer `%s'\n",
        "TRANSPORT",
        "PONG",
        GNUNET_i2s (peer));
  }
}

static int 
core_notify_receive_cb (void *cls,
			const struct GNUNET_PeerIdentity * peer,
			const struct GNUNET_MessageHeader * message,
			const struct GNUNET_ATS_Information* atsi,
			unsigned int atsi_count)
{
  struct PeerContainer *pc = NULL;

  pc = GNUNET_CONTAINER_multihashmap_get(peers, &peer->hashPubKey);

  if (NULL == pc)
  {
    if (0 == memcmp (peer, &my_peer_id, sizeof (my_peer_id)))
        return GNUNET_OK;

    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Received unexpected message type %u from unknown peer `%s'\n",
        ntohs (message->type),
        GNUNET_i2s (peer));

    GNUNET_break (0);
    return GNUNET_OK;
  }

  if ((message->size == ntohs (sizeof (struct PING))) && (message->type == ntohs (1234)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Received %s %s from peer `%s'\n",
        "CORE",
        "PING",
        GNUNET_i2s (peer));
    if (GNUNET_YES == ping)
    {
      if (NULL == pc->ch_pong)
        pc->ch_pong = GNUNET_CORE_notify_transmit_ready(ch,
                                               GNUNET_NO, UINT_MAX,
							GNUNET_TIME_UNIT_FOREVER_REL,
                                               peer,
                                               sizeof (struct PONG),
                                               send_core_pong_cb, pc);
      else
        GNUNET_break (0);
    }
  }

  if ((message->size == ntohs (sizeof (struct PONG))) && (message->type == ntohs (4321)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Received %s %s from peer `%s'\n",
        "CORE",
        "PONG",
        GNUNET_i2s (peer));

  }

  return GNUNET_OK;
}

static void
core_connect_cb (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_ATS_Information *atsi,
                      unsigned int atsi_count)
{
  if (0 != memcmp (peer, &my_peer_id, sizeof (struct GNUNET_PeerIdentity)))
  {
    core_connections ++;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "CORE      connect for peer `%s' (%u total)\n",
      GNUNET_i2s (peer), core_connections);
    map_connect (peer, ch);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "CORE      connect for myself `%s' (%u total)\n",
      GNUNET_i2s (peer), core_connections);
  }
}

static void
core_disconnect_cb (void *cls,
                      const struct
                      GNUNET_PeerIdentity * peer)
{
  if (0 != memcmp (peer, &my_peer_id, sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_assert (core_connections > 0);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "CORE      disconnect for peer `%s' (%u total)\n",
      GNUNET_i2s (peer), core_connections);
    map_disconnect (peer, ch);
    core_connections --;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "CORE      disconnect for myself `%s' (%u total)\n",
      GNUNET_i2s (peer), core_connections);
  }

}

static void
core_init_cb (void *cls, struct GNUNET_CORE_Handle *server,
                   const struct GNUNET_PeerIdentity *my_identity)
{
  my_peer_id = *my_identity;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Connected to core service\n");
}


static void
init ()
{
  struct TransportPlugin * cur;
  char *plugs;
  char *pos;
  char *secname;
  int counter;
  unsigned long long port;

  have_tcp = GNUNET_NO;
  have_udp = GNUNET_NO;
  have_http = GNUNET_NO;
  have_https = GNUNET_NO;
  have_unix = GNUNET_NO;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (mycfg, "TRANSPORT", "PLUGINS", &plugs))
    return;
  counter = 0;
  for (pos = strtok (plugs, " "); pos != NULL; pos = strtok (NULL, " "))
  {
    counter++;

    GNUNET_asprintf(&secname, "transport-%s", pos);

    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (mycfg, secname, "PORT", &port))
    {
      GNUNET_free (secname);
      continue;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Transport plugin: `%s' port %llu\n"), pos, port);
    cur = GNUNET_malloc(sizeof (struct TransportPlugin));
    cur->short_name = GNUNET_strdup (pos);
    cur->port = port;
    if (0 == strcmp("tcp", pos))
    {
      have_tcp = GNUNET_YES;
      cur->protocol = tcp;
    }
    if (0 == strcmp("udp", pos))
    {
      have_udp = GNUNET_YES;
      cur->protocol = udp;
    }
    if (0 == strcmp("http", pos))
    {
      have_http = GNUNET_YES;
      cur->protocol = tcp;
    }
    if (0 == strcmp("https", pos))
    {
      have_https = GNUNET_YES;
      cur->protocol = tcp;
    }
    if (0 == strcmp("unix", pos))
    {
      have_unix = GNUNET_YES;
      cur->protocol = unixdomain;
    }

    GNUNET_CONTAINER_DLL_insert(phead, ptail, cur);
    GNUNET_free (secname);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Found %u transport plugins: `%s'\n"),
              counter, plugs);

  GNUNET_free (plugs);
}

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  transport_connections = 0;
  core_connections = 0;
  mycfg = cfg;

  init();

  stats = GNUNET_STATISTICS_create ("watchdog", cfg);
  peers = GNUNET_CONTAINER_multihashmap_create (20);

  th = GNUNET_TRANSPORT_connect(cfg, NULL, NULL,
                                &transport_notify_receive_cb,
                                &transport_notify_connect_cb,
                                &transport_notify_disconnect_cb);
  GNUNET_assert (th != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Connected to transport service\n");
  ch =  GNUNET_CORE_connect (cfg, 1, NULL,
                             &core_init_cb,
                             &core_connect_cb,
                             &core_disconnect_cb,
                             &core_notify_receive_cb, GNUNET_NO,
                             NULL, GNUNET_NO,
                             NULL);
  GNUNET_assert (ch != NULL);

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task, NULL);

}


/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  ping = GNUNET_NO;
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
   {'p', "ping", NULL, gettext_noop ("Send ping messages to test connectivity (default == NO)"),
    GNUNET_NO, &GNUNET_GETOPT_set_one, &ping},
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "cn",
                              gettext_noop ("help text"), options, &run,
                              NULL)) ? ret : 1;
}

/* end of connection_watchdog.c */
