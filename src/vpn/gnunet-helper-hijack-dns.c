/*
   This file is part of GNUnet.
   (C) 2010 Christian Grothoff

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
 * @file vpn/gnunet-helper-hijack-dns.c
 * @brief
 * @author Philipp Tölke
 */
#include <platform.h>

#include "gnunet_common.h"

int fork_and_exec(char* file, char* cmd[]) {
	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "could not fork: %s\n", strerror(errno));
		return GNUNET_SYSERR;
	}

	int st = 0;

	if (pid == 0) {
		execv(file, cmd);
	} else {
		waitpid(pid, &st, 0);
	}
	return WIFEXITED(st) && (WEXITSTATUS(st) == 0);
}

int main(int argc, char** argv) {
	int delete = 0;
	int port = 0;
	if (argc < 2) return GNUNET_SYSERR;

	if (strncmp(argv[1], "-d", 2) == 0) {
		if (argc < 3) return GNUNET_SYSERR;
		delete = 1;
		port = atoi(argv[2]);
	} else {
		port = atoi(argv[1]);
	}

	if (port == 0) return GNUNET_SYSERR;

	struct stat s;
	if (stat("/sbin/iptables", &s) < 0) {
		fprintf(stderr, "stat on /sbin/iptables failed: %s\n", strerror(errno));
		return GNUNET_SYSERR;
	}

	char localport[7];
	snprintf(localport, 7, "%d", port);

	int r;
	if (delete) {
		r = fork_and_exec("/sbin/iptables", (char*[]){"iptables", "-t", "nat", "-D", "OUTPUT", "-p", "udp", "--sport", localport, "--dport", "53", "-j", "ACCEPT", NULL});
		r = fork_and_exec("/sbin/iptables", (char*[]){"iptables", "-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "10.10.10.2:53", NULL});
	} else {
		r = fork_and_exec("/sbin/iptables", (char*[]){"iptables", "-t", "nat", "-I", "OUTPUT", "1", "-p", "udp", "--sport", localport, "--dport", "53", "-j", "ACCEPT", NULL});
		r = fork_and_exec("/sbin/iptables", (char*[]){"iptables", "-t", "nat", "-I", "OUTPUT", "2", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "10.10.10.2:53", NULL});
	}
	if (r) return GNUNET_YES;
	return GNUNET_SYSERR;
}
