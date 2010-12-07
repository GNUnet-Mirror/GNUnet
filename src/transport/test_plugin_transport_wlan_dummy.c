/*
	 This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file transport/test_transport_wlan_dummy.c
 * @brief helper for the testcase for plugin_transport_wlan.c
 * @author David Brodski
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_os_lib.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"
#include "plugin_transport_wlan.h"
#include "gnunet_common.h"
#include "gnunet-transport-wlan-helper.h"
#include "plugin_transport_wlan.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#define FIFO_FILE1       "MYFIFOin"
#define FIFO_FILE2       "MYFIFOout"

int
main(int argc, char *argv[])
{
	struct stat st;
	int erg;
	int first;
	FILE *fpin;
	FILE *fpout;
	//make the fifos if needed
	if(stat(FIFO_FILE1,&st) != 0){
		if(stat(FIFO_FILE2,&st) != 0){
				perror("FIFO 2 exists, but FIFO 1 not");
                exit(1);
		}
		first = 1;
		umask(0);
		erg = mknod(FIFO_FILE1, S_IFIFO|0666, 0);
		erg = mknod(FIFO_FILE2, S_IFIFO|0666, 0);

		if((fpin = fopen(FIFO_FILE1, "r")) == NULL) {
                perror("fopen");
                exit(1);
        }
		if((fpout = fopen(FIFO_FILE2, "w")) == NULL) {
                perror("fopen");
                exit(1);
        }
	} else {
		first = 0;
		if(stat(FIFO_FILE2,&st) == 0){
				perror("FIFO 1 exists, but FIFO 2 not");
                exit(1);
		}
		if((fpout = fopen(FIFO_FILE1, "w")) == NULL) {
                perror("fopen");
                exit(1);
        }
		if((fpin = fopen(FIFO_FILE2, "r")) == NULL) {
                perror("fopen");
                exit(1);
        }

	}
	// Write the input to the output

	//clean up
	if (first == 1){
		unlink(FIFO_FILE1);
		unlink(FIFO_FILE2);
	}


	fclose(fpin);
	fclose(fpout);
    return(0);
}

