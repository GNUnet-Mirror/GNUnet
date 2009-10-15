/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file util/test_bio.c
 * @brief testcase for the buffered IO module
 * @author
 */


#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_disk_lib.h"
#include "gnunet_bio_lib.h"

int check(){

	int suc;
    char* fileName = GNUNET_DISK_mktemp ("gnunet_bio");
	struct GNUNET_BIO_ReadHandle *fileR;
	struct GNUNET_BIO_WriteHandle *fileW;
	char *msg;
	fileR = GNUNET_BIO_read_open (fileName);
	GNUNET_BIO_read_close(fileR,&msg);
	fileW = GNUNET_BIO_write_open(fileName);
	if (GNUNET_OK == GNUNET_BIO_write_close(fileW))
		suc = 0;
	else
		suc = 1;

	return suc;


}



int
main (int argc, char *argv[])
{

	int ch = check();
	return ch;

}                               /* end of main */
