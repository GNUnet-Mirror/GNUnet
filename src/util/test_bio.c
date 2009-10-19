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
 * @author Ji Lu
 */


#include "platform.h"
#include "gnunet_util_lib.h"
#define TESTSTRING "testString"
#define TESTNUMBER64 100000L

int
main (int argc, char *argv[])
{

        char *readResultString;
	int64_t testNumber = (int64_t)TESTNUMBER64;
	int64_t testNum;
	char *msg;

	char* fileName = GNUNET_DISK_mktemp ("gnunet_bio");
	struct GNUNET_BIO_ReadHandle *fileR;
	struct GNUNET_BIO_WriteHandle *fileW;
	struct GNUNET_CONTAINER_MetaData *metaDataW;
	struct GNUNET_CONTAINER_MetaData *metaDataR;
	metaDataR = GNUNET_CONTAINER_meta_data_create();
	metaDataW = GNUNET_CONTAINER_meta_data_create();
	GNUNET_CONTAINER_meta_data_add_publication_date(metaDataW);
	fileW = GNUNET_BIO_write_open(fileName);
	GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_string(fileW, TESTSTRING));
	GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_meta_data(fileW,metaDataW));
	GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_int64(fileW,testNumber));
	GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_close(fileW));
	fileR = GNUNET_BIO_read_open (fileName);
	GNUNET_assert(GNUNET_OK == GNUNET_BIO_read_string(fileR, "Read string error", &readResultString, 200));
	GNUNET_BIO_read_meta_data(fileR, "Read meta error", &metaDataR);
	GNUNET_assert(GNUNET_OK == GNUNET_BIO_read_int64(fileR, &testNum));
	GNUNET_BIO_read_close(fileR,&msg);
	GNUNET_CONTAINER_meta_data_destroy(metaDataW);
	GNUNET_CONTAINER_meta_data_destroy(metaDataR);
    free(fileName);

    return 0;

}                               /* end of main */
